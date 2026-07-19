#include "axvm_guard.h"
#include "axvm_ctx.h"
#include "axvm_stack_crypt.h"
#include "axvm_lazy.h"
#include "axvm_dynseed.h"
#include "axvm_strcrypt.h"
#include "axvm_log.h"

#if defined(AXVM_JIT_CACHE) && AXVM_JIT_CACHE
#include "axvm_jit.h"
#endif

#if defined(AXVM_SVC_ANTIDEBUG) && AXVM_SVC_ANTIDEBUG
#include "axvm_guard_svc.h"
#endif

#if defined(AXVM_WATCHDOG) && AXVM_WATCHDOG
#include "axvm_watchdog.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/ptrace.h>
#include <sys/syscall.h>
#endif

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

/* 前向声明：init 时抓取运行时例程 prologue */
axvm_status_t axvm_run(axvm_ctx_t *ctx);
axvm_status_t axvm_guard_probe_dispatch(axvm_ctx_t *ctx, axvm_guard_state_t *st);
axvm_status_t axvm_guard_probe_edge(axvm_ctx_t *ctx, axvm_guard_state_t *st);

static axvm_guard_state_t g_guard;
static int g_guard_inited;

/* ---------- 轻量字符串混淆（避免 .rodata 明文特征库） ---------- */
/* volatile key/out：阻止编译器把 XOR 常量折叠成明文 .asciz（pass2 反编译已证实）。 */
static void guard_xor_dec(char *out, const uint8_t *enc, size_t n, uint8_t k)
{
    volatile uint8_t vk = k;
    volatile char *vout = out;
    for (size_t i = 0; i < n; ++i) {
        vout[i] = (char)(enc[i] ^ vk);
    }
    vout[n] = '\0';
}

#define GUARD_PATH_KEY ((uint8_t)0xA7u)

/*
 * /proc/self/maps 单行的路径名列起点：首个 '/'（磁盘映射）或 '['（具名匿名区）。
 * 地址、权限、偏移、dev、inode 列均在其之前，避免十六进制地址等误命中。
 */
static const char *maps_line_path(const char *line)
{
    for (const char *p = line; *p; ++p) {
        if (*p == '/' || *p == '[') {
            return p;
        }
    }
    return NULL;
}

/* 要求命中处前一字符为路径组件边界，降低短特征（magisk/libhook）的部分词误报。 */
static int token_at_boundary(const char *path, const char *hit)
{
    if (hit == path) {
        return 1;
    }
    char c = hit[-1];
    return c == '/' || c == '.' || c == '-' || c == '_' ||
           c == '[' || c == ':' || c == ' ';
}

static int maps_line_has_token(const char *line, const char *tok)
{
    if (!tok || !*tok) {
        return 0;
    }
    const char *path = maps_line_path(line);
    if (!path) {
        return 0; /* 无路径名的匿名区不参与特征匹配 */
    }
    const char *p = path;
    while ((p = strstr(p, tok)) != NULL) {
        if (token_at_boundary(path, p)) {
            return 1;
        }
        ++p;
    }
    return 0;
}

static int scan_maps_tokens(const char *const *tokens, size_t ntok)
{
    char line[512];
    char maps_path[24];
    static const uint8_t maps_enc[] = {
        0x88, 0xd7, 0xd5, 0xc8, 0xc4, 0x88, 0xd4, 0xc2, 0xcb, 0xc1, 0x88, 0xca, 0xc6, 0xd7, 0xd4
    };
    guard_xor_dec(maps_path, maps_enc, sizeof(maps_enc), GUARD_PATH_KEY);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) {
        return 0;
    }
    int hit = 0;
    while (fgets(line, sizeof(line), fp)) {
        for (size_t i = 0; i < ntok; ++i) {
            if (maps_line_has_token(line, tokens[i])) {
                hit = 1;
                break;
            }
        }
        if (hit) {
            break;
        }
    }
    fclose(fp);
    return hit;
}

/* ---------- /proc/self/status ---------- */
static void guard_status_path(char out[24])
{
    static const uint8_t enc[] = {
        0x88, 0xd7, 0xd5, 0xc8, 0xc4, 0x88, 0xd4, 0xc2, 0xcb, 0xc1, 0x88, 0xd4, 0xd3, 0xc6, 0xd3, 0xd2,
        0xd4
    };
    guard_xor_dec(out, enc, sizeof(enc), GUARD_PATH_KEY);
}

static int read_status_field_int(const char *key, int *out)
{
    char status_path[24];
    guard_status_path(status_path);
    int fd = open(status_path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    char buf[2048];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return 0;
    }
    buf[n] = '\0';
    char *p = strstr(buf, key);
    if (!p) {
        return 0;
    }
    int v = 0;
    if (sscanf(p + strlen(key), "%d", &v) == 1) {
        *out = v;
        return 1;
    }
    return 0;
}

static int probe_tracer_pid(void)
{
    char key[16];
    /* "TracerPid:\t" ^ 0xA7 */
    static const uint8_t key_enc[] = {
        0xf3, 0xd5, 0xc6, 0xc4, 0xc2, 0xd5, 0xf7, 0xce, 0xc3, 0x9d, 0xae
    };
    guard_xor_dec(key, key_enc, sizeof(key_enc), GUARD_PATH_KEY);
    int pid = 0;
    if (read_status_field_int(key, &pid) && pid != 0) {
        return 1;
    }
    return 0;
}

static int probe_trace_state(void)
{
    char status_path[24];
    char state_key[8];
    guard_status_path(status_path);
    /* "State:" ^ 0xA7 */
    static const uint8_t state_enc[] = { 0xf4, 0xd3, 0xc6, 0xd3, 0xc2, 0x9d };
    guard_xor_dec(state_key, state_enc, sizeof(state_enc), GUARD_PATH_KEY);
    int fd = open(status_path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    char buf[2048];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return 0;
    }
    buf[n] = '\0';
    char *p = strstr(buf, state_key);
    if (!p) {
        return 0;
    }
    /* State:\tT (tracing stop) 或 t */
    char c = p[7];
    return (c == 'T' || c == 't') ? 1 : 0;
}

#if defined(__linux__) || defined(__ANDROID__)
static int probe_ptrace_traceme(axvm_guard_state_t *st)
{
    if (!st) {
        return 0;
    }
    if (!st->ptrace_sealed) {
#if defined(__ANDROID__)
        /*
         * Bionic 对非调试进程 PTRACE_TRACEME 常态返回 EPERM，
         * 不能据此判定被附加；仅 seal 后改读 TracerPid/State。
         */
        st->ptrace_sealed = 1;
        return probe_tracer_pid() || probe_trace_state();
#else
        errno = 0;
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) {
            st->ptrace_sealed = 1;
            return 0;
        }
        if (errno == EPERM) {
            return 1;
        }
        st->ptrace_sealed = 1;
#endif
    }
    return probe_tracer_pid() || probe_trace_state();
}
#else
static int probe_ptrace_traceme(axvm_guard_state_t *st)
{
    (void)st;
    return 0;
}
#endif

/* ---------- maps 特征扫描 ---------- */
static int probe_maps_frida(void)
{
    char a[16], b[16], c[16];
    /* key=0xfd: "frida", "frida-agent", "frida-gadget" */
    static const uint8_t e0[] = {0x9b, 0x8f, 0x94, 0x99, 0x9c};
    static const uint8_t e1[] = {0x9b, 0x8f, 0x94, 0x99, 0x9c, 0xd0, 0x9c, 0x9a, 0x98, 0x93, 0x89};
    /* frida-gadget ^ 0xfd (was mistyped; fixed in pass2) */
    static const uint8_t e2[] = {0x9b, 0x8f, 0x94, 0x99, 0x9c, 0xd0, 0x9a, 0x9c, 0x99, 0x9a, 0x98, 0x89};
    guard_xor_dec(a, e0, sizeof(e0), 0xfd);
    guard_xor_dec(b, e1, sizeof(e1), 0xfd);
    guard_xor_dec(c, e2, sizeof(e2), 0xfd);
    /* 多轮 strcrypt 密文（消除 .rodata 明文特征），运行期解密到栈临时缓冲。 */
    static const uint8_t s_gum[] = {0x55, 0x70, 0xdc, 0xf3, 0x0e, 0x73, 0xdc, 0x9d, 0xf2, 0x93, 0x9f};
    static const uint8_t s_lin[] = {0xa3, 0x30, 0xac, 0x07, 0x3e, 0x72, 0x68, 0x6d, 0xe1};
    static const uint8_t s_ref[] = {0xff, 0x6f, 0xa8, 0xc7, 0x56, 0x94, 0x69, 0x8d, 0x96, 0x52, 0x68, 0x9c, 0x80, 0x60, 0x88};
    const char *tok[] = {
        a, b, c,
        AXVM_STR(s_gum, sizeof(s_gum)),
        AXVM_STR(s_lin, sizeof(s_lin)),
        AXVM_STR(s_ref, sizeof(s_ref)),
    };
    return scan_maps_tokens(tok, sizeof(tok) / sizeof(tok[0]));
}

static int probe_maps_inject(void)
{
    char a[12], b[12];
    static const uint8_t e0[] = {0x9a, 0x99, 0x9e, 0x8c, 0x9c, 0x8b, 0x9b, 0x9c, 0x8b};
    static const uint8_t e1[] = {0x94, 0x93, 0x8a, 0x8c, 0x89, 0x8c};
    guard_xor_dec(a, e0, sizeof(e0), 0xfd);
    guard_xor_dec(b, e1, sizeof(e1), 0xfd);
    static const uint8_t s_sub[] = {0xa3, 0x30, 0x6e, 0x37, 0x07, 0x42, 0xbb, 0x20, 0xe1, 0x73, 0x5f, 0x6c};
    static const uint8_t s_xp[]  = {0xa3, 0x30, 0x6e, 0xa2, 0xf7, 0x32, 0xbb, 0xcc, 0x7f};
    static const uint8_t s_mag[] = {0xb5, 0xaf, 0x3e, 0x17, 0x66, 0xf3};
    static const uint8_t s_hk[]  = {0xa3, 0x30, 0x6e, 0xa7, 0x1e, 0x32, 0x38};
    const char *tok[] = {
        a, b,
        AXVM_STR(s_sub, sizeof(s_sub)),
        AXVM_STR(s_xp, sizeof(s_xp)),
        AXVM_STR(s_mag, sizeof(s_mag)),
        AXVM_STR(s_hk, sizeof(s_hk)),
    };
    return scan_maps_tokens(tok, sizeof(tok) / sizeof(tok[0]));
}

/* ---------- 时钟差分反单步 ---------- */
static uint64_t guard_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int probe_clock_skew(axvm_guard_state_t *st)
{
    if (!st) {
        return 0;
    }
    uint64_t t0 = guard_mono_ns();
    volatile uint64_t acc = st->clock_anchor;
    for (int i = 0; i < 128; ++i) {
        acc ^= (uint64_t)(i * 0x9E3779B97F4A7C15ULL);
        acc = (acc << 13) | (acc >> 51);
    }
    st->clock_anchor = acc ^ t0;
    uint64_t t1 = guard_mono_ns();
    uint64_t delta = (t1 >= t0) ? (t1 - t0) : 0;
    /* 128 次轻量运算正常 < 200us；单步调试通常 > 2ms */
    return (delta > 2000000ull) ? 1 : 0;
}

/* ---------- 信号 sigaction 劫持监控 ---------- */
static void *guard_sig_handler(const struct sigaction *sa)
{
    if (!sa) {
        return NULL;
    }
    if (sa->sa_flags & SA_SIGINFO) {
        return (void *)(uintptr_t)sa->sa_sigaction;
    }
    return (void *)(uintptr_t)sa->sa_handler;
}

static int probe_signal_tamper(axvm_guard_state_t *st)
{
    if (!st || !st->sig_trap_fn) {
        return 0;
    }
    struct sigaction cur;
    memset(&cur, 0, sizeof(cur));
    if (sigaction(SIGTRAP, NULL, &cur) != 0) {
        return 0;
    }
    void *h = guard_sig_handler(&cur);
    if (h != st->sig_trap_fn || cur.sa_flags != st->sig_trap_flags) {
        return 1;
    }
    if (sigaction(SIGINT, NULL, &cur) != 0) {
        return 0;
    }
    h = guard_sig_handler(&cur);
    if (h != st->sig_int_fn || cur.sa_flags != st->sig_int_flags) {
        return 1;
    }
    if (sigaction(SIGILL, NULL, &cur) != 0) {
        return 0;
    }
    h = guard_sig_handler(&cur);
    if (h != st->sig_ill_fn || cur.sa_flags != st->sig_ill_flags) {
        return 1;
    }
    return 0;
}

/* ---------- inline hook / 文本段完整性 ---------- */
static void guard_text_bind(axvm_guard_state_t *st, void *addr)
{
    if (!st || !addr || st->text_count >= AXVM_GUARD_TEXT_SLOTS) {
        return;
    }
    uint32_t idx = st->text_count++;
    st->text_addr[idx] = addr;
    memcpy(st->text_snap[idx], addr, 16);
}

static int probe_text_integrity(axvm_guard_state_t *st)
{
    if (!st) {
        return 0;
    }
    for (uint32_t i = 0; i < st->text_count; ++i) {
        if (!st->text_addr[i]) {
            continue;
        }
        if (memcmp(st->text_addr[i], st->text_snap[i], 16) != 0) {
            return 1;
        }
    }
    return 0;
}

static int probe_hook_integrity(axvm_guard_state_t *st)
{
    if (!st) {
        return 0;
    }
    for (uint32_t i = 0; i < st->hook_count; ++i) {
        if (!st->hook_addr[i]) {
            continue;
        }
        if (memcmp(st->hook_addr[i], st->hook_snap[i], 16) != 0) {
            return 1;
        }
    }
    return 0;
}

/* ---------- 模块 V：模拟器 / 云手机环境检测 ---------- */
#if defined(__ANDROID__)
static int prop_has_token(const char *name, const char *const *toks, size_t ntok)
{
    char val[PROP_VALUE_MAX];
    int n = __system_property_get(name, val);
    if (n <= 0) {
        return 0;
    }
    for (size_t i = 0; i < ntok; ++i) {
        if (strstr(val, toks[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}
#endif

/*
 * 强特征检测：仅命中 QEMU/goldfish/ranchu/vbox 等模拟器独有产物，
 * 真机（qcom/mt/exynos 等）全部落空，避免误杀。
 * 路径/属性名均 XOR 混淆，避免 .rodata 明文特征。
 */
static int probe_emulator(void)
{
#if defined(__ANDROID__)
    char tmp[80];
    /* 1. 模拟器独有的内核/设备文件（真机不存在） */
    static const uint8_t path0[] = {
        0x88, 0xc3, 0xc2, 0xd1, 0x88, 0xc0, 0xc8, 0xcb, 0xc3, 0xc1, 0xce, 0xd4, 0xcf, 0xf8, 0xd7, 0xce,
        0xd7, 0xc2
    };
    static const uint8_t path1[] = {
        0x88, 0xc3, 0xc2, 0xd1, 0x88, 0xd6, 0xc2, 0xca, 0xd2, 0xf8, 0xd7, 0xce, 0xd7, 0xc2
    };
    static const uint8_t path2[] = {
        0x88, 0xd4, 0xde, 0xd4, 0xd3, 0xc2, 0xca, 0x88, 0xcb, 0xce, 0xc5, 0x88, 0xcb, 0xce, 0xc5, 0xc4,
        0xf8, 0xca, 0xc6, 0xcb, 0xcb, 0xc8, 0xc4, 0xf8, 0xc3, 0xc2, 0xc5, 0xd2, 0xc0, 0xf8, 0xd6, 0xc2,
        0xca, 0xd2, 0x89, 0xd4, 0xc8
    };
    static const uint8_t path3[] = {
        0x88, 0xd4, 0xde, 0xd4, 0x88, 0xd6, 0xc2, 0xca, 0xd2, 0xf8, 0xd3, 0xd5, 0xc6, 0xc4, 0xc2
    };
    static const uint8_t path4[] = {
        0x88, 0xc3, 0xc2, 0xd1, 0x88, 0xd4, 0xc8, 0xc4, 0xcc, 0xc2, 0xd3, 0x88, 0xd6, 0xc2, 0xca, 0xd2,
        0xc3
    };
    static const uint8_t path5[] = {
        0x88, 0xc3, 0xc2, 0xd1, 0x88, 0xd4, 0xc8, 0xc4, 0xcc, 0xc2, 0xd3, 0x88, 0xc5, 0xc6, 0xd4, 0xc2,
        0xc5, 0xc6, 0xc9, 0xc3, 0xf8, 0xc0, 0xc2, 0xc9, 0xde, 0xc3
    };
    static const uint8_t path6[] = {
        0x88, 0xc3, 0xc2, 0xd1, 0x88, 0xd4, 0xc8, 0xc4, 0xcc, 0xc2, 0xd3, 0x88, 0xc0, 0xc2, 0xc9, 0xde,
        0xc3
    };
    static const struct {
        const uint8_t *enc;
        size_t len;
    } paths[] = {
        { path0, sizeof(path0) }, { path1, sizeof(path1) }, { path2, sizeof(path2) },
        { path3, sizeof(path3) }, { path4, sizeof(path4) }, { path5, sizeof(path5) },
        { path6, sizeof(path6) },
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        if (paths[i].len >= sizeof(tmp)) {
            continue;
        }
        guard_xor_dec(tmp, paths[i].enc, paths[i].len, GUARD_PATH_KEY);
        if (access(tmp, F_OK) == 0) {
            return 1;
        }
    }
    /* 2. ro.kernel.qemu == "1" */
    {
        static const uint8_t prop_enc[] = {
            0xd5, 0xc8, 0x89, 0xcc, 0xc2, 0xd5, 0xc9, 0xc2, 0xcb, 0x89, 0xd6, 0xc2, 0xca, 0xd2
        };
        char prop[24];
        char v[PROP_VALUE_MAX];
        guard_xor_dec(prop, prop_enc, sizeof(prop_enc), GUARD_PATH_KEY);
        if (__system_property_get(prop, v) > 0 && v[0] == '1') {
            return 1;
        }
    }
    /* 3. ro.hardware / ro.product.* 含模拟器标识 */
    {
        char hw_prop[16];
        char t0[12], t1[8], t2[8], t3[8], t4[8], t5[16], t6[12];
        static const uint8_t hw_enc[] = {
            0xd5, 0xc8, 0x89, 0xcf, 0xc6, 0xd5, 0xc3, 0xd0, 0xc6, 0xd5, 0xc2
        };
        static const uint8_t e0[] = { 0xc0, 0xc8, 0xcb, 0xc3, 0xc1, 0xce, 0xd4, 0xcf };
        static const uint8_t e1[] = { 0xd5, 0xc6, 0xc9, 0xc4, 0xcf, 0xd2 };
        static const uint8_t e2[] = { 0xd1, 0xc5, 0xc8, 0xdf };
        static const uint8_t e3[] = { 0xd3, 0xd3, 0xf1, 0xea };
        static const uint8_t e4[] = { 0xc9, 0xc8, 0xdf };
        static const uint8_t e5[] = {
            0xc6, 0xc9, 0xc3, 0xd5, 0xc8, 0xce, 0xc3, 0xf8, 0xdf, 0x9f, 0x91
        };
        static const uint8_t e6[] = { 0xd0, 0xce, 0xc9, 0xc3, 0xd5, 0xc8, 0xde, 0xc2 };
        guard_xor_dec(hw_prop, hw_enc, sizeof(hw_enc), GUARD_PATH_KEY);
        guard_xor_dec(t0, e0, sizeof(e0), GUARD_PATH_KEY);
        guard_xor_dec(t1, e1, sizeof(e1), GUARD_PATH_KEY);
        guard_xor_dec(t2, e2, sizeof(e2), GUARD_PATH_KEY);
        guard_xor_dec(t3, e3, sizeof(e3), GUARD_PATH_KEY);
        guard_xor_dec(t4, e4, sizeof(e4), GUARD_PATH_KEY);
        guard_xor_dec(t5, e5, sizeof(e5), GUARD_PATH_KEY);
        guard_xor_dec(t6, e6, sizeof(e6), GUARD_PATH_KEY);
        const char *hw_toks[] = { t0, t1, t2, t3, t4, t5, t6 };
        if (prop_has_token(hw_prop, hw_toks, sizeof(hw_toks) / sizeof(hw_toks[0]))) {
            return 1;
        }
    }
    {
        char model_prop[24];
        char m0[12], m1[24], m2[16], m3[8];
        static const uint8_t model_enc[] = {
            0xd5, 0xc8, 0x89, 0xd7, 0xd5, 0xc8, 0xc3, 0xd2, 0xc4, 0xd3, 0x89, 0xca, 0xc8, 0xc3, 0xc2, 0xcb
        };
        static const uint8_t e0[] = { 0xe2, 0xca, 0xd2, 0xcb, 0xc6, 0xd3, 0xc8, 0xd5 };
        static const uint8_t e1[] = {
            0xe6, 0xc9, 0xc3, 0xd5, 0xc8, 0xce, 0xc3, 0x87, 0xf4, 0xe3, 0xec, 0x87, 0xc5, 0xd2, 0xce, 0xcb,
            0xd3, 0x87, 0xc1, 0xc8, 0xd5
        };
        static const uint8_t e2[] = {
            0xd4, 0xc3, 0xcc, 0xf8, 0xc0, 0xd7, 0xcf, 0xc8, 0xc9, 0xc2
        };
        static const uint8_t e3[] = { 0xd1, 0xc5, 0xc8, 0xdf, 0x9f, 0x91 };
        guard_xor_dec(model_prop, model_enc, sizeof(model_enc), GUARD_PATH_KEY);
        guard_xor_dec(m0, e0, sizeof(e0), GUARD_PATH_KEY);
        guard_xor_dec(m1, e1, sizeof(e1), GUARD_PATH_KEY);
        guard_xor_dec(m2, e2, sizeof(e2), GUARD_PATH_KEY);
        guard_xor_dec(m3, e3, sizeof(e3), GUARD_PATH_KEY);
        const char *model_toks[] = { m0, m1, m2, m3 };
        if (prop_has_token(model_prop, model_toks,
                           sizeof(model_toks) / sizeof(model_toks[0]))) {
            return 1;
        }
    }
    return 0;
#else
    return 0;
#endif
}

/* ---------- 模块 W：指令计数 + 执行时序反单步 ---------- */
/*
 * 每次时序槽被调度时，测量自上次以来「窗口内执行的 VM 指令数」耗时。
 * 正常纯 VM 执行 640 条指令仅数十微秒；gdb 单步/断点每条 ~毫秒级，
 * 窗口会飙到数百毫秒。为避免调度抖动误报，连续 3 个异常窗口才触发。
 */
static int probe_exec_timing(axvm_guard_state_t *st)
{
    if (!st) {
        return 0;
    }
    uint64_t now = guard_mono_ns();
    uint64_t ticks = (uint64_t)st->dispatch_tick;
    if (st->timing_last_ns == 0 || ticks <= st->timing_last_tick) {
        /* 首次或计数回绕：仅建立锚点 */
        st->timing_last_ns = now;
        st->timing_last_tick = ticks;
        st->timing_strikes = 0;
        return 0;
    }
    uint64_t d_ns = (now >= st->timing_last_ns) ? (now - st->timing_last_ns) : 0;
    uint64_t d_insn = ticks - st->timing_last_tick;
    st->timing_last_ns = now;
    st->timing_last_tick = ticks;

    /*
     * JIT 快路径一次执行大量 VM 工作但 dispatch_tick 几乎不涨；
     * 表现为「极少 tick + 很长耗时」，不是调试器单步，跳过 strike。
     */
    if (d_insn > 0 && d_insn < 8u && d_ns > 1000000000ull) {
        st->timing_strikes = 0;
        return 0;
    }

    /* 阈值：窗口耗时 > 20ms 视为异常（正常远低于 1ms）。 */
    if (d_insn > 0 && d_ns > 20000000ull) {
        st->timing_strikes++;
    } else {
        st->timing_strikes = 0;
    }
    return (st->timing_strikes >= 3u) ? 1 : 0;
}

/* ---------- 公共 API ---------- */
int axvm_guard_enabled(void)
{
#if defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
    return 1;
#else
    return 0;
#endif
}

axvm_guard_state_t *axvm_guard_global(void)
{
    return &g_guard;
}

void axvm_guard_trip(axvm_guard_state_t *st, uint32_t flag)
{
    if (!st) {
        return;
    }
    st->flags |= flag;
    st->trip_count++;
}

void axvm_guard_trip_ctx(axvm_ctx_t *ctx, axvm_guard_state_t *st, uint32_t flag)
{
    axvm_guard_trip(st, flag);
    if (!ctx) {
        return;
    }
    ctx->halted = 1;
    ctx->ret_pending = 0;
    ctx->ret_val = 0;
    memset(ctx->x, 0, sizeof(ctx->x));
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    memset(ctx->v, 0, sizeof(ctx->v));
#endif
    ctx->nzcv = 0;
#if defined(AXVM_LAZY_DECRYPT) && AXVM_LAZY_DECRYPT
    axvm_lazy_reencrypt_active(ctx);
    axvm_lazy_wipe(ctx);
#endif
    axvm_stack_crypt_wipe(ctx);
    axvm_dynseed_wipe(ctx); /* 模块 M：触发防护时一并擦除 SessionSeed */
}

uint32_t axvm_guard_last_flags(const axvm_guard_state_t *st)
{
    return st ? st->flags : 0;
}

void axvm_guard_clear_flags(axvm_guard_state_t *st)
{
    if (st) {
        st->flags = 0;
    }
}

static inline uint64_t guard_chain_mix(uint64_t h, uint64_t v)
{
    /* 轻量可逆混合：不依赖大整数库 */
    h ^= v + 0x9E3779B97F4A7C15ULL;
    h = (h << 13) | (h >> 51);
    h ^= (h >> 7);
    return h;
}

void axvm_guard_observe_bl_native(axvm_guard_state_t *st, axvm_ctx_t *ctx,
                                  uint16_t slot, uint64_t pc_after)
{
#if !defined(AXVM_ENABLE_GUARD) || !AXVM_ENABLE_GUARD
    (void)st;
    (void)ctx;
    (void)slot;
    (void)pc_after;
    return;
#else
    if (!st) {
        return;
    }
    if (ctx) {
        ctx->chain_bl_seen = 1;
    }
    st->chain_hash = guard_chain_mix(st->chain_hash, (uint64_t)slot);
    st->chain_hash = guard_chain_mix(st->chain_hash, pc_after);
    st->chain_hash_last = st->chain_hash;
    return;
#endif
}

void axvm_guard_observe_ret(axvm_guard_state_t *st, axvm_ctx_t *ctx, uint64_t ret_val)
{
#if !defined(AXVM_ENABLE_GUARD) || !AXVM_ENABLE_GUARD
    (void)st;
    (void)ctx;
    (void)ret_val;
    return;
#else
    if (!st) {
        return;
    }
    (void)ret_val;

    if (!ctx || !ctx->chain_bl_seen) {
        return;
    }
    if (ctx->chain_baseline_set) {
        if (st->chain_hash != ctx->chain_baseline) {
            st->chain_hash_strikes++;
            axvm_guard_trip_ctx(ctx, st, AXVM_GUARD_CHAIN);
        }
    } else {
        ctx->chain_baseline = st->chain_hash;
        ctx->chain_baseline_set = 1;
    }
    return;
#endif
}

void axvm_guard_chain_begin_ctx(axvm_ctx_t *ctx, uint32_t entry_pc)
{
#if !defined(AXVM_ENABLE_GUARD) || !AXVM_ENABLE_GUARD
    (void)ctx;
    (void)entry_pc;
    return;
#else
    if (!ctx) {
        return;
    }
    ctx->chain_bl_seen = 0;
    axvm_guard_state_t *st = axvm_guard_global();
    if (!st) {
        return;
    }
    if (ctx->chain_baseline_set && ctx->chain_entry_pc != entry_pc) {
        ctx->chain_baseline_set = 0;
    }
    ctx->chain_entry_pc = entry_pc;
    uint64_t seed = 0xA5A5A5A5A5A5A5A5ULL;
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (axvm_dynseed_enabled() && ctx->session_seed_present) {
        seed = axvm_dynseed_session_mix(ctx);
    }
#endif
    seed ^= ((uint64_t)entry_pc << 32) | (uint64_t)entry_pc;
    axvm_guard_chain_reset(st, seed);
#endif
}

static int probe_chain_state(const axvm_guard_state_t *st)
{
    if (!st) {
        return 0;
    }
    /* 直接篡改 chain_hash 而未同步 chain_hash_last 时可检出 */
    return st->chain_hash != st->chain_hash_last;
}

void axvm_guard_chain_reset(axvm_guard_state_t *st, uint64_t seed)
{
    if (!st) {
        return;
    }
    st->chain_hash = seed ^ 0x9E3779B97F4A7C15ULL;
    st->chain_hash_last = st->chain_hash;
    st->chain_hash_strikes = 0;
}

uint64_t axvm_guard_chain_digest(const axvm_guard_state_t *st)
{
    return st ? st->chain_hash : 0;
}

static axvm_status_t guard_hit(axvm_ctx_t *ctx, axvm_guard_state_t *st, uint32_t flag)
{
    AXVM_LOGE("guard hit flag=0x%x pc=%llu", flag, ctx ? (unsigned long long)ctx->pc : 0ULL);
    axvm_guard_trip_ctx(ctx, st, flag);
    return AXVM_ERR_GUARD;
}

static axvm_status_t guard_probe_slot_run(axvm_ctx_t *ctx, axvm_guard_state_t *st, uint32_t slot)
{
    switch (slot) {
    case 0:
        if (probe_tracer_pid()) {
            return guard_hit(ctx, st, AXVM_GUARD_PTRACE);
        }
        break;
    case 1:
        if (probe_maps_frida()) {
            return guard_hit(ctx, st, AXVM_GUARD_FRIDA | AXVM_GUARD_MAPS);
        }
        break;
    case 2:
        if (probe_maps_inject()) {
            return guard_hit(ctx, st, AXVM_GUARD_INJECT | AXVM_GUARD_MAPS);
        }
        break;
    case 3:
        if (probe_ptrace_traceme(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_PT_LOOP | AXVM_GUARD_PTRACE);
        }
        break;
    case 4:
        if (probe_clock_skew(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_CLOCK);
        }
        break;
    case 5:
        if (probe_signal_tamper(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_SIGNAL);
        }
        break;
    case 6:
        if (probe_hook_integrity(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_HOOK);
        }
        break;
    case 7:
        if (probe_text_integrity(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_HOOK);
        }
        break;
    case 8:
        if (probe_emulator()) {
            return guard_hit(ctx, st, AXVM_GUARD_EMULATOR);
        }
        break;
    case 9:
#if defined(AXVM_JIT_CACHE) && AXVM_JIT_CACHE
        if (axvm_jit_runtime()) {
            st->timing_last_ns = guard_mono_ns();
            st->timing_last_tick = (uint64_t)st->dispatch_tick;
            st->timing_strikes = 0;
            return AXVM_OK;
        }
#endif
        if (probe_exec_timing(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_TIMING);
        }
        break;
    case 10:
        if (probe_chain_state(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_CHAIN);
        }
        break;
#if defined(AXVM_SVC_ANTIDEBUG) && AXVM_SVC_ANTIDEBUG
    case 11:
        if (axvm_guard_svc_probe_tracer()) {
            return guard_hit(ctx, st, AXVM_GUARD_SVC | AXVM_GUARD_PTRACE);
        }
        break;
#endif
    default:
        break;
    }
    return AXVM_OK;
}

axvm_status_t axvm_guard_init(axvm_guard_state_t *st)
{
    if (!st) {
        return AXVM_ERR_BAD_MAGIC;
    }
    memset(st, 0, sizeof(*st));
    st->clock_anchor = guard_mono_ns() ^ 0xA55AF00Du;
    st->chain_hash = st->clock_anchor ^ 0x9E3779B97F4A7C15ULL;
    st->chain_hash_last = st->chain_hash;
    st->chain_hash_strikes = 0;

#if defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    if (sigaction(SIGTRAP, NULL, &sa) == 0) {
        st->sig_trap_fn = guard_sig_handler(&sa);
        st->sig_trap_flags = sa.sa_flags;
    }
    if (sigaction(SIGINT, NULL, &sa) == 0) {
        st->sig_int_fn = guard_sig_handler(&sa);
        st->sig_int_flags = sa.sa_flags;
    }
    if (sigaction(SIGILL, NULL, &sa) == 0) {
        st->sig_ill_fn = guard_sig_handler(&sa);
        st->sig_ill_flags = sa.sa_flags;
    }

    guard_text_bind(st, (void *)(uintptr_t)axvm_run);
    guard_text_bind(st, (void *)(uintptr_t)axvm_guard_probe_dispatch);
    guard_text_bind(st, (void *)(uintptr_t)axvm_guard_probe_edge);

    (void)probe_ptrace_traceme(st);
#endif
    return AXVM_OK;
}

void axvm_guard_hook_bind(axvm_guard_state_t *st, void *addr)
{
#if defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
    if (!st || !addr || st->hook_count >= AXVM_GUARD_HOOK_SLOTS) {
        return;
    }
    uint32_t idx = st->hook_count++;
    st->hook_addr[idx] = addr;
    memcpy(st->hook_snap[idx], addr, 16);
#else
    (void)st;
    (void)addr;
#endif
}

/*
 * dispatch 主循环分散探针：每轮仅 1 项，probe_seq 轮转 8 槽。
 * 攻击者 patch 单一分支无法绕过全部检测面。
 */
axvm_status_t axvm_guard_probe_dispatch(axvm_ctx_t *ctx, axvm_guard_state_t *st)
{
#if !defined(AXVM_ENABLE_GUARD) || !AXVM_ENABLE_GUARD
    (void)ctx;
    (void)st;
    return AXVM_OK;
#else
    if (!st) {
        return AXVM_ERR_BAD_MAGIC;
    }
    if (st->pause_depth > 0) {
        return AXVM_OK;
    }
    /* 仅响应看门狗异步置位；其它 trip 标志由同步探针/bridge_enter 处理。 */
    if ((st->flags & AXVM_GUARD_WATCHDOG) != 0u) {
        return guard_hit(ctx, st, st->flags);
    }
    st->dispatch_tick++;
    if ((st->dispatch_tick % AXVM_GUARD_DISPATCH_PERIOD) != 0u) {
        return AXVM_OK;
    }
    uint32_t slot = st->probe_seq % AXVM_GUARD_PROBE_SLOTS;
    st->probe_seq++;

    return guard_probe_slot_run(ctx, st, slot);
#endif
}

axvm_status_t axvm_guard_probe_edge(axvm_ctx_t *ctx, axvm_guard_state_t *st)
{
#if !defined(AXVM_ENABLE_GUARD) || !AXVM_ENABLE_GUARD
    (void)ctx;
    (void)st;
    return AXVM_OK;
#else
    if (!st) {
        return AXVM_ERR_BAD_MAGIC;
    }
    if (st->pause_depth > 0) {
        return AXVM_OK;
    }
    st->edge_tick++;
    if ((st->edge_tick % AXVM_GUARD_EDGE_PERIOD) != 0u) {
        return AXVM_OK;
    }
    /*
     * 与 dispatch 轮转解耦：边缘路径使用独立序列并做相位偏移，
     * 即使 dispatch 入口被 patch，仍会在取指/访存路径触发探针。
     */
    uint32_t slot = (st->edge_seq + 3u) % AXVM_GUARD_PROBE_SLOTS;
    if (slot == 9u) {
        /* 时序探针依赖 dispatch_tick，边缘通道跳过以避免 JIT 场景误报。 */
        slot = 10u;
    }
    st->edge_seq++;
    return guard_probe_slot_run(ctx, st, slot);
#endif
}

/* BL_NATIVE 边界：另一组序号，偏重注入/调试器/maps */
axvm_status_t axvm_guard_probe_native(axvm_ctx_t *ctx, axvm_guard_state_t *st)
{
#if !defined(AXVM_ENABLE_GUARD) || !AXVM_ENABLE_GUARD
    (void)ctx;
    (void)st;
    return AXVM_OK;
#else
    if (!st) {
        return AXVM_ERR_BAD_MAGIC;
    }
    if (st->pause_depth > 0) {
        return AXVM_OK;
    }
    uint32_t slot = st->native_seq % 6u;
    st->native_seq++;

    switch (slot) {
    case 0:
        if (probe_tracer_pid() || probe_trace_state()) {
            return guard_hit(ctx, st, AXVM_GUARD_PTRACE);
        }
        break;
    case 1:
        if (probe_maps_frida() || probe_maps_inject()) {
            return guard_hit(ctx, st, AXVM_GUARD_MAPS);
        }
        break;
    case 2:
        if (probe_hook_integrity(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_HOOK);
        }
        break;
    case 3:
        if (probe_clock_skew(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_CLOCK);
        }
        break;
    case 4:
        if (probe_signal_tamper(st)) {
            return guard_hit(ctx, st, AXVM_GUARD_SIGNAL);
        }
        break;
    case 5:
        if (probe_emulator()) {
            return guard_hit(ctx, st, AXVM_GUARD_EMULATOR);
        }
        break;
    default:
        break;
    }
    return AXVM_OK;
#endif
}

/* bridge_enter 首轮快扫（仍分散为独立探针调用，非单一大函数） */
axvm_status_t axvm_guard_check(axvm_guard_state_t *st)
{
#if !defined(AXVM_ENABLE_GUARD) || !AXVM_ENABLE_GUARD
    (void)st;
    return AXVM_OK;
#else
    if (!st) {
        return AXVM_ERR_BAD_MAGIC;
    }
    if (probe_tracer_pid()) {
        axvm_guard_trip(st, AXVM_GUARD_PTRACE);
        return AXVM_ERR_GUARD;
    }
    if (probe_maps_frida()) {
        axvm_guard_trip(st, AXVM_GUARD_FRIDA);
        return AXVM_ERR_GUARD;
    }
    if (probe_maps_inject()) {
        axvm_guard_trip(st, AXVM_GUARD_INJECT);
        return AXVM_ERR_GUARD;
    }
    if (probe_ptrace_traceme(st)) {
        axvm_guard_trip(st, AXVM_GUARD_PT_LOOP);
        return AXVM_ERR_GUARD;
    }
#if defined(AXVM_SVC_ANTIDEBUG) && AXVM_SVC_ANTIDEBUG
    if (axvm_guard_svc_probe_tracer()) {
        axvm_guard_trip(st, AXVM_GUARD_SVC | AXVM_GUARD_PTRACE);
        return AXVM_ERR_GUARD;
    }
#endif
    return AXVM_OK;
#endif
}

void axvm_guard_ensure_init(void)
{
    if (!g_guard_inited) {
        axvm_guard_init(&g_guard);
        g_guard_inited = 1;
    }
#if defined(AXVM_WATCHDOG) && AXVM_WATCHDOG
    axvm_watchdog_start();
#endif
}

int axvm_guard_probe_emulator_live(void)
{
    return probe_emulator();
}

int axvm_guard_timing_mechanism_armed(const axvm_guard_state_t *st)
{
    return st && st->timing_last_ns != 0;
}

int axvm_guard_timing_selftest(axvm_guard_state_t *st)
{
    if (!st) {
        return 1;
    }
    st->timing_strikes = 0;
    for (int i = 0; i < 3; ++i) {
        st->timing_last_ns = guard_mono_ns() - 30000000ull;
        st->timing_last_tick = (uint64_t)(i * 1000u);
        st->dispatch_tick = (uint64_t)((i + 1) * 1000u);
        probe_exec_timing(st);
    }
    return (st->timing_strikes >= 3u) ? 0 : 2;
}

void axvm_guard_timing_anchor_reset(axvm_guard_state_t *st)
{
    if (!st) {
        return;
    }
    st->timing_strikes = 0;
    st->timing_last_ns = 0;
    st->timing_last_tick = 0;
}

void axvm_guard_pause(axvm_guard_state_t *st)
{
    if (!st) {
        return;
    }
    st->pause_depth++;
}

void axvm_guard_resume(axvm_guard_state_t *st)
{
    if (!st || st->pause_depth == 0) {
        return;
    }
    st->pause_depth--;
}
