#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "axvm.h"
#include "axvm_guard.h"
#include "axvm_pack.h"
#include "axvm_strcrypt.h"
#include "axvm_sample_bc.h"
#include "axvm_bench_bc.h"
#include "axvm_crypt.h"
#include "axvm_mem_guard.h"
#include "axvm_stext.h"
#include "axvm_reg.h"
#include "axvm_nested.h"
#include "axvm_engine.h"
#include "axvm_dispatch_perm.h"
#include "axvm_handler_poly.h"
#include "axvm_lazy_pf.h"
#include "axvm_guard_svc.h"
#include "axvm_watchdog.h"
#include "axvm_jit.h"
#include "axvm_dynseed.h"
#include "axvm_hmac.h"
#include "axvm_log.h"

#if defined(__ANDROID__)
#include <android/log.h>
#endif

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
#include "axvm_sample_fp_bc.h"
#endif

static axvm_ctx_t *g_ctx;
static axvm_ctx_t *g_bench_ctx;
static uint8_t g_bc_buf[AXVM_SAMPLE_BL_NATIVE_BC_SIZE];
static uint8_t g_bench_buf[AXVM_BENCH_LOOP_BC_SIZE];
static int g_jni_register_natives_done;

static uint64_t native_add_impl(uint64_t a, uint64_t b)
{
    return a + b;
}

/* ===================== 模块 AA：JNI 参数与对象完整性校验 =====================
 * 校验 Java 侧传入的引用参数（数组 / 字符串）是否合法且未被中间人（Frida 等）
 * 伪造或篡改。返回 0 表示全部合法；非 0 为按位异常标志。
 * 无 JNIEnv（纯 native / XP 注入场景）自动旁路。 */
#if !defined(AXVM_JNI_GUARD)
#define AXVM_JNI_GUARD 1
#endif

#define AXVM_AA_ARR_NULL      0x01u /* 期望非空数组却为 NULL */
#define AXVM_AA_ARR_LEN       0x02u /* 数组长度非法（<=0 或越界） */
#define AXVM_AA_ARR_REFTYPE   0x04u /* 数组引用类型非法（伪造句柄） */
#define AXVM_AA_ARR_INCONSIS  0x08u /* 两次独立读取内容不一致（被 hook 拦截） */
#define AXVM_AA_STR_NULL      0x10u /* 期望非空字符串却为 NULL */
#define AXVM_AA_STR_UTF       0x20u /* UTF 解码 / 长度自洽性失败 */
#define AXVM_AA_STR_REFTYPE   0x40u /* 字符串引用类型非法 */
#define AXVM_AA_ENV_BAD       0x80u /* JNIEnv 表异常 */
#define AXVM_AA_SCALAR_BAD    0x100u /* 标量参数指纹异常 */

#if AXVM_JNI_GUARD
static uint32_t aa_fnv1a(const uint8_t *p, size_t n)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static int aa_ref_ok(JNIEnv *env, jobject o)
{
    jobjectRefType t = (*env)->GetObjectRefType(env, o);
    return (t == JNILocalRefType || t == JNIGlobalRefType || t == JNIWeakGlobalRefType);
}

static uint32_t aa_check_array(JNIEnv *env, jbyteArray arr)
{
    if (arr == NULL) {
        return AXVM_AA_ARR_NULL;
    }
    uint32_t bad = 0;
    if (!aa_ref_ok(env, (jobject)arr)) {
        bad |= AXVM_AA_ARR_REFTYPE;
    }
    jsize n = (*env)->GetArrayLength(env, arr);
    if (n <= 0 || n > (1 << 24)) {
        return bad | AXVM_AA_ARR_LEN;
    }
    /* 两次独立 region 读取并比对哈希：中间人若非确定性伪造数据将暴露。 */
    uint8_t *b1 = (uint8_t *)malloc((size_t)n);
    uint8_t *b2 = (uint8_t *)malloc((size_t)n);
    if (b1 && b2) {
        (*env)->GetByteArrayRegion(env, arr, 0, n, (jbyte *)b1);
        (*env)->GetByteArrayRegion(env, arr, 0, n, (jbyte *)b2);
        if (aa_fnv1a(b1, (size_t)n) != aa_fnv1a(b2, (size_t)n)) {
            bad |= AXVM_AA_ARR_INCONSIS;
        }
    }
    free(b1);
    free(b2);
    return bad;
}

static uint32_t aa_check_string(JNIEnv *env, jstring s)
{
    if (s == NULL) {
        return AXVM_AA_STR_NULL;
    }
    uint32_t bad = 0;
    if (!aa_ref_ok(env, (jobject)s)) {
        bad |= AXVM_AA_STR_REFTYPE;
    }
    const char *u = (*env)->GetStringUTFChars(env, s, NULL);
    if (!u) {
        return bad | AXVM_AA_STR_UTF;
    }
    jsize ulen = (*env)->GetStringUTFLength(env, s);
    if (ulen < 0 || (jsize)strlen(u) != ulen) {
        bad |= AXVM_AA_STR_UTF;
    }
    (*env)->ReleaseStringUTFChars(env, s, u);
    return bad;
}

static uint32_t aa_check_env(JNIEnv *env)
{
    if (!env) {
        return 0;
    }
    if ((*env)->GetVersion(env) < JNI_VERSION_1_4) {
        return AXVM_AA_ENV_BAD;
    }
    return 0;
}

static uint32_t aa_guard_vm_scalars(JNIEnv *env, jlong a, jlong b)
{
    uint32_t bad = aa_check_env(env);
    uint64_t ua = (uint64_t)a;
    uint64_t ub = (uint64_t)b;
    uint32_t h = aa_fnv1a((const uint8_t *)&ua, sizeof(ua));
    h ^= aa_fnv1a((const uint8_t *)&ub, sizeof(ub));
    if (h == 0u && (ua != 0 || ub != 0)) {
        bad |= AXVM_AA_SCALAR_BAD;
    }
    return bad;
}
#endif /* AXVM_JNI_GUARD */

/*
 * 模块 Y：调用链哈希完整性自检。
 * 同一 BL_NATIVE 字节码：固定种子两次执行摘要应相等（确定性），
 * 注入一次伪造调用后摘要应变化（可检出链篡改）。返回 0=PASS。
 */
static uint64_t chain_run_once_jni(uint64_t seed, int inject_fake, uint64_t *rv_out)
{
    uint8_t buf[AXVM_SAMPLE_BL_NATIVE_BC_SIZE];
    memcpy(buf, g_axvm_sample_bl_native_bc, sizeof(buf));
    ((axvm_bc_header_t *)buf)->checksum = axvm_bc_checksum(buf, sizeof(buf));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, buf, sizeof(buf)) != AXVM_OK) {
        return 0;
    }
    axvm_bridge_register_native(ctx, (void *)native_add_impl);
    axvm_guard_ensure_init();
    axvm_guard_clear_flags(axvm_guard_global());
    axvm_bridge_enter(ctx);
    uint64_t args[2] = { 41, 1 };
    axvm_ctx_bind_args(ctx, args, 2);

    axvm_guard_state_t *g = axvm_guard_global();
    axvm_guard_chain_reset(g, seed);
    if (inject_fake) {
        axvm_guard_observe_bl_native(g, ctx, 0x1234, 0xDEADBEEFULL);
    }
    ctx->pc = 0;
    axvm_run(ctx);
    uint64_t rv = ctx->ret_val;
    uint64_t digest = axvm_guard_chain_digest(g);
    axvm_ctx_destroy(ctx);
    if (rv_out) {
        *rv_out = rv;
    }
    return digest;
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmChainHashSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    if (!axvm_guard_enabled()) {
        return 0; /* guard 关闭：机制空操作，视为通过 */
    }
    const uint64_t seed = 0x0BADF00DCAFEBABEULL;
    uint64_t rvA = 0, rvB = 0, rvC = 0;
    uint64_t dA = chain_run_once_jni(seed, 0, &rvA);
    uint64_t dB = chain_run_once_jni(seed, 0, &rvB);
    uint64_t dC = chain_run_once_jni(seed, 1, &rvC);
    int ok = (dA == dB) && (dA != 0) && (dC != dA)
             && rvA == 42 && rvB == 42 && rvC == 42;
    return ok ? 0 : 1;
}

/*
 * 模块 Y：同一 ctx 上二次 invoke，注入伪造 BL_NATIVE 事件后应触发 AXVM_GUARD_CHAIN。
 * 返回 trip 标志位（0=未触发, 非0=检测到链篡改）。
 */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmChainHashTripFlags(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    if (!axvm_guard_enabled()) {
        return 0;
    }

    uint8_t buf[AXVM_SAMPLE_BL_NATIVE_BC_SIZE];
    memcpy(buf, g_axvm_sample_bl_native_bc, sizeof(buf));
    ((axvm_bc_header_t *)buf)->checksum = axvm_bc_checksum(buf, sizeof(buf));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, buf, sizeof(buf)) != AXVM_OK) {
        return -1;
    }
    axvm_bridge_register_native(ctx, (void *)native_add_impl);
    axvm_guard_ensure_init();
    axvm_guard_state_t *g = axvm_guard_global();
    axvm_guard_clear_flags(g);

    axvm_bridge_enter(ctx);
    uint64_t args[2] = { 41, 1 };
    axvm_ctx_bind_args(ctx, args, 2);
    (void)axvm_invoke(ctx, 0); /* 首次执行：捕获 chain_baseline */

    axvm_bridge_enter(ctx);
    axvm_ctx_bind_args(ctx, args, 2);
    axvm_guard_chain_begin_ctx(ctx, 0);
    axvm_guard_observe_bl_native(g, ctx, 0x1234, 0xDEADBEEFULL); /* 伪造额外调用 */
    ctx->pc = 0;
    (void)axvm_run(ctx);

    uint32_t flags = axvm_guard_last_flags(g) & AXVM_GUARD_CHAIN;
    axvm_guard_clear_flags(g);
    axvm_ctx_destroy(ctx);
    return (jint)flags;
}

/* 模块 P：GOT/stub dispatch 指针加密 */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmGotCryptEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_got_crypt_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmGotCryptLeakProbe(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    axvm_rescan_modules();
    return axvm_loader_got_leak_probe();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmJniGuardEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
#if AXVM_JNI_GUARD
    return 1;
#else
    return 0;
#endif
}

/*
 * 模块 AA：对传入数组与字符串做完整性/合法性校验。
 * 返回 0 = 全部合法（正常路径）；非 0 = 检测到伪造/篡改（按位标志）。
 * env 为空或 AA 关闭时旁路返回 0。
 */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmJniGuardSelftest(JNIEnv *env, jobject thiz,
                                               jbyteArray data, jstring s)
{
    (void)thiz;
#if !AXVM_JNI_GUARD
    (void)env;
    (void)data;
    (void)s;
    return 0;
#else
    if (env == NULL) {
        return 0; /* 无 JNIEnv：自动关闭（XP/纯 native 场景） */
    }
    uint32_t bad = 0;
    bad |= aa_check_array(env, data);
    bad |= aa_check_string(env, s);
    return (jint)bad;
#endif
}

static int ensure_bl_ctx(void)
{
    if (g_ctx) {
        return 0;
    }
    memcpy(g_bc_buf, g_axvm_sample_bl_native_bc, sizeof(g_bc_buf));
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)g_bc_buf;
    hdr->checksum = axvm_bc_checksum(g_bc_buf, sizeof(g_bc_buf));
    if (axvm_ctx_create(&g_ctx, g_bc_buf, sizeof(g_bc_buf)) != AXVM_OK) {
        return -1;
    }
    axvm_bridge_register_native(g_ctx, (void *)native_add_impl);
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_init(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return ensure_bl_ctx();
}

JNIEXPORT jlong JNICALL
Java_com_axvm_demo_NativeVm_vmAdd(JNIEnv *env, jobject thiz, jlong a, jlong b)
{
    (void)thiz;
#if AXVM_JNI_GUARD
    if (env) {
        uint32_t bad = aa_guard_vm_scalars(env, a, b);
        if (bad != 0u) {
            return (jlong)(int64_t)(-(int64_t)bad);
        }
    }
#endif
    if (!g_ctx && ensure_bl_ctx() != 0) {
        return -1;
    }
    axvm_bridge_enter(g_ctx);
    uint64_t args[2] = { (uint64_t)a, (uint64_t)b };
    axvm_ctx_bind_args(g_ctx, args, 2);
    return (jlong)axvm_invoke(g_ctx, 0);
}

JNIEXPORT jlong JNICALL
Java_com_axvm_demo_NativeVm_nativeAdd(JNIEnv *env, jobject thiz, jlong a, jlong b)
{
    (void)env;
    (void)thiz;
    return (jlong)native_add_impl((uint64_t)a, (uint64_t)b);
}

JNIEXPORT jlong JNICALL
Java_com_axvm_demo_NativeVm_vmBlNativeAdd(JNIEnv *env, jobject thiz, jlong a, jlong b)
{
    (void)thiz;
#if AXVM_JNI_GUARD
    if (env) {
        uint32_t bad = aa_guard_vm_scalars(env, a, b);
        if (bad != 0u) {
            return (jlong)(int64_t)(-(int64_t)bad);
        }
    }
#endif
    if (ensure_bl_ctx() != 0) {
        return -1;
    }
    axvm_bridge_enter(g_ctx);
    uint64_t args[2] = { (uint64_t)a, (uint64_t)b };
    axvm_ctx_bind_args(g_ctx, args, 2);
    return (jlong)axvm_invoke(g_ctx, 0);
}

static int ensure_bench_ctx(void)
{
    if (g_bench_ctx) {
        return 0;
    }
    memcpy(g_bench_buf, g_axvm_bench_loop_bc, sizeof(g_bench_buf));
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)g_bench_buf;
    hdr->checksum = axvm_bc_checksum(g_bench_buf, sizeof(g_bench_buf));
    if (axvm_ctx_create(&g_bench_ctx, g_bench_buf, sizeof(g_bench_buf)) != AXVM_OK) {
        return -1;
    }
    return 0;
}

JNIEXPORT jlong JNICALL
Java_com_axvm_demo_NativeVm_vmBenchLoop(JNIEnv *env, jobject thiz, jint outer_runs)
{
    (void)env;
    (void)thiz;
    if (ensure_bench_ctx() != 0) {
        return -1;
    }
    int runs = outer_runs > 0 ? outer_runs : 1;

    axvm_guard_ensure_init();
    axvm_guard_timing_anchor_reset(axvm_guard_global());

    axvm_bridge_enter(g_bench_ctx);
    if (axvm_invoke(g_bench_ctx, 0) != AXVM_BENCH_LOOP_EXPECT) {
        return -2;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < runs; ++i) {
        axvm_bridge_enter(g_bench_ctx);
        (void)axvm_invoke(g_bench_ctx, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    int64_t us = (int64_t)(t1.tv_sec - t0.tv_sec) * 1000000
               + (int64_t)(t1.tv_nsec - t0.tv_nsec) / 1000;
    return (jlong)us;
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmDispatchMode(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_interp_dispatch_is_goto() ? 1 : 0;
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmStackCryptEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_stack_crypt_enabled();
}

JNIEXPORT jlong JNICALL
Java_com_axvm_demo_NativeVm_vmStackCryptKeyMix(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    if (ensure_bench_ctx() != 0) {
        return 0;
    }
    return (jlong)axvm_stack_crypt_key_mix(g_bench_ctx);
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmStackDumpProbe(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;

    uint8_t bc[AXVM_SAMPLE_MEM_BC_SIZE];
    memcpy(bc, g_axvm_sample_mem_bc, sizeof(bc));
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, sizeof(bc));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return -1;
    }

    axvm_bridge_enter(ctx);
    uint64_t rv = axvm_invoke(ctx, 0);
    if (rv != 0xCAFEBABEULL) {
        axvm_ctx_destroy(ctx);
        return -2;
    }
    int leak = axvm_stack_crypt_probe_plaintext(ctx, 0xCAFEBABEULL);
    axvm_ctx_destroy(ctx);
    return leak;
}

/* 模块 G：懒解密开关状态 */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmLazyEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_lazy_enabled();
}

/*
 * 模块 G：字节码明文泄露探测。
 * 创建 ctx 后比较代码区常驻字节与明文模板：1=明文泄露, 0=密文。
 */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmLazyDumpProbe(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;

    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, sizeof(bc));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return -1;
    }

    size_t coff = ((axvm_bc_header_t *)bc)->code_off;
    size_t csz = ((axvm_bc_header_t *)bc)->code_size;
    int leak = axvm_lazy_probe_plaintext(ctx, g_axvm_sample_add_bc + coff, csz);

    /* 验证懒解密下执行仍正确 */
    axvm_bridge_enter(ctx);
    uint64_t args[2] = {41, 1};
    axvm_ctx_bind_args(ctx, args, 2);
    uint64_t rv = axvm_invoke(ctx, 0);
    axvm_ctx_destroy(ctx);

    if (rv != 42) {
        return -2;
    }
    return leak;
}

/* 模块 H */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmGuardEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_guard_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmGuardTripFlags(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;

    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, sizeof(bc));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return -1;
    }

    axvm_guard_ensure_init();
    axvm_guard_clear_flags(axvm_guard_global());
    axvm_bridge_enter(ctx);
    uint64_t args[2] = {41, 1};
    axvm_ctx_bind_args(ctx, args, 2);
    (void)axvm_invoke(ctx, 0);
    uint32_t flags = axvm_guard_last_flags(axvm_guard_global());
    axvm_ctx_destroy(ctx);
    return (jint)flags;
}

/* 模块 I */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmIntegrityEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_integrity_enabled();
}

/*
 * 模块 I：完整性篡改自检。arm 一段 live 缓冲后篡改，返回 trip flags。
 * 未篡改基线为 0；篡改后非 0 => 校验生效。
 */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmIntegrityTripFlags(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;

    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, sizeof(bc));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return -1;
    }

    axvm_integrity_reset();
    axvm_integrity_arm_test(bc, sizeof(bc));
    bc[sizeof(bc) - 1] ^= 0xFF; /* arm 后篡改被监控段 */
    axvm_bridge_enter(ctx);
    uint64_t args[2] = {41, 1};
    axvm_ctx_bind_args(ctx, args, 2);
    (void)axvm_invoke(ctx, 0);
    uint32_t flags = axvm_integrity_trip_flags();
    axvm_ctx_destroy(ctx);
    axvm_integrity_reset();
    return (jint)flags;
}

/* 模块 K：字符串常量多轮解密 */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmStrcryptSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_strcrypt_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmStrcryptEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_strcrypt_enabled();
}

/* 模块 M：动态种子开关状态 */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmDynamicSeedEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_dynseed_enabled();
}

/*
 * 模块 M：返回新建 ctx 的 SessionSeed 64 位混合值（供 Java 侧比较两次调用是否互异）。
 * 每次调用创建独立 ctx，其 SessionSeed 由 HMAC-SHA256(MasterSeed, entropy) 派生，
 * 因此连续两次返回值应不同（DYNAMIC_SEED=ON 时）。
 */
JNIEXPORT jlong JNICALL
Java_com_axvm_demo_NativeVm_vmSessionSeedMix(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;

    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, sizeof(bc));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return 0;
    }
    uint64_t mix = axvm_dynseed_session_mix(ctx);
    axvm_ctx_destroy(ctx);
    return (jlong)mix;
}

/* 模块 J：热点 BasicBlock JIT 缓存 */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmJitEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_jit_enabled();
}

/*
 * 模块 J：同 ctx 内 JIT ON vs OFF 基准对比，返回加速比(OFF/ON) x100 的整数。
 * 语义正确性(rv==100000) 在两侧校验，任一侧不符返回 -1。
 */
JNIEXPORT jlong JNICALL
Java_com_axvm_demo_NativeVm_vmJitBenchCompare(JNIEnv *env, jobject thiz, jint outer_runs)
{
    (void)env;
    (void)thiz;

    uint8_t bc[AXVM_BENCH_LOOP_BC_SIZE];
    memcpy(bc, g_axvm_bench_loop_bc, sizeof(bc));
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, sizeof(bc));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return -1;
    }
    int runs = outer_runs > 0 ? outer_runs : 1;

    axvm_guard_ensure_init();
    axvm_guard_state_t *g = axvm_guard_global();
    axvm_guard_clear_flags(g);
    axvm_guard_timing_anchor_reset(g);
    axvm_guard_pause(g);

    axvm_jit_set_runtime(1);
    uint64_t rv_on = AXVM_BENCH_LOOP_EXPECT + 1;
    for (int i = 0; i < 8; ++i) {
        axvm_bridge_enter(ctx);
        rv_on = axvm_invoke(ctx, 0);
    }
    struct timespec a0, a1;
    clock_gettime(CLOCK_MONOTONIC, &a0);
    for (int i = 0; i < runs; ++i) {
        axvm_bridge_enter(ctx);
        (void)axvm_invoke(ctx, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &a1);
    int64_t ns_on = (int64_t)(a1.tv_sec - a0.tv_sec) * 1000000000
                  + (int64_t)(a1.tv_nsec - a0.tv_nsec);

    axvm_jit_set_runtime(0);
    axvm_bridge_enter(ctx);
    uint64_t rv_off = axvm_invoke(ctx, 0);
    struct timespec b0, b1;
    clock_gettime(CLOCK_MONOTONIC, &b0);
    for (int i = 0; i < runs; ++i) {
        axvm_bridge_enter(ctx);
        (void)axvm_invoke(ctx, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &b1);
    int64_t ns_off = (int64_t)(b1.tv_sec - b0.tv_sec) * 1000000000
                   + (int64_t)(b1.tv_nsec - b0.tv_nsec);
    axvm_jit_set_runtime(1);
    axvm_guard_resume(g);

    axvm_ctx_destroy(ctx);
    if (rv_on != AXVM_BENCH_LOOP_EXPECT || rv_off != AXVM_BENCH_LOOP_EXPECT || ns_on <= 0) {
        return -1;
    }
    return (jlong)((ns_off * 100) / ns_on); /* 加速比 x100 */
}

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
JNIEXPORT jdouble JNICALL
Java_com_axvm_demo_NativeVm_vmFadd(JNIEnv *env, jobject thiz, jdouble a, jdouble b)
{
    (void)env;
    (void)thiz;

    uint8_t bc[AXVM_SAMPLE_FADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_fadd_bc, sizeof(bc));
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, sizeof(bc));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return -1.0;
    }

    axvm_bridge_enter(ctx);
    double args[2] = { (double)a, (double)b };
    axvm_ctx_bind_fp_args(ctx, args, 2);
    uint64_t rv = axvm_invoke(ctx, 0);
    axvm_ctx_destroy(ctx);
    double out = 0.0;
    memcpy(&out, &rv, sizeof(out));
    return (jdouble)out;
}
#endif

/* ===================== 模块 U：寄存器置换自检 ===================== */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmRegPermEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
    return 1;
#else
    return 0;
#endif
}

static int reg_perm_run_add(axvm_ctx_t *ctx, uint32_t *sig_out)
{
    if (axvm_ctx_reset(ctx) != AXVM_OK) {
        return -1;
    }
    axvm_bridge_enter(ctx);
    uint64_t args[2] = { 41, 1 };
    axvm_ctx_bind_args(ctx, args, 2);
    uint64_t rv = axvm_invoke(ctx, 0);
#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
    if (sig_out) {
        *sig_out = axvm_reg_perm_signature(ctx);
    }
#else
    if (sig_out) {
        *sig_out = 0;
    }
#endif
    return (rv == 42) ? 0 : 1;
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmRegPermSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
#if !defined(AXVM_REG_PERM) || !AXVM_REG_PERM
    return 0;
#endif
    axvm_ctx_t *a = NULL;
    axvm_ctx_t *b = NULL;
    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
    if (axvm_ctx_create(&a, bc, sizeof(bc)) != AXVM_OK ||
        axvm_ctx_create(&b, bc, sizeof(bc)) != AXVM_OK) {
        axvm_ctx_destroy(a);
        axvm_ctx_destroy(b);
        return 1;
    }
    uint32_t sigA = 0, sigB = 0;
    int okA = reg_perm_run_add(a, &sigA);
    int okB = reg_perm_run_add(b, &sigB);
    axvm_ctx_destroy(a);
    axvm_ctx_destroy(b);
    if (okA != 0 || okB != 0) {
        return 2;
    }
    if (sigA == 0 || sigB == 0 || sigA == sigB) {
        return 3;
    }
    return 0;
}

/* ===================== 模块 Q：SessionSeed 分片字符串白盒 ===================== */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmStrcryptSessionSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return 1;
    }
    int rc = axvm_strcrypt_session_selftest(ctx);
    axvm_ctx_destroy(ctx);
    return (jint)rc;
}

/* ===================== 模块 N：多态流密码变体 ===================== */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmCryptVariant(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_crypt_variant();
}

/* ===================== 模块 S：JUNK 指令执行 ===================== */
static int junk_selftest_run(void)
{
    /*
     * LDRI64 x0,41 | JUNK pad=2 | LDRI64 x1,1 | ADD x0,x0,x1 | RET
     */
    uint8_t code[] = {
        AXOP_LDRI64, 0, 41, 0, 0, 0, 0, 0, 0, 0,
        AXOP_JUNK, 2, 0xAA, 0x55,
        AXOP_LDRI64, 1, 1, 0, 0, 0, 0, 0, 0, 0,
        AXOP_ADD_REG, 0, 0, 1,
        AXOP_RET,
    };
    uint8_t blob[128];
    memset(blob, 0, sizeof(blob));
    memcpy(blob, "AXV1", 4);
    uint32_t *u32 = (uint32_t *)blob;
    u32[1] = AXVM_VERSION;
    u32[3] = 40;
    u32[4] = (uint32_t)sizeof(code);
    u32[5] = 40 + (uint32_t)sizeof(code);
    u32[7] = 0;
    memcpy(blob + 40, code, sizeof(code));
    u32[8] = axvm_bc_checksum(blob, 40 + sizeof(code));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, blob, 40 + sizeof(code)) != AXVM_OK) {
        return 1;
    }
    axvm_bridge_enter(ctx);
    uint64_t rv = axvm_invoke(ctx, 0);
    axvm_ctx_destroy(ctx);
    return (rv == 42) ? 0 : 2;
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmJunkSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)junk_selftest_run();
}

/* ===================== 模块 X：mem_pool 页级 seal ===================== */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmMemGuardEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_mem_guard_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmMemGuardSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return 1;
    }
    int rc = axvm_mem_guard_selftest(ctx);
    int sealed = axvm_mem_guard_is_sealed(ctx);
    axvm_ctx_destroy(ctx);
    if (rc != 0) {
        return rc;
    }
    return sealed ? 0 : 4;
}

/* ===================== 模块 V/W：环境与时序探测 ===================== */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmEmulatorProbe(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    if (!axvm_guard_enabled()) {
        return 0;
    }
    return axvm_guard_probe_emulator_live();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmTimingGuardSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    if (!axvm_guard_enabled()) {
        return 0;
    }
    axvm_guard_ensure_init();
    axvm_guard_state_t *g = axvm_guard_global();
    if (axvm_guard_timing_selftest(g) != 0) {
        return 1;
    }
    return 0;
}

/* ===================== 模块 O：.text wipe 追踪 ===================== */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmStextEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_stext_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmStextWipedModules(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    axvm_scan_proc_maps();
    return (jint)axvm_stext_wiped_modules();
}

/* 模块 R：嵌套 VM */
static uint64_t nested_inner_vm(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                                uint64_t e, uint64_t f, uint64_t g, uint64_t h)
{
    (void)c;
    (void)d;
    (void)e;
    (void)f;
    (void)g;
    (void)h;
    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
    uint64_t args[2] = { a, b };
    return axvm_nested_invoke(NULL, bc, sizeof(bc), 0, args, 2);
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmNestedVmSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    uint8_t buf[AXVM_SAMPLE_BL_NATIVE_BC_SIZE];
    memcpy(buf, g_axvm_sample_bl_native_bc, sizeof(buf));
    ((axvm_bc_header_t *)buf)->checksum = axvm_bc_checksum(buf, sizeof(buf));
    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, buf, sizeof(buf)) != AXVM_OK) {
        return 1;
    }
    axvm_bridge_register_native(ctx, (void *)nested_inner_vm);
    axvm_bridge_enter(ctx);
    uint64_t args[2] = { 20, 22 };
    axvm_ctx_bind_args(ctx, args, 2);
    uint64_t rv = axvm_invoke(ctx, 0);
    axvm_ctx_destroy(ctx);
    return (rv == 42) ? 0 : 2;
}

extern int axvm_loader_dynsym_strip_probe(void);

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmDynsymStripProbe(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    axvm_scan_proc_maps();
    return (jint)axvm_loader_dynsym_strip_probe();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmDispatchPermEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_dispatch_perm_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmDispatchPermSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_dispatch_perm_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmHandlerPolyEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_handler_poly_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmHandlerPolySelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_handler_poly_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmLazyPfEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_lazy_pf_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmLazyPfSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_lazy_pf_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmGuardSvcEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_guard_svc_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmGuardSvcSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_guard_svc_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmWatchdogEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_watchdog_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmWatchdogSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_watchdog_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmJitHardenEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_jit_harden_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmJitHardenSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_jit_harden_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmCryptRoundtripSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_crypt_roundtrip_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmRisccSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_engine_riscc_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmRisccPermEnabled(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return axvm_riscc_perm_enabled();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmRisccPermSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_riscc_perm_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmInterpSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_interp_selftest();
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmNestedDepthSelftest(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
    axvm_ctx_t *root = NULL;
    if (axvm_ctx_create(&root, bc, sizeof(bc)) != AXVM_OK) {
        return 1;
    }
    axvm_ctx_t *child = NULL;
    int rc = 0;
    if (axvm_ctx_create_nested(root, &child, bc, sizeof(bc)) != AXVM_OK) {
        rc = 2;
    } else if (child->nest_depth != 1 || axvm_nested_depth(root) != 0) {
        rc = 3;
    }
    axvm_ctx_destroy(child);
    axvm_ctx_destroy(root);
    return rc;
}

/* ===================== 模块 AB：JNI_OnLoad + 跨层隧道 ===================== */
JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmJniRegisterNativesActive(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return g_jni_register_natives_done ? 1 : 0;
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmJniTunnelSelftest(JNIEnv *env, jobject thiz, jint plain)
{
    (void)env;
    (void)thiz;
    uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
    memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
    ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sizeof(bc)) != AXVM_OK) {
        return 1;
    }
    uint32_t tok = axvm_jni_tunnel_token(ctx, (uint32_t)plain);
    int rc = axvm_jni_tunnel_verify(ctx, tok, (uint32_t)plain);
    axvm_ctx_destroy(ctx);
    return (jint)rc;
}

JNIEXPORT jint JNICALL
Java_com_axvm_demo_NativeVm_vmDispatchEngineId(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)axvm_engine_default_id();
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    axvm_register_dispatch((void *)(uintptr_t)axvm_dispatch_ex);
#if defined(AXVM_DEMO_JNI) && AXVM_DEMO_JNI
#if defined(__ANDROID__)
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (!axvm_hmac_rfc4231_selftest()) {
        AXVM_LOGE("hmac rfc4231 selftest FAIL");
    }
    if (!axvm_hmac_apk_bind_vector_selftest()) {
        AXVM_LOGE("apk_bind vec selftest FAIL");
    }
    if (!axvm_dynseed_apk_bind_selftest()) {
        AXVM_LOGE("apk_bind selftest FAIL");
    }
#endif
#endif
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || !env) {
        return JNI_ERR;
    }
    static const JNINativeMethod methods[] = {
        { "init", "()I", (void *)Java_com_axvm_demo_NativeVm_init },
        { "vmAdd", "(JJ)J", (void *)Java_com_axvm_demo_NativeVm_vmAdd },
        { "nativeAdd", "(JJ)J", (void *)Java_com_axvm_demo_NativeVm_nativeAdd },
        { "vmBlNativeAdd", "(JJ)J", (void *)Java_com_axvm_demo_NativeVm_vmBlNativeAdd },
        { "vmBenchLoop", "(I)J", (void *)Java_com_axvm_demo_NativeVm_vmBenchLoop },
        { "vmDispatchMode", "()I", (void *)Java_com_axvm_demo_NativeVm_vmDispatchMode },
        { "vmStackCryptEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmStackCryptEnabled },
        { "vmStackCryptKeyMix", "()J", (void *)Java_com_axvm_demo_NativeVm_vmStackCryptKeyMix },
        { "vmStackDumpProbe", "()I", (void *)Java_com_axvm_demo_NativeVm_vmStackDumpProbe },
        { "vmLazyEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmLazyEnabled },
        { "vmLazyDumpProbe", "()I", (void *)Java_com_axvm_demo_NativeVm_vmLazyDumpProbe },
        { "vmGuardEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmGuardEnabled },
        { "vmGuardTripFlags", "()I", (void *)Java_com_axvm_demo_NativeVm_vmGuardTripFlags },
        { "vmIntegrityEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmIntegrityEnabled },
        { "vmIntegrityTripFlags", "()I", (void *)Java_com_axvm_demo_NativeVm_vmIntegrityTripFlags },
        { "vmStrcryptSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmStrcryptSelftest },
        { "vmStrcryptEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmStrcryptEnabled },
        { "vmDynamicSeedEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmDynamicSeedEnabled },
        { "vmSessionSeedMix", "()J", (void *)Java_com_axvm_demo_NativeVm_vmSessionSeedMix },
        { "vmJitEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmJitEnabled },
        { "vmJitBenchCompare", "(I)J", (void *)Java_com_axvm_demo_NativeVm_vmJitBenchCompare },
        { "vmChainHashSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmChainHashSelftest },
        { "vmChainHashTripFlags", "()I", (void *)Java_com_axvm_demo_NativeVm_vmChainHashTripFlags },
        { "vmJniGuardEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmJniGuardEnabled },
        { "vmJniGuardSelftest", "([BLjava/lang/String;)I",
          (void *)Java_com_axvm_demo_NativeVm_vmJniGuardSelftest },
        { "vmGotCryptEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmGotCryptEnabled },
        { "vmGotCryptLeakProbe", "()I", (void *)Java_com_axvm_demo_NativeVm_vmGotCryptLeakProbe },
        { "vmRegPermEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmRegPermEnabled },
        { "vmRegPermSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmRegPermSelftest },
        { "vmStrcryptSessionSelftest", "()I",
          (void *)Java_com_axvm_demo_NativeVm_vmStrcryptSessionSelftest },
        { "vmCryptVariant", "()I", (void *)Java_com_axvm_demo_NativeVm_vmCryptVariant },
        { "vmJunkSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmJunkSelftest },
        { "vmMemGuardEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmMemGuardEnabled },
        { "vmMemGuardSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmMemGuardSelftest },
        { "vmEmulatorProbe", "()I", (void *)Java_com_axvm_demo_NativeVm_vmEmulatorProbe },
        { "vmTimingGuardSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmTimingGuardSelftest },
        { "vmStextEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmStextEnabled },
        { "vmStextWipedModules", "()I", (void *)Java_com_axvm_demo_NativeVm_vmStextWipedModules },
        { "vmNestedVmSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmNestedVmSelftest },
        { "vmNestedDepthSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmNestedDepthSelftest },
        { "vmDynsymStripProbe", "()I", (void *)Java_com_axvm_demo_NativeVm_vmDynsymStripProbe },
        { "vmDispatchPermEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmDispatchPermEnabled },
        { "vmDispatchPermSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmDispatchPermSelftest },
        { "vmHandlerPolyEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmHandlerPolyEnabled },
        { "vmHandlerPolySelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmHandlerPolySelftest },
        { "vmLazyPfEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmLazyPfEnabled },
        { "vmLazyPfSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmLazyPfSelftest },
        { "vmGuardSvcEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmGuardSvcEnabled },
        { "vmGuardSvcSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmGuardSvcSelftest },
        { "vmWatchdogEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmWatchdogEnabled },
        { "vmWatchdogSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmWatchdogSelftest },
        { "vmJitHardenEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmJitHardenEnabled },
        { "vmJitHardenSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmJitHardenSelftest },
        { "vmCryptRoundtripSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmCryptRoundtripSelftest },
        { "vmRisccSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmRisccSelftest },
        { "vmRisccPermEnabled", "()I", (void *)Java_com_axvm_demo_NativeVm_vmRisccPermEnabled },
        { "vmRisccPermSelftest", "()I", (void *)Java_com_axvm_demo_NativeVm_vmRisccPermSelftest },
        { "vmJniRegisterNativesActive", "()I",
          (void *)Java_com_axvm_demo_NativeVm_vmJniRegisterNativesActive },
        { "vmJniTunnelSelftest", "(I)I", (void *)Java_com_axvm_demo_NativeVm_vmJniTunnelSelftest },
        { "vmDispatchEngineId", "()I", (void *)Java_com_axvm_demo_NativeVm_vmDispatchEngineId },
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
        { "vmFadd", "(DD)D", (void *)Java_com_axvm_demo_NativeVm_vmFadd },
#endif
    };
    jclass cls = (*env)->FindClass(env, "com/axvm/demo/NativeVm");
    if (!cls) {
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, cls, methods,
                                (jint)(sizeof(methods) / sizeof(methods[0]))) != 0) {
        return JNI_ERR;
    }
    g_jni_register_natives_done = 1;
#endif /* AXVM_DEMO_JNI */
    return JNI_VERSION_1_6;
}

