#include "axvm_entropy.h"

#include <string.h>
#include <time.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#endif

static size_t put_bytes(uint8_t *out, size_t cap, size_t off,
                        const void *src, size_t n)
{
    if (off >= cap) {
        return off;
    }
    size_t room = cap - off;
    if (n > room) {
        n = room;
    }
    memcpy(out + off, src, n);
    return off + n;
}

static uint64_t entropy_mono_ns(void)
{
    struct timespec ts;
#if defined(CLOCK_MONOTONIC)
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    }
#endif
    return 0;
}

#if defined(__linux__) || defined(__ANDROID__)
static uint64_t entropy_aslr_base(void)
{
    Dl_info info;
    /* 用本函数地址反查所在模块加载基址（ASLR 每进程随机）。 */
    if (dladdr((void *)(uintptr_t)&entropy_aslr_base, &info) != 0 && info.dli_fbase) {
        return (uint64_t)(uintptr_t)info.dli_fbase;
    }
    /* 回退：读取 /proc/self/maps 第一行起始地址。 */
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        char buf[64];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            uint64_t v = 0;
            for (int i = 0; i < n && buf[i] != '-' && buf[i] != '\0'; ++i) {
                char ch = buf[i];
                uint32_t d;
                if (ch >= '0' && ch <= '9') {
                    d = (uint32_t)(ch - '0');
                } else if (ch >= 'a' && ch <= 'f') {
                    d = (uint32_t)(ch - 'a' + 10);
                } else {
                    break;
                }
                v = (v << 4) | d;
            }
            return v;
        }
    }
    return 0;
}
#endif

size_t axvm_entropy_collect(void *stack_hint, uint8_t *out, size_t cap)
{
    if (!out || cap == 0) {
        return 0;
    }
    size_t off = 0;

#if defined(__linux__) || defined(__ANDROID__)
    /* 1. /dev/urandom（主熵） */
    uint8_t rnd[16] = {0};
    int got_rnd = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t r = 0;
        while (r < sizeof(rnd)) {
            ssize_t k = read(fd, rnd + r, sizeof(rnd) - r);
            if (k <= 0) {
                break;
            }
            r += (size_t)k;
        }
        close(fd);
        got_rnd = (r == sizeof(rnd));
    }
    if (!got_rnd) {
        /* 宿主/受限环境回退：xorshift 保证仍有变化量 */
        static uint64_t s = 0x9E3779B97F4A7C15ULL;
        for (size_t i = 0; i < sizeof(rnd); ++i) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            rnd[i] = (uint8_t)(s >> (i & 7));
        }
    }
    off = put_bytes(out, cap, off, rnd, sizeof(rnd));

    /* 2. getpid / gettid */
    uint32_t pid = (uint32_t)getpid();
    off = put_bytes(out, cap, off, &pid, sizeof(pid));
#if defined(__NR_gettid)
    uint32_t tid = (uint32_t)syscall(__NR_gettid);
#else
    uint32_t tid = (uint32_t)pid;
#endif
    off = put_bytes(out, cap, off, &tid, sizeof(tid));

    /* 4. ASLR 加载基址 */
    uint64_t aslr = entropy_aslr_base();
    off = put_bytes(out, cap, off, &aslr, sizeof(aslr));
#else
    /* 非 Linux 宿主：仅时间戳 + 地址随机性 */
    uint32_t pid = 0;
    off = put_bytes(out, cap, off, &pid, sizeof(pid));
#endif

    /* 3. CLOCK_MONOTONIC ns */
    uint64_t ns = entropy_mono_ns();
    off = put_bytes(out, cap, off, &ns, sizeof(ns));

    /* 5. VM 栈随机偏移（栈基址指针） */
    uint64_t stk = (uint64_t)(uintptr_t)stack_hint;
    off = put_bytes(out, cap, off, &stk, sizeof(stk));

    return off;
}
