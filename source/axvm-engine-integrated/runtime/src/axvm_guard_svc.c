#include "axvm_guard_svc.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/syscall.h>
#include <unistd.h>
#endif

int axvm_guard_svc_enabled(void)
{
#if defined(AXVM_SVC_ANTIDEBUG) && AXVM_SVC_ANTIDEBUG && defined(__aarch64__) && \
    (defined(__linux__) || defined(__ANDROID__))
    return 1;
#else
    return 0;
#endif
}

#if defined(AXVM_SVC_ANTIDEBUG) && AXVM_SVC_ANTIDEBUG && defined(__aarch64__) && \
    (defined(__linux__) || defined(__ANDROID__))

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

static long axvm_svc6(long n, long a0, long a1, long a2, long a3, long a4, long a5)
{
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    register long x5 asm("x5") = a5;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory", "cc");
    return x0;
}

static ssize_t axvm_svc_read(int fd, void *buf, size_t n)
{
    long r = axvm_svc6(__NR_read, fd, (long)(uintptr_t)buf, (long)n, 0, 0, 0);
    if (r < 0) {
        errno = (int)-r;
        return -1;
    }
    return (ssize_t)r;
}

static int axvm_svc_close(int fd)
{
    long r = axvm_svc6(__NR_close, fd, 0, 0, 0, 0, 0);
    if (r < 0) {
        errno = (int)-r;
        return -1;
    }
    return 0;
}

static int axvm_svc_openat(const char *path, int flags)
{
    long r = axvm_svc6(__NR_openat, AT_FDCWD, (long)(uintptr_t)path, flags, 0, 0, 0);
    if (r < 0) {
        errno = (int)-r;
        return -1;
    }
    return (int)r;
}

static int svc_parse_tracer_pid(const char *buf, size_t n)
{
    static const char key[] = "TracerPid:\t";
    size_t klen = sizeof(key) - 1u;
    if (n < klen) {
        return 0;
    }
    for (size_t i = 0; i + klen <= n; ++i) {
        if (memcmp(buf + i, key, klen) != 0) {
            continue;
        }
        const char *p = buf + i + klen;
        int pid = 0;
        while (p < buf + n && *p >= '0' && *p <= '9') {
            pid = pid * 10 + (*p - '0');
            ++p;
        }
        return pid;
    }
    return 0;
}

int axvm_guard_svc_probe_tracer(void)
{
    int fd = axvm_svc_openat("/proc/self/status", O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    char buf[2048];
    ssize_t n = axvm_svc_read(fd, buf, sizeof(buf));
    axvm_svc_close(fd);
    if (n <= 0) {
        return 0;
    }
  return svc_parse_tracer_pid(buf, (size_t)n) != 0;
}

int axvm_guard_svc_selftest(void)
{
    return axvm_guard_svc_probe_tracer() ? 1 : 0;
}

#else

int axvm_guard_svc_probe_tracer(void)
{
    return 0;
}

int axvm_guard_svc_selftest(void)
{
    return 0;
}

#endif
