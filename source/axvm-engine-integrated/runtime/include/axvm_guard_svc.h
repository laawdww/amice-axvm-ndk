#ifndef AXVM_GUARD_SVC_H
#define AXVM_GUARD_SVC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Phase 3 — SVC 直连反调试（绕过 libc open/read/ptrace hook）
 *
 * 通过 ARM64 syscall 指令读取 /proc/self/status TracerPid，
 * 并在 guard 探针/看门狗中作为独立检测面使用。
 *
 * 依赖：AXVM_ENABLE_GUARD，仅 aarch64 Linux/Android。
 */

int axvm_guard_svc_enabled(void);

/* 1 = 检测到非零 TracerPid（调试器附加） */
int axvm_guard_svc_probe_tracer(void);

/* 0 = 自检通过（当前无调试器） */
int axvm_guard_svc_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_GUARD_SVC_H */
