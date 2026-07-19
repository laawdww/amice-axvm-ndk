#ifndef AXVM_ENTROPY_H
#define AXVM_ENTROPY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 M — 免 root 熵采集。
 *
 * 采集来源（均无需特权）：
 *   - /dev/urandom
 *   - getpid()、gettid()（Android 走 syscall __NR_gettid）
 *   - CLOCK_MONOTONIC 纳秒时间戳
 *   - ASLR 加载基址（dladdr / 回退 /proc/self/maps）
 *   - VM 栈随机偏移（调用方传入的 stack_base 指针地址）
 *
 * 采集结果作为 HMAC-SHA256 的消息输入，与 MasterSeed 派生 per-instance SessionSeed。
 */

#define AXVM_ENTROPY_MAX 64u

/*
 * 采集熵到 out（容量 cap）。stack_hint 可为 VM 栈基址（提供每实例地址随机性），
 * 允许为 NULL。返回写入字节数（<= cap）。
 */
size_t axvm_entropy_collect(void *stack_hint, uint8_t *out, size_t cap);

/* Open /dev/urandom without leaving the path as a contiguous .rodata literal. */
int axvm_open_urandom(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_ENTROPY_H */
