#ifndef AXVM_WATCHDOG_H
#define AXVM_WATCHDOG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Phase 3 — 看门狗线程
 *
 * 后台周期执行 SVC TracerPid 探针；命中后通过全局 guard flags
 * 在下一次 dispatch 时触发 VM halt。
 *
 * 依赖：AXVM_ENABLE_GUARD + AXVM_SVC_ANTIDEBUG。
 */

int axvm_watchdog_enabled(void);

void axvm_watchdog_start(void);
void axvm_watchdog_stop(void);

uint32_t axvm_watchdog_ticks(void);

/* 0 = 线程已启动且累计 tick > 0 */
int axvm_watchdog_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_WATCHDOG_H */
