#ifndef AXVM_EXCL_H
#define AXVM_EXCL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 每线程独占监视器：LDXR 武装，STXR 校验并清除。
 * 不跨核建模外部失效；同线程 LDXR→STXR 自旋锁路径语义正确。
 */
static __thread uintptr_t axvm_excl_addr;
static __thread int       axvm_excl_armed;

static inline void axvm_excl_mark(uintptr_t addr)
{
    axvm_excl_addr = addr;
    axvm_excl_armed = 1;
}

static inline int axvm_excl_check_clear(uintptr_t addr)
{
    int ok = axvm_excl_armed && (axvm_excl_addr == addr);
    axvm_excl_armed = 0;
    return ok;
}

#ifdef __cplusplus
}
#endif

#endif /* AXVM_EXCL_H */
