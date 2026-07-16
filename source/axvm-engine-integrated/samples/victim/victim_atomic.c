#include "victim.h"

#include <stdatomic.h>
#include <stdint.h>

/* 强制发出 LDADD / CAS 等 LSE 原子指令，供真原子 lift 覆盖 */
uint64_t victim_atomic_add(uint64_t *p, uint64_t delta)
{
    return __atomic_fetch_add(p, delta, __ATOMIC_SEQ_CST);
}

uint64_t victim_atomic_cas(uint64_t *p, uint64_t expected, uint64_t desired)
{
    __atomic_compare_exchange_n(p, &expected, desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

uint64_t victim_atomic_swp(uint64_t *p, uint64_t neu)
{
    return __atomic_exchange_n(p, neu, __ATOMIC_SEQ_CST);
}

/* LDXR/STXR 自旋加一 */
uint64_t victim_atomic_inc_excl(uint64_t *p)
{
    uint64_t old, neu;
    int st;
    do {
        __asm__ __volatile__(
            "ldxr %0, [%2]\n"
            "add %1, %0, #1\n"
            "stxr %w3, %1, [%2]\n"
            : "=&r"(old), "=&r"(neu), "+r"(p), "=&r"(st)
            :
            : "memory");
    } while (st != 0);
    return old;
}

uint32_t victim_atomic_add32(uint32_t *p, uint32_t delta)
{
    return __atomic_fetch_add(p, delta, __ATOMIC_SEQ_CST);
}

uint32_t victim_atomic_cas32(uint32_t *p, uint32_t expected, uint32_t desired)
{
    __atomic_compare_exchange_n(p, &expected, desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

uint32_t victim_atomic_inc_excl32(uint32_t *p)
{
    uint32_t old, neu;
    int st;
    do {
        __asm__ __volatile__(
            "ldxr %w0, [%2]\n"
            "add %w1, %w0, #1\n"
            "stxr %w3, %w1, [%2]\n"
            : "=&r"(old), "=&r"(neu), "+r"(p), "=&r"(st)
            :
            : "memory");
    } while (st != 0);
    return old;
}
