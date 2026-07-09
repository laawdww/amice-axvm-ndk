#include "victim.h"

/* 模拟第三方 SO 敏感逻辑 — 将被 axpack 虚拟化 */

__attribute__((visibility("default")))
uint64_t victim_add(uint64_t a, uint64_t b)
{
    return a + b;
}

__attribute__((visibility("default")))
uint64_t victim_mul(uint64_t a, uint64_t b)
{
    uint64_t acc = 0;
    for (uint64_t i = 0; i < b; ++i) {
        acc += a;
    }
    return acc;
}

__attribute__((visibility("default")))
uint64_t victim_check(uint64_t key)
{
    uint64_t expect = 0xDEADBEEFCAFEBABEULL;
    if (key == expect) {
        return 0x1337;
    }
    return 0;
}
