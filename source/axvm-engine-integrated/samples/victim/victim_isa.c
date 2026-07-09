#include "victim.h"

/*
 * 指令集覆盖：编译后由 axpack lift_insn_test 验证提升路径。
 */
__attribute__((visibility("default")))
uint64_t victim_neg(uint64_t x)
{
    return (uint64_t)(-(int64_t)x);
}

__attribute__((visibility("default")))
uint64_t victim_cmp_imm(uint64_t x)
{
    if (x > 5) {
        return 1;
    }
    return 0;
}

__attribute__((visibility("default")))
uint64_t victim_and_imm(uint64_t x)
{
    return x & 0xFF00FF00u;
}

__attribute__((visibility("default")))
uint64_t victim_asr(uint64_t x)
{
    return (uint64_t)((int64_t)x >> 4);
}

__attribute__((visibility("default")))
uint64_t victim_ldp_stp(uint64_t a, uint64_t b)
{
    uint64_t buf[2];
    __asm__ volatile("stp %0, %1, [%2]" :: "r"(a), "r"(b), "r"(buf) : "memory");
    uint64_t o0 = 0, o1 = 0;
    __asm__ volatile("ldp %0, %1, [%2]" : "=r"(o0), "=r"(o1) : "r"(buf) : "memory");
    return o0 ^ o1;
}

__attribute__((visibility("default")))
uint64_t victim_movn(void)
{
    uint64_t v = 0;
    __asm__ volatile("movn %0, #0xFFFF, lsl #16" : "=r"(v));
    return v;
}

__attribute__((visibility("default")))
uint64_t victim_ldr_reg(uint64_t *p)
{
    uint64_t idx = 2;
    uint64_t out = 0;
    __asm__ volatile("ldr %0, [%1, %2, lsl #3]" : "=r"(out) : "r"(p), "r"(idx));
    return out;
}
