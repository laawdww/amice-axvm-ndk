#include "victim.h"

/*
 * 模块 D 混合指令测试：循环分支 + 栈访存 + 位运算。
 * 编译后覆盖 LDUR/STUR、B.cond/CBZ、EOR/ADD 等路径。
 */
__attribute__((visibility("default")))
uint64_t victim_mixed(uint64_t n, uint64_t seed)
{
    volatile uint64_t slot = seed;
    uint64_t acc = 0;

    for (uint64_t i = 0; i < n; ++i) {
        if ((i & 1u) == 0) {
            acc += slot ^ i;
        } else {
            acc -= i;
        }
        slot = (slot << 1) | (slot >> 63);
    }

    /* 栈槽往返 */
    volatile uint64_t buf[2];
    buf[0] = acc;
    buf[1] = slot;
    return buf[0] + buf[1];
}
