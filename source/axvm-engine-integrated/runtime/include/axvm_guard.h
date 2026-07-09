#ifndef AXVM_GUARD_H
#define AXVM_GUARD_H

#include "axvm_types.h"

struct axvm_ctx;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 H — 反调试 / 反注入 / 反 Frida
 * 编译期由 AXVM_ENABLE_GUARD 控制；关闭时全部探测为空操作。
 */

#define AXVM_GUARD_FRIDA     0x0001u
#define AXVM_GUARD_PTRACE    0x0002u
#define AXVM_GUARD_MAPS      0x0004u
#define AXVM_GUARD_INJECT    0x0008u
#define AXVM_GUARD_CLOCK     0x0010u
#define AXVM_GUARD_SIGNAL    0x0020u
#define AXVM_GUARD_HOOK      0x0040u
#define AXVM_GUARD_PT_LOOP   0x0080u
#define AXVM_GUARD_EMULATOR  0x0100u /* 模块 V：模拟器/云手机环境 */
#define AXVM_GUARD_TIMING    0x0200u /* 模块 W：指令计数/执行时序异常 */
#define AXVM_GUARD_CHAIN     0x0400u /* 模块 Y：VM 调用链哈希完整性 */
#define AXVM_GUARD_WATCHDOG  0x0800u /* Phase3：看门狗后台探针 */
#define AXVM_GUARD_SVC       0x1000u /* Phase3：SVC 直连 TracerPid 探针 */

#define AXVM_GUARD_HOOK_SLOTS 8u
#define AXVM_GUARD_TEXT_SLOTS 4u
#define AXVM_GUARD_PROBE_SLOTS 12u
/* dispatch 探针周期：每 N 条指令执行 1 次轮转探针（仍覆盖全部检测面） */
#define AXVM_GUARD_DISPATCH_PERIOD 64u
/* 边缘探针周期：取指/内存访问等边缘路径每 N 次触发 1 次 */
#define AXVM_GUARD_EDGE_PERIOD 257u

typedef struct axvm_guard_state {
    uint32_t trip_count;
    uint32_t flags;
    uint32_t probe_seq;       /* dispatch 轮转探针序号 */
    uint32_t native_seq;      /* BL_NATIVE 边界探针序号 */
    uint32_t dispatch_tick;   /* dispatch 周期计数 */
    uint32_t edge_seq;        /* 边缘路径轮转探针序号 */
    uint32_t edge_tick;       /* 边缘路径周期计数 */
    uint32_t pause_depth;     /* >0 时临时暂停探针（基准/自检窗口） */
    uint64_t clock_anchor;
    int      ptrace_sealed;   /* PTRACE_TRACEME 已调用标记 */

    /* 模块 W：指令窗口执行时序（检测单步/断点拖慢） */
    uint64_t timing_last_ns;   /* 上次时序槽的时钟锚点 */
    uint64_t timing_last_tick; /* 上次时序槽的累计指令数 */
    uint32_t timing_strikes;   /* 连续异常窗口计数 */

    /* 模块 Y：调用链滚动哈希（仅依赖内部观测，避免要求 packer 注入基准值） */
    uint64_t chain_hash;
    uint64_t chain_hash_last;
    uint32_t chain_hash_strikes;

    /* 信号劫持基线（SIGTRAP/SIGINT/SIGILL） */
    void    *sig_trap_fn;
    void    *sig_int_fn;
    void    *sig_ill_fn;
    uint32_t sig_trap_flags;
    uint32_t sig_int_flags;
    uint32_t sig_ill_flags;

    /* 已注册 native 槽 prologue 快照（inline hook 检测） */
    void    *hook_addr[AXVM_GUARD_HOOK_SLOTS];
    uint8_t  hook_snap[AXVM_GUARD_HOOK_SLOTS][16];
    uint32_t hook_count;

    /* 运行时关键例程 prologue 快照（GOT/inline 篡改） */
    void    *text_addr[AXVM_GUARD_TEXT_SLOTS];
    uint8_t  text_snap[AXVM_GUARD_TEXT_SLOTS][16];
    uint32_t text_count;
} axvm_guard_state_t;

int axvm_guard_enabled(void);

axvm_guard_state_t *axvm_guard_global(void);

axvm_status_t axvm_guard_init(axvm_guard_state_t *st);

/* 分散探针：dispatch 主循环每轮执行 1 项（轮转，无集中大函数） */
axvm_status_t axvm_guard_probe_dispatch(struct axvm_ctx *ctx, axvm_guard_state_t *st);

/* BL_NATIVE 桥接入口：执行另一组边界探针 */
axvm_status_t axvm_guard_probe_native(struct axvm_ctx *ctx, axvm_guard_state_t *st);

/* 取指/访存等边缘路径探针（独立于 dispatch 序列）。 */
axvm_status_t axvm_guard_probe_edge(struct axvm_ctx *ctx, axvm_guard_state_t *st);

/* 注册 native 时绑定 prologue 基线 */
void axvm_guard_hook_bind(axvm_guard_state_t *st, void *addr);

void axvm_guard_trip(axvm_guard_state_t *st, uint32_t flag);

/* 触发防护：记录标志 + VM halt + 清空密钥/栈敏感数据 */
void axvm_guard_trip_ctx(struct axvm_ctx *ctx, axvm_guard_state_t *st, uint32_t flag);

uint32_t axvm_guard_last_flags(const axvm_guard_state_t *st);

/* 测试/JNI 探针前清除累计 trip 标志（保留 chain 状态） */
void axvm_guard_clear_flags(axvm_guard_state_t *st);

/* 兼容旧入口：bridge_enter 首轮全量快扫 */
axvm_status_t axvm_guard_check(axvm_guard_state_t *st);

/* 进程内单次初始化（bridge 首次 enter 调用） */
void axvm_guard_ensure_init(void);

/* 调用链观测点：BL_NATIVE / RET */
void axvm_guard_observe_bl_native(axvm_guard_state_t *st, struct axvm_ctx *ctx,
                                  uint16_t slot, uint64_t pc_after);
void axvm_guard_observe_ret(axvm_guard_state_t *st, struct axvm_ctx *ctx, uint64_t ret_val);

/* 模块 Y：每次 invoke 前重置链哈希种子（SessionSeed + entry_pc） */
void axvm_guard_chain_begin_ctx(struct axvm_ctx *ctx, uint32_t entry_pc);

/* 模块 Y：调用链哈希——将滚动哈希重置到固定种子（供确定性自检/基线捕获） */
void axvm_guard_chain_reset(axvm_guard_state_t *st, uint64_t seed);
/* 模块 Y：读取当前调用链滚动哈希摘要 */
uint64_t axvm_guard_chain_digest(const axvm_guard_state_t *st);

/* 模块 V/W：独立探测（不 trip，供自检/UI） */
int axvm_guard_probe_emulator_live(void);
int axvm_guard_timing_mechanism_armed(const axvm_guard_state_t *st);
int axvm_guard_timing_selftest(axvm_guard_state_t *st);

/* JIT 基准前重置时序锚点，避免长循环误触发 AXVM_GUARD_TIMING */
void axvm_guard_timing_anchor_reset(axvm_guard_state_t *st);
void axvm_guard_pause(axvm_guard_state_t *st);
void axvm_guard_resume(axvm_guard_state_t *st);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_GUARD_H */
