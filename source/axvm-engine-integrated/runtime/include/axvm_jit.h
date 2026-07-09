#ifndef AXVM_JIT_H
#define AXVM_JIT_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 J — 轻量热点 BasicBlock JIT 缓存
 *
 * 设计要点：
 *  1. 纯旁路优化：命中已编译热块则跳入原生桩执行，否则原样落回解释器。
 *     绝不改变解释器指令语义、Module G 懒解密、Module C 栈加密。
 *  2. 以块入口 PC(相对 code_base) 为键统计热度；超过阈值触发编译。
 *  3. 编译目标为 32 字节对齐 BasicBlock 内的直线整型指令序列，
 *     遇到控制流/访存/原生调用/不支持指令即终止该桩（分支仍由解释器处理）。
 *  4. 桩入口把用到的 VM 虚拟寄存器 x0-x30 从 ctx->x[] 载入真实 x 寄存器，
 *     直线执行后写回 ctx->x[]、ctx->nzcv、ctx->pc，再返回解释器。
 *  5. 编译码页 mmap 匿名 RX(W^X)；每桩存哈希，执行前校验防篡改。
 *
 * 编译期开关 AXVM_JIT_CACHE：关闭时全部降级为零开销空桩（纯解释器）。
 */

/* 运行时查询开关状态：1=JIT 编译在编且当前主机可执行原生桩 */
int axvm_jit_enabled(void);

/*
 * 运行时软开关(便于单二进制内 ON/OFF 基准对比)：
 * off 时 axvm_jit_maybe_run 恒返回 0，直线落回解释器；已编译桩保留，可再启用。
 * 与编译期 AXVM_JIT_CACHE 正交：编译期关闭时本开关无意义。
 */
void axvm_jit_set_runtime(int on);
int  axvm_jit_runtime(void);

/* 实例生命周期 */
void axvm_jit_init(axvm_ctx_t *ctx);
void axvm_jit_destroy(axvm_ctx_t *ctx);

/*
 * dispatch 主循环钩子：在取指前调用。
 * 返回 1 表示已就地执行了当前 PC 的 JIT 桩（ctx 已更新，调用方应回到循环头）；
 * 返回 0 表示未执行（冷块/未编译/不支持），调用方按解释器正常取指。
 */
int axvm_jit_maybe_run(axvm_ctx_t *ctx);

/*
 * 导出编译入口(供 gdb 断点/日志)：为 rel_pc 处块编译原生桩。
 * 返回 0 成功，非 0 表示不可编译(已标记失败，后续不再重试)。
 */
int axvm_jit_compile_block(axvm_ctx_t *ctx, uint32_t rel_pc);

/* 调试观测 */
uint64_t axvm_jit_region_addr(const axvm_ctx_t *ctx);  /* RX 码页基址 */
uint32_t axvm_jit_compiled_count(const axvm_ctx_t *ctx);
uint32_t axvm_jit_hit_count(const axvm_ctx_t *ctx);

/* Phase 3：JIT 硬化（SessionSeed 混合哈希 + 执行后码页封存） */
int axvm_jit_harden_enabled(void);
int axvm_jit_harden_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_JIT_H */
