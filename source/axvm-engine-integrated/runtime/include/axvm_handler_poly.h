#ifndef AXVM_HANDLER_POLY_H
#define AXVM_HANDLER_POLY_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Phase 3 — Handler 多态化（扩展模块 N dispatch_perm）
 *
 * 1. per-ctx SessionSeed 派生 XOR 掩码，dispatch_ptr[] 以密文形态驻留内存；
 * 2. 未实现 opcode 槽位映射到 8 组诱饵 handler（非直接暴露 bad_insn 地址）；
 * 3. 取指 dispatch 时现场解密 handler 指针再 computed-goto。
 *
 * 依赖：AXVM_DISPATCH_PERM + AXVM_DYNAMIC_SEED + computed goto。
 */

int axvm_handler_poly_enabled(void);

void axvm_handler_poly_build(axvm_ctx_t *ctx, const uint8_t session_seed[32]);

void axvm_handler_poly_apply(axvm_ctx_t *ctx, void *bad_insn,
                             const void *const decoys[8]);

void *axvm_handler_poly_resolve(const axvm_ctx_t *ctx, uint8_t slot);

uint32_t axvm_handler_poly_signature(const axvm_ctx_t *ctx);

int axvm_handler_poly_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_HANDLER_POLY_H */
