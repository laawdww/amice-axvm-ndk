#ifndef AXVM_RISCC_H
#define AXVM_RISCC_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Phase 3 — RISCC 多 ISA 线格式扩展（模块 T）
 *
 * 在 AXVM_MULTI_ISA 之上提供：
 *  1. 扩展 wire opcode 语义映射（整型常用子集）；
 *  2. 可选 SessionSeed 置换 wire 命名空间（AXVM_RISCC_PERM）；
 *  3. 运行时按 ctx 生成 wire<->AXVM 双向表。
 */

#define AXVM_RISCC_WIRE_BASE 0xA0u
#define AXVM_RISCC_WIRE_SLOTS 16u

int axvm_riscc_perm_enabled(void);

void axvm_riscc_activate(axvm_ctx_t *ctx, int use_session_perm);

uint8_t axvm_riscc_wire_for(const axvm_ctx_t *ctx, uint8_t axop);

uint32_t axvm_riscc_wire_signature(const axvm_ctx_t *ctx);

int axvm_riscc_selftest(void);
int axvm_riscc_perm_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_RISCC_H */
