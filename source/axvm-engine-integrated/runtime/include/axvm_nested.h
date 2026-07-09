#ifndef AXVM_NESTED_H
#define AXVM_NESTED_H

#include "axvm_ctx.h"
#include "axvm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AXVM_NEST_MAX_DEPTH 8u

int axvm_nested_enabled(void);

axvm_status_t axvm_ctx_create_nested(axvm_ctx_t *parent, axvm_ctx_t **out,
                                   const uint8_t *bc, size_t bc_len);

uint8_t axvm_nested_depth(const axvm_ctx_t *ctx);

/* 模块 R：在 parent 子树内执行子字节码，返回 rv */
uint64_t axvm_nested_invoke(axvm_ctx_t *parent, const uint8_t *bc, size_t bc_len,
                            uint32_t entry_pc, const uint64_t *args, int argc);

uint64_t axvm_nested_vm_enter(axvm_ctx_t *parent, uint32_t child_off, uint8_t argc);

int axvm_nested_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_NESTED_H */
