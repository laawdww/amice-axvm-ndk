#ifndef AXVM_MEM_GUARD_H
#define AXVM_MEM_GUARD_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 模块 X：VM mem_pool 页级 seal/unseal，执行期外 PROT_NONE 防 dump */
int axvm_mem_guard_enabled(void);
void axvm_mem_guard_unseal(axvm_ctx_t *ctx);
void axvm_mem_guard_seal(axvm_ctx_t *ctx);
int axvm_mem_guard_is_sealed(const axvm_ctx_t *ctx);
int axvm_mem_guard_selftest(axvm_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_MEM_GUARD_H */
