#ifndef AXVM_DISPATCH_PERM_H
#define AXVM_DISPATCH_PERM_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

int axvm_dispatch_perm_enabled(void);

void axvm_dispatch_perm_build(axvm_ctx_t *ctx, const uint8_t session_seed[32]);

uint32_t axvm_dispatch_perm_signature(const axvm_ctx_t *ctx);

void axvm_dispatch_perm_materialize(axvm_ctx_t *ctx, const void *const *table);

int axvm_dispatch_perm_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_DISPATCH_PERM_H */
