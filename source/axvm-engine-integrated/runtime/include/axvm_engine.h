#ifndef AXVM_ENGINE_H
#define AXVM_ENGINE_H

#include "axvm_ctx.h"
#include "axvm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AXVM_ENGINE_A64   0x000000A64u
#define AXVM_ENGINE_RISCC 0x00000B01u

int axvm_multi_isa_enabled(void);

uint32_t axvm_engine_default_id(void);

axvm_status_t axvm_engine_run(axvm_ctx_t *ctx, uint32_t engine_id);

void axvm_engine_riscc_activate(axvm_ctx_t *ctx);

int axvm_engine_riscc_selftest(void);

int axvm_riscc_perm_enabled(void);
int axvm_riscc_perm_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_ENGINE_H */
