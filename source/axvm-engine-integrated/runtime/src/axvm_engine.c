#include "axvm_engine.h"
#include "axvm_riscc.h"
#include "axvm.h"
#include "axvm_bytecode.h"

#include <string.h>

int axvm_multi_isa_enabled(void)
{
#if defined(AXVM_MULTI_ISA) && AXVM_MULTI_ISA
    return 1;
#else
    return 0;
#endif
}

uint32_t axvm_engine_default_id(void)
{
    return AXVM_ENGINE_A64;
}

#if defined(AXVM_MULTI_ISA) && AXVM_MULTI_ISA

static axvm_status_t run_riscc(axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->bytecode) {
        return AXVM_ERR_BAD_MAGIC;
    }
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    if ((hdr->flags & AXVM_BC_FLAG_RISCC) == 0) {
        return AXVM_ERR_BAD_INSN;
    }
    int perm = (hdr->flags & AXVM_BC_FLAG_RISCC_PERM) != 0;
    axvm_riscc_activate(ctx, perm);
    return axvm_run(ctx);
}

#endif

axvm_status_t axvm_engine_run(axvm_ctx_t *ctx, uint32_t engine_id)
{
    if (!ctx) {
        return AXVM_ERR_BAD_MAGIC;
    }
#if defined(AXVM_MULTI_ISA) && AXVM_MULTI_ISA
    if (engine_id == AXVM_ENGINE_RISCC) {
        return run_riscc(ctx);
    }
    ctx->riscc_active = 0;
#endif
    ctx->engine_id = AXVM_ENGINE_A64;
    return axvm_run(ctx);
}

void axvm_engine_riscc_activate(axvm_ctx_t *ctx)
{
    axvm_riscc_activate(ctx, 0);
}

int axvm_engine_riscc_selftest(void)
{
    return axvm_riscc_selftest();
}
