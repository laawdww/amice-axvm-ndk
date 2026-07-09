#include "axvm_handler_poly.h"
#include "axvm_dynseed.h"
#include "axvm_bytecode.h"
#include "axvm_bridge.h"
#include "axvm_dispatch_perm.h"

#include <string.h>

int axvm_handler_poly_enabled(void)
{
#if defined(AXVM_HANDLER_POLY) && AXVM_HANDLER_POLY
    return 1;
#else
    return 0;
#endif
}

#if defined(AXVM_HANDLER_POLY) && AXVM_HANDLER_POLY

static uint64_t handler_poly_mix64(const uint8_t *buf, size_t n)
{
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= buf[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

void axvm_handler_poly_build(axvm_ctx_t *ctx, const uint8_t session_seed[32])
{
    if (!ctx || !session_seed) {
        return;
    }
    uint8_t sub[32];
    axvm_dynseed_subkey(session_seed, AXVM_DYNSEED_PURPOSE_HANDLER, sub, sizeof(sub));

    ctx->handler_ptr_mask = handler_poly_mix64(sub, sizeof(sub));
    if (ctx->handler_ptr_mask == 0) {
        ctx->handler_ptr_mask = 0xA5A5A5A5A5A5A5A5ULL;
    }
    ctx->handler_decoy_salt = (uint32_t)(handler_poly_mix64(sub + 8, 8) & 0xFFFFFFFFu);
    ctx->handler_poly_active = 1;
    ctx->handler_poly_applied = 0;

    volatile uint8_t *w = sub;
    for (size_t i = 0; i < sizeof(sub); ++i) {
        w[i] = 0;
    }
}

void axvm_handler_poly_apply(axvm_ctx_t *ctx, void *bad_insn,
                             const void *const decoys[8])
{
    if (!ctx || !bad_insn || !decoys || !ctx->handler_poly_active ||
        !ctx->dispatch_perm_active || !ctx->dispatch_ptr_ready || ctx->handler_poly_applied) {
        return;
    }

    for (uint16_t slot = 0; slot < 256; ++slot) {
        void *raw = ctx->dispatch_ptr[slot];
        if (raw == bad_insn) {
            uint32_t di = (slot + ctx->handler_decoy_salt) & 7u;
            raw = (void *)decoys[di];
            ctx->dispatch_ptr[slot] = raw;
        }
        ctx->dispatch_ptr[slot] =
            (void *)((uintptr_t)ctx->dispatch_ptr[slot] ^ (uintptr_t)ctx->handler_ptr_mask);
    }
    ctx->handler_poly_applied = 1;
}

void *axvm_handler_poly_resolve(const axvm_ctx_t *ctx, uint8_t slot)
{
    if (!ctx || !ctx->dispatch_ptr[slot]) {
        return NULL;
    }
    void *enc = ctx->dispatch_ptr[slot];
    if (!ctx->handler_poly_active || !ctx->handler_poly_applied) {
        return enc;
    }
    return (void *)((uintptr_t)enc ^ (uintptr_t)ctx->handler_ptr_mask);
}

uint32_t axvm_handler_poly_signature(const axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->handler_poly_active) {
        return 0;
    }
    uint32_t h = 2166136261u;
    h ^= (uint32_t)(ctx->handler_ptr_mask & 0xFFFFFFFFu);
    h *= 16777619u;
    h ^= (uint32_t)(ctx->handler_ptr_mask >> 32);
    h *= 16777619u;
    h ^= ctx->handler_decoy_salt;
    h *= 16777619u;
    return h;
}

int axvm_handler_poly_selftest(void)
{
    uint8_t bc[64];
    memset(bc, 0, sizeof(bc));
    memcpy(bc, "AXV1", 4);
    uint32_t *u32 = (uint32_t *)bc;
    u32[1] = AXVM_VERSION;
    u32[3] = 40;
    u32[7] = 0;
    uint8_t code[] = { AXOP_LDRI64, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, AXOP_RET };
    u32[4] = (uint32_t)sizeof(code);
    u32[5] = 40 + (uint32_t)sizeof(code);
    memcpy(bc + 40, code, sizeof(code));
    u32[8] = axvm_bc_checksum(bc, 40 + sizeof(code));

    axvm_ctx_t *a = NULL;
    axvm_ctx_t *b = NULL;
    if (axvm_ctx_create(&a, bc, 40 + sizeof(code)) != AXVM_OK ||
        axvm_ctx_create(&b, bc, 40 + sizeof(code)) != AXVM_OK) {
        axvm_ctx_destroy(a);
        axvm_ctx_destroy(b);
        return 1;
    }
    uint32_t sa = axvm_handler_poly_signature(a);
    uint32_t sb = axvm_handler_poly_signature(b);
    if (sa == 0 || sb == 0 || sa == sb) {
        axvm_ctx_destroy(a);
        axvm_ctx_destroy(b);
        return 2;
    }
    axvm_bridge_enter(a);
    uint64_t rv = axvm_invoke(a, 0);
    axvm_ctx_destroy(a);
    axvm_ctx_destroy(b);
    return (rv == 42) ? 0 : 3;
}

#else

void axvm_handler_poly_build(axvm_ctx_t *ctx, const uint8_t session_seed[32])
{
    (void)ctx;
    (void)session_seed;
}

void axvm_handler_poly_apply(axvm_ctx_t *ctx, void *bad_insn,
                             const void *const decoys[8])
{
    (void)ctx;
    (void)bad_insn;
    (void)decoys;
}

void *axvm_handler_poly_resolve(const axvm_ctx_t *ctx, uint8_t slot)
{
    (void)ctx;
    (void)slot;
    return NULL;
}

uint32_t axvm_handler_poly_signature(const axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

int axvm_handler_poly_selftest(void)
{
    return 0;
}

#endif
