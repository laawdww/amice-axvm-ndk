#include "axvm_dispatch_perm.h"
#include "axvm_dynseed.h"
#include "axvm_bytecode.h"
#include "axvm_ctx.h"
#include "axvm_bridge.h"

#include <string.h>

int axvm_dispatch_perm_enabled(void)
{
#if defined(AXVM_DISPATCH_PERM) && AXVM_DISPATCH_PERM
    return 1;
#else
    return 0;
#endif
}

#if defined(AXVM_DISPATCH_PERM) && AXVM_DISPATCH_PERM

static uint64_t disp_perm_next(uint64_t *st)
{
    uint64_t x = *st;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *st = x;
    return x;
}

void axvm_dispatch_perm_build(axvm_ctx_t *ctx, const uint8_t session_seed[32])
{
    if (!ctx || !session_seed) {
        return;
    }
    uint8_t subkey[32];
    axvm_dynseed_subkey(session_seed, AXVM_DYNSEED_PURPOSE_DISPATCH, subkey, sizeof(subkey));

    uint64_t s = 0;
    for (size_t i = 0; i < sizeof(subkey); ++i) {
        s = s * 1315423911u + (uint64_t)subkey[i] + 0xC2B2AE3D27D4EB4FULL;
    }

    for (uint16_t i = 0; i < 256; ++i) {
        ctx->dispatch_fwd[i] = (uint8_t)i;
    }
    for (int i = 255; i > 0; --i) {
        uint64_t r = disp_perm_next(&s);
        uint32_t j = (uint32_t)(r % (uint64_t)(i + 1));
        uint8_t t = ctx->dispatch_fwd[i];
        ctx->dispatch_fwd[i] = ctx->dispatch_fwd[j];
        ctx->dispatch_fwd[j] = t;
    }
    ctx->dispatch_perm_active = 1;

    volatile uint8_t *w = subkey;
    for (size_t i = 0; i < sizeof(subkey); ++i) {
        w[i] = 0;
    }
}

uint32_t axvm_dispatch_perm_signature(const axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->dispatch_perm_active) {
        return 0;
    }
    uint32_t h = 2166136261u;
    for (uint16_t i = 0; i < 256; ++i) {
        h ^= ctx->dispatch_fwd[i];
        h *= 16777619u;
    }
    return h;
}

void axvm_dispatch_perm_materialize(axvm_ctx_t *ctx, const void *const *table)
{
    if (!ctx || !table || !ctx->dispatch_perm_active || ctx->dispatch_ptr_ready) {
        return;
    }
    for (uint16_t i = 0; i < 256; ++i) {
        ctx->dispatch_ptr[ctx->dispatch_fwd[i]] = (void *)table[i];
    }
    ctx->dispatch_ptr_ready = 1;
}

int axvm_dispatch_perm_selftest(void)
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
    uint32_t sa = axvm_dispatch_perm_signature(a);
    uint32_t sb = axvm_dispatch_perm_signature(b);
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

void axvm_dispatch_perm_build(axvm_ctx_t *ctx, const uint8_t session_seed[32])
{
    (void)ctx;
    (void)session_seed;
}

uint32_t axvm_dispatch_perm_signature(const axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

void axvm_dispatch_perm_materialize(axvm_ctx_t *ctx, const void *const *table)
{
    (void)ctx;
    (void)table;
}

int axvm_dispatch_perm_selftest(void)
{
    return 0;
}

#endif
