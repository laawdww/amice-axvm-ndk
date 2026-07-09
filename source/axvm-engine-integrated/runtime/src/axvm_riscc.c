#include "axvm_riscc.h"
#include "axvm_bytecode.h"
#include "axvm_bridge.h"
#include "axvm_dynseed.h"
#include "axvm_engine.h"
#include "axvm.h"

#include <string.h>

#if defined(AXVM_MULTI_ISA) && AXVM_MULTI_ISA

static const uint8_t riscc_semantic_ops[] = {
    AXOP_LDRI64,
    AXOP_ADD_REG,
    AXOP_SUB_REG,
    AXOP_MUL_REG,
    AXOP_MOV_REG,
    AXOP_RET,
};

#define RISCC_SEM_COUNT ((uint8_t)(sizeof(riscc_semantic_ops) / sizeof(riscc_semantic_ops[0])))

static uint64_t riscc_perm_next(uint64_t *st)
{
    uint64_t x = *st;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *st = x;
    return x;
}

static void riscc_build_static(axvm_ctx_t *ctx)
{
    for (uint16_t i = 0; i < 256; ++i) {
        ctx->riscc_wire_inv[i] = (uint8_t)i;
        ctx->riscc_wire_fwd[i] = 0;
    }
    for (uint8_t i = 0; i < RISCC_SEM_COUNT; ++i) {
        uint8_t wire = (uint8_t)(AXVM_RISCC_WIRE_BASE + i);
        uint8_t ax = riscc_semantic_ops[i];
        ctx->riscc_wire_inv[wire] = ax;
        ctx->riscc_wire_fwd[ax] = wire;
    }
}

#if defined(AXVM_RISCC_PERM) && AXVM_RISCC_PERM && defined(AXVM_DYNAMIC_SEED) && \
    AXVM_DYNAMIC_SEED

static void riscc_build_session(axvm_ctx_t *ctx)
{
    uint8_t sub[32];
    if (!ctx->session_seed_present) {
        riscc_build_static(ctx);
        return;
    }
    axvm_dynseed_subkey(ctx->session_seed, AXVM_DYNSEED_PURPOSE_RISCC,
                        sub, sizeof(sub));

    for (uint16_t i = 0; i < 256; ++i) {
        ctx->riscc_wire_inv[i] = (uint8_t)i;
        ctx->riscc_wire_fwd[i] = 0;
    }

    uint8_t slots[AXVM_RISCC_WIRE_SLOTS];
    for (uint8_t i = 0; i < AXVM_RISCC_WIRE_SLOTS; ++i) {
        slots[i] = (uint8_t)(AXVM_RISCC_WIRE_BASE + i);
    }

    uint64_t s = 0;
    for (size_t i = 0; i < sizeof(sub); ++i) {
        s = s * 1315423911u + (uint64_t)sub[i] + 0xC2B2AE3D27D4EB4FULL;
    }
    for (int i = (int)AXVM_RISCC_WIRE_SLOTS - 1; i > 0; --i) {
        uint64_t r = riscc_perm_next(&s);
        uint32_t j = (uint32_t)(r % (uint64_t)(i + 1));
        uint8_t t = slots[i];
        slots[i] = slots[j];
        slots[j] = t;
    }

    for (uint8_t i = 0; i < RISCC_SEM_COUNT; ++i) {
        uint8_t wire = slots[i];
        uint8_t ax = riscc_semantic_ops[i];
        ctx->riscc_wire_inv[wire] = ax;
        ctx->riscc_wire_fwd[ax] = wire;
    }

    volatile uint8_t *w = sub;
    for (size_t i = 0; i < sizeof(sub); ++i) {
        w[i] = 0;
    }
}

int axvm_riscc_perm_enabled(void)
{
    return 1;
}

#else

int axvm_riscc_perm_enabled(void)
{
    return 0;
}

#endif

void axvm_riscc_activate(axvm_ctx_t *ctx, int use_session_perm)
{
    if (!ctx) {
        return;
    }
#if defined(AXVM_RISCC_PERM) && AXVM_RISCC_PERM && defined(AXVM_DYNAMIC_SEED) && \
    AXVM_DYNAMIC_SEED
    if (use_session_perm && axvm_dynseed_enabled() && ctx->session_seed_present) {
        riscc_build_session(ctx);
    } else
#endif
    {
        riscc_build_static(ctx);
    }
    ctx->riscc_active = 1;
    ctx->engine_id = AXVM_ENGINE_RISCC;
}

uint8_t axvm_riscc_wire_for(const axvm_ctx_t *ctx, uint8_t axop)
{
    if (!ctx || !ctx->riscc_active) {
        return axop;
    }
    uint8_t w = ctx->riscc_wire_fwd[axop];
    return w ? w : axop;
}

uint32_t axvm_riscc_wire_signature(const axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->riscc_active) {
        return 0;
    }
    uint32_t h = 2166136261u;
    for (uint16_t i = AXVM_RISCC_WIRE_BASE;
         i < AXVM_RISCC_WIRE_BASE + AXVM_RISCC_WIRE_SLOTS; ++i) {
        h ^= ctx->riscc_wire_inv[i];
        h *= 16777619u;
    }
    return h;
}

static size_t riscc_emit_add42(axvm_ctx_t *ctx, uint8_t *code, size_t cap)
{
    if (!ctx || !code || cap < 25) {
        return 0;
    }
    size_t n = 0;
    uint8_t w;
    uint64_t imm;

    w = axvm_riscc_wire_for(ctx, AXOP_LDRI64);
    code[n++] = w;
    code[n++] = 0;
    imm = 40;
    memcpy(code + n, &imm, 8);
    n += 8;

    w = axvm_riscc_wire_for(ctx, AXOP_LDRI64);
    code[n++] = w;
    code[n++] = 1;
    imm = 2;
    memcpy(code + n, &imm, 8);
    n += 8;

    w = axvm_riscc_wire_for(ctx, AXOP_ADD_REG);
    code[n++] = w;
    code[n++] = 0;
    code[n++] = 0;
    code[n++] = 1;

    w = axvm_riscc_wire_for(ctx, AXOP_RET);
    code[n++] = w;
    return n;
}

static int riscc_build_blob(uint8_t *blob, size_t blob_cap, const uint8_t *code,
                            size_t code_len, uint32_t bc_flags, size_t *out_len)
{
    if (!blob || !code || blob_cap < 40 + code_len || !out_len) {
        return -1;
    }
    memset(blob, 0, blob_cap);
    memcpy(blob, "AXV1", 4);
    uint32_t *u32 = (uint32_t *)blob;
    u32[1] = AXVM_VERSION;
    u32[3] = 40;
    u32[4] = (uint32_t)code_len;
    u32[5] = 40 + (uint32_t)code_len;
    u32[2] = bc_flags;
    memcpy(blob + 40, code, code_len);
    u32[8] = axvm_bc_checksum(blob, 40 + code_len);
    *out_len = 40 + code_len;
    return 0;
}

static int riscc_invoke_blob(const uint8_t *blob, size_t blob_len, int expect_perm)
{
    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, blob, blob_len) != AXVM_OK) {
        return 1;
    }
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)blob;
    int perm = (hdr->flags & AXVM_BC_FLAG_RISCC_PERM) != 0;
    if (perm != expect_perm) {
        axvm_ctx_destroy(ctx);
        return 2;
    }
    axvm_bridge_enter(ctx);
    axvm_status_t st = axvm_engine_run(ctx, AXVM_ENGINE_RISCC);
    uint64_t rv = ctx->ret_val;
    int ok = (st == AXVM_OK && rv == 42 && ctx->engine_id == AXVM_ENGINE_RISCC
              && ctx->riscc_active);
    axvm_ctx_destroy(ctx);
    return ok ? 0 : 3;
}

int axvm_riscc_selftest(void)
{
    axvm_ctx_t *enc = NULL;
    uint8_t stub[64];
    size_t stub_len = 0;
    if (riscc_build_blob(stub, sizeof(stub), (const uint8_t[]){ AXOP_RET }, 1,
                         AXVM_BC_FLAG_RISCC, &stub_len) != 0) {
        return 1;
    }
    if (axvm_ctx_create(&enc, stub, stub_len) != AXVM_OK) {
        return 1;
    }
    axvm_riscc_activate(enc, 0);

    uint8_t code[32];
    size_t clen = riscc_emit_add42(enc, code, sizeof(code));
    axvm_ctx_destroy(enc);
    if (clen == 0) {
        return 2;
    }

    uint8_t blob[128];
    size_t blen = 0;
    if (riscc_build_blob(blob, sizeof(blob), code, clen, AXVM_BC_FLAG_RISCC,
                         &blen) != 0) {
        return 2;
    }
    return riscc_invoke_blob(blob, blen, 0);
}

int axvm_riscc_perm_selftest(void)
{
#if !defined(AXVM_RISCC_PERM) || !AXVM_RISCC_PERM
    return 0;
#endif
    axvm_ctx_t *a = NULL;
    axvm_ctx_t *b = NULL;
    uint8_t stub[64];
    size_t stub_len = 0;
    if (riscc_build_blob(stub, sizeof(stub), (const uint8_t[]){ AXOP_RET }, 1,
                         AXVM_BC_FLAG_RISCC | AXVM_BC_FLAG_RISCC_PERM,
                         &stub_len) != 0) {
        return 1;
    }
    if (axvm_ctx_create(&a, stub, stub_len) != AXVM_OK ||
        axvm_ctx_create(&b, stub, stub_len) != AXVM_OK) {
        axvm_ctx_destroy(a);
        axvm_ctx_destroy(b);
        return 1;
    }
    axvm_riscc_activate(a, 1);
    axvm_riscc_activate(b, 1);

    uint32_t sa = axvm_riscc_wire_signature(a);
    uint32_t sb = axvm_riscc_wire_signature(b);
    if (sa == 0 || sb == 0 || sa == sb) {
        axvm_ctx_destroy(a);
        axvm_ctx_destroy(b);
        return 2;
    }

    uint8_t code[32];
    size_t clen = riscc_emit_add42(a, code, sizeof(code));
    if (clen == 0) {
        axvm_ctx_destroy(a);
        axvm_ctx_destroy(b);
        return 3;
    }

    uint8_t blob[128];
    size_t blen = 0;
    if (riscc_build_blob(blob, sizeof(blob), code, clen,
                         AXVM_BC_FLAG_RISCC | AXVM_BC_FLAG_RISCC_PERM,
                         &blen) != 0) {
        axvm_ctx_destroy(a);
        axvm_ctx_destroy(b);
        return 3;
    }

    axvm_ctx_t *run = NULL;
    if (axvm_ctx_create(&run, blob, blen) != AXVM_OK) {
        axvm_ctx_destroy(a);
        axvm_ctx_destroy(b);
        return 4;
    }
    /* 与编码时使用的 SessionSeed 对齐，验证 per-session wire 置换可闭环执行。 */
    axvm_ctx_rebind_session_seed(run, a->session_seed);
    axvm_bridge_enter(run);
    axvm_status_t st = axvm_engine_run(run, AXVM_ENGINE_RISCC);
    uint64_t rv = run->ret_val;
    int rc = (st == AXVM_OK && rv == 42) ? 0 : 5;

    axvm_ctx_destroy(run);
    axvm_ctx_destroy(a);
    axvm_ctx_destroy(b);
    return rc;
}

#else

int axvm_riscc_perm_enabled(void)
{
    return 0;
}

void axvm_riscc_activate(axvm_ctx_t *ctx, int use_session_perm)
{
    (void)ctx;
    (void)use_session_perm;
}

uint8_t axvm_riscc_wire_for(const axvm_ctx_t *ctx, uint8_t axop)
{
    (void)ctx;
    return axop;
}

uint32_t axvm_riscc_wire_signature(const axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

int axvm_riscc_selftest(void)
{
    return 0;
}

int axvm_riscc_perm_selftest(void)
{
    return 0;
}

#endif
