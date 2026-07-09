#ifndef AXVM_FREG_H
#define AXVM_FREG_H

#include "axvm_ctx.h"

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM

#include <math.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AXVM_FREG_DZR 31u

static inline int axvm_freg_dst_ok(uint8_t vd)
{
    return vd < AXVM_FP_REG_COUNT;
}

static inline int axvm_freg_src_ok(uint8_t v)
{
    return v <= AXVM_FREG_DZR;
}

/* v31 在 AArch64 中可作零寄存器；读为 +0.0 */
static inline double axvm_freg_read(const axvm_ctx_t *ctx, uint8_t v)
{
    if (v == AXVM_FREG_DZR) {
        return 0.0;
    }
    return ctx->v[v];
}

static inline axvm_status_t axvm_freg_write(axvm_ctx_t *ctx, uint8_t vd, double val)
{
    if (vd == AXVM_FREG_DZR) {
        return AXVM_OK;
    }
    if (!axvm_freg_dst_ok(vd)) {
        return AXVM_ERR_BAD_INSN;
    }
    ctx->v[vd] = val;
    return AXVM_OK;
}

/* AArch64 FCMP 后 NZCV 编码（N Z C V 位于 nzcv 的 bit2..bit0 与 bit3） */
static inline uint64_t axvm_freg_read_bits(const axvm_ctx_t *ctx, uint8_t v)
{
    uint64_t bits = 0;
    if (v == AXVM_FREG_DZR) {
        return 0;
    }
    if (!axvm_freg_src_ok(v)) {
        return 0;
    }
    memcpy(&bits, &ctx->v[v], sizeof(bits));
    return bits;
}

static inline axvm_status_t axvm_freg_write_bits(axvm_ctx_t *ctx, uint8_t vd, uint64_t bits)
{
    if (vd == AXVM_FREG_DZR) {
        return AXVM_OK;
    }
    if (!axvm_freg_dst_ok(vd)) {
        return AXVM_ERR_BAD_INSN;
    }
    memcpy(&ctx->v[vd], &bits, sizeof(bits));
    return AXVM_OK;
}

static inline uint64_t axvm_freg_read_q_hi_bits(const axvm_ctx_t *ctx, uint8_t v)
{
    if (v == AXVM_FREG_DZR || !axvm_freg_src_ok(v)) {
        return 0;
    }
    return ctx->q_hi[v];
}

static inline axvm_status_t axvm_freg_write_q_hi_bits(axvm_ctx_t *ctx, uint8_t vd, uint64_t bits)
{
    if (vd == AXVM_FREG_DZR) {
        return AXVM_OK;
    }
    if (!axvm_freg_dst_ok(vd)) {
        return AXVM_ERR_BAD_INSN;
    }
    ctx->q_hi[vd] = bits;
    return AXVM_OK;
}

static inline void axvm_freg_set_cmp_flags(uint32_t *nzcv, double a, double b)
{
    uint32_t n = 0, z = 0, c = 0, v = 0;
    if (isnan(a) || isnan(b)) {
        c = 1;
        v = 1;
    } else if (a == b) {
        z = 1;
        c = 1;
    } else if (a < b) {
        n = 1;
    } else {
        c = 1;
    }
    *nzcv = (*nzcv & ~0xFu) | (n << 2) | (z << 1) | c | (v << 3);
}

#ifdef __cplusplus
}
#endif

#endif /* AXVM_FLOAT_VM */

#endif /* AXVM_FREG_H */
