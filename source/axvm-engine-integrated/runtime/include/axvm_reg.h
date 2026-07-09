#ifndef AXVM_REG_H
#define AXVM_REG_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/* x0-x30 为通用寄存器文件；x31 为 XZR/WZR，只读恒 0，写入丢弃。 */
#define AXVM_REG_XZR 31u

static inline int axvm_reg_dst_ok(uint8_t rd)
{
    return rd < AXVM_REG_COUNT;
}

static inline int axvm_reg_src_ok(uint8_t r)
{
    return r <= AXVM_REG_XZR;
}

/* 模块 U：每实例寄存器置换 —— 逻辑寄存器 rd/rn/rm 映射到物理 ctx->x 下标 */
#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
static inline uint8_t axvm_reg_perm_phys(const axvm_ctx_t *ctx, uint8_t r)
{
    if (r == AXVM_REG_XZR) {
        return AXVM_REG_XZR;
    }
    if (!ctx || !ctx->reg_perm_active) {
        return r;
    }
    /* 字节码校验保证 r < AXVM_REG_COUNT（非 XZR） */
    return ctx->reg_perm[r];
}

static inline uint32_t axvm_reg_perm_signature(const axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->reg_perm_active) {
        return 0;
    }
    uint32_t h = 2166136261u;
    for (uint8_t i = 0; i < AXVM_REG_COUNT; ++i) {
        h ^= ctx->reg_perm[i];
        h *= 16777619u;
    }
    return h;
}
#endif

/* 读取源寄存器；XZR 恒 0。SP 通过 ctx->sp 影子，不使用 x[31]。 */
static inline uint64_t axvm_reg_read(const axvm_ctx_t *ctx, uint8_t r)
{
    if (r == AXVM_REG_XZR) {
        return 0;
    }
 #if defined(AXVM_REG_PERM) && AXVM_REG_PERM
    uint8_t pr = axvm_reg_perm_phys(ctx, r);
    return ctx->x[pr];
 #else
    return ctx->x[r];
 #endif
}

/* 写入目的寄存器；XZR 写入为 no-op。 */
static inline axvm_status_t axvm_reg_write(axvm_ctx_t *ctx, uint8_t rd, uint64_t v)
{
    if (rd == AXVM_REG_XZR) {
        return AXVM_OK;
    }
    if (!axvm_reg_dst_ok(rd)) {
        return AXVM_ERR_BAD_INSN;
    }
 #if defined(AXVM_REG_PERM) && AXVM_REG_PERM
    uint8_t pr = axvm_reg_perm_phys(ctx, rd);
    ctx->x[pr] = v;
 #else
    ctx->x[rd] = v;
 #endif
    return AXVM_OK;
}

/* 访存基址：rn==31 时使用 VM 栈指针影子。 */
static inline uint64_t axvm_reg_base(const axvm_ctx_t *ctx, uint8_t rn)
{
    if (rn == AXVM_REG_XZR) {
        return ctx->sp;
    }
    return axvm_reg_read(ctx, rn);
}

#ifdef __cplusplus
}
#endif

#endif /* AXVM_REG_H */
