#ifndef AXVM_JIT_EMIT_H
#define AXVM_JIT_EMIT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 J — 极简 A64 编码器（不引入 Keystone）。
 * 仅覆盖热块所需常用指令：mov/movz/movk、add/sub(shifted/imm→temp)、
 * 逻辑运算、mul、移位、ldr/str(unsigned imm)、cmp、cset、ret。
 * 所有指令定长 4 字节，小端写入。
 */

typedef struct axvm_emit {
    uint32_t *buf;   /* 目标缓冲(u32 对齐) */
    size_t    cap;   /* 容量(指令数) */
    size_t    n;     /* 已写入指令数 */
    int       oflow; /* 1=容量溢出 */
} axvm_emit_t;

/* ARM64 条件码(供 cset) */
#define A64_EQ 0x0
#define A64_NE 0x1
#define A64_CS 0x2
#define A64_CC 0x3
#define A64_MI 0x4
#define A64_PL 0x5
#define A64_VS 0x6
#define A64_VC 0x7

/* 真实寄存器编号约定：x0=ctx 基址; x9..x15=VM 寄存器缓存; x16/x17=临时; 31=XZR */
#define A64_XZR 31u

void axvm_emit_init(axvm_emit_t *e, uint32_t *buf, size_t cap_words);

/* 数据处理(移位寄存器) 64-bit：rd = rn OP (rm LSL sh) */
void axvm_emit_add_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm);
void axvm_emit_sub_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm);
void axvm_emit_and_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm);
void axvm_emit_orr_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm);
void axvm_emit_eor_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm);
void axvm_emit_mul_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm);
void axvm_emit_mov_reg(axvm_emit_t *e, uint32_t rd, uint32_t rm);   /* orr rd,xzr,rm */
void axvm_emit_mvn_reg(axvm_emit_t *e, uint32_t rd, uint32_t rm);   /* orn rd,xzr,rm */

/* 移位立即数 64-bit(UBFM) */
void axvm_emit_lsl_imm(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t sh);
void axvm_emit_lsr_imm(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t sh);

/* 立即数装载(64-bit，自动 movz + movk 展开；负值走 movn 优化) */
void axvm_emit_mov_imm64(axvm_emit_t *e, uint32_t rd, uint64_t imm);

/* 访存(unsigned scaled imm) */
void axvm_emit_ldr_x(axvm_emit_t *e, uint32_t rt, uint32_t rn, uint32_t byte_off);
void axvm_emit_str_x(axvm_emit_t *e, uint32_t rt, uint32_t rn, uint32_t byte_off);
void axvm_emit_ldr_w(axvm_emit_t *e, uint32_t rt, uint32_t rn, uint32_t byte_off);
void axvm_emit_str_w(axvm_emit_t *e, uint32_t rt, uint32_t rn, uint32_t byte_off);

/* 比较与条件置位 */
void axvm_emit_cmp_reg(axvm_emit_t *e, uint32_t rn, uint32_t rm); /* subs xzr,rn,rm */
void axvm_emit_cset(axvm_emit_t *e, uint32_t rd, uint32_t cond);  /* csinc rd,xzr,xzr,!cond */

/* 32-bit ORR(移位寄存器)：wd = wn | (wm LSL sh) —— 供 nzcv 打包 */
void axvm_emit_orr_reg_w_lsl(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm, uint32_t sh);
/* 32-bit 逻辑移位立即 —— 供 nzcv 清低位 */
void axvm_emit_lsl_imm_w(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t sh);
void axvm_emit_lsr_imm_w(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t sh);

void axvm_emit_ret(axvm_emit_t *e);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_JIT_EMIT_H */
