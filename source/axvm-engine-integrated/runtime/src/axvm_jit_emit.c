#include "axvm_jit_emit.h"

/* 极简 A64 编码器：所有指令 4 字节，直接拼位后小端写入。 */

static void emit_word(axvm_emit_t *e, uint32_t w)
{
    if (!e || !e->buf) {
        return;
    }
    if (e->n >= e->cap) {
        e->oflow = 1;
        return;
    }
    e->buf[e->n++] = w;
}

void axvm_emit_init(axvm_emit_t *e, uint32_t *buf, size_t cap_words)
{
    e->buf = buf;
    e->cap = cap_words;
    e->n = 0;
    e->oflow = 0;
}

/* ---- 数据处理(移位寄存器) 64-bit ---- */
static void dp_shifted(axvm_emit_t *e, uint32_t base, uint32_t rd, uint32_t rn, uint32_t rm)
{
    emit_word(e, base | ((rm & 31u) << 16) | ((rn & 31u) << 5) | (rd & 31u));
}

void axvm_emit_add_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm)
{
    dp_shifted(e, 0x8B000000u, rd, rn, rm);
}

void axvm_emit_sub_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm)
{
    dp_shifted(e, 0xCB000000u, rd, rn, rm);
}

void axvm_emit_and_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm)
{
    dp_shifted(e, 0x8A000000u, rd, rn, rm);
}

void axvm_emit_orr_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm)
{
    dp_shifted(e, 0xAA000000u, rd, rn, rm);
}

void axvm_emit_eor_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm)
{
    dp_shifted(e, 0xCA000000u, rd, rn, rm);
}

void axvm_emit_mul_reg(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm)
{
    /* madd rd, rn, rm, xzr */
    emit_word(e, 0x9B000000u | ((rm & 31u) << 16) | (31u << 10) | ((rn & 31u) << 5) | (rd & 31u));
}

void axvm_emit_mov_reg(axvm_emit_t *e, uint32_t rd, uint32_t rm)
{
    /* orr rd, xzr, rm */
    dp_shifted(e, 0xAA000000u, rd, A64_XZR, rm);
}

void axvm_emit_mvn_reg(axvm_emit_t *e, uint32_t rd, uint32_t rm)
{
    /* orn rd, xzr, rm (ORR with N=1) */
    dp_shifted(e, 0xAA200000u, rd, A64_XZR, rm);
}

/* ---- 移位立即 64-bit(UBFM, N=1) ---- */
static void ubfm_x(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t immr, uint32_t imms)
{
    emit_word(e, 0xD3400000u | ((immr & 63u) << 16) | ((imms & 63u) << 10) |
                     ((rn & 31u) << 5) | (rd & 31u));
}

void axvm_emit_lsl_imm(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t sh)
{
    sh &= 63u;
    ubfm_x(e, rd, rn, (64u - sh) & 63u, 63u - sh);
}

void axvm_emit_lsr_imm(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t sh)
{
    sh &= 63u;
    ubfm_x(e, rd, rn, sh, 63u);
}

/* ---- 移位立即 32-bit(UBFM, N=0) ---- */
static void ubfm_w(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t immr, uint32_t imms)
{
    emit_word(e, 0x53000000u | ((immr & 31u) << 16) | ((imms & 31u) << 10) |
                     ((rn & 31u) << 5) | (rd & 31u));
}

void axvm_emit_lsl_imm_w(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t sh)
{
    sh &= 31u;
    ubfm_w(e, rd, rn, (32u - sh) & 31u, 31u - sh);
}

void axvm_emit_lsr_imm_w(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t sh)
{
    sh &= 31u;
    ubfm_w(e, rd, rn, sh, 31u);
}

/* ---- 立即数装载 ---- */
static void movz(axvm_emit_t *e, uint32_t rd, uint32_t hw, uint16_t imm)
{
    emit_word(e, 0xD2800000u | ((hw & 3u) << 21) | ((uint32_t)imm << 5) | (rd & 31u));
}

static void movk(axvm_emit_t *e, uint32_t rd, uint32_t hw, uint16_t imm)
{
    emit_word(e, 0xF2800000u | ((hw & 3u) << 21) | ((uint32_t)imm << 5) | (rd & 31u));
}

static void movn(axvm_emit_t *e, uint32_t rd, uint32_t hw, uint16_t imm)
{
    emit_word(e, 0x92800000u | ((hw & 3u) << 21) | ((uint32_t)imm << 5) | (rd & 31u));
}

void axvm_emit_mov_imm64(axvm_emit_t *e, uint32_t rd, uint64_t imm)
{
    /* 负值/高位全 1 时用 movn 起头减少指令数 */
    int use_movn = 0;
    uint64_t base = imm;
    if ((int64_t)imm < 0) {
        uint64_t ones = 0;
        for (int i = 0; i < 4; ++i) {
            if (((imm >> (i * 16)) & 0xFFFFu) == 0xFFFFu) {
                ones++;
            }
        }
        if (ones >= 2) {
            use_movn = 1;
            base = ~imm;
        }
    }

    if (use_movn) {
        int first = 1;
        for (int i = 0; i < 4; ++i) {
            uint16_t h = (uint16_t)((base >> (i * 16)) & 0xFFFFu);
            if (first) {
                movn(e, rd, (uint32_t)i, h);
                first = 0;
            } else if (h != 0) {
                /* movn 之后需 movk 写入原值(非补码)的对应半字 */
                uint16_t orig = (uint16_t)((imm >> (i * 16)) & 0xFFFFu);
                movk(e, rd, (uint32_t)i, orig);
            }
        }
        return;
    }

    int first = 1;
    for (int i = 0; i < 4; ++i) {
        uint16_t h = (uint16_t)((imm >> (i * 16)) & 0xFFFFu);
        if (h == 0 && !first) {
            continue;
        }
        if (first) {
            movz(e, rd, (uint32_t)i, h);
            first = 0;
        } else {
            movk(e, rd, (uint32_t)i, h);
        }
    }
    if (first) {
        movz(e, rd, 0, 0); /* imm == 0 */
    }
}

/* ---- 访存(unsigned scaled imm) ---- */
void axvm_emit_ldr_x(axvm_emit_t *e, uint32_t rt, uint32_t rn, uint32_t byte_off)
{
    uint32_t imm12 = (byte_off >> 3) & 0xFFFu;
    emit_word(e, 0xF9400000u | (imm12 << 10) | ((rn & 31u) << 5) | (rt & 31u));
}

void axvm_emit_str_x(axvm_emit_t *e, uint32_t rt, uint32_t rn, uint32_t byte_off)
{
    uint32_t imm12 = (byte_off >> 3) & 0xFFFu;
    emit_word(e, 0xF9000000u | (imm12 << 10) | ((rn & 31u) << 5) | (rt & 31u));
}

void axvm_emit_ldr_w(axvm_emit_t *e, uint32_t rt, uint32_t rn, uint32_t byte_off)
{
    uint32_t imm12 = (byte_off >> 2) & 0xFFFu;
    emit_word(e, 0xB9400000u | (imm12 << 10) | ((rn & 31u) << 5) | (rt & 31u));
}

void axvm_emit_str_w(axvm_emit_t *e, uint32_t rt, uint32_t rn, uint32_t byte_off)
{
    uint32_t imm12 = (byte_off >> 2) & 0xFFFu;
    emit_word(e, 0xB9000000u | (imm12 << 10) | ((rn & 31u) << 5) | (rt & 31u));
}

/* ---- 比较/条件置位 ---- */
void axvm_emit_cmp_reg(axvm_emit_t *e, uint32_t rn, uint32_t rm)
{
    /* subs xzr, rn, rm */
    dp_shifted(e, 0xEB000000u, A64_XZR, rn, rm);
}

void axvm_emit_cset(axvm_emit_t *e, uint32_t rd, uint32_t cond)
{
    /* csinc rd, xzr, xzr, invert(cond) */
    uint32_t inv = cond ^ 1u;
    emit_word(e, 0x9A800400u | (31u << 16) | ((inv & 15u) << 12) | (31u << 5) | (rd & 31u));
}

void axvm_emit_orr_reg_w_lsl(axvm_emit_t *e, uint32_t rd, uint32_t rn, uint32_t rm, uint32_t sh)
{
    emit_word(e, 0x2A000000u | ((rm & 31u) << 16) | ((sh & 63u) << 10) |
                     ((rn & 31u) << 5) | (rd & 31u));
}

void axvm_emit_ret(axvm_emit_t *e)
{
    emit_word(e, 0xD65F03C0u); /* ret x30 */
}
