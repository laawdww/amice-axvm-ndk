#include "axvm_ctx.h"

#include "axvm_bytecode.h"

#include "axvm_reg.h"

#include "axvm_freg.h"

#include "axvm_excl.h"

#include "axvm_bridge.h"
#include "axvm_guard.h"
#include "axvm_integrity.h"

#include "axvm_interp.h"
#include "axvm_mem_guard.h"
#include "axvm_dispatch_perm.h"
#include "axvm_handler_poly.h"
#include "axvm_lazy_pf.h"
#include "axvm_nested.h"
#include "axvm_engine.h"
#include "axvm_branch_map.h"
#include "axvm_log.h"

#include "axvm_stack_crypt.h"

#include "axvm_lazy.h"



#include <stdlib.h>

#include <string.h>

#include <math.h>

/* 模块 G：取指/译码懒解密钩子；关闭 AXVM_LAZY_DECRYPT 时零开销降级 */
#if defined(AXVM_LAZY_DECRYPT) && AXVM_LAZY_DECRYPT
#define LAZY_ENSURE(ctx, off, w)                                               \
    do {                                                                       \
        axvm_status_t _es = axvm_lazy_ensure((ctx), (size_t)(off), (size_t)(w)); \
        if (_es != AXVM_OK) {                                                  \
            return _es;                                                        \
        }                                                                      \
    } while (0)
#define LAZY_REENCRYPT(ctx) axvm_lazy_reencrypt_active(ctx)
#else
#define LAZY_ENSURE(ctx, off, w) ((void)0)
#define LAZY_REENCRYPT(ctx) ((void)0)
#endif

/* 模块 H：dispatch 主循环分散探针（每轮 1 项，无集中检测大函数） */
#if defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
#define AXVM_GUARD_AT_DISPATCH(ctx)                                              \
    do {                                                                       \
        axvm_status_t _gst = axvm_guard_probe_dispatch(                        \
            (ctx), axvm_guard_global());                                       \
        if (_gst != AXVM_OK) {                                                 \
            return _gst;                                                       \
        }                                                                      \
    } while (0)
#else
#define AXVM_GUARD_AT_DISPATCH(ctx) ((void)0)
#endif

/* 模块 H：边缘探针（取指/访存路径），与 dispatch 探针序列解耦。 */
#if defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
#define AXVM_GUARD_AT_EDGE(ctx)                                                  \
    do {                                                                       \
        axvm_status_t _gst = axvm_guard_probe_edge((ctx), axvm_guard_global()); \
        if (_gst != AXVM_OK) {                                                 \
            return _gst;                                                       \
        }                                                                      \
    } while (0)
#else
#define AXVM_GUARD_AT_EDGE(ctx) ((void)0)
#endif

/* 模块 I：dispatch 主循环分散完整性校验（周期轮转，未 arm 时零开销） */
#if defined(AXVM_SO_INTEGRITY) && AXVM_SO_INTEGRITY
#define AXVM_INTEG_AT_DISPATCH(ctx)                                            \
    do {                                                                       \
        axvm_status_t _ist = axvm_integrity_probe_dispatch(ctx);              \
        if (_ist != AXVM_OK) {                                                 \
            return _ist;                                                       \
        }                                                                      \
    } while (0)
#else
#define AXVM_INTEG_AT_DISPATCH(ctx) ((void)0)
#endif

/* 模块 J：取指前尝试执行当前 PC 的 JIT 热块桩；命中则回循环头，否则原样落回解释器 */
#if defined(AXVM_JIT_CACHE) && AXVM_JIT_CACHE
#include "axvm_jit.h"
#define AXVM_JIT_TRY(ctx)                                                       \
    do {                                                                       \
        if (axvm_jit_maybe_run(ctx)) {                                         \
            goto axvm_loop_head;                                               \
        }                                                                      \
    } while (0)
#else
#define AXVM_JIT_TRY(ctx) ((void)0)
#endif



static axvm_status_t stack_push64(axvm_ctx_t *ctx, uint64_t v)

{

    if (ctx->sp < (uint64_t)(uintptr_t)ctx->vm_stack_base + 8) {

        return AXVM_ERR_OOB_STACK;

    }

    ctx->sp -= 8;

    if (ctx->sp & 7) {

        return AXVM_ERR_ALIGN;

    }

    *(uint64_t *)(uintptr_t)ctx->sp = v;

    return AXVM_OK;

}



static axvm_status_t stack_pop64(axvm_ctx_t *ctx, uint64_t *v)

{

    if (ctx->sp + 8 > (uint64_t)(uintptr_t)ctx->vm_stack_top) {

        return AXVM_ERR_OOB_STACK;

    }

    if (ctx->sp & 7) {

        return AXVM_ERR_ALIGN;

    }

    *v = *(uint64_t *)(uintptr_t)ctx->sp;

    ctx->sp += 8;

    return AXVM_OK;

}



static int cond_pass(uint32_t nzcv, uint8_t cond)

{

    uint32_t n = (nzcv >> 2) & 1u;

    uint32_t z = (nzcv >> 1) & 1u;

    uint32_t c = (nzcv >> 0) & 1u; /* bit0=C (进位/无借位) */

    uint32_t v = (nzcv >> 3) & 1u; /* bit3=V (有符号溢出) */



    switch (cond) {

    case AXCOND_EQ: return z;

    case AXCOND_NE: return !z;

    case AXCOND_CS: return c;

    case AXCOND_CC: return !c;

    case AXCOND_MI: return n;

    case AXCOND_PL: return !n;

    case AXCOND_VS: return v;

    case AXCOND_VC: return !v;

    case AXCOND_HI: return c && !z;

    case AXCOND_LS: return !c || z;

    case AXCOND_GE: return n == v;

    case AXCOND_LT: return n != v;

    case AXCOND_GT: return !z && (n == v);

    case AXCOND_LE: return z || (n != v);

    case AXCOND_AL: return 1;

    default: return 0;

    }

}



static const uint8_t *code_ptr(axvm_ctx_t *ctx)

{

    return ctx->bytecode + ctx->code_base + ctx->pc;

}



static axvm_status_t read_u8(axvm_ctx_t *ctx, const uint8_t **p, uint8_t *v)

{
    AXVM_GUARD_AT_EDGE(ctx);

    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;

    size_t off = (size_t)(*p - ctx->bytecode);

    if (off >= hdr->code_off + hdr->code_size) {

        return AXVM_ERR_OOB_PC;

    }

    LAZY_ENSURE(ctx, off, 1);

    *v = **p;

    (*p)++;

    ctx->pc = (uint32_t)(*p - ctx->bytecode - ctx->code_base);

    return AXVM_OK;

}



static axvm_status_t read_u16(axvm_ctx_t *ctx, const uint8_t **p, uint16_t *v)

{

    if (*p + 2 > ctx->bytecode + ctx->bc_size) {

        return AXVM_ERR_OOB_PC;

    }

    LAZY_ENSURE(ctx, (size_t)(*p - ctx->bytecode), 2);

    memcpy(v, *p, 2);

    *p += 2;

    ctx->pc = (uint32_t)(*p - ctx->bytecode - ctx->code_base);

    return AXVM_OK;

}



static axvm_status_t read_u32(axvm_ctx_t *ctx, const uint8_t **p, uint32_t *v)

{

    if (*p + 4 > ctx->bytecode + ctx->bc_size) {

        return AXVM_ERR_OOB_PC;

    }

    LAZY_ENSURE(ctx, (size_t)(*p - ctx->bytecode), 4);

    memcpy(v, *p, 4);

    *p += 4;

    ctx->pc = (uint32_t)(*p - ctx->bytecode - ctx->code_base);

    return AXVM_OK;

}



static axvm_status_t read_u64(axvm_ctx_t *ctx, const uint8_t **p, uint64_t *v)

{

    if (*p + 8 > ctx->bytecode + ctx->bc_size) {

        return AXVM_ERR_OOB_PC;

    }

    LAZY_ENSURE(ctx, (size_t)(*p - ctx->bytecode), 8);

    memcpy(v, *p, 8);

    *p += 8;

    ctx->pc = (uint32_t)(*p - ctx->bytecode - ctx->code_base);

    return AXVM_OK;

}



static int mem_in_pool(axvm_ctx_t *ctx, uint64_t addr, size_t width)

{

    uintptr_t base = (uintptr_t)ctx->mem_pool;

    uintptr_t end = base + ctx->mem_pool_size;
    if (addr < base) {
        return 0;
    }
    if ((uintptr_t)addr > end || width > (size_t)(end - (uintptr_t)addr)) {

        return 0;

    }

    return 1;

}



static int mem_in_vm_stack(axvm_ctx_t *ctx, uint64_t addr, size_t width)

{

    uintptr_t base = (uintptr_t)ctx->vm_stack_base;

    uintptr_t end = (uintptr_t)ctx->vm_stack_top;
    if (addr < base) {
        return 0;
    }
    if ((uintptr_t)addr > end || width > (size_t)(end - (uintptr_t)addr)) {

        return 0;

    }

    return 1;

}



static axvm_status_t mem_load64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out)

{
    AXVM_GUARD_AT_EDGE(ctx);

    if (mem_in_pool(ctx, addr, 8)) {
        memcpy(out, (void *)(uintptr_t)addr, 8);
        return AXVM_OK;
    }

    if (mem_in_vm_stack(ctx, addr, 8)) {
        if (addr & 7) {
            uint64_t v = 0;
            for (uint32_t i = 0; i < 8; ++i) {
                uint8_t b = 0;
                axvm_status_t st = axvm_vm_stack_load8(ctx, addr + i, &b);
                if (st != AXVM_OK) return st;
                v |= (uint64_t)b << (i * 8);
            }
            *out = v;
            return AXVM_OK;
        }
        return axvm_vm_stack_load64(ctx, addr, out);
    }

    if (addr == 0) {
        return AXVM_ERR_OOB_MEM;
    }
    memcpy(out, (void *)(uintptr_t)addr, 8);
    return AXVM_OK;

}



static axvm_status_t mem_store64(axvm_ctx_t *ctx, uint64_t addr, uint64_t val)

{
    AXVM_GUARD_AT_EDGE(ctx);

    if (mem_in_pool(ctx, addr, 8)) {
        memcpy((void *)(uintptr_t)addr, &val, 8);
        return AXVM_OK;
    }

    if (mem_in_vm_stack(ctx, addr, 8)) {
        if (addr & 7) {
            for (uint32_t i = 0; i < 8; ++i) {
                axvm_status_t st = axvm_vm_stack_store8(ctx, addr + i, (uint8_t)(val >> (i * 8)));
                if (st != AXVM_OK) return st;
            }
            return AXVM_OK;
        }
        return axvm_vm_stack_store64(ctx, addr, val);
    }

    if (addr == 0) {
        return AXVM_ERR_OOB_MEM;
    }
    memcpy((void *)(uintptr_t)addr, &val, 8);
    return AXVM_OK;

}



static axvm_status_t mem_load32(axvm_ctx_t *ctx, uint64_t addr, uint32_t *out)

{
    AXVM_GUARD_AT_EDGE(ctx);

    if (mem_in_pool(ctx, addr, 4)) {
        memcpy(out, (void *)(uintptr_t)addr, 4);
        return AXVM_OK;
    }

    if (mem_in_vm_stack(ctx, addr, 4)) {
        if (addr & 3) {
            uint32_t v = 0;
            for (uint32_t i = 0; i < 4; ++i) {
                uint8_t b = 0;
                axvm_status_t st = axvm_vm_stack_load8(ctx, addr + i, &b);
                if (st != AXVM_OK) return st;
                v |= (uint32_t)b << (i * 8);
            }
            *out = v;
            return AXVM_OK;
        }
        return axvm_vm_stack_load32(ctx, addr, out);
    }

    if (addr == 0) {
        return AXVM_ERR_OOB_MEM;
    }
    memcpy(out, (void *)(uintptr_t)addr, 4);
    return AXVM_OK;

}



static axvm_status_t mem_store32(axvm_ctx_t *ctx, uint64_t addr, uint32_t val)

{
    AXVM_GUARD_AT_EDGE(ctx);

    if (mem_in_pool(ctx, addr, 4)) {
        memcpy((void *)(uintptr_t)addr, &val, 4);
        return AXVM_OK;
    }

    if (mem_in_vm_stack(ctx, addr, 4)) {
        if (addr & 3) {
            for (uint32_t i = 0; i < 4; ++i) {
                axvm_status_t st = axvm_vm_stack_store8(ctx, addr + i, (uint8_t)(val >> (i * 8)));
                if (st != AXVM_OK) return st;
            }
            return AXVM_OK;
        }
        return axvm_vm_stack_store32(ctx, addr, val);
    }

    if (addr == 0) {
        return AXVM_ERR_OOB_MEM;
    }
    memcpy((void *)(uintptr_t)addr, &val, 4);
    return AXVM_OK;

}


static axvm_status_t mem_load16(axvm_ctx_t *ctx, uint64_t addr, uint16_t *out)

{
    AXVM_GUARD_AT_EDGE(ctx);
    if (mem_in_pool(ctx, addr, 2)) {
        *out = *(uint16_t *)(uintptr_t)addr;
        return AXVM_OK;
    }
    if (mem_in_vm_stack(ctx, addr, 2)) {
        return axvm_vm_stack_load16(ctx, addr, out);
    }
    if (addr == 0) {
        return AXVM_ERR_OOB_MEM;
    }
    *out = *(uint16_t *)(uintptr_t)addr;
    return AXVM_OK;
}


static axvm_status_t mem_store16(axvm_ctx_t *ctx, uint64_t addr, uint16_t val)

{
    AXVM_GUARD_AT_EDGE(ctx);
    if (mem_in_pool(ctx, addr, 2)) {
        *(uint16_t *)(uintptr_t)addr = val;
        return AXVM_OK;
    }
    if (mem_in_vm_stack(ctx, addr, 2)) {
        return axvm_vm_stack_store16(ctx, addr, val);
    }
    if (addr == 0) {
        return AXVM_ERR_OOB_MEM;
    }
    *(uint16_t *)(uintptr_t)addr = val;
    return AXVM_OK;
}


static axvm_status_t mem_load8(axvm_ctx_t *ctx, uint64_t addr, uint8_t *out)

{
    AXVM_GUARD_AT_EDGE(ctx);
    if (mem_in_pool(ctx, addr, 1)) {
        *out = *(uint8_t *)(uintptr_t)addr;
        return AXVM_OK;
    }
    if (mem_in_vm_stack(ctx, addr, 1)) {
        return axvm_vm_stack_load8(ctx, addr, out);
    }
    if (addr == 0) {
        return AXVM_ERR_OOB_MEM;
    }
    *out = *(uint8_t *)(uintptr_t)addr;
    return AXVM_OK;
}


static axvm_status_t mem_store8(axvm_ctx_t *ctx, uint64_t addr, uint8_t val)

{
    AXVM_GUARD_AT_EDGE(ctx);
    if (mem_in_pool(ctx, addr, 1)) {
        *(uint8_t *)(uintptr_t)addr = val;
        return AXVM_OK;
    }
    if (mem_in_vm_stack(ctx, addr, 1)) {
        return axvm_vm_stack_store8(ctx, addr, val);
    }
    if (addr == 0) {
        return AXVM_ERR_OOB_MEM;
    }
    *(uint8_t *)(uintptr_t)addr = val;
    return AXVM_OK;
}



static axvm_status_t branch_to(axvm_ctx_t *ctx, const axvm_bc_header_t *hdr, int32_t rel)

{

    int64_t npc = (int64_t)ctx->pc + rel;

    if (npc < 0 || (uint64_t)npc > hdr->code_size) {

        return AXVM_ERR_OOB_PC;

    }

    ctx->pc = (uint32_t)npc;

    return AXVM_OK;

}



static axvm_status_t exec_cmp(axvm_ctx_t *ctx, uint8_t rn, uint8_t rm)

{

    if (!axvm_reg_src_ok(rn) || !axvm_reg_src_ok(rm)) {

        return AXVM_ERR_BAD_INSN;

    }

    uint64_t vn = axvm_reg_read(ctx, rn);

    uint64_t vm = axvm_reg_read(ctx, rm);

    uint64_t res = vn - vm;

    /*
     * 完整复刻 AArch64 SUBS 标志（64-bit）：
     *   N = res<0, Z = res==0,
     *   C = 无借位 (vn >= vm, 无符号),
     *   V = 有符号溢出 = (vn^vm) & (vn^res) 的符号位。
     * nzcv 布局：bit3=V bit2=N bit1=Z bit0=C（与 FP FCMP 一致）。
     */
    uint32_t n = (uint32_t)((res >> 63) & 1u);

    uint32_t z = (res == 0) ? 1u : 0u;

    uint32_t c = (vn >= vm) ? 1u : 0u;

    uint32_t v = (uint32_t)((((vn ^ vm) & (vn ^ res)) >> 63) & 1u);

    ctx->nzcv = (ctx->nzcv & ~0xFu) | (v << 3) | (n << 2) | (z << 1) | c;

    return AXVM_OK;

}

static axvm_status_t exec_cmp32(axvm_ctx_t *ctx, uint8_t rn, uint8_t rm)

{

    if (!axvm_reg_src_ok(rn) || !axvm_reg_src_ok(rm)) {

        return AXVM_ERR_BAD_INSN;

    }

    uint32_t vn = (uint32_t)axvm_reg_read(ctx, rn);

    uint32_t vm = (uint32_t)axvm_reg_read(ctx, rm);

    uint32_t res = vn - vm;

    uint32_t n = (res >> 31) & 1u;

    uint32_t z = (res == 0) ? 1u : 0u;

    uint32_t c = (vn >= vm) ? 1u : 0u;

    uint32_t v = ((((vn ^ vm) & (vn ^ res)) >> 31) & 1u);

    ctx->nzcv = (ctx->nzcv & ~0xFu) | (v << 3) | (n << 2) | (z << 1) | c;

    return AXVM_OK;

}



#if defined(AXVM_USE_COMPUTED_GOTO) && AXVM_USE_COMPUTED_GOTO

int axvm_interp_dispatch_is_goto(void)

{

    return 1;

}

#else

int axvm_interp_dispatch_is_goto(void)

{

    return 0;

}

#endif



static axvm_status_t axvm_run_impl(axvm_ctx_t *ctx);

/*
 * 模块 G：对外入口薄封装。无论内层从何处返回（正常 RET/HALT、越界、非法指令），
 * 统一在此把仍处于明文状态的活动块异或回写为密文，保证执行结束后代码区无明文残留。
 */
axvm_status_t axvm_run(axvm_ctx_t *ctx)
{
#if defined(AXVM_MEM_GUARD) && AXVM_MEM_GUARD
    axvm_mem_guard_unseal(ctx);
#endif
#if defined(AXVM_LAZY_PF) && AXVM_LAZY_PF
    axvm_lazy_pf_install();
    axvm_lazy_pf_bind_ctx(ctx);
#endif
    axvm_status_t st = axvm_run_impl(ctx);
    LAZY_REENCRYPT(ctx);
#if defined(AXVM_LAZY_PF) && AXVM_LAZY_PF
    axvm_lazy_pf_seal_all(ctx);
    axvm_lazy_pf_unbind_ctx();
#endif
#if defined(AXVM_MEM_GUARD) && AXVM_MEM_GUARD
    axvm_mem_guard_seal(ctx);
#endif
    return st;
}

static axvm_status_t axvm_run_impl(axvm_ctx_t *ctx)

{

    if (!ctx) {

        return AXVM_ERR_BAD_MAGIC;

    }



    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;

    axvm_status_t st = AXVM_OK;

    uint8_t op = 0;

    const uint8_t *cursor = NULL;



#if defined(AXVM_USE_COMPUTED_GOTO) && AXVM_USE_COMPUTED_GOTO



    /*

     * Threaded Interpreter 跳转表：256 项直接索引 opcode 字节。

     * GNU 范围初始化将未实现槽位统一指向非法指令兜底 label。

     */

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winitializer-overrides"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverride-init"
#endif
    static void *const axvm_dispatch_table[256] = {

        [0 ... 255] = &&dispatch_bad_insn,

        [AXOP_NOP]       = &&op_nop,

        [AXOP_HALT]      = &&op_halt,

        [AXOP_LDRI64]    = &&op_ldri64,
        [AXOP_LDRI64_VADDR] = &&op_ldri64_vaddr,

        [AXOP_ADD_IMM]   = &&op_add_imm,

        [AXOP_SUB_IMM]   = &&op_sub_imm,

        [AXOP_ADD_REG]   = &&op_add_reg,

        [AXOP_SUB_REG]   = &&op_sub_reg,

        [AXOP_AND_REG]   = &&op_and_reg,

        [AXOP_ORR_REG]   = &&op_orr_reg,

        [AXOP_EOR_REG]   = &&op_eor_reg,

        [AXOP_LSL_IMM]   = &&op_lsl_imm,

        [AXOP_LSR_IMM]   = &&op_lsr_imm,

        [AXOP_CMP_REG]   = &&op_cmp_reg,
        [AXOP_CMP_REG32] = &&op_cmp_reg32,

        [AXOP_MUL_REG]   = &&op_mul_reg,

        [AXOP_CSEL_REG]  = &&op_csel_reg,

        [AXOP_MOVK]      = &&op_movk,

        [AXOP_LDR_U64]   = &&op_ldr_u64,

        [AXOP_STR_U64]   = &&op_str_u64,

        [AXOP_LDR_U32]   = &&op_ldr_u32,

        [AXOP_STR_U32]   = &&op_str_u32,

        [AXOP_LDUR_U64]  = &&op_ldur_u64,

        [AXOP_STUR_U64]  = &&op_stur_u64,

        [AXOP_LDUR_U32]  = &&op_ldur_u32,

        [AXOP_STUR_U32]  = &&op_stur_u32,

        [AXOP_LDR_U8]    = &&op_ldr_u8,

        [AXOP_STR_U8]    = &&op_str_u8,

        [AXOP_LDR_U16]   = &&op_ldr_u16,

        [AXOP_STR_U16]   = &&op_str_u16,

        [AXOP_MOV_REG]   = &&op_mov_reg,

        [AXOP_MVN_REG]   = &&op_mvn_reg,

        [AXOP_ASR_IMM]   = &&op_asr_imm,

        [AXOP_BR]        = &&op_br,

        [AXOP_B_COND]    = &&op_b_cond,

        [AXOP_BL_NATIVE] = &&op_bl_native,

        [AXOP_BR_REG]    = &&op_br_reg,

        [AXOP_BLR_REG]   = &&op_blr_reg,

        [AXOP_CALL_NAT]  = &&op_call_nat,
        [AXOP_CALL_NAT_VADDR] = &&op_call_nat_vaddr,

        [AXOP_RET]       = &&op_ret,

        [AXOP_PUSH_PAIR] = &&op_push_pair,

        [AXOP_POP_PAIR]  = &&op_pop_pair,

        [AXOP_LDR_REGOFF] = &&op_ldr_regoff,
        [AXOP_STR_REGOFF] = &&op_str_regoff,
        [AXOP_ZEXT32] = &&op_zext32,
        [AXOP_CMP_IMM] = &&op_cmp_imm,

        [AXOP_ATOMIC_CAS64]   = &&op_atomic_cas64,
        [AXOP_ATOMIC_SWP64]   = &&op_atomic_swp64,
        [AXOP_ATOMIC_LDADD64] = &&op_atomic_ldadd64,
        [AXOP_ATOMIC_LDCLR64] = &&op_atomic_ldclr64,
        [AXOP_ATOMIC_LDEOR64] = &&op_atomic_ldeor64,
        [AXOP_ATOMIC_LDSET64] = &&op_atomic_ldset64,
        [AXOP_ATOMIC_LDXR64]  = &&op_atomic_ldxr64,
        [AXOP_ATOMIC_STXR64]  = &&op_atomic_stxr64,
        [AXOP_ATOMIC_CASP64]  = &&op_atomic_casp64,
        [AXOP_ATOMIC_STXP64]  = &&op_atomic_stxp64,
        [AXOP_ATOMIC_LDXP64]  = &&op_atomic_ldxp64,
        [AXOP_ATOMIC_CAS32]   = &&op_atomic_cas32,
        [AXOP_ATOMIC_SWP32]   = &&op_atomic_swp32,
        [AXOP_ATOMIC_LDADD32] = &&op_atomic_ldadd32,
        [AXOP_ATOMIC_LDCLR32] = &&op_atomic_ldclr32,
        [AXOP_ATOMIC_LDEOR32] = &&op_atomic_ldeor32,
        [AXOP_ATOMIC_LDSET32] = &&op_atomic_ldset32,
        [AXOP_ATOMIC_LDXR32]  = &&op_atomic_ldxr32,
        [AXOP_ATOMIC_STXR32]  = &&op_atomic_stxr32,

#if defined(AXVM_NESTED_VM) && AXVM_NESTED_VM
        [AXOP_VM_ENTER]  = &&op_vm_enter,
        [AXOP_VM_LEAVE]  = &&op_vm_leave,
#endif

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
        [AXOP_FLDR_D]      = &&op_fldr_d,
        [AXOP_FSTR_D]      = &&op_fstr_d,
        [AXOP_FLDR_S]      = &&op_fldr_s,
        [AXOP_FSTR_S]      = &&op_fstr_s,
        [AXOP_FLDR_Q]      = &&op_fldr_q,
        [AXOP_FSTR_Q]      = &&op_fstr_q,
        [AXOP_FADD_D]      = &&op_fadd_d,
        [AXOP_FSUB_D]      = &&op_fsub_d,
        [AXOP_FMUL_D]      = &&op_fmul_d,
        [AXOP_FDIV_D]      = &&op_fdiv_d,
        [AXOP_FSQRT_D]     = &&op_fsqrt_d,
        [AXOP_FCMP_D]      = &&op_fcmp_d,
        [AXOP_FMOV_D_REG]  = &&op_fmov_d_reg,
        [AXOP_FMOV_X_BITS] = &&op_fmov_x_bits,
        [AXOP_FMOV_D_BITS] = &&op_fmov_d_bits,
        [AXOP_FMOV_D_X]    = &&op_fmov_d_x,
        [AXOP_FCVT_DS]     = &&op_fcvt_ds,
        [AXOP_FCVTZS_D]    = &&op_fcvtzs_d,
        [AXOP_SAVE_SCRATCH] = &&op_save_scratch,
        [AXOP_RESTORE_SCRATCH] = &&op_restore_scratch,
        [AXOP_VADD_2D]  = &&op_vadd_2d,
        [AXOP_VMUL_2D]  = &&op_vmul_2d,
        [AXOP_VFMLA_2D] = &&op_vfma_2d,
        [AXOP_VADD_4S]  = &&op_vadd_4s,
        [AXOP_VMUL_4S]  = &&op_vmul_4s,
        [AXOP_VFMLA_4S] = &&op_vfma_4s,
        [AXOP_VDUP_2D]  = &&op_vdup_2d,
        [AXOP_UMOV_D]   = &&op_umov_d,
        [AXOP_INS_D]    = &&op_ins_d,
#endif
        [AXOP_JUNK]        = &&op_junk,
        [AXOP_MRS_TPIDR]   = &&op_mrs_tpidr,
        [AXOP_UDIV_REG]    = &&op_udiv_reg,
        [AXOP_SDIV_REG]    = &&op_sdiv_reg,
        [AXOP_CCMP]        = &&op_ccmp,

    };
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif



#define AXVM_OP_BEGIN(op, lbl) lbl:

#define AXVM_OP_NEXT()       goto axvm_loop_head;



    /* 跳过 handler 区，进入取指循环 */

    goto axvm_loop_head;



#else



#define AXVM_OP_BEGIN(op, lbl) case (op):

#define AXVM_OP_NEXT()       break



    while (!ctx->halted && !ctx->ret_pending) {



#endif /* AXVM_USE_COMPUTED_GOTO */



axvm_loop_head:

        AXVM_GUARD_AT_DISPATCH(ctx);

        AXVM_INTEG_AT_DISPATCH(ctx);

        if (ctx->halted || ctx->ret_pending) {

#if defined(AXVM_USE_COMPUTED_GOTO) && AXVM_USE_COMPUTED_GOTO

            goto axvm_run_exit;

#else

            break;

#endif

        }

        if (ctx->pc >= hdr->code_size) {

            return AXVM_ERR_OOB_PC;

        }

        AXVM_JIT_TRY(ctx);



        {

            const uint8_t *ip = code_ptr(ctx);

            cursor = ip;

            st = read_u8(ctx, &cursor, &op);

            if (st != AXVM_OK) {

                return st;

            }

        }

#if defined(AXVM_MULTI_ISA) && AXVM_MULTI_ISA
        if (ctx->riscc_active) {
            op = ctx->riscc_wire_inv[op];
        }
#endif

#if defined(AXVM_OPCODE_PERM) && AXVM_OPCODE_PERM
        /* 模块 M：还原经 MasterSeed 置换的真实 opcode（未激活时恒等）。 */
        if (ctx->opcode_perm_active) {
            op = ctx->opcode_inv[op];
        }
#endif

        /* 模块 N：per-ctx 调度表物理置换（dispatch_ptr[fwd[op]] → 正确 handler） */
        {
            static uint32_t trace_count = 0;
            if (trace_count < 200) {
                AXVM_LOGE("trace pc=%llu op=0x%02x", (unsigned long long)(ctx->pc - 1), op);
                trace_count++;
            }
        }

#if defined(AXVM_DISPATCH_PERM) && AXVM_DISPATCH_PERM
        if (ctx->dispatch_perm_active) {
            if (!ctx->dispatch_ptr_ready) {
                axvm_dispatch_perm_materialize(ctx, (const void *const *)axvm_dispatch_table);
            }
#if defined(AXVM_HANDLER_POLY) && AXVM_HANDLER_POLY
            if (ctx->handler_poly_active && !ctx->handler_poly_applied) {
                const void *decoys[8] = {
                    &&decoy_0, &&decoy_1, &&decoy_2, &&decoy_3,
                    &&decoy_4, &&decoy_5, &&decoy_6, &&decoy_7,
                };
                axvm_handler_poly_apply(ctx, &&dispatch_bad_insn, decoys);
            }
            goto *axvm_handler_poly_resolve(ctx, ctx->dispatch_fwd[op]);
#else
            goto *ctx->dispatch_ptr[ctx->dispatch_fwd[op]];
#endif
        }
#endif
#if defined(AXVM_USE_COMPUTED_GOTO) && AXVM_USE_COMPUTED_GOTO

        goto *axvm_dispatch_table[op];

#else

        switch (op) {

#endif



#include "axvm_interp_insns.inc"



#if defined(AXVM_USE_COMPUTED_GOTO) && AXVM_USE_COMPUTED_GOTO

    decoy_0:
        ctx->stack_roll ^= (uint32_t)(uintptr_t)ctx & 0u;
        goto dispatch_bad_insn;
    decoy_1:
        ctx->pc += (ctx->pc == 0xFFFFFFFFu);
        goto dispatch_bad_insn;
    decoy_2:
        ctx->nzcv ^= (ctx->nzcv == 0xFFFFFFFFu);
        goto dispatch_bad_insn;
    decoy_3:
        ctx->stack_op_count += (ctx->stack_op_count == 0xFFFFFFFFu);
        goto dispatch_bad_insn;
    decoy_4:
        ctx->x[1] ^= (ctx->x[1] == 0xFFFFFFFFFFFFFFFFULL);
        goto dispatch_bad_insn;
    decoy_5:
        ctx->ret_pending &= (ctx->ret_pending == 2);
        goto dispatch_bad_insn;
    decoy_6:
        ctx->code_base ^= (ctx->code_base == 0xFFFFFFFFu);
        goto dispatch_bad_insn;
    decoy_7:
        ctx->data_base ^= (ctx->data_base == 0xFFFFFFFFu);
        goto dispatch_bad_insn;

    dispatch_bad_insn:

        AXVM_LOGE("bad insn pc=%llu op=0x%02x",
                  (unsigned long long)ctx->pc, op);

        return AXVM_ERR_BAD_INSN;



    axvm_run_exit:

        return AXVM_OK;



#else

        default:

            return AXVM_ERR_BAD_INSN;

        }

    }



    return AXVM_OK;

#endif /* AXVM_USE_COMPUTED_GOTO */

}



axvm_status_t axvm_load_bytecode(axvm_ctx_t *ctx, const uint8_t *bc, size_t len)

{

    if (!ctx || !axvm_bc_validate(bc, len)) {

        return AXVM_ERR_BAD_MAGIC;

    }

    uint8_t *nb = (uint8_t *)realloc(ctx->bytecode, len);

    if (!nb) {

        return AXVM_ERR_OOB_MEM;

    }

    memcpy(nb, bc, len);

    ctx->bytecode = nb;

    ctx->bc_size = len;

    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)bc;

    ctx->code_base = hdr->code_off;

    ctx->data_base = hdr->data_off;

    return axvm_ctx_reset(ctx);

}
