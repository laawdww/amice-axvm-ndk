#include "axvm_ctx.h"
#include "axvm_asm_offsets.h"
#include "axvm_stack_crypt.h"
#include "axvm_lazy.h"
#include "axvm_dynseed.h"
#include "axvm_jit.h"
#include "axvm_opcode_perm.h"
#include "axvm_reg.h"
#include "axvm_mem_guard.h"
#include "axvm_dispatch_perm.h"
#include "axvm_handler_poly.h"
#include "axvm_branch_map.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

_Static_assert(offsetof(axvm_ctx_t, x) == AXVM_CTX_OFF_X, "asm layout");
_Static_assert(offsetof(axvm_ctx_t, sp) == AXVM_CTX_OFF_SP, "asm layout");
_Static_assert(offsetof(axvm_ctx_t, host_sp_saved) == AXVM_CTX_OFF_HOST_SP, "asm layout");
_Static_assert(offsetof(axvm_ctx_t, native_bridge_sp) == AXVM_CTX_OFF_NATIVE_BRIDGE_SP,
                 "asm layout");
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
_Static_assert(offsetof(axvm_ctx_t, v) == AXVM_CTX_OFF_V, "asm layout fp v[]");
#endif
static axvm_status_t map_guarded_stack(uint8_t **base_out, size_t *size_out)
{
    size_t total = AXVM_STACK_GUARD + AXVM_STACK_SIZE + AXVM_STACK_GUARD;
    void *raw = mmap(NULL, total, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) {
        return AXVM_ERR_OOB_STACK;
    }

    uint8_t *base = (uint8_t *)raw;
    if (mprotect(base + AXVM_STACK_GUARD, AXVM_STACK_SIZE, PROT_READ | PROT_WRITE) != 0) {
        munmap(raw, total);
        return AXVM_ERR_OOB_STACK;
    }

    *base_out = base + AXVM_STACK_GUARD;
    *size_out = AXVM_STACK_SIZE;
    return AXVM_OK;
}

static void unmap_guarded_stack(uint8_t *stack_base)
{
    if (!stack_base) {
        return;
    }
    uint8_t *raw = stack_base - AXVM_STACK_GUARD;
    size_t total = AXVM_STACK_GUARD + AXVM_STACK_SIZE + AXVM_STACK_GUARD;
    munmap(raw, total);
}

#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
static uint64_t reg_perm_next_u64(uint64_t *st)
{
    uint64_t x = *st;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *st = x;
    return x;
}

static void reg_perm_build_from_session(axvm_ctx_t *ctx, const uint8_t session_seed[32])
{
    /* 用 SessionSeed 派生置换密钥，再 Fisher-Yates 打乱 x0-x30 */
    uint8_t subkey[32];
    axvm_dynseed_subkey(session_seed, AXVM_DYNSEED_PURPOSE_REGPERM, subkey, sizeof(subkey));

    uint64_t s = 0;
    for (size_t i = 0; i < sizeof(subkey); ++i) {
        s = s * 1315423911u + (uint64_t)subkey[i] + 0x9E3779B97F4A7C15ULL;
    }

    /* xorshift64 */

    for (uint8_t i = 0; i < AXVM_REG_COUNT; ++i) {
        ctx->reg_perm[i] = i;
    }

    for (int i = (int)AXVM_REG_COUNT - 1; i > 0; --i) {
        uint64_t r = reg_perm_next_u64(&s);
        uint32_t j = (uint32_t)(r % (uint64_t)(i + 1));
        uint8_t tmp = ctx->reg_perm[i];
        ctx->reg_perm[i] = ctx->reg_perm[j];
        ctx->reg_perm[j] = tmp;
    }

    /* 极小概率恒等：强制交换两个槽，避免“置换未生效”假阳性 */
    int fixed = 0;
    for (uint8_t i = 0; i < AXVM_REG_COUNT; ++i) {
        if (ctx->reg_perm[i] == i) {
            fixed++;
        }
    }
    if (fixed >= (int)AXVM_REG_COUNT - 1) {
        uint8_t t = ctx->reg_perm[0];
        ctx->reg_perm[0] = ctx->reg_perm[1];
        ctx->reg_perm[1] = t;
    }

    volatile uint8_t *p = subkey;
    for (size_t i = 0; i < sizeof(subkey); ++i) {
        p[i] = 0;
    }
    ctx->reg_perm_active = 1;
}
#endif

axvm_status_t axvm_ctx_create(axvm_ctx_t **out, const uint8_t *bc, size_t bc_len)
{
    if (!out || !bc || !axvm_bc_validate(bc, bc_len)) {
        return AXVM_ERR_BAD_MAGIC;
    }

    axvm_ctx_t *ctx = (axvm_ctx_t *)calloc(1, sizeof(axvm_ctx_t));
    if (!ctx) {
        return AXVM_ERR_OOB_MEM;
    }

    ctx->bytecode = (uint8_t *)malloc(bc_len);
    if (!ctx->bytecode) {
        free(ctx);
        return AXVM_ERR_OOB_MEM;
    }
    memcpy(ctx->bytecode, bc, bc_len);
    ctx->bc_size = bc_len;

    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)bc;
    ctx->code_base = hdr->code_off;
    ctx->data_base = hdr->data_off;
    ctx->pc = hdr->entry_pc;

    axvm_status_t st = map_guarded_stack(&ctx->vm_stack_base, &ctx->vm_stack_size);
    if (st != AXVM_OK) {
        free(ctx->bytecode);
        free(ctx);
        return st;
    }
    ctx->vm_stack_top = ctx->vm_stack_base + ctx->vm_stack_size;
    ctx->sp = (uint64_t)(uintptr_t)ctx->vm_stack_top;
    ctx->sp &= ~0xFULL; /* AAPCS64 16-byte align */

    ctx->mem_pool = (uint8_t *)malloc(AXVM_MEM_POOL);
    if (!ctx->mem_pool) {
        unmap_guarded_stack(ctx->vm_stack_base);
        free(ctx->bytecode);
        free(ctx);
        return AXVM_ERR_OOB_MEM;
    }
    ctx->mem_pool_size = AXVM_MEM_POOL;
#if defined(AXVM_MEM_GUARD) && AXVM_MEM_GUARD
    ctx->mem_pool_sealed = 0;
    axvm_mem_guard_seal(ctx);
#endif

    ctx->native_bridge_base = (uint8_t *)malloc(AXVM_NATIVE_BRIDGE_SIZE);
    if (!ctx->native_bridge_base) {
        free(ctx->mem_pool);
        unmap_guarded_stack(ctx->vm_stack_base);
        free(ctx->bytecode);
        free(ctx);
        return AXVM_ERR_OOB_MEM;
    }
    ctx->native_bridge_size = AXVM_NATIVE_BRIDGE_SIZE;
    ctx->native_bridge_sp =
        ((uint64_t)(uintptr_t)ctx->native_bridge_base + AXVM_NATIVE_BRIDGE_SIZE) & ~0xFULL;

    /*
     * 模块 M：先派生 per-instance SessionSeed（熵含 vm_stack_base 地址），
     * 供随后的栈/懒解密子密钥派生使用。AXVM_DYNAMIC_SEED 关闭时为空操作。
     */
    axvm_dynseed_derive_ctx(ctx);

    if (axvm_branch_map_attach(ctx) != 0) {
        axvm_ctx_destroy(ctx);
        return AXVM_ERR_BAD_INSN;
    }

#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
    /* 模块 U：基于 SessionSeed 生成 per-instance register permutation */
    ctx->reg_perm_active = 0;
    for (uint8_t i = 0; i < AXVM_REG_COUNT; ++i) {
        ctx->reg_perm[i] = i;
    }
    if (axvm_dynseed_enabled() && ctx->session_seed_present) {
        reg_perm_build_from_session(ctx, ctx->session_seed);
    }
#endif

#if defined(AXVM_DISPATCH_PERM) && AXVM_DISPATCH_PERM
    ctx->dispatch_perm_active = 0;
    ctx->dispatch_ptr_ready = 0;
    for (uint16_t i = 0; i < 256; ++i) {
        ctx->dispatch_fwd[i] = (uint8_t)i;
        ctx->dispatch_ptr[i] = NULL;
    }
    if (axvm_dynseed_enabled() && ctx->session_seed_present) {
        axvm_dispatch_perm_build(ctx, ctx->session_seed);
    }
#endif

#if defined(AXVM_HANDLER_POLY) && AXVM_HANDLER_POLY
    ctx->handler_poly_active = 0;
    ctx->handler_poly_applied = 0;
    ctx->handler_ptr_mask = 0;
    ctx->handler_decoy_salt = 0;
    if (axvm_dynseed_enabled() && ctx->session_seed_present) {
        axvm_handler_poly_build(ctx, ctx->session_seed);
    }
#endif

    axvm_stack_crypt_init(ctx);
#if defined(AXVM_STACK_CRYPT) && AXVM_STACK_CRYPT
    if (!ctx->stack_slot_meta) {
        axvm_stack_crypt_wipe(ctx);
        unmap_guarded_stack(ctx->vm_stack_base);
        free(ctx->mem_pool);
        free(ctx->native_bridge_base);
        free(ctx->bytecode);
        free(ctx);
        return AXVM_ERR_OOB_MEM;
    }
#endif

    /* 模块 G：生成实例密钥并将代码区就地加密为静止密文（移除全局一次性明文驻留） */
    axvm_lazy_init(ctx);
    axvm_lazy_seal(ctx);

    /* 模块 J：初始化 JIT 缓存(mmap RX 码页)。失败仅降级为纯解释器，不影响创建。 */
    axvm_jit_init(ctx);

#if defined(AXVM_OPCODE_PERM) && AXVM_OPCODE_PERM
    /*
     * 模块 M：若字节码带 OPCODE_PERM flag（axpack 已正向置换 opcode）且已登记真实
     * MasterSeed，则重建逆表；否则保持恒等（内联字节码/合成种子零影响）。
     */
    ctx->opcode_perm_active = 0;
    if ((hdr->flags & AXVM_BC_FLAG_OPCODE_PERM) && axvm_dynseed_master_is_real()) {
        uint8_t key[32];
        uint8_t fwd[256];
        axvm_dynseed_get_master_plain(key);
        axvm_opcode_perm_build(key, fwd, ctx->opcode_inv);
        ctx->opcode_perm_active = 1;
        memset(key, 0, sizeof(key));
        memset(fwd, 0, sizeof(fwd));
    }
#endif

    *out = ctx;
#if defined(AXVM_MULTI_ISA) && AXVM_MULTI_ISA
    for (uint16_t ri = 0; ri < 256; ++ri) {
        ctx->riscc_wire_inv[ri] = (uint8_t)ri;
        ctx->riscc_wire_fwd[ri] = 0;
    }
    ctx->riscc_active = 0;
#endif
    return AXVM_OK;
}

void axvm_ctx_rebind_session_seed(axvm_ctx_t *ctx, const uint8_t session_seed[32])
{
    if (!ctx || !session_seed) {
        return;
    }
    memcpy(ctx->session_seed, session_seed, 32);
    ctx->session_seed_present = 1;
#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
    for (uint8_t i = 0; i < AXVM_REG_COUNT; ++i) {
        ctx->reg_perm[i] = i;
    }
    if (axvm_dynseed_enabled()) {
        reg_perm_build_from_session(ctx, session_seed);
    }
#endif
#if defined(AXVM_DISPATCH_PERM) && AXVM_DISPATCH_PERM
    ctx->dispatch_ptr_ready = 0;
    for (uint16_t i = 0; i < 256; ++i) {
        ctx->dispatch_fwd[i] = (uint8_t)i;
        ctx->dispatch_ptr[i] = NULL;
    }
    if (axvm_dynseed_enabled()) {
        axvm_dispatch_perm_build(ctx, session_seed);
    }
#endif
#if defined(AXVM_HANDLER_POLY) && AXVM_HANDLER_POLY
    ctx->handler_poly_applied = 0;
    ctx->handler_ptr_mask = 0;
    ctx->handler_decoy_salt = 0;
    if (axvm_dynseed_enabled()) {
        axvm_handler_poly_build(ctx, session_seed);
    }
#endif
}

void axvm_ctx_destroy(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    axvm_jit_destroy(ctx); /* 模块 J：释放 JIT 码页与缓存 */
    axvm_lazy_wipe(ctx);
    axvm_stack_crypt_wipe(ctx);
    axvm_dynseed_wipe(ctx); /* 模块 M：擦除 SessionSeed */
#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
    /* 擦除寄存器置换表，降低“已知/派生种子”下的恢复门槛 */
    if (ctx->reg_perm_active) {
        memset(ctx->reg_perm, 0, sizeof(ctx->reg_perm));
        ctx->reg_perm_active = 0;
    }
#endif
    unmap_guarded_stack(ctx->vm_stack_base);
#if defined(AXVM_MEM_GUARD) && AXVM_MEM_GUARD
    axvm_mem_guard_unseal(ctx);
#endif
    axvm_branch_map_detach(ctx);
    free(ctx->mem_pool);
    free(ctx->native_bridge_base);
    free(ctx->bytecode);
    free(ctx);
}

axvm_status_t axvm_ctx_reset(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return AXVM_ERR_BAD_MAGIC;
    }
    memset(ctx->x, 0, sizeof(ctx->x));
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    memset(ctx->v, 0, sizeof(ctx->v));
#endif
    ctx->nzcv = 0;
    ctx->halted = 0;
    ctx->ret_pending = 0;
    ctx->ret_val = 0;
    ctx->sp = (uint64_t)(uintptr_t)ctx->vm_stack_top;
    ctx->sp &= ~0xFULL;

    axvm_stack_crypt_reset(ctx);

#if defined(AXVM_LAZY_DECRYPT) && AXVM_LAZY_DECRYPT
    /* 上次 run 异常退出时可能残留明文块，重置前强制回写密文 */
    axvm_lazy_reencrypt_active(ctx);
#endif

    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    ctx->pc = hdr->entry_pc;
    return AXVM_OK;
}

axvm_status_t axvm_ctx_bind_args(axvm_ctx_t *ctx, const uint64_t *args, int argc)
{
    if (!ctx) {
        return AXVM_ERR_BAD_MAGIC;
    }
    if (argc < 0 || argc > 8) {
        return AXVM_ERR_BAD_INSN;
    }
    for (int i = 0; i < argc; ++i) {
        axvm_status_t wr = axvm_reg_write(ctx, (uint8_t)i, args[i]);
        if (wr != AXVM_OK) {
            return wr;
        }
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
        memcpy(&ctx->v[i], &args[i], sizeof(ctx->v[i]));
#endif
    }
    return AXVM_OK;
}

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
axvm_status_t axvm_ctx_bind_fp_args(axvm_ctx_t *ctx, const double *args, int argc)
{
    if (!ctx) {
        return AXVM_ERR_BAD_MAGIC;
    }
    if (argc < 0 || argc > 8) {
        return AXVM_ERR_BAD_INSN;
    }
    for (int i = 0; i < argc; ++i) {
        ctx->v[i] = args[i];
        /* AAPCS64 HFA 同时镜像 x 寄存器位模式，便于混合参数原生桥 */
        uint64_t bits = 0;
        memcpy(&bits, &args[i], sizeof(bits));
        axvm_status_t wr = axvm_reg_write(ctx, (uint8_t)i, bits);
        if (wr != AXVM_OK) {
            return wr;
        }
    }
    return AXVM_OK;
}
#endif

void axvm_ctx_snapshot(const axvm_ctx_t *ctx, axvm_vcpu_frame_t *frame)
{
    if (!ctx || !frame) {
        return;
    }
    memcpy(frame->x, ctx->x, sizeof(frame->x));
    frame->sp = ctx->sp;
    frame->pc = (uint32_t)ctx->pc;
    frame->nzcv = ctx->nzcv;
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    memcpy(frame->v, ctx->v, sizeof(frame->v));
    memcpy(frame->q_hi, ctx->q_hi, sizeof(frame->q_hi));
#endif
}

void axvm_ctx_restore(axvm_ctx_t *ctx, const axvm_vcpu_frame_t *frame)
{
    if (!ctx || !frame) {
        return;
    }
    memcpy(ctx->x, frame->x, sizeof(ctx->x));
    ctx->sp = frame->sp;
    ctx->pc = frame->pc;
    ctx->nzcv = frame->nzcv;
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    memcpy(ctx->v, frame->v, sizeof(ctx->v));
    memcpy(ctx->q_hi, frame->q_hi, sizeof(ctx->q_hi));
#endif
}
