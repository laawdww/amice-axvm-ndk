#include "axvm_bridge.h"
#include "axvm_guard.h"
#include "axvm_integrity.h"
#include "axvm_stack_crypt.h"
#include "axvm_log.h"
#include "axvm.h"
#include "axvm_reg.h"
#include "axvm_engine.h"

#include <stddef.h>
#include <string.h>

#if defined(__aarch64__)
extern uint64_t axvm_invoke_native_asm(axvm_ctx_t *ctx, void *fn, uint64_t *x1_out,
                                       uint64_t call_sp);
#else
uint64_t axvm_invoke_native_asm(axvm_ctx_t *ctx, void *fn, uint64_t *x1_out,
                                uint64_t call_sp)
{
    (void)call_sp;
    typedef uint64_t (*fn8)(uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t, uint64_t, uint64_t, uint64_t);
    fn8 f = (fn8)fn;
    uint64_t rv = f(ctx->x[0], ctx->x[1], ctx->x[2], ctx->x[3],
             ctx->x[4], ctx->x[5], ctx->x[6], ctx->x[7]);
    if (x1_out) {
        *x1_out = 0;
    }
    return rv;
}
#endif

/*
 * 将 VM 加密栈区 [ctx->sp, vm_stack_top) 解密复制到 native bridge，
 * 供 AAPCS64 第 9+ 个参数读取。返回 0 表示使用默认 bridge 顶（无栈参数）。
 */
static axvm_status_t axvm_bridge_stage_native_stack(axvm_ctx_t *ctx, uint64_t *call_sp_out)
{
    if (!ctx || !call_sp_out) {
        return AXVM_ERR_BAD_MAGIC;
    }
    *call_sp_out = 0;

    uintptr_t guest_sp = (uintptr_t)ctx->sp;
    uintptr_t stack_base = (uintptr_t)ctx->vm_stack_base;
    uintptr_t stack_top = (uintptr_t)ctx->vm_stack_top;
    if (guest_sp >= stack_top) {
        return AXVM_OK;
    }
    if (guest_sp < stack_base) {
        return AXVM_ERR_OOB_STACK;
    }
    if (guest_sp & 0xF) {
        return AXVM_ERR_ALIGN;
    }

    size_t used = stack_top - guest_sp;
    if (used > ctx->native_bridge_size - 256u) {
        return AXVM_ERR_OOB_STACK;
    }

    uint64_t call_sp = ctx->native_bridge_sp - used;
    call_sp &= ~0xFULL;
    size_t staging = (size_t)(ctx->native_bridge_sp - call_sp);
    uint8_t *dst = (uint8_t *)(uintptr_t)call_sp;

    for (size_t off = 0; off < staging; off += 8) {
        uintptr_t gaddr = guest_sp + off;
        if (gaddr + 8 > stack_top) {
            break;
        }
        uint64_t word = 0;
        axvm_status_t st = axvm_vm_stack_peek_plain64(ctx, (uint64_t)gaddr, &word);
        if (st != AXVM_OK) {
            return st;
        }
        memcpy(dst + off, &word, 8);
    }

    *call_sp_out = call_sp;
    return AXVM_OK;
}

axvm_status_t axvm_bridge_enter(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return AXVM_ERR_BAD_MAGIC;
    }
    axvm_guard_ensure_init();
    axvm_status_t st = axvm_guard_check(axvm_guard_global());
    if (st != AXVM_OK) {
        axvm_guard_trip_ctx(ctx, axvm_guard_global(), axvm_guard_last_flags(axvm_guard_global()));
        return st;
    }
    /* 模块 I：VM 初始化全量分段完整性校验（未 arm 时空转） */
    axvm_status_t ist = axvm_integrity_probe_init(ctx);
    if (ist != AXVM_OK) {
        return ist;
    }
    return axvm_ctx_reset(ctx);
}

uint64_t axvm_invoke(axvm_ctx_t *ctx, uint32_t entry_pc)
{
    if (!ctx) {
        return 0;
    }
#if defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
    axvm_guard_chain_begin_ctx(ctx, entry_pc);
#endif
    ctx->pc = entry_pc;
#if defined(AXVM_MULTI_ISA) && AXVM_MULTI_ISA
    if (ctx->bytecode) {
        const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
        if (hdr->flags & AXVM_BC_FLAG_RISCC) {
            axvm_status_t st = axvm_engine_run(ctx, AXVM_ENGINE_RISCC);
            if (st != AXVM_OK) {
                AXVM_LOGE("riscc run fail st=%d pc=%u", (int)st, (unsigned)ctx->pc);
                return 0;
            }
            return ctx->ret_val;
        }
    }
#endif
    axvm_status_t st = axvm_run(ctx);
    if (st != AXVM_OK) {
        AXVM_LOGE("run fail st=%d pc=%u rv=%llu",
                  (int)st, (unsigned)ctx->pc,
                  (unsigned long long)ctx->ret_val);
        return 0;
    }
    return ctx->ret_val;
}

axvm_status_t axvm_bridge_leave(axvm_ctx_t *ctx, uint64_t *ret_out)
{
    if (!ctx || !ret_out) {
        return AXVM_ERR_BAD_MAGIC;
    }
    *ret_out = ctx->ret_val;
    return AXVM_OK;
}

int axvm_bridge_register_native(axvm_ctx_t *ctx, void *addr)
{
    if (!ctx || !addr) {
        return -1;
    }
    if (ctx->native_count >= AXVM_NATIVE_MAX) {
        return -1;
    }
    uint16_t idx = ctx->native_count++;
    ctx->natives[idx].addr = addr;
    ctx->natives[idx].flags = 0;
    axvm_guard_ensure_init();
    axvm_guard_hook_bind(axvm_guard_global(), addr);
    return (int)idx;
}

axvm_status_t axvm_bridge_call_native(axvm_ctx_t *ctx, uint16_t slot, uint64_t *ret_out)
{
    if (!ctx || !ret_out) {
        return AXVM_ERR_BAD_MAGIC;
    }
    if (slot >= ctx->native_count || !ctx->natives[slot].addr) {
        return AXVM_ERR_NATIVE;
    }
    return axvm_bridge_call_native_addr(ctx, ctx->natives[slot].addr, ret_out);
}

axvm_status_t axvm_bridge_call_native_addr(axvm_ctx_t *ctx, void *addr, uint64_t *ret_out)
{
    if (!ctx || !addr || !ret_out) {
        return AXVM_ERR_BAD_MAGIC;
    }

    axvm_guard_ensure_init();
    axvm_status_t gst = axvm_guard_probe_native(ctx, axvm_guard_global());
    if (gst != AXVM_OK) {
        return gst;
    }
    axvm_status_t ist = axvm_integrity_probe_native(ctx);
    if (ist != AXVM_OK) {
        return ist;
    }

#if defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
    axvm_guard_observe_bl_native(axvm_guard_global(), ctx, 0xFFFFu, (uint64_t)ctx->pc);
#endif

    axvm_vcpu_frame_t snap;
    axvm_ctx_snapshot(ctx, &snap);

#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
    if (ctx->reg_perm_active) {
        uint64_t tmp[AXVM_REG_COUNT];
        for (uint8_t i = 0; i < AXVM_REG_COUNT; ++i) {
            tmp[i] = ctx->x[ctx->reg_perm[i]];
        }
        memcpy(ctx->x, tmp, sizeof(tmp));
    }
#endif

    uint64_t call_sp = 0;
    axvm_status_t sst = axvm_bridge_stage_native_stack(ctx, &call_sp);
    if (sst != AXVM_OK) {
        axvm_ctx_restore(ctx, &snap);
        return sst;
    }

    uint64_t rv_hi = 0;
    uint64_t rv = axvm_invoke_native_asm(ctx, addr, &rv_hi, call_sp);

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    double v_post[8];
    memcpy(v_post, ctx->v, sizeof(v_post));
#endif

    axvm_ctx_restore(ctx, &snap);
    axvm_reg_write(ctx, 0, rv);
    axvm_reg_write(ctx, 1, rv_hi);
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    memcpy(ctx->v, v_post, sizeof(v_post));
#endif
    *ret_out = rv;
    return AXVM_OK;
}
