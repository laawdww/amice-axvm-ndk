    .text
    .align  4
    .global axvm_invoke_native_asm
    .type   axvm_invoke_native_asm, %function

#include "axvm_asm_offsets.h"

/*
 * uint64_t axvm_invoke_native_asm(axvm_ctx_t *ctx, void *fn, uint64_t *x1_out,
 *                                 uint64_t call_sp);
 *
 * 1. 保存宿主 SP 到 ctx->host_sp_saved
 * 2. 切换至 ctx->native_bridge_sp 独立小栈（AAPCS64 16B 对齐）
 * 3. 从 ctx->x[0..8] / ctx->v[0..7] 装载 AAPCS64 参数，BLR 原生函数
 * 4. 写回 d0-d7 至 ctx->v[0..7]，可选写回 x1_out，恢复宿主 SP，返回 x0
 */
axvm_invoke_native_asm:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!

    mov     x19, x0                 /* ctx */
    mov     x20, x1                 /* fn */
    mov     x24, x2                 /* x1_out */
    mov     x25, x3                 /* call_sp（0=默认 bridge 顶） */

    /* 保存宿主栈顶 */
    mov     x21, sp
    str     x21, [x19, #AXVM_CTX_OFF_HOST_SP]

    /* 切换调用栈：优先使用 C 侧解密的 guest 栈镜像 */
    cbnz    x25, 2f
    ldr     x25, [x19, #AXVM_CTX_OFF_NATIVE_BRIDGE_SP]
2:  mov     sp, x25

    /* AAPCS64 整数参数 x0-x8（x8 兼容 sret/间接返回） */
    add     x9, x19, #AXVM_CTX_OFF_X
    ldp     x0, x1, [x9]
    ldp     x2, x3, [x9, #16]
    ldp     x4, x5, [x9, #32]
    ldp     x6, x7, [x9, #48]
    ldr     x8, [x9, #64]

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    /* 浮点参数 v0-v7（double）覆盖 d0-d7 */
    add     x23, x19, #AXVM_CTX_OFF_V
    ldp     d0, d1, [x23]
    ldp     d2, d3, [x23, #16]
    ldp     d4, d5, [x23, #32]
    ldp     d6, d7, [x23, #48]
#endif

    blr     x20

    cbz     x24, 1f
    str     x1, [x24]
1:

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    /* 写回 caller-saved 浮点结果寄存器 */
    add     x23, x19, #AXVM_CTX_OFF_V
    stp     d0, d1, [x23]
    stp     d2, d3, [x23, #16]
    stp     d4, d5, [x23, #32]
    stp     d6, d7, [x23, #48]
#endif

    /* 恢复宿主 SP */
    ldr     x21, [x19, #AXVM_CTX_OFF_HOST_SP]
    mov     sp, x21

    ldp     x27, x28, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

    .size axvm_invoke_native_asm, .-axvm_invoke_native_asm
