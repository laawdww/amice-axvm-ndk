    .text
    .align 4
    .global axvm_aapcs64_trampoline
    .type axvm_aapcs64_trampoline, %function

/*
 * uint64_t axvm_aapcs64_trampoline(
 *   axvm_ctx_t *ctx,      x0
 *   uint32_t entry_pc,    w1
 *   uint64_t a0..a7        x2-x9  (optional spill)
 * )
 * 保存 callee-saved + 对齐栈，调用 axvm_invoke
 */
axvm_aapcs64_trampoline:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!

    mov     x19, x0          /* ctx */
    mov     w20, w1          /* entry_pc */

    /* 若调用方参数在 x0-x7，已由 AAPCS 传入；绑定到 ctx */
    ldr     x0, [x19]
    /* skip — C 层 axvm_ctx_bind_args 在 JNI 入口完成 */

    mov     x0, x19
    mov     w1, w20
    bl      axvm_invoke

    ldp     x27, x28, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

    .size axvm_aapcs64_trampoline, .-axvm_aapcs64_trampoline

    .global axvm_entry_token
    .type axvm_entry_token, %function
/*
 * VMPacker 风格 token 入口：X16=token，X0-X7=调用方参数，X8=sret。
 * 保存参数后 w0=func_id，x1-x7=caller x0-x6，栈上 a7+sret_x8，BL axvm_dispatch_ex。
 */
axvm_entry_token:
    stp     x29, x30, [sp, #-96]!
    mov     x29, sp
    stp     x0, x1, [sp, #16]
    stp     x2, x3, [sp, #32]
    stp     x4, x5, [sp, #48]
    stp     x6, x7, [sp, #64]
    str     x8, [sp, #80]
    ldr     x1, [sp, #16]
    ldr     x2, [sp, #24]
    ldr     x3, [sp, #32]
    ldr     x4, [sp, #40]
    ldr     x5, [sp, #48]
    ldr     x6, [sp, #56]
    ldr     x7, [sp, #64]
    and     w0, w16, #0xFFF
    ldr     x9, [sp, #72]          /* caller x7 → a7 */
    ldr     x10, [sp, #80]         /* caller x8 → sret */
    stp     x9, x10, [sp, #-16]!
    bl      axvm_dispatch_ex
    add     sp, sp, #16
    ldp     x29, x30, [sp], #96
    ret
    .size axvm_entry_token, .-axvm_entry_token
