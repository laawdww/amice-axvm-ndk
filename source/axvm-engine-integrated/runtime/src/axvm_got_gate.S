    .text
    .align  4
    .global axvm_got_gate
    .type   axvm_got_gate, %function

/*
 * Stub @ dispatch slot: BL axvm_got_gate (or direct axvm_dispatch_ex).
 * Entry AAPCS64：x0=func_id, x1..x7=a0..a6；[sp]=a7, [sp+8]=sret_x8
 * （stub 已 push；返回后 stub 再 add sp,#16 弹出）。
 * 本闸门再开一帧把 a7/sret 放到新 sp 供 C 序言读取，返回时恢复 stub 栈。
 */
axvm_got_gate:
    ldp     x9, x10, [sp]            /* peek a7, sret_x8 */
    sub     sp, sp, #32
    stp     x9, x10, [sp]            /* C stack args at [sp] */
    stp     x29, x30, [sp, #16]
    mov     x29, sp
    bl      axvm_got_gate_dispatch
    ldp     x29, x30, [sp, #16]
    add     sp, sp, #32              /* restore stub a7/sret slot */
    ret
    .size   axvm_got_gate, .-axvm_got_gate
