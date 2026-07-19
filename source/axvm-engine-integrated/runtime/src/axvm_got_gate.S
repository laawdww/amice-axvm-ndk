    .text
    .align  4
    .global x7g
    .type   x7g, %function

/*
 * Stub @ dispatch slot: BL x7g (or direct x7d).
 * Entry AAPCS64：x0=func_id, x1..x7=a0..a6；[sp]=a7, [sp+8]=sret_x8
 * （stub 已 push；返回后 stub 再 add sp,#16 弹出）。
 * 本闸门再开一帧把 a7/sret 放到新 sp 供 C 序言读取，返回时恢复 stub 栈。
 */
x7g:
    ldp     x9, x10, [sp]            /* peek a7, sret_x8 */
    sub     sp, sp, #32
    stp     x9, x10, [sp]            /* C stack args at [sp] */
    stp     x29, x30, [sp, #16]
    mov     x29, sp
    bl      x7g_dispatch
    ldp     x29, x30, [sp, #16]
    add     sp, sp, #32              /* restore stub a7/sret slot */
    ret
    .size   x7g, .-x7g
