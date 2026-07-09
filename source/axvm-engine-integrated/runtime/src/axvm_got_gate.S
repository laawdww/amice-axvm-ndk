    .text
    .align  4
    .global axvm_got_gate
    .type   axvm_got_gate, %function

/*
 * Stub @ offset 64: MOVZ/MOVK x16 + BLR x16 -> axvm_got_gate
 * 入口 AAPCS64：x0=func_id, x1..x7=原始 a0..a6（stub 已将原 x0 挪到 x1）
 * 仅保存帧指针，避免 C 序言破坏参数寄存器。
 */
axvm_got_gate:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      axvm_got_gate_dispatch
    ldp     x29, x30, [sp], #16
    ret
    .size   axvm_got_gate, .-axvm_got_gate
