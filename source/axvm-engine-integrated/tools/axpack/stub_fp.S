    .text
    .align  4
    /* 模块 F：浮点 AAPCS64 stub — d0-d7 参数/返回值，经 x1-x7 传入 dispatch */
    .global axvm_stub_body_fp
    .type   axvm_stub_body_fp, %function
axvm_stub_body_fp:
    stp     x29, x30, [sp, #-112]!
    mov     x29, sp
    stp     d0, d1, [sp, #16]
    stp     d2, d3, [sp, #32]
    stp     d4, d5, [sp, #48]
    stp     d6, d7, [sp, #64]
    fmov    x1, d0
    fmov    x2, d1
    fmov    x3, d2
    fmov    x4, d3
    fmov    x5, d4
    fmov    x6, d5
    fmov    x7, d6
    mov     w0, #1
    .align  4
axvm_stub_dispatch_slot_fp:
    nop
    nop
    nop
    nop
    fmov    d0, x0
    ldp     x29, x30, [sp], #112
    ret
    .size axvm_stub_body_fp, .-axvm_stub_body_fp
