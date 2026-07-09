    .text
    .align  4
    .global axvm_stub_body
    .type   axvm_stub_body, %function
axvm_stub_body:
    stp     x29, x30, [sp, #-96]!
    mov     x29, sp
    stp     x0, x1, [sp, #16]
    stp     x2, x3, [sp, #32]
    stp     x4, x5, [sp, #48]
    stp     x6, x7, [sp, #64]
    ldr     x1, [sp, #16]
    ldr     x2, [sp, #24]
    ldr     x3, [sp, #32]
    ldr     x4, [sp, #40]
    ldr     x5, [sp, #48]
    ldr     x6, [sp, #56]
    ldr     x7, [sp, #64]
    mov     w0, #1
    .align  4
    .global axvm_stub_dispatch_slot
axvm_stub_dispatch_slot:
    nop
    nop
    nop
    nop
    ldp     x29, x30, [sp], #96
    ret
    .size axvm_stub_body, .-axvm_stub_body
