/* axgate_entry.S — ARM64：销毁易失上下文后跳转 OEP（不返回） */
    .text
    .align 4
    .global axgate_jump_oep
    .type axgate_jump_oep, %function
axgate_jump_oep:
    /* x0 = oep */
    mov     x16, x0
    /* 清常见参数/临时寄存器，降低栈/寄存器残留 */
    mov     x0,  xzr
    mov     x1,  xzr
    mov     x2,  xzr
    mov     x3,  xzr
    mov     x4,  xzr
    mov     x5,  xzr
    mov     x6,  xzr
    mov     x7,  xzr
    mov     x8,  xzr
    /* 不主动改 SP：调用约定由 OEP 自行建立帧 */
    br      x16
    .size axgate_jump_oep, .-axgate_jump_oep
