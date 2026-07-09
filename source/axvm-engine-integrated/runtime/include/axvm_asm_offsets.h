#ifndef AXVM_ASM_OFFSETS_H
#define AXVM_ASM_OFFSETS_H

/*
 * 与 axvm_ctx_t 布局同步 — axvm_ctx.c 内有 _Static_assert 校验。
 * 供 axvm_native_call.S 使用。
 */
#define AXVM_CTX_OFF_X               0
#define AXVM_CTX_OFF_SP              248
#define AXVM_CTX_OFF_HOST_SP         272
#define AXVM_CTX_OFF_NATIVE_BRIDGE_SP 280
#define AXVM_CTX_OFF_V               288   /* double v[32]，仅 AXVM_FLOAT_VM */

#endif /* AXVM_ASM_OFFSETS_H */
