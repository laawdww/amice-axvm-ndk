#ifndef AXVM_BRIDGE_H
#define AXVM_BRIDGE_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

axvm_status_t axvm_bridge_enter(axvm_ctx_t *ctx);
uint64_t      axvm_invoke(axvm_ctx_t *ctx, uint32_t entry_pc);
axvm_status_t axvm_bridge_leave(axvm_ctx_t *ctx, uint64_t *ret_out);
int           axvm_bridge_register_native(axvm_ctx_t *ctx, void *addr);

/* AArch64 汇编跳板 — axvm_entry.S */
uint64_t axvm_aapcs64_trampoline(axvm_ctx_t *ctx, uint32_t entry_pc);

/*
 * BL_NATIVE 底层：切换物理栈后 BLR 原生函数（axvm_native_call.S）。
 * 非 arm64 主机构建时回退为直接 C 函数指针调用。
 */
uint64_t axvm_invoke_native_asm(axvm_ctx_t *ctx, void *fn, uint64_t *x1_out,
                                uint64_t call_sp);
axvm_status_t axvm_bridge_call_native(axvm_ctx_t *ctx, uint16_t slot, uint64_t *ret_out);
axvm_status_t axvm_bridge_call_native_addr(axvm_ctx_t *ctx, void *addr, uint64_t *ret_out);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_BRIDGE_H */
