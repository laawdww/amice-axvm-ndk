#ifndef AXVM_STACK_CRYPT_H
#define AXVM_STACK_CRYPT_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 编译期开关由 AXVM_STACK_CRYPT 控制；运行时查询 */
int axvm_stack_crypt_enabled(void);

/* 实例生命周期 */
void axvm_stack_crypt_init(axvm_ctx_t *ctx);
void axvm_stack_crypt_reset(axvm_ctx_t *ctx);
void axvm_stack_crypt_wipe(axvm_ctx_t *ctx);

/*
 * 统一 VM 栈访问（解释器 mem_* / PUSH / POP 路径调用）
 * 内存中始终保存密文；读时解密，写时加密；每次操作后滚动主密钥。
 */
axvm_status_t axvm_vm_stack_store64(axvm_ctx_t *ctx, uint64_t addr, uint64_t val);
axvm_status_t axvm_vm_stack_load64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out);
axvm_status_t axvm_vm_stack_store32(axvm_ctx_t *ctx, uint64_t addr, uint32_t val);
axvm_status_t axvm_vm_stack_load32(axvm_ctx_t *ctx, uint64_t addr, uint32_t *out);
axvm_status_t axvm_vm_stack_store16(axvm_ctx_t *ctx, uint64_t addr, uint16_t val);
axvm_status_t axvm_vm_stack_load16(axvm_ctx_t *ctx, uint64_t addr, uint16_t *out);
axvm_status_t axvm_vm_stack_store8(axvm_ctx_t *ctx, uint64_t addr, uint8_t val);
axvm_status_t axvm_vm_stack_load8(axvm_ctx_t *ctx, uint64_t addr, uint8_t *out);

axvm_status_t axvm_vm_stack_push64(axvm_ctx_t *ctx, uint64_t val);
axvm_status_t axvm_vm_stack_pop64(axvm_ctx_t *ctx, uint64_t *out);
axvm_status_t axvm_vm_stack_peek64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out);

/* 解密读取但不滚动栈密钥（BL_NATIVE 栈参数镜像用） */
axvm_status_t axvm_vm_stack_peek_plain64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out);

/* 调试：返回当前滚动密钥混合值（gdb 断点观测用） */
uint64_t axvm_stack_crypt_key_mix(const axvm_ctx_t *ctx);

/*
 * 内存 dump 对抗测试：在 VM 执行栈写指令后扫描物理栈区，
 * 若发现明文魔数出现在栈区则失败。返回 0=PASS。
 */
int axvm_stack_crypt_probe_plaintext(axvm_ctx_t *ctx, uint64_t magic);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_STACK_CRYPT_H */
