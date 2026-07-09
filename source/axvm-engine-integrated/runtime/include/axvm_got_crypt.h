#ifndef AXVM_GOT_CRYPT_H
#define AXVM_GOT_CRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 模块 P：GOT/跳板 dispatch 指针运行时加密（需 AXVM_DYNAMIC_SEED） */

int axvm_got_crypt_enabled(void);

/* 注册 dispatch 目标并生成加密副本（明文指针不落 stub 可执行区） */
void axvm_got_crypt_bind_dispatch(void *dispatch_plain);

/* 运行时解密 dispatch 指针（axvm_got_gate 调用） */
void *axvm_got_crypt_resolve_dispatch(void);

/*
 * 探测 stub dispatch 槽 @ offset 64 是否泄露明文 dispatch 地址。
 * 0=无明文泄露(PASS), 1=发现明文片段。
 */
int axvm_got_crypt_probe_stub_leak(const void *stub_slot16);

int axvm_got_crypt_selftest(void);

/* 模块 P：stub BL 跳板入口（ARM64） */
uint64_t axvm_got_gate(void);

/* 扫描已加载模块首个 stub dispatch 槽是否泄露明文指针；-1=无模块 */
int axvm_loader_got_leak_probe(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_GOT_CRYPT_H */
