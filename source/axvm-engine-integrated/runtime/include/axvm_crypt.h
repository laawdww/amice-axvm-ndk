#ifndef AXVM_CRYPT_H
#define AXVM_CRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 模块 N：pack 字节码流密码（多态变体由 MasterSeed 派生） */
void axvm_crypt_set_key(const uint8_t *seed, size_t n);
void axvm_crypt_set_variant(uint8_t variant);
int  axvm_crypt_variant(void);
void axvm_crypt_decrypt(uint8_t *buf, size_t len, uint32_t func_id);

/* 与 pack 侧 cryptVariant 相同方向；对 v1-v3 为 XOR 自逆，v0 需调用两次还原 */
void axvm_crypt_encrypt(uint8_t *buf, size_t len, uint32_t func_id);
int axvm_crypt_roundtrip_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_CRYPT_H */
