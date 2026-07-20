#ifndef AXGATE_AES_H
#define AXGATE_AES_H

#include "axgate_types.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 5 — AES-128-CTR（自研紧凑实现，无 OpenSSL 指纹）
 * 就地或 out-of-place 解密；调用方负责之后清零 key/iv。
 */
axgate_status_t axgate_aes128_ctr_crypt(const uint8_t key[16], const uint8_t iv[16],
                                        const uint8_t *in, uint8_t *out, size_t len);

void axgate_secure_wipe(void *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_AES_H */
