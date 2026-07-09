#ifndef AXVM_HMAC_H
#define AXVM_HMAC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 M — HMAC-SHA256（复用模块 I 的自研 SHA256，避免重复实现/符号冲突）。
 * 无 OpenSSL 依赖。用于 MasterSeed -> SessionSeed 及子密钥派生。
 */

#define AXVM_SHA256_DIGEST 32u
#define AXVM_SHA256_BLOCK  64u

/* HMAC-SHA256(key, msg) -> out[32] */
void axvm_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[AXVM_SHA256_DIGEST]);

/* RFC 4231 test case 1；返回 1=通过。 */
int axvm_hmac_rfc4231_selftest(void);

/* apk_bind 标准向量；返回 1=通过。 */
int axvm_hmac_apk_bind_vector_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_HMAC_H */
