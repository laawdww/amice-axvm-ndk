#ifndef AXVM_STRCRYPT_H
#define AXVM_STRCRYPT_H

#include <stddef.h>
#include <stdint.h>

struct axvm_ctx;

#ifdef __cplusplus
extern "C" {
#endif

#define AXVM_STRCRYPT_ROUNDS 4

int axvm_strcrypt_enabled(void);

char *axvm_strcrypt_dec(char *dest, const uint8_t *enc, size_t len);
char *axvm_strcrypt_dec_ex(char *dest, const uint8_t *enc, size_t len,
                           const uint8_t key[16]);
char *axvm_strcrypt_dec_ctx(char *dest, const uint8_t *enc, size_t len,
                            const struct axvm_ctx *ctx);

int axvm_strcrypt_selftest(void);
int axvm_strcrypt_session_selftest(struct axvm_ctx *ctx);

/* 模块 AB：SessionSeed 派生 JNI 跨层隧道 token（对合 XOR 混合） */
uint32_t axvm_jni_tunnel_token(const struct axvm_ctx *ctx, uint32_t plain);
int axvm_jni_tunnel_verify(const struct axvm_ctx *ctx, uint32_t token,
                           uint32_t expect_plain);
int axvm_jni_tunnel_selftest(struct axvm_ctx *ctx);

#define AXVM_STR(enc, len) \
    axvm_strcrypt_dec((char[(len) + 1]){0}, (enc), (len))

#ifdef __cplusplus
}
#endif

#endif /* AXVM_STRCRYPT_H */
