#include "axvm_strcrypt.h"
#include "axvm_dynseed.h"
#include "axvm_ctx.h"

#include <string.h>

static const uint8_t g_strcrypt_key[16] = {
    0xA7, 0x3C, 0x91, 0x5E, 0xD2, 0x48, 0xF6, 0x0B,
    0x73, 0x29, 0xBE, 0x64, 0x18, 0xC5, 0x8A, 0x4F,
};

int axvm_strcrypt_enabled(void)
{
#if defined(AXVM_STRCRYPT) && AXVM_STRCRYPT
    return 1;
#else
    return 0;
#endif
}

static void strcrypt_decrypt_buf(char *buf, size_t len, const uint8_t key[16])
{
    for (int r = AXVM_STRCRYPT_ROUNDS - 1; r >= 0; --r) {
        for (size_t i = 0; i < len; ++i) {
            uint8_t b = (uint8_t)buf[i];
            b = (uint8_t)(b - key[i & 15]);
            b ^= (uint8_t)(r + 1);
            b = (uint8_t)((b >> 3) | (b << 5));
            b ^= key[(i + (size_t)r * 3u) & 15];
            buf[i] = (char)b;
        }
    }
}

static void strcrypt_encrypt_buf(char *buf, size_t len, const uint8_t key[16])
{
    for (int r = 0; r < AXVM_STRCRYPT_ROUNDS; ++r) {
        for (size_t i = 0; i < len; ++i) {
            uint8_t b = (uint8_t)buf[i];
            b ^= key[(i + (size_t)r * 3u) & 15];
            b = (uint8_t)((b << 3) | (b >> 5));
            b ^= (uint8_t)(r + 1);
            b = (uint8_t)(b + key[i & 15]);
            buf[i] = (char)b;
        }
    }
}

char *axvm_strcrypt_dec_ex(char *dest, const uint8_t *enc, size_t len, const uint8_t key[16])
{
    if (!dest || !enc || !key) {
        return dest;
    }
    memcpy(dest, enc, len);
    strcrypt_decrypt_buf(dest, len, key);
    dest[len] = '\0';
    return dest;
}

char *axvm_strcrypt_dec(char *dest, const uint8_t *enc, size_t len)
{
    return axvm_strcrypt_dec_ex(dest, enc, len, g_strcrypt_key);
}

char *axvm_strcrypt_dec_ctx(char *dest, const uint8_t *enc, size_t len, const axvm_ctx_t *ctx)
{
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (ctx && ctx->session_seed_present) {
        uint8_t subkey[16];
        axvm_dynseed_subkey(ctx->session_seed, AXVM_DYNSEED_PURPOSE_STRCRYPT,
                            subkey, sizeof(subkey));
        char *out = axvm_strcrypt_dec_ex(dest, enc, len, subkey);
        volatile uint8_t *w = subkey;
        for (size_t i = 0; i < sizeof(subkey); ++i) {
            w[i] = 0;
        }
        return out;
    }
#endif
    return axvm_strcrypt_dec(dest, enc, len);
}

int axvm_strcrypt_selftest(void)
{
#if !defined(AXVM_STRCRYPT) || !AXVM_STRCRYPT
    return 0;
#endif
    static const uint8_t enc[] = {
        0xEE, 0xE1, 0x4B, 0x5D, 0x25, 0x69, 0x6A, 0xF6,
        0x24, 0x94, 0xD4, 0x0B,
    };
    char buf[32];
    axvm_strcrypt_dec(buf, enc, sizeof(enc));
    return (strcmp(buf, "AXVM_STR7_OK") == 0) ? 0 : 1;
}

int axvm_strcrypt_session_selftest(axvm_ctx_t *ctx)
{
#if !defined(AXVM_STRCRYPT) || !AXVM_STRCRYPT
    (void)ctx;
    return 0;
#endif
#if !defined(AXVM_DYNAMIC_SEED) || !AXVM_DYNAMIC_SEED
    (void)ctx;
    return 0;
#endif
    if (!ctx || !ctx->session_seed_present) {
        return 1;
    }
    static const char plain[] = "AXVM_Q_OK";
    const size_t n = sizeof(plain) - 1u;
    uint8_t subkey[16];
    axvm_dynseed_subkey(ctx->session_seed, AXVM_DYNSEED_PURPOSE_STRCRYPT,
                        subkey, sizeof(subkey));
    char enc[32];
    memcpy(enc, plain, n);
    strcrypt_encrypt_buf(enc, n, subkey);
    char buf[32];
    axvm_strcrypt_dec_ex(buf, (const uint8_t *)enc, n, subkey);
    volatile uint8_t *w = subkey;
    for (size_t i = 0; i < sizeof(subkey); ++i) {
        w[i] = 0;
    }
    return (strcmp(buf, plain) == 0) ? 0 : 2;
}

uint32_t axvm_jni_tunnel_token(const axvm_ctx_t *ctx, uint32_t plain)
{
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (ctx && ctx->session_seed_present) {
        uint8_t subkey[16];
        axvm_dynseed_subkey(ctx->session_seed, AXVM_DYNSEED_PURPOSE_JNI_TUN,
                            subkey, sizeof(subkey));
        uint32_t tok = plain ^ (uint32_t)subkey[0] ^ ((uint32_t)subkey[7] << 8);
        tok ^= (uint32_t)subkey[15] << 16;
        volatile uint8_t *w = subkey;
        for (size_t i = 0; i < sizeof(subkey); ++i) {
            w[i] = 0;
        }
        return tok;
    }
#endif
    return plain ^ 0xA5A5A5A5u;
}

int axvm_jni_tunnel_selftest(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return 1;
    }
    uint32_t tok = axvm_jni_tunnel_token(ctx, 0x12345678u);
    if (axvm_jni_tunnel_verify(ctx, tok, 0x12345678u) != 0) {
        return 2;
    }
    if (axvm_jni_tunnel_verify(ctx, tok ^ 1u, 0x12345678u) == 0) {
        return 3;
    }
    return 0;
}

int axvm_jni_tunnel_verify(const axvm_ctx_t *ctx, uint32_t token, uint32_t expect_plain)
{
    return axvm_jni_tunnel_token(ctx, expect_plain) == token ? 0 : 1;
}
