#include "axvm_hmac.h"
#include "axvm_integrity.h" /* 复用模块 I 的 axvm_sha256* */

#include <string.h>

#if defined(__ANDROID__)
#include <android/log.h>
#endif

int axvm_hmac_rfc4231_selftest(void)
{
    static const uint8_t k_key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
    };
    static const uint8_t k_msg[] = "Hi There";
    static const uint8_t k_expect[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    uint8_t out[32];
    axvm_hmac_sha256(k_key, sizeof(k_key), k_msg, sizeof(k_msg) - 1u, out);
    if (memcmp(out, k_expect, sizeof(k_expect)) != 0) {
#if defined(__ANDROID__)
        __android_log_print(ANDROID_LOG_ERROR, "AXVM",
                            "hmac rfc4231 got=%02x%02x%02x%02x want=%02x%02x%02x%02x",
                            out[0], out[1], out[2], out[3],
                            k_expect[0], k_expect[1], k_expect[2], k_expect[3]);
#endif
        return 0;
    }
    return 1;
}

int axvm_hmac_apk_bind_vector_selftest(void)
{
    static const uint8_t k_raw[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    static const uint8_t k_msg_enc[62] = {
        /* AXVM_APK_BIND1 + com.example.app\\0 + cert bytes, XOR 0xA5 */
        0xe4,0xfd,0xf3,0xe8,0xfa,0xe4,0xf5,0xee,0xfa,0xe7,0xec,0xeb,0xe1,0x94,
        0xc6,0xca,0xc8,0x8b,0xc0,0xdd,0xc4,0xc8,0xd5,0xc9,0xc0,0x8b,0xc4,0xd5,0xd5,0xa5,
        0x05,0x04,0x07,0x06,0x01,0x00,0x03,0x02,0x0d,0x0c,0x0f,0x0e,0x09,0x08,0x0b,0x0a,
        0x15,0x14,0x17,0x16,0x11,0x10,0x13,0x12,0x1d,0x1c,0x1f,0x1e,0x19,0x18,0x1b,0x1a,
    };
    static const uint8_t k_expect[4] = { 0x85, 0x76, 0x58, 0x16 };
    uint8_t out[32];
    uint8_t k_msg[62];
    {
        volatile uint8_t x = 0xA5u;
        for (size_t i = 0; i < sizeof(k_msg); ++i) {
            k_msg[i] = (uint8_t)(k_msg_enc[i] ^ x);
        }
    }
    axvm_hmac_sha256(k_raw, sizeof(k_raw), k_msg, sizeof(k_msg), out);
    {
        volatile uint8_t *w = k_msg;
        for (size_t i = 0; i < sizeof(k_msg); ++i) {
            w[i] = 0;
        }
    }
    if (memcmp(out, k_expect, 4) != 0) {
#if defined(__ANDROID__)
        __android_log_print(ANDROID_LOG_ERROR, "AXVM",
                            "apk_bind vec got=%02x%02x%02x%02x",
                            out[0], out[1], out[2], out[3]);
#endif
        return 0;
    }
    return 1;
}

void axvm_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[AXVM_SHA256_DIGEST])
{
    uint8_t k_pad[AXVM_SHA256_BLOCK];
    uint8_t k_norm[AXVM_SHA256_DIGEST];
    uint8_t inner[AXVM_SHA256_DIGEST];
    axvm_sha256_ctx_t c;

    if (key_len > AXVM_SHA256_BLOCK) {
        axvm_sha256(key, key_len, k_norm);
        key = k_norm;
        key_len = AXVM_SHA256_DIGEST;
    }

    /* inner = H((K ^ ipad) || msg) */
    for (size_t i = 0; i < AXVM_SHA256_BLOCK; ++i) {
        uint8_t kb = (i < key_len && key) ? key[i] : 0u;
        k_pad[i] = kb ^ 0x36u;
    }
    axvm_sha256_init(&c);
    axvm_sha256_update(&c, k_pad, AXVM_SHA256_BLOCK);
    if (msg && msg_len) {
        axvm_sha256_update(&c, msg, msg_len);
    }
    axvm_sha256_final(&c, inner);

    /* outer = H((K ^ opad) || inner) */
    for (size_t i = 0; i < AXVM_SHA256_BLOCK; ++i) {
        uint8_t kb = (i < key_len && key) ? key[i] : 0u;
        k_pad[i] = kb ^ 0x5cu;
    }
    axvm_sha256_init(&c);
    axvm_sha256_update(&c, k_pad, AXVM_SHA256_BLOCK);
    axvm_sha256_update(&c, inner, AXVM_SHA256_DIGEST);
    axvm_sha256_final(&c, out);

    memset(k_pad, 0, sizeof(k_pad));
    memset(k_norm, 0, sizeof(k_norm));
    memset(inner, 0, sizeof(inner));
}
