#include "axvm_crypt.h"

#include <string.h>

static uint8_t g_key[16];
static uint8_t g_variant;

void axvm_crypt_set_key(const uint8_t *seed, size_t n)
{
    memset(g_key, 0, sizeof(g_key));
    if (!seed || n == 0) {
        return;
    }
    if (n > sizeof(g_key)) {
        n = sizeof(g_key);
    }
    memcpy(g_key, seed, n);
    g_variant = (uint8_t)(g_key[15] & 3u);
}

void axvm_crypt_set_variant(uint8_t variant)
{
    g_variant = (uint8_t)(variant & 3u);
}

int axvm_crypt_variant(void)
{
    return (int)g_variant;
}

static void crypt_v0(uint8_t *buf, size_t len, uint32_t func_id)
{
    uint8_t roll = (uint8_t)(func_id ^ g_key[0] ^ 0xA5u);
    for (size_t i = 0; i < len; ++i) {
        uint8_t k = (uint8_t)(g_key[i & 15] ^ roll ^ (uint8_t)(i * 13u + func_id));
        buf[i] ^= k;
        roll = (uint8_t)((roll + k) ^ 0x5Au);
    }
}

static void crypt_v1(uint8_t *buf, size_t len, uint32_t func_id)
{
    uint32_t s = func_id ^ 0xC3A5C85Cu;
    for (size_t i = 0; i < len; ++i) {
        s = s * 1664525u + 1013904223u + (uint32_t)g_key[i & 15];
        uint8_t k = (uint8_t)(s >> 24);
        k ^= (uint8_t)(i * 7u + func_id);
        uint8_t cipher = buf[i];
        buf[i] ^= k;
    }
}

static void crypt_v2(uint8_t *buf, size_t len, uint32_t func_id)
{
    uint8_t roll = (uint8_t)(g_key[7] ^ func_id);
    for (size_t i = 0; i < len; ++i) {
        uint8_t k = (uint8_t)(g_key[(i + func_id) & 15] + roll + (uint8_t)(i >> 2));
        buf[i] ^= k;
        roll = (uint8_t)((roll * 31u + k) ^ g_key[i & 15]);
    }
}

static void crypt_v3(uint8_t *buf, size_t len, uint32_t func_id)
{
    uint64_t s = ((uint64_t)g_key[0] << 56) | ((uint64_t)g_key[1] << 48) | func_id;
    for (size_t i = 0; i < len; ++i) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        uint8_t k = (uint8_t)(s >> (i & 7)) ^ g_key[(i * 3u + func_id) & 15];
        buf[i] ^= k;
        s += k + (uint64_t)i;
    }
}

void axvm_crypt_decrypt(uint8_t *buf, size_t len, uint32_t func_id)
{
    if (!buf || len == 0) {
        return;
    }
    switch (g_variant) {
    case 1:
        crypt_v1(buf, len, func_id);
        break;
    case 2:
        crypt_v2(buf, len, func_id);
        break;
    case 3:
        crypt_v3(buf, len, func_id);
        break;
    default:
        crypt_v0(buf, len, func_id);
        break;
    }
}

void axvm_crypt_encrypt(uint8_t *buf, size_t len, uint32_t func_id)
{
    axvm_crypt_decrypt(buf, len, func_id);
}

int axvm_crypt_roundtrip_selftest(void)
{
    uint8_t seed[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    axvm_crypt_set_key(seed, sizeof(seed));
    for (int v = 0; v <= 3; ++v) {
        axvm_crypt_set_variant((uint8_t)v);
        uint8_t buf[16] = { 0x10, 0x13, 0x00, 0x00, 0x01, 0x7e, 0x02, 0x5a, 0x5b, 0x50,
                            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
        uint8_t ref[16];
        memcpy(ref, buf, sizeof(ref));
        axvm_crypt_encrypt(buf, sizeof(buf), 7);
        if (memcmp(buf, ref, sizeof(ref)) == 0) {
            return v + 10;
        }
        axvm_crypt_decrypt(buf, sizeof(buf), 7);
        if (memcmp(buf, ref, sizeof(ref)) != 0) {
            return v + 20;
        }
    }
    return 0;
}
