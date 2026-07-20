#include "axgate_kdf.h"
#include "axgate_integrity.h"
#include "axgate_aes.h"

#include <string.h>

#define AXGATE_UK_XOR 0xD00DF00DD00DF00Dull

static char g_rt_pkg[96];
static uint8_t g_rt_cert[32];
static int g_rt_ready;

void axgate_uk_seed(uint8_t out[32])
{
    for (int i = 0; i < 4; i++) {
        uint64_t v = axgate_uk_q[i] ^ AXGATE_UK_XOR;
        out[i * 8 + 0] = (uint8_t)(v);
        out[i * 8 + 1] = (uint8_t)(v >> 8);
        out[i * 8 + 2] = (uint8_t)(v >> 16);
        out[i * 8 + 3] = (uint8_t)(v >> 24);
        out[i * 8 + 4] = (uint8_t)(v >> 32);
        out[i * 8 + 5] = (uint8_t)(v >> 40);
        out[i * 8 + 6] = (uint8_t)(v >> 48);
        out[i * 8 + 7] = (uint8_t)(v >> 56);
    }
}

int axgate_set_runtime_identity(const char *pkg, const uint8_t cert[32])
{
    if (!pkg || !cert) {
        return 0;
    }
    size_t n = strlen(pkg);
    if (n == 0 || n >= sizeof(g_rt_pkg)) {
        return 0;
    }
    memcpy(g_rt_pkg, pkg, n + 1);
    memcpy(g_rt_cert, cert, 32);
    g_rt_ready = 1;
    return 1;
}

int axgate_runtime_identity(char *out_pkg, size_t pkg_cap, uint8_t out_cert[32])
{
    if (!g_rt_ready || !out_pkg || pkg_cap < 2 || !out_cert) {
        return 0;
    }
    size_t n = strlen(g_rt_pkg);
    if (n == 0 || n + 1 > pkg_cap) {
        return 0;
    }
    memcpy(out_pkg, g_rt_pkg, n + 1);
    memcpy(out_cert, g_rt_cert, 32);
    return 1;
}

void axgate_kdf_wrap_mask(const axgate_desc_t *desc, uint8_t mask[32])
{
    char pkg[96];
    uint8_t cert[32];
    uint8_t seed[32];
    uint8_t buf[32 + 4 + 96 + 1 + 32 + 4 + 4 + 16];
    size_t o = 0;
    size_t pkg_len = 0;

    memset(buf, 0, sizeof(buf));
    memset(pkg, 0, sizeof(pkg));
    memset(cert, 0, sizeof(cert));
    axgate_uk_seed(seed);

    if (!axgate_runtime_identity(pkg, sizeof(pkg), cert)) {
        axgate_sha256(seed, 32, mask);
        axgate_secure_wipe(seed, sizeof(seed));
        return;
    }
    pkg_len = strlen(pkg);
    if (pkg_len == 0 || pkg_len >= sizeof(pkg)) {
        axgate_sha256(seed, 32, mask);
        axgate_secure_wipe(seed, sizeof(seed));
        axgate_secure_wipe(pkg, sizeof(pkg));
        axgate_secure_wipe(cert, sizeof(cert));
        return;
    }

    memcpy(buf + o, seed, 32);
    o += 32;
    buf[o++] = 0x55;
    buf[o++] = 0x57;
    buf[o++] = 0x32;
    buf[o++] = 0x00;
    memcpy(buf + o, pkg, pkg_len);
    o += pkg_len;
    buf[o++] = 0;
    memcpy(buf + o, cert, 32);
    o += 32;
    buf[o++] = (uint8_t)(desc->image_size);
    buf[o++] = (uint8_t)(desc->image_size >> 8);
    buf[o++] = (uint8_t)(desc->image_size >> 16);
    buf[o++] = (uint8_t)(desc->image_size >> 24);
    buf[o++] = (uint8_t)(desc->reserved1);
    buf[o++] = (uint8_t)(desc->reserved1 >> 8);
    buf[o++] = (uint8_t)(desc->reserved1 >> 16);
    buf[o++] = (uint8_t)(desc->reserved1 >> 24);
    memcpy(buf + o, desc->sha256, 16);
    o += 16;

    axgate_sha256(buf, o, mask);
    axgate_secure_wipe(buf, sizeof(buf));
    axgate_secure_wipe(seed, sizeof(seed));
    axgate_secure_wipe(pkg, sizeof(pkg));
    axgate_secure_wipe(cert, sizeof(cert));
}

axgate_status_t axgate_unwrap_aes_material(const axgate_desc_t *desc,
                                           uint8_t key[16], uint8_t iv[16])
{
    if (!desc || !key || !iv) {
        return AXGATE_ERR_ARGS;
    }
    if (desc->flags & AXGATE_FLAG_KEY_WRAP) {
        uint8_t mask[32];
        uint8_t plain[32];
        if (!g_rt_ready) {
            return AXGATE_ERR_AES;
        }
        axgate_kdf_wrap_mask(desc, mask);
        for (int i = 0; i < 32; i++) {
            plain[i] = (uint8_t)(desc->key_wrap[i] ^ mask[i]);
        }
        axgate_secure_wipe(mask, sizeof(mask));
        memcpy(key, plain, 16);
        memcpy(iv, plain + 16, 16);
        axgate_secure_wipe(plain, sizeof(plain));
        return AXGATE_OK;
    }
    memcpy(key, desc->key_wrap, 16);
    memcpy(iv, desc->key_wrap + 16, 16);
    return AXGATE_OK;
}
