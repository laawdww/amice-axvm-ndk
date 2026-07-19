#include "axvm_dynseed.h"
#include "axvm_hmac.h"
#include "axvm_pack.h"
#include "axvm_entropy.h"
#include "axvm_ctx.h"

#include <string.h>
#include <stddef.h>
#include <stdio.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <fcntl.h>
#include <unistd.h>
#endif
#if defined(__ANDROID__)
#include <android/log.h>
#endif

/* fnv1a32 —— 与 axpack 侧一致，用于 AXDS 块校验。 */
static uint32_t dynseed_fnv1a32(const uint8_t *p, size_t n)
{
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x01000193u;
    }
    return h;
}

void axvm_dynseed_master_cipher(uint8_t *buf, size_t n, const uint8_t nonce[16])
{
    /* HMAC-SHA256(nonce, "AXDS-MK2"||block) — must match axpack dynseedMasterCipher. */
    size_t off;
    unsigned block;
    if (!buf || !nonce || n == 0) {
        return;
    }
    for (off = 0, block = 0; off < n; off += 32u, ++block) {
        uint8_t msg[9];
        uint8_t ks[AXVM_SHA256_DIGEST];
        size_t chunk;
        /* Obfuscated "AXDS-MK2" — volatile XOR so compiler cannot fold to .rodata string. */
        {
            volatile uint8_t x = 0xA5u;
            msg[0] = (uint8_t)(0xE4u ^ x);
            msg[1] = (uint8_t)(0xFDu ^ x);
            msg[2] = (uint8_t)(0xE1u ^ x);
            msg[3] = (uint8_t)(0xF6u ^ x);
            msg[4] = (uint8_t)(0x88u ^ x);
            msg[5] = (uint8_t)(0xE8u ^ x);
            msg[6] = (uint8_t)(0xEEu ^ x);
            msg[7] = (uint8_t)(0x97u ^ x);
        }
        msg[8] = (uint8_t)block;
        axvm_hmac_sha256(nonce, 16, msg, sizeof(msg), ks);
        chunk = n - off;
        if (chunk > 32u) {
            chunk = 32u;
        }
        for (size_t i = 0; i < chunk; ++i) {
            buf[off + i] ^= ks[i];
        }
        volatile uint8_t *w = ks;
        for (size_t i = 0; i < sizeof(ks); ++i) {
            w[i] = 0;
        }
    }
}

static void dynseed_master_cipher_v1(uint8_t *buf, size_t n, const uint8_t nonce[16])
{
    if (!buf || !nonce) {
        return;
    }
    for (size_t i = 0; i < n; ++i) {
        uint8_t k = (uint8_t)(nonce[i & 15]
                              ^ nonce[(i * 7u + 3u) & 15]
                              ^ (uint8_t)(i * 167u + 0x3Bu));
        buf[i] ^= k;
    }
}

#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED

static uint8_t g_master_enc[32];
static uint8_t g_master_nonce[16];
static int     g_master_present;
static int     g_master_synth;
static int     g_master_cipher_ver = 2;
static int     g_apk_bind_required;
static int     g_apk_binding_present;
static char    g_apk_package[256];
static uint8_t g_apk_cert_sha256[32];

/* Encrypted "AXVM_APK_BIND1" — numeric only; decode with volatile XOR (no .rodata plain). */
static const uint8_t k_apk_bind_prefix_enc[14] = {
    0xe4, 0xfd, 0xf3, 0xe8, 0xfa, 0xe4, 0xf5, 0xee,
    0xfa, 0xe7, 0xec, 0xeb, 0xe1, 0x94
};

static void apk_bind_prefix_plain(char out[15])
{
    volatile uint8_t x = 0xA5u;
    size_t i;
    for (i = 0; i < sizeof(k_apk_bind_prefix_enc); ++i) {
        out[i] = (char)(k_apk_bind_prefix_enc[i] ^ x);
    }
    out[sizeof(k_apk_bind_prefix_enc)] = 0;
}

static void master_dec_plain(uint8_t *buf, size_t n);
static void synth_master(void);

static void derive_apk_bound_master(const uint8_t raw_seed[32],
                                    const char *package,
                                    const uint8_t cert_sha256[32],
                                    uint8_t out[32])
{
    uint8_t msg[320];
    size_t n = 0;
    size_t plen;
    if (!raw_seed || !package || !cert_sha256 || !out) {
        return;
    }
    plen = strlen(package);
    if (plen > 200u) {
        plen = 200u;
    }
    {
        char prefix[15];
        apk_bind_prefix_plain(prefix);
        size_t prefix_len = 14u;
        memcpy(msg, prefix, prefix_len);
        n = prefix_len;
        volatile char *pw = prefix;
        for (size_t i = 0; i < sizeof(prefix); ++i) {
            pw[i] = 0;
        }
    }
    memcpy(msg + n, package, plen);
    n += plen;
    msg[n++] = 0;
    memcpy(msg + n, cert_sha256, 32);
    n += 32;
    axvm_hmac_sha256(raw_seed, 32, msg, n, out);
    memset(msg, 0, sizeof(msg));
}

static void resolve_master_plain(uint8_t out[32])
{
    uint8_t raw[32];
    if (!out) {
        return;
    }
    if (!g_master_present) {
        synth_master();
    }
    memcpy(raw, g_master_enc, sizeof(raw));
    master_dec_plain(raw, sizeof(raw));
    if (g_apk_bind_required) {
        if (g_apk_binding_present) {
            derive_apk_bound_master(raw, g_apk_package, g_apk_cert_sha256, out);
        } else {
            memset(out, 0, 32);
        }
    } else {
        memcpy(out, raw, sizeof(raw));
    }
    volatile uint8_t *w = raw;
    for (size_t i = 0; i < sizeof(raw); ++i) {
        w[i] = 0;
    }
}

int axvm_dynseed_set_apk_binding(const char *package, const uint8_t cert_sha256[32])
{
    if (!package || !cert_sha256) {
        return 0;
    }
    size_t n = strlen(package);
    if (n == 0 || n >= sizeof(g_apk_package)) {
        return 0;
    }
    memcpy(g_apk_package, package, n + 1);
    memcpy(g_apk_cert_sha256, cert_sha256, 32);
    g_apk_binding_present = 1;
    return 1;
}

int axvm_dynseed_apk_bind_required(void)
{
    return g_apk_bind_required;
}

int axvm_dynseed_apk_binding_present(void)
{
    return g_apk_binding_present;
}

int axvm_dynseed_apk_bind_selftest(void)
{
    static const uint8_t k_golden[32] = {
        0x85, 0x76, 0x58, 0x16, 0x6e, 0x65, 0x43, 0x15,
        0xb2, 0x9e, 0x4d, 0xee, 0x1a, 0x2b, 0x61, 0x48,
        0x29, 0x9d, 0x89, 0x40, 0xc4, 0xfb, 0xc8, 0x15,
        0xc9, 0x70, 0xd6, 0xa4, 0xfc, 0xc7, 0xea, 0x49,
    };
    uint8_t raw[32];
    uint8_t cert[32];
    uint8_t msg[320];
    uint8_t out[32];
    const char *pkg = "com.example.app";
    size_t plen = strlen(pkg);
    char prefix[15];
    size_t n = 0;
    apk_bind_prefix_plain(prefix);
    size_t prefix_len = 14u;
    for (size_t i = 0; i < 32; ++i) {
        raw[i] = (uint8_t)(i + 1u);
        cert[i] = (uint8_t)(0xA0u + i);
    }
    memcpy(msg, prefix, prefix_len);
    n = prefix_len;
    memcpy(msg + n, pkg, plen);
    n += plen;
    msg[n++] = 0;
    memcpy(msg + n, cert, 32);
    n += 32;
    axvm_hmac_sha256(raw, 32, msg, n, out);
    if (memcmp(out, k_golden, sizeof(k_golden)) != 0) {
#if defined(__ANDROID__)
        char hex[140];
        size_t p = 0;
        for (size_t i = 0; i < n && p + 2 < sizeof(hex); ++i) {
            p += (size_t)snprintf(hex + p, sizeof(hex) - p, "%02x", msg[i]);
        }
        hex[sizeof(hex) - 1] = '\0';
        __android_log_print(ANDROID_LOG_ERROR, "AXVM",
                            "apk_bind raw=%02x%02x msg=%s got=%02x%02x%02x%02x",
                            raw[0], raw[1], hex, out[0], out[1], out[2], out[3]);
#endif
        return 0;
    }
    return 1;
}

static uint32_t derive_pack_magic_from_raw(const uint8_t raw[32])
{
    /* "AXVM_PACK_MAGIC1" via volatile XOR — no contiguous .rodata label. */
    static const uint8_t enc[] = {
        0xe4, 0xfd, 0xf3, 0xe8, 0xfa, 0xf5, 0xe4, 0xe6, 0xee, 0xfa,
        0xe8, 0xe4, 0xe2, 0xec, 0xe6, 0x94
    };
    char label[sizeof(enc) + 1];
    volatile uint8_t x = 0xA5u;
    for (size_t i = 0; i < sizeof(enc); ++i) {
        label[i] = (char)(enc[i] ^ x);
    }
    label[sizeof(enc)] = 0;
    size_t label_len = sizeof(enc);
    uint8_t msg[16 + 32];
    memcpy(msg, label, label_len);
    memcpy(msg + label_len, raw, 32);
    uint32_t h = dynseed_fnv1a32(msg, label_len + 32);
    {
        volatile char *w = label;
        for (size_t i = 0; i < sizeof(label); ++i) {
            w[i] = 0;
        }
    }
    if (h == 0 || h == AXPK_MAGIC) {
        h ^= 0x5A5A5A5Au;
    }
    return h;
}

static void decrypt_raw_seed(uint8_t raw[32])
{
    if (!g_master_present) {
        synth_master();
    }
    memcpy(raw, g_master_enc, 32);
    master_dec_plain(raw, 32);
}

uint32_t axvm_dynseed_pack_magic(void)
{
    if (!g_master_present || g_master_synth) {
        return AXPK_MAGIC;
    }
    uint8_t raw[32];
    decrypt_raw_seed(raw);
    uint32_t m = derive_pack_magic_from_raw(raw);
    volatile uint8_t *w = raw;
    for (size_t i = 0; i < sizeof(raw); ++i) {
        w[i] = 0;
    }
    return m;
}

int axvm_dynseed_enabled(void)
{
    return 1;
}

int axvm_dynseed_set_master(const uint8_t *master_enc, size_t enc_len,
                            const uint8_t *nonce, size_t nonce_len)
{
    if (!master_enc || enc_len < sizeof(g_master_enc) ||
        !nonce || nonce_len < sizeof(g_master_nonce)) {
        return 0;
    }
    memcpy(g_master_enc, master_enc, sizeof(g_master_enc));
    memcpy(g_master_nonce, nonce, sizeof(g_master_nonce));
    g_master_present = 1;
    g_master_synth = 0;
    return 1;
}

static int axds_block_valid(const axvm_dynseed_block_t *blk)
{
    if (!blk || blk->magic != AXDS_MAGIC) {
        return 0;
    }
    if (blk->version != AXDS_VERSION && blk->version != AXDS_VERSION_V2 &&
        blk->version != AXDS_VERSION_V3) {
        return 0;
    }
    uint32_t want = dynseed_fnv1a32((const uint8_t *)blk,
                                    offsetof(axvm_dynseed_block_t, checksum));
    return blk->checksum == want;
}

static int axds_apply_block(const axvm_dynseed_block_t *blk)
{
    if (!blk) {
        return 0;
    }
    if (blk->version == AXDS_VERSION_V3) {
        g_master_cipher_ver = 2;
        g_apk_bind_required = (blk->flags & AXDS_FLAG_APK_BIND) ? 1 : 0;
    } else {
        g_master_cipher_ver = (blk->version == AXDS_VERSION_V2) ? 2 : 1;
        g_apk_bind_required = 0;
    }
    return axvm_dynseed_set_master(blk->master_enc, sizeof(blk->master_enc),
                                   blk->nonce, sizeof(blk->nonce));
}

int axvm_dynseed_scan_and_set(const uint8_t *buf, size_t len)
{
    if (!buf || len < sizeof(axvm_dynseed_block_t)) {
        return 0;
    }
    size_t last = (size_t)-1;
    for (size_t off = 0; off + sizeof(axvm_dynseed_block_t) <= len; off += 4) {
        const axvm_dynseed_block_t *blk =
            (const axvm_dynseed_block_t *)(buf + off);
        if (!axds_block_valid(blk)) {
            continue;
        }
        last = off;
    }
    if (last == (size_t)-1) {
        return 0;
    }
    return axds_apply_block((const axvm_dynseed_block_t *)(buf + last));
}

void axvm_dynseed_reset_for_prepatch(void)
{
    g_master_present = 0;
    g_master_synth = 0;
    g_apk_bind_required = 0;
    g_master_cipher_ver = 2;
    memset(g_master_enc, 0, sizeof(g_master_enc));
    memset(g_master_nonce, 0, sizeof(g_master_nonce));
}

int axvm_dynseed_scan_tail_and_set(const uint8_t *buf, size_t len)
{
    if (!buf || len < sizeof(axvm_dynseed_block_t)) {
        return 0;
    }
    /* axpack：AXDS 在 EOF 对齐 padding 之前；跳过尾部 0 再试 EOF-64。 */
    size_t trim = len;
    while (trim > sizeof(axvm_dynseed_block_t) && buf[trim - 1] == 0) {
        trim--;
    }
    if (trim >= sizeof(axvm_dynseed_block_t)) {
        const axvm_dynseed_block_t *eof =
            (const axvm_dynseed_block_t *)(buf + trim - sizeof(axvm_dynseed_block_t));
        if (axds_block_valid(eof)) {
            return axds_apply_block(eof);
        }
    }
    return axvm_dynseed_scan_and_set(buf, len);
}

/* 合成每进程稳定的伪 MasterSeed（无 EOF 块时使用，仍保证 ON 可用）。 */
static void synth_master(void)
{
    uint8_t plain[32];
    int got = 0;
#if defined(__linux__) || defined(__ANDROID__)
    int fd = axvm_open_urandom();
    if (fd >= 0) {
        size_t r = 0;
        while (r < sizeof(plain)) {
            ssize_t k = read(fd, plain + r, sizeof(plain) - r);
            if (k <= 0) {
                break;
            }
            r += (size_t)k;
        }
        close(fd);
        got = (r == sizeof(plain));
    }
#endif
    if (!got) {
        static uint64_t s = 0xD1CE4E5B9F4A7C15ULL;
        for (size_t i = 0; i < sizeof(plain); ++i) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            plain[i] = (uint8_t)(s >> (i & 7));
        }
    }
    /* 生成 nonce 并将合成 master 存为密文，路径与真实块一致。 */
    for (size_t i = 0; i < sizeof(g_master_nonce); ++i) {
        g_master_nonce[i] = (uint8_t)(plain[(i * 5u + 1u) & 31] ^ (uint8_t)(i * 91u + 7u));
    }
    memcpy(g_master_enc, plain, sizeof(g_master_enc));
    axvm_dynseed_master_cipher(g_master_enc, sizeof(g_master_enc), g_master_nonce);
    memset(plain, 0, sizeof(plain));
    g_master_present = 1;
    g_master_synth = 1;
}

void axvm_dynseed_get_master_enc(uint8_t out_enc[32])
{
    if (!g_master_present) {
        synth_master();
    }
    memcpy(out_enc, g_master_enc, sizeof(g_master_enc));
}

int axvm_dynseed_master_is_real(void)
{
    return g_master_present && !g_master_synth;
}

static void master_dec_plain(uint8_t *buf, size_t n)
{
    if (g_master_cipher_ver == 1) {
        dynseed_master_cipher_v1(buf, n, g_master_nonce);
    } else {
        axvm_dynseed_master_cipher(buf, n, g_master_nonce);
    }
}

void axvm_dynseed_get_master_plain(uint8_t out[32])
{
    if (!out) {
        return;
    }
    resolve_master_plain(out);
}

void axvm_derive_session_seed(const uint8_t *master_enc, size_t master_len,
                              const uint8_t *entropy, size_t ent_len,
                              uint8_t out_seed[32])
{
    uint8_t plain_master[32];
    if (!master_enc || master_len < sizeof(plain_master) || !out_seed) {
        if (out_seed) {
            memset(out_seed, 0, 32);
        }
        return;
    }
    memcpy(plain_master, master_enc, sizeof(plain_master));
    if (g_apk_bind_required) {
        if (g_apk_binding_present) {
            uint8_t raw[32];
            master_dec_plain(plain_master, sizeof(raw));
            derive_apk_bound_master(raw, g_apk_package, g_apk_cert_sha256, plain_master);
            volatile uint8_t *rw = raw;
            for (size_t i = 0; i < sizeof(raw); ++i) {
                rw[i] = 0;
            }
        } else {
            memset(plain_master, 0, sizeof(plain_master));
        }
    } else {
        master_dec_plain(plain_master, sizeof(plain_master));
    }

    axvm_hmac_sha256(plain_master, sizeof(plain_master),
                     entropy, ent_len, out_seed);

    /* 立即擦除瞬时明文 MasterSeed。 */
    volatile uint8_t *p = plain_master;
    for (size_t i = 0; i < sizeof(plain_master); ++i) {
        p[i] = 0;
    }
}

void axvm_dynseed_subkey(const uint8_t session_seed[32], uint32_t purpose,
                         uint8_t *out, size_t n)
{
    uint8_t tag[4];
    uint8_t digest[AXVM_SHA256_DIGEST];
    if (!session_seed || !out) {
        return;
    }
    tag[0] = (uint8_t)(purpose);
    tag[1] = (uint8_t)(purpose >> 8);
    tag[2] = (uint8_t)(purpose >> 16);
    tag[3] = (uint8_t)(purpose >> 24);
    axvm_hmac_sha256(session_seed, 32, tag, sizeof(tag), digest);
    if (n > sizeof(digest)) {
        n = sizeof(digest);
    }
    memcpy(out, digest, n);
    memset(digest, 0, sizeof(digest));
}

void axvm_dynseed_master_subkey(const uint8_t master_plain[32], uint32_t purpose,
                                uint8_t *out, size_t n)
{
    uint8_t tag[4];
    uint8_t digest[AXVM_SHA256_DIGEST];
    if (!master_plain || !out) {
        return;
    }
    tag[0] = (uint8_t)(purpose);
    tag[1] = (uint8_t)(purpose >> 8);
    tag[2] = (uint8_t)(purpose >> 16);
    tag[3] = (uint8_t)(purpose >> 24);
    axvm_hmac_sha256(master_plain, 32, tag, sizeof(tag), digest);
    if (n > sizeof(digest)) {
        n = sizeof(digest);
    }
    memcpy(out, digest, n);
    memset(digest, 0, sizeof(digest));
}

void axvm_dynseed_derive_ctx(struct axvm_ctx *ctx)
{
    if (!ctx) {
        return;
    }
    uint8_t plain_master[32];
    uint8_t entropy[AXVM_ENTROPY_MAX];

    resolve_master_plain(plain_master);
    size_t elen = axvm_entropy_collect((void *)ctx->vm_stack_base,
                                       entropy, sizeof(entropy));
    axvm_hmac_sha256(plain_master, sizeof(plain_master),
                     entropy, elen, ctx->session_seed);
    ctx->session_seed_present = 1;

    memset(plain_master, 0, sizeof(plain_master));
    memset(entropy, 0, sizeof(entropy));
}

void axvm_dynseed_wipe(struct axvm_ctx *ctx)
{
    if (!ctx) {
        return;
    }
    volatile uint8_t *p = ctx->session_seed;
    for (size_t i = 0; i < sizeof(ctx->session_seed); ++i) {
        p[i] = 0;
    }
    ctx->session_seed_present = 0;
}

uint64_t axvm_dynseed_session_mix(const struct axvm_ctx *ctx)
{
    if (!ctx || !ctx->session_seed_present) {
        return 0;
    }
    uint64_t mix = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < sizeof(ctx->session_seed); ++i) {
        mix ^= ctx->session_seed[i];
        mix *= 0x100000001b3ULL;
    }
    return mix;
}

#else /* !AXVM_DYNAMIC_SEED — 向后兼容：全部降级为空/静态行为 */

int axvm_dynseed_enabled(void)
{
    return 0;
}

int axvm_dynseed_set_master(const uint8_t *master_enc, size_t enc_len,
                            const uint8_t *nonce, size_t nonce_len)
{
    (void)master_enc; (void)enc_len; (void)nonce; (void)nonce_len;
    return 0;
}

int axvm_dynseed_scan_and_set(const uint8_t *buf, size_t len)
{
    (void)buf; (void)len;
    return 0;
}

void axvm_dynseed_reset_for_prepatch(void) {}

int axvm_dynseed_scan_tail_and_set(const uint8_t *buf, size_t len)
{
    (void)buf;
    (void)len;
    return 0;
}

void axvm_dynseed_get_master_enc(uint8_t out_enc[32])
{
    memset(out_enc, 0, 32);
}

int axvm_dynseed_master_is_real(void)
{
    return 0;
}

void axvm_dynseed_get_master_plain(uint8_t out[32])
{
    if (out) {
        memset(out, 0, 32);
    }
}

int axvm_dynseed_set_apk_binding(const char *package, const uint8_t cert_sha256[32])
{
    (void)package; (void)cert_sha256;
    return 0;
}

int axvm_dynseed_apk_bind_required(void)
{
    return 0;
}

int axvm_dynseed_apk_binding_present(void)
{
    return 0;
}

uint32_t axvm_dynseed_pack_magic(void)
{
    return AXPK_MAGIC;
}

void axvm_derive_session_seed(const uint8_t *master_enc, size_t master_len,
                              const uint8_t *entropy, size_t ent_len,
                              uint8_t out_seed[32])
{
    (void)master_enc; (void)master_len; (void)entropy; (void)ent_len;
    if (out_seed) {
        memset(out_seed, 0, 32);
    }
}

void axvm_dynseed_subkey(const uint8_t session_seed[32], uint32_t purpose,
                         uint8_t *out, size_t n)
{
    (void)session_seed; (void)purpose;
    if (out) {
        memset(out, 0, n);
    }
}

void axvm_dynseed_derive_ctx(struct axvm_ctx *ctx)
{
    (void)ctx;
}

void axvm_dynseed_wipe(struct axvm_ctx *ctx)
{
    (void)ctx;
}

uint64_t axvm_dynseed_session_mix(const struct axvm_ctx *ctx)
{
    (void)ctx;
    return 0;
}

#endif /* AXVM_DYNAMIC_SEED */
