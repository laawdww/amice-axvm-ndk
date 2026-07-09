#include "axvm_integrity.h"
#include "axvm_ctx.h"
#include "axvm_stack_crypt.h"
#include "axvm_lazy.h"

#include <string.h>

/* ============================ SHA256 ============================ */
/* 自研紧凑实现，无外部依赖，避免链接 openssl 等同质化特征库 */

static uint32_t sha_ror(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32u - n));
}

static const uint32_t SHA_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static void sha_block(axvm_sha256_ctx_t *c, const uint8_t *p)
{
    uint32_t w[64];
    for (uint32_t i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | ((uint32_t)p[i * 4 + 3]);
    }
    for (uint32_t i = 16; i < 64; ++i) {
        uint32_t s0 = sha_ror(w[i - 15], 7) ^ sha_ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sha_ror(w[i - 2], 17) ^ sha_ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];

    for (uint32_t i = 0; i < 64; ++i) {
        uint32_t S1 = sha_ror(e, 6) ^ sha_ror(e, 11) ^ sha_ror(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = sha_ror(a, 2) ^ sha_ror(a, 13) ^ sha_ror(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

void axvm_sha256_init(axvm_sha256_ctx_t *c)
{
    c->state[0] = 0x6a09e667u; c->state[1] = 0xbb67ae85u;
    c->state[2] = 0x3c6ef372u; c->state[3] = 0xa54ff53au;
    c->state[4] = 0x510e527fu; c->state[5] = 0x9b05688cu;
    c->state[6] = 0x1f83d9abu; c->state[7] = 0x5be0cd19u;
    c->bitlen = 0;
    c->buflen = 0;
}

void axvm_sha256_update(axvm_sha256_ctx_t *c, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t *)data;
    while (n > 0) {
        uint32_t take = 64u - c->buflen;
        if ((size_t)take > n) {
            take = (uint32_t)n;
        }
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64u) {
            sha_block(c, c->buf);
            c->bitlen += 512u;
            c->buflen = 0;
        }
    }
}

void axvm_sha256_final(axvm_sha256_ctx_t *c, uint8_t out[32])
{
    /* 必须在 padding 前冻结消息位长：update 在凑满 64 字节块时会继续累加 bitlen，
     * 若 buflen>=56 会先消化一整块 padding，导致嵌入的长度字段错误（HMAC 长消息必现）。 */
    const uint64_t total_bits = c->bitlen + (uint64_t)c->buflen * 8u;
    uint8_t pad = 0x80u;
    axvm_sha256_update(c, &pad, 1);
    uint8_t zero = 0x00u;
    while (c->buflen != 56u) {
        axvm_sha256_update(c, &zero, 1);
    }
    uint8_t lenbe[8];
    for (int i = 0; i < 8; ++i) {
        lenbe[i] = (uint8_t)(total_bits >> (56 - i * 8));
    }
    axvm_sha256_update(c, lenbe, 8);
    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

void axvm_sha256(const void *data, size_t n, uint8_t out[32])
{
    axvm_sha256_ctx_t c;
    axvm_sha256_init(&c);
    axvm_sha256_update(&c, data, n);
    axvm_sha256_final(&c, out);
}

/* ============================ 完整性状态 ============================ */

#if defined(AXVM_SO_INTEGRITY) && AXVM_SO_INTEGRITY

typedef struct integ_seg {
    uint32_t       seg_id;
    const uint8_t *base;      /* live 内存段起始 */
    size_t         size;
    uint8_t        expect[32];
} integ_seg_t;

typedef struct integ_state {
    int         armed;
    uint32_t    seg_count;
    integ_seg_t segs[AXVM_INTSEG_MAX];
    uint32_t    trip_flags;
    uint32_t    probe_seq;
    uint32_t    dispatch_tick;
} integ_state_t;

static integ_state_t g_integ;

/*
 * 哈希 XOR 流：keyed by key_seed[16] + seg_id，与 axvm_crypt 同构但自包含，
 * 不触碰全局 bytecode 解密密钥。
 */
static void integ_xor_hash(uint8_t hash[32], const uint8_t key_seed[16], uint32_t seg_id)
{
    uint8_t roll = (uint8_t)(seg_id ^ key_seed[0] ^ 0xA5u);
    for (int i = 0; i < 32; ++i) {
        uint8_t k = (uint8_t)(key_seed[i & 15] ^ roll ^ (uint8_t)(i * 13 + (int)seg_id));
        uint8_t cipher = hash[i];
        hash[i] ^= k;
        roll = (uint8_t)((roll + cipher + k) ^ 0x5Au);
    }
}

int axvm_integrity_enabled(void)
{
    return 1;
}

int axvm_integrity_armed(void)
{
    return g_integ.armed;
}

uint32_t axvm_integrity_trip_flags(void)
{
    return g_integ.trip_flags;
}

void axvm_integrity_reset(void)
{
    memset(&g_integ, 0, sizeof(g_integ));
}

void axvm_integrity_trip_ctx(axvm_ctx_t *ctx, uint32_t flag)
{
    g_integ.trip_flags |= flag;
    if (!ctx) {
        return;
    }
    ctx->halted = 1;
    ctx->ret_pending = 0;
    ctx->ret_val = 0;
    memset(ctx->x, 0, sizeof(ctx->x));
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    memset(ctx->v, 0, sizeof(ctx->v));
#endif
    ctx->nzcv = 0;
#if defined(AXVM_LAZY_DECRYPT) && AXVM_LAZY_DECRYPT
    axvm_lazy_reencrypt_active(ctx);
    axvm_lazy_wipe(ctx);
#endif
    axvm_stack_crypt_wipe(ctx);
}

static uint32_t integ_flag_for_seg(uint32_t seg_id)
{
    switch (seg_id) {
    case AXVM_INTSEG_BC:   return AXVM_INTEG_TRIP_BC;
    case AXVM_INTSEG_STUB: return AXVM_INTEG_TRIP_STUB;
    case AXVM_INTSEG_TEXT: return AXVM_INTEG_TRIP_TEXT;
    default:               return AXVM_INTEG_TRIP_PARSE;
    }
}

axvm_status_t axvm_integrity_verify_seg(axvm_ctx_t *ctx, uint32_t idx)
{
    if (!g_integ.armed || idx >= g_integ.seg_count) {
        return AXVM_OK;
    }
    integ_seg_t *s = &g_integ.segs[idx];
    if (!s->base || s->size == 0) {
        return AXVM_OK;
    }
    uint8_t cur[32];
    axvm_sha256(s->base, s->size, cur);
    if (memcmp(cur, s->expect, 32) != 0) {
        axvm_integrity_trip_ctx(ctx, integ_flag_for_seg(s->seg_id));
        return AXVM_ERR_GUARD;
    }
    return AXVM_OK;
}

axvm_status_t axvm_integrity_probe_init(axvm_ctx_t *ctx)
{
    if (!g_integ.armed) {
        return AXVM_OK;
    }
    for (uint32_t i = 0; i < g_integ.seg_count; ++i) {
        axvm_status_t st = axvm_integrity_verify_seg(ctx, i);
        if (st != AXVM_OK) {
            return st;
        }
    }
    return AXVM_OK;
}

axvm_status_t axvm_integrity_probe_dispatch(axvm_ctx_t *ctx)
{
    if (!g_integ.armed) {
        return AXVM_OK;
    }
    g_integ.dispatch_tick++;
    if ((g_integ.dispatch_tick % AXVM_INTEG_DISPATCH_PERIOD) != 0u) {
        return AXVM_OK;
    }
    for (uint32_t tries = 0; tries < g_integ.seg_count; ++tries) {
        uint32_t idx = g_integ.probe_seq % g_integ.seg_count;
        g_integ.probe_seq++;
        if (g_integ.segs[idx].seg_id == AXVM_INTSEG_BC) {
            continue;
        }
        return axvm_integrity_verify_seg(ctx, idx);
    }
    return AXVM_OK;
}

axvm_status_t axvm_integrity_probe_native(axvm_ctx_t *ctx)
{
    if (!g_integ.armed) {
        return AXVM_OK;
    }
    /* BL_NATIVE 边界优先校验 STUB 与 TEXT（原生跳板篡改面） */
    for (uint32_t i = 0; i < g_integ.seg_count; ++i) {
        if (g_integ.segs[i].seg_id == AXVM_INTSEG_BC) {
            continue;
        }
        axvm_status_t st = axvm_integrity_verify_seg(ctx, i);
        if (st != AXVM_OK) {
            return st;
        }
    }
    return AXVM_OK;
}

/* 在 pack 尾部（blob 之后）扫描 'AXP2' 完整性节 */
static const axvm_integ_hdr_t *find_integ_section(const uint8_t *pack, size_t pack_len)
{
    if (!pack || pack_len < sizeof(axvm_integ_hdr_t)) {
        return NULL;
    }
    size_t limit = pack_len - sizeof(axvm_integ_hdr_t);
    for (size_t off = 0; off <= limit; off += 4) {
        const axvm_integ_hdr_t *h = (const axvm_integ_hdr_t *)(pack + off);
        if (h->magic != AXVM_INTEG_MAGIC) {
            continue;
        }
        if (h->version != AXVM_INTEG_VERSION) {
            continue;
        }
        if (h->seg_count == 0 || h->seg_count > AXVM_INTSEG_MAX) {
            continue;
        }
        size_t need = off + sizeof(axvm_integ_hdr_t) +
                      (size_t)h->seg_count * sizeof(axvm_integ_entry_t);
        if (need > pack_len) {
            continue;
        }
        return h;
    }
    return NULL;
}

axvm_status_t axvm_integrity_register(const uint8_t *pack, size_t pack_len,
                                      void *load_base)
{
    if (!pack) {
        return AXVM_ERR_BAD_MAGIC;
    }
    const axvm_integ_hdr_t *h = find_integ_section(pack, pack_len);
    if (!h) {
        return AXVM_ERR_BAD_MAGIC; /* 无完整性节：保持未 arm，探针空转 */
    }
    const axvm_integ_entry_t *ents =
        (const axvm_integ_entry_t *)((const uint8_t *)h + sizeof(axvm_integ_hdr_t));

    memset(&g_integ, 0, sizeof(g_integ));
    uint32_t n = h->seg_count;
    if (n > AXVM_INTSEG_MAX) {
        n = AXVM_INTSEG_MAX;
    }
    for (uint32_t i = 0; i < n; ++i) {
        const axvm_integ_entry_t *e = &ents[i];
        integ_seg_t *s = &g_integ.segs[i];
        s->seg_id = e->seg_id;
        s->size = (size_t)e->seg_size;
        if (e->seg_id == AXVM_INTSEG_TEXT) {
            if (!load_base) {
                continue;
            }
            s->base = (const uint8_t *)load_base + e->seg_off;
        } else {
            /* BC / STUB 相对 pack 首字节 */
            if (e->seg_off + e->seg_size > pack_len) {
                continue;
            }
            s->base = pack + e->seg_off;
        }
        memcpy(s->expect, e->enc_hash, 32);
        integ_xor_hash(s->expect, h->key_seed, e->seg_id); /* 解密期望哈希 */
    }
    g_integ.seg_count = n;
    g_integ.armed = 1;
    return AXVM_OK;
}

axvm_status_t axvm_integrity_arm_test(const void *seg, size_t n)
{
    if (!seg || n == 0) {
        return AXVM_ERR_BAD_MAGIC;
    }
    memset(&g_integ, 0, sizeof(g_integ));
    integ_seg_t *s = &g_integ.segs[0];
    s->seg_id = AXVM_INTSEG_BC;
    s->base = (const uint8_t *)seg;
    s->size = n;
    axvm_sha256(seg, n, s->expect); /* 直接记录当前哈希作为期望值 */
    g_integ.seg_count = 1;
    g_integ.armed = 1;
    return AXVM_OK;
}

void axvm_integrity_refresh_live(void)
{
    if (!g_integ.armed) {
        return;
    }
    for (uint32_t i = 0; i < g_integ.seg_count; ++i) {
        integ_seg_t *s = &g_integ.segs[i];
        if (!s->base || s->size == 0) {
            continue;
        }
        if (s->seg_id == AXVM_INTSEG_TEXT) {
            axvm_sha256(s->base, s->size, s->expect);
        }
    }
}

#else /* !AXVM_SO_INTEGRITY — 全部空操作 */

int axvm_integrity_enabled(void) { return 0; }
int axvm_integrity_armed(void) { return 0; }
uint32_t axvm_integrity_trip_flags(void) { return 0; }
void axvm_integrity_reset(void) {}
void axvm_integrity_trip_ctx(struct axvm_ctx *ctx, uint32_t flag) { (void)ctx; (void)flag; }

axvm_status_t axvm_integrity_verify_seg(struct axvm_ctx *ctx, uint32_t idx)
{
    (void)ctx; (void)idx;
    return AXVM_OK;
}
axvm_status_t axvm_integrity_probe_init(struct axvm_ctx *ctx) { (void)ctx; return AXVM_OK; }
axvm_status_t axvm_integrity_probe_dispatch(struct axvm_ctx *ctx) { (void)ctx; return AXVM_OK; }
axvm_status_t axvm_integrity_probe_native(struct axvm_ctx *ctx) { (void)ctx; return AXVM_OK; }

axvm_status_t axvm_integrity_register(const uint8_t *pack, size_t pack_len, void *load_base)
{
    (void)pack; (void)pack_len; (void)load_base;
    return AXVM_OK;
}
axvm_status_t axvm_integrity_arm_test(const void *seg, size_t n)
{
    (void)seg; (void)n;
    return AXVM_OK;
}
void axvm_integrity_refresh_live(void) {}

#endif /* AXVM_SO_INTEGRITY */
