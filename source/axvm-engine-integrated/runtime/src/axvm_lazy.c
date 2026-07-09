#include "axvm_lazy.h"
#include "axvm_bytecode.h"
#include "axvm_dynseed.h"
#include "axvm_lazy_pf.h"

#include <string.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <fcntl.h>
#include <unistd.h>
#endif

#if defined(AXVM_LAZY_DECRYPT) && AXVM_LAZY_DECRYPT

/* ------- 实例密钥熵源（与栈加密一致的 /dev/urandom + xorshift 回退） ------- */
static void lazy_fill_random(uint8_t *buf, size_t n)
{
#if defined(__linux__) || defined(__ANDROID__)
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t off = 0;
        while (off < n) {
            ssize_t r = read(fd, buf + off, n - off);
            if (r <= 0) {
                break;
            }
            off += (size_t)r;
        }
        close(fd);
        if (off == n) {
            return;
        }
    }
#endif
    static uint64_t s_fallback = 0x5AA5F00D0FF0A55AULL;
    for (size_t i = 0; i < n; ++i) {
        s_fallback ^= s_fallback << 13;
        s_fallback ^= s_fallback >> 7;
        s_fallback ^= s_fallback << 17;
        buf[i] = (uint8_t)(s_fallback >> (i & 7));
    }
}

static uint64_t lazy_splitmix64(uint64_t x)
{
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

/*
 * 与数据无关的对合密钥流字节。
 * code_rel 为相对代码区首字节偏移；仅依赖实例密钥与偏移，
 * 因此对同一字节施加两次 XOR 即可在明文/密文间来回切换。
 */
static uint8_t lazy_keybyte(const axvm_ctx_t *ctx, size_t code_rel)
{
    uint32_t blk = (uint32_t)(code_rel / AXVM_LAZY_BLOCK);
    uint64_t s = ctx->lazy_key_lo + 0x9E3779B97F4A7C15ULL * ((uint64_t)blk + 1u);
    s ^= ctx->lazy_key_hi;
    s = lazy_splitmix64(s);
    uint8_t kb = (uint8_t)(s >> ((code_rel & 7u) * 8u));
    kb ^= (uint8_t)(ctx->lazy_key_lo >> ((blk & 7u) * 8u));
    kb ^= (uint8_t)(code_rel * 167u + 0x3Bu);
    return kb;
}

int axvm_lazy_enabled(void)
{
    return 1;
}

void axvm_lazy_xor_block(axvm_ctx_t *ctx, uint32_t blk)
{
    if (!ctx || !ctx->bytecode) {
        return;
    }
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    size_t code_size = hdr->code_size;
    size_t start = (size_t)blk * AXVM_LAZY_BLOCK;
    if (start >= code_size) {
        return;
    }
    size_t end = start + AXVM_LAZY_BLOCK;
    if (end > code_size) {
        end = code_size;
    }
    uint8_t *code = ctx->bytecode + hdr->code_off;
    for (size_t r = start; r < end; ++r) {
        code[r] ^= lazy_keybyte(ctx, r);
    }
}

static int lazy_block_active(const axvm_ctx_t *ctx, uint32_t blk)
{
    for (uint32_t i = 0; i < ctx->lazy_active_count; ++i) {
        if (ctx->lazy_active[i] == blk) {
            return 1;
        }
    }
    return 0;
}

void axvm_lazy_reencrypt_active(axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->lazy_sealed) {
        return;
    }
    for (uint32_t i = 0; i < ctx->lazy_active_count; ++i) {
        axvm_lazy_xor_block(ctx, ctx->lazy_active[i]); /* 再次 XOR = 还原密文 */
    }
    ctx->lazy_active_count = 0;
}

axvm_status_t axvm_lazy_ensure(axvm_ctx_t *ctx, size_t abs_off, size_t width)
{
    if (!ctx || !ctx->lazy_sealed) {
        return AXVM_OK;
    }
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    size_t code_off = hdr->code_off;
    size_t code_size = hdr->code_size;

    /* 头部区不加密，落在其中直接放行 */
    if (abs_off < code_off) {
        return AXVM_OK;
    }
    size_t rel = abs_off - code_off;
    /* 校验 6：拒绝越界读取未解密/非代码数据 */
    if (rel >= code_size) {
        return AXVM_ERR_OOB_PC;
    }
#if defined(AXVM_LAZY_PF) && AXVM_LAZY_PF
    axvm_lazy_pf_unseal_for_range(ctx, rel, width);
#endif
    size_t last = rel + (width ? width - 1u : 0u);
    if (last >= code_size) {
        last = code_size - 1u;
    }

    uint32_t b0 = (uint32_t)(rel / AXVM_LAZY_BLOCK);
    uint32_t b1 = (uint32_t)(last / AXVM_LAZY_BLOCK);

    /*
     * BasicBlock 粒度滑动窗口：
     *  - 只要 PC 仍落在已解密块内，窗口保持不变（块内多指令零重复异或，避免 20x 抖动）；
     *  - 一旦访问落到窗口外的块，先把不再需要的旧块异或回写为密文（“执行完毕立刻加密”），
     *    再解密新块。任一时刻内存中仅当前块(跨界时至多相邻 2 块)为明文。
     */
    uint32_t kept[AXVM_LAZY_ACTIVE_MAX];
    uint32_t nk = 0;
    for (uint32_t i = 0; i < ctx->lazy_active_count; ++i) {
        uint32_t a = ctx->lazy_active[i];
        if (a >= b0 && a <= b1) {
            kept[nk++] = a; /* 仍在需求范围内，保持明文 */
        } else {
            axvm_lazy_xor_block(ctx, a); /* 离开该块 -> 立即重加密 */
        }
    }
    memcpy(ctx->lazy_active, kept, nk * sizeof(uint32_t));
    ctx->lazy_active_count = nk;

    for (uint32_t b = b0; b <= b1; ++b) {
        if (lazy_block_active(ctx, b)) {
            continue;
        }
        if (ctx->lazy_active_count >= AXVM_LAZY_ACTIVE_MAX) {
            axvm_lazy_reencrypt_active(ctx); /* 安全兜底，正常不触发 */
        }
        axvm_lazy_xor_block(ctx, b); /* 解密新块 */
        ctx->lazy_active[ctx->lazy_active_count++] = b;
    }
    return AXVM_OK;
}

void axvm_lazy_init(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (ctx->session_seed_present) {
        /* 模块 M：懒解密密钥由 SessionSeed 派生。 */
        uint8_t sub[16];
        axvm_dynseed_subkey(ctx->session_seed, AXVM_DYNSEED_PURPOSE_LAZY,
                            sub, sizeof(sub));
        memcpy(&ctx->lazy_key_lo, sub, 8);
        memcpy(&ctx->lazy_key_hi, sub + 8, 8);
        volatile uint8_t *w = sub;
        for (size_t i = 0; i < sizeof(sub); ++i) {
            w[i] = 0;
        }
    } else
#endif
    {
        uint8_t seed[16];
        lazy_fill_random(seed, sizeof(seed));
        memcpy(&ctx->lazy_key_lo, seed, 8);
        memcpy(&ctx->lazy_key_hi, seed + 8, 8);
    }
    ctx->lazy_active_count = 0;
    ctx->lazy_sealed = 0;
}

void axvm_lazy_seal(axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->bytecode) {
        return;
    }
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    size_t code_size = hdr->code_size;
    uint32_t nblk = (uint32_t)((code_size + AXVM_LAZY_BLOCK - 1u) / AXVM_LAZY_BLOCK);

    ctx->lazy_active_count = 0;
    ctx->lazy_sealed = 1;
    for (uint32_t b = 0; b < nblk; ++b) {
        axvm_lazy_xor_block(ctx, b); /* 明文 -> 密文 */
    }
#if defined(AXVM_LAZY_PF) && AXVM_LAZY_PF
    axvm_lazy_pf_install();
    axvm_lazy_pf_seal_all(ctx);
#endif
}

void axvm_lazy_wipe(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    ctx->lazy_active_count = 0;
    ctx->lazy_sealed = 0;
    ctx->lazy_key_lo = 0;
    ctx->lazy_key_hi = 0;
}

uint64_t axvm_lazy_key_mix(const axvm_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->lazy_key_lo ^ ctx->lazy_key_hi;
}

int axvm_lazy_probe_plaintext(const axvm_ctx_t *ctx, const uint8_t *plain, size_t n)
{
    if (!ctx || !ctx->bytecode || !plain) {
        return -1;
    }
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    size_t code_off = hdr->code_off;
    size_t code_size = hdr->code_size;
    if (n > code_size) {
        n = code_size;
    }
    const uint8_t *resident = ctx->bytecode + code_off;
    return (memcmp(resident, plain, n) == 0) ? 1 : 0;
}

#else /* !AXVM_LAZY_DECRYPT — 关闭懒解密，全部空操作，代码区保持明文便于调试 */

int axvm_lazy_enabled(void)
{
    return 0;
}

void axvm_lazy_init(axvm_ctx_t *ctx)
{
    (void)ctx;
}

void axvm_lazy_seal(axvm_ctx_t *ctx)
{
    (void)ctx;
}

void axvm_lazy_wipe(axvm_ctx_t *ctx)
{
    (void)ctx;
}

axvm_status_t axvm_lazy_ensure(axvm_ctx_t *ctx, size_t abs_off, size_t width)
{
    (void)ctx;
    (void)abs_off;
    (void)width;
    return AXVM_OK;
}

void axvm_lazy_reencrypt_active(axvm_ctx_t *ctx)
{
    (void)ctx;
}

void axvm_lazy_xor_block(axvm_ctx_t *ctx, uint32_t blk)
{
    (void)ctx;
    (void)blk;
}

uint64_t axvm_lazy_key_mix(const axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

int axvm_lazy_probe_plaintext(const axvm_ctx_t *ctx, const uint8_t *plain, size_t n)
{
    /* 未启用懒解密时代码区为明文，模板匹配即返回泄露 */
    if (!ctx || !ctx->bytecode || !plain) {
        return -1;
    }
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    size_t code_off = hdr->code_off;
    size_t code_size = hdr->code_size;
    if (n > code_size) {
        n = code_size;
    }
    return (memcmp(ctx->bytecode + code_off, plain, n) == 0) ? 1 : 0;
}

#endif /* AXVM_LAZY_DECRYPT */
