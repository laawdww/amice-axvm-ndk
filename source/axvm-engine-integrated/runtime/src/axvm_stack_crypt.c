#include "axvm_stack_crypt.h"
#include "axvm_dynseed.h"

#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <fcntl.h>
#include <unistd.h>
#endif

#if defined(AXVM_STACK_CRYPT) && AXVM_STACK_CRYPT

static void fill_random(uint8_t *buf, size_t n)
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
    /* 宿主调试回退：仍保证每实例不同 */
    static uint64_t s_fallback = 0xA5A55A5AA5A55A5AULL;
    for (size_t i = 0; i < n; ++i) {
        s_fallback ^= s_fallback << 13;
        s_fallback ^= s_fallback >> 7;
        s_fallback ^= s_fallback << 17;
        buf[i] = (uint8_t)(s_fallback >> (i & 7));
    }
}

static uint64_t splitmix64(uint64_t x)
{
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

static void stack_key_roll(axvm_ctx_t *ctx)
{
    /* 滚动计数器每次栈操作推进；主密钥在实例生命周期内保持稳定，解密靠 slot meta 中的 roll 快照 */
    uint32_t r = ctx->stack_roll;
    r = r * 1664525u + 1013904223u;
    r ^= (uint32_t)(ctx->stack_key_lo >> 17);
    r ^= (uint32_t)(ctx->stack_key_hi >> 3);
    ctx->stack_roll = r;
    ctx->stack_op_count++;
}

static uint32_t stack_slot_index(const axvm_ctx_t *ctx, uint64_t addr)
{
    return (uint32_t)((addr - (uint64_t)(uintptr_t)ctx->vm_stack_base) >> 3);
}

static uint64_t stack_mask64(const axvm_ctx_t *ctx, uint32_t slot, uint32_t gen, uint32_t roll_tag)
{
    uint64_t x = ctx->stack_key_lo;
    x ^= splitmix64(ctx->stack_key_hi ^ ((uint64_t)slot << 33) ^ (uint64_t)gen);
    x ^= splitmix64(((uint64_t)roll_tag << 17) ^ ctx->stack_key_hi ^ (uint64_t)slot);
    return x;
}

static uint64_t *slot_meta_ptr(axvm_ctx_t *ctx, uint32_t slot)
{
    if (!ctx->stack_slot_meta || slot >= ctx->stack_slot_count) {
        return NULL;
    }
    return &ctx->stack_slot_meta[slot];
}

static axvm_status_t slot_read_plain64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out)
{
    uint32_t slot = stack_slot_index(ctx, addr);
    uint64_t *meta = slot_meta_ptr(ctx, slot);
    if (!meta || !out) {
        return AXVM_ERR_OOB_STACK;
    }
    uint32_t gen = (uint32_t)(*meta >> 32);
    if (gen == 0) {
        *out = 0;
        return AXVM_OK;
    }
    uint32_t tag = (uint32_t)(*meta);
    uint64_t enc = 0;
    memcpy(&enc, (void *)(uintptr_t)addr, 8);
    *out = enc ^ stack_mask64(ctx, slot, gen - 1u, tag);
    return AXVM_OK;
}

int axvm_stack_crypt_enabled(void)
{
    return 1;
}

void axvm_stack_crypt_init(axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->vm_stack_base) {
        return;
    }

    ctx->stack_slot_count = (uint32_t)(ctx->vm_stack_size >> 3);
    ctx->stack_slot_meta = (uint64_t *)calloc(ctx->stack_slot_count, sizeof(uint64_t));
    if (!ctx->stack_slot_meta) {
        ctx->stack_slot_count = 0;
        return;
    }

#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (ctx->session_seed_present) {
        /* 模块 M：滚动栈密钥由 SessionSeed 派生（urandom 已作为熵源进入 SessionSeed）。 */
        uint8_t sub[20];
        axvm_dynseed_subkey(ctx->session_seed, AXVM_DYNSEED_PURPOSE_STACK,
                            sub, sizeof(sub));
        memcpy(&ctx->stack_key_lo, sub, 8);
        memcpy(&ctx->stack_key_hi, sub + 8, 8);
        memcpy(&ctx->stack_roll, sub + 16, sizeof(ctx->stack_roll));
        volatile uint8_t *w = sub;
        for (size_t i = 0; i < sizeof(sub); ++i) {
            w[i] = 0;
        }
    } else
#endif
    {
        uint8_t seed[16];
        fill_random(seed, sizeof(seed));
        memcpy(&ctx->stack_key_lo, seed, 8);
        memcpy(&ctx->stack_key_hi, seed + 8, 8);
        fill_random((uint8_t *)&ctx->stack_roll, sizeof(ctx->stack_roll));
    }
    ctx->stack_op_count = 0;

    /* 栈区预填充随机密文，避免未写槽位泄露零页特征 */
    for (size_t i = 0; i < ctx->vm_stack_size; i += 8) {
        uint64_t noise = splitmix64(ctx->stack_key_lo ^ (i * 0x9E3779B97F4A7C15ULL));
        memcpy(ctx->vm_stack_base + i, &noise, 8);
    }
}

void axvm_stack_crypt_reset(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    if (ctx->stack_slot_meta && ctx->stack_slot_count > 0) {
        memset(ctx->stack_slot_meta, 0, ctx->stack_slot_count * sizeof(uint64_t));
    }
    ctx->stack_op_count = 0;
    if (ctx->vm_stack_base && ctx->vm_stack_size > 0) {
        for (size_t i = 0; i < ctx->vm_stack_size; i += 8) {
            uint64_t noise = splitmix64(ctx->stack_key_hi ^ (i * 0xC2B2AE3D27D4EB4FULL));
            memcpy(ctx->vm_stack_base + i, &noise, 8);
        }
    }
    stack_key_roll(ctx);
}

void axvm_stack_crypt_wipe(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    if (ctx->vm_stack_base && ctx->vm_stack_size > 0) {
        volatile uint8_t *p = ctx->vm_stack_base;
        for (size_t i = 0; i < ctx->vm_stack_size; ++i) {
            p[i] = 0;
        }
    }
    if (ctx->stack_slot_meta) {
        volatile uint64_t *g = ctx->stack_slot_meta;
        for (uint32_t i = 0; i < ctx->stack_slot_count; ++i) {
            g[i] = 0;
        }
        free(ctx->stack_slot_meta);
        ctx->stack_slot_meta = NULL;
    }
    ctx->stack_slot_count = 0;
    ctx->stack_key_lo = 0;
    ctx->stack_key_hi = 0;
    ctx->stack_roll = 0;
    ctx->stack_op_count = 0;
}

uint64_t axvm_stack_crypt_key_mix(const axvm_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->stack_key_lo ^ ctx->stack_key_hi ^ (uint64_t)ctx->stack_roll;
}

axvm_status_t axvm_vm_stack_store64(axvm_ctx_t *ctx, uint64_t addr, uint64_t val)
{
    uint32_t slot = stack_slot_index(ctx, addr);
    uint64_t *meta = slot_meta_ptr(ctx, slot);
    if (!meta) {
        return AXVM_ERR_OOB_STACK;
    }

    uint32_t gen = (uint32_t)(*meta >> 32);
    uint32_t tag = ctx->stack_roll;
    uint64_t mask = stack_mask64(ctx, slot, gen, tag);
    uint64_t enc = val ^ mask;
    memcpy((void *)(uintptr_t)addr, &enc, 8);
    *meta = ((uint64_t)(gen + 1u) << 32) | (uint64_t)tag;
    stack_key_roll(ctx);
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_load64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out)
{
    uint32_t slot = stack_slot_index(ctx, addr);
    uint64_t *meta = slot_meta_ptr(ctx, slot);
    if (!meta || !out) {
        return AXVM_ERR_OOB_STACK;
    }
    if ((*meta >> 32) == 0) {
        return AXVM_ERR_OOB_MEM;
    }

    axvm_status_t st = slot_read_plain64(ctx, addr, out);
    if (st != AXVM_OK) {
        return st;
    }
    stack_key_roll(ctx);
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_store32(axvm_ctx_t *ctx, uint64_t addr, uint32_t val)
{
    uint64_t aligned = addr & ~7ULL;
    uint64_t plain = 0;
    axvm_status_t st = slot_read_plain64(ctx, aligned, &plain);
    if (st != AXVM_OK) {
        return st;
    }
    if (addr & 4) {
        plain = (plain & 0xFFFFFFFFULL) | ((uint64_t)val << 32);
    } else {
        plain = (plain & 0xFFFFFFFF00000000ULL) | (uint64_t)val;
    }
    return axvm_vm_stack_store64(ctx, aligned, plain);
}

axvm_status_t axvm_vm_stack_load32(axvm_ctx_t *ctx, uint64_t addr, uint32_t *out)
{
    uint64_t aligned = addr & ~7ULL;
    uint64_t plain = 0;
    axvm_status_t st = axvm_vm_stack_load64(ctx, aligned, &plain);
    if (st != AXVM_OK) {
        return st;
    }
    *out = (uint32_t)((addr & 4) ? (plain >> 32) : plain);
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_store8(axvm_ctx_t *ctx, uint64_t addr, uint8_t val)
{
    uint64_t aligned = addr & ~7ULL;
    uint64_t plain = 0;
    axvm_status_t st = slot_read_plain64(ctx, aligned, &plain);
    if (st != AXVM_OK) {
        return st;
    }
    uint32_t sh = (uint32_t)((addr & 7ULL) * 8ULL);
    uint64_t mask = 0xFFULL << sh;
    plain = (plain & ~mask) | ((uint64_t)val << sh);
    return axvm_vm_stack_store64(ctx, aligned, plain);
}

axvm_status_t axvm_vm_stack_load8(axvm_ctx_t *ctx, uint64_t addr, uint8_t *out)
{
    uint64_t aligned = addr & ~7ULL;
    uint64_t plain = 0;
    axvm_status_t st = axvm_vm_stack_load64(ctx, aligned, &plain);
    if (st != AXVM_OK) {
        return st;
    }
    *out = (uint8_t)(plain >> ((addr & 7ULL) * 8ULL));
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_store16(axvm_ctx_t *ctx, uint64_t addr, uint16_t val)
{
    axvm_status_t st = axvm_vm_stack_store8(ctx, addr, (uint8_t)val);
    if (st != AXVM_OK) {
        return st;
    }
    return axvm_vm_stack_store8(ctx, addr + 1, (uint8_t)(val >> 8));
}

axvm_status_t axvm_vm_stack_load16(axvm_ctx_t *ctx, uint64_t addr, uint16_t *out)
{
    uint8_t lo = 0, hi = 0;
    axvm_status_t st = axvm_vm_stack_load8(ctx, addr, &lo);
    if (st != AXVM_OK) {
        return st;
    }
    st = axvm_vm_stack_load8(ctx, addr + 1, &hi);
    if (st != AXVM_OK) {
        return st;
    }
    *out = (uint16_t)lo | ((uint16_t)hi << 8);
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_push64(axvm_ctx_t *ctx, uint64_t val)
{
    if (ctx->sp < (uint64_t)(uintptr_t)ctx->vm_stack_base + 8) {
        return AXVM_ERR_OOB_STACK;
    }
    ctx->sp -= 8;
    if (ctx->sp & 7) {
        return AXVM_ERR_ALIGN;
    }
    return axvm_vm_stack_store64(ctx, ctx->sp, val);
}

axvm_status_t axvm_vm_stack_pop64(axvm_ctx_t *ctx, uint64_t *out)
{
    if (ctx->sp + 8 > (uint64_t)(uintptr_t)ctx->vm_stack_top) {
        return AXVM_ERR_OOB_STACK;
    }
    if (ctx->sp & 7) {
        return AXVM_ERR_ALIGN;
    }
    axvm_status_t st = axvm_vm_stack_load64(ctx, ctx->sp, out);
    if (st != AXVM_OK) {
        return st;
    }
    ctx->sp += 8;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_peek64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out)
{
    return axvm_vm_stack_load64(ctx, addr, out);
}

axvm_status_t axvm_vm_stack_peek_plain64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out)
{
    return slot_read_plain64(ctx, addr, out);
}

int axvm_stack_crypt_probe_plaintext(axvm_ctx_t *ctx, uint64_t magic)
{
    if (!ctx || !ctx->vm_stack_base) {
        return -1;
    }

    const uint8_t *base = ctx->vm_stack_base;
    const uint8_t *end = ctx->vm_stack_top;
    const uint8_t pat[8] = {
        (uint8_t)(magic),
        (uint8_t)(magic >> 8),
        (uint8_t)(magic >> 16),
        (uint8_t)(magic >> 24),
        (uint8_t)(magic >> 32),
        (uint8_t)(magic >> 40),
        (uint8_t)(magic >> 48),
        (uint8_t)(magic >> 56),
    };

    for (const uint8_t *p = base; p + 8 <= end; ++p) {
        if (memcmp(p, pat, 8) == 0) {
            return 1; /* 发现明文 */
        }
    }
    return 0;
}

#else /* !AXVM_STACK_CRYPT */

int axvm_stack_crypt_enabled(void)
{
    return 0;
}

void axvm_stack_crypt_init(axvm_ctx_t *ctx)
{
    (void)ctx;
}

void axvm_stack_crypt_reset(axvm_ctx_t *ctx)
{
    (void)ctx;
}

void axvm_stack_crypt_wipe(axvm_ctx_t *ctx)
{
    (void)ctx;
}

uint64_t axvm_stack_crypt_key_mix(const axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

axvm_status_t axvm_vm_stack_store64(axvm_ctx_t *ctx, uint64_t addr, uint64_t val)
{
    *(uint64_t *)(uintptr_t)addr = val;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_load64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out)
{
    *out = *(uint64_t *)(uintptr_t)addr;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_store32(axvm_ctx_t *ctx, uint64_t addr, uint32_t val)
{
    *(uint32_t *)(uintptr_t)addr = val;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_load32(axvm_ctx_t *ctx, uint64_t addr, uint32_t *out)
{
    *out = *(uint32_t *)(uintptr_t)addr;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_store16(axvm_ctx_t *ctx, uint64_t addr, uint16_t val)
{
    *(uint16_t *)(uintptr_t)addr = val;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_load16(axvm_ctx_t *ctx, uint64_t addr, uint16_t *out)
{
    *out = *(uint16_t *)(uintptr_t)addr;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_store8(axvm_ctx_t *ctx, uint64_t addr, uint8_t val)
{
    *(uint8_t *)(uintptr_t)addr = val;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_load8(axvm_ctx_t *ctx, uint64_t addr, uint8_t *out)
{
    *out = *(uint8_t *)(uintptr_t)addr;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_push64(axvm_ctx_t *ctx, uint64_t val)
{
    if (ctx->sp < (uint64_t)(uintptr_t)ctx->vm_stack_base + 8) {
        return AXVM_ERR_OOB_STACK;
    }
    ctx->sp -= 8;
    if (ctx->sp & 7) {
        return AXVM_ERR_ALIGN;
    }
    return axvm_vm_stack_store64(ctx, ctx->sp, val);
}

axvm_status_t axvm_vm_stack_pop64(axvm_ctx_t *ctx, uint64_t *out)
{
    if (ctx->sp + 8 > (uint64_t)(uintptr_t)ctx->vm_stack_top) {
        return AXVM_ERR_OOB_STACK;
    }
    if (ctx->sp & 7) {
        return AXVM_ERR_ALIGN;
    }
    axvm_status_t st = axvm_vm_stack_load64(ctx, ctx->sp, out);
    if (st != AXVM_OK) {
        return st;
    }
    ctx->sp += 8;
    return AXVM_OK;
}

axvm_status_t axvm_vm_stack_peek64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out)
{
    return axvm_vm_stack_load64(ctx, addr, out);
}

axvm_status_t axvm_vm_stack_peek_plain64(axvm_ctx_t *ctx, uint64_t addr, uint64_t *out)
{
    if (!out) {
        return AXVM_ERR_BAD_MAGIC;
    }
    memcpy(out, (void *)(uintptr_t)addr, 8);
    return AXVM_OK;
}

int axvm_stack_crypt_probe_plaintext(axvm_ctx_t *ctx, uint64_t magic)
{
    (void)ctx;
    (void)magic;
    return 0; /* 未启用加密时不做对抗检测 */
}

#endif /* AXVM_STACK_CRYPT */
