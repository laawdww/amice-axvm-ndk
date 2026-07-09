#include "axvm_mem_guard.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#if defined(AXVM_MEM_GUARD) && AXVM_MEM_GUARD

static int g_page_size;

static void mem_guard_init_once(void)
{
    if (g_page_size <= 0) {
        long ps = sysconf(_SC_PAGESIZE);
        g_page_size = (ps > 0) ? (int)ps : 4096;
    }
}

static int mprotect_pool(axvm_ctx_t *ctx, int prot)
{
    if (!ctx || !ctx->mem_pool || ctx->mem_pool_size == 0) {
        return -1;
    }
    mem_guard_init_once();
    uintptr_t base = (uintptr_t)ctx->mem_pool & ~((uintptr_t)g_page_size - 1u);
    uintptr_t end = (uintptr_t)ctx->mem_pool + ctx->mem_pool_size;
    size_t len = (size_t)(end - base);
    len = (len + (size_t)g_page_size - 1u) & ~((size_t)g_page_size - 1u);
    return mprotect((void *)base, len, prot);
}

int axvm_mem_guard_enabled(void)
{
    return 1;
}

void axvm_mem_guard_unseal(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    if (mprotect_pool(ctx, PROT_READ | PROT_WRITE) == 0) {
        ctx->mem_pool_sealed = 0;
    }
}

void axvm_mem_guard_seal(axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->mem_pool) {
        return;
    }
    if (mprotect_pool(ctx, PROT_NONE) == 0) {
        ctx->mem_pool_sealed = 1;
    }
}

int axvm_mem_guard_is_sealed(const axvm_ctx_t *ctx)
{
    return ctx && ctx->mem_pool_sealed;
}

int axvm_mem_guard_selftest(axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->mem_pool) {
        return 1;
    }
    axvm_mem_guard_unseal(ctx);
    ctx->mem_pool[0] = 0x5A;
    axvm_mem_guard_seal(ctx);
    if (!ctx->mem_pool_sealed) {
        return 2;
    }
    axvm_mem_guard_unseal(ctx);
    if (ctx->mem_pool[0] != 0x5A) {
        return 3;
    }
    axvm_mem_guard_seal(ctx);
    return 0;
}

#else

int axvm_mem_guard_enabled(void)
{
    return 0;
}

void axvm_mem_guard_unseal(axvm_ctx_t *ctx)
{
    (void)ctx;
}

void axvm_mem_guard_seal(axvm_ctx_t *ctx)
{
    (void)ctx;
}

int axvm_mem_guard_is_sealed(const axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

int axvm_mem_guard_selftest(axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

#endif /* AXVM_MEM_GUARD */
