#include "axvm_lazy_pf.h"
#include "axvm_lazy.h"
#include "axvm_bytecode.h"
#include "axvm_bridge.h"

#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

#if defined(AXVM_LAZY_PF) && AXVM_LAZY_PF && (defined(__linux__) || defined(__ANDROID__))

static int g_page_size;
static volatile int g_lazy_pf_installed;
static struct sigaction g_prev_segv;
static __thread axvm_ctx_t *g_lazy_pf_tls_ctx;

static void lazy_pf_page_init(void)
{
    if (g_page_size <= 0) {
        long ps = sysconf(_SC_PAGESIZE);
        g_page_size = (ps > 0) ? (int)ps : 4096;
    }
}

static void lazy_pf_code_span(const axvm_ctx_t *ctx, uintptr_t *base_out, size_t *len_out)
{
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    uintptr_t code_start = (uintptr_t)ctx->bytecode + hdr->code_off;
    uintptr_t code_end = code_start + hdr->code_size;
    uintptr_t base = code_start & ~((uintptr_t)g_page_size - 1u);
    uintptr_t end = (code_end + (uintptr_t)g_page_size - 1u) &
                    ~((uintptr_t)g_page_size - 1u);
    *base_out = base;
    *len_out = (size_t)(end - base);
}

int axvm_lazy_pf_enabled(void)
{
    return 1;
}

void axvm_lazy_pf_bind_ctx(axvm_ctx_t *ctx)
{
    g_lazy_pf_tls_ctx = ctx;
}

void axvm_lazy_pf_unbind_ctx(void)
{
    g_lazy_pf_tls_ctx = NULL;
}

static int lazy_pf_page_in_code(const axvm_ctx_t *ctx, uintptr_t addr)
{
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    uintptr_t code_start = (uintptr_t)ctx->bytecode + hdr->code_off;
    uintptr_t code_end = code_start + hdr->code_size;
    return addr >= code_start && addr < code_end;
}

static void lazy_pf_seal_full_pages(axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->bytecode || !ctx->lazy_sealed) {
        return;
    }
    lazy_pf_page_init();
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    uintptr_t code_start = (uintptr_t)ctx->bytecode + hdr->code_off;
    uintptr_t code_end = code_start + hdr->code_size;
  /* 跳过与头部共享的首个非对齐页，仅封存完全落在代码区内的整页。 */
    uintptr_t first_full = (code_start + (uintptr_t)g_page_size - 1u) &
                           ~((uintptr_t)g_page_size - 1u);
    for (uintptr_t p = first_full; p + (uintptr_t)g_page_size <= code_end;
         p += (uintptr_t)g_page_size) {
        mprotect((void *)p, (size_t)g_page_size, PROT_NONE);
    }
}

void axvm_lazy_pf_seal_all(axvm_ctx_t *ctx)
{
    lazy_pf_seal_full_pages(ctx);
}

void axvm_lazy_pf_unseal_for_range(axvm_ctx_t *ctx, size_t rel_off, size_t width)
{
    if (!ctx || !ctx->lazy_sealed || !ctx->bytecode) {
        return;
    }
    lazy_pf_page_init();
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    if (rel_off >= hdr->code_size) {
        return;
    }
    size_t last = rel_off + (width ? width - 1u : 0u);
    if (last >= hdr->code_size) {
        last = hdr->code_size - 1u;
    }
    uintptr_t code_start = (uintptr_t)ctx->bytecode + hdr->code_off;
    uintptr_t p0 = (code_start + rel_off) & ~((uintptr_t)g_page_size - 1u);
    uintptr_t p1 = (code_start + last) & ~((uintptr_t)g_page_size - 1u);
    for (uintptr_t p = p0; p <= p1; p += (uintptr_t)g_page_size) {
        mprotect((void *)p, (size_t)g_page_size, PROT_READ | PROT_WRITE);
    }
}

static void lazy_pf_sigsegv(int sig, siginfo_t *info, void *ucontext)
{
    (void)ucontext;
    if (sig != SIGSEGV || !info) {
        if (g_prev_segv.sa_flags & SA_SIGINFO) {
            void (*fn)(int, siginfo_t *, void *) =
                (void (*)(int, siginfo_t *, void *))g_prev_segv.sa_sigaction;
            fn(sig, info, ucontext);
        } else if (g_prev_segv.sa_handler != SIG_DFL && g_prev_segv.sa_handler != SIG_IGN) {
            g_prev_segv.sa_handler(sig);
        }
        return;
    }

    axvm_ctx_t *ctx = g_lazy_pf_tls_ctx;
    uintptr_t fault = (uintptr_t)info->si_addr;
    if (!ctx || !ctx->lazy_sealed || !lazy_pf_page_in_code(ctx, fault)) {
        if (g_prev_segv.sa_flags & SA_SIGINFO) {
            void (*fn)(int, siginfo_t *, void *) =
                (void (*)(int, siginfo_t *, void *))g_prev_segv.sa_sigaction;
            fn(sig, info, ucontext);
        } else if (g_prev_segv.sa_handler != SIG_DFL && g_prev_segv.sa_handler != SIG_IGN) {
            g_prev_segv.sa_handler(sig);
        } else {
            signal(SIGSEGV, SIG_DFL);
            raise(SIGSEGV);
        }
        return;
    }

    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    size_t rel = (size_t)(fault - ((uintptr_t)ctx->bytecode + hdr->code_off));
    lazy_pf_page_init();
    uintptr_t page = fault & ~((uintptr_t)g_page_size - 1u);
    mprotect((void *)page, (size_t)g_page_size, PROT_READ | PROT_WRITE);
    (void)axvm_lazy_ensure(ctx, hdr->code_off + rel, 1);
}

static void lazy_pf_install_once(void)
{
    lazy_pf_page_init();
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = lazy_pf_sigsegv;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, &g_prev_segv);
}

void axvm_lazy_pf_install(void)
{
    if (g_lazy_pf_installed) {
        return;
    }
    lazy_pf_install_once();
    g_lazy_pf_installed = 1;
}

int axvm_lazy_pf_selftest(void)
{
    axvm_lazy_pf_install();

    uint8_t bc[64];
    memset(bc, 0, sizeof(bc));
    memcpy(bc, "AXV1", 4);
    uint32_t *u32 = (uint32_t *)bc;
    u32[1] = AXVM_VERSION;
    u32[3] = 40;
    u32[7] = 0;
    uint8_t code[] = { AXOP_LDRI64, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, AXOP_RET };
    u32[4] = (uint32_t)sizeof(code);
    u32[5] = 40 + (uint32_t)sizeof(code);
    memcpy(bc + 40, code, sizeof(code));
    u32[8] = axvm_bc_checksum(bc, 40 + sizeof(code));

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, 40 + sizeof(code)) != AXVM_OK) {
        return 1;
    }
    if (!ctx->lazy_sealed) {
        axvm_ctx_destroy(ctx);
        return 2;
    }
    axvm_lazy_pf_seal_all(ctx);
    axvm_lazy_pf_bind_ctx(ctx);
    axvm_bridge_enter(ctx);
    uint64_t rv = axvm_invoke(ctx, 0);
    axvm_lazy_pf_unbind_ctx();
    axvm_ctx_destroy(ctx);
    return (rv == 42) ? 0 : 3;
}

#else

int axvm_lazy_pf_enabled(void)
{
    return 0;
}

void axvm_lazy_pf_install(void)
{
}

void axvm_lazy_pf_bind_ctx(axvm_ctx_t *ctx)
{
    (void)ctx;
}

void axvm_lazy_pf_unbind_ctx(void)
{
}

void axvm_lazy_pf_seal_all(axvm_ctx_t *ctx)
{
    (void)ctx;
}

void axvm_lazy_pf_unseal_for_range(axvm_ctx_t *ctx, size_t rel_off, size_t width)
{
    (void)ctx;
    (void)rel_off;
    (void)width;
}

int axvm_lazy_pf_selftest(void)
{
    return 0;
}

#endif
