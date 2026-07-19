#include "axvm_got_crypt.h"
#include "axvm_dynseed.h"

#include <stdint.h>

#if defined(AXVM_GOT_CRYPT) && AXVM_GOT_CRYPT && defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED

#include "axvm_got_crypt.h"
#include "axvm_dynseed.h"

#include <stdint.h>

static void     *g_dispatch_plain;
static uint64_t  g_dispatch_enc;
static uint64_t  g_got_key;
static int       g_got_bound;

static uint64_t got_key_from_master(void)
{
    uint8_t mk[32];
    axvm_dynseed_get_master_plain(mk);
    uint64_t k = 0x428A2F98D728AE22ULL;
    for (int i = 0; i < 32; ++i) {
        k ^= ((uint64_t)mk[i]) << ((i & 7) * 8);
        k = (k << 13) | (k >> 51);
        k ^= 0x9E3779B97F4A7C15ULL;
    }
    return k | 1ULL;
}

int axvm_got_crypt_enabled(void)
{
    return 1;
}

void axvm_got_crypt_bind_dispatch(void *dispatch_plain)
{
    g_dispatch_plain = dispatch_plain;
    g_got_key = got_key_from_master();
    g_dispatch_enc = (uint64_t)(uintptr_t)dispatch_plain ^ g_got_key;
    g_got_bound = (dispatch_plain != NULL);
}

void *axvm_got_crypt_resolve_dispatch(void)
{
    if (!g_got_bound) {
        return g_dispatch_plain;
    }
    return (void *)(uintptr_t)(g_dispatch_enc ^ g_got_key);
}

int axvm_got_crypt_probe_stub_leak(const void *stub_slot16)
{
    if (!stub_slot16 || !g_got_bound || !g_dispatch_plain) {
        return 0;
    }
    const uint8_t *p = (const uint8_t *)stub_slot16;
    uint64_t addr = (uint64_t)(uintptr_t)g_dispatch_plain;
    for (int shift = 0; shift <= 48; shift += 16) {
        uint16_t chunk = (uint16_t)((addr >> shift) & 0xFFFFu);
        if (chunk == 0) {
            continue;
        }
        for (int i = 0; i + 1 < 16; i += 2) {
            uint16_t at = (uint16_t)p[i] | ((uint16_t)p[i + 1] << 8);
            if (at == chunk) {
                return 1;
            }
        }
    }
    return 0;
}

int axvm_got_crypt_selftest(void)
{
    extern uint64_t x7d(uint32_t func_id,
                                     uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                                     uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                                     uint64_t sret_x8);
    axvm_got_crypt_bind_dispatch((void *)(uintptr_t)x7d);
    void *plain = axvm_got_crypt_resolve_dispatch();
    if (plain != (void *)(uintptr_t)x7d) {
        return 1;
    }
    uint8_t slot[16] = { 0 };
    if (axvm_got_crypt_probe_stub_leak(slot) != 0) {
        return 2;
    }
    return 0;
}

#if defined(__aarch64__)
extern uint64_t x7d(uint32_t func_id,
                                 uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                                 uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                                 uint64_t sret_x8);

uint64_t x7g_dispatch(uint32_t func_id,
                                uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                                uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                                uint64_t sret_x8)
{
    void *fn = axvm_got_crypt_resolve_dispatch();
    if (!fn) {
        return x7d(func_id, a0, a1, a2, a3, a4, a5, a6, a7, sret_x8);
    }
    typedef uint64_t (*disp_fn_t)(uint32_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                  uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    return ((disp_fn_t)fn)(func_id, a0, a1, a2, a3, a4, a5, a6, a7, sret_x8);
}
#endif /* __aarch64__ */

#else /* !AXVM_GOT_CRYPT */

int axvm_got_crypt_enabled(void)
{
    return 0;
}

void axvm_got_crypt_bind_dispatch(void *dispatch_plain)
{
    (void)dispatch_plain;
}

void *axvm_got_crypt_resolve_dispatch(void)
{
    return NULL;
}

int axvm_got_crypt_probe_stub_leak(const void *stub_slot16)
{
    (void)stub_slot16;
    return 0;
}

int axvm_got_crypt_selftest(void)
{
    return 0;
}

#endif /* AXVM_GOT_CRYPT */
