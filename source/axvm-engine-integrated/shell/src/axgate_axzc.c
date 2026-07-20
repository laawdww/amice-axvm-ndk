#include "axgate_axzc.h"
#include "axgate_aes.h"
#include "axgate_mem.h"

#include <string.h>
#include <sys/mman.h>
#include <zlib.h>

/*
 * AXZC v4 on-wire:
 *   u8  ver=4
 *   u8  hdr_flags
 *   u16 block_count    LE
 *   u32 stream_seed    LE
 *   blocks[block_count]:
 *     u32 raw_len      LE
 *     u32 packed_len   LE
 *     u16 dyn_check    LE
 *     u8  payload[packed_len]   // perturbed zlib stream
 *
 * Block key = key_c(seed,blk) XOR smc_mix(seed,blk).
 * SMC page must return smc_mix or inflate fails (anti-patch).
 */

#define AXZC_VER           4u
#define AXZC_SMC_PAGE      4096u
#define AXZC_MAX_PACKED    (16u * 1024u * 1024u)

static const uint8_t k_smc_mask[4] = { 0x5A, 0xA3, 0xC7, 0x19 };

/* Hand-assembled mix; portable C + RX page that must match. */
static uint32_t axzc_smc_mix(uint32_t seed, uint32_t blk)
{
    return ((seed ^ 0xA5C96357u) * 0x45D9F3Bu) ^ ((blk + 7u) * 0x119DE1F3u);
}

static uint32_t axzc_key_c(uint32_t seed, uint32_t blk)
{
    return (seed * 0x85EBCA6Bu) ^ ((blk + 1u) * 0xC2B2AE35u);
}

static uint32_t axzc_block_key(uint32_t seed, uint32_t blk)
{
    return axzc_key_c(seed, blk) ^ axzc_smc_mix(seed, blk);
}

static uint16_t axzc_rd16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t axzc_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t axzc_dyn_check(const uint8_t *p, size_t n, uint32_t seed, uint32_t blk)
{
    uint32_t h = seed ^ (blk * 0x9E3779B9u) ^ (uint32_t)n;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x01000193u;
        h ^= h >> 7;
    }
    return (uint16_t)(h ^ (h >> 16));
}

static void axzc_unperturb(uint8_t *buf, size_t n, uint32_t key, uint32_t blk)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t b = buf[i];
        b ^= (uint8_t)(i) ^ (uint8_t)blk;
        b = (uint8_t)((b >> 3) | (b << 5));
        b ^= (uint8_t)(key >> ((i & 3u) * 8u));
        buf[i] = b;
    }
}

static axgate_status_t axzc_zlib_inflate(const uint8_t *src, size_t src_len,
                                         uint8_t *dst, size_t dst_len)
{
    if (src_len > 0xffffffffu || dst_len > 0xffffffffu) {
        return AXGATE_ERR_ARGS;
    }
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = (Bytef *)(uintptr_t)src;
    strm.avail_in = (uInt)src_len;
    strm.next_out = (Bytef *)dst;
    strm.avail_out = (uInt)dst_len;
    if (inflateInit(&strm) != Z_OK) {
        return AXGATE_ERR_INFLATE;
    }
    int rc = inflate(&strm, Z_FINISH);
    unsigned long out = strm.total_out;
    inflateEnd(&strm);
    if (rc != Z_STREAM_END || out != dst_len) {
        return AXGATE_ERR_INFLATE;
    }
    return AXGATE_OK;
}

typedef uint32_t (*axzc_smc_fn)(uint32_t seed, uint32_t blk);

static void axzc_emit_arm64_mix(uint8_t *p)
{
    /* mov w2, #0x6357 */
    p[0] = 0xe2; p[1] = 0x6a; p[2] = 0x8c; p[3] = 0x52;
    /* movk w2, #0xa5c9, lsl #16 */
    p[4] = 0x22; p[5] = 0xb9; p[6] = 0xb4; p[7] = 0x72;
    /* eor w2, w0, w2 */
    p[8] = 0x02; p[9] = 0x00; p[10] = 0x02; p[11] = 0x4a;
    /* mov w3, #0x9f3b */
    p[12] = 0x63; p[13] = 0xe7; p[14] = 0x93; p[15] = 0x52;
    /* movk w3, #0x045d, lsl #16 */
    p[16] = 0xa3; p[17] = 0x8b; p[18] = 0xa0; p[19] = 0x72;
    /* mul w2, w2, w3 */
    p[20] = 0x42; p[21] = 0x7c; p[22] = 0x03; p[23] = 0x1b;
    /* add w3, w1, #7 */
    p[24] = 0x23; p[25] = 0x1c; p[26] = 0x00; p[27] = 0x11;
    /* mov w4, #0xe1f3 */
    p[28] = 0x64; p[29] = 0x3e; p[30] = 0x9c; p[31] = 0x52;
    /* movk w4, #0x119d, lsl #16 */
    p[32] = 0xa4; p[33] = 0x33; p[34] = 0xa2; p[35] = 0x72;
    /* mul w3, w3, w4 */
    p[36] = 0x63; p[37] = 0x7c; p[38] = 0x04; p[39] = 0x1b;
    /* eor w0, w2, w3 */
    p[40] = 0x40; p[41] = 0x00; p[42] = 0x03; p[43] = 0x4a;
    /* ret */
    p[44] = 0xc0; p[45] = 0x03; p[46] = 0x5f; p[47] = 0xd6;
}

static axgate_status_t axzc_smc_install(const axgate_apis_t *api, void **out_page,
                                        axzc_smc_fn *out_fn)
{
    *out_page = NULL;
    *out_fn = NULL;
    if (!api || !api->mmap || !api->mprotect || !api->munmap) {
        return AXGATE_ERR_ARGS;
    }

    void *page = api->mmap(NULL, AXZC_SMC_PAGE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!page || page == MAP_FAILED) {
        return AXGATE_ERR_MEM;
    }

    uint8_t *p = (uint8_t *)page;
    memset(p, 0, AXZC_SMC_PAGE);
#if defined(__aarch64__)
    axzc_emit_arm64_mix(p);
    /* light self-check decoy */
    p[48] ^= 0x11;
    p[48] ^= 0x11;
    __builtin___clear_cache((char *)page, (char *)page + 64);
#else
    (void)k_smc_mask;
    /* Non-ARM: leave page zero; caller uses C mix only. */
#endif
    if (api->mprotect(page, AXZC_SMC_PAGE, PROT_READ | PROT_EXEC) != 0) {
        axgate_secure_wipe(page, AXZC_SMC_PAGE);
        api->munmap(page, AXZC_SMC_PAGE);
        return AXGATE_ERR_MEM;
    }

    *out_page = page;
    *out_fn = (axzc_smc_fn)page;
    return AXGATE_OK;
}

static void axzc_smc_teardown(const axgate_apis_t *api, void *page)
{
    if (!api || !page || !api->mprotect || !api->munmap) {
        return;
    }
    (void)api->mprotect(page, AXZC_SMC_PAGE, PROT_READ | PROT_WRITE);
    axgate_secure_wipe(page, AXZC_SMC_PAGE);
    api->munmap(page, AXZC_SMC_PAGE);
}

static uint32_t axzc_smc_key(const axgate_apis_t *api, void *page, axzc_smc_fn fn,
                             uint32_t seed, uint32_t blk)
{
    uint32_t expect = axzc_smc_mix(seed, blk);
#if defined(__aarch64__)
    if (!page || !fn) {
        return expect ^ 0xFFFFFFFFu; /* force mismatch */
    }
    if (api && api->mprotect) {
        uint8_t *p = (uint8_t *)page;
        (void)api->mprotect(page, AXZC_SMC_PAGE, PROT_READ | PROT_WRITE);
        p[49] = (uint8_t)(blk ^ 0x5A);
        p[50] = (uint8_t)seed;
        /* restore code bytes 0..47 if tampered lightly — re-emit */
        axzc_emit_arm64_mix(p);
        __builtin___clear_cache((char *)page, (char *)page + 64);
        (void)api->mprotect(page, AXZC_SMC_PAGE, PROT_READ | PROT_EXEC);
    }
    uint32_t got = fn(seed, blk);
    if (got != expect) {
        return got; /* caller compares */
    }
    return got;
#else
    (void)api;
    (void)page;
    (void)fn;
    (void)blk;
    return expect;
#endif
}

axgate_status_t axgate_axzc_inflate(const axgate_apis_t *api,
                                    const uint8_t *src, size_t src_len,
                                    uint8_t *dst, size_t dst_len)
{
    if (!src || !dst || src_len < 8u || dst_len == 0) {
        return AXGATE_ERR_ARGS;
    }
    if (src[0] != AXZC_VER) {
        return AXGATE_ERR_INFLATE;
    }

    uint16_t block_count = axzc_rd16(src + 2);
    uint32_t seed = axzc_rd32(src + 4);
    if (block_count == 0) {
        return AXGATE_ERR_INFLATE;
    }

    void *smc_page = NULL;
    axzc_smc_fn smc_fn = NULL;
    if (axzc_smc_install(api, &smc_page, &smc_fn) != AXGATE_OK) {
#if defined(__aarch64__)
        return AXGATE_ERR_INFLATE;
#endif
    }

    size_t off = 8;
    size_t di = 0;
    axgate_status_t st = AXGATE_OK;

    for (uint32_t bi = 0; bi < (uint32_t)block_count; bi++) {
        if (off + 10u > src_len) {
            st = AXGATE_ERR_INFLATE;
            break;
        }
        uint32_t raw_len = axzc_rd32(src + off);
        uint32_t packed_len = axzc_rd32(src + off + 4);
        uint16_t expect = axzc_rd16(src + off + 8);
        off += 10;
        if (raw_len == 0 || packed_len == 0 || packed_len > AXZC_MAX_PACKED ||
            off + packed_len > src_len || di + raw_len > dst_len) {
            st = AXGATE_ERR_INFLATE;
            break;
        }
        if (!api) {
            st = AXGATE_ERR_ARGS;
            break;
        }

        axgate_image_t scratch;
        memset(&scratch, 0, sizeof(scratch));
        st = axgate_mem_map_rw(api, packed_len, &scratch);
        if (st != AXGATE_OK) {
            break;
        }

        uint32_t mix = axzc_smc_key(api, smc_page, smc_fn, seed, bi);
        if (mix != axzc_smc_mix(seed, bi)) {
            axgate_secure_wipe(scratch.addr, scratch.size);
            axgate_mem_unmap(api, &scratch);
            st = AXGATE_ERR_INFLATE;
            break;
        }
        uint32_t key = axzc_block_key(seed, bi);
        memcpy(scratch.addr, src + off, packed_len);
        off += packed_len;
        axzc_unperturb((uint8_t *)scratch.addr, packed_len, key, bi);

        st = axzc_zlib_inflate((const uint8_t *)scratch.addr, packed_len,
                               dst + di, raw_len);
        axgate_secure_wipe(scratch.addr, scratch.size);
        axgate_mem_unmap(api, &scratch);
        if (st != AXGATE_OK) {
            break;
        }
        if (axzc_dyn_check(dst + di, raw_len, seed, bi) != expect) {
            st = AXGATE_ERR_INFLATE;
            break;
        }
        di += raw_len;
    }

    axzc_smc_teardown(api, smc_page);

    if (st != AXGATE_OK) {
        return st;
    }
    if (off != src_len || di != dst_len) {
        return AXGATE_ERR_INFLATE;
    }
    return AXGATE_OK;
}
