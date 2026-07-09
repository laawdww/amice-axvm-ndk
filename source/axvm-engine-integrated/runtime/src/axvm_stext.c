#include "axvm_stext.h"
#include "axvm_dynseed.h"
#include "axvm_pack.h"

#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

extern int axvm_loader_stext_wiped_count(void);
extern int axvm_loader_stext_unlock_total(void);

size_t axvm_stext_patch_len(const uint8_t *entry)
{
    if (!entry) {
        return 4;
    }
    uint32_t w0;
    uint32_t w1;
    memcpy(&w0, entry, sizeof(w0));
    if (w0 == 0x58000050u) {
        memcpy(&w1, entry + 4, sizeof(w1));
        if (w1 == 0xD61F0200u) {
            return 16;
        }
    }
    return 4;
}

void axvm_stext_crypt(uint8_t *buf, size_t n, const uint8_t master[32], uint32_t func_id)
{
    if (!buf || n == 0 || !master) {
        return;
    }
    uint8_t roll = (uint8_t)(func_id ^ master[1] ^ 0x7Eu);
    for (size_t i = 0; i < n; ++i) {
        uint8_t k = (uint8_t)(master[(i + (size_t)func_id * 3u) & 31] ^ roll ^ (uint8_t)(i * 11u + 0x2Du));
        buf[i] ^= k;
        /* 滚动链仅依赖索引/密钥，保证 pack 加密与 runtime 解密对合 */
        roll = (uint8_t)((roll + (uint8_t)(i + 1u) + k) ^ 0xA3u);
    }
}

int axvm_stext_enabled(void)
{
#if defined(AXVM_STEXT) && AXVM_STEXT
    return 1;
#else
    return 0;
#endif
}

int axvm_stext_wiped_modules(void)
{
    int unlocked = axvm_loader_stext_unlock_total();
    if (unlocked > 0) {
        return unlocked;
    }
    return axvm_loader_stext_wiped_count();
}

int axvm_stext_unlock_regions(void)
{
    return axvm_loader_stext_unlock_total();
}

int axvm_stext_decrypt_runtime(uint8_t *mem, size_t n, uint32_t func_id)
{
#if !defined(AXVM_STEXT) || !AXVM_STEXT
    (void)mem;
    (void)n;
    (void)func_id;
    return 0;
#endif
    if (!mem || n == 0) {
        return -1;
    }
    if (!axvm_dynseed_master_is_real()) {
        return 0;
    }
    uint8_t master[32];
    axvm_dynseed_get_master_plain(master);
    axvm_stext_crypt(mem, n, master, func_id);
    volatile uint8_t *w = master;
    for (size_t i = 0; i < sizeof(master); ++i) {
        w[i] = 0;
    }
    return 1;
}

int axvm_stext_decrypt_file_range(uint8_t *file, size_t file_off, size_t n,
                                  uint32_t func_id)
{
#if !defined(AXVM_STEXT) || !AXVM_STEXT
    (void)file;
    (void)file_off;
    (void)n;
    (void)func_id;
    return 0;
#endif
    if (!file || n == 0 || file_off + n > (size_t)-1) {
        return -1;
    }
    return axvm_stext_decrypt_runtime(file + file_off, n, func_id);
}

int axvm_stext_roundtrip_selftest(void)
{
#if !defined(AXVM_STEXT) || !AXVM_STEXT
    return 0;
#endif
    static const uint8_t fake_master[32] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x20,
    };
    uint8_t jump4[4] = { 0x14, 0x00, 0x00, 0x14 };
    if (axvm_stext_patch_len(jump4) != 4) {
        return 1;
    }
    uint8_t buf[32] = "axvm-stext-roundtrip-selftest!!";
    uint8_t ref[32];
    memcpy(ref, buf, sizeof(ref));
    axvm_stext_crypt(buf, sizeof(buf), fake_master, 7);
    if (memcmp(buf, ref, sizeof(ref)) == 0) {
        return 2;
    }
    axvm_stext_crypt(buf, sizeof(buf), fake_master, 7);
    return (memcmp(buf, ref, sizeof(ref)) == 0) ? 0 : 3;
}
