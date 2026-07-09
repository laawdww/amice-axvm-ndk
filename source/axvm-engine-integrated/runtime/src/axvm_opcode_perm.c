#include "axvm_opcode_perm.h"

#include <string.h>

void axvm_opcode_perm_build(const uint8_t key[32], uint8_t fwd[256], uint8_t inv[256])
{
    for (int i = 0; i < 256; ++i) {
        fwd[i] = (uint8_t)i;
    }
    if (key) {
        /* Fisher-Yates，直接由 32 字节密钥驱动 LCG（与 Go 侧逐位一致）。 */
        uint32_t acc = 0x9E3779B9u;
        for (int i = 255; i > 0; --i) {
            acc = acc * 1664525u + 1013904223u + (uint32_t)key[i & 31] + (uint32_t)i;
            int j = (int)(acc % (uint32_t)(i + 1));
            uint8_t t = fwd[i];
            fwd[i] = fwd[j];
            fwd[j] = t;
        }
    }
    for (int i = 0; i < 256; ++i) {
        inv[fwd[i]] = (uint8_t)i;
    }
}

int axvm_opcode_perm_selftest(void)
{
    static const uint8_t key[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
        0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
    };
    uint8_t fwd[256], inv[256];
    axvm_opcode_perm_build(key, fwd, inv);

    for (int i = 0; i < 256; ++i) {
        if (inv[fwd[i]] != (uint8_t)i) {
            return 1;
        }
    }
    uint8_t seen[256];
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < 256; ++i) {
        if (seen[fwd[i]]) {
            return 2; /* 非双射 */
        }
        seen[fwd[i]] = 1;
    }
    return 0;
}
