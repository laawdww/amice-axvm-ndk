/*
 * Host tool: encrypt string literals for AXVM_STRCRYPT.
 * Build: cc -o gen_strcrypt tools/gen_strcrypt.c
 * Usage: gen_strcrypt "my secret string"
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const uint8_t key[16] = {
    0xA7, 0x3C, 0x91, 0x5E, 0xD2, 0x48, 0xF6, 0x0B,
    0x73, 0x29, 0xBE, 0x64, 0x18, 0xC5, 0x8A, 0x4F,
};

#define ROUNDS 4

static void encrypt(const uint8_t *plain, uint8_t *out, size_t n)
{
    memcpy(out, plain, n);
    for (int r = 0; r < ROUNDS; ++r) {
        for (size_t i = 0; i < n; ++i) {
            uint8_t b = out[i];
            b ^= key[(i + (size_t)r * 3u) & 15];
            b = (uint8_t)((b << 3) | (b >> 5));
            b ^= (uint8_t)(r + 1);
            b = (uint8_t)(b + key[i & 15]);
            out[i] = b;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <string>\n", argv[0]);
        return 1;
    }
    const char *s = argv[1];
    size_t n = strlen(s);
    uint8_t enc[512];
    if (n >= sizeof(enc)) {
        return 1;
    }
    encrypt((const uint8_t *)s, enc, n);
    printf("/* \"%s\" len=%zu */\n", s, n);
    printf("static const uint8_t enc[] = {\n    ");
    for (size_t i = 0; i < n; ++i) {
        printf("0x%02x%s", enc[i], (i + 1 < n) ? ", " : "");
        if ((i + 1) % 8 == 0 && i + 1 < n) {
            printf("\n    ");
        }
    }
    printf("\n};\n");
    return 0;
}
