#include "axvm_dynseed.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    if (!axvm_dynseed_apk_bind_selftest()) {
        uint8_t raw[32], cert[32], out[32];
        for (int i = 0; i < 32; ++i) {
            raw[i] = (uint8_t)(i + 1);
            cert[i] = (uint8_t)(0xA0 + i);
        }
        /* derive via public API path is internal; selftest already ran */
        fprintf(stderr, "apk_bind selftest FAIL\n");
        return 1;
    }
    printf("apk_bind selftest PASS\n");
    return 0;
}
