#ifndef AXVM_STEXT_H
#define AXVM_STEXT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int axvm_stext_enabled(void);
int axvm_stext_wiped_modules(void);
int axvm_stext_unlock_regions(void);

size_t axvm_stext_patch_len(const uint8_t *entry);

void axvm_stext_crypt(uint8_t *buf, size_t n, const uint8_t master[32], uint32_t func_id);
int axvm_stext_decrypt_runtime(uint8_t *mem, size_t n, uint32_t func_id);
int axvm_stext_decrypt_file_range(uint8_t *file, size_t file_off, size_t n,
                                  uint32_t func_id);
int axvm_stext_roundtrip_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_STEXT_H */
