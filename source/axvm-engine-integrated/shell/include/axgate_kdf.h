#ifndef AXGATE_KDF_H
#define AXGATE_KDF_H

#include "axgate_types.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * UW2：mask = SHA256(uk_seed || "UW2" || pkg || 0 || cert[32] || meta)
 * uk_seed 打散存于 host；完整解包钥依赖运行时注入的 APK 身份（非 SO 内嵌）。
 */
extern const uint64_t axgate_uk_q[4];
extern const uint32_t axgate_desc_magic;

void axgate_uk_seed(uint8_t out[32]);
void axgate_kdf_wrap_mask(const axgate_desc_t *desc, uint8_t mask[32]);
axgate_status_t axgate_unwrap_aes_material(const axgate_desc_t *desc,
                                           uint8_t key[16], uint8_t iv[16]);

/* Java / host 在 decrypt 前注入；成功返回 1 */
int axgate_set_runtime_identity(const char *pkg, const uint8_t cert[32]);
int axgate_runtime_identity(char *out_pkg, size_t pkg_cap, uint8_t out_cert[32]);

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_KDF_H */
