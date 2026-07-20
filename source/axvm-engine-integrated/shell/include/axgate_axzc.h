#ifndef AXGATE_AXZC_H
#define AXGATE_AXZC_H

#include "axgate_types.h"
#include "axgate_iat.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AXZC v4 — 专属帧（分块/动校/SMC/扰动）+ zlib BestCompression 载荷
 * 磁盘密文仍经 AES；zlib 比特流不裸露。
 */
axgate_status_t axgate_axzc_inflate(const axgate_apis_t *api,
                                    const uint8_t *src, size_t src_len,
                                    uint8_t *dst, size_t dst_len);

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_AXZC_H */
