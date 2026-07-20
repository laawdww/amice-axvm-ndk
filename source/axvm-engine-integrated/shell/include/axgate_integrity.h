#ifndef AXGATE_INTEGRITY_H
#define AXGATE_INTEGRITY_H

#include "axgate_types.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 3 — SHA256 完整性
 * 对解密后的 axvm 解释器镜像做摘要比对；失败则拒绝进入 OEP。
 */
void axgate_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
axgate_status_t axgate_integrity_verify(const uint8_t *plain, size_t len,
                                        const uint8_t expect[32]);

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_INTEGRITY_H */
