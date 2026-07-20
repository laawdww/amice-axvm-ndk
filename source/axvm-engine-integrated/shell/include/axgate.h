#ifndef AXGATE_H
#define AXGATE_H

#include "axgate_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 总入口：按六大模块顺序执行门卫流程。
 * desc / image_base 由构造器或打包器注入；成功后不返回（FLAT）或返回 OK（MEMFD）。
 */
axgate_status_t axgate_boot(const axgate_desc_t *desc, const uint8_t *section_base);

/* ELF 构造器钩子：在 DT_INIT_ARRAY 早期运行 */
void axgate_ctor(void);

/* 确保门卫已跑完（ctor 或显式调用均可）。返回 1=内层已就绪。 */
int axgate_ensure_booted(void);

/* MEMFD_ELF 成功后的内层 dlopen handle；未就绪返回 NULL。勿 dlclose。 */
void *axgate_inner_handle(void);

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_H */
