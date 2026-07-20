#ifndef AXGATE_MEM_H
#define AXGATE_MEM_H

#include "axgate_types.h"
#include "axgate_iat.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 6 — mmap 匿名私有内存 + mprotect RX
 * 解密缓冲仅存在于匿名页；成功后 RX，失败则 munmap。
 */
typedef struct axgate_image {
    void  *addr;
    size_t size;
    int    memfd; /* MEMFD 模式可选持有；FLAT 为 -1 */
} axgate_image_t;

axgate_status_t axgate_mem_map_rw(const axgate_apis_t *api, size_t size, axgate_image_t *img);
axgate_status_t axgate_mem_protect_rx(const axgate_apis_t *api, axgate_image_t *img);
void            axgate_mem_unmap(const axgate_apis_t *api, axgate_image_t *img);

/* ARM64：清易失寄存器痕迹后 BR 到 OEP（不返回） */
void axgate_jump_oep(void *oep) __attribute__((noreturn));

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_MEM_H */
