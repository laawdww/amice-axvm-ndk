#include "axgate_mem.h"
#include "axgate_aes.h"

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

axgate_status_t axgate_mem_map_rw(const axgate_apis_t *api, size_t size, axgate_image_t *img)
{
    if (!api || !api->mmap || !img || size == 0) {
        return AXGATE_ERR_ARGS;
    }
    memset(img, 0, sizeof(*img));
    img->memfd = -1;
    img->size = size;
    img->addr = api->mmap(NULL, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (img->addr == MAP_FAILED || !img->addr) {
        img->addr = NULL;
        return AXGATE_ERR_MEM;
    }
    return AXGATE_OK;
}

axgate_status_t axgate_mem_protect_rx(const axgate_apis_t *api, axgate_image_t *img)
{
    if (!api || !api->mprotect || !img || !img->addr) {
        return AXGATE_ERR_ARGS;
    }
    if (api->mprotect(img->addr, img->size, PROT_READ | PROT_EXEC) != 0) {
        return AXGATE_ERR_MEM;
    }
    return AXGATE_OK;
}

void axgate_mem_unmap(const axgate_apis_t *api, axgate_image_t *img)
{
    if (!img) {
        return;
    }
    if (api && api->munmap && img->addr) {
        api->munmap(img->addr, img->size);
    }
    if (img->memfd >= 0 && api && api->close) {
        api->close(img->memfd);
    }
    memset(img, 0, sizeof(*img));
    img->memfd = -1;
}
