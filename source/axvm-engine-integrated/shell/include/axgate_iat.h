#ifndef AXGATE_IAT_H
#define AXGATE_IAT_H

#include "axgate_types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 4 — 去静态 IAT：dlopen + 加密名 dlsym
 * 门卫层不直接链接 mmap/mprotect/open 等符号（编译可见性隐藏 + 弱依赖），
 * 运行时用滚动 XOR 解密 API 名再 dlsym，降低导入表特征。
 *
 * 引导仅保留对 linker 的 dlopen/dlsym（不可避免的最小导入）。
 */

typedef struct axgate_apis {
    void *(*mmap)(void *, size_t, int, int, int, long);
    int   (*mprotect)(void *, size_t, int);
    int   (*munmap)(void *, size_t);
    int   (*memfd_create)(const char *, unsigned int);
    int   (*ftruncate)(int, long);
    void *(*dlopen)(const char *, int);
    void *(*dlsym)(void *, const char *);
    int   (*dlclose)(void *);
    int   (*open)(const char *, int, ...);
    long  (*read)(int, void *, size_t);
    int   (*close)(int);
    int   (*ptrace)(int, int, void *, void *);
} axgate_apis_t;

axgate_status_t axgate_iat_resolve(axgate_apis_t *apis, uint8_t name_xor,
                                   const uint8_t *name_tab, uint32_t name_tab_len);

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_IAT_H */
