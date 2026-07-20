#include "axgate_iat.h"
#include "axgate_aes.h"

#include <dlfcn.h>
#include <string.h>

/*
 * 名表格式：连续 NUL 结尾字符串，已按 api_xor_key 滚动 XOR。
 * 顺序固定：
 *   0 mmap 1 mprotect 2 munmap 3 memfd_create 4 ftruncate
 *   5 libc.so 6 libdl.so（可选，优先 RTLD_DEFAULT）
 */

static void dec_name(char *out, size_t out_cap, const uint8_t *enc, size_t enc_len, uint8_t key)
{
    size_t n = enc_len;
    if (n >= out_cap) {
        n = out_cap - 1;
    }
    for (size_t i = 0; i < n; ++i) {
        out[i] = (char)(enc[i] ^ (uint8_t)(key + (uint8_t)i));
    }
    out[n] = '\0';
}

static const uint8_t *next_cstr(const uint8_t *p, const uint8_t *end, size_t *len)
{
    const uint8_t *s = p;
    while (p < end && *p) {
        ++p;
    }
    *len = (size_t)(p - s);
    if (p < end) {
        ++p; /* skip NUL */
    }
    return p;
}

axgate_status_t axgate_iat_resolve(axgate_apis_t *apis, uint8_t name_xor,
                                   const uint8_t *name_tab, uint32_t name_tab_len)
{
    if (!apis) {
        return AXGATE_ERR_ARGS;
    }
    memset(apis, 0, sizeof(*apis));

    /* 最小导入：仅使用 linker 提供的 dl* */
    apis->dlopen = dlopen;
    apis->dlsym = dlsym;
    apis->dlclose = dlclose;

    void *libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) {
        libc = dlopen("libc.so.6", RTLD_NOW);
    }
    if (!libc) {
        return AXGATE_ERR_IAT;
    }

    const char *defaults[] = {
        "mmap", "mprotect", "munmap", "memfd_create", "ftruncate",
        "open", "read", "close", "ptrace"
    };
    void **slots[] = {
        (void **)&apis->mmap, (void **)&apis->mprotect, (void **)&apis->munmap,
        (void **)&apis->memfd_create, (void **)&apis->ftruncate,
        (void **)&apis->open, (void **)&apis->read, (void **)&apis->close,
        (void **)&apis->ptrace
    };

    if (name_tab && name_tab_len > 0) {
        const uint8_t *p = name_tab;
        const uint8_t *end = name_tab + name_tab_len;
        for (int i = 0; i < 9 && p < end; ++i) {
            size_t ln = 0;
            const uint8_t *next = next_cstr(p, end, &ln);
            char name[64];
            dec_name(name, sizeof(name), p, ln, name_xor);
            *slots[i] = dlsym(libc, name);
            axgate_secure_wipe(name, sizeof(name));
            p = next;
        }
    } else {
        for (int i = 0; i < 9; ++i) {
            *slots[i] = dlsym(libc, defaults[i]);
        }
    }

    /* memfd_create 在旧 NDK 可能缺失 — 允许为空，boot 走纯匿名 mmap */
    if (!apis->mmap || !apis->mprotect || !apis->munmap) {
        return AXGATE_ERR_IAT;
    }
    return AXGATE_OK;
}
