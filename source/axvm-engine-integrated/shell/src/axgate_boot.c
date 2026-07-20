#include "axgate.h"
#include "axgate_elf.h"
#include "axgate_antidebug.h"
#include "axgate_integrity.h"
#include "axgate_iat.h"
#include "axgate_aes.h"
#include "axgate_mem.h"
#include "axgate_axzc.h"
#include "axgate_kdf.h"

#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * 门卫编排（严格顺序，模块解耦只通过头文件 API）：
 *  1) ELF 定位描述符
 *  2) IAT 动态解析
 *  3) 反调试
 *  4) mmap RW → AES-CTR 解密 [→ AXZC 解压]
 *  5) SHA256 完整性（明文）
 *  6) mprotect RX → 清密钥 → 跳 OEP / 或 memfd+dlopen
 *
 * 不调用 axvm_invoke / 不改 pack 字节码 / 不碰私有 ISA。
 */

extern const uint8_t axgate_section[] __attribute__((weak));
extern const uint32_t axgate_section_size __attribute__((weak));

static void *g_inner_handle;
static int g_boot_done;
static int g_boot_ok;

/* Decrypt (+optional inflate) into img sized to uncompressed image_size. */
static axgate_status_t decrypt_plain(const axgate_desc_t *desc, const uint8_t *ct,
                                     axgate_apis_t *api, axgate_image_t *img)
{
    size_t plain_len = desc->image_size;
    size_t cipher_len = plain_len;
    if (desc->flags & AXGATE_FLAG_AXZC) {
        cipher_len = desc->reserved1;
        if (cipher_len == 0 || cipher_len > plain_len * 4u + 64u) {
            return AXGATE_ERR_ARGS;
        }
    }

    axgate_status_t st = axgate_mem_map_rw(api, plain_len, img);
    if (st != AXGATE_OK) {
        return st;
    }

    uint8_t key[16], iv[16];
    st = axgate_unwrap_aes_material(desc, key, iv);
    if (st != AXGATE_OK) {
        axgate_mem_unmap(api, img);
        return st;
    }

    if (desc->flags & AXGATE_FLAG_AXZC) {
        axgate_image_t tmp;
        st = axgate_mem_map_rw(api, cipher_len, &tmp);
        if (st != AXGATE_OK) {
            axgate_secure_wipe(key, sizeof(key));
            axgate_secure_wipe(iv, sizeof(iv));
            axgate_mem_unmap(api, img);
            return st;
        }
        st = axgate_aes128_ctr_crypt(key, iv, ct, (uint8_t *)tmp.addr, cipher_len);
        axgate_secure_wipe(key, sizeof(key));
        axgate_secure_wipe(iv, sizeof(iv));
        if (st != AXGATE_OK) {
            axgate_mem_unmap(api, &tmp);
            axgate_mem_unmap(api, img);
            return st;
        }
        st = axgate_axzc_inflate(api, (const uint8_t *)tmp.addr, cipher_len,
                                 (uint8_t *)img->addr, plain_len);
        axgate_secure_wipe(tmp.addr, tmp.size);
        axgate_mem_unmap(api, &tmp);
        if (st != AXGATE_OK) {
            axgate_mem_unmap(api, img);
            return st;
        }
    } else {
        st = axgate_aes128_ctr_crypt(key, iv, ct, (uint8_t *)img->addr, cipher_len);
        axgate_secure_wipe(key, sizeof(key));
        axgate_secure_wipe(iv, sizeof(iv));
        if (st != AXGATE_OK) {
            axgate_mem_unmap(api, img);
            return st;
        }
    }

    if (desc->flags & AXGATE_FLAG_INTEGRITY) {
        st = axgate_integrity_verify((const uint8_t *)img->addr, plain_len, desc->sha256);
        if (st != AXGATE_OK) {
            axgate_mem_unmap(api, img);
            return st;
        }
    }
    return AXGATE_OK;
}

static axgate_status_t boot_flat(const axgate_desc_t *desc, const uint8_t *ct,
                                 axgate_apis_t *api)
{
    axgate_image_t img;
    axgate_status_t st = decrypt_plain(desc, ct, api, &img);
    if (st != AXGATE_OK) {
        return st;
    }

    st = axgate_mem_protect_rx(api, &img);
    if (st != AXGATE_OK) {
        axgate_mem_unmap(api, &img);
        return st;
    }

    void *oep = (void *)((uintptr_t)img.addr + (uintptr_t)desc->oep_rva);
    axgate_jump_oep(oep);
    return AXGATE_OK; /* unreachable */
}

static axgate_status_t boot_memfd_elf(const axgate_desc_t *desc, const uint8_t *ct,
                                      axgate_apis_t *api)
{
    axgate_image_t img;
    axgate_status_t st = decrypt_plain(desc, ct, api, &img);
    if (st != AXGATE_OK) {
        return st;
    }

    if (!api->memfd_create || !api->ftruncate) {
        st = axgate_mem_protect_rx(api, &img);
        if (st != AXGATE_OK) {
            axgate_mem_unmap(api, &img);
            return st;
        }
        axgate_jump_oep((void *)((uintptr_t)img.addr + (uintptr_t)desc->oep_rva));
        return AXGATE_OK; /* unreachable */
    }

    int fd = api->memfd_create(".", 1 /* MFD_CLOEXEC */);
    if (fd < 0) {
        axgate_mem_unmap(api, &img);
        return AXGATE_ERR_MEM;
    }
    if (api->ftruncate(fd, (long)desc->image_size) != 0) {
        if (api->close) {
            api->close(fd);
        }
        axgate_mem_unmap(api, &img);
        return AXGATE_ERR_MEM;
    }

    void *w = api->mmap(NULL, desc->image_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!w || w == MAP_FAILED) {
        if (api->close) {
            api->close(fd);
        }
        axgate_mem_unmap(api, &img);
        return AXGATE_ERR_MEM;
    }
    memcpy(w, img.addr, desc->image_size);
    api->munmap(w, desc->image_size);
    axgate_secure_wipe(img.addr, img.size);
    axgate_mem_unmap(api, &img);

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    void *h = api->dlopen(path, RTLD_NOW);
    axgate_secure_wipe(path, sizeof(path));
    if (!h) {
        if (api->close) {
            api->close(fd);
        }
        return AXGATE_ERR_OEP;
    }
    /* Keep memfd open so the mapping stays valid. */
    (void)fd;
    g_inner_handle = h;

    void *disp = api->dlsym(h, "x7d");
    void *reg = api->dlsym(h, "axvm_register_dispatch");
    if (reg && disp) {
        typedef void (*reg_fn)(void *);
        ((reg_fn)reg)(disp);
    }
    return AXGATE_OK;
}

axgate_status_t axgate_boot(const axgate_desc_t *desc, const uint8_t *section_base)
{
    if (!desc || !axgate_desc_magic || desc->magic != axgate_desc_magic) {
        return AXGATE_ERR_MAGIC;
    }
    if (desc->version != AXGATE_VERSION) {
        return AXGATE_ERR_MAGIC;
    }
    if (!section_base) {
        return AXGATE_ERR_ARGS;
    }

    axgate_apis_t api;
    const uint8_t *ntab = NULL;
    uint32_t nlen = 0;
    if ((desc->flags & AXGATE_FLAG_IAT_CRYPT) && desc->name_tab_len && desc->name_tab_off) {
        ntab = section_base + desc->name_tab_off;
        nlen = desc->name_tab_len;
    }
    axgate_status_t st = axgate_iat_resolve(&api, (uint8_t)desc->api_xor_key, ntab, nlen);
    if (st != AXGATE_OK) {
        return st;
    }

    if (desc->flags & AXGATE_FLAG_ANTIDEBUG) {
        st = axgate_antidebug_check(&api);
        if (st != AXGATE_OK) {
            return st;
        }
    }

    const uint8_t *ct = section_base + desc->image_off;
    if (desc->flags & AXGATE_FLAG_MEMFD_ELF) {
        return boot_memfd_elf(desc, ct, &api);
    }
    return boot_flat(desc, ct, &api);
}

void axgate_ctor(void)
{
    if (g_boot_done) {
        return;
    }
    g_boot_done = 1;
    const uint8_t *sec = NULL;
    size_t slen = 0;
    if (axgate_section && axgate_section_size) {
        sec = axgate_section;
        slen = axgate_section_size;
    }
    if (!sec || !slen) {
        g_boot_ok = 0;
        return;
    }
    const axgate_desc_t *d = axgate_elf_find_desc(sec, slen);
    if (!d) {
        g_boot_ok = 0;
        return;
    }
    g_boot_ok = (axgate_boot(d, sec) == AXGATE_OK && g_inner_handle != NULL) ? 1 : 0;
}

int axgate_ensure_booted(void)
{
    if (!g_boot_done) {
        axgate_ctor();
    }
    return g_boot_ok && g_inner_handle != NULL;
}

void *axgate_inner_handle(void)
{
    if (!axgate_ensure_booted()) {
        return NULL;
    }
    return g_inner_handle;
}

__attribute__((constructor(90)))
static void axgate_auto_ctor(void)
{
    /* Defer heavy AXZC/XZ inflate out of .init_array — Android init stacks
     * are small; boot on first JNI_OnLoad / ensure_booted instead. */
}
