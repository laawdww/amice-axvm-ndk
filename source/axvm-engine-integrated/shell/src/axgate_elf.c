#include "axgate_elf.h"
#include "axgate_kdf.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#if defined(__LP64__)
typedef Elf64_Ehdr Ehdr;
typedef Elf64_Phdr Phdr;
typedef Elf64_Shdr Shdr;
#else
typedef Elf32_Ehdr Ehdr;
typedef Elf32_Phdr Phdr;
typedef Elf32_Shdr Shdr;
#endif

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    axgate_elf_view_t *v = (axgate_elf_view_t *)data;
    /* 取第一个可执行 ET_DYN 且含我们构造器的对象较难；用 dladdr 在 boot 里补 */
    if (!v->load_base && info->dlpi_name && info->dlpi_phnum > 0) {
        v->load_base = (uintptr_t)info->dlpi_addr;
    }
    return 0;
}

int axgate_elf_locate_self(axgate_elf_view_t *out)
{
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    dl_iterate_phdr(phdr_cb, out);

    /* 通过本函数地址反查所属模块基址 */
    Dl_info di;
    if (dladdr((const void *)&axgate_elf_locate_self, &di) && di.dli_fbase) {
        out->load_base = (uintptr_t)di.dli_fbase;
    }
    return out->load_base ? 0 : -1;
}

const axgate_desc_t *axgate_elf_find_desc(const uint8_t *sec, size_t len)
{
    if (!sec || len < sizeof(axgate_desc_t)) {
        return NULL;
    }
    if (!axgate_desc_magic) {
        return NULL;
    }
    /* 节首或对齐扫描打包派生 magic（非固定 ASCII） */
    for (size_t off = 0; off + sizeof(axgate_desc_t) <= len; off += 8) {
        const axgate_desc_t *d = (const axgate_desc_t *)(sec + off);
        if (d->magic == axgate_desc_magic && d->version == AXGATE_VERSION) {
            return d;
        }
    }
    return NULL;
}
