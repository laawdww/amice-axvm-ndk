#ifndef AXGATE_ELF_H
#define AXGATE_ELF_H

#include "axgate_types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 1 — 入口劫持 / ELF 元数据辅助
 * 打包期改写 e_entry 或 DT_INIT_ARRAY 指向 axgate_ctor；
 * 运行期仅解析自身 so 基址与 .axgate 描述符，不改写 axvm 字节码区。
 */

typedef struct axgate_elf_view {
    uintptr_t load_base;     /* 本 SO PT_LOAD 最小 vaddr 对应基址 */
    const uint8_t *gate_sec; /* .axgate 映射地址（可空） */
    size_t        gate_len;
    uint64_t      saved_oep; /* 原始入口 VA（可选，供恢复） */
} axgate_elf_view_t;

int axgate_elf_locate_self(axgate_elf_view_t *out);
const axgate_desc_t *axgate_elf_find_desc(const uint8_t *sec, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_ELF_H */
