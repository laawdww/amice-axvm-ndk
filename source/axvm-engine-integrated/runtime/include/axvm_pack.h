#ifndef AXVM_PACK_H
#define AXVM_PACK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AXPK_MAGIC 0x31585041u  /* 'AXP1' little-endian */

#define AXPK_FLAG_ENCRYPTED 0x00000001u
#define AXPK_FLAG_WIPED     0x00000002u
#define AXPK_FLAG_TOKEN     0x00000004u /* VMPacker 风格 3 指令 token 入口 */

#pragma pack(push, 1)
typedef struct axvm_pack_hdr {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    uint32_t func_count;
    uint32_t table_off;
    uint32_t blob_off;
    uint32_t blob_size;
    uint8_t  key_seed[16];
    uint32_t checksum;
    uint64_t file_off;   /* pack offset in on-disk SO (EOF append) */
} axvm_pack_hdr_t;

typedef struct axvm_func_rec {
    uint32_t func_id;
    uint32_t name_hash;
    uint32_t entry_pc;
    uint32_t bc_size;
    uint64_t orig_vaddr;
    uint32_t stub_off;
    uint32_t blob_off;
    char     name[36];
    uint32_t orig_size;
    uint32_t stub_meta; /* v2+: low16=stub_size, bits16-23=dispatch_off, bits24-31=variant */
} axvm_func_rec_t;
#pragma pack(pop)

#define AXVM_PACK_VERSION     0x00010001u
#define AXVM_PACK_VERSION_L1  0x00010000u
#define AXVM_PACK_VERSION_V2 0x00010002u /* func_rec.stub_meta: stub size + dispatch off */

#define AXVM_REC_SIZE_V1 72u
#define AXVM_REC_SIZE_V2 76u

/* 由 libaxvm.so 导出 — 加固 SO 跳板调用.
 * a0..a6 in x1..x7; a7 + sret_x8 on stack (AAPCS64).
 * sret_x8 is AArch64 indirect-result (X8) for std::string / large struct returns. */
uint64_t axvm_dispatch_ex(uint32_t func_id,
                          uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                          uint64_t sret_x8);

/* 扫描 /proc/self/maps 注册所有 .axvm 节 */
void axvm_scan_proc_maps(void);
void axvm_rescan_modules(void);
void axvm_register_symbol(void *symbol);
/* 由 libaxvm 在 JNI_OnLoad 登记 dispatch，避免 dlsym("axvm_dispatch_ex") 字符串指纹 */
void axvm_register_dispatch(void *dispatch_fn);
void axvm_module_load(const uint8_t *pack, size_t len, void *load_base);
void axvm_module_load_ex(const uint8_t *pack, size_t len, void *load_base,
                         void *stub_exec, uint64_t stub_map_vaddr, int pack_owned);

/* 加载前对磁盘 SO 解密 stext / 打跳板，避免 Android SELinux execmod */
int axvm_prepatch_so_file(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_PACK_H */
