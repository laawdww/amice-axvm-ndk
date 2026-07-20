#ifndef AXGATE_TYPES_H
#define AXGATE_TYPES_H

/*
 * axgate — ARM64 Android ELF 轻量化前置 Stub 安全壳（门卫层）
 *
 * 职责边界：
 *   - 只做外层引导：反调试 / 完整性 / 去 IAT 动态解析 / AES 解密镜像 /
 *     mmap 匿名私有页 / mprotect RX / 清密钥 / 跳转 OEP
 *   - 不干涉 axvm 私有 ISA、字节码调度、x7d 解释路径
 *
 * 指纹策略：魔数由打包时派生（非固定 ASCII），密文 AES 钥不落 desc 明文。
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 版本布局；magic 由 host 侧 axgate_desc_magic（打包派生）校验 */
#define AXGATE_VERSION 0x00010001u

#define AXGATE_FLAG_ANTIDEBUG   0x00000001u
#define AXGATE_FLAG_INTEGRITY   0x00000002u
#define AXGATE_FLAG_IAT_CRYPT   0x00000004u
#define AXGATE_FLAG_AES_CTR     0x00000008u
#define AXGATE_FLAG_FLAT_OEP    0x00000010u /* 解密后直接 BR 到 map+oep_rva（PIC 镜像） */
#define AXGATE_FLAG_MEMFD_ELF   0x00000020u /* 解密后 memfd+dlopen 完整 ELF（兼容 libaxvm.so） */
#define AXGATE_FLAG_AXZC        0x00000040u /* 密文为 AXZC v4；reserved1=压缩长度 */
#define AXGATE_FLAG_KEY_WRAP    0x00000080u /* aes 材料为 uk 包裹，非明文 key/iv */

#pragma pack(push, 1)
/*
 * 描述符通常置于宿主 blob 头。
 * image 密文紧随其后（或由 image_off 相对本节基址定位）。
 */
typedef struct axgate_desc {
    uint32_t magic;       /* 打包派生，匹配 axgate_desc_magic */
    uint32_t version;     /* AXGATE_VERSION */
    uint32_t flags;       /* AXGATE_FLAG_* */
    uint32_t reserved0;

    uint32_t image_size;  /* 明文（解压后）字节数 */
    uint32_t image_off;   /* 相对 desc 起点的密文偏移 */
    uint32_t name_tab_off;/* 加密 API 名表偏移（相对 desc） */
    uint32_t name_tab_len;

    uint8_t  key_wrap[32]; /* KEY_WRAP: (aes_key||aes_iv) XOR kdf(uk,desc)；否则旧布局兼容 */
    uint8_t  sha256[32];  /* 明文镜像 SHA256（解压后） */

    uint64_t oep_rva;     /* FLAT：映射基址 + rva；MEMFD：忽略，改用 symbol */
    uint32_t api_xor_key; /* API 名表 XOR 滚动密钥（低 8 位有效） */
    uint32_t reserved1;   /* AXZC：压缩后字节数（= 密文长度） */
} axgate_desc_t;
#pragma pack(pop)

typedef enum axgate_status {
    AXGATE_OK = 0,
    AXGATE_ERR_MAGIC = 1,
    AXGATE_ERR_DEBUG = 2,
    AXGATE_ERR_HASH = 3,
    AXGATE_ERR_IAT = 4,
    AXGATE_ERR_AES = 5,
    AXGATE_ERR_MEM = 6,
    AXGATE_ERR_OEP = 7,
    AXGATE_ERR_ARGS = 8,
    AXGATE_ERR_INFLATE = 9
} axgate_status_t;

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_TYPES_H */
