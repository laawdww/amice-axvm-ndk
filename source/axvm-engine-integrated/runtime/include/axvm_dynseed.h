#ifndef AXVM_DYNSEED_H
#define AXVM_DYNSEED_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 M — 双层动态种子（Virbox 风格）
 *
 *   MasterSeed  : 32 字节有效密钥。默认由 AXDS 块内 raw seed 解密得到；
 *                 启用 APK_BIND 时为 HMAC-SHA256(raw_seed, package||cert_sha256)。
 *                 密文形式存放于 SO 的 EOF 扩展块（AXDS），绝不明文落盘。
 *   SessionSeed : 每个 axvm_ctx 实例独立，由
 *                 HMAC-SHA256(MasterSeed, entropy_pool) 派生 32 字节。
 *
 * 由 SessionSeed 再派生栈滚动密钥、懒解密密钥（及未来 opcode 置换表），
 * 使同批 SO、乃至同进程多实例的运行期密钥各不相同，抬高内存 dump / 静态提取门槛。
 *
 * 编译期开关 AXVM_DYNAMIC_SEED：
 *   ON  : 启用双层种子，运行期子密钥来自 SessionSeed。
 *   OFF : 回退到既有 urandom-only / 静态种子行为（向后兼容）。
 */

/* ---- AXDS EOF 扩展块格式（axpack 生成，loader 解析） ---- */
#define AXDS_MAGIC   0x31445841u  /* 'AXD1' little-endian */
#define AXDS_VERSION 0x00010000u
#define AXDS_VERSION_V2 0x00010001u
#define AXDS_VERSION_V3 0x00010002u /* APK_BIND + MK2 (legacy: nonce-as-HMAC-key) */
#define AXDS_VERSION_V4 0x00010003u /* APK_BIND + MK3 (wrap key from pkg||cert) */

#define AXDS_FLAG_APK_BIND 0x00000001u

#pragma pack(push, 1)
typedef struct axvm_dynseed_block {
    uint32_t magic;        /* AXDS_MAGIC */
    uint32_t version;      /* AXDS_VERSION* */
    uint8_t  nonce[16];    /* per-build random; NOT the cipher key for V4 */
    uint8_t  master_enc[32]; /* encrypted raw seed */
    uint32_t checksum;     /* fnv1a32(magic..master_enc) */
    uint32_t flags;        /* AXDS_FLAG_APK_BIND 等 */
} axvm_dynseed_block_t;
#pragma pack(pop)

/* 子密钥用途标签（HMAC 消息） */
#define AXVM_DYNSEED_PURPOSE_STACK  0x4b435453u /* 'STCK' */
#define AXVM_DYNSEED_PURPOSE_LAZY   0x595a414cu /* 'LAZY' */
#define AXVM_DYNSEED_PURPOSE_OPCODE 0x45444f43u /* 'CODE' */
#define AXVM_DYNSEED_PURPOSE_REGPERM 0x50474552u /* 'REGP' — 模块 U */
#define AXVM_DYNSEED_PURPOSE_STRCRYPT 0x54525453u /* 'STRT' — 模块 Q */
#define AXVM_DYNSEED_PURPOSE_JNI_TUN 0x4e494a54u /* 'TJNI' — 模块 AB 隧道 */
#define AXVM_DYNSEED_PURPOSE_CRYPT  0x50595243u /* 'CRYP' — 模块 N 流密码变体 */
#define AXVM_DYNSEED_PURPOSE_KSEED  0x4445534Bu /* 'KSED' — wrap on-disk pack key_seed */
#define AXVM_DYNSEED_PURPOSE_DISPATCH 0x54434944u /* 'DICT' — 模块 N goto 调度置换 */
#define AXVM_DYNSEED_PURPOSE_HANDLER  0x4c4f5048u /* 'HPOL' — Phase3 handler 多态 */
#define AXVM_DYNSEED_PURPOSE_RISCC    0x43435352u /* 'RISC' — Phase3 RISCC wire 置换 */

/* 运行时查询开关状态：1=启用动态种子。 */
int axvm_dynseed_enabled(void);

/*
 * 由 loader 从 EOF AXDS 块调用：登记本模块加密后的 MasterSeed 与 nonce。
 * 允许多次调用（后者覆盖）。返回 1=接受。
 */
int axvm_dynseed_set_master(const uint8_t *master_enc, size_t enc_len,
                            const uint8_t *nonce, size_t nonce_len);

/*
 * 从原始 EOF 字节缓冲中查找并登记 AXDS 块（loader 便捷入口）。
 * 返回 1=找到并登记。
 */
int axvm_dynseed_scan_and_set(const uint8_t *buf, size_t len);

/*
 * prepatch 专用：清除进程内合成/陈旧 MasterSeed，从 SO 文件尾扫描并登记 AXDS。
 * 返回 1=找到 AXDS。
 */
void axvm_dynseed_reset_for_prepatch(void);
int axvm_dynseed_scan_tail_and_set(const uint8_t *buf, size_t len);

/*
 * 取当前（加密态）MasterSeed 到 out_enc[32]。
 * 若尚未由 EOF 登记，则合成一个每进程稳定的伪 MasterSeed（保证 ON 仍可用）。
 */
void axvm_dynseed_get_master_enc(uint8_t out_enc[32]);

/*
 * 1 = 已登记来自 AXDS 的真实 MasterSeed（非合成）。
 * opcode 置换等需与 axpack 严格对齐的功能须以此为前置条件。
 */
int axvm_dynseed_master_is_real(void);

/* 取当前 MasterSeed 的明文到 out[32]（内部解密；调用方用毕应擦除）。 */
void axvm_dynseed_get_master_plain(uint8_t out[32]);

/*
 * APK 绑定（AXDS v3 + AXDS_FLAG_APK_BIND）：
 * 在 prepatch / dlopen 保护 SO 之前调用，传入当前 APK 的 package 与签名证书 SHA-256。
 * 返回 1=已登记。
 */
int axvm_dynseed_set_apk_binding(const char *package, const uint8_t cert_sha256[32]);

/* 1 = 当前 AXDS 块要求 APK 绑定后才可解出有效 MasterSeed。 */
int axvm_dynseed_apk_bind_required(void);

/* 1 = 已登记 APK 绑定材料（package + cert）。 */
int axvm_dynseed_apk_binding_present(void);

/* 返回 1=derive_apk_bound_master 与 axpack Go 向量一致。 */
int axvm_dynseed_apk_bind_selftest(void);

/*
 * 轻量流密码：对 buf 原地加/解密（对合，同一函数双向）。keyed by nonce。
 * axpack 侧 Go 实现与此保持一致。
 */
void axvm_dynseed_master_cipher(uint8_t *buf, size_t n, const uint8_t nonce[16]);

/*
 * 从加密 MasterSeed 与熵派生 SessionSeed：
 *   plain_master = master_cipher(master_enc, g_nonce)
 *   out_seed     = HMAC-SHA256(plain_master, entropy)
 * 内部使用完毕即擦除明文 master。
 */
void axvm_derive_session_seed(const uint8_t *master_enc, size_t master_len,
                              const uint8_t *entropy, size_t ent_len,
                              uint8_t out_seed[32]);

/*
 * 由 SessionSeed 派生特定用途子密钥：
 *   out = HMAC-SHA256(session_seed, purpose_tag)[0..n)
 */
void axvm_dynseed_subkey(const uint8_t session_seed[32], uint32_t purpose,
                         uint8_t *out, size_t n);

/* 由 MasterSeed 明文派生子密钥（pack 级：流密码变体等） */
void axvm_dynseed_master_subkey(const uint8_t master_plain[32], uint32_t purpose,
                                uint8_t *out, size_t n);

struct axvm_ctx; /* fwd */

/*
 * 便捷入口：为 ctx 采集熵并派生 SessionSeed 写入 ctx->session_seed，
 * 置位 ctx->session_seed_present。AXVM_DYNAMIC_SEED 关闭时为空操作。
 */
void axvm_dynseed_derive_ctx(struct axvm_ctx *ctx);

/* 安全擦除 ctx->session_seed（volatile 清零）。 */
void axvm_dynseed_wipe(struct axvm_ctx *ctx);

/* 调试观测：返回 SessionSeed 的 64 位混合值（不泄露原始种子）。 */
uint64_t axvm_dynseed_session_mix(const struct axvm_ctx *ctx);

/*
 * 由 AXDS raw seed 派生的 pack magic（模块 Z 指纹弱化）。
 * 无真实 AXDS 时返回 AXPK_MAGIC。
 */
uint32_t axvm_dynseed_pack_magic(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_DYNSEED_H */
