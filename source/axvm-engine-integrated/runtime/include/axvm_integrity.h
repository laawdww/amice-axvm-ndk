#ifndef AXVM_INTEGRITY_H
#define AXVM_INTEGRITY_H

#include "axvm_types.h"

struct axvm_ctx;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 I — 分段 SHA256 SO 完整性校验
 *
 * axpack 打包时对以下段各计算 SHA256，XOR 加密后写入 EOF 扩展完整性节：
 *   AXVM_INTSEG_BC   : pack 字节码 blob 段
 *   AXVM_INTSEG_STUB : stub 跳板代码段
 *   AXVM_INTSEG_TEXT : 被保护 SO 自身 .text 段（入口跳转+NOP 抹除后的最终形态）
 *
 * 说明：选择 hash 被保护 SO 自身 .text 而非 libaxvm.so 解释器 .text，
 * 避免受保护应用与运行时库版本耦合；解释器自身完整性由模块 H 的
 * text_integrity prologue 快照负责。
 *
 * 运行时在 VM 初始化 / BL_NATIVE 入口 / dispatch 循环分散校验；
 * 命中篡改即清空密钥/栈/寄存器并 halt。
 *
 * 编译期开关 AXVM_SO_INTEGRITY；关闭时全部 API 空操作。
 * 运行期：仅当已 arm（注册有效清单）时探针才生效，无 pack 环境零误报。
 */

#define AXVM_INTEG_MAGIC   0x32585041u  /* 'AXP2' little-endian */
#define AXVM_INTEG_VERSION 0x00010000u

#define AXVM_INTSEG_BC     0u
#define AXVM_INTSEG_STUB   1u
#define AXVM_INTSEG_TEXT   2u
#define AXVM_INTSEG_MAX    4u

/* trip 标志 */
#define AXVM_INTEG_TRIP_BC    0x0001u
#define AXVM_INTEG_TRIP_STUB  0x0002u
#define AXVM_INTEG_TRIP_TEXT  0x0004u
#define AXVM_INTEG_TRIP_PARSE 0x0008u

/* dispatch 分散探针周期（与模块 H 一致的稀疏策略） */
#define AXVM_INTEG_DISPATCH_PERIOD 128u

#pragma pack(push, 1)
typedef struct axvm_integ_entry {
    uint32_t seg_id;
    uint32_t flags;
    uint64_t seg_off;    /* BC/STUB: 相对 pack 首字节；TEXT: 相对 load_base */
    uint64_t seg_size;
    uint8_t  enc_hash[32];
} axvm_integ_entry_t;

typedef struct axvm_integ_hdr {
    uint32_t magic;
    uint32_t version;
    uint32_t seg_count;
    uint32_t reserved;
    uint8_t  key_seed[16];
    /* 后接 seg_count 个 axvm_integ_entry_t */
} axvm_integ_hdr_t;
#pragma pack(pop)

/* ---- SHA256（供运行时与自检使用） ---- */
typedef struct axvm_sha256_ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    uint32_t buflen;
} axvm_sha256_ctx_t;

void axvm_sha256_init(axvm_sha256_ctx_t *c);
void axvm_sha256_update(axvm_sha256_ctx_t *c, const void *data, size_t n);
void axvm_sha256_final(axvm_sha256_ctx_t *c, uint8_t out[32]);
void axvm_sha256(const void *data, size_t n, uint8_t out[32]);

/* ---- 公共 API ---- */
int axvm_integrity_enabled(void);

/* 运行时是否已注册有效清单（探针生效前置条件） */
int axvm_integrity_armed(void);

/*
 * 从 pack 定位并解析 EOF 完整性节，解密期望哈希，解析各段内存指针，arm。
 * load_base 用于解析 TEXT 段（相对 load_base）。返回 AXVM_OK 表示成功 arm。
 */
axvm_status_t axvm_integrity_register(const uint8_t *pack, size_t pack_len,
                                      void *load_base);

/* 校验单段（idx 为段序号）。armed 且失败时 trip 并返回 AXVM_ERR_GUARD */
axvm_status_t axvm_integrity_verify_seg(struct axvm_ctx *ctx, uint32_t idx);

/* 分散探针：dispatch 主循环（周期轮转 1 段）；BL_NATIVE 入口 */
axvm_status_t axvm_integrity_probe_dispatch(struct axvm_ctx *ctx);
axvm_status_t axvm_integrity_probe_native(struct axvm_ctx *ctx);

/* VM 初始化全量校验（axvm_ctx_create / module load 调用） */
axvm_status_t axvm_integrity_probe_init(struct axvm_ctx *ctx);

/* 命中篡改：记录标志 + halt + 清空 ctx 敏感数据 */
void axvm_integrity_trip_ctx(struct axvm_ctx *ctx, uint32_t flag);

uint32_t axvm_integrity_trip_flags(void);

/*
 * 自检（无 pack 的 PIE 环境）：对给定内存段构造 1 段清单并 arm，
 * 使 probe_dispatch 直接校验该 live 段。用于篡改自测。
 */
axvm_status_t axvm_integrity_arm_test(const void *seg, size_t n);
void          axvm_integrity_reset(void);

/* 合法运行时修补（如 TEXT 跳转到 stub）后，重算 live 段期望哈希 */
void axvm_integrity_refresh_live(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_INTEGRITY_H */
