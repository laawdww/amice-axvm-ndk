#ifndef AXVM_LAZY_H
#define AXVM_LAZY_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 G — BasicBlock 粒度字节码懒解密
 *
 * 设计要点：
 *  1. 代码区静止时整体为密文（每 axvm_ctx 独立随机密钥）。
 *  2. 取指命中某 AXVM_LAZY_BLOCK 块时临时就地解密；下一条取指前立刻异或回写密文。
 *  3. 采用与数据无关的对合(involutive) XOR 密钥流：同一 keystream 施加两次即还原，
 *     因此“解密”与“重加密”是同一操作，无需保存明文副本。
 *  4. 任一时刻内存中最多只有当前指令跨越的 1~2 个块为明文，全量 dump 只能抓到密文。
 *
 * 编译期开关 AXVM_LAZY_DECRYPT：关闭时全部降级为空操作，代码区保持明文便于调试。
 */

/* 运行时查询开关状态 */
int axvm_lazy_enabled(void);

/* 实例生命周期 */
void axvm_lazy_init(axvm_ctx_t *ctx);   /* 生成单实例密钥 */
void axvm_lazy_seal(axvm_ctx_t *ctx);   /* 将整个代码区就地加密（静止密文） */
void axvm_lazy_wipe(axvm_ctx_t *ctx);   /* 清零密钥与活动窗口 */

/* 取指/译码钩子：确保 [abs_off, abs_off+width) 覆盖的块已解密 */
axvm_status_t axvm_lazy_ensure(axvm_ctx_t *ctx, size_t abs_off, size_t width);

/* 指令边界：把当前活动窗口内的块全部异或回写为密文 */
void axvm_lazy_reencrypt_active(axvm_ctx_t *ctx);

/* 单块就地异或（解密或重加密同一入口，供 gdb 断点监控块流程） */
void axvm_lazy_xor_block(axvm_ctx_t *ctx, uint32_t blk);

/* 调试观测：返回实例密钥混合值 */
uint64_t axvm_lazy_key_mix(const axvm_ctx_t *ctx);

/*
 * 内存 dump 对抗测试：比较代码区常驻字节与给定明文模板，
 * 返回 1 表示常驻内存出现明文（泄露），0 表示为密文。
 */
int axvm_lazy_probe_plaintext(const axvm_ctx_t *ctx, const uint8_t *plain, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_LAZY_H */
