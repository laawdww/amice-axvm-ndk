#ifndef AXVM_LAZY_PF_H
#define AXVM_LAZY_PF_H

#include "axvm_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Phase 3 — 页故障驱动的懒解密增强（扩展模块 G）
 *
 * 在 BasicBlock XOR 懒解密之上，将代码区按页 mprotect(PROT_NONE) 封存；
 * 合法路径由 lazy_ensure 主动解封；非法直读触发 SIGSEGV，由运行期 handler
 * 在绑定线程上下文中解封并解密对应块后重试。
 *
 * 依赖：AXVM_LAZY_DECRYPT，仅 Linux/Android。
 */

int axvm_lazy_pf_enabled(void);

void axvm_lazy_pf_install(void);

void axvm_lazy_pf_bind_ctx(axvm_ctx_t *ctx);
void axvm_lazy_pf_unbind_ctx(void);

void axvm_lazy_pf_seal_all(axvm_ctx_t *ctx);
void axvm_lazy_pf_unseal_for_range(axvm_ctx_t *ctx, size_t rel_off, size_t width);

int axvm_lazy_pf_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_LAZY_PF_H */
