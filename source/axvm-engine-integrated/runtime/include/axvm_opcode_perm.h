#ifndef AXVM_OPCODE_PERM_H
#define AXVM_OPCODE_PERM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 M — Opcode 动态置换（已接入 dispatch，随 axpack 联动生效）
 *
 * 设计：
 *   axpack 用本次 build 的 MasterSeed（存于 AXDS EOF 块）确定性生成一张
 *   [0,256) 双射置换表，对每个受保护函数字节码的“操作码字节”做正向置换 fwd[]，
 *   并在其字节码头 flags 置 AXVM_BC_FLAG_OPCODE_PERM。
 *   运行时 loader 从 AXDS 解出 MasterSeed；ctx 创建时若字节码带该 flag 且
 *   MasterSeed 为真实（非合成），则重建逆表 inv[] 存入 ctx，dispatch 取指后
 *   以 inv[] 还原真实 opcode。内联字节码（无 flag）零影响。
 *
 *   与 tools/axpack/opcode_perm.go 的 Fisher-Yates 逐位一致（同一 32 字节密钥）。
 *   fail-safe：字节码流无法整齐走完（含未知 opcode/错位）时 axpack 放弃置换，
 *   不置 flag；MasterSeed 合成或 DYNAMIC_SEED 关闭时 ctx 不激活 → 恒等，语义不变。
 */

/*
 * 由 32 字节密钥确定性构建 opcode 双射置换。
 *   fwd[明文op] = 置换op；inv[置换op] = 明文op。
 * key 为 NULL 时生成恒等置换。
 */
void axvm_opcode_perm_build(const uint8_t key[32], uint8_t fwd[256], uint8_t inv[256]);

/* 自检：验证固定向量下 inv∘fwd == 恒等且 fwd 为排列。PASS 返回 0。 */
int axvm_opcode_perm_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_OPCODE_PERM_H */
