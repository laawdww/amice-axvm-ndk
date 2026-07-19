#ifndef AXVM_BYTECODE_H
#define AXVM_BYTECODE_H

#include "axvm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)
typedef struct axvm_bc_header {
    uint8_t  magic[4];      /* 'A','X','V','1' */
    uint32_t version;
    uint32_t flags;
    uint32_t code_off;      /* 代码区起始（通常 40） */
    uint32_t code_size;
    uint32_t data_off;
    uint32_t data_size;
    uint32_t entry_pc;      /* 相对 code_off 的 PC */
    uint32_t checksum;
    uint8_t  reserved[4];
} axvm_bc_header_t;
#pragma pack(pop)

#define AXVM_BC_HDR_SIZE sizeof(axvm_bc_header_t)

#define AXVM_BC_FLAG_ENCRYPTED   0x00000001u
#define AXVM_BC_FLAG_RELOC       0x00000002u
#define AXVM_BC_FLAG_OPCODE_PERM 0x00000004u /* 模块 M：操作码经 MasterSeed 置换 */
#define AXVM_BC_FLAG_RISCC       0x00000008u /* 模块 T：RISCC 线格式字节码 */
#define AXVM_BC_FLAG_RISCC_PERM  0x00000020u /* Phase3：RISCC wire SessionSeed 置换 */
#define AXVM_BC_FLAG_ADDR_MAP    0x00000010u /* VMPacker 风格 BR 映射 trailer */

/*
 * 私有 Opcode 编码（与 tools/axpack/lift.go 常量一致）
 * 变长：首字节 op，后续为操作数。
 */
typedef enum axvm_opcode {
    AXOP_NOP       = 0x00,
    AXOP_HALT      = 0x01,

    AXOP_LDRI64    = 0x10, /* u8 rd; u64 imm */
    AXOP_ADD_IMM   = 0x11, /* u8 rd; u8 rs; i32 imm */
    AXOP_SUB_IMM   = 0x12, /* u8 rd; u8 rs; i32 imm */

    AXOP_ADD_REG   = 0x13, /* u8 rd; u8 rn; u8 rm */
    AXOP_SUB_REG   = 0x14,
    AXOP_AND_REG   = 0x15,
    AXOP_ORR_REG   = 0x16,
    AXOP_EOR_REG   = 0x17,
    AXOP_LSL_IMM   = 0x18, /* u8 rd; u8 rs; u8 shamt (0-63) */
    AXOP_LSR_IMM   = 0x19,
    AXOP_CMP_REG   = 0x1A, /* u8 rn; u8 rm -> nzcv */
    AXOP_MUL_REG   = 0x1B,
    AXOP_CSEL_REG  = 0x1C, /* u8 rd; u8 rn; u8 rm; u8 cond */
    AXOP_MOVK      = 0x1D, /* u8 rd; u8 hw; u16 imm */

    AXOP_LDR_U64   = 0x20, /* u8 rt; u8 rn; i32 off (unsigned scaled, byte offset) */
    AXOP_STR_U64   = 0x21,
    AXOP_LDR_U32   = 0x22,
    AXOP_STR_U32   = 0x23,
    AXOP_LDUR_U64  = 0x24, /* u8 rt; u8 rn; i32 simm (unscaled byte offset) */
    AXOP_STUR_U64  = 0x25,
    AXOP_LDUR_U32  = 0x26,
    AXOP_STUR_U32  = 0x27,
    AXOP_LDR_U8    = 0x28,
    AXOP_STR_U8    = 0x29,
    AXOP_LDR_U16   = 0x2A,
    AXOP_STR_U16   = 0x2B,

    AXOP_MOV_REG   = 0x30, /* u8 rd; u8 rm */
    AXOP_MVN_REG   = 0x31, /* u8 rd; u8 rm */
    AXOP_ASR_IMM   = 0x32, /* u8 rd; u8 rs; u8 shamt (0-63) 算术右移 */

    AXOP_BR        = 0x40, /* i32 rel (相对当前 pc 的字节偏移) */
    AXOP_CMP_REG32 = 0x33, /* u8 rn; u8 rm -> 32-bit SUBS nzcv */

    AXOP_B_COND    = 0x41, /* u8 cond; i32 rel */
    AXOP_BL_NATIVE = 0x42, /* u16 slot -> natives[slot] AAPCS64 调用 */
    AXOP_BR_REG    = 0x43, /* u8 rn — 寄存器间接分支（函数内查 addr_map） */
    AXOP_BLR_REG   = 0x44, /* u8 rn — 寄存器间接原生调用 */
    AXOP_CALL_NAT  = 0x45, /* u64 addr — BL 绝对地址原生调用 */
    AXOP_LDRI64_VADDR = 0x46, /* u8 rd; u64 vaddr — 运行时 +module_load_base */
    AXOP_CALL_NAT_VADDR = 0x47, /* u64 vaddr — 运行时 +module_load_base */

    AXOP_RET       = 0x50,
    AXOP_PUSH_PAIR = 0x60, /* u8 rt; u8 rt2 — 压入 VM 栈 */
    AXOP_POP_PAIR  = 0x61,

    AXOP_LDR_REGOFF = 0x84, /* u8 rt; u8 rn; u8 rm; u8 width; u8 extend; u8 scale */
    AXOP_STR_REGOFF = 0x85, /* u8 rt; u8 rn; u8 rm; u8 width; u8 extend; u8 scale */
    AXOP_ZEXT32     = 0x86, /* u8 rd; rd = (uint32_t)rd */
    AXOP_CMP_IMM    = 0x87, /* u8 rn; u8 is32; i32 imm */

    /* 真原子：宿主 __atomic_* / 独占监视器（与 tools/axpack/lift_opc.go 对齐） */
    AXOP_ATOMIC_CAS64   = 0x88, /* u8 rs(old/expected); u8 rt(new); u8 rn(addr) */
    AXOP_ATOMIC_SWP64   = 0x89, /* u8 rt(old); u8 rs(new); u8 rn */
    AXOP_ATOMIC_LDADD64 = 0x8A, /* u8 rt(old); u8 rs(addend); u8 rn */
    AXOP_ATOMIC_LDCLR64 = 0x8B, /* u8 rt(old); u8 rs(mask); u8 rn */
    AXOP_ATOMIC_LDEOR64 = 0x8C, /* u8 rt(old); u8 rs(xor); u8 rn */
    AXOP_ATOMIC_LDSET64 = 0x8D, /* u8 rt(old); u8 rs(bits); u8 rn */
    AXOP_ATOMIC_LDXR64  = 0x8E, /* u8 rt; u8 rn — load + arm exclusive */
    AXOP_ATOMIC_STXR64  = 0x8F, /* u8 rs(status); u8 rt; u8 rn */
    AXOP_ATOMIC_CASP64  = 0x90, /* u8 rs(lo); u8 rt(lo); u8 rn — pair rs/rs+1, rt/rt+1 */
    AXOP_ATOMIC_STXP64  = 0x99, /* u8 rs(status); u8 rt; u8 rt2; u8 rn */
    AXOP_ATOMIC_LDXP64  = 0x9A, /* u8 rt; u8 rt2; u8 rn — 128-bit exclusive load */
    AXOP_ATOMIC_CAS32   = 0x9B,
    AXOP_ATOMIC_SWP32   = 0x9C,
    AXOP_ATOMIC_LDADD32 = 0x9D,
    AXOP_ATOMIC_LDCLR32 = 0x9E,
    AXOP_ATOMIC_LDEOR32 = 0x9F,
    AXOP_ATOMIC_LDSET32 = 0xA0,
    AXOP_ATOMIC_LDXR32  = 0xA1,
    AXOP_ATOMIC_STXR32  = 0xA2,

#if defined(AXVM_NESTED_VM) && AXVM_NESTED_VM
    /* 模块 R：嵌套 VM 字节码入口/出口 */
    AXOP_VM_ENTER  = 0x62, /* u32 child_off; u8 argc — 子 BC 在 blob 内偏移，参数 x0.. */
    AXOP_VM_LEAVE  = 0x63, /* 子 VM 显式返回（父 VM 继续） */
#endif

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    /* 模块 F：浮点访存/运算（与 tools/axpack/lift_opc.go 对齐） */
    AXOP_FLDR_D      = 0x70, /* u8 vt; u8 rn; i32 off (byte, unsigned) */
    AXOP_FSTR_D      = 0x71,
    AXOP_FLDR_S      = 0x72, /* load float widen to double in vt */
    AXOP_FSTR_S      = 0x73, /* narrow vt to float store */
    AXOP_FADD_D      = 0x74, /* u8 vd; u8 vn; u8 vm */
    AXOP_FSUB_D      = 0x75,
    AXOP_FMUL_D      = 0x76,
    AXOP_FDIV_D      = 0x77,
    AXOP_FCMP_D      = 0x78, /* u8 vn; u8 vm -> nzcv (AArch64 FP 标志) */
    AXOP_FMOV_D_REG  = 0x79, /* u8 vd; u8 vm */
    AXOP_FMOV_X_BITS = 0x7A, /* u8 xd; u8 vn — v 位模式写入 x，无转换 */
    AXOP_FMOV_D_BITS = 0x7B, /* u8 vd; u8 xn — x 位模式写入 v */
    AXOP_FMOV_D_X    = 0x7C, /* u8 vd; u8 xn — SCVTF 有符号整型转 double */
    AXOP_FCVT_DS     = 0x7D, /* u8 vd; u8 vn — double -> float 再 widen 回 vd */
    AXOP_JUNK        = 0x7E, /* u8 pad_len; pad_len 字节垃圾填充（模块 S） */
    AXOP_FCVTZS_D    = 0x7F, /* u8 rd; u8 vn; u8 is32 — double -> signed int */
    AXOP_FLDR_Q      = 0x80, /* u8 vt; u8 rn; i32 off — 128-bit SIMD load */
    AXOP_FSTR_Q      = 0x81, /* u8 vt; u8 rn; i32 off — 128-bit SIMD store */
    AXOP_SAVE_SCRATCH = 0x82,
    AXOP_RESTORE_SCRATCH = 0x83,
    /* AdvSIMD 向量算术（2D / 4S） */
    AXOP_VADD_2D     = 0x91, /* u8 vd; u8 vn; u8 vm */
    AXOP_VMUL_2D     = 0x92,
    AXOP_VFMLA_2D    = 0x93, /* vd += vn * vm (2D) */
    AXOP_VADD_4S     = 0x94,
    AXOP_VMUL_4S     = 0x95,
    AXOP_VDUP_2D     = 0x96, /* u8 vd; u8 vn — vn.d[0] -> both lanes */
    AXOP_UMOV_D      = 0x97, /* u8 xd; u8 vn; u8 idx */
    AXOP_INS_D       = 0x98, /* u8 vd; u8 vd_idx; u8 vn; u8 vn_idx */
    AXOP_VFMLA_4S    = 0xA3, /* vd += vn * vm (4S) */
#endif
    AXOP_MRS_TPIDR   = 0xA4, /* u8 rd — MRS rd, TPIDR_EL0 (TLS base) */
    AXOP_FSQRT_D     = 0xA5, /* u8 vd; u8 vn — FSQRT Dd, Dn (AXVM_FLOAT_VM) */
    AXOP_UDIV_REG    = 0xA6, /* u8 rd; u8 rn; u8 rm — unsigned divide */
    AXOP_SDIV_REG    = 0xA7, /* u8 rd; u8 rn; u8 rm — signed divide */
    /* CCMP/CCMN: flags bit0=is32 bit1=imm bit2=ccmn; nzcv_arm = ARM PSTATE nibble (N|Z|C|V) */
    AXOP_CCMP        = 0xA8, /* u8 rn; u8 rm_or_imm; u8 cond; u8 nzcv_arm; u8 flags */
} axvm_opcode_t;

typedef enum axvm_cond {
    AXCOND_EQ = 0, AXCOND_NE, AXCOND_CS, AXCOND_CC,
    AXCOND_MI, AXCOND_PL, AXCOND_VS, AXCOND_VC,
    AXCOND_HI, AXCOND_LS, AXCOND_GE, AXCOND_LT,
    AXCOND_GT, AXCOND_LE, AXCOND_AL,
} axvm_cond_t;

uint32_t axvm_bc_checksum(const uint8_t *blob, size_t len);
int      axvm_bc_validate(const uint8_t *blob, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_BYTECODE_H */
