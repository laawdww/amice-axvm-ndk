#ifndef AXVM_CTX_H
#define AXVM_CTX_H

#include "axvm_types.h"
#include "axvm_bytecode.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct axvm_addr_map_entry {
    uint32_t arm64_off;
    uint32_t vm_off;
} axvm_addr_map_entry_t;

typedef struct axvm_native_slot {
    void    *addr;
    uint32_t flags;
} axvm_native_slot_t;

#define AXVM_NATIVE_MAX 64
#define AXVM_NATIVE_BRIDGE_SIZE 8192u

typedef struct axvm_ctx {
    uint64_t x[AXVM_REG_COUNT];   /* x0-x30; x31=XZR 见 axvm_reg.h */
    uint64_t sp;                  /* VM 栈顶影子（字节地址） */
    uint64_t pc;
    uint32_t nzcv;
    uint32_t pad_nzcv;

    /* BL_NATIVE 物理栈隔离（模块 A） */
    uint64_t host_sp_saved;
    uint64_t native_bridge_sp;

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    /* 模块 F：v0-v31 标量浮点虚拟寄存器（IEEE754 double 语义存储） */
    double v[AXVM_FP_REG_COUNT];
    uint64_t q_hi[AXVM_FP_REG_COUNT];
#endif

    uint8_t *bytecode;
    size_t   bc_size;
    uint32_t code_base;
    uint32_t data_base;

    uint8_t *vm_stack_base;
    uint8_t *vm_stack_top;
    size_t   vm_stack_size;

    uint8_t *mem_pool;
    size_t   mem_pool_size;

    uint8_t *native_bridge_base;
    size_t   native_bridge_size;

    axvm_native_slot_t natives[AXVM_NATIVE_MAX];
    uint16_t           native_count;

    void *user_data;
    int   halted;
    int   ret_pending;
    uint64_t ret_val;

    /* 模块 C：每实例独立滚动栈密钥（置于结构体末尾，不影响 asm 布局） */
    uint64_t  stack_key_lo;
    uint64_t  stack_key_hi;
    uint32_t  stack_roll;
    uint32_t  stack_op_count;
    uint32_t  stack_slot_count;
    uint64_t *stack_slot_meta;   /* 高32=写代数, 低32=写时 stack_roll 快照 */

#if defined(AXVM_LAZY_DECRYPT) && AXVM_LAZY_DECRYPT
    /* 模块 G：单实例独立字节码懒解密密钥（结构体末尾，不影响 asm 布局） */
    uint64_t  lazy_key_lo;
    uint64_t  lazy_key_hi;
    uint32_t  lazy_active[AXVM_LAZY_ACTIVE_MAX]; /* 当前明文块索引窗口 */
    uint32_t  lazy_active_count;
    int       lazy_sealed;       /* 1=代码区静止时为密文 */
#endif

#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    /* 模块 M：每实例 SessionSeed（HMAC-SHA256(MasterSeed, entropy) 派生，结构体末尾） */
    uint8_t   session_seed[32];
    int       session_seed_present;
#endif

#if defined(AXVM_JIT_CACHE) && AXVM_JIT_CACHE
    /* 模块 J：热点 BasicBlock JIT 缓存（不透明状态，堆分配于结构体末尾，不影响 asm 布局） */
    void *jit;
#endif

#if defined(AXVM_OPCODE_PERM) && AXVM_OPCODE_PERM
    /* 模块 M：每实例 opcode 逆置换表（仅当字节码带 OPCODE_PERM flag 且 MasterSeed 为真时激活） */
    uint8_t opcode_inv[256];
    int     opcode_perm_active;
#endif

#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
    /* 模块 U：每实例虚拟寄存器索引置换（仅 x0-x30，x31=XZR 不置换） */
    uint8_t reg_perm[AXVM_REG_COUNT];
    int     reg_perm_active;
#endif

#if defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
    /* 模块 Y：调用链基线（首次 RET 捕获，后续 invoke 比对） */
    uint64_t chain_baseline;
    int      chain_baseline_set;
    uint32_t chain_entry_pc; /* 基线对应的 entry_pc */
    int      chain_bl_seen;  /* 本次 invoke 是否经过 BL_NATIVE */
#endif

    struct axvm_ctx *parent;
    uint8_t  nest_depth;
    uint32_t engine_id;

#if defined(AXVM_MULTI_ISA) && AXVM_MULTI_ISA
    uint8_t  riscc_wire_inv[256];
    uint8_t  riscc_wire_fwd[256];
    int      riscc_active;
#endif

#if defined(AXVM_DISPATCH_PERM) && AXVM_DISPATCH_PERM
    uint8_t  dispatch_fwd[256];
    void    *dispatch_ptr[256];
    int      dispatch_perm_active;
    int      dispatch_ptr_ready;
#endif

#if defined(AXVM_HANDLER_POLY) && AXVM_HANDLER_POLY
    uint64_t handler_ptr_mask;
    uint32_t handler_decoy_salt;
    int      handler_poly_active;
    int      handler_poly_applied;
#endif

#if defined(AXVM_MEM_GUARD) && AXVM_MEM_GUARD
    /* 模块 X：mem_pool 页级 seal 状态（1=PROT_NONE） */
    int      mem_pool_sealed;
#endif

    /* 装载模块的运行时基址（用于 VADDR 指令重定位）。 */
    uint64_t module_load_base;

    /* VMPacker 风格 BR_REG 内部跳转映射（AXVM_BC_FLAG_ADDR_MAP trailer） */
    uint64_t                branch_func_vaddr;
    uint32_t                branch_func_size;
    axvm_addr_map_entry_t  *branch_map;
    uint32_t                branch_map_count;
    uint64_t                scratch_save0;
    uint64_t                scratch_save1;
} axvm_ctx_t;

/* VM 虚拟 CPU 快照 — BL_NATIVE 前后完整保存/恢复 */
typedef struct axvm_vcpu_frame {
    uint64_t x[AXVM_REG_COUNT];
    uint64_t sp;
    uint32_t pc;
    uint32_t nzcv;
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    double v[AXVM_FP_REG_COUNT];
    uint64_t q_hi[AXVM_FP_REG_COUNT];
#endif
} axvm_vcpu_frame_t;

axvm_status_t axvm_ctx_create(axvm_ctx_t **out, const uint8_t *bc, size_t bc_len);
void          axvm_ctx_destroy(axvm_ctx_t *ctx);
void          axvm_ctx_rebind_session_seed(axvm_ctx_t *ctx, const uint8_t session_seed[32]);

axvm_status_t axvm_ctx_reset(axvm_ctx_t *ctx);
axvm_status_t axvm_ctx_bind_args(axvm_ctx_t *ctx, const uint64_t *args, int argc);
#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
axvm_status_t axvm_ctx_bind_fp_args(axvm_ctx_t *ctx, const double *args, int argc);
#endif

void axvm_ctx_snapshot(const axvm_ctx_t *ctx, axvm_vcpu_frame_t *frame);
void axvm_ctx_restore(axvm_ctx_t *ctx, const axvm_vcpu_frame_t *frame);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_CTX_H */
