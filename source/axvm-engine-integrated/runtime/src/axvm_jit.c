#include "axvm_jit.h"
#include "axvm_jit_emit.h"
#include "axvm_bytecode.h"
#include "axvm_reg.h"
#include "axvm_lazy.h"

#if defined(AXVM_JIT_HARDEN) && AXVM_JIT_HARDEN && defined(AXVM_DYNAMIC_SEED) && \
    AXVM_DYNAMIC_SEED
#include "axvm_dynseed.h"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#if defined(AXVM_JIT_CACHE) && AXVM_JIT_CACHE

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/mman.h>
#include <unistd.h>
#endif

/* 仅 arm64 主机可执行动态生成的 A64 桩；其它主机降级为纯解释器。 */
#if defined(__aarch64__)
#define AXVM_JIT_ARCH_OK 1
#else
#define AXVM_JIT_ARCH_OK 0
#endif

#define AXVM_JIT_TABLE        256u    /* 热度/桩缓存哈希表槽位 */
#define AXVM_JIT_HOT_THRESH   8u      /* 命中该次数后触发编译 */
#define AXVM_JIT_REGION       (128u * 1024u)
#define AXVM_JIT_MAX_STUB_W   512u    /* 单桩最大指令数(word) */
#define AXVM_JIT_VERIFY_MASK  1023u   /* 每 1024 次执行抽样校验一次完整性 */
#if defined(AXVM_JIT_HARDEN) && AXVM_JIT_HARDEN
#define AXVM_JIT_VERIFY_ACTIVE  127u    /* 硬化模式更频繁校验 */
#else
#define AXVM_JIT_VERIFY_ACTIVE  AXVM_JIT_VERIFY_MASK
#endif
#define AXVM_JIT_READ_MAX     128u    /* 单次编译读取字节窗口 */
#define AXVM_JIT_MAX_OPS      64u     /* 单桩最大 VM 指令数 */
#define AXVM_JIT_MAP_BASE     9u      /* VM 寄存器缓存真实寄存器起点 x9 */
#define AXVM_JIT_MAP_COUNT    7u      /* x9..x15 共 7 个 */
#define AXVM_JIT_TMP0         16u     /* x16 临时 */

enum { JIT_COLD = 0, JIT_COMPILED = 1, JIT_FAILED = 2 };

typedef struct {
    uint32_t key_pc;   /* rel_pc + 1；0 表示空槽 */
    uint32_t heat;
    uint8_t  state;
    uint32_t pc_end;   /* 编译区结束 rel_pc */
    uint32_t code_off; /* 桩在 region 内偏移 */
    uint32_t code_len; /* 桩字节数 */
    uint64_t hash;     /* 桩机器码完整性哈希 */
    uint32_t runs;     /* 已执行次数(用于抽样完整性校验) */
} jit_entry_t;

typedef struct axvm_jit_state {
    jit_entry_t tab[AXVM_JIT_TABLE];
    uint8_t    *region;
    size_t      region_sz;
    size_t      region_used;
    int         region_mode; /* 0=RW 1=RX 2=PROT_NONE sealed */
    uint32_t    compiled;
    uint32_t    hits;
} axvm_jit_state_t;

typedef uint64_t (*axvm_jit_fn)(void *ctx);

/* 运行时软开关：默认开；关闭后 maybe_run 直接落回解释器(已编译桩保留)。 */
static int g_jit_runtime_on = 1;

void axvm_jit_set_runtime(int on)
{
    g_jit_runtime_on = on ? 1 : 0;
}

int axvm_jit_runtime(void)
{
    return g_jit_runtime_on;
}

/* ---- FNV-1a 64 完整性哈希（轻量，非 SHA 重依赖） ---- */
static uint64_t jit_hash(const uint8_t *p, size_t n)
{
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

#if defined(AXVM_JIT_HARDEN) && AXVM_JIT_HARDEN
static uint64_t jit_hash_ctx(const axvm_ctx_t *ctx, const uint8_t *p, size_t n)
{
    uint64_t h = jit_hash(p, n);
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (ctx && ctx->session_seed_present) {
        h ^= axvm_dynseed_session_mix(ctx);
        h *= 0x100000001B3ULL;
        h ^= (uint64_t)(uintptr_t)ctx;
    }
#endif
    return h;
}

int axvm_jit_harden_enabled(void)
{
    return 1;
}

int axvm_jit_harden_selftest(void)
{
    return axvm_jit_enabled() ? 0 : 1;
}
#else
static uint64_t jit_hash_ctx(const axvm_ctx_t *ctx, const uint8_t *p, size_t n)
{
    (void)ctx;
    return jit_hash(p, n);
}

int axvm_jit_harden_enabled(void)
{
    return 0;
}

int axvm_jit_harden_selftest(void)
{
    return 0;
}
#endif

/* ---- Module G 协同：读取一段明文字节码而不残留明文 ---- */
static void jit_read_code(axvm_ctx_t *ctx, size_t rel, uint8_t *out, size_t n)
{
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    uint8_t *code = ctx->bytecode + hdr->code_off;
#if defined(AXVM_LAZY_DECRYPT) && AXVM_LAZY_DECRYPT
    if (ctx->lazy_sealed) {
        axvm_lazy_reencrypt_active(ctx); /* 活动块回写密文，窗口清空 */
        uint32_t b0 = (uint32_t)(rel / AXVM_LAZY_BLOCK);
        uint32_t b1 = (uint32_t)((rel + n - 1u) / AXVM_LAZY_BLOCK);
        for (uint32_t b = b0; b <= b1; ++b) {
            axvm_lazy_xor_block(ctx, b); /* 解密 */
        }
        memcpy(out, code + rel, n);
        for (uint32_t b = b0; b <= b1; ++b) {
            axvm_lazy_xor_block(ctx, b); /* 立即回密文 */
        }
        return;
    }
#endif
    memcpy(out, code + rel, n);
}

/* ---- 码页 W^X / 封存切换 ---- */
static int region_set_mode(axvm_jit_state_t *st, int mode)
{
#if AXVM_JIT_ARCH_OK && (defined(__linux__) || defined(__ANDROID__))
    if (!st->region) {
        return -1;
    }
    if (st->region_mode == mode) {
        return 0;
    }
    int prot;
    switch (mode) {
    case 2:
        prot = PROT_NONE;
        break;
    case 1:
        prot = PROT_READ | PROT_EXEC;
        break;
    default:
        prot = PROT_READ | PROT_WRITE;
        mode = 0;
        break;
    }
    if (mprotect(st->region, st->region_sz, prot) != 0) {
        return -1;
    }
    st->region_mode = mode;
    return 0;
#else
    (void)st;
    (void)mode;
    return -1;
#endif
}

static int region_set_rx(axvm_jit_state_t *st, int rx)
{
    return region_set_mode(st, rx ? 1 : 0);
}

#if defined(AXVM_JIT_HARDEN) && AXVM_JIT_HARDEN
static void region_seal(axvm_jit_state_t *st)
{
    (void)region_set_mode(st, 2);
}
#endif

/* ---- 哈希表查找/建槽 ---- */
static jit_entry_t *jit_find(axvm_jit_state_t *st, uint32_t rel_pc, int create)
{
    uint32_t key = rel_pc + 1u;
    uint32_t h = (rel_pc * 2654435761u) & (AXVM_JIT_TABLE - 1u);
    for (uint32_t i = 0; i < AXVM_JIT_TABLE; ++i) {
        uint32_t idx = (h + i) & (AXVM_JIT_TABLE - 1u);
        jit_entry_t *e = &st->tab[idx];
        if (e->key_pc == key) {
            return e;
        }
        if (e->key_pc == 0) {
            if (!create) {
                return NULL;
            }
            memset(e, 0, sizeof(*e));
            e->key_pc = key;
            e->state = JIT_COLD;
            return e;
        }
    }
    return NULL; /* 表满 */
}

/* ---- VM 寄存器 -> 真实寄存器分配 ---- */
typedef struct {
    int8_t  map[32];   /* -1 未分配，否则真实寄存器号 */
    uint8_t dirty[32];
    uint32_t nmapped;
    int     overflow;
} jit_alloc_t;

static void alloc_init(jit_alloc_t *a)
{
    for (int i = 0; i < 32; ++i) {
        a->map[i] = -1;
        a->dirty[i] = 0;
    }
    a->nmapped = 0;
    a->overflow = 0;
}

/* 读源寄存器真实号：XZR 直接用 31，否则按需分配缓存寄存器 */
static uint32_t alloc_src(jit_alloc_t *a, uint8_t v)
{
    if (v == AXVM_REG_XZR) {
        return A64_XZR;
    }
    if (a->map[v] < 0) {
        if (a->nmapped >= AXVM_JIT_MAP_COUNT) {
            a->overflow = 1;
            return A64_XZR;
        }
        a->map[v] = (int8_t)(AXVM_JIT_MAP_BASE + a->nmapped++);
    }
    return (uint32_t)a->map[v];
}

static uint32_t alloc_dst(jit_alloc_t *a, uint8_t v)
{
    uint32_t r = alloc_src(a, v);
    if (v != AXVM_REG_XZR) {
        a->dirty[v] = 1;
    }
    return r;
}

/* 解码得到的可编译 VM 指令 */
typedef struct {
    uint8_t  vop;
    uint8_t  rd, rn, rm;
    uint8_t  sh;
    uint64_t imm;
} jit_op_t;

/* 单条指令的操作数长度(含 opcode)；不支持返回 0 */
static size_t vop_len(uint8_t op)
{
    switch (op) {
    case AXOP_LDRI64: return 10;
    case AXOP_ADD_IMM:
    case AXOP_SUB_IMM: return 7;
    case AXOP_ADD_REG:
    case AXOP_SUB_REG:
    case AXOP_AND_REG:
    case AXOP_ORR_REG:
    case AXOP_EOR_REG:
    case AXOP_MUL_REG:
    case AXOP_LSL_IMM:
    case AXOP_LSR_IMM: return 4;
    case AXOP_CMP_REG: return 3;
    case AXOP_MOV_REG:
    case AXOP_MVN_REG: return 3;
    default: return 0;
    }
}

/*
 * 解码窗口内的直线整型序列并做寄存器分配。
 * 返回编译到的指令数(nops)，*pc_end_rel 为结束偏移；遇控制流/访存/不支持/非法寄存器即停。
 */
static uint32_t jit_decode(const uint8_t *buf, size_t n, size_t base_rel, size_t code_size,
                           jit_op_t *ops, uint32_t max_ops, jit_alloc_t *a,
                           uint32_t *pc_end_rel, int *has_cmp)
{
    uint32_t nops = 0;
    size_t c = 0;
    *has_cmp = 0;
    while (nops < max_ops) {
        size_t rel = base_rel + c;
        if (rel >= code_size) {
            break;
        }
        uint8_t op = buf[c];
        size_t len = vop_len(op);
        if (len == 0 || c + len > n || rel + len > code_size) {
            break; /* 不支持或跨窗口/越界 -> 交回解释器 */
        }
        jit_op_t o;
        memset(&o, 0, sizeof(o));
        o.vop = op;
        int ok = 1;
        switch (op) {
        case AXOP_LDRI64: {
            o.rd = buf[c + 1];
            memcpy(&o.imm, buf + c + 2, 8);
            ok = axvm_reg_dst_ok(o.rd);
            break;
        }
        case AXOP_ADD_IMM:
        case AXOP_SUB_IMM: {
            o.rd = buf[c + 1];
            o.rn = buf[c + 2];
            int32_t imm32 = 0;
            memcpy(&imm32, buf + c + 3, 4);
            o.imm = (uint64_t)(int64_t)imm32;
            ok = axvm_reg_dst_ok(o.rd) && axvm_reg_src_ok(o.rn);
            break;
        }
        case AXOP_ADD_REG:
        case AXOP_SUB_REG:
        case AXOP_AND_REG:
        case AXOP_ORR_REG:
        case AXOP_EOR_REG:
        case AXOP_MUL_REG: {
            o.rd = buf[c + 1];
            o.rn = buf[c + 2];
            o.rm = buf[c + 3];
            ok = axvm_reg_dst_ok(o.rd) && axvm_reg_src_ok(o.rn) && axvm_reg_src_ok(o.rm);
            break;
        }
        case AXOP_LSL_IMM:
        case AXOP_LSR_IMM: {
            o.rd = buf[c + 1];
            o.rn = buf[c + 2];
            o.sh = buf[c + 3];
            ok = axvm_reg_dst_ok(o.rd) && axvm_reg_src_ok(o.rn) && o.sh <= 63;
            break;
        }
        case AXOP_CMP_REG: {
            o.rn = buf[c + 1];
            o.rm = buf[c + 2];
            ok = axvm_reg_src_ok(o.rn) && axvm_reg_src_ok(o.rm);
            break;
        }
        case AXOP_MOV_REG:
        case AXOP_MVN_REG: {
            o.rd = buf[c + 1];
            o.rm = buf[c + 2];
            ok = axvm_reg_dst_ok(o.rd) && axvm_reg_src_ok(o.rm);
            break;
        }
        default:
            ok = 0;
            break;
        }
        if (!ok) {
            break; /* 非法编码 -> 交回解释器以复现原语义(含错误码) */
        }

        /* 预分配寄存器；溢出则在本条前停止 */
        jit_alloc_t save = *a;
        switch (op) {
        case AXOP_LDRI64:
            alloc_dst(a, o.rd);
            break;
        case AXOP_ADD_IMM:
        case AXOP_SUB_IMM:
            alloc_src(a, o.rn);
            alloc_dst(a, o.rd);
            break;
        case AXOP_ADD_REG:
        case AXOP_SUB_REG:
        case AXOP_AND_REG:
        case AXOP_ORR_REG:
        case AXOP_EOR_REG:
        case AXOP_MUL_REG:
            alloc_src(a, o.rn);
            alloc_src(a, o.rm);
            alloc_dst(a, o.rd);
            break;
        case AXOP_LSL_IMM:
        case AXOP_LSR_IMM:
            alloc_src(a, o.rn);
            alloc_dst(a, o.rd);
            break;
        case AXOP_CMP_REG:
            alloc_src(a, o.rn);
            alloc_src(a, o.rm);
            *has_cmp = 1;
            break;
        case AXOP_MOV_REG:
        case AXOP_MVN_REG:
            alloc_src(a, o.rm);
            alloc_dst(a, o.rd);
            break;
        default:
            break;
        }
        if (a->overflow) {
            *a = save; /* 回滚本条分配 */
            break;
        }

        ops[nops++] = o;
        c += len;
    }
    *pc_end_rel = (uint32_t)(base_rel + c);
    return nops;
}

/* 发射单桩机器码到 emitter；返回指令数(word)，溢出返回 0 */
static size_t jit_emit_stub(axvm_ctx_t *ctx, axvm_emit_t *e, const jit_op_t *ops,
                            uint32_t nops,
                            const jit_alloc_t *a, uint32_t pc_end_rel)
{
    const uint32_t OFF_NZCV = (uint32_t)offsetof(axvm_ctx_t, nzcv);
    const uint32_t OFF_PC = (uint32_t)offsetof(axvm_ctx_t, pc);
    const uint32_t OFF_X = (uint32_t)offsetof(axvm_ctx_t, x);

    /* 入口：把用到的 VM 寄存器从 ctx->x[] 载入真实缓存寄存器(x0=ctx 基址) */
    for (uint32_t v = 0; v < 31; ++v) {
        if (a->map[v] >= 0) {
            uint32_t pv = v;
 #if defined(AXVM_REG_PERM) && AXVM_REG_PERM
            pv = axvm_reg_perm_phys(ctx, (uint8_t)v);
 #endif
            axvm_emit_ldr_x(e, (uint32_t)a->map[v], 0, OFF_X + pv * 8u);
        }
    }

    for (uint32_t i = 0; i < nops; ++i) {
        const jit_op_t *o = &ops[i];
        uint32_t rd = (o->rd == AXVM_REG_XZR) ? A64_XZR : (uint32_t)a->map[o->rd];
        uint32_t rn = (o->rn == AXVM_REG_XZR) ? A64_XZR : (uint32_t)a->map[o->rn];
        uint32_t rm = (o->rm == AXVM_REG_XZR) ? A64_XZR : (uint32_t)a->map[o->rm];
        switch (o->vop) {
        case AXOP_LDRI64:
            axvm_emit_mov_imm64(e, rd, o->imm);
            break;
        case AXOP_ADD_IMM:
            axvm_emit_mov_imm64(e, AXVM_JIT_TMP0, o->imm);
            axvm_emit_add_reg(e, rd, rn, AXVM_JIT_TMP0);
            break;
        case AXOP_SUB_IMM:
            axvm_emit_mov_imm64(e, AXVM_JIT_TMP0, o->imm);
            axvm_emit_sub_reg(e, rd, rn, AXVM_JIT_TMP0);
            break;
        case AXOP_ADD_REG:
            axvm_emit_add_reg(e, rd, rn, rm);
            break;
        case AXOP_SUB_REG:
            axvm_emit_sub_reg(e, rd, rn, rm);
            break;
        case AXOP_AND_REG:
            axvm_emit_and_reg(e, rd, rn, rm);
            break;
        case AXOP_ORR_REG:
            axvm_emit_orr_reg(e, rd, rn, rm);
            break;
        case AXOP_EOR_REG:
            axvm_emit_eor_reg(e, rd, rn, rm);
            break;
        case AXOP_MUL_REG:
            axvm_emit_mul_reg(e, rd, rn, rm);
            break;
        case AXOP_MOV_REG:
            axvm_emit_mov_reg(e, rd, rm);
            break;
        case AXOP_MVN_REG:
            axvm_emit_mvn_reg(e, rd, rm);
            break;
        case AXOP_LSL_IMM:
            axvm_emit_lsl_imm(e, rd, rn, o->sh);
            break;
        case AXOP_LSR_IMM:
            axvm_emit_lsr_imm(e, rd, rn, o->sh);
            break;
        case AXOP_CMP_REG:
            /* 复刻解释器 nzcv 布局：bit3=V bit2=N bit1=Z bit0=C（清低 4 位后重建） */
            axvm_emit_ldr_w(e, AXVM_JIT_TMP0, 0, OFF_NZCV);
            axvm_emit_lsr_imm_w(e, AXVM_JIT_TMP0, AXVM_JIT_TMP0, 4);
            axvm_emit_lsl_imm_w(e, AXVM_JIT_TMP0, AXVM_JIT_TMP0, 4);
            axvm_emit_cmp_reg(e, rn, rm);
            axvm_emit_cset(e, 17, A64_VS);
            axvm_emit_orr_reg_w_lsl(e, AXVM_JIT_TMP0, AXVM_JIT_TMP0, 17, 3);
            axvm_emit_cset(e, 17, A64_MI);
            axvm_emit_orr_reg_w_lsl(e, AXVM_JIT_TMP0, AXVM_JIT_TMP0, 17, 2);
            axvm_emit_cset(e, 17, A64_EQ);
            axvm_emit_orr_reg_w_lsl(e, AXVM_JIT_TMP0, AXVM_JIT_TMP0, 17, 1);
            axvm_emit_cset(e, 17, A64_CS);
            axvm_emit_orr_reg_w_lsl(e, AXVM_JIT_TMP0, AXVM_JIT_TMP0, 17, 0);
            axvm_emit_str_w(e, AXVM_JIT_TMP0, 0, OFF_NZCV);
            break;
        default:
            break;
        }
    }

    /* 出口：写回脏寄存器、pc，返回 */
    for (uint32_t v = 0; v < 31; ++v) {
        if (a->map[v] >= 0 && a->dirty[v]) {
            uint32_t pv = v;
 #if defined(AXVM_REG_PERM) && AXVM_REG_PERM
            pv = axvm_reg_perm_phys(ctx, (uint8_t)v);
 #endif
            axvm_emit_str_x(e, (uint32_t)a->map[v], 0, OFF_X + pv * 8u);
        }
    }
    axvm_emit_mov_imm64(e, AXVM_JIT_TMP0, (uint64_t)pc_end_rel);
    axvm_emit_str_x(e, AXVM_JIT_TMP0, 0, OFF_PC);
    axvm_emit_ret(e);

    if (e->oflow) {
        return 0;
    }
    return e->n;
}

int axvm_jit_enabled(void)
{
    return AXVM_JIT_ARCH_OK ? 1 : 0;
}

void axvm_jit_init(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    axvm_jit_state_t *st = (axvm_jit_state_t *)calloc(1, sizeof(axvm_jit_state_t));
    if (!st) {
        ctx->jit = NULL;
        return;
    }
#if AXVM_JIT_ARCH_OK && (defined(__linux__) || defined(__ANDROID__))
    void *r = mmap(NULL, AXVM_JIT_REGION, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (r != MAP_FAILED) {
        st->region = (uint8_t *)r;
        st->region_sz = AXVM_JIT_REGION;
        st->region_mode = 0;
    }
#endif
    ctx->jit = st;
}

void axvm_jit_destroy(axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->jit) {
        return;
    }
    axvm_jit_state_t *st = (axvm_jit_state_t *)ctx->jit;
#if AXVM_JIT_ARCH_OK && (defined(__linux__) || defined(__ANDROID__))
    if (st->region) {
        munmap(st->region, st->region_sz);
    }
#endif
    free(st);
    ctx->jit = NULL;
}

int axvm_jit_compile_block(axvm_ctx_t *ctx, uint32_t rel_pc)
{
    if (!ctx || !ctx->jit || !AXVM_JIT_ARCH_OK) {
        return -1;
    }
    axvm_jit_state_t *st = (axvm_jit_state_t *)ctx->jit;
    if (!st->region) {
        return -1;
    }
    jit_entry_t *e = jit_find(st, rel_pc, 1);
    if (!e) {
        return -1;
    }
    if (e->state == JIT_COMPILED) {
        return 0;
    }
    if (e->state == JIT_FAILED) {
        return -1;
    }

    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    size_t code_size = hdr->code_size;
    if (rel_pc >= code_size) {
        e->state = JIT_FAILED;
        return -1;
    }

    uint8_t win[AXVM_JIT_READ_MAX];
    size_t remain = code_size - rel_pc;
    size_t n = remain < AXVM_JIT_READ_MAX ? remain : AXVM_JIT_READ_MAX;
    jit_read_code(ctx, rel_pc, win, n);

    jit_op_t ops[AXVM_JIT_MAX_OPS];
    jit_alloc_t alloc;
    alloc_init(&alloc);
    uint32_t pc_end = 0;
    int has_cmp = 0;
    uint32_t nops =
        jit_decode(win, n, rel_pc, code_size, ops, AXVM_JIT_MAX_OPS, &alloc, &pc_end, &has_cmp);
    if (nops == 0) {
        e->state = JIT_FAILED; /* 首指令即不可编译，永不重试 */
        return -1;
    }

    /* 剩余码页空间检查 */
    size_t avail = st->region_sz - st->region_used;
    if (avail < AXVM_JIT_MAX_STUB_W * 4u) {
        e->state = JIT_FAILED;
        return -1;
    }

    if (region_set_rx(st, 0) != 0) {
        e->state = JIT_FAILED;
        return -1;
    }

    uint32_t *slot = (uint32_t *)(st->region + st->region_used);
    axvm_emit_t em;
    axvm_emit_init(&em, slot, AXVM_JIT_MAX_STUB_W);
    size_t words = jit_emit_stub(ctx, &em, ops, nops, &alloc, pc_end);
    if (words == 0) {
        e->state = JIT_FAILED;
        return -1;
    }

    size_t bytes = words * 4u;
    e->code_off = (uint32_t)st->region_used;
    e->code_len = (uint32_t)bytes;
    e->pc_end = pc_end;
    e->hash = jit_hash_ctx(ctx, (const uint8_t *)slot, bytes);
    st->region_used += bytes;
    st->compiled++;

    if (region_set_rx(st, 1) != 0) {
        e->state = JIT_FAILED;
        return -1;
    }
#if AXVM_JIT_ARCH_OK
    __builtin___clear_cache((char *)slot, (char *)slot + bytes);
#endif
    e->state = JIT_COMPILED;
    return 0;
}

int axvm_jit_maybe_run(axvm_ctx_t *ctx)
{
#if !AXVM_JIT_ARCH_OK
    (void)ctx;
    return 0;
#else
    if (!ctx || !ctx->jit || !g_jit_runtime_on) {
        return 0;
    }
    axvm_jit_state_t *st = (axvm_jit_state_t *)ctx->jit;
    if (!st->region) {
        return 0;
    }
    uint32_t rel = (uint32_t)ctx->pc;
    jit_entry_t *e = jit_find(st, rel, 1);
    if (!e) {
        return 0;
    }

    if (e->state == JIT_COLD) {
        if (++e->heat < AXVM_JIT_HOT_THRESH) {
            return 0;
        }
        if (axvm_jit_compile_block(ctx, rel) != 0) {
            return 0; /* 已标记 FAILED */
        }
        e = jit_find(st, rel, 0);
        if (!e || e->state != JIT_COMPILED) {
            return 0;
        }
    } else if (e->state != JIT_COMPILED) {
        return 0; /* FAILED */
    }

    if (region_set_rx(st, 1) != 0) {
        e->state = JIT_FAILED;
        return 0;
    }
    const uint8_t *code = st->region + e->code_off;
    /*
     * 完整性校验：抽样式(首次执行 + 每 1024 次)重算桩码页哈希并比对，
     * 检测 RX 码页被 mprotect 改写/patch 的篡改；命中篡改即弃用回落解释器。
     * 抽样避免在百万次热循环里对每次调用做全页哈希从而吞掉 JIT 收益。
     */
    if ((e->runs++ & AXVM_JIT_VERIFY_ACTIVE) == 0) {
        if (jit_hash_ctx(ctx, code, e->code_len) != e->hash) {
            e->state = JIT_FAILED;
            return 0;
        }
    }

    axvm_jit_fn fn = (axvm_jit_fn)(void *)code;
    fn(ctx); /* 同步 x 寄存器 -> 执行直线块 -> 写回 x/nzcv/pc */
#if defined(AXVM_JIT_HARDEN) && AXVM_JIT_HARDEN
    region_seal(st);
#endif
    st->hits++;
    return 1;
#endif
}

uint64_t axvm_jit_region_addr(const axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->jit) {
        return 0;
    }
    return (uint64_t)(uintptr_t)((const axvm_jit_state_t *)ctx->jit)->region;
}

uint32_t axvm_jit_compiled_count(const axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->jit) {
        return 0;
    }
    return ((const axvm_jit_state_t *)ctx->jit)->compiled;
}

uint32_t axvm_jit_hit_count(const axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->jit) {
        return 0;
    }
    return ((const axvm_jit_state_t *)ctx->jit)->hits;
}

#else /* !AXVM_JIT_CACHE — 纯解释器，零开销空桩 */

int axvm_jit_enabled(void)
{
    return 0;
}

void axvm_jit_set_runtime(int on)
{
    (void)on;
}

int axvm_jit_runtime(void)
{
    return 0;
}

void axvm_jit_init(axvm_ctx_t *ctx)
{
    (void)ctx;
}

void axvm_jit_destroy(axvm_ctx_t *ctx)
{
    (void)ctx;
}

int axvm_jit_maybe_run(axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

int axvm_jit_compile_block(axvm_ctx_t *ctx, uint32_t rel_pc)
{
    (void)ctx;
    (void)rel_pc;
    return -1;
}

uint64_t axvm_jit_region_addr(const axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

uint32_t axvm_jit_compiled_count(const axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

uint32_t axvm_jit_hit_count(const axvm_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

int axvm_jit_harden_enabled(void)
{
    return 0;
}

int axvm_jit_harden_selftest(void)
{
    return 0;
}

#endif /* AXVM_JIT_CACHE */
