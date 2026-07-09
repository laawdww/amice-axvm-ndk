#include <stdio.h>

#include <stdint.h>

#include <stdlib.h>

#include <string.h>

#include <time.h>



#include "axvm.h"
#include "axvm_bridge.h"
#include "axvm_stack_crypt.h"

#include "axvm_strcrypt.h"

#include "axvm_opcode_perm.h"

#include "axvm_dispatch_perm.h"
#include "axvm_handler_poly.h"
#include "axvm_lazy_pf.h"
#include "axvm_guard_svc.h"
#include "axvm_watchdog.h"
#include "axvm_jit.h"
#include "axvm_riscc.h"
#include "axvm_crypt.h"
#include "axvm_stext.h"
#include "axvm_got_crypt.h"
#include "axvm_nested.h"
#include "axvm_engine.h"
#include "axvm_mem_guard.h"
#include "axvm_reg.h"

#include "axvm_sample_bc.h"

#include "axvm_bench_bc.h"

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
#include "axvm_sample_fp_bc.h"
#endif



static const char *status_str(axvm_status_t s)

{

    switch (s) {

    case AXVM_OK: return "OK";

    case AXVM_ERR_BAD_MAGIC: return "BAD_MAGIC";

    case AXVM_ERR_OOB_PC: return "OOB_PC";

    case AXVM_ERR_OOB_STACK: return "OOB_STACK";

    case AXVM_ERR_OOB_MEM: return "OOB_MEM";

    case AXVM_ERR_BAD_INSN: return "BAD_INSN";

    case AXVM_ERR_ALIGN: return "ALIGN";

    case AXVM_ERR_NATIVE: return "NATIVE";

    default: return "OTHER";

    }

}



static uint64_t native_add(uint64_t a, uint64_t b)

{

    return a + b;

}

static uint64_t native_sum9(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                            uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                            uint64_t a8)
{
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8;
}

#if defined(__aarch64__)
typedef struct { uint64_t lo, hi; } native_u128_t;

static native_u128_t native_ret_pair(uint64_t x)
{
    native_u128_t r = { x, x + 0x1000ULL };
    return r;
}
#endif

static int run_abi_native_selftest(void)
{
    uint8_t buf[256];
    memcpy(buf, g_axvm_sample_add_bc, AXVM_SAMPLE_ADD_BC_SIZE);
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)buf;
    hdr->checksum = axvm_bc_checksum(buf, AXVM_SAMPLE_ADD_BC_SIZE);

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, buf, AXVM_SAMPLE_ADD_BC_SIZE) != AXVM_OK) {
        return 1;
    }

    for (int i = 0; i < 8; ++i) {
        axvm_reg_write(ctx, (uint8_t)i, (uint64_t)(i + 1));
    }
    ctx->sp -= 16;
    if ((ctx->sp & 0xF) || axvm_vm_stack_store64(ctx, ctx->sp, 9) != AXVM_OK) {
        axvm_ctx_destroy(ctx);
        return 1;
    }

    uint64_t ret = 0;
    if (axvm_bridge_call_native_addr(ctx, (void *)native_sum9, &ret) != AXVM_OK || ret != 45) {
        printf("[abi_stack9] rv=%llu expect=45 FAIL\n", (unsigned long long)ret);
        axvm_ctx_destroy(ctx);
        return 1;
    }
    printf("[abi_stack9] rv=%llu expect=45 PASS\n", (unsigned long long)ret);

#if defined(__aarch64__)
    if (axvm_ctx_reset(ctx) != AXVM_OK) {
        axvm_ctx_destroy(ctx);
        return 1;
    }
    axvm_reg_write(ctx, 0, 7);
    ret = 0;
    if (axvm_bridge_call_native_addr(ctx, (void *)native_ret_pair, &ret) != AXVM_OK) {
        axvm_ctx_destroy(ctx);
        return 1;
    }
    uint64_t hi = axvm_reg_read(ctx, 1);
    if (ret != 7 || hi != 7 + 0x1000ULL) {
        printf("[abi_x0x1] lo=%llu hi=%llu FAIL\n",
               (unsigned long long)ret, (unsigned long long)hi);
        axvm_ctx_destroy(ctx);
        return 1;
    }
    printf("[abi_x0x1] lo=%llu hi=%llu PASS\n",
           (unsigned long long)ret, (unsigned long long)hi);
#endif

    axvm_ctx_destroy(ctx);
    return 0;
}



static int run_bc(const char *name, const uint8_t *tmpl, size_t sz,

                  const uint64_t *args, int argc, uint64_t expect)

{

    uint8_t *bc = (uint8_t *)malloc(sz);

    if (!bc) {

        return -1;

    }

    memcpy(bc, tmpl, sz);

    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;

    hdr->checksum = axvm_bc_checksum(bc, sz);



    axvm_ctx_t *ctx = NULL;

    axvm_status_t st = axvm_ctx_create(&ctx, bc, sz);

    if (st != AXVM_OK) {

        fprintf(stderr, "[%s] ctx_create %s\n", name, status_str(st));

        free(bc);

        return 1;

    }



    if (strstr(name, "bl_native") != NULL) {

        axvm_bridge_register_native(ctx, (void *)native_add);

    }



    axvm_bridge_enter(ctx);

    if (args && argc > 0) {

        axvm_ctx_bind_args(ctx, args, argc);

    }

    uint64_t rv = axvm_invoke(ctx, 0);

    int pass = (rv == expect);

    printf("[%s] rv=%llu expect=%llu %s\n",

           name, (unsigned long long)rv, (unsigned long long)expect,

           pass ? "PASS" : "FAIL");



    axvm_ctx_destroy(ctx);

    free(bc);

    return pass ? 0 : 2;

}



/*
 * NZCV V(有符号溢出) 标志完整性自检（不依赖 axpack）。
 * 手工构造字节码：
 *   x0 = INT64_MIN; x1 = 1; x2 = 111; x3 = 222;
 *   CMP x0, x1  (INT64_MIN - 1 溢出 -> res 符号位=0 但真实为负 => N=0,V=1)
 *   CSEL x0 = (LT) ? x2 : x3   (LT = N!=V)
 *   RET
 * 正确实现 V 标志时 LT 成立 -> rv=111；旧实现(V 恒 0)会得 222。
 */
static int run_cmp_vflag_selftest(void)
{
    uint8_t code[64];
    size_t n = 0;
    /* LDRI64 rd, imm64 */
    #define EMIT_LDRI64(rd, imm)                                   \
        do {                                                       \
            code[n++] = 0x10; code[n++] = (uint8_t)(rd);           \
            uint64_t _v = (uint64_t)(imm);                         \
            for (int _i = 0; _i < 8; ++_i) {                       \
                code[n++] = (uint8_t)(_v >> (_i * 8));             \
            }                                                      \
        } while (0)
    EMIT_LDRI64(0, 0x8000000000000000ULL); /* INT64_MIN */
    EMIT_LDRI64(1, 1ULL);
    EMIT_LDRI64(2, 111ULL);
    EMIT_LDRI64(3, 222ULL);
    code[n++] = 0x1A; code[n++] = 0; code[n++] = 1;         /* CMP x0,x1 */
    code[n++] = 0x1C; code[n++] = 0; code[n++] = 2;         /* CSEL rd=x0 */
    code[n++] = 3; code[n++] = 11;                          /* rm=x3, cond=LT */
    code[n++] = 0x50;                                       /* RET */
    #undef EMIT_LDRI64

    size_t total = 40 + n;
    uint8_t *bc = (uint8_t *)calloc(1, total);
    if (!bc) {
        return -1;
    }
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->magic[0] = 'A'; hdr->magic[1] = 'X'; hdr->magic[2] = 'V'; hdr->magic[3] = '1';
    hdr->version = 0x00010000u;
    hdr->flags = 0;
    hdr->code_off = 40;
    hdr->code_size = (uint32_t)n;
    hdr->data_off = (uint32_t)total;
    hdr->data_size = 0;
    hdr->entry_pc = 0;
    memcpy(bc + 40, code, n);
    hdr->checksum = axvm_bc_checksum(bc, total);

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, total) != AXVM_OK) {
        printf("[cmp_vflag] ctx_create FAIL\n");
        free(bc);
        return 1;
    }
    axvm_bridge_enter(ctx);
    uint64_t rv = axvm_invoke(ctx, 0);
    axvm_ctx_destroy(ctx);
    free(bc);

    int pass = (rv == 111);
    printf("[cmp_vflag] signed_overflow LT rv=%llu expect=111 %s\n",
           (unsigned long long)rv, pass ? "PASS" : "FAIL");
    return pass ? 0 : 2;
}

/*
 * 模块 Y：VM 调用链哈希完整性自检（不依赖 axpack）。
 * 用带 BL_NATIVE 的样例字节码驱动 observe_bl_native / observe_ret 观测点：
 *   A: 固定种子重置链哈希后执行 -> 摘要 dA
 *   B: 相同输入再执行一次        -> 摘要 dB   （应 dA==dB，确定性）
 *   C: 重置后注入一次伪造调用再执行 -> 摘要 dC （应 dC!=dA，链被篡改可检出）
 * 三条均要求 rv==42。guard 关闭时该机制为空操作，直接判 PASS。
 */
static uint64_t chain_run_once(const uint8_t *tmpl, size_t sz, uint64_t seed,
                               int inject_fake, uint64_t *rv_out)
{
    uint8_t *bc = (uint8_t *)malloc(sz);
    if (!bc) {
        return 0;
    }
    memcpy(bc, tmpl, sz);
    ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sz);

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sz) != AXVM_OK) {
        free(bc);
        return 0;
    }
    axvm_bridge_register_native(ctx, (void *)native_add);
    axvm_guard_ensure_init();
    axvm_bridge_enter(ctx);
    uint64_t args[2] = { 41, 1 };
    axvm_ctx_bind_args(ctx, args, 2);

    axvm_guard_state_t *g = axvm_guard_global();
    axvm_guard_chain_reset(g, seed);
    if (inject_fake) {
        /* 模拟被注入的额外调用：链上多出一个事件 */
        axvm_guard_observe_bl_native(g, ctx, 0x1234, 0xDEADBEEFULL);
    }
    ctx->pc = 0;
    axvm_run(ctx);
    uint64_t rv = ctx->ret_val;
    uint64_t digest = axvm_guard_chain_digest(g);
    axvm_ctx_destroy(ctx);
    free(bc);
    if (rv_out) {
        *rv_out = rv;
    }
    return digest;
}

static int run_chain_hash_selftest(void)
{
    if (!axvm_guard_enabled()) {
        printf("[chain_hash] guard disabled -> skip PASS\n");
        return 0;
    }
    const uint64_t seed = 0x0BADF00DCAFEBABEULL;
    uint64_t rvA = 0, rvB = 0, rvC = 0;
    uint64_t dA = chain_run_once(g_axvm_sample_bl_native_bc, AXVM_SAMPLE_BL_NATIVE_BC_SIZE,
                                 seed, 0, &rvA);
    uint64_t dB = chain_run_once(g_axvm_sample_bl_native_bc, AXVM_SAMPLE_BL_NATIVE_BC_SIZE,
                                 seed, 0, &rvB);
    uint64_t dC = chain_run_once(g_axvm_sample_bl_native_bc, AXVM_SAMPLE_BL_NATIVE_BC_SIZE,
                                 seed, 1, &rvC);

    int deterministic = (dA == dB && dA != 0);
    int sensitive = (dC != dA);
    int func_ok = (rvA == 42 && rvB == 42 && rvC == 42);
    int pass = deterministic && sensitive && func_ok;
    printf("[chain_hash] dA=0x%llx dB=0x%llx dC=0x%llx rv=%llu det=%d sens=%d %s\n",
           (unsigned long long)dA, (unsigned long long)dB, (unsigned long long)dC,
           (unsigned long long)rvA, deterministic, sensitive, pass ? "PASS" : "FAIL");
    return pass ? 0 : 2;
}



static int run_stack_dump_probe(void)

{

    const uint64_t magic = 0xCAFEBABEULL;

    uint8_t *bc = (uint8_t *)malloc(AXVM_SAMPLE_MEM_BC_SIZE);

    if (!bc) {

        return -1;

    }

    memcpy(bc, g_axvm_sample_mem_bc, AXVM_SAMPLE_MEM_BC_SIZE);

    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;

    hdr->checksum = axvm_bc_checksum(bc, AXVM_SAMPLE_MEM_BC_SIZE);



    axvm_ctx_t *ctx = NULL;

    if (axvm_ctx_create(&ctx, bc, AXVM_SAMPLE_MEM_BC_SIZE) != AXVM_OK) {

        free(bc);

        return 1;

    }



    axvm_bridge_enter(ctx);

    uint64_t rv = axvm_invoke(ctx, 0);

    int func_ok = (rv == magic);

    int leak = axvm_stack_crypt_probe_plaintext(ctx, magic);

    int pass = func_ok;

    if (axvm_stack_crypt_enabled()) {

        pass = pass && (leak == 0);

    }



    printf("[stack_dump_probe] crypt=%d rv=0x%llx leak=%d key_mix=0x%llx %s\n",

           axvm_stack_crypt_enabled(),

           (unsigned long long)rv,

           leak,

           (unsigned long long)axvm_stack_crypt_key_mix(ctx),

           pass ? "PASS" : "FAIL");



    axvm_ctx_destroy(ctx);

    free(bc);

    return pass ? 0 : 2;

}



/*
 * 模块 G：字节码明文泄露 dump 对比。
 * 创建 ctx 后代码区应处于静止密文；与原始明文模板逐字节比较：
 *   AXVM_LAZY_DECRYPT=ON  -> 常驻内存为密文, leak=0
 *   AXVM_LAZY_DECRYPT=OFF -> 常驻内存为明文, leak=1
 * 无论开关，执行结果必须正确(rv==42)以证明懒解密不破坏语义。
 */
static int run_lazy_dump_probe(void)
{
    const uint8_t *tmpl = g_axvm_sample_add_bc;
    size_t sz = AXVM_SAMPLE_ADD_BC_SIZE;
    uint8_t *bc = (uint8_t *)malloc(sz);
    if (!bc) {
        return -1;
    }
    memcpy(bc, tmpl, sz);
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, sz);

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sz) != AXVM_OK) {
        free(bc);
        return 1;
    }

    size_t coff = ((axvm_bc_header_t *)bc)->code_off;
    size_t csz = ((axvm_bc_header_t *)bc)->code_size;
    const uint8_t *resident = ctx->bytecode + coff; /* ctx 内静止字节码 */
    const uint8_t *plain = tmpl + coff;

    int leak = axvm_lazy_probe_plaintext(ctx, plain, csz);

    printf("[lazy_dump] enabled=%d code_size=%zu key_mix=0x%llx\n",
           axvm_lazy_enabled(), csz,
           (unsigned long long)axvm_lazy_key_mix(ctx));
    printf("[lazy_dump] plaintext:");
    for (size_t i = 0; i < csz; ++i) {
        printf(" %02x", plain[i]);
    }
    printf("\n[lazy_dump] resident :");
    for (size_t i = 0; i < csz; ++i) {
        printf(" %02x", resident[i]);
    }
    printf("\n");

    axvm_bridge_enter(ctx);
    uint64_t args[2] = {41, 1};
    axvm_ctx_bind_args(ctx, args, 2);
    uint64_t rv = axvm_invoke(ctx, 0);

    int pass = (rv == 42);
    if (axvm_lazy_enabled()) {
        pass = pass && (leak == 0);
    }
    printf("[lazy_dump] rv=%llu leak=%d %s\n",
           (unsigned long long)rv, leak, pass ? "PASS" : "FAIL");

    axvm_ctx_destroy(ctx);
    free(bc);
    return pass ? 0 : 2;
}



/*
 * 模块 H：无调试器环境下 guard 自检。
 * enabled=1 且 trip_flags=0 且 rv=42 => PASS。
 * gdb/Frida 附着时 dispatch 探针将 trip 并 halt，rv!=42 或 flags!=0。
 */
static int run_guard_selftest(void)
{
    uint8_t *bc = (uint8_t *)malloc(AXVM_SAMPLE_ADD_BC_SIZE);
    if (!bc) {
        return -1;
    }
    memcpy(bc, g_axvm_sample_add_bc, AXVM_SAMPLE_ADD_BC_SIZE);
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, AXVM_SAMPLE_ADD_BC_SIZE);

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, AXVM_SAMPLE_ADD_BC_SIZE) != AXVM_OK) {
        free(bc);
        return 1;
    }

    axvm_guard_ensure_init();
    axvm_bridge_enter(ctx);
    uint64_t args[2] = {41, 1};
    axvm_ctx_bind_args(ctx, args, 2);
    uint64_t rv = axvm_invoke(ctx, 0);
    uint32_t flags = axvm_guard_last_flags(axvm_guard_global());

    int pass = (rv == 42);
    if (axvm_guard_enabled()) {
        pass = pass && (flags == 0);
    }

    printf("[guard_selftest] enabled=%d rv=%llu flags=0x%x %s\n",
           axvm_guard_enabled(),
           (unsigned long long)rv,
           (unsigned)flags,
           pass ? "PASS" : "FAIL");

    axvm_ctx_destroy(ctx);
    free(bc);
    return pass ? 0 : 2;
}



/*
 * 模块 I：分段完整性自检（无 pack 的 PIE 环境）。
 *  1) SHA256 已知答案向量校验实现正确性；
 *  2) arm_test 绑定一段 live 字节码缓冲，干净运行 -> rv=42, 无 trip；
 *  3) arm 后篡改该缓冲，再运行 -> 初始化/ dispatch 探针命中 -> halt, trip flags 置位。
 */
static int run_integrity_selftest(void)
{
    /* SHA256("abc") 已知答案 */
    static const uint8_t kat[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t dig[32];
    axvm_sha256("abc", 3, dig);
    int sha_ok = (memcmp(dig, kat, 32) == 0);

    size_t sz = AXVM_SAMPLE_ADD_BC_SIZE;

    /* --- 干净运行 --- */
    uint8_t *bc = (uint8_t *)malloc(sz);
    if (!bc) {
        return -1;
    }
    memcpy(bc, g_axvm_sample_add_bc, sz);
    ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sz);

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sz) != AXVM_OK) {
        free(bc);
        return 1;
    }
    axvm_integrity_reset();
    axvm_integrity_arm_test(bc, sz);
    axvm_bridge_enter(ctx);
    uint64_t a0[2] = {41, 1};
    axvm_ctx_bind_args(ctx, a0, 2);
    uint64_t rv_clean = axvm_invoke(ctx, 0);
    uint32_t flags_clean = axvm_integrity_trip_flags();
    axvm_ctx_destroy(ctx);
    free(bc);

    /* --- 篡改运行 --- */
    uint8_t *bc2 = (uint8_t *)malloc(sz);
    if (!bc2) {
        return -1;
    }
    memcpy(bc2, g_axvm_sample_add_bc, sz);
    ((axvm_bc_header_t *)bc2)->checksum = axvm_bc_checksum(bc2, sz);

    axvm_ctx_t *ctx2 = NULL;
    if (axvm_ctx_create(&ctx2, bc2, sz) != AXVM_OK) {
        free(bc2);
        return 1;
    }
    axvm_integrity_reset();
    axvm_integrity_arm_test(bc2, sz);      /* 期望哈希 = 原始 */
    bc2[sz - 1] ^= 0xFF;                    /* arm 后篡改被监控段 */
    axvm_bridge_enter(ctx2);                /* probe_init 命中 -> trip+halt */
    axvm_ctx_bind_args(ctx2, a0, 2);
    uint64_t rv_tamper = axvm_invoke(ctx2, 0);
    uint32_t flags_tamper = axvm_integrity_trip_flags();
    axvm_ctx_destroy(ctx2);
    free(bc2);
    axvm_integrity_reset();

    int pass;
    if (axvm_integrity_enabled()) {
        pass = sha_ok && (rv_clean == 42) && (flags_clean == 0) &&
               (flags_tamper != 0) && (rv_tamper != 42);
    } else {
        pass = (rv_clean == 42); /* 关闭时 arm_test 空转 */
    }

    printf("[integ_selftest] enabled=%d sha_kat=%d rv_clean=%llu flags_clean=0x%x "
           "rv_tamper=%llu flags_tamper=0x%x %s\n",
           axvm_integrity_enabled(), sha_ok,
           (unsigned long long)rv_clean, (unsigned)flags_clean,
           (unsigned long long)rv_tamper, (unsigned)flags_tamper,
           pass ? "PASS" : "FAIL");

    return pass ? 0 : 2;
}



#if defined(AXVM_OPCODE_PERM) && AXVM_OPCODE_PERM
/* 测试用：opcode 之后操作数字节数（镜像 axpack opOperandLen / 解释器解码宽度）。 */
static int tst_op_operand_len(uint8_t op, int *ok)
{
    *ok = 1;
    switch (op) {
    case 0x00: case 0x01: case 0x50: return 0;
    case 0x10: return 9;
    case 0x11: case 0x12: return 6;
    case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
    case 0x18: case 0x19: case 0x1B: return 3;
    case 0x1A: return 2;
    case 0x1C: return 4;
    case 0x1D: return 4;
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x24: case 0x25: case 0x26: case 0x27: return 6;
    case 0x30: case 0x31: return 2;
    case 0x40: return 4;
    case 0x41: return 5;
    case 0x42: return 2;
    case 0x60: case 0x61: return 2;
    case 0x70: case 0x71: case 0x72: case 0x73: return 6;
    case 0x74: case 0x75: case 0x76: case 0x77: return 3;
    case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: return 2;
    }
    *ok = 0;
    return 0;
}

/*
 * 模块 M：opcode 置换端到端自检（不依赖 axpack）。
 *   1) 表自检 inv∘fwd==恒等；
 *   2) 登记已知“真实”MasterSeed，按 fwd 正向置换样例字节码的 opcode 并置 flag；
 *   3) 创建 ctx 应激活逆置换，执行结果仍须正确(42)。
 */
static int run_opcode_perm_selftest(void)
{
    if (axvm_opcode_perm_selftest() != 0) {
        printf("[opcode_perm] table selftest FAIL\n");
        return 1;
    }

    uint8_t master_plain[32];
    for (int i = 0; i < 32; ++i) {
        master_plain[i] = (uint8_t)(i * 7 + 3);
    }
    uint8_t nonce[16];
    for (int i = 0; i < 16; ++i) {
        nonce[i] = (uint8_t)(i * 11 + 1);
    }
    uint8_t master_enc[32];
    memcpy(master_enc, master_plain, 32);
    axvm_dynseed_master_cipher(master_enc, 32, nonce);
    if (!axvm_dynseed_set_master(master_enc, 32, nonce, 16)) {
        printf("[opcode_perm] set_master FAIL\n");
        return 2;
    }

    uint8_t fwd[256], inv[256];
    axvm_opcode_perm_build(master_plain, fwd, inv);

    size_t sz = AXVM_SAMPLE_ADD_BC_SIZE;
    uint8_t *bc = (uint8_t *)malloc(sz);
    if (!bc) {
        return -1;
    }
    memcpy(bc, g_axvm_sample_add_bc, sz);
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;

    uint32_t co = hdr->code_off, csz = hdr->code_size;
    size_t i = co;
    int walk_ok = 1;
    while (i < (size_t)co + csz) {
        int ok = 0;
        int n = tst_op_operand_len(bc[i], &ok);
        if (!ok || i + 1 + (size_t)n > (size_t)co + csz) {
            walk_ok = 0;
            break;
        }
        bc[i] = fwd[bc[i]];
        i += 1 + (size_t)n;
    }
    if (!walk_ok || i != (size_t)co + csz) {
        printf("[opcode_perm] walk mismatch\n");
        free(bc);
        return 3;
    }
    hdr->flags |= AXVM_BC_FLAG_OPCODE_PERM;
    hdr->checksum = axvm_bc_checksum(bc, sz);

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sz) != AXVM_OK) {
        printf("[opcode_perm] ctx_create FAIL\n");
        free(bc);
        return 4;
    }
    int active = ctx->opcode_perm_active;
    axvm_bridge_enter(ctx);
    uint64_t a0[2] = {41, 1};
    axvm_ctx_bind_args(ctx, a0, 2);
    uint64_t rv = axvm_invoke(ctx, 0);
    axvm_ctx_destroy(ctx);
    free(bc);

    int pass = active && (rv == 42);
    printf("[opcode_perm] active=%d rv=%llu expect=42 %s\n",
           active, (unsigned long long)rv, pass ? "PASS" : "FAIL");

    memset(master_plain, 0, sizeof(master_plain));
    return pass ? 0 : 5;
}
#endif

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
static int run_fp_fadd(void)
{
    const uint64_t expect = 0x4010000000000000ULL; /* 4.0 */
    uint8_t *bc = (uint8_t *)malloc(AXVM_SAMPLE_FADD_BC_SIZE);
    if (!bc) {
        return -1;
    }
    memcpy(bc, g_axvm_sample_fadd_bc, AXVM_SAMPLE_FADD_BC_SIZE);
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, AXVM_SAMPLE_FADD_BC_SIZE);

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, AXVM_SAMPLE_FADD_BC_SIZE) != AXVM_OK) {
        free(bc);
        return 1;
    }

    axvm_bridge_enter(ctx);
    double fargs[2] = {2.5, 1.5};
    axvm_ctx_bind_fp_args(ctx, fargs, 2);
    uint64_t rv = axvm_invoke(ctx, 0);
    int pass = (rv == expect);

    printf("[fp_fadd] rv=%a expect=%a %s\n",
           *(double *)&rv, *(double *)&expect, pass ? "PASS" : "FAIL");

    axvm_ctx_destroy(ctx);
    free(bc);
    return pass ? 0 : 2;
}
#endif



/*
 * 模块 M：双层动态种子探测。
 * 创建 2 个 ctx 实例，比较其 SessionSeed 混合值应各不相同；
 * 销毁后重建（模拟重启）应再次得到不同的 SessionSeed。
 * DYNAMIC_SEED=ON  -> 各 mix 互异且非零；OFF -> 不校验互异（回退行为）。
 * 无论开关，执行结果必须正确(42) 以证明动态种子不破坏语义。
 */
static int run_dynseed_dump_probe(void)
{
    uint8_t *bc = (uint8_t *)malloc(AXVM_SAMPLE_ADD_BC_SIZE);
    if (!bc) {
        return -1;
    }
    memcpy(bc, g_axvm_sample_add_bc, AXVM_SAMPLE_ADD_BC_SIZE);
    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;
    hdr->checksum = axvm_bc_checksum(bc, AXVM_SAMPLE_ADD_BC_SIZE);

    axvm_ctx_t *c1 = NULL, *c2 = NULL, *c3 = NULL;
    if (axvm_ctx_create(&c1, bc, AXVM_SAMPLE_ADD_BC_SIZE) != AXVM_OK) {
        free(bc);
        return 1;
    }
    if (axvm_ctx_create(&c2, bc, AXVM_SAMPLE_ADD_BC_SIZE) != AXVM_OK) {
        axvm_ctx_destroy(c1);
        free(bc);
        return 1;
    }

    int en = axvm_dynseed_enabled();
    uint64_t m1 = axvm_dynseed_session_mix(c1);
    uint64_t m2 = axvm_dynseed_session_mix(c2);

    axvm_bridge_enter(c1);
    uint64_t a1[2] = {41, 1};
    axvm_ctx_bind_args(c1, a1, 2);
    uint64_t r1 = axvm_invoke(c1, 0);

    axvm_bridge_enter(c2);
    uint64_t a2[2] = {20, 22};
    axvm_ctx_bind_args(c2, a2, 2);
    uint64_t r2 = axvm_invoke(c2, 0);

    /* 重启模拟：销毁 c1 后重建，新的 entropy 应派生出不同 SessionSeed */
    axvm_ctx_destroy(c1);
    (void)axvm_ctx_create(&c3, bc, AXVM_SAMPLE_ADD_BC_SIZE);
    uint64_t m3 = axvm_dynseed_session_mix(c3);

    int pass = (r1 == 42) && (r2 == 42);
    if (en) {
        pass = pass && (m1 != m2) && (m1 != 0) && (m2 != 0) && (m3 != m2);
    }

    printf("[dynseed_dump] enabled=%d mix1=0x%llx mix2=0x%llx mix3_restart=0x%llx "
           "r1=%llu r2=%llu %s\n",
           en, (unsigned long long)m1, (unsigned long long)m2,
           (unsigned long long)m3, (unsigned long long)r1, (unsigned long long)r2,
           pass ? "PASS" : "FAIL");

    axvm_ctx_destroy(c2);
    axvm_ctx_destroy(c3);
    free(bc);
    return pass ? 0 : 2;
}



static uint64_t now_ns(void)

{

    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;

}



static int run_bench(const char *name, const uint8_t *tmpl, size_t sz,

                     uint64_t expect, int outer_runs)

{

    uint8_t *bc = (uint8_t *)malloc(sz);

    if (!bc) {

        return -1;

    }

    memcpy(bc, tmpl, sz);

    axvm_bc_header_t *hdr = (axvm_bc_header_t *)bc;

    hdr->checksum = axvm_bc_checksum(bc, sz);



    axvm_ctx_t *ctx = NULL;

    if (axvm_ctx_create(&ctx, bc, sz) != AXVM_OK) {

        free(bc);

        return 1;

    }



    axvm_bridge_enter(ctx);

    uint64_t rv = axvm_invoke(ctx, 0);

    if (rv != expect) {

        printf("[%s] correctness FAIL rv=%llu\n", name, (unsigned long long)rv);

        axvm_ctx_destroy(ctx);

        free(bc);

        return 2;

    }



    uint64_t t0 = now_ns();

    for (int i = 0; i < outer_runs; ++i) {

        axvm_bridge_enter(ctx);

        (void)axvm_invoke(ctx, 0);

    }

    uint64_t t1 = now_ns();



    double ms = (double)(t1 - t0) / 1000000.0;

    printf("[%s] dispatch=%s outer=%d total=%.2f ms avg=%.3f ms/invoke expect=%llu PASS\n",

           name,

           axvm_interp_dispatch_is_goto() ? "computed_goto" : "switch",

           outer_runs, ms, ms / (double)outer_runs,

           (unsigned long long)expect);



    axvm_ctx_destroy(ctx);

    free(bc);

    return 0;

}



/*
 * 模块 J：热点 BasicBlock JIT 缓存基准对比。
 * 同一 ctx 内：先预热使热块编译，计时 JIT ON；再运行时软关 JIT 计时 OFF。
 * 打印 ms/invoke 及 OFF/ON 加速比、编译块数/命中数/RX 码页地址(供 gdb)。
 * 语义正确性(rv==100000) 在 ON/OFF 两侧均校验，证明 JIT 为纯旁路优化。
 */
static int run_jit_bench_compare(int outer_runs)
{
    const uint8_t *tmpl = g_axvm_bench_loop_bc;
    size_t sz = AXVM_BENCH_LOOP_BC_SIZE;
    uint8_t *bc = (uint8_t *)malloc(sz);
    if (!bc) {
        return -1;
    }
    memcpy(bc, tmpl, sz);
    ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sz);

    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, sz) != AXVM_OK) {
        free(bc);
        return 1;
    }
    if (outer_runs < 1) {
        outer_runs = 1;
    }

    /* JIT ON：预热(高于热度阈值)使入口/循环热块完成编译 */
    axvm_jit_set_runtime(1);
    uint64_t rv_on = AXVM_BENCH_LOOP_EXPECT + 1;
    for (int i = 0; i < 20; ++i) {
        axvm_bridge_enter(ctx);
        rv_on = axvm_invoke(ctx, 0);
    }

    uint64_t t0 = now_ns();
    for (int i = 0; i < outer_runs; ++i) {
        axvm_bridge_enter(ctx);
        (void)axvm_invoke(ctx, 0);
    }
    uint64_t t1 = now_ns();
    double ms_on = (double)(t1 - t0) / 1000000.0;

    uint32_t compiled = axvm_jit_compiled_count(ctx);
    uint32_t hits = axvm_jit_hit_count(ctx);
    unsigned long long region = (unsigned long long)axvm_jit_region_addr(ctx);

    /* JIT OFF：运行时软关，落回纯解释器路径 */
    axvm_jit_set_runtime(0);
    uint64_t rv_off = AXVM_BENCH_LOOP_EXPECT + 1;
    axvm_bridge_enter(ctx);
    rv_off = axvm_invoke(ctx, 0);
    uint64_t t2 = now_ns();
    for (int i = 0; i < outer_runs; ++i) {
        axvm_bridge_enter(ctx);
        (void)axvm_invoke(ctx, 0);
    }
    uint64_t t3 = now_ns();
    double ms_off = (double)(t3 - t2) / 1000000.0;
    axvm_jit_set_runtime(1);

    int pass = (rv_on == AXVM_BENCH_LOOP_EXPECT) && (rv_off == AXVM_BENCH_LOOP_EXPECT);
    double ratio = (ms_on > 0.0) ? (ms_off / ms_on) : 0.0;

    printf("[jit_bench] jit_enabled=%d compiled_blocks=%u jit_hits=%u region=0x%llx\n",
           axvm_jit_enabled(), compiled, hits, region);
    printf("[jit_bench] JIT_ON  outer=%d total=%.2f ms avg=%.4f ms/invoke rv=%llu\n",
           outer_runs, ms_on, ms_on / (double)outer_runs, (unsigned long long)rv_on);
    printf("[jit_bench] JIT_OFF outer=%d total=%.2f ms avg=%.4f ms/invoke rv=%llu\n",
           outer_runs, ms_off, ms_off / (double)outer_runs, (unsigned long long)rv_off);
    printf("[jit_bench] speedup(OFF/ON)=%.2fx %s\n", ratio, pass ? "PASS" : "FAIL");

    axvm_ctx_destroy(ctx);
    free(bc);
    return pass ? 0 : 2;
}



int main(int argc, char **argv)

{

    int outer = 30;

    int bench_only = 0;



    for (int i = 1; i < argc; ++i) {

        if (strcmp(argv[i], "--bench-only") == 0) {

            bench_only = 1;

        } else if (strncmp(argv[i], "--outer=", 8) == 0) {

            outer = atoi(argv[i] + 8);

            if (outer < 1) {

                outer = 1;

            }

        }

    }



    if (!bench_only) {

        int fails = 0;

        fails += run_bc("add", g_axvm_sample_add_bc, AXVM_SAMPLE_ADD_BC_SIZE,

                        (uint64_t[]){41, 1}, 2, 42);

        fails += run_bc("isa_eor_shift", g_axvm_sample_isa_bc, AXVM_SAMPLE_ISA_BC_SIZE,

                        NULL, 0, 0x7F);

        fails += run_bc("mem_ldur", g_axvm_sample_mem_bc, AXVM_SAMPLE_MEM_BC_SIZE,

                        NULL, 0, 0xCAFEBABEULL);

        fails += run_bc("bl_native", g_axvm_sample_bl_native_bc,

                        AXVM_SAMPLE_BL_NATIVE_BC_SIZE, (uint64_t[]){41, 1}, 2, 42);

        if (run_abi_native_selftest() != 0) {
            printf("module_a_abi_standalone: FAIL\n");
            return 3;
        }
        printf("module_a_abi_standalone: PASS\n");

        printf("module_a_standalone: %s\n", fails == 0 ? "PASS" : "FAIL");

        if (fails != 0) {

            return 3;

        }

        if (run_cmp_vflag_selftest() != 0) {

            printf("cmp_vflag_standalone: FAIL\n");

            return 3;

        }

        printf("cmp_vflag_standalone: PASS\n");

        if (run_chain_hash_selftest() != 0) {
            printf("module_y_standalone: FAIL\n");
            return 3;
        }
        printf("module_y_standalone: PASS\n");



        if (run_stack_dump_probe() != 0) {

            return 5;

        }

        printf("module_c_standalone: PASS\n");

        if (run_lazy_dump_probe() != 0) {
            printf("module_g_standalone: FAIL\n");
            return 7;
        }
        printf("module_g_standalone: PASS\n");

        if (run_guard_selftest() != 0) {
            printf("module_h_standalone: FAIL\n");
            return 8;
        }
        printf("module_h_standalone: PASS\n");

        if (run_dynseed_dump_probe() != 0) {
            printf("module_m_standalone: FAIL\n");
            return 9;
        }
        printf("module_m_standalone: PASS\n");

        if (run_integrity_selftest() != 0) {
            printf("module_i_standalone: FAIL\n");
            return 9;
        }
        printf("module_i_standalone: PASS\n");

        if (axvm_strcrypt_selftest() != 0) {
            printf("module_k_standalone: FAIL\n");
            return 10;
        }
        printf("[strcrypt_selftest] enabled=%d PASS\n", axvm_strcrypt_enabled());
        printf("module_k_standalone: PASS\n");

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
        if (run_fp_fadd() != 0) {
            printf("module_f_standalone: FAIL\n");
            return 6;
        }
        printf("module_f_standalone: PASS\n");
#endif

        if (axvm_crypt_roundtrip_selftest() != 0) {
            printf("module_n_crypt_standalone: FAIL\n");
            return 18;
        }
        printf("module_n_crypt_standalone: PASS\n");

#if defined(AXVM_OPCODE_PERM) && AXVM_OPCODE_PERM
        /* opcode 置换自检置于末尾：会登记固定 MasterSeed，避免污染前序模块 M 用例 */
        if (run_opcode_perm_selftest() != 0) {
            printf("module_m_opcode_perm_standalone: FAIL\n");
            return 12;
        }
        printf("module_m_opcode_perm_standalone: PASS\n");
#endif

#if defined(AXVM_DISPATCH_PERM) && AXVM_DISPATCH_PERM
        if (axvm_dispatch_perm_selftest() != 0) {
            printf("module_n_standalone: FAIL\n");
            return 13;
        }
        printf("module_n_standalone: PASS\n");
#endif

#if defined(AXVM_HANDLER_POLY) && AXVM_HANDLER_POLY
        if (axvm_handler_poly_selftest() != 0) {
            printf("module_n_handler_standalone: FAIL\n");
            return 13;
        }
        printf("module_n_handler_standalone: PASS\n");
#endif

#if defined(AXVM_LAZY_PF) && AXVM_LAZY_PF
        if (axvm_lazy_pf_selftest() != 0) {
            printf("module_g_pf_standalone: FAIL\n");
            return 13;
        }
        printf("module_g_pf_standalone: PASS\n");
#endif

#if defined(AXVM_SVC_ANTIDEBUG) && AXVM_SVC_ANTIDEBUG
        if (axvm_guard_svc_selftest() != 0) {
            printf("module_h_svc_standalone: FAIL\n");
            return 13;
        }
        printf("module_h_svc_standalone: PASS\n");
#endif

#if defined(AXVM_WATCHDOG) && AXVM_WATCHDOG
        if (axvm_watchdog_selftest() != 0) {
            printf("module_watchdog_standalone: FAIL\n");
            return 13;
        }
        printf("module_watchdog_standalone: PASS\n");
#endif

#if defined(AXVM_JIT_HARDEN) && AXVM_JIT_HARDEN
        if (axvm_jit_harden_selftest() != 0) {
            printf("module_j_harden_standalone: FAIL\n");
            return 13;
        }
        printf("module_j_harden_standalone: PASS\n");
#endif

#if defined(AXVM_STEXT) && AXVM_STEXT
        {
            int orc = axvm_stext_roundtrip_selftest();
            if (orc != 0) {
                printf("module_o_standalone: FAIL rc=%d\n", orc);
                return 14;
            }
            printf("module_o_standalone: PASS\n");
        }
#endif

#if defined(AXVM_GOT_CRYPT) && AXVM_GOT_CRYPT
        if (axvm_got_crypt_selftest() != 0) {
            printf("module_p_standalone: FAIL\n");
            return 15;
        }
        printf("module_p_standalone: PASS\n");
#endif

        {
            uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
            memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
            ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
            axvm_ctx_t *qctx = NULL;
            if (axvm_ctx_create(&qctx, bc, sizeof(bc)) != AXVM_OK ||
                axvm_strcrypt_session_selftest(qctx) != 0) {
                axvm_ctx_destroy(qctx);
                printf("module_q_standalone: FAIL\n");
                return 16;
            }
            axvm_ctx_destroy(qctx);
            printf("module_q_standalone: PASS\n");
        }

#if defined(AXVM_NESTED_VM) && AXVM_NESTED_VM
        {
            int rrc = axvm_nested_selftest();
            if (rrc != 0) {
                printf("module_r_standalone: FAIL rc=%d\n", rrc);
                return 17;
            }
            printf("module_r_standalone: PASS\n");
        }
#endif

#if defined(AXVM_MULTI_ISA) && AXVM_MULTI_ISA
        if (axvm_engine_riscc_selftest() != 0) {
            printf("module_t_standalone: FAIL\n");
            return 19;
        }
        printf("module_t_standalone: PASS\n");
#endif

#if defined(AXVM_RISCC_PERM) && AXVM_RISCC_PERM
        if (axvm_riscc_perm_selftest() != 0) {
            printf("module_t_perm_standalone: FAIL\n");
            return 19;
        }
        printf("module_t_perm_standalone: PASS\n");
#endif

        if (axvm_interp_selftest() != 0) {
            printf("module_isa_standalone: FAIL\n");
            return 20;
        }
        printf("module_isa_standalone: PASS\n");

#if defined(AXVM_REG_PERM) && AXVM_REG_PERM
        {
            axvm_ctx_t *ra = NULL;
            uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
            memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
            ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
            int ufail = 0;
            if (axvm_ctx_create(&ra, bc, sizeof(bc)) != AXVM_OK) {
                ufail = 1;
            } else {
                axvm_bridge_enter(ra);
                uint64_t args[2] = { 41, 1 };
                axvm_ctx_bind_args(ra, args, 2);
                uint64_t rv = axvm_invoke(ra, 0);
                if (rv != 42) {
                    ufail = 2;
                }
            }
            axvm_ctx_destroy(ra);
            if (ufail != 0) {
                printf("module_u_standalone: FAIL\n");
                return 20;
            }
            printf("module_u_standalone: PASS\n");
        }
#endif

        {
            uint8_t code[] = {
                AXOP_JUNK, 2, 0xAA, 0x55,
                AXOP_LDRI64, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0,
                AXOP_RET,
            };
            uint8_t blob[128];
            memset(blob, 0, sizeof(blob));
            memcpy(blob, "AXV1", 4);
            uint32_t *u32 = (uint32_t *)blob;
            u32[1] = AXVM_VERSION;
            u32[3] = 40;
            u32[4] = (uint32_t)sizeof(code);
            u32[5] = 40 + (uint32_t)sizeof(code);
            u32[7] = 0;
            memcpy(blob + 40, code, sizeof(code));
            u32[8] = axvm_bc_checksum(blob, 40 + sizeof(code));
            axvm_ctx_t *sctx = NULL;
            if (axvm_ctx_create(&sctx, blob, 40 + sizeof(code)) != AXVM_OK) {
                printf("module_s_standalone: FAIL\n");
                return 23;
            }
            axvm_bridge_enter(sctx);
            uint64_t srv = axvm_invoke(sctx, 0);
            axvm_ctx_destroy(sctx);
            if (srv != 42) {
                printf("module_s_standalone: FAIL\n");
                return 23;
            }
            printf("module_s_standalone: PASS\n");
        }

        {
            uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
            memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
            ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
            axvm_ctx_t *abctx = NULL;
            if (axvm_ctx_create(&abctx, bc, sizeof(bc)) != AXVM_OK ||
                axvm_jni_tunnel_selftest(abctx) != 0) {
                axvm_ctx_destroy(abctx);
                printf("module_ab_standalone: FAIL\n");
                return 24;
            }
            axvm_ctx_destroy(abctx);
            printf("module_ab_standalone: PASS\n");
        }

#if defined(AXVM_MEM_GUARD) && AXVM_MEM_GUARD
        {
            axvm_ctx_t *xctx = NULL;
            uint8_t bc[AXVM_SAMPLE_ADD_BC_SIZE];
            memcpy(bc, g_axvm_sample_add_bc, sizeof(bc));
            ((axvm_bc_header_t *)bc)->checksum = axvm_bc_checksum(bc, sizeof(bc));
            int xfail = 0;
            if (axvm_ctx_create(&xctx, bc, sizeof(bc)) != AXVM_OK ||
                axvm_mem_guard_selftest(xctx) != 0) {
                xfail = 1;
            }
            axvm_ctx_destroy(xctx);
            if (xfail != 0) {
                printf("module_x_standalone: FAIL\n");
                return 21;
            }
            printf("module_x_standalone: PASS\n");
        }
#endif

#if defined(AXVM_ENABLE_GUARD) && AXVM_ENABLE_GUARD
        {
            axvm_guard_state_t gst;
            if (axvm_guard_init(&gst) != AXVM_OK) {
                printf("module_vw_standalone: FAIL\n");
                return 22;
            }
            int vw = axvm_guard_probe_emulator_live();
            int wt = axvm_guard_timing_selftest(&gst);
            if (wt != 0) {
                printf("module_vw_standalone: FAIL\n");
                return 22;
            }
            printf("module_vw_standalone: PASS (emu=%d)\n", vw);
        }
#endif

    }



    if (run_bench("bench_loop", g_axvm_bench_loop_bc, AXVM_BENCH_LOOP_BC_SIZE,

                  AXVM_BENCH_LOOP_EXPECT, outer) != 0) {

        return 4;

    }



    printf("module_b_standalone: PASS\n");

    if (run_jit_bench_compare(outer) != 0) {
        printf("module_j_standalone: FAIL\n");
        return 11;
    }
    printf("module_j_standalone: PASS\n");

    return 0;

}


