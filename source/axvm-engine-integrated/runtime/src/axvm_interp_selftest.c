#include "axvm.h"
#include "axvm_bridge.h"
#include "axvm_bytecode.h"

#include <stdio.h>
#include <string.h>

static int run_bc(const uint8_t *bc, size_t len, const uint64_t *args, int argc, uint64_t expect)
{
    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, len) != AXVM_OK) {
        return 1;
    }
    if (axvm_bridge_enter(ctx) != AXVM_OK) {
        axvm_ctx_destroy(ctx);
        return 2;
    }
    if (argc > 0) {
        axvm_ctx_bind_args(ctx, args, argc);
    }
    uint64_t rv = axvm_invoke(ctx, 0);
    axvm_ctx_destroy(ctx);
    if (rv != expect) {
        fprintf(stderr, "interp_selftest fail rv=%llu expect=%llu\n",
                (unsigned long long)rv, (unsigned long long)expect);
        return 3;
    }
    return 0;
}

static uint8_t *mk_hdr(uint8_t *buf, size_t code_len, uint32_t flags)
{
    memset(buf, 0, 40);
    axvm_bc_header_t *h = (axvm_bc_header_t *)buf;
    memcpy(h->magic, "AXV1", 4);
    h->version = 0x00010000u;
    h->flags = flags;
    h->code_off = 40;
    h->code_size = (uint32_t)code_len;
    h->data_off = 40 + (uint32_t)code_len;
    h->data_size = 0;
    h->entry_pc = 0;
    h->checksum = axvm_bc_checksum(buf, 40 + code_len);
    return buf;
}

int axvm_interp_selftest(void)
{
    uint8_t buf[256];
    uint64_t args[4];

    /* ADD_REG x0 = x0 + x1 */
    {
        uint8_t code[] = {AXOP_ADD_REG, 0, 0, 1, AXOP_RET};
        memcpy(buf + 40, code, sizeof(code));
        mk_hdr(buf, sizeof(code), 0);
        args[0] = 41;
        args[1] = 1;
        if (run_bc(buf, 40 + sizeof(code), args, 2, 42) != 0) {
            return 10;
        }
    }

    /* ASR_IMM */
    {
        uint8_t code[] = {AXOP_ASR_IMM, 0, 0, 4, AXOP_RET};
        memcpy(buf + 40, code, sizeof(code));
        mk_hdr(buf, sizeof(code), 0);
        args[0] = 0x8000000000000000ULL;
        if (run_bc(buf, 40 + sizeof(code), args, 1, 0xF800000000000000ULL) != 0) {
            return 11;
        }
    }

    /* EOR + LSL + LSR -> 0x7F */
    {
        uint8_t code[] = {
            AXOP_LDRI64, 0, 0xFF, 0, 0, 0, 0, 0, 0, 0,
            AXOP_LDRI64, 1, 0x01, 0, 0, 0, 0, 0, 0, 0,
            AXOP_EOR_REG, 0, 0, 1,
            AXOP_LSL_IMM, 0, 0, 0,
            AXOP_LSR_IMM, 0, 0, 1,
            AXOP_RET,
        };
        memcpy(buf + 40, code, sizeof(code));
        mk_hdr(buf, sizeof(code), 0);
        args[0] = 0;
        args[1] = 0;
        if (run_bc(buf, 40 + sizeof(code), args, 2, 0x7F) != 0) {
            return 12;
        }
    }

    /* B_COND EQ */
    {
        uint8_t code[] = {
            AXOP_CMP_REG, 0, 1,
            AXOP_B_COND, AXCOND_EQ, 0, 0, 0, 0,
            AXOP_LDRI64, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            AXOP_RET,
            AXOP_LDRI64, 0, 99, 0, 0, 0, 0, 0, 0, 0,
            AXOP_RET,
        };
        int32_t rel = 11;
        memcpy(code + 5, &rel, 4);
        memcpy(buf + 40, code, sizeof(code));
        mk_hdr(buf, sizeof(code), 0);
        args[0] = 7;
        args[1] = 7;
        if (run_bc(buf, 40 + sizeof(code), args, 2, 99) != 0) {
            return 13;
        }
    }

    /* MUL */
    {
        uint8_t code[] = {AXOP_MUL_REG, 0, 1, 2, AXOP_RET};
        memcpy(buf + 40, code, sizeof(code));
        mk_hdr(buf, sizeof(code), 0);
        args[0] = 0;
        args[1] = 6;
        args[2] = 7;
        if (run_bc(buf, 40 + sizeof(code), args, 3, 42) != 0) {
            return 14;
        }
    }

    /* CSEL */
    {
        uint8_t code[] = {
            AXOP_CMP_REG, 0, 1,
            AXOP_CSEL_REG, 0, 0, 1, AXCOND_EQ,
            AXOP_RET,
        };
        memcpy(buf + 40, code, sizeof(code));
        mk_hdr(buf, sizeof(code), 0);
        args[0] = 5;
        args[1] = 5;
        if (run_bc(buf, 40 + sizeof(code), args, 2, 5) != 0) {
            return 15;
        }
    }

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM
    /* FADD */
    {
        uint8_t code[] = {AXOP_FADD_D, 0, 0, 1, AXOP_FMOV_X_BITS, 0, 0, AXOP_RET};
        memcpy(buf + 40, code, sizeof(code));
        mk_hdr(buf, sizeof(code), 0);
        double da = 1.5, db = 2.5;
        uint64_t a0, a1;
        memcpy(&a0, &da, 8);
        memcpy(&a1, &db, 8);
        args[0] = a0;
        args[1] = a1;
        uint64_t expect = 0;
        double de = 4.0;
        memcpy(&expect, &de, 8);
        if (run_bc(buf, 40 + sizeof(code), args, 2, expect) != 0) {
            return 16;
        }
    }
#endif

    return 0;
}
