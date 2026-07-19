#include "axvm_nested.h"
#include "axvm_bridge.h"
#include "axvm.h"
#include "axvm_bytecode.h"
#include "axvm_dynseed.h"
#include "axvm_reg.h"

#include <stdlib.h>
#include <string.h>

static int nested_build_add_bc(uint8_t *bc, size_t cap, size_t *out_len)
{
    static const uint8_t code[] = {
        AXOP_ADD_REG, 0, 0, 1,
        AXOP_RET,
    };
    if (!bc || cap < 40 + sizeof(code) || !out_len) {
        return -1;
    }
    memset(bc, 0, 40 + sizeof(code));
    memcpy(bc, "AXV1", 4);
    uint32_t *u32 = (uint32_t *)bc;
    u32[1] = AXVM_VERSION;
    u32[3] = 40;
    u32[4] = (uint32_t)sizeof(code);
    u32[5] = 40 + (uint32_t)sizeof(code);
    u32[7] = 0;
    memcpy(bc + 40, code, sizeof(code));
    u32[8] = axvm_bc_checksum(bc, 40 + sizeof(code));
    *out_len = 40 + sizeof(code);
    return 0;
}

int axvm_nested_enabled(void)
{
#if defined(AXVM_NESTED_VM) && AXVM_NESTED_VM
    return 1;
#else
    return 0;
#endif
}

uint8_t axvm_nested_depth(const axvm_ctx_t *ctx)
{
    return ctx ? ctx->nest_depth : 0;
}

#if defined(AXVM_NESTED_VM) && AXVM_NESTED_VM

axvm_status_t axvm_ctx_create_nested(axvm_ctx_t *parent, axvm_ctx_t **out,
                                     const uint8_t *bc, size_t bc_len)
{
    if (!out || !bc || !axvm_bc_validate(bc, bc_len)) {
        return AXVM_ERR_BAD_MAGIC;
    }
    uint8_t depth = parent ? (uint8_t)(parent->nest_depth + 1u) : 0;
    if (depth >= AXVM_NEST_MAX_DEPTH) {
        return AXVM_ERR_OOB_MEM;
    }
    axvm_status_t st = axvm_ctx_create(out, bc, bc_len);
    if (st != AXVM_OK || !*out) {
        return st;
    }
    (*out)->parent = parent;
    (*out)->nest_depth = depth;
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (parent && parent->session_seed_present) {
        axvm_ctx_rebind_session_seed(*out, parent->session_seed);
    }
#endif
    return AXVM_OK;
}

uint64_t axvm_nested_invoke(axvm_ctx_t *parent, const uint8_t *bc, size_t bc_len,
                            uint32_t entry_pc, const uint64_t *args, int argc)
{
    axvm_vcpu_frame_t parent_snap;
    int snap = 0;
    if (parent) {
        axvm_ctx_snapshot(parent, &parent_snap);
        snap = 1;
    }
    axvm_ctx_t *child = NULL;
    if (axvm_ctx_create_nested(parent, &child, bc, bc_len) != AXVM_OK) {
        return 0;
    }
    if (entry_pc != 0) {
        child->pc = entry_pc;
    }
    axvm_bridge_enter(child);
    if (args && argc > 0) {
        axvm_ctx_bind_args(child, args, argc);
    }
    if (parent) {
        (void)axvm_reg_write(child, 8, parent->x[8]);
    }
    uint64_t rv = axvm_invoke(child, 0);
    axvm_ctx_destroy(child);
    if (snap) {
        axvm_ctx_restore(parent, &parent_snap);
    }
    return rv;
}

#else

axvm_status_t axvm_ctx_create_nested(axvm_ctx_t *parent, axvm_ctx_t **out,
                                     const uint8_t *bc, size_t bc_len)
{
    (void)parent;
    return axvm_ctx_create(out, bc, bc_len);
}

uint64_t axvm_nested_invoke(axvm_ctx_t *parent, const uint8_t *bc, size_t bc_len,
                            uint32_t entry_pc, const uint64_t *args, int argc)
{
    (void)parent;
    (void)entry_pc;
    axvm_ctx_t *ctx = NULL;
    if (axvm_ctx_create(&ctx, bc, bc_len) != AXVM_OK) {
        return 0;
    }
    axvm_bridge_enter(ctx);
    if (args && argc > 0) {
        axvm_ctx_bind_args(ctx, args, argc);
    }
    uint64_t rv = axvm_invoke(ctx, 0);
    axvm_ctx_destroy(ctx);
    return rv;
}

#endif

uint64_t axvm_nested_vm_enter(axvm_ctx_t *parent, uint32_t child_off, uint8_t argc)
{
#if !defined(AXVM_NESTED_VM) || !AXVM_NESTED_VM
    (void)parent;
    (void)child_off;
    (void)argc;
    return 0;
#else
    if (!parent || !parent->bytecode || child_off >= parent->bc_size) {
        return 0;
    }
    const uint8_t *child = parent->bytecode + child_off;
    size_t child_len = parent->bc_size - (size_t)child_off;
    if (!axvm_bc_validate(child, child_len)) {
        return 0;
    }
    uint64_t args[8] = { 0 };
    uint8_t n = argc > 8 ? 8 : argc;
    for (uint8_t i = 0; i < n; ++i) {
        args[i] = parent->x[i];
    }
    return axvm_nested_invoke(parent, child, child_len, 0, args, (int)n);
#endif
}

int axvm_nested_selftest(void)
{
#if !defined(AXVM_NESTED_VM) || !AXVM_NESTED_VM
    return 0;
#endif
    uint8_t bc[128];
    size_t bc_len = 0;
    if (nested_build_add_bc(bc, sizeof(bc), &bc_len) != 0) {
        return 1;
    }
    uint64_t args[2] = { 20, 22 };
    uint64_t rv = axvm_nested_invoke(NULL, bc, bc_len, 0, args, 2);
    if (rv != 42) {
        return 2;
    }

    axvm_ctx_t *root = NULL;
    if (axvm_ctx_create(&root, bc, bc_len) != AXVM_OK) {
        return 3;
    }
    axvm_ctx_t *child = NULL;
    int rc = 0;
    if (axvm_ctx_create_nested(root, &child, bc, bc_len) != AXVM_OK) {
        rc = 4;
    } else if (child->nest_depth != 1 || child->parent != root) {
        rc = 5;
    } else if (root->session_seed_present && !child->session_seed_present) {
        rc = 6;
    } else if (root->session_seed_present &&
               memcmp(child->session_seed, root->session_seed, 32) != 0) {
        rc = 7;
    }
    axvm_ctx_destroy(child);
    axvm_ctx_destroy(root);
    if (rc != 0) {
        return rc;
    }

    axvm_ctx_t *proot = NULL;
    if (axvm_ctx_create(&proot, bc, bc_len) != AXVM_OK) {
        return 8;
    }
    axvm_bridge_enter(proot);
    uint64_t pargs[2] = { 11, 31 };
    axvm_ctx_bind_args(proot, pargs, 2);
    if (axvm_nested_invoke(proot, bc, bc_len, 0, pargs, 2) != 42) {
        axvm_ctx_destroy(proot);
        return 9;
    }
    axvm_ctx_destroy(proot);
    return 0;
}
