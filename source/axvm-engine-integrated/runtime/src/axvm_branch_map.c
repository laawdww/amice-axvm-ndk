#include "axvm_branch_map.h"
#include "axvm_ctx.h"
#include "axvm_bytecode.h"

#include <stdlib.h>
#include <string.h>

#define AXVM_BRANCH_TAIL_FIXED 21u /* reverse(1)+oc_key(4)+map_count(4)+func_addr(8)+func_size(4) */

static uint32_t branch_map_tail_size(uint32_t map_count)
{
    return map_count * 8u + AXVM_BRANCH_TAIL_FIXED;
}

int axvm_branch_map_attach(axvm_ctx_t *ctx)
{
    if (!ctx || !ctx->bytecode) {
        return 0;
    }
    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)ctx->bytecode;
    if ((hdr->flags & AXVM_BC_FLAG_ADDR_MAP) == 0) {
        return 0;
    }
    if (hdr->code_off + hdr->code_size > ctx->bc_size) {
        return -1;
    }
    if (hdr->data_off < hdr->code_off + hdr->code_size) {
        return -1;
    }

    size_t trailer_len = (size_t)hdr->data_off - (size_t)hdr->code_off - (size_t)hdr->code_size;
    const uint8_t *tail_base = ctx->bytecode + hdr->code_off + hdr->code_size;

    if (trailer_len < AXVM_BRANCH_TAIL_FIXED) {
        return -1;
    }

    const uint8_t *p = tail_base + trailer_len - AXVM_BRANCH_TAIL_FIXED;
    uint32_t func_size = (uint32_t)p[17] | ((uint32_t)p[18] << 8) | ((uint32_t)p[19] << 16) |
                         ((uint32_t)p[20] << 24);
    uint64_t func_addr = 0;
    memcpy(&func_addr, p + 9, sizeof(func_addr));
    uint32_t map_count = (uint32_t)p[5] | ((uint32_t)p[6] << 8) | ((uint32_t)p[7] << 16) |
                         ((uint32_t)p[8] << 24);
    (void)func_size;
    (void)p[0]; /* reverse */
    (void)((uint32_t)p[1] | ((uint32_t)p[2] << 8) | ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 24));

    uint32_t need = branch_map_tail_size(map_count);
    if (trailer_len < need) {
        return -1;
    }

    const uint8_t *map_bytes = tail_base + trailer_len - need;
    axvm_addr_map_entry_t *map =
        (axvm_addr_map_entry_t *)malloc((size_t)map_count * sizeof(axvm_addr_map_entry_t));
    if (!map && map_count > 0) {
        return -1;
    }
    for (uint32_t i = 0; i < map_count; ++i) {
        const uint8_t *e = map_bytes + (size_t)i * 8u;
        map[i].arm64_off =
            (uint32_t)e[0] | ((uint32_t)e[1] << 8) | ((uint32_t)e[2] << 16) | ((uint32_t)e[3] << 24);
        map[i].vm_off =
            (uint32_t)e[4] | ((uint32_t)e[5] << 8) | ((uint32_t)e[6] << 16) | ((uint32_t)e[7] << 24);
    }

    ctx->branch_func_vaddr = func_addr;
    ctx->branch_func_size = func_size;
    ctx->branch_map = map;
    ctx->branch_map_count = map_count;
    return 0;
}

int axvm_branch_map_lookup(const axvm_ctx_t *ctx, uint32_t arm64_off, uint32_t *vm_off_out)
{
    if (!ctx || !vm_off_out || !ctx->branch_map || ctx->branch_map_count == 0) {
        return 0;
    }
    uint32_t lo = 0;
    uint32_t hi = ctx->branch_map_count;
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        uint32_t mid_off = ctx->branch_map[mid].arm64_off;
        if (mid_off < arm64_off) {
            lo = mid + 1;
        } else if (mid_off > arm64_off) {
            hi = mid;
        } else {
            *vm_off_out = ctx->branch_map[mid].vm_off;
            return 1;
        }
    }
    return 0;
}

void axvm_branch_map_detach(axvm_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    free(ctx->branch_map);
    ctx->branch_map = NULL;
    ctx->branch_map_count = 0;
    ctx->branch_func_vaddr = 0;
    ctx->branch_func_size = 0;
}
