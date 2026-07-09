#ifndef AXVM_BRANCH_MAP_H
#define AXVM_BRANCH_MAP_H

#include <stdint.h>

struct axvm_ctx;

#ifdef __cplusplus
extern "C" {
#endif

int axvm_branch_map_attach(struct axvm_ctx *ctx);
int axvm_branch_map_lookup(const struct axvm_ctx *ctx, uint32_t arm64_off, uint32_t *vm_off_out);
void axvm_branch_map_detach(struct axvm_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_BRANCH_MAP_H */
