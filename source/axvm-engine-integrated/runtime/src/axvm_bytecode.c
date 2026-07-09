#include "axvm_bytecode.h"

#include <stddef.h>
#include <string.h>

static uint32_t fnv1a32(const uint8_t *data, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

uint32_t axvm_bc_checksum(const uint8_t *blob, size_t len)
{
    if (!blob || len < sizeof(axvm_bc_header_t)) {
        return 0;
    }
    size_t skip = offsetof(axvm_bc_header_t, checksum);
    uint32_t h = fnv1a32(blob, skip);
    h ^= fnv1a32(blob + skip + sizeof(uint32_t), len - skip - sizeof(uint32_t));
    return h;
}

int axvm_bc_validate(const uint8_t *blob, size_t len)
{
    if (!blob || len < sizeof(axvm_bc_header_t)) {
        return 0;
    }

    const axvm_bc_header_t *hdr = (const axvm_bc_header_t *)blob;
    if (hdr->magic[0] != AXVM_MAGIC_0 || hdr->magic[1] != AXVM_MAGIC_1 ||
        hdr->magic[2] != AXVM_MAGIC_2 || hdr->magic[3] != AXVM_MAGIC_3) {
        return 0;
    }
    if (hdr->version != AXVM_VERSION) {
        return 0;
    }
    if ((uint64_t)hdr->code_off + (uint64_t)hdr->code_size > (uint64_t)len) {
        return 0;
    }
    if ((uint64_t)hdr->data_off + (uint64_t)hdr->data_size > (uint64_t)len) {
        return 0;
    }
    if (hdr->entry_pc >= hdr->code_size) {
        return 0;
    }
    if (hdr->checksum != axvm_bc_checksum(blob, len)) {
        return 0;
    }
    return 1;
}
