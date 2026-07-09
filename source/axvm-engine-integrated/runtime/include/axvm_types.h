#ifndef AXVM_TYPES_H
#define AXVM_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum axvm_status {
    AXVM_OK              = 0,
    AXVM_ERR_BAD_MAGIC   = -1,
    AXVM_ERR_BAD_VERSION = -2,
    AXVM_ERR_OOB_PC      = -3,
    AXVM_ERR_OOB_STACK   = -4,
    AXVM_ERR_OOB_MEM     = -5,
    AXVM_ERR_BAD_INSN    = -6,
    AXVM_ERR_ALIGN       = -7,
    AXVM_ERR_GUARD       = -8,
    AXVM_ERR_NATIVE      = -9,
    AXVM_ERR_HALT        = -10,
} axvm_status_t;

#define AXVM_MAGIC_0 'A'
#define AXVM_MAGIC_1 'X'
#define AXVM_MAGIC_2 'V'
#define AXVM_MAGIC_3 '1'

#define AXVM_VERSION 0x00010000u

#define AXVM_REG_COUNT   31
#define AXVM_FP_REG_COUNT 32

/* 模块 G：BasicBlock 懒解密单元粒度与同时解密窗口上限 */
#define AXVM_LAZY_BLOCK      32u
#define AXVM_LAZY_ACTIVE_MAX 4u
#define AXVM_STACK_SIZE  (64 * 1024)
#define AXVM_STACK_GUARD 4096
#define AXVM_MEM_POOL    (256 * 1024)

#ifdef __aarch64__
#define AXVM_HOST_ARM64 1
#else
#define AXVM_HOST_ARM64 0
#endif

#ifdef __cplusplus
}
#endif

#endif /* AXVM_TYPES_H */
