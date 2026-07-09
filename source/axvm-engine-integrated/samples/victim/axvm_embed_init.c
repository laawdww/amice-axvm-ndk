#include "axvm_pack.h"

/*
 * 单 SO 模式：将 axvm_runtime 静态链入 libvictim 时，在 .so load 时登记 dispatch，
 * 避免 dlsym("axvm_dispatch_ex") 字符串指纹。JNI prepatch 仍可由 libaxvm 或同 SO 导出。
 */
__attribute__((constructor(101))) static void axvm_embed_runtime_init(void)
{
    axvm_register_dispatch((void *)(uintptr_t)axvm_dispatch_ex);
}

int axvm_embed_runtime_linked(void)
{
    return 1;
}
