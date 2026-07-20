/* 非 ARM64 回退：清关键易失参数后跳转（宿主工具链测试用） */
#include "axgate_mem.h"

#if !defined(__aarch64__)
void axgate_jump_oep(void *oep)
{
    typedef void (*fn_t)(void);
    fn_t fn = (fn_t)oep;
    fn();
    __builtin_unreachable();
}
#endif
