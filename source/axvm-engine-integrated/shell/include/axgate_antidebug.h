#ifndef AXGATE_ANTIDEBUG_H
#define AXGATE_ANTIDEBUG_H

#include "axgate_types.h"
#include "axgate_iat.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 模块 2 — TracerPid / ptrace 反调试
 * 读 /proc/self/status 的 TracerPid；可选 PTRACE_TRACEME 探测。
 * 路径与关键字 XOR 混淆，避免明文指纹。
 * 优先走 IAT 动态解析的 open/read/close，避免静态导入。
 */
axgate_status_t axgate_antidebug_check(const axgate_apis_t *api);

#ifdef __cplusplus
}
#endif

#endif /* AXGATE_ANTIDEBUG_H */
