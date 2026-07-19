#ifndef AXVM_LOG_H
#define AXVM_LOG_H

#include <android/log.h>

#if defined(AXVM_DEBUG) && AXVM_DEBUG
#define AXVM_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "AXVM", __VA_ARGS__)
#define AXVM_LOGW(...) __android_log_print(ANDROID_LOG_WARN,  "AXVM", __VA_ARGS__)
#define AXVM_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "AXVM", __VA_ARGS__)
#else
/* Release: silence all logcat (format strings otherwise leak VM internals). */
#define AXVM_LOGI(...) ((void)0)
#define AXVM_LOGW(...) ((void)0)
#define AXVM_LOGE(...) ((void)0)
#endif

#endif /* AXVM_LOG_H */
