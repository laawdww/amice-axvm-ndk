#include "victim.h"

#include <stddef.h>

/*
 * 模块 F 浮点测试：标量 double 运算 + 简易 dot（OpenCV 类 float 累加）。
 */
__attribute__((visibility("default")))
double victim_fadd(double a, double b)
{
    return a + b;
}

__attribute__((visibility("default")))
double victim_fmul(double a, double b)
{
    return a * b;
}

__attribute__((visibility("default")))
float victim_dot3(const float *a, const float *b)
{
    float acc = 0.0f;
    for (int i = 0; i < 3; ++i) {
        acc += a[i] * b[i];
    }
    return acc;
}
