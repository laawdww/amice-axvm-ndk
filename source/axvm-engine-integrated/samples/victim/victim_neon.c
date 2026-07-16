#include "victim.h"

#if defined(__aarch64__)

/* 使用 LDR/STR Q + FADD/FMUL/FMLA 向量，对齐已实现的 AdvSIMD lift */
void victim_neon_add2d(double out[2], const double a[2], const double b[2])
{
    __asm__ __volatile__(
        "ldr q0, [%1]\n"
        "ldr q1, [%2]\n"
        "fadd v2.2d, v0.2d, v1.2d\n"
        "str q2, [%0]\n"
        :
        : "r"(out), "r"(a), "r"(b)
        : "v0", "v1", "v2", "memory");
}

void victim_neon_mul4s(float out[4], const float a[4], const float b[4])
{
    __asm__ __volatile__(
        "ldr q0, [%1]\n"
        "ldr q1, [%2]\n"
        "fmul v2.4s, v0.4s, v1.4s\n"
        "str q2, [%0]\n"
        :
        : "r"(out), "r"(a), "r"(b)
        : "v0", "v1", "v2", "memory");
}

void victim_neon_fmla4s(float out[4], const float acc[4], const float a[4], const float b[4])
{
    __asm__ __volatile__(
        "ld1 {v0.4s}, [%1]\n"
        "ld1 {v1.4s}, [%2]\n"
        "ld1 {v2.4s}, [%3]\n"
        "fmla v0.4s, v1.4s, v2.4s\n"
        "st1 {v0.4s}, [%0]\n"
        :
        : "r"(out), "r"(acc), "r"(a), "r"(b)
        : "v0", "v1", "v2", "memory");
}

double victim_neon_hadd2d(const double a[2], const double b[2])
{
    double tmp[2];
    victim_neon_add2d(tmp, a, b);
    return tmp[0] + tmp[1];
}

#else

void victim_neon_add2d(double out[2], const double a[2], const double b[2])
{
    out[0] = a[0] + b[0];
    out[1] = a[1] + b[1];
}

void victim_neon_mul4s(float out[4], const float a[4], const float b[4])
{
    for (int i = 0; i < 4; ++i) {
        out[i] = a[i] * b[i];
    }
}

void victim_neon_fmla4s(float out[4], const float acc[4], const float a[4], const float b[4])
{
    for (int i = 0; i < 4; ++i) {
        out[i] = acc[i] + a[i] * b[i];
    }
}

double victim_neon_hadd2d(const double a[2], const double b[2])
{
    return a[0] + b[0] + a[1] + b[1];
}

#endif
