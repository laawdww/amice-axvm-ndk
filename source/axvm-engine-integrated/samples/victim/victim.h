#ifndef VICTIM_H
#define VICTIM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t victim_add(uint64_t a, uint64_t b);
uint64_t victim_mul(uint64_t a, uint64_t b);
uint64_t victim_check(uint64_t key);
uint64_t victim_mixed(uint64_t n, uint64_t seed);

uint64_t victim_neg(uint64_t x);
uint64_t victim_cmp_imm(uint64_t x);
uint64_t victim_and_imm(uint64_t x);
uint64_t victim_asr(uint64_t x);
uint64_t victim_ldp_stp(uint64_t a, uint64_t b);
uint64_t victim_movn(void);
uint64_t victim_ldr_reg(uint64_t *p);

double victim_fadd(double a, double b);
double victim_fmul(double a, double b);
float victim_dot3(const float *a, const float *b);

#ifdef __cplusplus
}
#endif

#endif
