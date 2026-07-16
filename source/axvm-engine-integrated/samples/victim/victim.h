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

uint64_t victim_atomic_add(uint64_t *p, uint64_t delta);
uint64_t victim_atomic_cas(uint64_t *p, uint64_t expected, uint64_t desired);
uint64_t victim_atomic_swp(uint64_t *p, uint64_t neu);
uint64_t victim_atomic_inc_excl(uint64_t *p);
uint32_t victim_atomic_add32(uint32_t *p, uint32_t delta);
uint32_t victim_atomic_cas32(uint32_t *p, uint32_t expected, uint32_t desired);
uint32_t victim_atomic_inc_excl32(uint32_t *p);

void victim_neon_add2d(double out[2], const double a[2], const double b[2]);
void victim_neon_mul4s(float out[4], const float a[4], const float b[4]);
void victim_neon_fmla4s(float out[4], const float acc[4], const float a[4], const float b[4]);
double victim_neon_hadd2d(const double a[2], const double b[2]);

#ifdef __cplusplus
}
#endif

#endif
