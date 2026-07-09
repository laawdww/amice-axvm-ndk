#ifndef AXVM_INTERP_H
#define AXVM_INTERP_H

#ifdef __cplusplus
extern "C" {
#endif

/* 1 = computed goto 调度；0 = switch 调度 */
int axvm_interp_dispatch_is_goto(void);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_INTERP_H */
