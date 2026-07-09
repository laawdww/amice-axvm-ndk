#ifndef AXVM_H
#define AXVM_H

#include "axvm_types.h"
#include "axvm_bytecode.h"
#include "axvm_ctx.h"
#include "axvm_bridge.h"
#include "axvm_guard.h"
#include "axvm_interp.h"
#include "axvm_stack_crypt.h"
#include "axvm_freg.h"
#include "axvm_lazy.h"
#include "axvm_integrity.h"
#include "axvm_dynseed.h"
#include "axvm_got_crypt.h"
#include "axvm_jit.h"
#include "axvm_crypt.h"
#include "axvm_mem_guard.h"
#include "axvm_stext.h"
#include "axvm_nested.h"
#include "axvm_engine.h"
#include "axvm_dispatch_perm.h"
#include "axvm_handler_poly.h"
#include "axvm_lazy_pf.h"
#include "axvm_guard_svc.h"
#include "axvm_watchdog.h"
#include "axvm_riscc.h"
#include "axvm_interp_selftest.h"

#ifdef __cplusplus
extern "C" {
#endif

axvm_status_t axvm_run(axvm_ctx_t *ctx);
axvm_status_t axvm_load_bytecode(axvm_ctx_t *ctx, const uint8_t *bc, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* AXVM_H */
