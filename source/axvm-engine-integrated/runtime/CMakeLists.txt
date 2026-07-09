cmake_minimum_required(VERSION 3.18)

add_library(axvm_runtime STATIC
    src/axvm_bytecode.c
    src/axvm_ctx.c
    src/axvm_interp.c
    src/axvm_bridge.c
    src/axvm_guard.c
    src/axvm_crypt.c
    src/axvm_loader.c
    src/axvm_dispatch.c
    src/axvm_stack_crypt.c
    src/axvm_lazy.c
    src/axvm_integrity.c
    src/axvm_dynseed.c
    src/axvm_hmac.c
    src/axvm_entropy.c
    src/axvm_jit.c
    src/axvm_jit_emit.c
    src/axvm_strcrypt.c
    src/axvm_opcode_perm.c
    src/axvm_got_crypt.c
    src/axvm_mem_guard.c
    src/axvm_stext.c
    src/axvm_dispatch_perm.c
    src/axvm_handler_poly.c
    src/axvm_lazy_pf.c
    src/axvm_guard_svc.c
    src/axvm_watchdog.c
    src/axvm_riscc.c
    src/axvm_nested.c
    src/axvm_engine.c
    src/axvm_branch_map.c
    src/axvm_interp_selftest.c
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    target_sources(axvm_runtime PRIVATE src/axvm_entry.S src/axvm_native_call.S)
    if(AXVM_GOT_CRYPT AND AXVM_DYNAMIC_SEED)
        target_sources(axvm_runtime PRIVATE src/axvm_got_gate.S)
    endif()
endif()

target_include_directories(axvm_runtime PUBLIC include)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    if(AXVM_USE_COMPUTED_GOTO)
        target_compile_definitions(axvm_runtime PRIVATE AXVM_USE_COMPUTED_GOTO=1)
        message(STATUS "axvm_runtime: computed goto dispatch ENABLED (ARM64)")
    else()
        message(STATUS "axvm_runtime: switch dispatch (AXVM_USE_COMPUTED_GOTO=OFF)")
    endif()
else()
    if(AXVM_USE_COMPUTED_GOTO)
        message(STATUS "axvm_runtime: computed goto disabled on non-ARM64, using switch")
    endif()
endif()

if(AXVM_ENABLE_GUARD)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_ENABLE_GUARD=1)
endif()

if(AXVM_STACK_CRYPT)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_STACK_CRYPT=1)
    message(STATUS "axvm_runtime: VM stack XOR encryption ENABLED")
else()
    message(STATUS "axvm_runtime: VM stack encryption OFF (debug plaintext)")
endif()

if(AXVM_FLOAT_VM)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_FLOAT_VM=1)
    target_link_libraries(axvm_runtime PUBLIC m)
    message(STATUS "axvm_runtime: scalar FP virtual register file ENABLED")
else()
    message(STATUS "axvm_runtime: FP VM OFF (integer-only)")
endif()

if(AXVM_LAZY_DECRYPT)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_LAZY_DECRYPT=1)
    message(STATUS "axvm_runtime: BasicBlock lazy bytecode decryption ENABLED")
else()
    message(STATUS "axvm_runtime: lazy decrypt OFF (bytecode plaintext, debug)")
endif()

if(AXVM_SO_INTEGRITY)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_SO_INTEGRITY=1)
    message(STATUS "axvm_runtime: segmented SHA256 SO integrity ENABLED")
else()
    message(STATUS "axvm_runtime: SO integrity OFF")
endif()

if(AXVM_STRCRYPT)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_STRCRYPT=1)
    message(STATUS "axvm_runtime: string constant encryption ENABLED")
else()
    message(STATUS "axvm_runtime: string crypt OFF")
endif()

if(AXVM_DYNAMIC_SEED)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_DYNAMIC_SEED=1)
    message(STATUS "axvm_runtime: dual-layer dynamic seed ENABLED")
else()
    message(STATUS "axvm_runtime: dynamic seed OFF (static/urandom fallback)")
endif()

if(AXVM_OPCODE_PERM AND AXVM_DYNAMIC_SEED)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_OPCODE_PERM=1)
    message(STATUS "axvm_runtime: MasterSeed-keyed opcode permutation ENABLED")
else()
    message(STATUS "axvm_runtime: opcode permutation OFF")
endif()

if(AXVM_REG_PERM AND AXVM_DYNAMIC_SEED)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_REG_PERM=1)
    message(STATUS "axvm_runtime: SessionSeed-keyed register permutation ENABLED")
else()
    message(STATUS "axvm_runtime: register permutation OFF")
endif()

if(AXVM_GOT_CRYPT AND AXVM_DYNAMIC_SEED)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_GOT_CRYPT=1)
    message(STATUS "axvm_runtime: GOT dispatch pointer encryption ENABLED (module P)")
else()
    message(STATUS "axvm_runtime: GOT dispatch encryption OFF")
endif()

if(AXVM_MEM_GUARD)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_MEM_GUARD=1)
    message(STATUS "axvm_runtime: mem_pool page seal guard ENABLED (module X)")
else()
    message(STATUS "axvm_runtime: mem_pool page seal OFF")
endif()

if(AXVM_STEXT)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_STEXT=1)
    message(STATUS "axvm_runtime: native .text wipe tracking ENABLED (module O)")
else()
    message(STATUS "axvm_runtime: stext tracking OFF")
endif()

if(AXVM_DISPATCH_PERM AND AXVM_DYNAMIC_SEED)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_DISPATCH_PERM=1)
    message(STATUS "axvm_runtime: SessionSeed dispatch permutation ENABLED (module N)")
else()
    message(STATUS "axvm_runtime: dispatch permutation OFF")
endif()

if(AXVM_HANDLER_POLY AND AXVM_DISPATCH_PERM AND AXVM_USE_COMPUTED_GOTO)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_HANDLER_POLY=1)
    message(STATUS "axvm_runtime: handler polymorphism ENABLED (Phase 3)")
else()
    message(STATUS "axvm_runtime: handler polymorphism OFF")
endif()

if(AXVM_LAZY_PF AND AXVM_LAZY_DECRYPT)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_LAZY_PF=1)
    message(STATUS "axvm_runtime: page-fault lazy decrypt ENABLED (Phase 3)")
else()
    message(STATUS "axvm_runtime: page-fault lazy decrypt OFF")
endif()

if(AXVM_SVC_ANTIDEBUG AND AXVM_ENABLE_GUARD)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_SVC_ANTIDEBUG=1)
    message(STATUS "axvm_runtime: SVC anti-debug ENABLED (Phase 3)")
else()
    message(STATUS "axvm_runtime: SVC anti-debug OFF")
endif()

if(AXVM_WATCHDOG AND AXVM_SVC_ANTIDEBUG AND AXVM_ENABLE_GUARD)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_WATCHDOG=1)
    message(STATUS "axvm_runtime: guard watchdog thread ENABLED (Phase 3)")
else()
    message(STATUS "axvm_runtime: guard watchdog OFF")
endif()

if(AXVM_JIT_HARDEN AND AXVM_JIT_CACHE)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_JIT_HARDEN=1)
    message(STATUS "axvm_runtime: JIT hardening ENABLED (Phase 3)")
else()
    message(STATUS "axvm_runtime: JIT hardening OFF")
endif()

if(AXVM_NESTED_VM)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_NESTED_VM=1)
    message(STATUS "axvm_runtime: nested VM hierarchy ENABLED (module R)")
else()
    message(STATUS "axvm_runtime: nested VM OFF")
endif()

if(AXVM_MULTI_ISA)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_MULTI_ISA=1)
    message(STATUS "axvm_runtime: multi-ISA engine dispatch ENABLED (module T)")
else()
    message(STATUS "axvm_runtime: multi-ISA OFF")
endif()

if(AXVM_RISCC_PERM AND AXVM_MULTI_ISA AND AXVM_DYNAMIC_SEED)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_RISCC_PERM=1)
    message(STATUS "axvm_runtime: RISCC wire permutation ENABLED (Phase 3)")
else()
    message(STATUS "axvm_runtime: RISCC wire permutation OFF")
endif()

# 模块 J：热点 BasicBlock JIT 缓存（默认 ON；OFF=纯解释器零开销）
option(AXVM_JIT_CACHE "Lightweight hotspot BasicBlock JIT cache" ON)
if(AXVM_JIT_CACHE)
    target_compile_definitions(axvm_runtime PUBLIC AXVM_JIT_CACHE=1)
    message(STATUS "axvm_runtime: hotspot BasicBlock JIT cache ENABLED")
else()
    message(STATUS "axvm_runtime: JIT cache OFF (pure interpreter)")
endif()

if(ANDROID)
    target_link_libraries(axvm_runtime PUBLIC log)
endif()

target_compile_options(axvm_runtime PRIVATE -fvisibility=hidden)
axvm_apply_amice_obfuscation(axvm_runtime)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(axvm_runtime PRIVATE AXVM_DEBUG=1)
    message(STATUS "axvm_runtime: AXVM_DEBUG logcat ENABLED")
else()
    message(STATUS "axvm_runtime: release build — logcat silenced (AXVM_DEBUG OFF)")
endif()
