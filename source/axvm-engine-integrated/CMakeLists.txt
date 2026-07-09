cmake_minimum_required(VERSION 3.18)
project(axvm-engine C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(AXVM_BUILD_TOOLS "Build host Go lifter" OFF)
option(AXVM_ENABLE_GUARD "Enable anti-tamper layer" ON)
option(AXVM_USE_COMPUTED_GOTO "ARM64 threaded interpreter dispatch" ON)
option(AXVM_STACK_CRYPT "VM stack slot rolling XOR encryption" ON)
option(AXVM_FLOAT_VM "Enable v[32] scalar FP virtual registers and opcodes" ON)
option(AXVM_LAZY_DECRYPT "BasicBlock-grained lazy bytecode decrypt/re-encrypt" ON)
option(AXVM_DYNAMIC_SEED "Dual-layer dynamic seed: MasterSeed(EOF)->per-ctx SessionSeed" ON)
option(AXVM_SO_INTEGRITY "Segmented SHA256 SO integrity verification" ON)
option(AXVM_JIT_CACHE "Lightweight hotspot BasicBlock JIT cache (Module J)" ON)
option(AXVM_STRCRYPT "String constant multi-round runtime decryption" ON)
option(AXVM_OPCODE_PERM "Per-build opcode permutation keyed by AXDS MasterSeed (needs AXVM_DYNAMIC_SEED)" ON)
option(AXVM_REG_PERM "Per-ctx VM register index permutation keyed by AXDS SessionSeed (needs AXVM_DYNAMIC_SEED)" ON)
option(AXVM_JNI_GUARD "JNI parameter/object integrity checks (module AA)" ON)
option(AXVM_GOT_CRYPT "Encrypt GOT/stub dispatch pointers keyed by MasterSeed (module P; needs AXVM_DYNAMIC_SEED)" ON)
option(AXVM_MEM_GUARD "VM mem_pool page seal/unseal anti-dump (module X)" ON)
option(AXVM_STEXT "Track native .text wipe via AXPK_FLAG_WIPED (module O)" ON)
option(AXVM_DISPATCH_PERM "SessionSeed-keyed computed-goto dispatch shuffle (module N)" ON)
option(AXVM_HANDLER_POLY "SessionSeed XOR dispatch ptr + decoy handlers (Phase 3)" ON)
option(AXVM_LAZY_PF "Page-fault augmented lazy bytecode decrypt (Phase 3)" ON)
option(AXVM_SVC_ANTIDEBUG "Raw syscall anti-debug TracerPid probe (Phase 3)" ON)
option(AXVM_WATCHDOG "Background guard watchdog thread (Phase 3)" ON)
option(AXVM_JIT_HARDEN "JIT session-keyed hash + region seal (Phase 3)" ON)
option(AXVM_RISCC_PERM "SessionSeed RISCC wire permutation (Phase 3)" ON)
option(AXVM_NESTED_VM "Nested VM ctx hierarchy (module R)" ON)
option(AXVM_MULTI_ISA "Multi-ISA engine dispatch (module T)" ON)
option(AXVM_OLLVM "AMICE/OLLVM compile-time obfuscation (requires AMICE_PLUGIN bundle)" OFF)
option(AXVM_EMBED_RUNTIME "Statically link axvm_runtime into libvictim.so (single-SO init)" OFF)
option(AXVM_DEMO_JNI "Register demo NativeVm/VictimTest JNI + module selftests (OFF for delivery libaxvm.so)" ON)

if(AXVM_OPCODE_PERM AND NOT AXVM_DYNAMIC_SEED)
    message(WARNING "AXVM_OPCODE_PERM requires AXVM_DYNAMIC_SEED; forcing OPCODE_PERM OFF")
    set(AXVM_OPCODE_PERM OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_REG_PERM AND NOT AXVM_DYNAMIC_SEED)
    message(WARNING "AXVM_REG_PERM requires AXVM_DYNAMIC_SEED; forcing REG_PERM OFF")
    set(AXVM_REG_PERM OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_DISPATCH_PERM AND NOT AXVM_DYNAMIC_SEED)
    message(WARNING "AXVM_DISPATCH_PERM requires AXVM_DYNAMIC_SEED; forcing DISPATCH_PERM OFF")
    set(AXVM_DISPATCH_PERM OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_HANDLER_POLY AND NOT AXVM_DISPATCH_PERM)
    message(WARNING "AXVM_HANDLER_POLY requires AXVM_DISPATCH_PERM; forcing HANDLER_POLY OFF")
    set(AXVM_HANDLER_POLY OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_HANDLER_POLY AND NOT AXVM_USE_COMPUTED_GOTO)
    message(WARNING "AXVM_HANDLER_POLY requires AXVM_USE_COMPUTED_GOTO; forcing HANDLER_POLY OFF")
    set(AXVM_HANDLER_POLY OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_LAZY_PF AND NOT AXVM_LAZY_DECRYPT)
    message(WARNING "AXVM_LAZY_PF requires AXVM_LAZY_DECRYPT; forcing LAZY_PF OFF")
    set(AXVM_LAZY_PF OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_SVC_ANTIDEBUG AND NOT AXVM_ENABLE_GUARD)
    message(WARNING "AXVM_SVC_ANTIDEBUG requires AXVM_ENABLE_GUARD; forcing SVC_ANTIDEBUG OFF")
    set(AXVM_SVC_ANTIDEBUG OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_WATCHDOG AND NOT AXVM_SVC_ANTIDEBUG)
    message(WARNING "AXVM_WATCHDOG requires AXVM_SVC_ANTIDEBUG; forcing WATCHDOG OFF")
    set(AXVM_WATCHDOG OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_JIT_HARDEN AND NOT AXVM_JIT_CACHE)
    message(WARNING "AXVM_JIT_HARDEN requires AXVM_JIT_CACHE; forcing JIT_HARDEN OFF")
    set(AXVM_JIT_HARDEN OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_RISCC_PERM AND NOT AXVM_MULTI_ISA)
    message(WARNING "AXVM_RISCC_PERM requires AXVM_MULTI_ISA; forcing RISCC_PERM OFF")
    set(AXVM_RISCC_PERM OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_RISCC_PERM AND NOT AXVM_DYNAMIC_SEED)
    message(WARNING "AXVM_RISCC_PERM requires AXVM_DYNAMIC_SEED; forcing RISCC_PERM OFF")
    set(AXVM_RISCC_PERM OFF CACHE BOOL "" FORCE)
endif()

if(AXVM_GOT_CRYPT AND NOT AXVM_DYNAMIC_SEED)
    message(WARNING "AXVM_GOT_CRYPT requires AXVM_DYNAMIC_SEED; forcing GOT_CRYPT OFF")
    set(AXVM_GOT_CRYPT OFF CACHE BOOL "" FORCE)
endif()

include(${CMAKE_SOURCE_DIR}/cmake/AxvmObfuscate.cmake)

add_subdirectory(runtime)
add_subdirectory(target)
add_subdirectory(samples/victim)

if(AXVM_BUILD_TOOLS)
    add_custom_target(axlift ALL
        COMMAND ${CMAKE_SOURCE_DIR}/scripts/build-axlift.sh
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tools/axlift
        COMMENT "Building axlift host tool"
    )
endif()
