cmake_minimum_required(VERSION 3.18)

# axgate：axvm 前置 Stub 安全壳（与 runtime ISA 解耦）
option(AXVM_BUILD_AXGATE "Build axgate preload shell static lib" ON)

if(NOT AXVM_BUILD_AXGATE)
    return()
endif()

add_library(axgate STATIC
    src/axgate_aes.c
    src/axgate_integrity.c
    src/axgate_antidebug.c
    src/axgate_iat.c
    src/axgate_elf.c
    src/axgate_mem.c
    src/axgate_axzc.c
    src/axgate_kdf.c
    src/axgate_boot.c
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64|arm64" OR ANDROID_ABI STREQUAL "arm64-v8a")
    target_sources(axgate PRIVATE src/axgate_entry.S)
else()
    target_sources(axgate PRIVATE src/axgate_entry_fallback.c)
endif()

target_include_directories(axgate PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(axgate PRIVATE
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -fno-asynchronous-unwind-tables
)

target_link_libraries(axgate PRIVATE dl z)

if(TARGET victim AND AXVM_EMBED_RUNTIME)
    message(STATUS "axgate: static lib ready — link with: target_link_libraries(victim PRIVATE axgate)")
endif()

message(STATUS "axgate: lightweight ARM64 gate shell ENABLED (AXZC+zlib)")
