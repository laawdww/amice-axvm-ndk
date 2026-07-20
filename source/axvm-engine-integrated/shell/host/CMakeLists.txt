# axgate host: outer libaxvm.so (gate + encrypted inner interpreter blob)
cmake_minimum_required(VERSION 3.18)

set(AXGATE_BLOB_C "" CACHE FILEPATH "axgatepack-generated axgate_blob.c")
set(AXGATE_UK_C "" CACHE FILEPATH "axgatepack-generated axgate_uk.c")

add_library(axgate_host SHARED
    axgate_host_jni.c
)

if(AXGATE_BLOB_C AND EXISTS "${AXGATE_BLOB_C}")
    target_sources(axgate_host PRIVATE "${AXGATE_BLOB_C}")
    message(STATUS "axgate_host: linking blob ${AXGATE_BLOB_C}")
else()
    message(WARNING "axgate_host: no AXGATE_BLOB_C — gate will no-op at runtime")
endif()

if(AXGATE_UK_C AND EXISTS "${AXGATE_UK_C}")
    target_sources(axgate_host PRIVATE "${AXGATE_UK_C}")
    message(STATUS "axgate_host: linking uk ${AXGATE_UK_C}")
else()
    message(WARNING "axgate_host: no AXGATE_UK_C — KEY_WRAP unavailable")
endif()

# Prefer static libz to avoid DT_NEEDED libz.so fingerprint.
set(_axgate_z "z")
if(ANDROID_NDK)
    set(_z_cand "${ANDROID_NDK}/toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/lib/aarch64-linux-android/libz.a")
    if(EXISTS "${_z_cand}")
        set(_axgate_z "${_z_cand}")
        message(STATUS "axgate_host: static libz")
    endif()
endif()

target_link_libraries(axgate_host PRIVATE axgate log dl "${_axgate_z}")
target_include_directories(axgate_host PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

set_target_properties(axgate_host PROPERTIES
    OUTPUT_NAME "axvm"
    POSITION_INDEPENDENT_CODE ON
)

target_compile_options(axgate_host PRIVATE
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -fno-asynchronous-unwind-tables
)

target_link_options(axgate_host PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/axgate_host.exports"
    "-Wl,--gc-sections"
    "-Wl,-s"
    "-Wl,-u,x7d"
    "-Wl,-u,x7g"
    "-Wl,-u,Java_com_hook_bypass_AxvmApkBinding_nativeEnsureBinding"
    "-Wl,-u,Java_com_hook_bypass_AxvmPrepatch_nativePrepatch"
)

target_link_options(axgate_host PRIVATE
    "-Wl,--undefined=axgate_section"
    "-Wl,--undefined=axgate_section_size"
    "-Wl,--undefined=axgate_uk_q"
    "-Wl,--undefined=axgate_desc_magic"
)
