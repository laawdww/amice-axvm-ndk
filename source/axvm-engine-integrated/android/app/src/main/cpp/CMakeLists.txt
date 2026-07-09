cmake_minimum_required(VERSION 3.18)

project(axvm_jni C ASM)

# android/app/src/main/cpp -> axvm-engine root (5 levels up)
get_filename_component(AXVM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../" ABSOLUTE)
include("${AXVM_ROOT}/cmake/AxvmObfuscate.cmake")

add_subdirectory("${AXVM_ROOT}/runtime" axvm_runtime_build)

add_library(axvm SHARED
    "${AXVM_ROOT}/target/sample/axvm_jni.c"
    victim_jni.c
)

target_include_directories(axvm PRIVATE
    "${AXVM_ROOT}/runtime/include"
    "${AXVM_ROOT}/target/sample"
    "${AXVM_ROOT}/samples/victim"
)

target_link_libraries(axvm PRIVATE axvm_runtime log)

if(NOT DEFINED AXVM_DEMO_JNI OR AXVM_DEMO_JNI)
    set(_axvm_export_map "${AXVM_ROOT}/cmake/axvm_exports_demo.map")
    target_compile_definitions(axvm PRIVATE AXVM_DEMO_JNI=1)
else()
    set(_axvm_export_map "${AXVM_ROOT}/cmake/axvm_exports.map")
    target_compile_definitions(axvm PRIVATE AXVM_DEMO_JNI=0)
endif()

target_compile_options(axvm PRIVATE -fvisibility=hidden -ffunction-sections -fdata-sections)
target_link_options(axvm PRIVATE
    "-Wl,--version-script=${_axvm_export_map}"
    "-Wl,--gc-sections"
)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_link_options(axvm PRIVATE "-Wl,-s")
endif()
axvm_apply_amice_obfuscation(axvm)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(axvm PRIVATE AXVM_DEBUG=1)
endif()

# 模块 AA：JNI 参数完整性校验（默认开启；与 root/target CMake 保持一致）
if(NOT DEFINED AXVM_JNI_GUARD OR AXVM_JNI_GUARD)
    target_compile_definitions(axvm PRIVATE AXVM_JNI_GUARD=1)
else()
    target_compile_definitions(axvm PRIVATE AXVM_JNI_GUARD=0)
endif()

set_target_properties(axvm PROPERTIES OUTPUT_NAME "axvm")

# victim 预编译保护库由 axpack 产出后放入 jniLibs
