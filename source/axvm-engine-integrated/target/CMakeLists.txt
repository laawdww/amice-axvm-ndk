cmake_minimum_required(VERSION 3.18)

add_executable(axvm_standalone sample/axvm_standalone.c)
target_link_libraries(axvm_standalone PRIVATE axvm_runtime)
target_include_directories(axvm_standalone PRIVATE sample)

add_library(axvm_jni SHARED sample/axvm_jni.c)
target_link_libraries(axvm_jni PRIVATE axvm_runtime)
target_include_directories(axvm_jni PRIVATE sample)

add_library(axvm SHARED sample/axvm_jni.c sample/victim_jni.c)
target_link_libraries(axvm PRIVATE axvm_runtime)
target_include_directories(axvm PRIVATE sample ${CMAKE_SOURCE_DIR}/runtime/include)
set_target_properties(axvm PROPERTIES OUTPUT_NAME "axvm" POSITION_INDEPENDENT_CODE ON)

if(AXVM_DEMO_JNI)
    set(_axvm_export_map "${CMAKE_SOURCE_DIR}/cmake/axvm_exports_demo.map")
    target_compile_definitions(axvm PRIVATE AXVM_DEMO_JNI=1)
    target_compile_definitions(axvm_jni PRIVATE AXVM_DEMO_JNI=1)
    message(STATUS "axvm: demo JNI ENABLED (NativeVm/VictimTest probes exported)")
else()
    set(_axvm_export_map "${CMAKE_SOURCE_DIR}/cmake/axvm_exports.map")
    target_compile_definitions(axvm PRIVATE AXVM_DEMO_JNI=0)
    target_compile_definitions(axvm_jni PRIVATE AXVM_DEMO_JNI=0)
    message(STATUS "axvm: delivery build — demo JNI OFF (minimal exports)")
endif()

target_compile_options(axvm PRIVATE -fvisibility=hidden -ffunction-sections -fdata-sections)
target_link_options(axvm PRIVATE
    "-Wl,--version-script=${_axvm_export_map}"
    "-Wl,--gc-sections"
)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_link_options(axvm PRIVATE "-Wl,-s")
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(axvm PRIVATE AXVM_DEBUG=1)
endif()
axvm_apply_amice_obfuscation(axvm)

# 模块 AA：JNI 参数完整性校验（默认开启；关闭时 selftest 旁路返回 0）
if(AXVM_JNI_GUARD)
    target_compile_definitions(axvm PRIVATE AXVM_JNI_GUARD=1)
    target_compile_definitions(axvm_jni PRIVATE AXVM_JNI_GUARD=1)
    message(STATUS "axvm jni: parameter integrity guard (module AA) ENABLED")
else()
    target_compile_definitions(axvm PRIVATE AXVM_JNI_GUARD=0)
    target_compile_definitions(axvm_jni PRIVATE AXVM_JNI_GUARD=0)
endif()
