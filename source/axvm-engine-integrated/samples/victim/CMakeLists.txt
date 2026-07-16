cmake_minimum_required(VERSION 3.18)

add_library(victim SHARED
    victim.c
    victim_mixed.c
    victim_float.c
    victim_isa.c
    victim_atomic.c
    victim_neon.c
)

target_include_directories(victim PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(victim PROPERTIES
    OUTPUT_NAME "victim"
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
)
target_compile_options(victim PRIVATE -g0)
set_source_files_properties(victim_isa.c PROPERTIES COMPILE_FLAGS "-fno-stack-protector")
axvm_apply_amice_obfuscation(victim)

if(AXVM_EMBED_RUNTIME)
    target_sources(victim PRIVATE axvm_embed_init.c)
    target_link_libraries(victim PRIVATE axvm_runtime log)
    target_include_directories(victim PRIVATE ${CMAKE_SOURCE_DIR}/runtime/include)
    target_compile_definitions(victim PRIVATE AXVM_EMBED_RUNTIME=1)
endif()

# 单 SO：runtime + ApkBinding/Prepatch/VictimTest JNI 链入 libvictim
# NativeVm MODULE_* 仍由 libaxvm 提供（aggressive pack 不宜虚拟化全部 demo JNI）
option(AXVM_SINGLE_SO "Embed runtime+JNI into libvictim (no separate libaxvm for victim path)" OFF)
if(AXVM_SINGLE_SO)
    if(NOT AXVM_EMBED_RUNTIME)
        message(FATAL_ERROR "AXVM_SINGLE_SO requires AXVM_EMBED_RUNTIME=ON")
    endif()
    target_sources(victim PRIVATE
        ${CMAKE_SOURCE_DIR}/android/app/src/main/cpp/victim_jni.c
    )
    target_compile_definitions(victim PRIVATE AXVM_SINGLE_SO=1)
endif()
