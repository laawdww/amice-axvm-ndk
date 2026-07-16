# AXVM NDK one-click post-build protect (CMake)
#
# include(${AXVM_REPO}/cmake/AxvmProtect.cmake)
# axvm_ndk_protect(mylib
#   SYMBOLS "foo,bar"          # optional; empty => aggressive + scan in script
#   SINGLE_SO ON               # default ON
#   PACKAGE "com.example.app"  # optional apk-bind
#   APK "${CMAKE_SOURCE_DIR}/app.apk"
# )
#
# Requires Windows host + protect-ndk.ps1 + artifacts/axpack.exe.

function(axvm_ndk_protect target)
    set(options)
    set(oneValueArgs SYMBOLS PACKAGE APK APK_CERT_SHA256 PROTECT_LEVEL OUT_NAME)
    set(multiValueArgs)
    cmake_parse_arguments(AXP "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT WIN32)
        message(STATUS "axvm_ndk_protect(${target}): skipped (Windows host packer)")
        return()
    endif()

    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
        message(STATUS "axvm_ndk_protect(${target}): skipped (not Android ABI build)")
        return()
    endif()

    get_filename_component(_axvm_cmake_dir "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
    get_filename_component(_axvm_engine "${_axvm_cmake_dir}/.." ABSOLUTE)
    get_filename_component(_axvm_repo "${_axvm_engine}/../.." ABSOLUTE)
    set(_script "${_axvm_repo}/protect-ndk.ps1")
    if(NOT EXISTS "${_script}")
        set(_script "${_axvm_engine}/../../protect-ndk.ps1")
    endif()
    if(NOT EXISTS "${_script}")
        message(WARNING "axvm_ndk_protect: protect-ndk.ps1 not found; skip ${target}")
        return()
    endif()

    if(NOT AXP_PROTECT_LEVEL)
        set(AXP_PROTECT_LEVEL aggressive)
    endif()

    set(_out_expr "$<TARGET_FILE:${target}>")
    if(AXP_OUT_NAME)
        set(_out_expr "$<TARGET_FILE_DIR:${target}>/${AXP_OUT_NAME}")
    endif()

    set(_ps_args
        -NoProfile -ExecutionPolicy Bypass
        -File "${_script}"
        -In "$<TARGET_FILE:${target}>"
        -Out "${_out_expr}"
        -RepoRoot "${_axvm_repo}"
        -ProtectLevel "${AXP_PROTECT_LEVEL}"
        -SingleSo:$true
    )
    if(AXP_SYMBOLS)
        list(APPEND _ps_args -Symbols "${AXP_SYMBOLS}")
    endif()
    if(AXP_PACKAGE)
        list(APPEND _ps_args -Package "${AXP_PACKAGE}" -ApkBind)
    endif()
    if(AXP_APK)
        list(APPEND _ps_args -Apk "${AXP_APK}")
    endif()
    if(AXP_APK_CERT_SHA256)
        list(APPEND _ps_args -ApkCertSha256 "${AXP_APK_CERT_SHA256}")
    endif()

    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND powershell @_ps_args
        COMMENT "AXVM one-click protect $<TARGET_FILE_NAME:${target}>"
        VERBATIM
    )
    message(STATUS "axvm_ndk_protect: POST_BUILD hooked on ${target}")
endfunction()
