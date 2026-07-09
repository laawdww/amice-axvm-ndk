# Optional AMICE/OLLVM compile-time obfuscation (default OFF).
#
# Android clang can only load an AMICE plugin built for that clang host.
# The Windows amice.dll/opt.exe bundle is an opt-hosted plugin; it can run an
# offline bitcode pass, but it cannot be loaded directly by NDK clang++.exe.
#
# Usage (Linux/macOS/CI with a clang-loadable plugin):
#   export AMICE_ANDROID_BUNDLE=/path/to/amice-android-ndk-r26d-linux-x86_64
#   source $AMICE_ANDROID_BUNDLE/amice/env.sh
#   cmake -DAXVM_OLLVM=ON -DAMICE_PLUGIN=$AMICE_ANDROID_BUNDLE/amice/lib/libamice.so ...

option(AMICE_ALLOW_WINDOWS_CLANG_PLUGIN "Allow -fpass-plugin with a Windows AMICE DLL anyway" OFF)

if(AXVM_OLLVM)
    if(DEFINED ENV{AMICE_PLUGIN})
        set(AMICE_PLUGIN "$ENV{AMICE_PLUGIN}" CACHE FILEPATH "Path to libamice.so")
    endif()
    if(NOT AMICE_PLUGIN)
        message(WARNING "AXVM_OLLVM=ON but AMICE_PLUGIN not set; compile-time obfuscation disabled")
        set(AXVM_OLLVM OFF CACHE BOOL "" FORCE)
    elseif(WIN32 AND AMICE_PLUGIN MATCHES "\\.dll$" AND NOT AMICE_ALLOW_WINDOWS_CLANG_PLUGIN)
        message(WARNING
            "AXVM_OLLVM=ON but AMICE_PLUGIN points to a Windows DLL. "
            "This bundle is opt-hosted and cannot be loaded by NDK clang++.exe with -fpass-plugin; "
            "use a clang-loadable libamice.so in WSL/Linux CI, or run the Windows opt.exe bitcode flow. "
            "Set AMICE_ALLOW_WINDOWS_CLANG_PLUGIN=ON only if you know this DLL is clang-loadable.")
        set(AXVM_OLLVM OFF CACHE BOOL "" FORCE)
    else()
        message(STATUS "AXVM_OLLVM: AMICE plugin ${AMICE_PLUGIN}")
    endif()
endif()

function(axvm_apply_amice_obfuscation target)
    if(NOT AXVM_OLLVM OR NOT AMICE_PLUGIN)
        return()
    endif()
    target_compile_options(${target} PRIVATE
        "-fpass-plugin=${AMICE_PLUGIN}"
    )
    if(DEFINED ENV{AMICE_STRING_ENCRYPTION})
        message(STATUS "  ${target}: AMICE_STRING_ENCRYPTION=$ENV{AMICE_STRING_ENCRYPTION}")
    endif()
endfunction()
