cmake_minimum_required(VERSION 3.18)

# 供 NDK 外部 toolchain 引用
if(NOT ANDROID)
    message(STATUS "AXVM: 非 Android 构建，跳过 log 链接适配")
endif()
