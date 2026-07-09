# Windows NDK cross-compile for axvm-engine
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$SdkRoot = $env:ANDROID_HOME
if (-not $SdkRoot) { $SdkRoot = "C:\Users\Administrator\AppData\Local\Android\Sdk" }
$Ndk = $env:ANDROID_NDK_HOME
if (-not $Ndk) { $Ndk = Join-Path $SdkRoot "ndk\26.1.10909125" }

$Cmake = Join-Path $env:USERPROFILE "Tools\cmake-3.28.1-windows-x86_64\bin\cmake.exe"
if (-not (Test-Path $Cmake)) {
    $Cmake = Join-Path $SdkRoot "cmake\3.22.1\bin\cmake.exe"
}
if (-not (Test-Path $Cmake)) { throw "cmake not found" }
if (-not (Test-Path $Ndk)) { throw "NDK not found: $Ndk" }

$BuildDir = Join-Path $Root "build-ndk-arm64"
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$Ninja = Join-Path $env:USERPROFILE "Tools\ninja\ninja.exe"
if (-not (Test-Path $Ninja)) { throw "ninja not found: $Ninja" }

$Toolchain = Join-Path $Ndk "build\cmake\android.toolchain.cmake"

& $Cmake -S $Root -B $BuildDir -G Ninja -DCMAKE_MAKE_PROGRAM=$Ninja `
    -DCMAKE_TOOLCHAIN_FILE=$Toolchain `
    -DANDROID_ABI=arm64-v8a `
    -DANDROID_PLATFORM=android-24 `
    -DANDROID_STL=c++_static `
    -DCMAKE_BUILD_TYPE=Release `
    -DAXVM_ENABLE_GUARD=ON

& $Cmake --build $BuildDir -j 8

Write-Host ""
Write-Host "Build outputs:"
Write-Host (Join-Path $BuildDir "target\axvm_standalone")
Write-Host (Join-Path $BuildDir "target\libaxvm.so")
