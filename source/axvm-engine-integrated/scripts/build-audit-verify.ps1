param(
    [string]$Guard = "ON",
    [string]$Jit = "OFF"
)

$ErrorActionPreference = "Stop"
$Root = "C:\Users\Administrator\Projects\axvm-engine"
$Cmake = "C:\Users\Administrator\Tools\cmake-3.28.1-windows-x86_64\bin\cmake.exe"
$Ninja = "C:\Users\Administrator\AppData\Local\Android\Sdk\cmake\3.22.1\bin\ninja.exe"
$Ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$Toolchain = Join-Path $Ndk "build\cmake\android.toolchain.cmake"
$Tag = "audit-G$Guard-J$Jit"
$BuildDir = Join-Path $Root ("build-audit-" + $Tag)

if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$cfgArgs = @(
    "-S", $Root,
    "-B", $BuildDir,
    "-G", "Ninja",
    ("-DCMAKE_MAKE_PROGRAM=" + $Ninja),
    ("-DCMAKE_TOOLCHAIN_FILE=" + $Toolchain),
    "-DANDROID_ABI=arm64-v8a",
    "-DANDROID_PLATFORM=android-24",
    "-DANDROID_STL=c++_static",
    "-DCMAKE_BUILD_TYPE=Release",
    ("-DAXVM_ENABLE_GUARD=" + $Guard),
    "-DAXVM_FLOAT_VM=ON",
    "-DAXVM_LAZY_DECRYPT=ON",
    "-DAXVM_STRCRYPT=ON",
    "-DAXVM_SO_INTEGRITY=ON",
    ("-DAXVM_JIT_CACHE=" + $Jit),
    "-DAXVM_OLLVM=OFF"
)

& $Cmake @cfgArgs
if ($LASTEXITCODE -ne 0) { throw "configure failed" }

& $Cmake --build $BuildDir -j 8
if ($LASTEXITCODE -ne 0) { throw "build failed" }

Write-Host "OK build: $BuildDir"
Write-Host "Standalone: $(Join-Path $BuildDir 'target\axvm_standalone')"
