$ErrorActionPreference = "Stop"

$Root  = "C:\Users\Administrator\Projects\axvm-engine"
$Cmake = "C:\Users\Administrator\Tools\cmake-3.28.1-windows-x86_64\bin\cmake.exe"
$Ninja = "C:\Users\Administrator\AppData\Local\Android\Sdk\cmake\3.22.1\bin\ninja.exe"
$Ndk   = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$Tc    = "$Ndk\build\cmake\android.toolchain.cmake"

function Build-Cfg {
    param([string]$Label, [string]$BuildType, [hashtable]$Opts)

    $Build = Join-Path $Root "build-audit-$Label"
    if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }

    $args = @(
        "-S", $Root, "-B", $Build, "-G", "Ninja",
        "-DCMAKE_MAKE_PROGRAM=$Ninja",
        "-DCMAKE_TOOLCHAIN_FILE=$Tc",
        "-DANDROID_ABI=arm64-v8a",
        "-DANDROID_PLATFORM=android-24",
        "-DANDROID_STL=c++_static",
        "-DCMAKE_BUILD_TYPE=$BuildType"
    )
    foreach ($k in $Opts.Keys) { $args += "-D$k=$($Opts[$k])" }

    Write-Host "==================== CONFIGURE $Label ($BuildType) ====================" -ForegroundColor Cyan
    & $Cmake @args
    if ($LASTEXITCODE -ne 0) { throw "configure failed: $Label" }

    Write-Host "==================== BUILD $Label ====================" -ForegroundColor Cyan
    & $Cmake --build $Build --target axvm_standalone -j 8
    if ($LASTEXITCODE -ne 0) { throw "build failed: $Label" }

    $Bin = Join-Path $Build "target\axvm_standalone"
    if (-not (Test-Path $Bin)) { throw "missing binary: $Bin" }
    Write-Host "OK -> $Bin" -ForegroundColor Green
}

Build-Cfg -Label "default"   -BuildType "Release" -Opts @{
    AXVM_ENABLE_GUARD="ON"; AXVM_USE_COMPUTED_GOTO="ON"; AXVM_STACK_CRYPT="ON";
    AXVM_FLOAT_VM="ON"; AXVM_LAZY_DECRYPT="ON" }

Build-Cfg -Label "dbg-float" -BuildType "Debug" -Opts @{
    AXVM_ENABLE_GUARD="ON"; AXVM_USE_COMPUTED_GOTO="ON"; AXVM_STACK_CRYPT="ON";
    AXVM_FLOAT_VM="ON"; AXVM_LAZY_DECRYPT="ON" }

Build-Cfg -Label "float-off" -BuildType "Release" -Opts @{
    AXVM_ENABLE_GUARD="ON"; AXVM_USE_COMPUTED_GOTO="ON"; AXVM_STACK_CRYPT="ON";
    AXVM_FLOAT_VM="OFF"; AXVM_LAZY_DECRYPT="ON" }

Build-Cfg -Label "switch"    -BuildType "Release" -Opts @{
    AXVM_ENABLE_GUARD="ON"; AXVM_USE_COMPUTED_GOTO="OFF"; AXVM_STACK_CRYPT="ON";
    AXVM_FLOAT_VM="ON"; AXVM_LAZY_DECRYPT="ON" }

Write-Host "ALL BUILDS OK" -ForegroundColor Green
