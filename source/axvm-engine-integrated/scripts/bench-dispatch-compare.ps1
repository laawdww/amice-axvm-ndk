# 对比 computed goto vs switch 调度性能（需分别编译两次）
$ErrorActionPreference = "Stop"

$Root = "C:\Users\Administrator\Projects\axvm-engine"
$Sdk = "C:\Users\Administrator\AppData\Local\Android\Sdk"
$Ndk = "$Sdk\ndk\26.1.10909125"
$Cmake = "C:\Users\Administrator\Tools\cmake-3.28.1-windows-x86_64\bin\cmake.exe"
$Ninja = "C:\Users\Administrator\Tools\ninja\ninja.exe"
$Adb = "$Sdk\platform-tools\adb.exe"

function Build-And-Run {
    param([bool]$UseGoto, [string]$Label)

    $Build = Join-Path $Root "build-bench-$Label"
    if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }
    $GotoFlag = if ($UseGoto) { "ON" } else { "OFF" }

    & $Cmake -S $Root -B $Build -G Ninja "-DCMAKE_MAKE_PROGRAM=$Ninja" `
        -DCMAKE_TOOLCHAIN_FILE="$Ndk\build\cmake\android.toolchain.cmake" `
        -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 `
        -DCMAKE_BUILD_TYPE=Release -DAXVM_ENABLE_GUARD=ON `
        "-DAXVM_USE_COMPUTED_GOTO:BOOL=$UseGoto"
    & $Cmake --build $Build --target axvm_standalone -j 8

    $Bin = Join-Path $Build "target\axvm_standalone"
    & $Adb push $Bin /data/local/tmp/axvm_standalone | Out-Null
    & $Adb shell chmod 755 /data/local/tmp/axvm_standalone
    Write-Host "`n=== $Label (AXVM_USE_COMPUTED_GOTO=$GotoFlag) ===" -ForegroundColor Cyan
    & $Adb shell /data/local/tmp/axvm_standalone --bench-only --outer=40
}

Build-And-Run -UseGoto $true -Label "goto"
Build-And-Run -UseGoto $false -Label "switch"
