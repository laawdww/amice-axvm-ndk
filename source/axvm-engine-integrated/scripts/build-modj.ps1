# 模块 J：热点 BasicBlock JIT 缓存 —— 分别构建 AXVM_JIT_CACHE ON/OFF，
# 推送 PIE 到设备(若在线)并运行标准自检 + JIT ON/OFF 基准对比。
$ErrorActionPreference = "Stop"

$Root  = "C:\Users\Administrator\Projects\axvm-engine"
$Sdk   = "C:\Users\Administrator\AppData\Local\Android\Sdk"
$Ndk   = "$Sdk\ndk\26.1.10909125"
$Cmake = "C:\Users\Administrator\Tools\cmake-3.28.1-windows-x86_64\bin\cmake.exe"
$Ninja = "C:\Users\Administrator\Tools\ninja\ninja.exe"
$Adb   = "$Sdk\platform-tools\adb.exe"
$Dev   = "/data/local/tmp/axvm_modj"

function Build-Std {
    param([string]$Jit, [string]$Label)

    $Build = Join-Path $Root "build-modj-$Label"
    if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }

    $cfg = @(
        "-S", $Root,
        "-B", $Build,
        "-G", "Ninja",
        "-DCMAKE_MAKE_PROGRAM=$Ninja",
        "-DCMAKE_TOOLCHAIN_FILE=$Ndk\build\cmake\android.toolchain.cmake",
        "-DANDROID_ABI=arm64-v8a",
        "-DANDROID_PLATFORM=android-24",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DAXVM_JIT_CACHE:BOOL=$Jit"
    )
    & $Cmake @cfg
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed ($Label)" }
    & $Cmake --build $Build --target axvm_standalone -j 8
    if ($LASTEXITCODE -ne 0) { throw "cmake build failed ($Label)" }
}

function Run-OnDevice {
    param([string]$Label)

    $Bin = Join-Path $Root "build-modj-$Label\target\axvm_standalone"
    $online = (& $Adb devices | Select-String "device$")
    if (-not $online) {
        Write-Host "== $Label : no device online, skipping on-device run ==" -ForegroundColor Yellow
        return
    }
    & $Adb shell "mkdir -p $Dev" | Out-Null
    $remote = "$Dev/axvm_standalone_$Label"
    & $Adb push $Bin $remote | Out-Host
    & $Adb shell "chmod 755 $remote"
    Write-Host "==================== $Label (AXVM_JIT_CACHE=$Label) ====================" -ForegroundColor Cyan
    & $Adb shell "$remote --outer=60"
    Write-Host ""
}

Build-Std -Jit "ON"  -Label "ON"
Build-Std -Jit "OFF" -Label "OFF"

Run-OnDevice -Label "ON"
Run-OnDevice -Label "OFF"
