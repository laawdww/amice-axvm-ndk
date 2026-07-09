param([string]$Seed = "BOTH", [switch]$Run)

# 模块 M — 双层动态种子 构建/设备验证脚本。
#   -Seed ON|OFF|BOTH  选择 AXVM_DYNAMIC_SEED 配置（默认 BOTH）
#   -Run               构建后推送 standalone 到 adb 设备并运行

$ErrorActionPreference = "Stop"
$Root = "C:\Users\Administrator\Projects\axvm-engine"
$Cmake = "C:\Users\Administrator\Tools\cmake-3.28.1-windows-x86_64\bin\cmake.exe"
$Ninja = "C:\Users\Administrator\AppData\Local\Android\Sdk\cmake\3.22.1\bin\ninja.exe"
$Ndk = "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125"
$Toolchain = Join-Path $Ndk "build\cmake\android.toolchain.cmake"
$Adb = "C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe"
$Dev = "/data/local/tmp/axvm_modm"

$seeds = @()
switch ($Seed.ToUpper()) {
    "ON"   { $seeds = @("ON") }
    "OFF"  { $seeds = @("OFF") }
    default { $seeds = @("ON", "OFF") }
}

if ($Run) { & $Adb shell "mkdir -p $Dev" | Out-Null }

foreach ($s in $seeds) {
    $tag = "DS$s"
    $BuildDir = Join-Path $Root ("build-modm-" + $tag)
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
        ("-DAXVM_DYNAMIC_SEED=" + $s),
        "-DAXVM_STACK_CRYPT=ON",
        "-DAXVM_LAZY_DECRYPT=ON",
        "-DAXVM_SO_INTEGRITY=ON",
        "-DAXVM_ENABLE_GUARD=ON"
    )

    Write-Host "==================== build AXVM_DYNAMIC_SEED=$s ===================="
    & $Cmake @cfgArgs
    if ($LASTEXITCODE -ne 0) { throw "configure failed ($s)" }
    & $Cmake --build $BuildDir -j 8
    if ($LASTEXITCODE -ne 0) { throw "build failed ($s)" }
    Write-Host "OK build: $BuildDir"

    if ($Run) {
        $bin = Join-Path $BuildDir "target\axvm_standalone"
        if (-not (Test-Path $bin)) { throw "standalone missing: $bin" }
        $remote = "$Dev/axvm_standalone_$tag"
        & $Adb push $bin $remote | Out-Null
        & $Adb shell "chmod 755 $remote"
        Write-Host "-------------------- run $tag --------------------"
        & $Adb shell "$remote --outer=5"
        Write-Host ""
    }
}
