# 免 Java：直接下载 platform-tools + NDK + CMake
$ErrorActionPreference = "Stop"

$SdkRoot = "C:\Users\Administrator\AppData\Local\Android\Sdk"
$ToolsDir = "C:\Users\Administrator\Tools"
New-Item -ItemType Directory -Force -Path $SdkRoot, $ToolsDir | Out-Null

function Download-Expand($Url, $DestDir, $Label) {
    $zip = Join-Path $env:TEMP ("dl_" + [guid]::NewGuid().ToString() + ".zip")
    Write-Host "下载 $Label ..."
    Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
    Expand-Archive -Path $zip -DestinationPath $DestDir -Force
    Remove-Item $zip -Force
}

# platform-tools
if (-not (Test-Path "$SdkRoot\platform-tools\adb.exe")) {
    $ptTmp = "$env:TEMP\pt"
    if (Test-Path $ptTmp) { Remove-Item -Recurse -Force $ptTmp }
    Download-Expand "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" $ptTmp "platform-tools"
    Copy-Item -Recurse -Force "$ptTmp\platform-tools" "$SdkRoot\"
    Remove-Item -Recurse -Force $ptTmp
}

# NDK r26b
$NdkDir = "$SdkRoot\ndk\26.1.10909125"
if (-not (Test-Path "$NdkDir\build\cmake\android.toolchain.cmake")) {
    $ndkTmp = "$env:TEMP\ndk"
    if (Test-Path $ndkTmp) { Remove-Item -Recurse -Force $ndkTmp }
    Download-Expand "https://dl.google.com/android/repository/android-ndk-r26b-windows.zip" $ndkTmp "NDK r26b"
    New-Item -ItemType Directory -Force -Path "$SdkRoot\ndk" | Out-Null
    $extracted = Get-ChildItem $ndkTmp -Directory | Select-Object -First 1
    Move-Item -Force $extracted.FullName $NdkDir
    Remove-Item -Recurse -Force $ndkTmp
}

# CMake + Ninja (host build tools)
$CmakeDir = "$ToolsDir\cmake-3.28.1-windows-x86_64"
if (-not (Test-Path "$CmakeDir\bin\cmake.exe")) {
    $cmTmp = "$env:TEMP\cmake"
    if (Test-Path $cmTmp) { Remove-Item -Recurse -Force $cmTmp }
    Download-Expand "https://github.com/Kitware/CMake/releases/download/v3.28.1/cmake-3.28.1-windows-x86_64.zip" $cmTmp "CMake"
    $extracted = Get-ChildItem $cmTmp -Directory | Select-Object -First 1
    Move-Item -Force $extracted.FullName $CmakeDir
    Remove-Item -Recurse -Force $cmTmp
}

$NinjaDir = "$ToolsDir\ninja"
if (-not (Test-Path "$NinjaDir\ninja.exe")) {
    $nz = "$env:TEMP\ninja-win.zip"
    Invoke-WebRequest -Uri "https://github.com/ninja-build/ninja/releases/download/v1.11.1/ninja-win.zip" -OutFile $nz -UseBasicParsing
    New-Item -ItemType Directory -Force -Path $NinjaDir | Out-Null
    Expand-Archive $nz -DestinationPath $NinjaDir -Force
    Remove-Item $nz -Force
}

# 环境变量
[Environment]::SetEnvironmentVariable("ANDROID_HOME", $SdkRoot, "User")
[Environment]::SetEnvironmentVariable("ANDROID_SDK_ROOT", $SdkRoot, "User")
[Environment]::SetEnvironmentVariable("ANDROID_NDK_HOME", $NdkDir, "User")

$oldPath = [Environment]::GetEnvironmentVariable("Path", "User")
$CmakeBin = "$CmakeDir\bin\cmake.exe"
$add = @("$SdkRoot\platform-tools", "$CmakeDir\bin", "$NinjaDir")
foreach ($p in $add) {
    if ($oldPath -notlike "*$p*") { $oldPath = "$oldPath;$p" }
}
[Environment]::SetEnvironmentVariable("Path", $oldPath, "User")

$env:ANDROID_HOME = $SdkRoot
$env:ANDROID_NDK_HOME = $NdkDir
$env:Path = "$SdkRoot\platform-tools;$CmakeDir\bin;$env:Path"

Write-Host ""
Write-Host "=== 验证 ==="
& "$SdkRoot\platform-tools\adb.exe" version
& $CmakeBin --version | Select-Object -First 1
Write-Host "NDK: $NdkDir"
& "$SdkRoot\platform-tools\adb.exe" devices
