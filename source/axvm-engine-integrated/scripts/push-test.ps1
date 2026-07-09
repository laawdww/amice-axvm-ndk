# Push and run standalone test on rooted device
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$SdkRoot = $env:ANDROID_HOME
if (-not $SdkRoot) { $SdkRoot = "C:\Users\Administrator\AppData\Local\Android\Sdk" }
$Adb = Join-Path $SdkRoot "platform-tools\adb.exe"
$Bin = Join-Path $Root "build-ndk-arm64\target\axvm_standalone"
$Remote = "/data/local/tmp/axvm"

if (-not (Test-Path $Bin)) { throw "binary not found, run build-ndk.ps1 first" }

& $Adb devices
& $Adb shell "mkdir -p $Remote"
& $Adb push $Bin "${Remote}/axvm_standalone"
& $Adb shell "chmod 755 ${Remote}/axvm_standalone && ${Remote}/axvm_standalone"
