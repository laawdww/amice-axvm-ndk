# Build debug APK, install and launch on device
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$AndroidDir = Join-Path $Root "android"
$SdkRoot = "C:\Users\Administrator\AppData\Local\Android\Sdk"
$Jdk = "C:\Users\Administrator\Tools\jdk-17"
$Adb = Join-Path $SdkRoot "platform-tools\adb.exe"
$Apk = Join-Path $AndroidDir "app\build\outputs\apk\debug\app-debug.apk"

$env:ANDROID_HOME = $SdkRoot
$env:ANDROID_SDK_ROOT = $SdkRoot
$env:JAVA_HOME = $Jdk
$env:Path = "$Jdk\bin;$SdkRoot\platform-tools;$env:Path"

Push-Location $AndroidDir
try {
    .\gradlew.bat assembleDebug --no-daemon
    if (-not (Test-Path $Apk)) { throw "APK not found" }

    & $Adb devices
    & $Adb install -r $Apk
    & $Adb shell am force-stop com.axvm.demo
    & $Adb logcat -c
    & $Adb shell am start -n com.axvm.demo/.MainActivity
    Start-Sleep -Seconds 2
    & $Adb logcat -d -s AXVM:* | Select-Object -Last 10
} finally {
    Pop-Location
}
