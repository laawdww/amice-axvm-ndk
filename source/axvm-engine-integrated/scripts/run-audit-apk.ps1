$ErrorActionPreference = "Stop"
$Root = "C:\Users\Administrator\Projects\axvm-engine"
$Sdk = "C:\Users\Administrator\AppData\Local\Android\Sdk"
$Ndk = "$Sdk\ndk\26.1.10909125"
$Cmake = "C:\Users\Administrator\Tools\cmake-3.28.1-windows-x86_64\bin\cmake.exe"
$Ninja = "C:\Users\Administrator\AppData\Local\Android\Sdk\cmake\3.22.1\bin\ninja.exe"
$Jdk = "C:\Users\Administrator\Tools\jdk-17"
$Build = "$Root\build-audit-apk"
$JniLibs = "$Root\android\app\src\main\jniLibs\arm64-v8a"
$Adb = "$Sdk\platform-tools\adb.exe"
$Device = "8a08ca71"

$env:ANDROID_HOME = $Sdk
$env:ANDROID_NDK_HOME = $Ndk
$env:JAVA_HOME = $Jdk
$env:Path = "$Jdk\bin;$Sdk\platform-tools;$env:Path"

if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }
& $Cmake -S $Root -B $Build -G Ninja "-DCMAKE_MAKE_PROGRAM=$Ninja" `
    -DCMAKE_TOOLCHAIN_FILE="$Ndk\build\cmake\android.toolchain.cmake" `
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 -DANDROID_STL=c++_static `
    -DCMAKE_BUILD_TYPE=Release -DAXVM_ENABLE_GUARD=ON -DAXVM_STRCRYPT=ON `
    -DAXVM_JIT_CACHE=OFF -DAXVM_SO_INTEGRITY=ON
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
& $Cmake --build $Build -j 8
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

$VictimIn = Join-Path $Build "samples\victim\libvictim.so"
$AxvmSo = Join-Path $Build "target\libaxvm.so"
if (-not (Test-Path $VictimIn)) { throw "libvictim.so missing" }

$Go = "go"
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    $Go = "C:\Users\Administrator\Tools\go122\bin\go.exe"
}
Push-Location "$Root\tools\axpack"
& $Go build -o "$Root\build\axpack.exe" .
Pop-Location

$VictimOut = "$Root\build\libvictim.ax.so"
& "$Root\build\axpack.exe" -in $VictimIn -out $VictimOut -syms "victim_add,victim_mul,victim_check,victim_mixed,victim_fadd,victim_fmul" -wipe -encrypt -no-patch

New-Item -ItemType Directory -Force -Path $JniLibs | Out-Null
Copy-Item $VictimOut (Join-Path $JniLibs "libvictim.so") -Force
Copy-Item $AxvmSo (Join-Path $JniLibs "libaxvm.so") -Force

Set-Location "$Root\android"
& .\gradlew.bat assembleDebug --no-daemon
if ($LASTEXITCODE -ne 0) { throw "gradle failed" }

$Apk = "$Root\android\app\build\outputs\apk\debug\app-debug.apk"
& $Adb -s $Device install -r $Apk
& $Adb -s $Device shell am force-stop com.axvm.demo
& $Adb -s $Device logcat -c
& $Adb -s $Device shell am start -n com.axvm.demo/.MainActivity
Start-Sleep -Seconds 4
Write-Host "=== logcat AXVM ==="
& $Adb -s $Device logcat -d -s AXVM:* AndroidRuntime:E | Select-Object -Last 40
