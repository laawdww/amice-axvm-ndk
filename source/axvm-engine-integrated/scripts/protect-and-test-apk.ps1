# Lighter pipeline: NDK build -> axpack (apk-bind) -> APK -> install
$ErrorActionPreference = "Stop"

$Root = "C:\Users\Administrator\Projects\axvm-engine"
$Sdk = "C:\Users\Administrator\AppData\Local\Android\Sdk"
$Ndk = "$Sdk\ndk\26.1.10909125"
$Cmake = "C:\Users\Administrator\Tools\cmake-3.28.1-windows-x86_64\bin\cmake.exe"
$Jdk = "C:\Users\Administrator\Tools\jdk-17"
$Build = "$Root\build-ndk-arm64"
$JniLibs = "$Root\android\app\src\main\jniLibs\arm64-v8a"
$Go = "$Root\tools\go1.22.10\bin\go.exe"
if (-not (Test-Path $Go)) { $Go = "go" }
$ApkPackage = "com.axvm.demo"

function Get-DebugKeystoreCertSha256 {
    param([string]$KeytoolExe)
    $debugKs = Join-Path $env:USERPROFILE ".android\debug.keystore"
    if (-not (Test-Path $debugKs)) {
        throw "debug keystore not found: $debugKs"
    }
    $tmpCer = Join-Path $env:TEMP ("axvm_debug_{0}.cer" -f [guid]::NewGuid().ToString("N"))
    try {
        & $KeytoolExe -exportcert -alias androiddebugkey -keystore $debugKs `
            -storepass android -keypass android -file $tmpCer 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "keytool failed" }
        $certBytes = [System.IO.File]::ReadAllBytes($tmpCer)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        return -join ($sha.ComputeHash($certBytes) | ForEach-Object { $_.ToString("x2") })
    } finally {
        if (Test-Path $tmpCer) { Remove-Item -Force $tmpCer }
    }
}

$env:ANDROID_HOME = $Sdk
$env:ANDROID_NDK_HOME = $Ndk
$env:JAVA_HOME = $Jdk
$env:Path = "$Jdk\bin;$Sdk\platform-tools;$env:Path"

if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }
& $Cmake -S $Root -B $Build -G Ninja "-DCMAKE_MAKE_PROGRAM=C:/Users/Administrator/Tools/ninja/ninja.exe" `
    -DCMAKE_TOOLCHAIN_FILE="$Ndk\build\cmake\android.toolchain.cmake" `
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 `
    -DCMAKE_BUILD_TYPE=Release -DAXVM_ENABLE_GUARD=ON -DAXVM_DYNAMIC_SEED=ON
& $Cmake --build $Build -j 8

$VictimIn = Join-Path $Build "samples\victim\libvictim.so"
if (-not (Test-Path $VictimIn)) { throw "libvictim.so missing" }

Push-Location "$Root\tools\axpack"
& $Go test -count=1 ./...
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "go test failed" }
& $Go build -o "$Root\build\axpack.exe" .
Pop-Location

$Keytool = Join-Path $Jdk "bin\keytool.exe"
$CertHex = Get-DebugKeystoreCertSha256 -KeytoolExe $Keytool
$VictimOut = "$Root\build\libvictim.ax.so"
& "$Root\build\axpack.exe" -in $VictimIn -out $VictimOut `
    -syms "victim_add,victim_mul,victim_check,victim_mixed,victim_fadd,victim_fmul" `
    -wipe -encrypt -no-patch -dep=- `
    -apk-bind -package $ApkPackage -apk-cert-sha256 $CertHex
if ($LASTEXITCODE -ne 0) { throw "axpack failed" }

New-Item -ItemType Directory -Force -Path $JniLibs | Out-Null
Copy-Item $VictimOut (Join-Path $JniLibs "libvictim.so") -Force

Set-Location "$Root\android"
.\gradlew.bat clean assembleDebug --no-daemon 2>&1 | Select-Object -Last 8

$Adb = "$Sdk\platform-tools\adb.exe"
$Apk = "$Root\android\app\build\outputs\apk\debug\app-debug.apk"
& $Adb install -r $Apk
& $Adb shell pm clear com.axvm.demo
& $Adb logcat -c
& $Adb shell am start -W -n com.axvm.demo/.MainActivity
. (Join-Path $PSScriptRoot "Wait-AxvmLogcat.ps1")
$log = Wait-AxvmLogcat -Adb $Adb -Pattern "PACK:" -TimeoutSec 60
$log | Select-String -Pattern "PACK:|scan skip|prepatch"
