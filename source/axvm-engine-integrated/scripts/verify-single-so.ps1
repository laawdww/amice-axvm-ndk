# Full verification: NDK build + axpack + PIE + APK + logcat (amice-axvm-ndk tree)
$ErrorActionPreference = "Stop"

$Root = "C:\Users\Administrator\Projects\amice-axvm-ndk\source\axvm-engine-integrated"
$Sdk = "C:\Users\Administrator\AppData\Local\Android\Sdk"
$Ndk = "$Sdk\ndk\21.3.6528147"
$Cmake = "$Sdk\cmake\3.22.1\bin\cmake.exe"
$Ninja = "$Sdk\cmake\3.22.1\bin\ninja.exe"
$Jdk = "C:\Users\Administrator\Tools\jdk-17"
$GoBin = "C:\Users\Administrator\Tools\go\bin\go.exe"
$Build = "$Root\build-verify-arm64"
$Adb = "$Sdk\platform-tools\adb.exe"
$JniLibs = "$Root\android\app\src\main\jniLibs\arm64-v8a"
$Axpack = "$Root\build\axpack.exe"
$ApkPackage = "com.axvm.demo"
# Product path: embed runtime+JNI into victim; keep libaxvm for NativeVm MODULE_* only
$SingleSo = $true

function Get-DebugKeystoreCertSha256 {
    param([string]$KeytoolExe)
    $debugKs = Join-Path $env:USERPROFILE ".android\debug.keystore"
    if (-not (Test-Path $debugKs)) {
        throw "debug keystore not found: $debugKs (run Android Studio / gradle once)"
    }
    $tmpCer = Join-Path $env:TEMP ("axvm_debug_{0}.cer" -f [guid]::NewGuid().ToString("N"))
    try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $KeytoolExe -exportcert -alias androiddebugkey -keystore $debugKs `
            -storepass android -keypass android -file $tmpCer 2>$null | Out-Null
        $ErrorActionPreference = $prevEap
        if ($LASTEXITCODE -ne 0) { throw "keytool -exportcert failed" }
        $certBytes = [System.IO.File]::ReadAllBytes($tmpCer)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha.ComputeHash($certBytes)
        return -join ($hash | ForEach-Object { $_.ToString("x2") })
    } finally {
        if (Test-Path $tmpCer) { Remove-Item -Force $tmpCer }
    }
}

$env:ANDROID_HOME = $Sdk
$env:ANDROID_NDK_HOME = $Ndk
$env:JAVA_HOME = $Jdk
$env:Path = "$Jdk\bin;$Sdk\platform-tools;$env:Path"

Write-Host "=== 1. NDK Release build (atomics/NEON/embed) ==="
if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }

$cfgArgs = @(
    "-S", $Root,
    "-B", $Build,
    "-G", "Ninja",
    ("-DCMAKE_MAKE_PROGRAM=" + $Ninja),
    ("-DCMAKE_TOOLCHAIN_FILE=" + (Join-Path $Ndk "build\cmake\android.toolchain.cmake")),
    "-DANDROID_ABI=arm64-v8a",
    "-DANDROID_PLATFORM=android-24",
    "-DANDROID_STL=c++_static",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DAXVM_ENABLE_GUARD=ON",
    "-DAXVM_USE_COMPUTED_GOTO=ON",
    "-DAXVM_STACK_CRYPT=ON",
    "-DAXVM_FLOAT_VM=ON",
    "-DAXVM_LAZY_DECRYPT=ON",
    "-DAXVM_SO_INTEGRITY=ON",
    "-DAXVM_DYNAMIC_SEED=ON",
    "-DAXVM_STRCRYPT=ON",
    "-DAXVM_JIT_CACHE=ON",
    "-DAXVM_OPCODE_PERM=ON",
    "-DAXVM_REG_PERM=ON",
    "-DAXVM_JNI_GUARD=ON",
    "-DAXVM_GOT_CRYPT=ON",
    "-DAXVM_MEM_GUARD=ON",
    "-DAXVM_STEXT=ON",
    "-DAXVM_DISPATCH_PERM=ON",
    "-DAXVM_HANDLER_POLY=ON",
    "-DAXVM_LAZY_PF=ON",
    "-DAXVM_SVC_ANTIDEBUG=ON",
    "-DAXVM_WATCHDOG=ON",
    "-DAXVM_JIT_HARDEN=ON",
    "-DAXVM_RISCC_PERM=ON",
    "-DAXVM_NESTED_VM=ON",
    "-DAXVM_MULTI_ISA=ON",
    "-DAXVM_EMBED_RUNTIME=ON",
    "-DAXVM_SINGLE_SO=ON"
)
& $Cmake @cfgArgs
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
& $Cmake --build $Build -j 8
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }
Write-Host "NDK build OK: $Build"

Write-Host "`n=== 2. axpack go test + build ==="
New-Item -ItemType Directory -Force -Path "$Root\build" | Out-Null
Push-Location "$Root\tools\axpack"
& $GoBin test -count=1 ./...
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "go test failed" }
& $GoBin build -o $Axpack .
Pop-Location
Write-Host "axpack OK: $Axpack"

Write-Host "`n=== 3. PIE standalone on device ==="
$devices = & $Adb devices
Write-Host $devices
if ($devices -notmatch "device") { throw "no adb device" }

$Standalone = Join-Path $Build "target\axvm_standalone"
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
& $Adb push $Standalone "/data/local/tmp/axvm_verify_standalone" 2>$null | Out-Null
$ErrorActionPreference = $prevEap
if ($LASTEXITCODE -ne 0) { throw "adb push standalone failed" }
& $Adb shell "chmod 755 /data/local/tmp/axvm_verify_standalone"
Write-Host "--- standalone output ---"
& $Adb shell "/data/local/tmp/axvm_verify_standalone --outer=3" 2>&1
$pieExit = $LASTEXITCODE
Write-Host "standalone exit: $pieExit"

Write-Host "`n=== 4. axpack scan + apk-bind + APK (single-SO disk-ready) ==="
$VictimIn = Join-Path $Build "samples\victim\libvictim.so"
$VictimOut = "$Root\build\libvictim.ax.so"
$ScanReport = "$Root\build\scan-victim.json"
if (-not (Test-Path $VictimIn)) { throw "missing victim input: $VictimIn" }

Write-Host "--- axpack -scan ---"
& $Axpack -in $VictimIn -scan -report $ScanReport
if ($LASTEXITCODE -ne 0) { throw "axpack -scan failed" }

$Keytool = Join-Path $Jdk "bin\keytool.exe"
$CertHex = Get-DebugKeystoreCertSha256 -KeytoolExe $Keytool
Write-Host "debug signing cert sha256: $($CertHex.Substring(0,16))..."

$LlvmStrip = Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe"
$VictimStrip = "$Root\build\libvictim.stripped.so"
Copy-Item $VictimIn $VictimStrip -Force
& $LlvmStrip -s -o $VictimStrip $VictimStrip
if ($LASTEXITCODE -ne 0) { throw "llvm-strip input failed" }

Write-Host "--- axpack protect (single-SO: disk-ready + true atomics) ---"
& $Axpack -in $VictimStrip -out $VictimOut `
    -protect-level aggressive `
    -wipe -encrypt `
    -disk-ready `
    -stable-stub `
    -dep=- `
    -apk-bind -package $ApkPackage -apk-cert-sha256 $CertHex
if ($LASTEXITCODE -ne 0) { throw "axpack apk-bind failed" }

New-Item -ItemType Directory -Force -Path $JniLibs | Out-Null
Copy-Item $VictimOut (Join-Path $JniLibs "libvictim.so") -Force
$StaleAxvm = Join-Path $JniLibs "libaxvm.so"
if (Test-Path $StaleAxvm) { Remove-Item -Force $StaleAxvm }

Set-Location "$Root\android"
$gradleArgs = @("clean", "assembleDebug", "--no-daemon")
if ($SingleSo) {
    $gradleArgs = @("clean", "assembleDebug", "--no-daemon", "-PAXVM_SINGLE_SO=true")
}
& .\gradlew.bat @gradleArgs 2>&1 | Select-Object -Last 40
if ($LASTEXITCODE -ne 0) { throw "gradle failed" }

$Apk = "$Root\android\app\build\outputs\apk\debug\app-debug.apk"
if (Test-Path $Apk) {
    Write-Host "--- cross-check APK signing cert ---"
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $apkCertLine = (& $Axpack -print-apk-cert $Apk 2>$null | Select-Object -Last 1).Trim()
    $apkCert = ($apkCertLine -split "`t")[0].Trim()
    $ErrorActionPreference = $prevEap
    if ($apkCert -match "^[0-9a-f]{64}$") {
        if ($apkCert -ne $CertHex) {
            throw "APK cert sha256 mismatch: keystore=$CertHex apk=$apkCert"
        }
        Write-Host "APK cert matches debug keystore"
    } else {
        throw "print-apk-cert failed: $apkCert"
    }
}

$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
& $Adb install -r $Apk 2>$null | Out-Null
$ErrorActionPreference = $prevEap
if ($LASTEXITCODE -ne 0) { throw "adb install failed" }
& $Adb shell pm clear com.axvm.demo
& $Adb shell am force-stop com.axvm.demo
& $Adb logcat -c
$launchOut = & $Adb shell am start -W -n com.axvm.demo/.MainActivity 2>&1 | Out-String
Write-Host $launchOut.Trim()
if ($launchOut -match "TotalTime:\s*(\d+)") {
    $launchMs = [int]$Matches[1]
    Write-Host "Activity cold start: ${launchMs}ms"
    if ($launchMs -gt 5000) {
        throw "Activity launch too slow (${launchMs}ms) — possible main-thread ANR"
    }
} elseif ($launchOut -match "Status:\s*timeout") {
    throw "Activity launch timed out (am start -W) — main-thread ANR likely"
}

Write-Host "`n=== 5. logcat AXVM ==="
. (Join-Path $PSScriptRoot "Wait-AxvmLogcat.ps1")
$log = Wait-AxvmLogcat -Adb $Adb -Pattern "MODULE_AB: PASS" -TimeoutSec 120
$logText = ($log | Out-String)
$log | Select-Object -Last 50

$failPatterns = @("PACK: FAIL", "FATAL EXCEPTION", "SIGBUS", "APP_SCOUT_HANG")
$requiredPasses = @(
    "PACK: PASS",
    "MODULE_A: PASS",
    "MODULE_F: PASS",
    "MODULE_AB: PASS"
)
$hasFail = $false
foreach ($p in $failPatterns) {
    if ($logText -match $p) {
        Write-Host "WARNING: logcat matched $p"
        $hasFail = $true
    }
}
if ($logText -match "MODULE_\w+: FAIL") {
    Write-Host "WARNING: logcat matched MODULE FAIL"
    $hasFail = $true
}
foreach ($need in $requiredPasses) {
    if ($logText -notmatch [regex]::Escape($need)) {
        Write-Host "MISSING: $need"
        $hasFail = $true
    }
}

Write-Host "`n=== SUMMARY ==="
Write-Host "PIE exit: $pieExit (0=PASS)"
Write-Host "single-SO disk-ready + true atomics + NEON 2D/4S"
if ($hasFail) { Write-Host "APK logcat: ISSUES DETECTED"; exit 1 }
Write-Host "APK logcat: OK"
exit 0
