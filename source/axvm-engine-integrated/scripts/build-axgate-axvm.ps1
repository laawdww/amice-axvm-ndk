# Build delivery libaxvm.so wrapped by axgate (MEMFD_ELF host).
# 1) plain interpreter (DEMO_JNI=OFF)
# 2) axgatepack -> blob.c
# 3) link axgate_host as libaxvm.so
# 4) copy to amice-axvm-ndk/artifacts + optional jniLibs
param(
    [string]$JniOut = "",
    [switch]$SkipInnerRebuild
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$SdkRoot = $env:ANDROID_HOME
if (-not $SdkRoot) { $SdkRoot = Join-Path $env:LOCALAPPDATA "Android\Sdk" }
$Ndk = $env:ANDROID_NDK_HOME
if (-not $Ndk) {
    foreach ($cand in @(
        (Join-Path $SdkRoot "ndk\29.0.14206865"),
        (Join-Path $SdkRoot "ndk\26.1.10909125"),
        (Join-Path $SdkRoot "ndk\21.3.6528147")
    )) {
        if (Test-Path $cand) { $Ndk = $cand; break }
    }
}
$Cmake = Join-Path $SdkRoot "cmake\3.22.1\bin\cmake.exe"
$Ninja = Join-Path $SdkRoot "cmake\3.22.1\bin\ninja.exe"
if (-not (Test-Path $Cmake)) { throw "cmake not found" }
if (-not $Ndk -or -not (Test-Path $Ndk)) { throw "NDK not found" }
$Toolchain = Join-Path $Ndk "build\cmake\android.toolchain.cmake"

$Artifacts = Join-Path (Split-Path -Parent (Split-Path -Parent $Root)) "artifacts"
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null
$RepoArt = $Artifacts
$BuildDir = Join-Path $Root "build-ndk-arm64"
$InnerSo = Join-Path $RepoArt "libaxvm.inner.so"
$HostSo = Join-Path $RepoArt "libaxvm.so"
$PackDir = Join-Path $Root "shell\tools\axgatepack"
$BlobC = Join-Path $BuildDir "axgate_blob.c"
$BlobBin = Join-Path $BuildDir "axgate_blob.bin"
$UkC = Join-Path $BuildDir "axgate_uk.c"
$ApkPkg = if ($env:AXGATE_APK_PKG) { $env:AXGATE_APK_PKG } else { "com.example.iauuwnno" }
$ApkCert = if ($env:AXGATE_APK_CERT) { $env:AXGATE_APK_CERT } else { "DF0178FAEF54B854AD02CFC43E76F623FDBF5EC5C8DBF8F76C180D264A7562D9" }

if (-not $SkipInnerRebuild) {
    Write-Host "=== build delivery interpreter (inner) ==="
    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    }
    & $Cmake -S $Root -B $BuildDir -G Ninja "-DCMAKE_MAKE_PROGRAM=$Ninja" `
        "-DCMAKE_TOOLCHAIN_FILE=$Toolchain" `
        "-DANDROID_ABI=arm64-v8a" `
        "-DANDROID_PLATFORM=android-24" `
        "-DANDROID_STL=c++_static" `
        "-DCMAKE_BUILD_TYPE=Release" `
        "-DAXVM_ENABLE_GUARD=ON" `
        "-DAXVM_DEMO_JNI=OFF" `
        "-DAXVM_LAZY_PF=OFF" `
        "-DAXVM_BUILD_AXGATE=ON"
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
    # Force relink axvm target
    $old = Get-ChildItem $BuildDir -Recurse -Filter "libaxvm.so" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "axgate_host" } | Select-Object -First 1
    if ($old) { Remove-Item $old.FullName -Force -ErrorAction SilentlyContinue }
    & $Cmake --build $BuildDir -j 8 --target axvm
    if ($LASTEXITCODE -ne 0) { throw "axvm (inner) build failed" }
    $built = Get-ChildItem $BuildDir -Recurse -Filter "libaxvm.so" |
        Where-Object { $_.DirectoryName -match "target$" -or $_.FullName -match "\\target\\" } |
        Select-Object -First 1
    if (-not $built) {
        $built = Get-ChildItem $BuildDir -Recurse -Filter "libaxvm.so" |
            Sort-Object Length -Descending | Select-Object -First 1
    }
    if (-not $built) { throw "inner libaxvm.so not found" }
    Copy-Item $built.FullName $InnerSo -Force
    Write-Host "inner: $InnerSo size=$($built.Length)"
} else {
    if (-not (Test-Path $InnerSo)) { throw "missing $InnerSo (run without -SkipInnerRebuild)" }
}

Write-Host "=== axgatepack memfd (KEY_WRAP + bind) ==="
$env:PATH = "C:\Program Files\Go\bin;" + $env:PATH
Push-Location $PackDir
try {
    & go run . -in $InnerSo -mode memfd -no-antidebug `
        -out $BlobBin -c $BlobC -uk $UkC `
        -apk-pkg $ApkPkg -apk-cert-sha256 $ApkCert
    if ($LASTEXITCODE -ne 0) { throw "axgatepack failed" }
} finally {
    Pop-Location
}

Write-Host "=== build axgate host (outer libaxvm.so) ==="
& $Cmake -S $Root -B $BuildDir -G Ninja "-DCMAKE_MAKE_PROGRAM=$Ninja" `
    "-DCMAKE_TOOLCHAIN_FILE=$Toolchain" `
    "-DANDROID_ABI=arm64-v8a" `
    "-DANDROID_PLATFORM=android-24" `
    "-DANDROID_STL=c++_static" `
    "-DCMAKE_BUILD_TYPE=Release" `
    "-DAXVM_DEMO_JNI=OFF" `
    "-DAXVM_BUILD_AXGATE=ON" `
    "-DAXGATE_BLOB_C=$BlobC" `
    "-DAXGATE_UK_C=$UkC"
if ($LASTEXITCODE -ne 0) { throw "cmake reconfigure host failed" }
& $Cmake --build $BuildDir -j 8 --target axgate_host
if ($LASTEXITCODE -ne 0) { throw "axgate_host build failed" }

$hostBuilt = Get-ChildItem $BuildDir -Recurse -Filter "libaxvm.so" |
    Where-Object { $_.DirectoryName -match "host" -or $_.FullName -match "\\host\\" } |
    Select-Object -First 1
if (-not $hostBuilt) {
    # OUTPUT_NAME axvm may land under shell/host/
    $hostBuilt = Get-ChildItem $BuildDir -Recurse -Filter "libaxvm.so" |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if (-not $hostBuilt) { throw "host libaxvm.so not found" }
Copy-Item $hostBuilt.FullName $HostSo -Force
Write-Host "host: $HostSo size=$($hostBuilt.Length)"

if ($JniOut) {
    New-Item -ItemType Directory -Force -Path $JniOut | Out-Null
    Copy-Item $HostSo (Join-Path $JniOut "libaxvm.so") -Force
    Write-Host "copied -> $JniOut\libaxvm.so"
}

Write-Host "OK axgate-wrapped libaxvm.so"
