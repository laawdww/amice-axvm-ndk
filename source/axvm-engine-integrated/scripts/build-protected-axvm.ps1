param(
    [string]$Root = "",
    [string]$Build = "",
    [string]$Ndk = $env:ANDROID_NDK_HOME,
    [string]$Cmake = "cmake",
    [string]$Ninja = "",
    [string]$Go = "go",
    [switch]$EnableOllvm,
    [string]$AmicePlugin = $env:AMICE_PLUGIN,
    [switch]$AllowWindowsClangPlugin,
    [switch]$EmbedRuntime,
    [switch]$RebuildAxpack,
    [string]$InputSo = "",
    [string]$OutputSo = "",
    [string]$Symbols = "",
    [string]$RuntimeDependency = "libaxvm.so",
    [switch]$PatchEntries,
    [switch]$ApkBind,
    [string]$Package = "",
    [string]$Apk = "",
    [string]$ApkCertSha256 = ""
)

$ErrorActionPreference = "Stop"

function Fail($Message) {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Need-Path($Path, $Name) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        Fail "$Name was not found: $Path"
    }
}

if (-not $Root) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
if (-not $Build) {
    $Build = Join-Path $Root "build-ndk-r28c-arm64-protected"
}

Need-Path $Root "Root"
Need-Path $Ndk "Android NDK. Set ANDROID_NDK_HOME or pass -Ndk"

$toolchain = Join-Path $Ndk "build\cmake\android.toolchain.cmake"
Need-Path $toolchain "Android CMake toolchain"

$axpack = Join-Path $Root "build\axpack.exe"
if ($RebuildAxpack -or -not (Test-Path -LiteralPath $axpack)) {
    Write-Host "Building axpack..."
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $axpack) | Out-Null
    Push-Location (Join-Path $Root "tools\axpack")
    try {
        & $Go build -o $axpack .
        if ($LASTEXITCODE -ne 0) { Fail "go build axpack failed" }
    }
    finally {
        Pop-Location
    }
}
Need-Path $axpack "axpack"

$env:ANDROID_NDK_HOME = $Ndk

$cfgArgs = @(
    "-S", $Root,
    "-B", $Build,
    "-DANDROID_ABI=arm64-v8a",
    "-DANDROID_PLATFORM=android-24",
    "-DCMAKE_TOOLCHAIN_FILE=$toolchain",
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
    "-DAXVM_MULTI_ISA=ON"
)

if ($Ninja) {
    Need-Path $Ninja "Ninja"
    $cfgArgs += @("-G", "Ninja", "-DCMAKE_MAKE_PROGRAM=$Ninja")
}

if ($EmbedRuntime) {
    $cfgArgs += "-DAXVM_EMBED_RUNTIME=ON"
}

if ($EnableOllvm) {
    if (-not $AmicePlugin) {
        Fail "-EnableOllvm requires -AmicePlugin or AMICE_PLUGIN"
    }
    Need-Path $AmicePlugin "AMICE plugin"
    $cfgArgs += @("-DAXVM_OLLVM=ON", "-DAMICE_PLUGIN=$AmicePlugin")
    if ($AllowWindowsClangPlugin) {
        $cfgArgs += "-DAMICE_ALLOW_WINDOWS_CLANG_PLUGIN=ON"
    }
}

Write-Host "Configuring AXVM build..."
& $Cmake @cfgArgs
if ($LASTEXITCODE -ne 0) { Fail "cmake configure failed" }

Write-Host "Building AXVM runtime and sample targets..."
& $Cmake --build $Build -j 8
if ($LASTEXITCODE -ne 0) { Fail "cmake build failed" }

if (-not $InputSo) {
    $InputSo = Join-Path $Build "samples\victim\libvictim.so"
}
Need-Path $InputSo "Input SO"

if (-not $OutputSo) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($InputSo)
    $OutputSo = Join-Path (Join-Path $Root "build") "$baseName.axvm.so"
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputSo) | Out-Null

$scanReport = Join-Path (Join-Path $Root "build") ("scan-" + [System.IO.Path]::GetFileNameWithoutExtension($InputSo) + ".json")
Write-Host "Scanning lift coverage..."
& $axpack -in $InputSo -scan -report $scanReport
if ($LASTEXITCODE -ne 0) { Fail "axpack scan failed" }

if (-not $Symbols -and (Test-Path -LiteralPath $scanReport)) {
    $scan = Get-Content -LiteralPath $scanReport -Raw | ConvertFrom-Json
    $Symbols = $scan.suggested_syms
}

$packArgs = @("-in", $InputSo, "-out", $OutputSo, "-wipe", "-encrypt")
if (-not $PatchEntries) {
    $packArgs += "-no-patch"
}
if ($Symbols) {
    $packArgs += @("-syms", $Symbols)
}
else {
    $packArgs += @("-protect-level", "aggressive")
}
if ($RuntimeDependency) {
    $packArgs += @("-dep", $RuntimeDependency)
}
if ($ApkBind) {
    if (-not $Package) { Fail "-ApkBind requires -Package" }
    $packArgs += @("-apk-bind", "-package", $Package)
    if ($Apk) {
        Need-Path $Apk "APK"
        $packArgs += @("-apk", $Apk)
    }
    elseif ($ApkCertSha256) {
        $packArgs += @("-apk-cert-sha256", $ApkCertSha256)
    }
    else {
        Fail "-ApkBind requires -Apk or -ApkCertSha256"
    }
}

Write-Host "Protecting SO with AXVM runtime virtualization..."
& $axpack @packArgs
if ($LASTEXITCODE -ne 0) { Fail "axpack protect failed" }

Write-Host "Protected SO: $OutputSo"
Write-Host "Scan report:  $scanReport"
