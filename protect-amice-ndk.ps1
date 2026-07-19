# AMICE (OLLVM-style) NDK one-click — Windows IR path only (no AXVM).
#
#   .\protect-amice-ndk.ps1 -Source .\foo.c -Out .\libfoo.so `
#     -Flatten -MBA -BogusControlFlow -StringEncryption
#
# Needs: Android NDK (auto-detect) + LLVM opt.exe (LLVM_HOME / -LlvmRoot) + amice.dll

param(
    [Parameter(Mandatory = $true)]
    [string]$Source,

    [Parameter(Mandatory = $true)]
    [string]$Out,

    [string]$NdkRoot = "",
    [string]$LlvmRoot = "",
    [string]$Plugin = "",

    [string]$Target = "aarch64-linux-android",
    [int]$Api = 24,
    [switch]$Cxx,
    [string]$OptLevel = "O1",

    # Common OLLVM-style passes (env → AMICE_*)
    [switch]$StringEncryption,
    [switch]$Flatten,
    [ValidateSet("", "basic", "dominator")]
    [string]$FlattenMode = "basic",
    [switch]$MBA,
    [switch]$BogusControlFlow,
    [ValidateSet("", "basic", "polaris-primes")]
    [string]$BogusMode = "basic",
    [switch]$IndirectCall,
    [switch]$IndirectBranch,
    [switch]$SplitBasicBlock,
    [switch]$VmFlatten,
    [switch]$VmVirtualize,
    [switch]$FunctionWrapper,
    [switch]$CloneFunction,
    [switch]$ShuffleBlocks,
    [switch]$All,   # enable a sensible default set

    [string[]]$ExtraClangArgs = @(),
    [string[]]$ExtraLinkArgs = @(),
    [hashtable]$ExtraAmiceEnv = @{}
)

$ErrorActionPreference = "Stop"

function Find-NdkRoot([string]$Hint) {
    if ($Hint -and (Test-Path $Hint)) { return (Resolve-Path $Hint).Path }
    foreach ($n in @("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_ROOT")) {
        $v = [Environment]::GetEnvironmentVariable($n)
        if ($v -and (Test-Path $v)) { return (Resolve-Path $v).Path }
    }
    $sdk = $env:ANDROID_HOME; if (-not $sdk) { $sdk = $env:ANDROID_SDK_ROOT }
    if (-not $sdk) {
        $local = Join-Path $env:LOCALAPPDATA "Android\Sdk"
        if (Test-Path $local) { $sdk = $local }
    }
    if ($sdk) {
        $ndkDir = Join-Path $sdk "ndk"
        if (Test-Path $ndkDir) {
            $vers = Get-ChildItem $ndkDir -Directory | Sort-Object Name -Descending
            if ($vers) { return $vers[0].FullName }
        }
    }
    return ""
}

function Find-LlvmRoot([string]$Hint) {
    if ($Hint -and (Test-Path (Join-Path $Hint "bin\opt.exe"))) { return (Resolve-Path $Hint).Path }
    foreach ($n in @("LLVM_HOME", "LLVM_ROOT", "AMICE_LLVM_ROOT")) {
        $v = [Environment]::GetEnvironmentVariable($n)
        if ($v -and (Test-Path (Join-Path $v "bin\opt.exe"))) { return (Resolve-Path $v).Path }
    }
    foreach ($p in @(
        (Join-Path $PSScriptRoot "llvm"),
        "C:\Users\Administrator\Tools\llvm",
        "C:\Program Files\LLVM"
    )) {
        if (Test-Path (Join-Path $p "bin\opt.exe")) { return (Resolve-Path $p).Path }
    }
    return ""
}

function Require-Path([string]$Path, [string]$Name) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        throw "$Name not found: $Path"
    }
}

if (-not (Test-Path -LiteralPath $Source)) { throw "Source not found: $Source" }

if (-not $Plugin) {
    foreach ($c in @(
        (Join-Path $PSScriptRoot "amice.dll"),
        (Join-Path $PSScriptRoot "lib\amice.dll")
    )) {
        if (Test-Path $c) { $Plugin = $c; break }
    }
}
Require-Path $Plugin "amice.dll"

$NdkRoot = Find-NdkRoot $NdkRoot
if (-not $NdkRoot) { throw "NDK not found. Set ANDROID_NDK_HOME or -NdkRoot." }
$LlvmRoot = Find-LlvmRoot $LlvmRoot
if (-not $LlvmRoot) {
    throw "LLVM opt.exe not found. Set LLVM_HOME / -LlvmRoot to an LLVM build that matches amice.dll."
}

$ndkBin = Join-Path $NdkRoot "toolchains\llvm\prebuilt\windows-x86_64\bin"
$driver = if ($Cxx) { "$Target$Api-clang++.cmd" } else { "$Target$Api-clang.cmd" }
$clang = Join-Path $ndkBin $driver
$opt = Join-Path $LlvmRoot "bin\opt.exe"
Require-Path $clang "NDK clang"
Require-Path $opt "opt.exe"

if ($Target -ne "aarch64-linux-android") {
    Write-Warning "Primary verification path is aarch64-linux-android; current Target=$Target"
}

$useFlatten = $Flatten -or $All
$useMba = $MBA -or $All
$useBogus = $BogusControlFlow -or $All
$useStr = $StringEncryption -or $All
$useICall = $IndirectCall -or $All
$useIBr = $IndirectBranch -or $All
$useSplit = $SplitBasicBlock -or $All
$useVmFlat = $VmFlatten
$useVmVirt = $VmVirtualize
$useWrap = $FunctionWrapper -or $All
$useClone = $CloneFunction
$useShuffle = $ShuffleBlocks -or $All

$outFull = [IO.Path]::GetFullPath($Out)
$outDir = Split-Path -Parent $outFull
if ($outDir -and !(Test-Path $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("amice-ndk-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$rawLl = Join-Path $tmp "raw.ll"
$amiceLl = Join-Path $tmp "amice.ll"

$oldPath = $env:PATH
$saved = @{}
$amiceKeys = @(
    "AMICE_STRING_ENCRYPTION","AMICE_FLATTEN","AMICE_FLATTEN_MODE","AMICE_MBA",
    "AMICE_BOGUS_CONTROL_FLOW","AMICE_BOGUS_CONTROL_FLOW_MODE","AMICE_BOGUS_CONTROL_FLOW_PROB",
    "AMICE_INDIRECT_CALL","AMICE_INDIRECT_BRANCH","AMICE_SPLIT_BASIC_BLOCK",
    "AMICE_VM_FLATTEN","AMICE_VM_VIRTUALIZE","AMICE_FUNCTION_WRAPPER","AMICE_CLONE_FUNCTION",
    "AMICE_SHUFFLE_BLOCKS","AMICE_SHUFFLE_BLOCKS_FLAGS"
)
try {
    foreach ($k in $amiceKeys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }

    Write-Host "=== NDK emit-llvm ==="
    & $clang -S -emit-llvm "-$OptLevel" -fPIC @ExtraClangArgs $Source -o $rawLl
    if ($LASTEXITCODE -ne 0) { throw "clang emit-llvm failed ($LASTEXITCODE)" }

    $env:PATH = (Join-Path $LlvmRoot "bin") + ";" + $env:PATH
    $env:AMICE_STRING_ENCRYPTION = if ($useStr) { "true" } else { $null }
    $env:AMICE_FLATTEN = if ($useFlatten) { "true" } else { $null }
    $env:AMICE_FLATTEN_MODE = if ($useFlatten) { $FlattenMode } else { $null }
    $env:AMICE_MBA = if ($useMba) { "true" } else { $null }
    $env:AMICE_BOGUS_CONTROL_FLOW = if ($useBogus) { "true" } else { $null }
    $env:AMICE_BOGUS_CONTROL_FLOW_MODE = if ($useBogus) { $BogusMode } else { $null }
    $env:AMICE_BOGUS_CONTROL_FLOW_PROB = if ($useBogus) { "80" } else { $null }
    $env:AMICE_INDIRECT_CALL = if ($useICall) { "true" } else { $null }
    $env:AMICE_INDIRECT_BRANCH = if ($useIBr) { "true" } else { $null }
    $env:AMICE_SPLIT_BASIC_BLOCK = if ($useSplit) { "true" } else { $null }
    $env:AMICE_VM_FLATTEN = if ($useVmFlat) { "true" } else { $null }
    $env:AMICE_VM_VIRTUALIZE = if ($useVmVirt) { "true" } else { $null }
    $env:AMICE_FUNCTION_WRAPPER = if ($useWrap) { "true" } else { $null }
    $env:AMICE_CLONE_FUNCTION = if ($useClone) { "true" } else { $null }
    $env:AMICE_SHUFFLE_BLOCKS = if ($useShuffle) { "true" } else { $null }
    $env:AMICE_SHUFFLE_BLOCKS_FLAGS = if ($useShuffle) { "reverse,rotate" } else { $null }
    foreach ($kv in $ExtraAmiceEnv.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($kv.Key, [string]$kv.Value)
    }

    Write-Host "=== AMICE opt pass ==="
    & $opt "-load-pass-plugin=$Plugin" "-passes=default<$OptLevel>" -S $rawLl -o $amiceLl
    if ($LASTEXITCODE -ne 0) { throw "opt/amice failed ($LASTEXITCODE)" }

    Write-Host "=== NDK link shared ==="
    & $clang -shared "-$OptLevel" -fPIC $amiceLl @ExtraLinkArgs -o $outFull
    if ($LASTEXITCODE -ne 0) { throw "clang link failed ($LASTEXITCODE)" }

    Write-Host ""
    Write-Host "OK: $outFull"
    Write-Host "Plugin: $Plugin"
    Write-Host "NDK: $NdkRoot"
    Write-Host "LLVM: $LlvmRoot"
} finally {
    $env:PATH = $oldPath
    foreach ($k in $amiceKeys) {
        [Environment]::SetEnvironmentVariable($k, $saved[$k])
    }
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
