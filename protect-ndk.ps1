# AMICE + AXVM NDK one-click protect
# Modes:
#   A) Protect existing SO (default product path):
#        .\protect-ndk.ps1 -In .\libfoo.so -Out .\libfoo.axvm.so
#   B) Compile C/C++ then protect (optional AMICE IR passes):
#        .\protect-ndk.ps1 -Source .\foo.c -Out .\libfoo.axvm.so -EnableAmice -EnableFlatten
#
# Defaults: SingleSo ON (disk-ready, no DT_NEEDED libaxvm), aggressive + degrade, auto-scan.

param(
    [string]$In = "",
    [string]$Source = "",
    [Parameter(Mandatory = $true)]
    [string]$Out,

    [string]$RepoRoot = "",
    [string]$NdkRoot = "",
    [string]$Axpack = "",
    [string]$AxvmRuntimeSo = "",
    [string]$AmicePlugin = "",
    [string]$LlvmRoot = "",

    [string]$Target = "aarch64-linux-android",
    [int]$Api = 24,
    [switch]$Cxx,

    # Product defaults
    [bool]$SingleSo = $true,
    [string]$ProtectLevel = "aggressive",
    [string]$Symbols = "",
    [switch]$NoScan,
    [string]$Report = "",
    [switch]$StableStub,
    [switch]$SkipAtomic,
    [int]$Decoys = 2,
    [switch]$DualSo,          # force DT_NEEDED libaxvm.so (overrides SingleSo)
    [switch]$NoCopyRuntime,

    # apk-bind
    [string]$Package = "",
    [string]$Apk = "",
    [string]$ApkCertSha256 = "",
    [switch]$ApkBind,

    # AMICE IR (optional; needs opt.exe + amice.dll)
    [switch]$EnableAmice,
    [switch]$EnableStringEncryption,
    [switch]$EnableFlatten,
    [switch]$EnableMBA,
    [switch]$EnableBogusControlFlow,
    [switch]$EnableIndirectCall,
    [switch]$EnableIndirectBranch,
    [switch]$EnableVmFlatten,
    [switch]$EnableVmVirtualize,

    [string[]]$ExtraClangArgs = @(),
    [string[]]$ExtraLinkArgs = @()
)

$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    param([string]$Hint)
    if ($Hint -and (Test-Path (Join-Path $Hint "artifacts"))) { return (Resolve-Path $Hint).Path }
    $here = $PSScriptRoot
    if (Test-Path (Join-Path $here "artifacts")) { return $here }
    $parent = Split-Path $here -Parent
    if ($parent -and (Test-Path (Join-Path $parent "artifacts"))) { return $parent }
    return $here
}

function Find-NdkRoot {
    param([string]$Hint)
    if ($Hint -and (Test-Path $Hint)) { return (Resolve-Path $Hint).Path }
    foreach ($envName in @("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_ROOT")) {
        $v = [Environment]::GetEnvironmentVariable($envName)
        if ($v -and (Test-Path $v)) { return (Resolve-Path $v).Path }
    }
    $sdk = $env:ANDROID_HOME
    if (-not $sdk) { $sdk = $env:ANDROID_SDK_ROOT }
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
        $side = Join-Path $sdk "ndk-bundle"
        if (Test-Path $side) { return $side }
    }
    return ""
}

function Find-FilePrefer {
    param([string[]]$Candidates, [string]$Name)
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path -LiteralPath $c).Path }
    }
    throw "$Name not found. Tried:`n  - $($Candidates -join "`n  - ")"
}

function Find-LlvmRoot {
    param([string]$Hint, [string]$Repo)
    if ($Hint -and (Test-Path (Join-Path $Hint "bin\opt.exe"))) { return (Resolve-Path $Hint).Path }
    foreach ($envName in @("LLVM_HOME", "LLVM_ROOT", "AMICE_LLVM_ROOT")) {
        $v = [Environment]::GetEnvironmentVariable($envName)
        if ($v -and (Test-Path (Join-Path $v "bin\opt.exe"))) { return (Resolve-Path $v).Path }
    }
    $probe = @(
        (Join-Path $Repo "tools\llvm"),
        (Join-Path $Repo "artifacts\llvm"),
        "C:\Users\Administrator\Tools\llvm",
        "C:\Program Files\LLVM"
    )
    foreach ($p in $probe) {
        if (Test-Path (Join-Path $p "bin\opt.exe")) { return (Resolve-Path $p).Path }
    }
    return ""
}

function Get-DebugKeystoreCertSha256 {
    $keytool = $null
    if ($env:JAVA_HOME) {
        $kt = Join-Path $env:JAVA_HOME "bin\keytool.exe"
        if (Test-Path $kt) { $keytool = $kt }
    }
    if (-not $keytool) {
        $cmd = Get-Command keytool -ErrorAction SilentlyContinue
        if ($cmd) { $keytool = $cmd.Source }
    }
    if (-not $keytool) { return "" }
    $debugKs = Join-Path $env:USERPROFILE ".android\debug.keystore"
    if (-not (Test-Path $debugKs)) { return "" }
    $tmpCer = Join-Path $env:TEMP ("axvm_debug_{0}.cer" -f [guid]::NewGuid().ToString("N"))
    try {
        & $keytool -exportcert -alias androiddebugkey -keystore $debugKs `
            -storepass android -keypass android -file $tmpCer 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return "" }
        $certBytes = [IO.File]::ReadAllBytes($tmpCer)
        $sha = [Security.Cryptography.SHA256]::Create()
        $hash = $sha.ComputeHash($certBytes)
        return -join ($hash | ForEach-Object { $_.ToString("x2") })
    } finally {
        if (Test-Path $tmpCer) { Remove-Item -Force $tmpCer }
    }
}

$Repo = Resolve-RepoRoot -Hint $RepoRoot
$useSingleSo = $SingleSo -and (-not $DualSo)

$axpackCandidates = @(
    $Axpack,
    (Join-Path $Repo "artifacts\axpack.exe"),
    (Join-Path $Repo "source\axvm-engine-integrated\build\axpack.exe"),
    (Join-Path $Repo "source\axvm-engine-integrated\tools\axpack\axpack.exe")
)
$Axpack = Find-FilePrefer -Candidates $axpackCandidates -Name "axpack.exe"

$runtimeCandidates = @(
    $AxvmRuntimeSo,
    (Join-Path $Repo "artifacts\libaxvm.so"),
    (Join-Path $Repo "source\axvm-engine-integrated\build-verify-arm64\runtime\libaxvm.so")
)
# runtime optional in SingleSo mode
$runtimeResolved = $null
foreach ($c in $runtimeCandidates) {
    if ($c -and (Test-Path -LiteralPath $c)) { $runtimeResolved = (Resolve-Path -LiteralPath $c).Path; break }
}
$AxvmRuntimeSo = $runtimeResolved

if (-not $NdkRoot) { $NdkRoot = Find-NdkRoot -Hint $NdkRoot }

$outFull = [IO.Path]::GetFullPath($Out)
$outDir = Split-Path -Parent $outFull
if ($outDir -and !(Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}
if (-not $Report) {
    $base = [IO.Path]::GetFileNameWithoutExtension($outFull)
    $Report = Join-Path $outDir "$base.axvm-scan.json"
}

$workSo = $null
$tmp = $null

try {
    if ($Source) {
        if (-not $NdkRoot) { throw "NDK not found. Set ANDROID_NDK_HOME or -NdkRoot." }
        if ($Target -ne "aarch64-linux-android") {
            throw "AXVM currently supports ARM64 only (-Target aarch64-linux-android)."
        }
        $ndkBin = Join-Path $NdkRoot "toolchains\llvm\prebuilt\windows-x86_64\bin"
        $driver = if ($Cxx) { "$Target$Api-clang++.cmd" } else { "$Target$Api-clang.cmd" }
        $clang = Join-Path $ndkBin $driver
        if (!(Test-Path $clang)) { throw "NDK clang not found: $clang" }

        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("axvm-ndk-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $linkedSo = Join-Path $tmp "input.so"

        $wantAmice = $EnableAmice -or $EnableFlatten -or $EnableMBA -or $EnableBogusControlFlow `
            -or $EnableIndirectCall -or $EnableIndirectBranch -or $EnableVmFlatten -or $EnableVmVirtualize `
            -or $EnableStringEncryption

        if ($wantAmice) {
            $pluginCandidates = @(
                $AmicePlugin,
                (Join-Path $Repo "artifacts\amice.dll"),
                (Join-Path $env:TEMP "axvm-ndk-peek\amice.dll")
            )
            $AmicePlugin = Find-FilePrefer -Candidates $pluginCandidates -Name "amice.dll"
            if (-not $LlvmRoot) { $LlvmRoot = Find-LlvmRoot -Hint $LlvmRoot -Repo $Repo }
            if (-not $LlvmRoot) {
                throw "AMICE needs LLVM opt.exe. Set -LlvmRoot or LLVM_HOME, or omit AMICE flags for SO-only protect."
            }
            $opt = Join-Path $LlvmRoot "bin\opt.exe"
            if (!(Test-Path $opt)) { throw "opt.exe not found under $LlvmRoot" }

            $rawLl = Join-Path $tmp "input.raw.ll"
            $amiceLl = Join-Path $tmp "input.amice.ll"
            & $clang -S -emit-llvm -O1 @ExtraClangArgs $Source -o $rawLl
            if ($LASTEXITCODE -ne 0) { throw "clang emit-llvm failed ($LASTEXITCODE)" }

            $oldPath = $env:PATH
            try {
                $env:PATH = (Join-Path $LlvmRoot "bin") + ";" + $env:PATH
                $env:AMICE_STRING_ENCRYPTION = if ($EnableStringEncryption) { "true" } else { $null }
                $env:AMICE_FLATTEN = if ($EnableFlatten) { "true" } else { $null }
                $env:AMICE_MBA = if ($EnableMBA) { "true" } else { $null }
                $env:AMICE_BOGUS_CONTROL_FLOW = if ($EnableBogusControlFlow) { "true" } else { $null }
                $env:AMICE_INDIRECT_CALL = if ($EnableIndirectCall) { "true" } else { $null }
                $env:AMICE_INDIRECT_BRANCH = if ($EnableIndirectBranch) { "true" } else { $null }
                $env:AMICE_VM_FLATTEN = if ($EnableVmFlatten) { "true" } else { $null }
                $env:AMICE_VM_VIRTUALIZE = if ($EnableVmVirtualize) { "true" } else { $null }
                & $opt "-load-pass-plugin=$AmicePlugin" "-passes=default<O1>" -S $rawLl -o $amiceLl
                if ($LASTEXITCODE -ne 0) { throw "opt/amice failed ($LASTEXITCODE)" }
            } finally {
                $env:PATH = $oldPath
            }

            $linkArgs = @() + $ExtraLinkArgs
            if (-not $useSingleSo) {
                if (-not $AxvmRuntimeSo) { throw "DualSo mode needs libaxvm.so (place under artifacts/)." }
                $runtimeDir = Split-Path -Parent $AxvmRuntimeSo
                $linkArgs += @("-L$runtimeDir", "-Wl,--no-as-needed", "-l:libaxvm.so")
            }
            & $clang -shared -O1 $amiceLl @linkArgs -o $linkedSo
            if ($LASTEXITCODE -ne 0) { throw "clang link failed ($LASTEXITCODE)" }
        } else {
            & $clang -shared -O1 @ExtraClangArgs $Source @ExtraLinkArgs -o $linkedSo
            if ($LASTEXITCODE -ne 0) { throw "clang link failed ($LASTEXITCODE)" }
        }
        $workSo = $linkedSo
    } elseif ($In) {
        if (!(Test-Path -LiteralPath $In)) { throw "Input SO not found: $In" }
        $workSo = (Resolve-Path -LiteralPath $In).Path
    } else {
        throw "Specify -In <so> or -Source <c/cc>."
    }

    # --- axpack ---
    $syms = $Symbols
    if (-not $NoScan) {
        Write-Host "=== axpack scan ==="
        & $Axpack -in $workSo -scan -report $Report
        if ($LASTEXITCODE -ne 0) { throw "axpack -scan failed ($LASTEXITCODE)" }
        if (-not $syms -and (Test-Path -LiteralPath $Report)) {
            $scan = Get-Content -LiteralPath $Report -Raw | ConvertFrom-Json
            if ($scan.suggested_syms) { $syms = [string]$scan.suggested_syms }
        }
    }

    $packArgs = @(
        "-in", $workSo,
        "-out", $outFull,
        "-wipe", "-encrypt", "-no-patch", "-degrade",
        "-decoys", "$Decoys",
        "-protect-level", $ProtectLevel
    )
    if ($syms) { $packArgs += @("-syms", $syms) }
    if ($StableStub) { $packArgs += "-stable-stub" }
    if ($SkipAtomic) { $packArgs += "-skip-atomic" }

    if ($useSingleSo) {
        $packArgs += @("-disk-ready", "-dep=-")
    } else {
        $packArgs += @("-dep", "libaxvm.so")
    }

    $doApkBind = $ApkBind -or $Package -or $Apk -or $ApkCertSha256
    if ($doApkBind) {
        if (-not $Package) { throw "apk-bind requires -Package <applicationId>" }
        $packArgs += @("-apk-bind", "-package", $Package)
        if ($Apk) {
            if (!(Test-Path -LiteralPath $Apk)) { throw "APK not found: $Apk" }
            $packArgs += @("-apk", (Resolve-Path -LiteralPath $Apk).Path)
        } elseif ($ApkCertSha256) {
            $packArgs += @("-apk-cert-sha256", $ApkCertSha256)
        } else {
            $autoCert = Get-DebugKeystoreCertSha256
            if (-not $autoCert) {
                throw "apk-bind needs -Apk / -ApkCertSha256, or a debug keystore + keytool on PATH"
            }
            Write-Host "apk-bind: using debug keystore cert $($autoCert.Substring(0,16))..."
            $packArgs += @("-apk-cert-sha256", $autoCert)
        }
    }

    Write-Host "=== axpack protect ==="
    Write-Host ("  " + ($packArgs -join " "))
    & $Axpack @packArgs
    if ($LASTEXITCODE -ne 0) { throw "axpack protect failed ($LASTEXITCODE)" }

    if (-not $useSingleSo -and -not $NoCopyRuntime) {
        if (-not $AxvmRuntimeSo) { throw "DualSo mode needs artifacts/libaxvm.so" }
        $dest = Join-Path $outDir "libaxvm.so"
        if ((Resolve-Path $AxvmRuntimeSo).Path -ne [IO.Path]::GetFullPath($dest)) {
            Copy-Item -LiteralPath $AxvmRuntimeSo -Destination $dest -Force
        }
        Write-Host "Runtime copied: $dest"
    }

    Write-Host ""
    Write-Host "OK: $outFull"
    if (-not $NoScan) { Write-Host "Scan: $Report" }
    if ($useSingleSo) {
        Write-Host "Mode: SingleSo (disk-ready, no DT_NEEDED libaxvm.so)"
    } else {
        Write-Host "Mode: DualSo (ship libaxvm.so beside protected SO)"
    }
} finally {
    if ($tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
