# 批量加固第三方 SO 并输出 lift 失败日志
param(
    [string]$InputSo = "C:\Users\Administrator\Projects\axvm-engine\build-ndk-arm64\samples\victim\libvictim.so",
    [string]$OutDir = "C:\Users\Administrator\Projects\axvm-engine\build\protected",
    [string]$Syms = "victim_add,victim_mul,victim_check,victim_mixed"
)

$ErrorActionPreference = "Stop"
$Root = "C:\Users\Administrator\Projects\axvm-engine"
$Axpack = Join-Path $Root "build\axpack.exe"

if (-not (Test-Path $Axpack)) {
    Push-Location $Root
    go build -o build\axpack.exe .\tools\axpack
    Pop-Location
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$symList = $Syms -split ","
foreach ($sym in $symList) {
    $sym = $sym.Trim()
    if (-not $sym) { continue }
    $out = Join-Path $OutDir ("lib_" + $sym + ".ax.so")
    Write-Host "`n=== protect $sym ===" -ForegroundColor Cyan
    & $Axpack -in $InputSo -out $out -syms $sym -wipe -encrypt -no-patch 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[FAIL] $sym — see unsupported insn log above" -ForegroundColor Red
    } else {
        Write-Host "[PASS] $out" -ForegroundColor Green
    }
}

Write-Host "`nDiagnose full .text lift:" -ForegroundColor Yellow
Write-Host "  cd $Root; go test ./tools/axpack -run TestLiftAllExported -v"
