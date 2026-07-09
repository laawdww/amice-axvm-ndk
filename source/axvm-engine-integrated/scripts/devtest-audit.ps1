$ErrorActionPreference = "Stop"

$Root = "C:\Users\Administrator\Projects\axvm-engine"
$Adb  = "C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe"
$Dev  = "8a08ca71"
$Rem  = "/data/local/tmp/axvm_audit"

& $Adb -s $Dev shell "mkdir -p $Rem"

foreach ($cfg in @("default","dbg-float","float-off","switch")) {
    $Bin = Join-Path $Root "build-audit-$cfg\target\axvm_standalone"
    if (-not (Test-Path $Bin)) { Write-Host "MISSING $cfg" -ForegroundColor Red; continue }
    $R = "$Rem/axvm_standalone_$cfg"
    & $Adb -s $Dev push $Bin $R | Out-Null
    & $Adb -s $Dev shell "chmod 755 $R"
    Write-Host "==================== RUN $cfg ====================" -ForegroundColor Cyan
    & $Adb -s $Dev shell "$R --outer=5"
    Write-Host "---- exit=$LASTEXITCODE ----"
    Write-Host ""
}
