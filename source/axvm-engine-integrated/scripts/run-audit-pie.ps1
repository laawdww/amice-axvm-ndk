$ErrorActionPreference = "Stop"
$Root = "C:\Users\Administrator\Projects\axvm-engine"
$Adb = "C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe"
$Device = "8a08ca71"
$Bin = Join-Path $Root "build-audit-audit-GON-JOFF\target\axvm_standalone"
$Remote = "/data/local/tmp/axvm_audit_standalone"

& $Adb -s $Device shell "mkdir -p /data/local/tmp"
& $Adb -s $Device push $Bin $Remote
if ($LASTEXITCODE -ne 0) { throw "adb push failed" }
& $Adb -s $Device shell "chmod 755 $Remote"
& $Adb -s $Device shell $Remote --outer=1 2>&1
