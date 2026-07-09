$ErrorActionPreference = "Stop"
$adb = "C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe"
$dev = "/data/local/tmp/axvm_modg"

& $adb shell "mkdir -p $dev"

foreach ($tag in @("LON-FOFF", "LOFF-FOFF")) {
    $bin = "C:\Users\Administrator\Projects\axvm-engine\build-modg-$tag\target\axvm_standalone"
    $remote = "$dev/axvm_standalone_$tag"
    & $adb push $bin $remote | Out-Null
    & $adb shell "chmod 755 $remote"
    Write-Host "==================== $tag ===================="
    & $adb shell "$remote --outer=5"
    Write-Host ""
}
