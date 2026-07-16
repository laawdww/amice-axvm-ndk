# Event-driven wait for AXVM logcat lines. No Start-Sleep / busy-spin.
# Dot-source: . "$PSScriptRoot\Wait-AxvmLogcat.ps1"

function Wait-AxvmLogcat {
    param(
        [Parameter(Mandatory = $true)][string]$Adb,
        [string]$Pattern = "MODULE_AB: PASS",
        [int]$TimeoutSec = 120,
        [string]$Device = "",
        [string[]]$ExtraTags = @()
    )

    $argList = New-Object System.Collections.Generic.List[string]
    if ($Device) {
        $argList.Add("-s")
        $argList.Add($Device)
    }
    $argList.Add("logcat")
    $argList.Add("-v")
    $argList.Add("brief")
    $argList.Add("-s")
    $argList.Add("AXVM")
    foreach ($t in $ExtraTags) {
        if ($t) { $argList.Add($t) }
    }

    $job = Start-Job -ScriptBlock {
        param($AdbPath, $ArgsArr, $Pat)
        & $AdbPath @ArgsArr 2>&1 | ForEach-Object {
            $line = "$_"
            Write-Output $line
            if ($line -match $Pat) { break }
        }
    } -ArgumentList $Adb, $argList.ToArray(), $Pattern

    try {
        $null = Wait-Job $job -Timeout $TimeoutSec
        $lines = @(Receive-Job $job -ErrorAction SilentlyContinue)
        return ,$lines
    } finally {
        if ($job.State -eq "Running") {
            Stop-Job $job -ErrorAction SilentlyContinue
        }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}
