# Install portable JDK 17 for sdkmanager / Gradle
$ErrorActionPreference = "Stop"
$JdkDir = "C:\Users\Administrator\Tools\jdk-17"
if (Test-Path "$JdkDir\bin\java.exe") {
    Write-Host "JDK already installed: $JdkDir"
} else {
    $zip = "$env:TEMP\temurin17.zip"
    Write-Host "Downloading JDK 17..."
    Invoke-WebRequest -Uri "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.14%2B7/OpenJDK17U-jdk_x64_windows_hotspot_17.0.14_7.zip" -OutFile $zip -UseBasicParsing
    $tmp = "$env:TEMP\jdk17"
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    Expand-Archive $zip -DestinationPath $tmp -Force
    $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
    Move-Item -Force $inner.FullName $JdkDir
    Remove-Item $zip, $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
[Environment]::SetEnvironmentVariable("JAVA_HOME", $JdkDir, "User")
$env:JAVA_HOME = $JdkDir
$old = [Environment]::GetEnvironmentVariable("Path", "User")
if ($old -notlike "*$JdkDir\bin*") {
    [Environment]::SetEnvironmentVariable("Path", "$old;$JdkDir\bin", "User")
}
& "$JdkDir\bin\java.exe" -version
