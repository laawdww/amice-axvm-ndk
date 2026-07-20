# axgate — 将加密镜像节注入已链接的 ARM64 SO（可选）
#
# 优先推荐：编译期把 axgatepack 生成的 axgate_blob.c 与 libaxgate.a 一起链接，
# 由 constructor(90) 完成「入口劫持」。本脚本用于对现成 SO 追加 .axgate 节。
#
# 依赖：llvm-objcopy / llvm-strip（NDK llvm 工具链）
# 用法：
#   .\axgate-inject.ps1 -So libhost.so -Blob axgate_blob.bin -Objcopy llvm-objcopy.exe

param(
    [Parameter(Mandatory = $true)][string]$So,
    [Parameter(Mandatory = $true)][string]$Blob,
    [string]$Objcopy = "llvm-objcopy",
    [string]$Out = ""
)

if (-not $Out) { $Out = $So -replace '\.so$', '.gated.so' }
if (-not (Test-Path $So)) { throw "SO not found: $So" }
if (-not (Test-Path $Blob)) { throw "blob not found: $Blob" }

& $Objcopy --add-section .axgate=$Blob --set-section-flags .axgate=alloc,data $So $Out
if ($LASTEXITCODE -ne 0) { throw "objcopy failed" }
Write-Host "axgate-inject: $Out (+.axgate from $Blob)"
Write-Host "注意：仍需 SO 内已链接 axgate 构造器；仅追加节不会自动装载门卫代码。"
