param(
    [switch]$SkipBuild,
    [int]$Port = 9000
)

$ErrorActionPreference = "Stop"
$moduleDir = Join-Path $PSScriptRoot "modules\mobile_flutter"

$flutter = "C:\Users\ccuen\flutter\bin\flutter.bat"
if (-not (Test-Path $flutter)) {
    $flutter = "flutter"
}

$ip = (Get-NetIPConfiguration |
    Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" -and $_.InterfaceAlias -notmatch "Tailscale|vEthernet|WSL|VirtualBox|Docker|VMware" } |
    Select-Object -First 1).IPv4Address.IPAddress
if (-not $ip) { $ip = "127.0.0.1" }

if (-not $SkipBuild) {
    Write-Host "Compilando la app movil (Flutter Web)..."
    Set-Location $moduleDir
    & $flutter pub get
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $flutter build web --release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host ""
Write-Host "App movil:  http://localhost:$Port"
Write-Host "En el telefono (misma Wi-Fi): http://${ip}:$Port"
Write-Host "Frigate API proxificada:      http://${ip}:$Port/api"
Write-Host ""

$env:PORT = "$Port"
$env:FRIGATE_URL = "http://127.0.0.1:5000"
Set-Location $moduleDir
python tools\serve_web.py
