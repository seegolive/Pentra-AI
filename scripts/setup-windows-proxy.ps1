# setup-windows-proxy.ps1
# Run as Administrator to expose WSL2 services to Windows browser.
# Usage: powershell -ExecutionPolicy Bypass -File setup-windows-proxy.ps1

param(
    [int[]]$Ports = @(5174, 8001),
    [string]$WslDistro = ""
)

# ── Require elevation ──────────────────────────────────────────────────────────
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

# ── Get current WSL2 IP ────────────────────────────────────────────────────────
Write-Host "Getting WSL2 IP address..." -ForegroundColor Cyan

$wslCmd = if ($WslDistro) { "wsl -d $WslDistro" } else { "wsl" }
$wslIp = (Invoke-Expression "$wslCmd -- ip -4 addr show eth0") |
    Select-String -Pattern 'inet (\d+\.\d+\.\d+\.\d+)' |
    ForEach-Object { $_.Matches[0].Groups[1].Value } |
    Select-Object -First 1

# Fallback: try eth3 (mirrored networking may use different interface)
if (-not $wslIp) {
    $wslIp = (Invoke-Expression "$wslCmd -- ip -4 addr show eth3") |
        Select-String -Pattern 'inet (\d+\.\d+\.\d+\.\d+)' |
        ForEach-Object { $_.Matches[0].Groups[1].Value } |
        Select-Object -First 1
}

# Fallback: hostname -I
if (-not $wslIp) {
    $wslIp = (Invoke-Expression "$wslCmd -- hostname -I").Trim().Split()[0]
}

if (-not $wslIp) {
    Write-Error "Could not determine WSL2 IP. Is WSL running?"
    exit 1
}

Write-Host "WSL2 IP: $wslIp" -ForegroundColor Green

# ── Note: WSL2 mirrored networking shares loopback with Windows ───────────────
# portproxy is NOT needed — Windows browser accesses localhost directly.
# We only need firewall rules to allow inbound connections on these ports.
Write-Host "WSL2 IP: $wslIp (mirrored — no portproxy needed)" -ForegroundColor DarkGray

# ── Firewall rules only ────────────────────────────────────────────────────────
foreach ($port in $Ports) {
    Write-Host "`nConfiguring firewall for port $port..." -ForegroundColor Cyan

    # Remove any stale portproxy rule that may interfere
    $existing = (netsh interface portproxy show v4tov4) -join "`n" |
        Select-String "0\.0\.0\.0\s+$port\s"
    if ($existing) {
        netsh interface portproxy delete v4tov4 listenport=$port listenaddress=0.0.0.0 | Out-Null
        Write-Host "  Removed stale portproxy rule for port $port"
    }

    # Add firewall rule (skip if already exists)
    $ruleName = "Pentra_WSL2_$port"
    $ruleExists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($ruleExists) {
        Write-Host "  Firewall rule already exists: $ruleName"
    } else {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -LocalPort $port `
            -Protocol TCP `
            -Action Allow `
            -Profile Any | Out-Null
        Write-Host "  Firewall rule created: $ruleName"
    }
}

# ── Show current portproxy rules ──────────────────────────────────────────────
Write-Host "`nCurrent portproxy rules:" -ForegroundColor Cyan
netsh interface portproxy show all

# ── Quick connectivity test ───────────────────────────────────────────────────
Write-Host "`nTesting connectivity..." -ForegroundColor Cyan
Start-Sleep -Seconds 1

foreach ($port in $Ports) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $result = $tcp.BeginConnect("127.0.0.1", $port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne(3000)
        $tcp.Close()
        if ($success) {
            Write-Host "  localhost:$port  OK" -ForegroundColor Green
        } else {
            Write-Host "  localhost:$port  TIMEOUT (service may not be running in WSL2)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  localhost:$port  ERROR: $_" -ForegroundColor Red
    }
}

Write-Host "`nDone. Open in Windows browser:" -ForegroundColor Green
Write-Host "  Frontend : http://localhost:5174" -ForegroundColor White
Write-Host "  API      : http://localhost:8001" -ForegroundColor White
Write-Host "  Login    : admin / Pentra@2026!" -ForegroundColor White
