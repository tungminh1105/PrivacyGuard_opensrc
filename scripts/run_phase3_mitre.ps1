$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Run this script as Administrator." -ForegroundColor Red
    exit 2
}
Set-Location "D:\KERNAL PROTECT\privacyguard"
Write-Host "Running Phase 3 MITRE verification with elevated Sysmon privileges..." -ForegroundColor Green
.\.venv\Scripts\python.exe scripts\run_mitre_scenarios.py --db data\privacyguard.db --port 8765 --alt-port 8443
