# PrivacyGuard Phase 4: Demo Environment Preflight Verification
# Strictly read-only; verifies environment, database, ports, and evidence files.

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "      PRIVACYGUARD PHASE 4: DEMO PREFLIGHT VERIFICATION" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$allPassed = $true

# Resolve Project Root
$projectRoot = if ($PSScriptRoot) {
    (Get-Item $PSScriptRoot).Parent.FullName
} else {
    (Get-Location).Path
}

# 1. Administrator Check
Write-Host "[*] Check 1: Checking Administrator Privileges..." -NoNewline
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host " [PASS]" -ForegroundColor Green
} else {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "    -> Can chay PowerShell voi quyen Administrator (Run as Administrator)." -ForegroundColor Yellow
    $allPassed = $false
}

# 2. Port Availability (8765 and 8443)
function Test-PortAvailable([string]$ip, [int]$port) {
    try {
        $listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Parse($ip)), $port
        $listener.Start()
        $listener.Stop()
        return $true
    } catch {
        return $false
    }
}

Write-Host "[*] Check 2: Verifying Localhost Ports 8765 & 8443 are free..." -NoNewline
$port8765Free = Test-PortAvailable "127.0.0.1" 8765
$port8443Free = Test-PortAvailable "127.0.0.1" 8443

if ($port8765Free -and $port8443Free) {
    Write-Host " [PASS]" -ForegroundColor Green
} else {
    Write-Host " [FAIL]" -ForegroundColor Red
    if (-not $port8765Free) { Write-Host "    -> Cong 8765 dang bi ung dung khac chiem dung." -ForegroundColor Yellow }
    if (-not $port8443Free) { Write-Host "    -> Cong 8443 dang bi ung dung khac chiem dung." -ForegroundColor Yellow }
    $allPassed = $false
}

# 3. Check for lingering background runner processes
Write-Host "[*] Check 3: Checking for lingering scenario processes..." -NoNewline
$lingering = $false
try {
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match "run_mitre_scenarios" -or $_.CommandLine -match "mitre_payload"
    }
    if ($procs -and $procs.Count -gt 0) {
        $lingering = $true
    }
} catch {
    # Silently continue
}

if (-not $lingering) {
    Write-Host " [PASS]" -ForegroundColor Green
} else {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "    -> Phat hien tien trinh run_mitre_scenarios hoac mitre_payload dang chay nen." -ForegroundColor Yellow
    $allPassed = $false
}

# 4. Database Integrity Check (PRAGMA quick_check)
Write-Host "[*] Check 4: Verifying SQLite Database Integrity (quick_check)..." -NoNewline
$dbPath = Join-Path $projectRoot "data\privacyguard.db"
$dbCheckOk = $false
if (Test-Path $dbPath) {
    $pyExec = Join-Path $projectRoot ".venv\Scripts\python.exe"
    $qcCode = "import sqlite3; conn = sqlite3.connect('file:data/privacyguard.db?mode=ro', uri=True); print(conn.execute('PRAGMA quick_check;').fetchone()[0])"
    $qcRes = & $pyExec -c $qcCode 2>$null
    if ($qcRes -and ($qcRes -join '').Trim() -eq "ok") {
        $dbCheckOk = $true
    }
}

if ($dbCheckOk) {
    Write-Host " [PASS]" -ForegroundColor Green
} else {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "    -> Co so du lieu data/privacyguard.db bi loi hoac khong phan hoi 'ok'." -ForegroundColor Yellow
    $allPassed = $false
}

# 5. Check Presence of Alerts #175-#177
Write-Host "[*] Check 5: Verifying Phase 3 Alerts #175-#177 in DB..." -NoNewline
$alertsOk = $false
if (Test-Path $dbPath) {
    $pyExec = Join-Path $projectRoot ".venv\Scripts\python.exe"
    $aCode = "import sqlite3; conn = sqlite3.connect('file:data/privacyguard.db?mode=ro', uri=True); ids = [r[0] for r in conn.execute('SELECT id FROM alerts WHERE id BETWEEN 175 AND 177 ORDER BY id ASC').fetchall()]; print('ALERT_CHECK_OK' if ids == [175, 176, 177] else 'FAIL')"
    $aRes = & $pyExec -c $aCode 2>$null
    if ($aRes -and ($aRes -join '').Trim() -eq "ALERT_CHECK_OK") {
        $alertsOk = $true
    }
}

if ($alertsOk) {
    Write-Host " [PASS]" -ForegroundColor Green
} else {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "    -> Khong tim thay du 3 canh bao #175-#177 trong bang alerts." -ForegroundColor Yellow
    $allPassed = $false
}

# 6. Check Required Results & Report Files
Write-Host "[*] Check 6: Verifying Required Benchmark & Report Files..." -NoNewline
$resultsDir = Join-Path $projectRoot "results"
$requiredFiles = @(
    "mitre_results.csv",
    "mitre_alerts.csv",
    "mitre_summary.json",
    "MITRE_REPORT.md",
    "fpr_summary.json",
    "FPR_REPORT.md"
)

$missingFiles = @()
foreach ($f in $requiredFiles) {
    $fp = Join-Path $resultsDir $f
    if (-not (Test-Path $fp)) {
        $missingFiles += $f
    }
}

if ($missingFiles.Count -eq 0) {
    Write-Host " [PASS]" -ForegroundColor Green
} else {
    Write-Host " [FAIL]" -ForegroundColor Red
    Write-Host "    -> Thieu cac file ket qua: $($missingFiles -join ', ')" -ForegroundColor Yellow
    $allPassed = $false
}

# Summary
Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray
if ($allPassed) {
    Write-Host "[+] TAT CA 6 HANG MUC PREFLIGHT DEU DAT (PASS)!" -ForegroundColor Green
    Write-Host "[+] Moi truong san sang 100% de thuc hien quay video demo 5 phut." -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""
    exit 0
} else {
    Write-Host "[-] MOT HOAC NHIEU HANG MUC CHUA DAT (FAIL). VUI LONG KIEM TRA LAI!" -ForegroundColor Red
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}
