# ============================================================
#  IoCManager v1.6 - Tam Otomatik Kurulum (NSSM Servis)
#  PowerShell'i YONETICI olarak calistirin
#
#  Kullanim:
#    Set-ExecutionPolicy Bypass -Scope Process -Force
#    .\kurulum.ps1
# ============================================================

$ErrorActionPreference = "Stop"

$AppDir     = "C:\IoCManager"
$PythonDir  = "$AppDir\python"
$PythonExe  = "$PythonDir\python.exe"
$NssmDir    = "$AppDir\nssm"
$FeedDir    = "C:\ThreatFeed\public"
$Port       = 5000
$SvcName    = "IoCManager"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir   # windows/ klasorunun bir ustu = repo koku

function Write-Step($n, $msg) { Write-Host "[$n/9] $msg" -ForegroundColor Cyan }

Write-Host ""
Write-Host "  ================================" -ForegroundColor Cyan
Write-Host "   IoCManager v1.6 Kurulum (NSSM)" -ForegroundColor Cyan
Write-Host "  ================================" -ForegroundColor Cyan
Write-Host ""

# 1. Klasorler
Write-Step 1 "Klasorler olusturuluyor..."
New-Item -ItemType Directory -Force -Path $AppDir        | Out-Null
New-Item -ItemType Directory -Force -Path "$AppDir\data" | Out-Null
New-Item -ItemType Directory -Force -Path "$AppDir\logs" | Out-Null
New-Item -ItemType Directory -Force -Path $FeedDir       | Out-Null

# 2. Uygulama dosyalari
Write-Step 2 "Uygulama dosyalari kopyalaniyor..."
Copy-Item "$RepoRoot\app.py"           "$AppDir\app.py"           -Force
Copy-Item "$RepoRoot\run.py"           "$AppDir\run.py"           -Force
Copy-Item "$RepoRoot\requirements.txt" "$AppDir\requirements.txt" -Force
Copy-Item "$RepoRoot\templates"        "$AppDir\templates"        -Recurse -Force
if (Test-Path "$RepoRoot\static") {
    Copy-Item "$RepoRoot\static" "$AppDir\static" -Recurse -Force
}

# 3. Embeddable Python indir
Write-Step 3 "Python indiriliyor (embeddable, kurulum gerektirmez)..."
if (Test-Path $PythonDir) { Remove-Item $PythonDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $PythonDir | Out-Null
$zipUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip"
Invoke-WebRequest $zipUrl -OutFile "$AppDir\python-embed.zip" -UseBasicParsing
Expand-Archive "$AppDir\python-embed.zip" -DestinationPath $PythonDir -Force
Remove-Item "$AppDir\python-embed.zip"

# 4. pip etkinlestir (_pth duzenle)
Write-Step 4 "pip etkinlestiriliyor..."
$pth = Get-ChildItem "$PythonDir\python*._pth" | Select-Object -First 1
(Get-Content $pth.FullName) -replace '#import site','import site' | Set-Content $pth.FullName

# 5. pip + Flask + Waitress kur
Write-Step 5 "pip, Flask ve Waitress kuruluyor..."
Invoke-WebRequest "https://bootstrap.pypa.io/get-pip.py" -OutFile "$AppDir\get-pip.py" -UseBasicParsing
& $PythonExe "$AppDir\get-pip.py" --quiet
Remove-Item "$AppDir\get-pip.py"
& $PythonExe -m pip install flask waitress --quiet

# 6. Firewall
Write-Step 6 "Firewall kurali ekleniyor (port $Port)..."
Remove-NetFirewallRule -DisplayName $SvcName -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $SvcName -Direction Inbound `
  -Protocol TCP -LocalPort $Port -Action Allow | Out-Null

# 7. NSSM indir
Write-Step 7 "NSSM indiriliyor (servis yoneticisi)..."
if (-not (Test-Path $NssmDir)) {
    New-Item -ItemType Directory -Force -Path $NssmDir | Out-Null
    Invoke-WebRequest "https://nssm.cc/release/nssm-2.24.zip" -OutFile "$AppDir\nssm.zip" -UseBasicParsing
    Expand-Archive "$AppDir\nssm.zip" -DestinationPath $NssmDir -Force
    Remove-Item "$AppDir\nssm.zip"
}
$nssmExe = "$NssmDir\nssm-2.24\win64\nssm.exe"

# 8. Eski Task Scheduler gorevi varsa temizle (onceki surumlerden kalan)
Write-Step 8 "Eski kurulum kalintilari temizleniyor..."
Unregister-ScheduledTask -TaskName $SvcName -Confirm:$false -ErrorAction SilentlyContinue
if (Get-Service $SvcName -ErrorAction SilentlyContinue) {
    Stop-Service $SvcName -Force -ErrorAction SilentlyContinue
    & $nssmExe remove $SvcName confirm | Out-Null
    Start-Sleep -Seconds 2
}

# 9. NSSM ile Windows Servisi kur
Write-Step 9 "Windows servisi kuruluyor (NSSM)..."
& $nssmExe install $SvcName $PythonExe "$AppDir\run.py"
& $nssmExe set $SvcName AppDirectory $AppDir
& $nssmExe set $SvcName DisplayName $SvcName
& $nssmExe set $SvcName Description "IoCManager - IoC Feed Yonetim Portali"
& $nssmExe set $SvcName Start SERVICE_AUTO_START
& $nssmExe set $SvcName AppExit Default Restart
& $nssmExe set $SvcName AppRestartDelay 5000
& $nssmExe set $SvcName AppStdout "$AppDir\logs\service-out.log"
& $nssmExe set $SvcName AppStderr "$AppDir\logs\service-err.log"

# Log klasorune yazma izni (NSSM icin)
icacls "$AppDir\logs" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T | Out-Null

Set-Service $SvcName -StartupType Automatic
Start-Service $SvcName

Start-Sleep -Seconds 4
$svc = Get-Service $SvcName -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "  ================================" -ForegroundColor Green
Write-Host "   Kurulum tamamlandi!" -ForegroundColor Green
Write-Host "  ================================" -ForegroundColor Green
Write-Host ""
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "  Servis durumu : Running" -ForegroundColor Green
} else {
    Write-Host "  Servis durumu : $($svc.Status)" -ForegroundColor Yellow
}
Write-Host "  Baslangic tipi: Automatic (reboot'ta otomatik baslar)" -ForegroundColor Cyan
Write-Host "  Portal        : http://$($env:COMPUTERNAME):$Port" -ForegroundColor Cyan
Write-Host "  Lokal test    : http://localhost:$Port" -ForegroundColor Cyan
Write-Host "  Giris         : admin / IoCManager2026!" -ForegroundColor Cyan
Write-Host "  UYARI         : Ilk girisde sifreyi degistirin!" -ForegroundColor Red
Write-Host ""

if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "  Servis Running degil. Kontrol icin:" -ForegroundColor Yellow
    Write-Host "    Get-Content $AppDir\logs\service-err.log -Tail 30" -ForegroundColor Yellow
    Write-Host "    Get-Service $SvcName" -ForegroundColor Yellow
    Write-Host ""
}
