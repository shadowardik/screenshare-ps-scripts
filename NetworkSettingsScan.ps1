[console]::OutputEncoding = [System.Text.Encoding]::UTF8

$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n==================================================" -ForegroundColor Red
    Write-Host "           ADMINISTRATOR PRIVILEGES REQUIRED      " -ForegroundColor Red
    Write-Host "     Please run this script as Administrator!     " -ForegroundColor Red
    Write-Host "==================================================" -ForegroundColor Red
    exit
}

Write-Host " -> Network Settings Checker by qwersome (based on https://github.com/Kaiman30/NetworkSettingsChecker/blob/main/NetworkChecker.PS1)" -ForegroundColor DarkMagenta
Write-Host ""

$totalSteps = 8
$currentStep = 0
$Detected = @()
$NotDetected = @()

function Update-Progress {
    param($stepName)
    $script:currentStep++
    # Защита от превышения 100%
    $percent = [math]::Round(($script:currentStep / $totalSteps) * 100)
    if ($percent -gt 100) { $percent = 100 }
    
    Write-Progress -Activity "Scanning Network Settings" -Status $stepName -PercentComplete $percent
}

function Get-RegVal {
    param($Path, $Name)
    $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $val -and $null -ne $val.$Name) { return $val.$Name }
    return $null
}

# ===================================================================
# 1. TCP/IP GLOBAL PARAMETERS
# ===================================================================
Update-Progress "Checking TCP/IP Parameters..."
$tcpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

$tcpKeys = @(
    "SackOpts", "EnableWsd", "Tcp1323Opts",
    "DefaultTTL", "EnablePMTUDiscovery", "EnablePMTUBHDetect",
    "GlobalMaxTcpWindowSize", "TcpMaxDataRetransmissions"
)

foreach ($k in $tcpKeys) {
    $val = Get-RegVal -Path $tcpPath -Name $k
    if ($null -ne $val) {
        $Detected += "$k - $val"
    } else {
        $NotDetected += $k
    }
}

# ===================================================================
# 2. AFD PARAMETERS (UDP)
# ===================================================================
Update-Progress "Checking UDP Acceleration..."
$afdVal = Get-RegVal -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "FastSendDatagramThreshold"
if ($null -ne $afdVal) { 
    $Detected += "FastSendDatagramThreshold - $afdVal" 
} else { 
    $NotDetected += "FastSendDatagramThreshold" 
}

# ===================================================================
# 3. SYSTEM PROFILE (Throttling)
# ===================================================================
Update-Progress "Checking System Throttling..."
$sysPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"

$nti = Get-RegVal -Path $sysPath -Name "NetworkThrottlingIndex"
if ($null -ne $nti -and $nti -ne 10) { 
    $Detected += "NetworkThrottlingIndex - $nti" 
} else { 
    $NotDetected += "NetworkThrottlingIndex" 
}

# ===================================================================
# 4. QoS BANDWIDTH
# ===================================================================
Update-Progress "Checking QoS Bandwidth..."
$qosVal = Get-RegVal -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit"
if ($null -ne $qosVal) { 
    $Detected += "NonBestEffortLimit - $qosVal" 
} else { 
    $NotDetected += "NonBestEffortLimit" 
}

# ===================================================================
# 5. INTERFACE SETTINGS (Nagle/ACK)
# ===================================================================
Update-Progress "Checking Interface Settings..."
$ifaceKeys = @("TCPNoDelay", "TcpAckFrequency", "TcpDelAckTicks")
$interfaces = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -ErrorAction SilentlyContinue

foreach ($k in $ifaceKeys) {
    $found = $null
    foreach ($iface in $interfaces) {
        $v = Get-RegVal -Path $iface.PSPath -Name $k
        if ($null -ne $v) { $found = $v; break }
    }
    if ($null -ne $found) { 
        $Detected += "$k - $found" 
    } else { 
        $NotDetected += $k 
    }
}

# ===================================================================
# 6. DRIVER KEYS CHECK
# ===================================================================
Update-Progress "Checking Driver Keys..."
$adapters = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^.*\\\\[0-9]{4}$' }

$jumboFound = $null
foreach ($adapter in $adapters) {
    $v = Get-RegVal -Path $adapter.PSPath -Name "*JumboPacket"
    if ($null -ne $v -and $v -ne "1514") { $jumboFound = $v; break }
}
if ($null -ne $jumboFound) { 
    $Detected += "*JumboPacket - $jumboFound" 
} else { 
    $NotDetected += "*JumboPacket" 
}

# ===================================================================
# 7. NETSH TCP GLOBAL
# ===================================================================
Update-Progress "Checking Netsh TCP Global..."
$netshOutput = netsh int tcp show global 2>$null | Out-String
if ($netshOutput -match "Мощность ECN.*disabled|ECN Capability.*disabled") {
    $Detected += "ECN Capability (disabled)"
} else {
    $NotDetected += "ECN Capability"
}

# ===================================================================
# FINALIZE PROGRESS
# ===================================================================
Update-Progress "Завершение..."
Start-Sleep -Milliseconds 300
Write-Progress -Activity "Scanning Network Settings" -Completed

# ===================================================================
# SUMMARY OUTPUT
# ===================================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "                         Отчет                              " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "`n  [X] Обнаруженные настройки (требуют внимания): " -NoNewline -ForegroundColor White
Write-Host "$($Detected.Count)" -ForegroundColor Red
if ($Detected.Count -gt 0) {
    foreach ($item in $Detected | Sort-Object) {
        Write-Host "    - $item" -ForegroundColor Red
    }
} else {
    Write-Host "    Пусто" -ForegroundColor DarkGray
}

Write-Host "`n  [V] Настройки не обнаружены (оптимально): " -NoNewline -ForegroundColor White
Write-Host "$($NotDetected.Count)" -ForegroundColor Green
if ($NotDetected.Count -gt 0) {
    $greenItems = ($NotDetected | Sort-Object) -join " | "
    Write-Host "    $greenItems" -ForegroundColor DarkGreen
}

Write-Host "`nПроверка выполнена" -ForegroundColor Cyan