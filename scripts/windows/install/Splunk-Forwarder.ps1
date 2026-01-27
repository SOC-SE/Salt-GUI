# ==============================================================================
# Splunk Universal Forwarder Installation - Windows
# Automates the installation and configuration of Splunk Universal Forwarder
# For Salt-GUI / CCDC Competition Use
#
# Based on original by Samuel Brucker 2024-2026
# Fixed and improved for Salt-GUI integration
# ==============================================================================

#Requires -Version 5.1

param (
    # IP address of the Splunk Indexer (receiver)
    [Parameter(Mandatory=$false)]
    [string]$INDEXER_IP = "172.20.242.20",

    # Hostname to be used by Splunk (defaults to machine hostname)
    [Parameter(Mandatory=$false)]
    [string]$SplunkHostname = $env:COMPUTERNAME,

    # Admin username for Splunk
    [Parameter(Mandatory=$false)]
    [string]$AdminUsername = "admin",

    # Admin password (will prompt if not provided)
    [Parameter(Mandatory=$false)]
    [string]$AdminPassword
)

# Define variables
$SPLUNK_VERSION = "10.0.1"
$SPLUNK_BUILD = "c486717c322b"
$SPLUNK_MSI = "splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-windows-x64.msi"
$SPLUNK_DOWNLOAD_URL = "https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/windows/${SPLUNK_MSI}"
$INSTALL_DIR = "C:\Program Files\SplunkUniversalForwarder"
$RECEIVER_PORT = "9997"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SPLUNK FORWARDER INSTALLATION" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if already installed
if (Test-Path $INSTALL_DIR) {
    Write-Host "Splunk Universal Forwarder already installed at $INSTALL_DIR" -ForegroundColor Yellow
    Write-Host "Exiting to prevent duplicate installation." -ForegroundColor Yellow
    exit 0
}

# Prompt for password if not provided
if (-not $AdminPassword) {
    $securePassword = Read-Host -Prompt "Enter Splunk admin password" -AsSecureString
    $AdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    )
}

Write-Host "`nConfiguration:" -ForegroundColor Green
Write-Host "  Indexer IP: $INDEXER_IP"
Write-Host "  Hostname: $SplunkHostname"
Write-Host "  Admin User: $AdminUsername"

Write-Host "`n[1/5] DOWNLOADING SPLUNK FORWARDER" -ForegroundColor Yellow
Write-Host "----------------------------------------"
# Disable progress bar for faster downloads
$ProgressPreference = 'SilentlyContinue'

try {
    Write-Host "Downloading from: $SPLUNK_DOWNLOAD_URL"
    Invoke-WebRequest -Uri $SPLUNK_DOWNLOAD_URL -OutFile $SPLUNK_MSI -UseBasicParsing
    Write-Host "Download complete: $SPLUNK_MSI" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to download Splunk Forwarder" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

Write-Host "`n[2/5] INSTALLING SPLUNK FORWARDER" -ForegroundColor Yellow
Write-Host "----------------------------------------"
try {
    $msiArgs = "/i `"$SPLUNK_MSI`" AGREETOLICENSE=Yes RECEIVING_INDEXER=${INDEXER_IP}:${RECEIVER_PORT} SPLUNKPASSWORD=$AdminPassword /quiet"
    Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow
    Write-Host "Installation complete" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Installation failed" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Clean up MSI
Remove-Item $SPLUNK_MSI -Force -ErrorAction SilentlyContinue

Write-Host "`n[3/5] CONFIGURING INPUTS.CONF" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$inputsConfPath = "$INSTALL_DIR\etc\system\local\inputs.conf"

# Fixed inputs.conf - the original had garbage characters on line 51
$inputsContent = @"
# ==============================================================================
# Splunk Universal Forwarder Inputs Configuration
# For Salt-GUI / CCDC Competition Use
# ==============================================================================

# -----------------------------------------------------------------------------
# Standard Windows Event Logs
# -----------------------------------------------------------------------------

[WinEventLog://Application]
disabled = 0
index = main

[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main

# -----------------------------------------------------------------------------
# Security Services (Defender, Sysmon)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:Defender

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:Sysmon

# -----------------------------------------------------------------------------
# PowerShell Logging (Critical for threat detection)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = main
sourcetype = WinEventLog:PowerShell

[WinEventLog://Windows PowerShell]
disabled = 0
index = main
sourcetype = WinEventLog:PowerShell

# -----------------------------------------------------------------------------
# Security Tools (Suricata, Yara)
# Splunk will gracefully ignore paths that do not exist.
# -----------------------------------------------------------------------------

[monitor://C:\Program Files\Suricata\log\eve.json]
disabled = 0
index = main
sourcetype = suricata:eve

[monitor://C:\Program Files\Suricata\log\fast.log]
disabled = 0
index = main
sourcetype = suricata:fast

[monitor://C:\ProgramData\Yara\yara_scans.log]
disabled = 0
index = main
sourcetype = yara

# -----------------------------------------------------------------------------
# Firewall Logs
# -----------------------------------------------------------------------------

[monitor://C:\Windows\System32\LogFiles\Firewall\pfirewall.log]
disabled = 0
index = main
sourcetype = windows:firewall

# -----------------------------------------------------------------------------
# IIS Logs (if IIS is installed)
# -----------------------------------------------------------------------------

[monitor://C:\inetpub\logs\LogFiles\*\*.log]
disabled = 0
index = main
sourcetype = iis

# -----------------------------------------------------------------------------
# Salt Minion Logs
# -----------------------------------------------------------------------------

[monitor://C:\ProgramData\Salt Project\Salt\var\log\salt\minion]
disabled = 0
index = main
sourcetype = salt:minion

# -----------------------------------------------------------------------------
# Test Log
# -----------------------------------------------------------------------------

[monitor://C:\tmp\test.log]
disabled = 0
index = main
sourcetype = test
"@

try {
    $inputsContent | Out-File -FilePath $inputsConfPath -Encoding ASCII -Force
    Write-Host "inputs.conf configured" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not write inputs.conf" -ForegroundColor Yellow
}

Write-Host "`n[4/5] CONFIGURING SERVER.CONF" -ForegroundColor Yellow
Write-Host "----------------------------------------"
$serverConfPath = "$INSTALL_DIR\etc\system\local\server.conf"

$serverContent = @"
[general]
serverName = $SplunkHostname
hostnameOption = shortname
"@

try {
    $serverContent | Out-File -FilePath $serverConfPath -Encoding ASCII -Force
    Write-Host "server.conf configured with hostname: $SplunkHostname" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not write server.conf" -ForegroundColor Yellow
}

Write-Host "`n[5/5] STARTING SPLUNK SERVICE" -ForegroundColor Yellow
Write-Host "----------------------------------------"

# Start the service
try {
    Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "start" -Wait -NoNewWindow
    Write-Host "Splunk Forwarder started" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not start Splunk" -ForegroundColor Yellow
}

# Enable boot-start
try {
    Start-Process -FilePath "$INSTALL_DIR\bin\splunk.exe" -ArgumentList "enable boot-start" -Wait -NoNewWindow
    Write-Host "Boot-start enabled" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not enable boot-start" -ForegroundColor Yellow
}

# Create test log directory and file
New-Item -ItemType Directory -Path "C:\tmp" -Force | Out-Null
"Test log entry - $(Get-Date)" | Out-File -FilePath "C:\tmp\test.log" -Encoding ASCII

# Verify installation
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Splunk Universal Forwarder v$SPLUNK_VERSION installed"
Write-Host "Forwarding to: ${INDEXER_IP}:${RECEIVER_PORT}"
Write-Host "Hostname: $SplunkHostname"

# Check service status
$service = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Service Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') {'Green'} else {'Yellow'})
}

Write-Host "========================================" -ForegroundColor Cyan
