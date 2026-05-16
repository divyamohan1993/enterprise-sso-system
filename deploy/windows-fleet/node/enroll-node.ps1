<#
.SYNOPSIS
    MILNET SSO - Node Enrollment

.DESCRIPTION
    Run this ONCE on each Windows 11 machine that you want to become a MILNET
    SSO cluster node. It pre-authorizes the Fleet Commander to deploy to this
    machine. Nothing is "taken over" without this explicit, local consent step.

    It performs four things:
      1. Installs + enables the built-in OpenSSH Server (sshd).
      2. Sets PowerShell as the SSH default shell (so the controller can drive
         WSL2 setup remotely).
      3. Authorizes the Fleet Commander's public key (admin-level key file).
      4. Opens the Windows Firewall for SSH (22) and the MILNET service ports.

    The Fleet Commander still cannot do anything until YOU select this host's
    IP in its GUI and click Deploy. Enrollment is consent, not deployment.

.PARAMETER PublicKey
    The Fleet Commander public key. If omitted, the script looks for
    'fleet-authorized-key.pub' next to this script.

.NOTES
    Requires Administrator. Idempotent - safe to re-run.
#>
[CmdletBinding()]
param(
    [string]$PublicKey,
    [int[]]$MilnetPorts = @(22, 5432, 9090, 9100, 9101, 9102, 9103, 9104, 9105, 9106, 9108, 9109, 9190, 9110, 9111, 9112, 9113, 9114, 10100, 10101, 10102, 10103, 10104, 10105, 10106, 10108, 10109, 10110, 10111, 10112, 10113, 10114, 8080, 9080)
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "[!] $msg" -ForegroundColor Yellow }

# --- Admin check ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn2 "Not elevated - relaunching as Administrator..."
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    if ($PublicKey) { $argList += @('-PublicKey', "`"$PublicKey`"") }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    return
}

Write-Host ""
Write-Host "===== MILNET SSO - Node Enrollment =====" -ForegroundColor White
Write-Host ""

# --- Resolve the public key ---
if (-not $PublicKey) {
    $pubFile = Join-Path $PSScriptRoot 'fleet-authorized-key.pub'
    if (-not (Test-Path $pubFile)) {
        $pubFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'fleet-authorized-key.pub'
    }
    if (Test-Path $pubFile) {
        $PublicKey = (Get-Content $pubFile -Raw).Trim()
    }
}
if (-not $PublicKey -or $PublicKey -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-)') {
    throw "No valid SSH public key supplied. Pass -PublicKey '<key>' or place fleet-authorized-key.pub next to this script. (The Fleet Commander prints/exports this key on first run.)"
}

# --- 1. OpenSSH Server ---
Write-Step "Ensuring OpenSSH Server is installed..."
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
if ($cap.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
    Write-Ok "OpenSSH Server installed."
} else {
    Write-Ok "OpenSSH Server already installed."
}

Write-Step "Starting and enabling the sshd service..."
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Set-Service -Name ssh-agent -StartupType Automatic -ErrorAction SilentlyContinue
Write-Ok "sshd is running and set to start automatically."

# --- 2. Default shell = PowerShell ---
Write-Step "Setting PowerShell as the SSH default shell..."
$psPath = (Get-Command powershell.exe).Source
New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
    -Value $psPath -PropertyType String -Force | Out-Null
Write-Ok "Default shell set."

# --- 3. Authorize the Fleet Commander key ---
Write-Step "Authorizing the Fleet Commander public key..."
$adminKeys = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
$existing = ''
if (Test-Path $adminKeys) { $existing = Get-Content $adminKeys -Raw -ErrorAction SilentlyContinue }
if ($existing -notmatch [Regex]::Escape($PublicKey.Trim())) {
    Add-Content -Path $adminKeys -Value $PublicKey.Trim()
    Write-Ok "Key added to administrators_authorized_keys."
} else {
    Write-Ok "Key already authorized."
}
# Lock down ACLs as Windows OpenSSH requires (Administrators + SYSTEM only)
icacls $adminKeys /inheritance:r            | Out-Null
icacls $adminKeys /grant 'Administrators:F' | Out-Null
icacls $adminKeys /grant 'SYSTEM:F'         | Out-Null
Write-Ok "Key file ACLs hardened."

# --- 4. Firewall ---
Write-Step "Opening Windows Firewall for SSH + MILNET service ports..."
$ruleName = 'MILNET-SSO-Fleet'
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $MilnetPorts -Profile Any | Out-Null
Write-Ok "Firewall rule '$ruleName' created for $($MilnetPorts.Count) ports."

# Allow inbound ICMP echo so the Fleet Commander's LAN scan reliably finds
# this machine (Windows 11 blocks ping by default).
$pingRule = 'MILNET-SSO-Fleet-Ping'
Get-NetFirewallRule -DisplayName $pingRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $pingRule -Direction Inbound -Action Allow `
    -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
Write-Ok "Firewall rule '$pingRule' created (discoverable by LAN scan)."

Restart-Service sshd

Write-Host ""
Write-Host "===== ENROLLMENT COMPLETE =====" -ForegroundColor Green
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
        Select-Object -First 1).IPAddress
Write-Host ""
Write-Host "  This machine is now enrollable as a MILNET node."
Write-Host "  LAN IP : $ip" -ForegroundColor White
Write-Host "  Hostname: $env:COMPUTERNAME" -ForegroundColor White
Write-Host ""
Write-Host "  Go back to the Fleet Commander, select this IP, and click Deploy."
Write-Host ""
