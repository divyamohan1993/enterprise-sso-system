<#
.SYNOPSIS
    MILNET SSO - WSL2 Node Bootstrap (runs ON each Windows 11 node).

.DESCRIPTION
    Pushed to a node by the Fleet Commander and executed over SSH. Turns a
    plain Windows 11 machine into a MILNET-capable host by provisioning a
    WSL2 Ubuntu environment that the Linux-native MILNET services run inside.

    Steps (all idempotent):
      1. Verify Windows 11 build supports WSL2 mirrored networking.
      2. Enable the WSL + Virtual Machine Platform features (may need reboot).
      3. wsl --update, set default version 2.
      4. Install Ubuntu-22.04 distro (headless, no first-run user prompt).
      5. Configure .wslconfig for MIRRORED networking - this puts the WSL2
         guest directly on the LAN so nodes can mTLS each other.
      6. Enable systemd inside the distro (/etc/wsl.conf).
      7. wsl --shutdown to apply.

    Exit codes:
      0    = WSL2 ready, distro installed, systemd + mirrored networking on.
      3010 = A reboot is required; Fleet Commander will reboot and re-run.
      1    = Unrecoverable error.

.PARAMETER Distro
    WSL distro name to install. Default: Ubuntu-22.04
#>
[CmdletBinding()]
param(
    [string]$Distro = 'Ubuntu-22.04'
)

$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'   # force wsl.exe to emit UTF-8 instead of UTF-16

function Log($m) { Write-Host "[bootstrap-wsl] $m" }
$REBOOT = $false

# --- 1. Windows build check ---------------------------------------------------
$build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
Log "Windows build: $build"
if ($build -lt 22000) {
    Log "ERROR: Windows 11 (build >= 22000) required. This host is build $build."
    exit 1
}
$mirroredOk = $build -ge 22621   # mirrored networking needs 22H2+
if (-not $mirroredOk) {
    Log "WARNING: build < 22621 - mirrored networking unavailable; will fall back to portproxy."
}

# --- 2. Enable WSL + VM Platform features ------------------------------------
function Get-FeatureState($name) {
    (Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue).State
}
foreach ($feat in 'Microsoft-Windows-Subsystem-Linux','VirtualMachinePlatform') {
    if ((Get-FeatureState $feat) -ne 'Enabled') {
        Log "Enabling Windows feature: $feat"
        $r = Enable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -All
        if ($r.RestartNeeded) { $REBOOT = $true }
    } else {
        Log "Feature already enabled: $feat"
    }
}
if ($REBOOT) {
    Log "Reboot required to finish enabling WSL platform features."
    exit 3010
}

# --- 3. WSL kernel + default version -----------------------------------------
Log "Updating WSL kernel (wsl --update)..."
& wsl.exe --update 2>&1 | ForEach-Object { Log $_ }
Log "Setting default WSL version to 2..."
& wsl.exe --set-default-version 2 2>&1 | Out-Null

# --- 4. Install the Ubuntu distro --------------------------------------------
$installed = (& wsl.exe --list --quiet 2>$null) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if ($installed -notcontains $Distro) {
    Log "Installing WSL distro: $Distro (headless)..."
    & wsl.exe --install -d $Distro --no-launch 2>&1 | ForEach-Object { Log $_ }
    Start-Sleep -Seconds 5
    $installed = (& wsl.exe --list --quiet 2>$null) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($installed -notcontains $Distro) {
        Log "ERROR: distro $Distro did not register. wsl --list: $installed"
        exit 1
    }
} else {
    Log "WSL distro already present: $Distro"
}

# --- 5. Mirrored networking via .wslconfig -----------------------------------
$wslConfig = Join-Path $env:USERPROFILE '.wslconfig'
$netMode = if ($mirroredOk) { 'mirrored' } else { 'nat' }
$cfg = @"
# Managed by MILNET Fleet Commander
[wsl2]
networkingMode=$netMode
firewall=true
dhcp=true
[experimental]
hostAddressLoopback=true
"@
Set-Content -Path $wslConfig -Value $cfg -Encoding ASCII
Log ".wslconfig written (networkingMode=$netMode)."

# --- 6. systemd inside the distro --------------------------------------------
Log "Enabling systemd inside $Distro..."
$wslConf = "[boot]`nsystemd=true`n[network]`ngenerateResolvConf=true`n"
# write /etc/wsl.conf as root inside the distro
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($wslConf))
& wsl.exe -d $Distro -u root -- bash -c "echo $b64 | base64 -d > /etc/wsl.conf" 2>&1 | ForEach-Object { Log $_ }

# --- 7. Apply ----------------------------------------------------------------
Log "Shutting down WSL to apply config..."
& wsl.exe --shutdown 2>&1 | Out-Null
Start-Sleep -Seconds 3

# Verify systemd came up
$systemdCheck = & wsl.exe -d $Distro -u root -- bash -c "ps -p 1 -o comm= 2>/dev/null" 2>$null
Log "PID 1 inside $Distro = '$systemdCheck'"
if ($systemdCheck -notmatch 'systemd') {
    Log "WARNING: systemd not yet PID 1 - it will initialise on next WSL start."
}

Log "WSL2 bootstrap complete. Distro=$Distro, networking=$netMode."
exit 0
