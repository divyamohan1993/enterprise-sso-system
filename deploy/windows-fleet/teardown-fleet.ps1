<#
.SYNOPSIS
    MILNET SSO - Fleet Teardown. Reverses a deployment.

.DESCRIPTION
    Stops and disables every MILNET systemd service inside each node's WSL2
    guest. With -Purge it also unregisters the WSL2 distro (deletes the guest
    filesystem) and removes staged payloads - returning the machine to its
    pre-deployment state. The Windows OpenSSH enrollment is left intact unless
    -Unenroll is given.

.PARAMETER Hosts    IPs of the nodes to tear down. If omitted, the last
                    deployment plan in ~\.milnet\work is used.
.PARAMETER SshUser  SSH user (default: current user).
.PARAMETER Purge    Also unregister the WSL2 Ubuntu distro.
.PARAMETER Unenroll Also remove the fleet key + firewall rule (full reversal).
#>
[CmdletBinding()]
param(
    [string[]]$Hosts,
    [string]$SshUser = $env:USERNAME,
    [switch]$Purge,
    [switch]$Unenroll
)
$ErrorActionPreference = 'Stop'

$KeyPath    = Join-Path $env:USERPROFILE '.milnet\fleet_id_ed25519'
$KnownHosts = Join-Path $env:USERPROFILE '.milnet\known_hosts'

function SshExec([string]$ip,[string]$cmd) {
    & ssh.exe -i $KeyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new `
        -o UserKnownHostsFile=$KnownHosts -o ConnectTimeout=12 "$SshUser@$ip" $cmd 2>&1
}

if (-not $Hosts) {
    $planFile = Join-Path $env:USERPROFILE '.milnet\work\last-plan.json'
    if (Test-Path $planFile) {
        $Hosts = (Get-Content $planFile -Raw | ConvertFrom-Json).Hosts
    }
}
if (-not $Hosts) { throw "No hosts given and no saved plan found. Pass -Hosts a.b.c.d,..." }

Write-Host "MILNET Fleet Teardown - $($Hosts.Count) node(s)" -ForegroundColor Cyan
foreach ($ip in $Hosts) {
    Write-Host "[$ip] stopping MILNET services..." -ForegroundColor Yellow
    $stop = @'
$units = wsl -d Ubuntu-22.04 -u root -- bash -c "systemctl list-units 'milnet-*' --no-legend --plain 2>/dev/null | awk '{print \$1}'"
foreach ($u in $units) { if ($u) { wsl -d Ubuntu-22.04 -u root -- systemctl disable --now $u 2>$null } }
wsl -d Ubuntu-22.04 -u root -- bash -c "rm -rf /tmp/milnet-payload" 2>$null
Remove-Item 'C:\milnet-stage' -Recurse -Force -ErrorAction SilentlyContinue
'@
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($stop))
    SshExec $ip "powershell -NoProfile -EncodedCommand $enc" | ForEach-Object { Write-Host "  $_" }

    if ($Purge) {
        Write-Host "[$ip] unregistering WSL2 distro..." -ForegroundColor Yellow
        SshExec $ip 'wsl --unregister Ubuntu-22.04' | ForEach-Object { Write-Host "  $_" }
    }
    if ($Unenroll) {
        Write-Host "[$ip] removing fleet enrollment..." -ForegroundColor Yellow
        $un = @'
$ak = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
if (Test-Path $ak) {
    (Get-Content $ak) | Where-Object { $_ -notmatch 'milnet-fleet-commander' } | Set-Content $ak
}
Get-NetFirewallRule -DisplayName 'MILNET-SSO-Fleet' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
'@
        $enc2 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($un))
        SshExec $ip "powershell -NoProfile -EncodedCommand $enc2" | ForEach-Object { Write-Host "  $_" }
    }
    Write-Host "[$ip] torn down." -ForegroundColor Green
}
Write-Host "Teardown complete." -ForegroundColor Cyan
