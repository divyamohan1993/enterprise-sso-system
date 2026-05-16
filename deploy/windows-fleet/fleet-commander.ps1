<#
=================================================================================
 MILNET SSO - Fleet Commander
=================================================================================
 One double-click deploys the entire 21-node quantum-safe SSO cluster across the
 machines on your LAN.

 Flow:
   1. Pre-flight  - check the controller has OpenSSH + WSL2.
   2. Identity    - generate / load the fleet SSH keypair, export the public key.
   3. Discover    - scan the LAN, list every reachable host.
   4. Select      - YOU pick the IPs (GUI) and click Deploy. Nothing connects
                    until you do, and only to enrolled hosts you chose.
   5. Probe       - confirm SSH + WSL capability on each chosen host.
   6. Map         - assign the chosen hosts to the 21 MILNET roles.
   7. Build       - compile the 10 MILNET binaries once (controller WSL2).
   8. Ceremony    - generate the CA, per-node mTLS certs, master KEK + sub-keys,
                    FROST 3-of-5 shares - the quantum-safe key material.
   9. Deploy      - per node: SSH in, provision WSL2, push the role payload,
                    start the systemd services.
  10. Verify      - health + quorum dashboard (Raft / FROST / OPAQUE / BFT).

 Authorized-use note: this tool DEPLOYS to machines you own and have enrolled
 (see node\Enroll-This-Node.bat). It does not exploit or commandeer anything.
 Discovery only lists hosts; connection needs your selection AND the SSH key
 you authorized on each node.
=================================================================================
#>
[CmdletBinding()]
param(
    [string]$SshUser     = $env:USERNAME,
    [string]$Distro      = 'Ubuntu-22.04',
    [int]   $MaxParallel = 6,
    [switch]$NoGui,
    [string[]]$Hosts            # optional: skip the GUI, pass IPs directly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ------------------------------------------------------------------ paths ----
$Script:Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:StateDir  = Join-Path $env:USERPROFILE '.milnet'
$Script:KeyPath   = Join-Path $StateDir 'fleet_id_ed25519'
$Script:PubPath   = "$KeyPath.pub"
$Script:KnownHosts= Join-Path $StateDir 'known_hosts'
$Script:WorkDir   = Join-Path $StateDir 'work'
$Script:LogFile   = Join-Path $StateDir ("deploy-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
$Script:TopoFile  = Join-Path $Root 'topology.json'
$Script:RepoRoot  = (Resolve-Path (Join-Path $Root '..\..')).Path

New-Item -ItemType Directory -Force -Path $StateDir, $WorkDir | Out-Null

# --------------------------------------------------------------- logging ----
function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = "[{0:HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Msg
    $color = switch ($Level) {
        'OK'   { 'Green' }  'WARN' { 'Yellow' }
        'ERR'  { 'Red' }    'STEP' { 'Cyan' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $Script:LogFile -Value $line -ErrorAction SilentlyContinue
}
function Write-Banner {
    param([string]$Text)
    $bar = '=' * 78
    Write-Host ""
    Write-Host $bar -ForegroundColor DarkCyan
    Write-Host ("  " + $Text) -ForegroundColor White
    Write-Host $bar -ForegroundColor DarkCyan
}

# =============================================================================
# 1. PRE-FLIGHT
# =============================================================================
function Test-Prerequisites {
    Write-Log 'Checking controller prerequisites...' 'STEP'

    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    if ($build -lt 22000) { throw "Windows 11 required on the controller (build >= 22000). Found $build." }
    Write-Log "Windows 11 build $build" 'OK'

    if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
        throw "OpenSSH client not found. Install it: Settings > Apps > Optional Features > OpenSSH Client."
    }
    if (-not (Get-Command scp.exe -ErrorAction SilentlyContinue)) {
        throw "scp.exe not found (part of OpenSSH client)."
    }
    Write-Log "OpenSSH client present" 'OK'

    $env:WSL_UTF8 = '1'
    $wslOk = $false
    try { & wsl.exe --status *>$null; if ($LASTEXITCODE -eq 0) { $wslOk = $true } } catch {}
    if (-not $wslOk) {
        Write-Log "WSL2 not ready on the controller - attempting 'wsl --install'..." 'WARN'
        & wsl.exe --install --no-distribution 2>&1 | ForEach-Object { Write-Log $_ }
        throw "WSL2 was just enabled on this controller. REBOOT, then double-click MILNET-Fleet-Commander.bat again."
    }
    Write-Log "WSL2 available on controller" 'OK'

    # ensure the build distro exists on the controller (used to compile binaries)
    $distros = (& wsl.exe --list --quiet 2>$null) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($distros -notcontains $Distro) {
        Write-Log "Installing controller build distro: $Distro" 'STEP'
        & wsl.exe --install -d $Distro --no-launch 2>&1 | ForEach-Object { Write-Log $_ }
        Start-Sleep 5
    }
    Write-Log "Controller build distro ready: $Distro" 'OK'
}

# =============================================================================
# 2. FLEET SSH IDENTITY
# =============================================================================
function Initialize-FleetIdentity {
    Write-Log 'Preparing fleet SSH identity...' 'STEP'
    if (-not (Test-Path $Script:KeyPath)) {
        Write-Log "Generating new ed25519 fleet keypair..." 'INFO'
        & ssh-keygen.exe -t ed25519 -N '""' -C "milnet-fleet-commander" -f $Script:KeyPath -q
        if (-not (Test-Path $Script:KeyPath)) { throw "ssh-keygen failed to create $Script:KeyPath" }
    }
    $pub = (Get-Content $Script:PubPath -Raw).Trim()
    # export the public key next to the enrollment script for easy distribution
    Copy-Item $Script:PubPath (Join-Path $Root 'fleet-authorized-key.pub') -Force
    Copy-Item $Script:PubPath (Join-Path $Root 'node\fleet-authorized-key.pub') -Force -ErrorAction SilentlyContinue
    Write-Log "Fleet public key ready (exported to fleet-authorized-key.pub)" 'OK'
    return $pub
}

# =============================================================================
# 3. LAN DISCOVERY
# =============================================================================
function Get-LanSubnets {
    # Skip virtual adapters (WSL, Hyper-V, Docker) - they are not the real LAN.
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and
            $_.PrefixOrigin -in 'Dhcp','Manual' -and
            $_.InterfaceAlias -notmatch 'WSL|vEthernet|Hyper-V|Loopback|Docker'
        } |
        ForEach-Object {
            $octets = $_.IPAddress.Split('.')
            [pscustomobject]@{
                Base      = "$($octets[0]).$($octets[1]).$($octets[2])"
                Self      = $_.IPAddress
                Prefix    = $_.PrefixLength
            }
        } | Sort-Object Base -Unique
}

function Invoke-LanScan {
    param([int]$TimeoutMs = 400)
    Write-Log 'Scanning the LAN for live hosts...' 'STEP'
    $subnets = Get-LanSubnets
    if (-not $subnets) { Write-Log 'No usable LAN subnet found.' 'WARN'; return @() }

    $targets = New-Object System.Collections.Generic.List[string]
    foreach ($s in $subnets) {
        Write-Log "  subnet $($s.Base).0/24 (controller $($s.Self))" 'INFO'
        1..254 | ForEach-Object { $targets.Add("$($s.Base).$_") }
    }

    # parallel async ping
    $pings = @{}
    foreach ($ip in $targets) {
        $p = New-Object System.Net.NetworkInformation.Ping
        $pings[$ip] = $p.SendPingAsync($ip, $TimeoutMs)
    }
    $live = New-Object System.Collections.Generic.List[string]
    foreach ($ip in $targets) {
        try { if ($pings[$ip].Result.Status -eq 'Success') { $live.Add($ip) } } catch {}
    }

    # ARP table also reveals hosts that did not answer ICMP
    $arp = @{}
    foreach ($line in (arp -a)) {
        if ($line -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)') {
            $arp[$matches[1]] = $matches[2].ToUpper()
            if ($matches[3] -eq 'dynamic' -and $live -notcontains $matches[1]) { $live.Add($matches[1]) }
        }
    }

    $selfIps = $subnets.Self
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($ip in ($live | Sort-Object { [version]$_ } -Unique)) {
        if ($selfIps -contains $ip) { continue }
        $sshOpen = Test-TcpPort -IP $ip -Port 22 -TimeoutMs 600
        $name = ''
        try { $name = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}
        $results.Add([pscustomobject]@{
            Select   = $false
            IP       = $ip
            Hostname = $name
            MAC      = if ($arp.ContainsKey($ip)) { $arp[$ip] } else { '' }
            SSH      = if ($sshOpen) { 'open' } else { 'closed' }
            Status   = if ($sshOpen) { 'enrolled?' } else { 'not enrolled' }
        })
    }
    Write-Log ("Discovery found {0} host(s); {1} have SSH open." -f `
        $results.Count, ($results | Where-Object SSH -eq 'open').Count) 'OK'
    return $results
}

function Test-TcpPort {
    param([string]$IP, [int]$Port, [int]$TimeoutMs = 800)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($IP, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs) -and $client.Connected) {
            $client.EndConnect($iar); return $true
        }
        return $false
    } catch { return $false } finally { $client.Close() }
}

# =============================================================================
# 4. HOST SELECTION GUI
# =============================================================================
function Show-HostSelector {
    param([object[]]$Discovered, [string]$PublicKey)

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object Windows.Forms.Form
    $form.Text = 'MILNET SSO - Fleet Commander : Select Cluster Nodes'
    $form.Size = New-Object Drawing.Size(940, 660)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = [Drawing.Color]::FromArgb(24,26,32)
    $form.ForeColor = [Drawing.Color]::White
    $form.Font = New-Object Drawing.Font('Segoe UI', 9)

    $header = New-Object Windows.Forms.Label
    $header.Text = "Select the LAN machines to become MILNET SSO nodes (minimum 5, ideal 21)."
    $header.ForeColor = [Drawing.Color]::FromArgb(120,200,255)
    $header.Location = New-Object Drawing.Point(14,12)
    $header.Size = New-Object Drawing.Size(890,22)
    $form.Controls.Add($header)

    $grid = New-Object Windows.Forms.DataGridView
    $grid.Location = New-Object Drawing.Point(14,40)
    $grid.Size = New-Object Drawing.Size(890,360)
    $grid.BackgroundColor = [Drawing.Color]::FromArgb(32,34,42)
    $grid.ForeColor = [Drawing.Color]::Black
    $grid.AllowUserToAddRows = $false
    $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.AutoSizeColumnsMode = 'Fill'

    $colSel = New-Object Windows.Forms.DataGridViewCheckBoxColumn
    $colSel.HeaderText = 'Use'; $colSel.Name = 'Select'; $colSel.FillWeight = 12
    [void]$grid.Columns.Add($colSel)
    foreach ($c in 'IP','Hostname','MAC','SSH','Status') {
        $col = New-Object Windows.Forms.DataGridViewTextBoxColumn
        $col.HeaderText = $c; $col.Name = $c; $col.ReadOnly = $true
        [void]$grid.Columns.Add($col)
    }
    foreach ($h in $Discovered) {
        $i = $grid.Rows.Add()
        $grid.Rows[$i].Cells['Select'].Value = $false
        $grid.Rows[$i].Cells['IP'].Value = $h.IP
        $grid.Rows[$i].Cells['Hostname'].Value = $h.Hostname
        $grid.Rows[$i].Cells['MAC'].Value = $h.MAC
        $grid.Rows[$i].Cells['SSH'].Value = $h.SSH
        $grid.Rows[$i].Cells['Status'].Value = $h.Status
        if ($h.SSH -ne 'open') { $grid.Rows[$i].DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(255,225,225) }
    }
    $form.Controls.Add($grid)

    # manual add
    $lblAdd = New-Object Windows.Forms.Label
    $lblAdd.Text = 'Add IP(s) manually (comma or space separated):'
    $lblAdd.Location = New-Object Drawing.Point(14,410); $lblAdd.Size = New-Object Drawing.Size(300,20)
    $form.Controls.Add($lblAdd)
    $txtAdd = New-Object Windows.Forms.TextBox
    $txtAdd.Location = New-Object Drawing.Point(316,408); $txtAdd.Size = New-Object Drawing.Size(360,22)
    $txtAdd.BackColor = [Drawing.Color]::FromArgb(45,47,56); $txtAdd.ForeColor = [Drawing.Color]::White
    $form.Controls.Add($txtAdd)
    $btnAdd = New-Object Windows.Forms.Button
    $btnAdd.Text = 'Add'; $btnAdd.Location = New-Object Drawing.Point(686,407); $btnAdd.Size = New-Object Drawing.Size(70,24)
    $form.Controls.Add($btnAdd)
    $btnAdd.Add_Click({
        foreach ($ip in ($txtAdd.Text -split '[,\s]+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })) {
            $exists = $false
            foreach ($r in $grid.Rows) { if ($r.Cells['IP'].Value -eq $ip) { $exists = $true; break } }
            if (-not $exists) {
                $sshOpen = Test-TcpPort -IP $ip -Port 22 -TimeoutMs 600
                $i = $grid.Rows.Add()
                $grid.Rows[$i].Cells['Select'].Value = $true
                $grid.Rows[$i].Cells['IP'].Value = $ip
                $grid.Rows[$i].Cells['SSH'].Value = if ($sshOpen) {'open'} else {'closed'}
                $grid.Rows[$i].Cells['Status'].Value = if ($sshOpen) {'manual'} else {'manual/unreachable'}
            }
        }
        $txtAdd.Clear()
    })

    # ssh user
    $lblUser = New-Object Windows.Forms.Label
    $lblUser.Text = 'SSH user (same on every node):'
    $lblUser.Location = New-Object Drawing.Point(14,442); $lblUser.Size = New-Object Drawing.Size(300,20)
    $form.Controls.Add($lblUser)
    $txtUser = New-Object Windows.Forms.TextBox
    $txtUser.Text = $SshUser
    $txtUser.Location = New-Object Drawing.Point(316,440); $txtUser.Size = New-Object Drawing.Size(200,22)
    $txtUser.BackColor = [Drawing.Color]::FromArgb(45,47,56); $txtUser.ForeColor = [Drawing.Color]::White
    $form.Controls.Add($txtUser)

    # key info
    $keyBox = New-Object Windows.Forms.TextBox
    $keyBox.Multiline = $true; $keyBox.ReadOnly = $true; $keyBox.ScrollBars = 'Vertical'
    $keyBox.Location = New-Object Drawing.Point(14,472); $keyBox.Size = New-Object Drawing.Size(890,70)
    $keyBox.BackColor = [Drawing.Color]::FromArgb(45,47,56); $keyBox.ForeColor = [Drawing.Color]::FromArgb(160,255,160)
    $keyBox.Text = "ENROLL EACH NODE FIRST: run node\Enroll-This-Node.bat on every machine below.`r`n" +
                   "Fleet public key (also saved as fleet-authorized-key.pub):`r`n$PublicKey"
    $form.Controls.Add($keyBox)

    $status = New-Object Windows.Forms.Label
    $status.Location = New-Object Drawing.Point(14,548); $status.Size = New-Object Drawing.Size(600,40)
    $status.ForeColor = [Drawing.Color]::FromArgb(255,210,120)
    $form.Controls.Add($status)

    $btnScan = New-Object Windows.Forms.Button
    $btnScan.Text = 'Re-scan LAN'; $btnScan.Size = New-Object Drawing.Size(110,34)
    $btnScan.Location = New-Object Drawing.Point(560,556)
    $form.Controls.Add($btnScan)

    $btnDeploy = New-Object Windows.Forms.Button
    $btnDeploy.Text = 'DEPLOY CLUSTER'; $btnDeploy.Size = New-Object Drawing.Size(150,40)
    $btnDeploy.Location = New-Object Drawing.Point(686,553)
    $btnDeploy.BackColor = [Drawing.Color]::FromArgb(0,140,80); $btnDeploy.ForeColor = [Drawing.Color]::White
    $btnDeploy.FlatStyle = 'Flat'
    $form.Controls.Add($btnDeploy)

    $btnCancel = New-Object Windows.Forms.Button
    $btnCancel.Text = 'Cancel'; $btnCancel.Size = New-Object Drawing.Size(70,40)
    $btnCancel.Location = New-Object Drawing.Point(838,553)
    $form.Controls.Add($btnCancel)

    $script:guiResult = $null
    $btnScan.Add_Click({
        $status.Text = 'Re-scanning...'
        $form.Refresh()
        $fresh = Invoke-LanScan
        $grid.Rows.Clear()
        foreach ($h in $fresh) {
            $i = $grid.Rows.Add()
            $grid.Rows[$i].Cells['Select'].Value = $false
            $grid.Rows[$i].Cells['IP'].Value = $h.IP
            $grid.Rows[$i].Cells['Hostname'].Value = $h.Hostname
            $grid.Rows[$i].Cells['MAC'].Value = $h.MAC
            $grid.Rows[$i].Cells['SSH'].Value = $h.SSH
            $grid.Rows[$i].Cells['Status'].Value = $h.Status
            if ($h.SSH -ne 'open') { $grid.Rows[$i].DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(255,225,225) }
        }
        $status.Text = 'Re-scan complete.'
    })
    $btnDeploy.Add_Click({
        $grid.EndEdit()
        $picked = @()
        foreach ($r in $grid.Rows) {
            if ($r.Cells['Select'].Value -eq $true) { $picked += [string]$r.Cells['IP'].Value }
        }
        if ($picked.Count -lt 5) {
            $status.Text = "Select at least 5 nodes (FROST 3-of-5 needs 5 distinct hosts). Selected: $($picked.Count)."
            return
        }
        if ([string]::IsNullOrWhiteSpace($txtUser.Text)) { $status.Text = 'Enter the SSH user.'; return }
        $script:guiResult = [pscustomobject]@{ Hosts = $picked; SshUser = $txtUser.Text.Trim() }
        $form.Close()
    })
    $btnCancel.Add_Click({ $script:guiResult = $null; $form.Close() })

    [void]$form.ShowDialog()
    return $script:guiResult
}

# =============================================================================
# 5. SSH HELPERS
# =============================================================================
function Get-SshArgs {
    param([string]$Target)
    return @(
        '-i', $Script:KeyPath,
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', "UserKnownHostsFile=$Script:KnownHosts",
        '-o', 'ConnectTimeout=12',
        $Target
    )
}
function Invoke-Ssh {
    param([string]$Ip, [string]$User, [string]$Command, [int]$TimeoutSec = 600)
    $target = "$User@$Ip"
    $out = & ssh.exe @(Get-SshArgs $target) $Command 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($out -join "`n") }
}
function Invoke-SshPwsh {
    # run a PowerShell snippet on a Windows node (default shell is powershell.exe)
    param([string]$Ip, [string]$User, [string]$Script, [int]$TimeoutSec = 1800)
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
    return Invoke-Ssh -Ip $Ip -User $User -Command "powershell -NoProfile -EncodedCommand $enc" -TimeoutSec $TimeoutSec
}
function Copy-ToNode {
    param([string]$Ip, [string]$User, [string]$Local, [string]$Remote)
    $target = "$User@${Ip}:$Remote"
    & scp.exe @('-i',$Script:KeyPath,'-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new',
                '-o',"UserKnownHostsFile=$Script:KnownHosts",'-r',$Local,$target) 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

# =============================================================================
# 6. TOPOLOGY RESOLUTION  (map chosen hosts -> 21 roles)
# =============================================================================
function Resolve-NodeMapping {
    param([string[]]$Hosts)
    $topo = Get-Content $Script:TopoFile -Raw | ConvertFrom-Json
    $roles = $topo.roles
    $n = $Hosts.Count
    $assignment = @{}   # roleId -> host index

    $layout = $null
    if ($topo.packing_layouts.PSObject.Properties.Name -contains "$n") {
        $layout = $topo.packing_layouts."$n"
    }
    if ($n -ge $roles.Count) {
        for ($i = 0; $i -lt $roles.Count; $i++) { $assignment[$roles[$i].id] = $i }
    }
    elseif ($layout) {
        foreach ($entry in $layout) {
            foreach ($rid in $entry.roles) { $assignment[$rid] = [int]$entry.host }
        }
    }
    else {
        # greedy bin-packer: keep threshold-group members on distinct hosts
        $load = @(0) * $n
        $groupHosts = @{}   # group -> set of host indices used
        foreach ($r in $roles) {
            $grp = $null
            if ($r.PSObject.Properties.Name -contains 'threshold_group') { $grp = $r.threshold_group }
            elseif ($r.PSObject.Properties.Name -contains 'raft_group')   { $grp = $r.raft_group }
            $forbidden = @()
            if ($grp -and $groupHosts.ContainsKey($grp)) { $forbidden = $groupHosts[$grp] }
            $best = -1; $bestLoad = [int]::MaxValue
            for ($h = 0; $h -lt $n; $h++) {
                if ($forbidden -contains $h) { continue }
                if ($load[$h] -lt $bestLoad) { $bestLoad = $load[$h]; $best = $h }
            }
            if ($best -lt 0) { for ($h=0; $h -lt $n; $h++) { if ($load[$h] -lt $bestLoad) { $bestLoad=$load[$h]; $best=$h } } }
            $assignment[$r.id] = $best
            $load[$best]++
            if ($grp) {
                if (-not $groupHosts.ContainsKey($grp)) { $groupHosts[$grp] = @() }
                $groupHosts[$grp] += $best
            }
        }
    }

    $map = New-Object System.Collections.Generic.List[object]
    foreach ($r in $roles) {
        $hi = $assignment[$r.id]
        $map.Add([pscustomobject]@{
            RoleId   = $r.id
            Label    = $r.label
            Zone     = $r.zone
            Services = $r.services
            Binaries = $r.binaries
            Role     = $r
            HostIndex= $hi
            Ip       = $Hosts[$hi]
        })
    }
    return [pscustomobject]@{ Topology = $topo; Map = $map; Hosts = $Hosts }
}

# =============================================================================
# 7-10. BUILD / CEREMONY / DEPLOY / VERIFY  -- see fleet-deploy.ps1 (dot-sourced)
# =============================================================================
. (Join-Path $Root 'fleet-deploy.ps1')

# =============================================================================
# MAIN
# =============================================================================
function Main {
    Write-Banner 'MILNET SSO - FLEET COMMANDER'
    Write-Log "Log file: $Script:LogFile" 'INFO'
    Write-Log "Repo root: $Script:RepoRoot" 'INFO'

    Test-Prerequisites
    $pub = Initialize-FleetIdentity

    Write-Banner 'STEP 1/6 - DISCOVER & SELECT NODES'
    $chosen = $null
    if ($Hosts -and $Hosts.Count -ge 5) {
        $chosen = [pscustomobject]@{ Hosts = $Hosts; SshUser = $SshUser }
        Write-Log "Using $($Hosts.Count) hosts passed on the command line." 'INFO'
    } else {
        $discovered = Invoke-LanScan
        if ($NoGui) { throw "NoGui set but no -Hosts provided." }
        $chosen = Show-HostSelector -Discovered $discovered -PublicKey $pub
    }
    if (-not $chosen) { Write-Log 'Cancelled by operator. Nothing was changed.' 'WARN'; return 2 }
    $Script:FleetUser = $chosen.SshUser
    Write-Log ("Operator selected {0} node(s) as user '{1}'." -f $chosen.Hosts.Count, $chosen.SshUser) 'OK'

    Write-Banner 'STEP 2/6 - PROBE SELECTED NODES'
    $probe = Test-FleetNodes -Hosts $chosen.Hosts -User $chosen.SshUser
    if ($probe.Reachable.Count -lt 5) {
        throw "Only $($probe.Reachable.Count) node(s) reachable over SSH. Need >= 5. Enroll them first (node\Enroll-This-Node.bat)."
    }

    Write-Banner 'STEP 3/6 - MAP HOSTS TO THE 21 MILNET ROLES'
    $plan = Resolve-NodeMapping -Hosts $probe.Reachable
    Show-DeploymentPlan -Plan $plan
    if (-not (Confirm-Plan)) { Write-Log 'Operator declined the plan. Nothing changed.' 'WARN'; return 2 }

    Write-Banner 'STEP 4/6 - BUILD BINARIES + KEY CEREMONY'
    $binDir   = Invoke-MilnetBuild
    $ceremony = Invoke-KeyCeremony -Plan $plan

    Write-Banner 'STEP 5/6 - DEPLOY TO NODES'
    $deployResults = Invoke-FleetDeploy -Plan $plan -BinDir $binDir -Ceremony $ceremony -User $Script:FleetUser

    Write-Banner 'STEP 6/6 - VERIFY HEALTH & QUORUM'
    Show-QuorumDashboard -Plan $plan -User $Script:FleetUser -DeployResults $deployResults

    Write-Banner 'DEPLOYMENT COMPLETE'
    $gw = ($plan.Map | Where-Object RoleId -eq 'node-01' | Select-Object -First 1).Ip
    Write-Log "MILNET SSO cluster is live. Gateway endpoint: https://${gw}:9100" 'OK'
    Write-Log "Full log: $Script:LogFile" 'INFO'
    return 0
}

try {
    $rc = Main
    exit $rc
} catch {
    Write-Log $_.Exception.Message 'ERR'
    Write-Log ($_.ScriptStackTrace) 'ERR'
    exit 1
}
