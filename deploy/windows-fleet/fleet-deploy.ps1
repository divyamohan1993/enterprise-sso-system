<#
=================================================================================
 MILNET SSO - Fleet Commander : deployment engine
 Dot-sourced by fleet-commander.ps1. Holds the heavy lifting:
   Test-FleetNodes      - probe SSH + WSL capability
   Show-DeploymentPlan  - render the 21-role mapping
   Invoke-MilnetBuild   - compile the 10 binaries once, in controller WSL2
   Invoke-KeyCeremony   - CA, per-node mTLS certs, KEK, FROST 3-of-5 shares
   New-NodeEnvFiles     - generate each node's MILNET_* environment files
   Invoke-FleetDeploy   - per node: WSL2 bootstrap -> payload -> systemd start
   Show-QuorumDashboard - health + Raft/FROST/OPAQUE/BFT quorum verdict
=================================================================================
#>

# --------------------------------------------------------------- constants ---
$Script:Ports = @{
    gateway=9100; admin=8080; orchestrator=9101; opaque=9102; tss_coordinator=9103
    verifier=9104; ratchet=9105; risk=9106; audit=9108; kt=9109
    raft_orch=9090; raft_tss=9190; tss_signer_base=9110; health_offset=1000
}
$Script:CtrlDistro = 'Ubuntu-22.04'

# Resolve a Windows path to its /mnt/<drive>/... WSL form.
function Get-WslPath {
    param([string]$WinPath)
    $full = (Resolve-Path -LiteralPath $WinPath).Path
    $drive = $full.Substring(0,1).ToLower()
    return '/mnt/' + $drive + ($full.Substring(2) -replace '\\','/')
}

# Write a file with strict LF endings (bash / systemd / env files require it).
function Write-LfFile {
    param([string]$Path, [string]$Content)
    $lf = ($Content -replace "`r`n","`n") -replace "`r","`n"
    [System.IO.File]::WriteAllText($Path, $lf, (New-Object System.Text.UTF8Encoding($false)))
}

# Run a bash script (given as a local file) inside the controller's WSL2,
# CR-stripping it first so Windows line endings never break the shebang.
function Invoke-CtrlWslScript {
    param([string]$LocalScript, [string[]]$ScriptArgs = @())
    $staged = Join-Path $Script:WorkDir ('wsl-' + (Split-Path $LocalScript -Leaf))
    Write-LfFile -Path $staged -Content (Get-Content -LiteralPath $LocalScript -Raw)
    $wslScript = Get-WslPath $staged
    $allArgs = @('-d', $Script:CtrlDistro, '-u', 'root', '--', 'bash', $wslScript) + $ScriptArgs
    & wsl.exe @allArgs 2>&1 | ForEach-Object { Write-Log $_ }
    return $LASTEXITCODE
}

# =============================================================================
# PROBE
# =============================================================================
function Test-FleetNodes {
    param([string[]]$Hosts, [string]$User)
    Write-Log "Probing $($Hosts.Count) node(s) for SSH + WSL readiness..." 'STEP'
    $reachable = New-Object System.Collections.Generic.List[string]
    $unreachable = New-Object System.Collections.Generic.List[string]
    foreach ($ip in $Hosts) {
        $r = Invoke-Ssh -Ip $ip -User $User -Command 'echo MILNET_SSH_OK' -TimeoutSec 20
        if ($r.ExitCode -eq 0 -and $r.Output -match 'MILNET_SSH_OK') {
            Write-Log "  $ip  SSH OK" 'OK'
            $reachable.Add($ip)
        } else {
            Write-Log "  $ip  unreachable - not enrolled? ($($r.Output.Trim()))" 'WARN'
            $unreachable.Add($ip)
        }
    }
    return [pscustomobject]@{ Reachable = $reachable.ToArray(); Unreachable = $unreachable.ToArray() }
}

# =============================================================================
# PLAN DISPLAY + CONFIRM
# =============================================================================
function Show-DeploymentPlan {
    param([object]$Plan)
    Write-Log "Deployment plan ($($Plan.Hosts.Count) hosts -> 21 MILNET roles):" 'STEP'
    $rows = $Plan.Map | ForEach-Object {
        [pscustomobject]@{
            Node     = $_.RoleId
            Role     = $_.Label
            Zone     = $_.Zone
            'LAN IP' = $_.Ip
            Services = ($_.Services -join ', ')
        }
    }
    $rows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ -ForegroundColor Gray }

    # persist the plan so teardown-fleet.ps1 can find the hosts later
    $planFile = Join-Path $Script:WorkDir 'last-plan.json'
    @{ Hosts = $Plan.Hosts; When = (Get-Date).ToString('o') } | ConvertTo-Json |
        Set-Content -Path $planFile -Encoding ASCII

    $byHost = $Plan.Map | Group-Object Ip
    Write-Log "Host packing: $($Plan.Hosts.Count) machine(s), $($Plan.Map.Count) roles" 'INFO'
    foreach ($g in $byHost) {
        Write-Log ("  {0} -> {1}" -f $g.Name, (($g.Group.Label) -join ', ')) 'INFO'
    }
}

function Confirm-Plan {
    Add-Type -AssemblyName System.Windows.Forms
    $r = [System.Windows.Forms.MessageBox]::Show(
        "Proceed to BUILD the MILNET binaries, run the key ceremony, and DEPLOY to the selected nodes?`n`nEach node gets a WSL2 Ubuntu environment running its MILNET services. This is reversible with teardown-fleet.ps1.",
        'MILNET Fleet Commander - Confirm Deployment',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question)
    return ($r -eq [System.Windows.Forms.DialogResult]::Yes)
}

# =============================================================================
# BUILD  (compile the 10 binaries once, in the controller's WSL2)
# =============================================================================
function Invoke-MilnetBuild {
    Write-Log 'Building MILNET binaries in controller WSL2 (one-time)...' 'STEP'
    $binOut = Join-Path $Script:WorkDir 'bin'
    New-Item -ItemType Directory -Force -Path $binOut | Out-Null

    $svc = 'gateway','orchestrator','opaque','tss','verifier','ratchet','risk','audit','kt','admin'
    $relDir = Join-Path $Script:RepoRoot 'target\release'
    $haveAll = $true
    foreach ($s in $svc) { if (-not (Test-Path (Join-Path $relDir $s))) { $haveAll = $false } }

    if (-not $haveAll) {
        $repoWsl = Get-WslPath $Script:RepoRoot
        $buildSh = @"
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo '[build] installing toolchain + system dependencies...'
apt-get update -qq
apt-get install -y -qq build-essential cmake clang pkg-config libssl-dev \
    ca-certificates curl git perl nasm >/dev/null
if ! command -v cargo >/dev/null 2>&1; then
  echo '[build] installing Rust 1.88 toolchain...'
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88.0 >/dev/null
fi
export PATH="\$HOME/.cargo/bin:\$PATH"
cd '$repoWsl'
echo '[build] cargo build --release (several minutes on first run)...'
cargo build --release
echo '[build] done.'
"@
        $buildFile = Join-Path $Script:WorkDir 'milnet-build.sh'
        Write-LfFile -Path $buildFile -Content $buildSh
        $rc = Invoke-CtrlWslScript -LocalScript $buildFile
        if ($rc -ne 0) { throw "cargo build failed (exit $rc). See the log." }
    } else {
        Write-Log 'Reusing existing target/release binaries.' 'OK'
    }

    $missing = @()
    foreach ($s in $svc) {
        $src = Join-Path $relDir $s
        if (Test-Path $src) { Copy-Item $src (Join-Path $binOut $s) -Force }
        else { $missing += $s }
    }
    if ($missing.Count -gt 0) {
        throw "These expected binaries were not produced: $($missing -join ', '). Check the crate [[bin]] names."
    }
    Write-Log "All 10 binaries staged in $binOut" 'OK'
    return $binOut
}

# =============================================================================
# KEY CEREMONY
# =============================================================================
function Invoke-KeyCeremony {
    param([object]$Plan)
    Write-Log 'Running quantum-safe key ceremony...' 'STEP'
    $cerDir = Join-Path $Script:WorkDir 'ceremony'
    if (Test-Path $cerDir) { Remove-Item $cerDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $cerDir | Out-Null

    $outWsl  = Get-WslPath $cerDir
    $binWsl  = Get-WslPath (Join-Path $Script:WorkDir 'bin')
    $repoWsl = Get-WslPath $Script:RepoRoot
    $ips     = @($Plan.Hosts | Sort-Object -Unique)

    $rc = Invoke-CtrlWslScript -LocalScript (Join-Path $Script:Root 'keygen\key-ceremony.sh') `
                               -ScriptArgs (@($outWsl, $binWsl, $repoWsl) + $ips)
    if ($rc -ne 0) { throw "Key ceremony failed (exit $rc)." }

    function Read-Cer($name) {
        $p = Join-Path $cerDir $name
        if (Test-Path $p) { return (Get-Content $p -Raw).Trim() }
        return ''
    }
    $cer = @{
        Dir              = $cerDir
        MasterKek        = Read-Cer 'master_kek.hex'
        GroupVerifyKey   = Read-Cer 'group_verifying_key.hex'
        PqVerifyKey      = Read-Cer 'pq_verifying_key.hex'
        TssPublicKeyPkg  = Read-Cer 'tss_public_key.b64'
        KeyPins          = Read-Cer 'key_pins.txt'
        DeploymentId     = Read-Cer 'deployment_id.txt'
        DbPassword       = Read-Cer 'db_password.txt'
        TssThreshold     = Read-Cer 'tss_threshold.txt'
        TssShares        = @{}
        SignerIds        = @{}
    }
    for ($i=1; $i -le 5; $i++) {
        $cer.TssShares[$i] = Read-Cer "tss_share_$i.b64"
        $cer.SignerIds[$i] = Read-Cer "tss_signer_$i.id"
    }
    if (-not $cer.MasterKek) { throw "Key ceremony produced no master KEK." }
    $frostOk = [bool]$cer.TssShares[1] -and [bool]$cer.GroupVerifyKey
    if ($frostOk) {
        Write-Log "Key ceremony complete: CA + per-node mTLS certs, master KEK, FROST 3-of-5 shares + group key." 'OK'
    } else {
        Write-Log "Key ceremony complete: CA + mTLS certs + KEK. FROST material NOT generated -" 'WARN'
        Write-Log "  TSS + verifier nodes will await it (see ceremony/keygen.log)." 'WARN'
    }
    return $cer
}

# =============================================================================
# ENV FILE GENERATION
# =============================================================================
function New-NodeEnvFiles {
    param([object]$Plan, [object]$Ceremony, [object]$NodeRole)

    $map = $Plan.Map
    function IpOf([string]$roleId) { ($map | Where-Object RoleId -eq $roleId | Select-Object -First 1).Ip }

    $orchIps   = @('node-02','node-03','node-04') | ForEach-Object { IpOf $_ }
    $raftPeers = ($orchIps | ForEach-Object { "${_}:$($Script:Ports.raft_orch)" }) -join ','
    $orchEndpoints = ($orchIps | ForEach-Object { "${_}:$($Script:Ports.orchestrator)" }) -join ','
    $opaqueIps = @('node-05','node-06','node-07') | ForEach-Object { IpOf $_ }
    $opaquePeers = ($opaqueIps | ForEach-Object { "${_}:$($Script:Ports.opaque)" }) -join ','
    $signerIds = @('node-08','node-09','node-10','node-11','node-12')
    $signerAddrs = (0..4 | ForEach-Object { "$(IpOf $signerIds[$_]):$($Script:Ports.tss_signer_base + $_)" }) -join ','
    # Coordinator addresses signers as "frost_id_hex@host:port" (tss/src/
    # distributed.rs load_coordinator_config_from_env). The id comes from the
    # key ceremony; if absent, fall back to bare host:port.
    $signerAddrsId = (0..4 | ForEach-Object {
        $sid = $Ceremony.SignerIds[$_ + 1]
        $sip = IpOf $signerIds[$_]
        $sp  = $Script:Ports.tss_signer_base + $_
        if ($sid) { "$sid@${sip}:$sp" } else { "${sip}:$sp" }
    }) -join ','
    # Optional crypto lines - emitted only when the ceremony produced them.
    # An empty MILNET_TSS_* / MILNET_*_VERIFYING_KEY value is fatal to the
    # consuming service, so the whole line is omitted when blank.
    $tssThreshold = if ($Ceremony.TssThreshold) { $Ceremony.TssThreshold } else { '3' }
    $auditIds  = @('node-17','node-18','node-19','node-20','node-21')
    $auditPeers = ($auditIds | ForEach-Object { "$(IpOf $_):$($Script:Ports.audit)" }) -join ','

    $kek    = $Ceremony.MasterKek
    $dbHost = IpOf 'node-02'
    $dbUrl  = "postgres://milnet:$($Ceremony.DbPassword)@${dbHost}:5432/milnet_sso?sslmode=require"
    $tls    = "/etc/milnet/tls"
    # NOTE on the env contract (verified against the source):
    #  - MILNET_PRODUCTION is left UNSET: with it set, MILNET_HSM_BACKEND=software
    #    panics (crypto/src/hsm.rs:345-349). A WSL2 lab has no HSM/TPM, so the
    #    software backend keyed on MILNET_MASTER_KEK is the only option.
    #  - MILNET_MILITARY_DEPLOYMENT must be 0: =1 makes platform_integrity
    #    exit(199) on any host without a hardware vTPM 2.0 (common/src/
    #    platform_integrity.rs:145-164).
    #  - Single master KEK (no Shamir peer shares) needs both single-KEK acks
    #    (common/src/sealed_keys.rs:542,599).
    $common = @"
MILNET_MILITARY_DEPLOYMENT=0
MILNET_HSM_BACKEND=software
MILNET_ERROR_LEVEL=verbose
MILNET_MASTER_KEK=$kek
MILNET_ALLOW_SINGLE_KEK=1
MILNET_TESTING_SINGLE_KEK_ACK=1
MILNET_KEY_DIR=/etc/milnet/keys
MILNET_TLS_CERT=$tls/node.crt
MILNET_TLS_KEY=$tls/node.key
MILNET_CA_CERT=$tls/ca.crt
MILNET_SHARD_CA_INITIAL_BOOTSTRAP=1
RUST_LOG=info,milnet=info
"@
    # MILNET_SHARD_CA_INITIAL_BOOTSTRAP=1 lets the SHARD mTLS transport create
    # its distributed CA on the first-ever deployment (shard/src/tls_ca.rs).
    # Without it, services refuse to start when no CA exists on disk yet -
    # the deliberate interlock against silently regenerating the trust anchor.
    # On later runs the CA is loaded from /var/lib/milnet/shard-ca.pem; the
    # flag then only permits (re)bootstrap for a freshly added node.

    $files = @{}
    $thisIp = $NodeRole.Ip
    foreach ($svc in $NodeRole.Services) {
        switch -Regex ($svc) {
            '^gateway$' {
                $files['gateway.env'] = @"
$common
MILNET_PQ_TLS_ONLY=1
GATEWAY_BIND_ADDR=0.0.0.0
MILNET_GATEWAY_PORT=$($Script:Ports.gateway)
MILNET_GATEWAY_CERT_PATH=$tls/node.crt
MILNET_GATEWAY_KEY_PATH=$tls/node.key
ORCH_ADDR=$(IpOf 'node-02'):$($Script:Ports.orchestrator)
MILNET_ORCHESTRATOR_ENDPOINTS=$orchEndpoints
MILNET_RATE_LIMIT_PER_IP=100
MILNET_RATE_LIMIT_PER_USER=50
MILNET_RATE_LIMIT_WINDOW_SECS=60
MILNET_RATE_LIMIT_BURST=20
MILNET_SIEM_ENABLED=false
"@
            }
            '^admin$' {
                $files['admin.env'] = @"
$common
MILNET_DEPLOYMENT_ID=$($Ceremony.DeploymentId)
ADMIN_BIND_ADDR=0.0.0.0:$($Script:Ports.admin)
ADMIN_PORT=$($Script:Ports.admin)
REQUIRE_TLS=0
DATABASE_URL=$dbUrl
"@
            }
            '^orchestrator$' {
                $oid = switch ($NodeRole.RoleId) {
                    'node-02' {'orchestrator-0'} 'node-03' {'orchestrator-1'}
                    'node-04' {'orchestrator-2'} default {"orchestrator-$($NodeRole.RoleId)"} }
                $files['orchestrator.env'] = @"
$common
MILNET_PQ_TLS_ONLY=1
MILNET_NODE_ID=$oid
MILNET_SERVICE_TYPE=orchestrator
MILNET_SERVICE_ADDR=${thisIp}:$($Script:Ports.orchestrator)
ORCH_LISTEN_ADDR=0.0.0.0:$($Script:Ports.orchestrator)
MILNET_RAFT_ADDR=${thisIp}:$($Script:Ports.raft_orch)
MILNET_CLUSTER_PEERS=$raftPeers
OPAQUE_ADDR=$(IpOf 'node-05'):$($Script:Ports.opaque)
MILNET_OPAQUE_ADDRS=$opaquePeers
TSS_ADDR=$(IpOf 'node-02'):$($Script:Ports.tss_coordinator)
MILNET_TSS_ADDRS=$signerAddrs
VERIFIER_ADDR=$(IpOf 'node-13'):$($Script:Ports.verifier)
RATCHET_ADDR=$(IpOf 'node-15'):$($Script:Ports.ratchet)
RISK_ADDR=$(IpOf 'node-20'):$($Script:Ports.risk)
AUDIT_ADDR=$(IpOf 'node-17'):$($Script:Ports.audit)
KT_ADDR=$(IpOf 'node-21'):$($Script:Ports.kt)
DATABASE_URL=$dbUrl
MILNET_CERT_LIFETIME_HOURS=720
MILNET_CERT_ROTATION_THRESHOLD=0.8
MILNET_SIEM_ENABLED=false
"@
            }
            '^opaque$' {
                $files['opaque.env'] = @"
$common
MILNET_OPAQUE_ADDR=0.0.0.0:$($Script:Ports.opaque)
MILNET_OPAQUE_MODE=threshold
MILNET_OPAQUE_SERVER_ID=$($NodeRole.Role.opaque_server_id)
MILNET_OPAQUE_THRESHOLD=2
MILNET_OPAQUE_PEERS=$opaquePeers
"@
            }
            '^tss-coordinator$' {
                $pkgLine = if ($Ceremony.TssPublicKeyPkg) { "MILNET_TSS_PUBLIC_KEY_PACKAGE=$($Ceremony.TssPublicKeyPkg)" } else { '' }
                $files['tss-coordinator.env'] = @"
$common
MILNET_TSS_ROLE=coordinator
MILNET_TSS_MODE=distributed
TSS_ADDR=0.0.0.0:$($Script:Ports.tss_coordinator)
MILNET_NODE_ID=tss-coordinator-0
MILNET_SERVICE_TYPE=tss-coordinator
MILNET_RAFT_ADDR=${thisIp}:$($Script:Ports.raft_tss)
MILNET_CLUSTER_PEERS=${thisIp}:$($Script:Ports.raft_tss)
MILNET_TSS_SIGNER_ADDRS=$signerAddrsId
$pkgLine
MILNET_TSS_THRESHOLD=$tssThreshold
MILNET_TSS_SIGNING_TIMEOUT_SECS=10
"@
            }
            '^tss-signer@(\d+)$' {
                $idx = [int]$Matches[1]
                $port = $Script:Ports.tss_signer_base + ($idx - 1)
                $shareLine = if ($Ceremony.TssShares[$idx]) { "MILNET_TSS_SHARE_SEALED=$($Ceremony.TssShares[$idx])" } else { '' }
                $files["tss-signer-$idx.env"] = @"
$common
MILNET_TSS_ROLE=signer
MILNET_TSS_SIGNER_ADDR=0.0.0.0:$port
MILNET_TSS_SIGNER_INDEX=$idx
$shareLine
MILNET_TSS_THRESHOLD=$tssThreshold
MILNET_TSS_NONCE_STATE_PATH=/var/lib/milnet/tss_nonce_state/signer-$idx
"@
            }
            '^verifier$' {
                $gvkLine = if ($Ceremony.GroupVerifyKey) { "MILNET_GROUP_VERIFYING_KEY=$($Ceremony.GroupVerifyKey)" } else { '' }
                $pqkLine = if ($Ceremony.PqVerifyKey)    { "MILNET_PQ_VERIFYING_KEY=$($Ceremony.PqVerifyKey)" } else { '' }
                $files['verifier.env'] = @"
$common
VERIFIER_ADDR=0.0.0.0:$($Script:Ports.verifier)
RATCHET_ADDR=$(IpOf 'node-15'):$($Script:Ports.ratchet)
$gvkLine
$pqkLine
"@
            }
            '^ratchet$' {
                $files['ratchet.env'] = @"
$common
RATCHET_ADDR=0.0.0.0:$($Script:Ports.ratchet)
RATCHET_KEK=$kek
DATABASE_URL=$dbUrl
"@
            }
            '^risk$' {
                $files['risk.env'] = @"
$common
RISK_ADDR=0.0.0.0:$($Script:Ports.risk)
"@
            }
            '^audit$' {
                # BFT node index is 0-based in audit/src/bft.rs; topology
                # audit_bft_index is 1-based, so subtract 1.
                $bidx = if ($NodeRole.Role.PSObject.Properties.Name -contains 'audit_bft_index') { [int]$NodeRole.Role.audit_bft_index - 1 } else { 0 }
                $files['audit.env'] = @"
$common
AUDIT_ADDR=0.0.0.0:$($Script:Ports.audit)
AUDIT_DATA_DIR=/var/lib/milnet/audit
MILNET_BFT_NODE_INDEX=$bidx
MILNET_BFT_NODE_ADDRS=$auditPeers
KT_ADDR=$(IpOf 'node-21'):$($Script:Ports.kt)
"@
            }
            '^kt$' {
                $files['kt.env'] = @"
$common
KT_ADDR=0.0.0.0:$($Script:Ports.kt)
"@
            }
        }
    }
    return $files
}

# =============================================================================
# PER-NODE PAYLOAD + DEPLOY
# =============================================================================
function New-NodePayload {
    param([object]$Plan, [string]$BinDir, [object]$Ceremony, [object]$NodeRole)

    $payload = Join-Path $Script:WorkDir "payload\$($NodeRole.RoleId)"
    if (Test-Path $payload) { Remove-Item $payload -Recurse -Force }
    foreach ($d in 'bin','tls','keys','env','systemd') {
        New-Item -ItemType Directory -Force -Path (Join-Path $payload $d) | Out-Null
    }

    foreach ($b in ($NodeRole.Binaries | Select-Object -Unique)) {
        Copy-Item (Join-Path $BinDir $b) (Join-Path $payload "bin\$b") -Force
    }
    Copy-Item (Join-Path $Ceremony.Dir 'ca.crt') (Join-Path $payload 'tls\ca.crt') -Force
    $ipSafe = $NodeRole.Ip -replace '\.','-'
    Copy-Item (Join-Path $Ceremony.Dir "$ipSafe.crt") (Join-Path $payload 'tls\node.crt') -Force
    Copy-Item (Join-Path $Ceremony.Dir "$ipSafe.key") (Join-Path $payload 'tls\node.key') -Force
    foreach ($k in 'shard_hmac.hex','receipt_signing.hex','audit_hmac.hex','session_enc.hex','ratchet_seed.hex','kt_hmac.hex') {
        $src = Join-Path $Ceremony.Dir $k
        if (Test-Path $src) { Copy-Item $src (Join-Path $payload "keys\$k") -Force }
    }

    $envFiles = New-NodeEnvFiles -Plan $Plan -Ceremony $Ceremony -NodeRole $NodeRole
    foreach ($name in $envFiles.Keys) {
        Write-LfFile -Path (Join-Path $payload "env\$name") -Content $envFiles[$name]
    }

    $vmDir = Join-Path $Script:RepoRoot 'deploy\vm'
    $manifest = New-Object System.Collections.Generic.List[string]
    foreach ($svc in $NodeRole.Services) {
        if ($svc -match '^tss-signer@(\d+)$') {
            Copy-Item (Join-Path $vmDir 'milnet-tss-signer@.service') (Join-Path $payload 'systemd\milnet-tss-signer@.service') -Force
            $manifest.Add("milnet-$svc.service")
        } else {
            $unit = "milnet-$svc.service"
            $src = Join-Path $vmDir $unit
            if (Test-Path $src) {
                Copy-Item $src (Join-Path $payload "systemd\$unit") -Force
                $manifest.Add($unit)
            } else {
                Write-Log "  (no systemd unit for '$svc' - skipped)" 'WARN'
            }
        }
    }
    Write-LfFile -Path (Join-Path $payload 'node.manifest') -Content ($manifest -join "`n")
    Write-LfFile -Path (Join-Path $payload 'node.info') -Content (@(
        "node_id=$($NodeRole.RoleId)", "role=$($NodeRole.Label)",
        "zone=$($NodeRole.Zone)", "ip=$($NodeRole.Ip)",
        "services=$($NodeRole.Services -join ',')") -join "`n")
    Write-LfFile -Path (Join-Path $payload 'provision-milnet.sh') `
        -Content (Get-Content -LiteralPath (Join-Path $Script:Root 'node\provision-milnet.sh') -Raw)

    # The database host (node-02) also gets PostgreSQL: ship the db marker +
    # the schema migrations so admin / ratchet / orchestrator have their store.
    if ($NodeRole.RoleId -eq 'node-02') {
        Write-LfFile -Path (Join-Path $payload 'db.conf') -Content (@(
            "DB_PASSWORD='$($Ceremony.DbPassword)'", "DB_NAME='milnet_sso'") -join "`n")
        $migSrc = Join-Path $Script:RepoRoot 'migrations'
        if (Test-Path $migSrc) {
            New-Item -ItemType Directory -Force -Path (Join-Path $payload 'migrations') | Out-Null
            Copy-Item (Join-Path $migSrc '*.sql') (Join-Path $payload 'migrations') -Force
        }
    }
    return $payload
}

function Install-OneNode {
    param([object]$Plan, [string]$BinDir, [object]$Ceremony, [object]$NodeRole, [string]$User)

    $ip = $NodeRole.Ip
    Write-Log "[$ip / $($NodeRole.Label)] deploying..." 'STEP'

    # 1. WSL2 bootstrap (may require a reboot; retry once after)
    $bootScript = Get-Content -LiteralPath (Join-Path $Script:Root 'node\bootstrap-wsl.ps1') -Raw
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $r = Invoke-SshPwsh -Ip $ip -User $User -Script $bootScript -TimeoutSec 2400
        Write-Log "[$ip] bootstrap:`n$($r.Output)" 'INFO'
        if ($r.ExitCode -eq 0) { break }
        if ($r.ExitCode -eq 3010 -and $attempt -eq 1) {
            Write-Log "[$ip] reboot required - rebooting node and waiting..." 'WARN'
            Invoke-Ssh -Ip $ip -User $User -Command 'shutdown /r /t 5 /c "MILNET WSL setup"' | Out-Null
            Start-Sleep -Seconds 45
            $online = $false
            for ($w=0; $w -lt 40; $w++) {
                if (Test-TcpPort -IP $ip -Port 22 -TimeoutMs 1500) { $online = $true; break }
                Start-Sleep -Seconds 10
            }
            if (-not $online) { throw "[$ip] node did not return after reboot." }
            Write-Log "[$ip] back online - resuming bootstrap." 'OK'
        } else {
            throw "[$ip] WSL2 bootstrap failed (exit $($r.ExitCode))."
        }
    }

    # 2. stage the payload on the node
    $payload = New-NodePayload -Plan $Plan -BinDir $BinDir -Ceremony $Ceremony -NodeRole $NodeRole
    Invoke-SshPwsh -Ip $ip -User $User -Script "Remove-Item 'C:\milnet-stage' -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force -Path 'C:\milnet-stage' | Out-Null" | Out-Null
    if (-not (Copy-ToNode -Ip $ip -User $User -Local $payload -Remote 'C:/milnet-stage/')) {
        throw "[$ip] failed to copy payload."
    }
    $payloadName = Split-Path $payload -Leaf

    # 3. run the in-WSL provisioner as root. The payload's provision-milnet.sh
    #    and env/manifest files were written with strict LF by New-NodePayload,
    #    so it runs straight from the /mnt/c mount - no copy or CR-strip needed.
    $payWsl = "/mnt/c/milnet-stage/$payloadName"
    $provPs = "wsl -d $Script:CtrlDistro -u root -- bash $payWsl/provision-milnet.sh $payWsl"
    $r = Invoke-SshPwsh -Ip $ip -User $User -Script $provPs -TimeoutSec 1800
    Write-Log "[$ip] provision:`n$($r.Output)" 'INFO'

    if ($r.ExitCode -ne 0) {
        Write-Log "[$ip] provisioning reported failures." 'ERR'
        return [pscustomobject]@{ Ip=$ip; Role=$NodeRole.Label; Ok=$false }
    }
    Write-Log "[$ip / $($NodeRole.Label)] services started." 'OK'
    return [pscustomobject]@{ Ip=$ip; Role=$NodeRole.Label; Ok=$true }
}

function Invoke-FleetDeploy {
    param([object]$Plan, [string]$BinDir, [object]$Ceremony, [string]$User)
    # dependency order: DB host first (node-02 carries PostgreSQL), then
    # data/intel -> audit -> auth core -> signing -> verify -> orch -> gateway.
    # Services use Restart=always, so any that start ahead of a dependency
    # simply restart until it converges - strict ordering is best-effort.
    $order = 'node-02',
             'node-21','node-20','node-17','node-18','node-19',
             'node-05','node-06','node-07',
             'node-08','node-09','node-10','node-11','node-12',
             'node-13','node-14','node-15','node-16',
             'node-03','node-04','node-01'
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($rid in $order) {
        $nr = $Plan.Map | Where-Object RoleId -eq $rid | Select-Object -First 1
        if (-not $nr) { continue }
        try {
            $results.Add((Install-OneNode -Plan $Plan -BinDir $BinDir -Ceremony $Ceremony -NodeRole $nr -User $User))
        } catch {
            Write-Log $_.Exception.Message 'ERR'
            $results.Add([pscustomobject]@{ Ip=$nr.Ip; Role=$nr.Label; Ok=$false })
        }
    }
    return $results
}

# =============================================================================
# VERIFY
# =============================================================================
function Show-QuorumDashboard {
    param([object]$Plan, [string]$User, [object]$DeployResults)
    Write-Log 'Verifying service health across the fleet...' 'STEP'

    $healthy = 0; $total = 0
    foreach ($nr in $Plan.Map) {
        foreach ($svc in $nr.Services) {
            $total++
            $port = switch -Regex ($svc) {
                '^gateway$'          { $Script:Ports.gateway }
                '^admin$'            { $Script:Ports.admin }
                '^orchestrator$'     { $Script:Ports.orchestrator }
                '^opaque$'           { $Script:Ports.opaque }
                '^tss-coordinator$'  { $Script:Ports.tss_coordinator }
                '^tss-signer@(\d+)$' { $Script:Ports.tss_signer_base + ([int]$Matches[1]-1) }
                '^verifier$'         { $Script:Ports.verifier }
                '^ratchet$'          { $Script:Ports.ratchet }
                '^risk$'             { $Script:Ports.risk }
                '^audit$'            { $Script:Ports.audit }
                '^kt$'               { $Script:Ports.kt }
                default { 0 }
            }
            $hp = $port + $Script:Ports.health_offset
            $open = (Test-TcpPort -IP $nr.Ip -Port $port -TimeoutMs 1500) -or `
                    (Test-TcpPort -IP $nr.Ip -Port $hp  -TimeoutMs 1500)
            if ($open) { $healthy++; $st='UP  ' } else { $st='DOWN' }
            $col = if ($open) {'Green'} else {'Red'}
            Write-Host ("  [{0}] {1,-18} {2,-16} svc:{3}" -f $st,$nr.Label,$nr.Ip,$port) -ForegroundColor $col
        }
    }

    function Get-UpCount([string[]]$roleIds, [int[]]$ports) {
        $c = 0
        for ($i=0; $i -lt $roleIds.Count; $i++) {
            $nr = $Plan.Map | Where-Object RoleId -eq $roleIds[$i] | Select-Object -First 1
            $p  = if ($ports.Count -eq 1) { $ports[0] } else { $ports[$i] }
            if ($nr -and (Test-TcpPort -IP $nr.Ip -Port $p -TimeoutMs 1500)) { $c++ }
        }
        return $c
    }
    Write-Host ""
    Write-Log 'QUORUM STATUS:' 'STEP'
    $raftUp  = Get-UpCount @('node-02','node-03','node-04') @($Script:Ports.orchestrator)
    $opUp    = Get-UpCount @('node-05','node-06','node-07') @($Script:Ports.opaque)
    $signerPorts = 0..4 | ForEach-Object { $Script:Ports.tss_signer_base + $_ }
    $frostUp = Get-UpCount @('node-08','node-09','node-10','node-11','node-12') $signerPorts
    $auditUp = Get-UpCount @('node-17','node-18','node-19','node-20','node-21') @($Script:Ports.audit)

    function Verdict($name,$up,$need,$of) {
        $ok = $up -ge $need
        $col = if ($ok) {'Green'} else {'Red'}
        $mark = if ($ok) {'QUORUM MET'} else {'QUORUM LOST'}
        Write-Host ("  {0,-22} {1}/{2} up  (need {3})  {4}" -f $name,$up,$of,$need,$mark) -ForegroundColor $col
    }
    Verdict 'Raft (orchestrator)' $raftUp  2 3
    Verdict 'OPAQUE 2-of-3'       $opUp    2 3
    Verdict 'FROST 3-of-5'        $frostUp 3 5
    Verdict 'Audit BFT'           $auditUp 3 5

    Write-Host ""
    Write-Log ("Fleet health: {0}/{1} service endpoints reachable." -f $healthy,$total) $(if ($healthy -eq $total){'OK'}else{'WARN'})
    $failed = @($DeployResults | Where-Object { -not $_.Ok })
    if ($failed.Count -gt 0) {
        Write-Log ("Nodes with deploy errors: {0}" -f (($failed.Ip) -join ', ')) 'WARN'
        Write-Log "Re-run MILNET-Fleet-Commander.bat to retry (deployment is idempotent)." 'INFO'
    }
}
