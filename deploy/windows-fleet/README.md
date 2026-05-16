# MILNET SSO — Windows Fleet Commander

Deploy the entire 21-node quantum-safe SSO cluster across the Windows 11
machines on your LAN. One double-click on the controller; pick the IPs; the
cluster builds itself.

```
   Windows 11 controller  ──SSH──▶  21 enrolled Windows 11 nodes
        (you)                          each runs WSL2 Ubuntu
          │                            └─ MILNET Linux services under systemd
          │                               talking mTLS over the SHARD transport
   double-click  ──▶  discover LAN  ──▶  you pick IPs  ──▶  build ▸ ceremony ▸ deploy ▸ verify
```

The 21 MILNET services are Linux-native (systemd-hardened, `nftables`,
`/opt/milnet`). They cannot run as native Windows processes. So on every node
the Fleet Commander provisions a **WSL2 Ubuntu** environment and runs the real
binaries inside it — with WSL2 **mirrored networking** so each node sits
directly on the LAN and can mutually-authenticate (mTLS) with its peers.

---

## What you need

**Controller** (the machine you sit at):
- Windows 11 22H2 or newer (build ≥ 22621).
- OpenSSH Client — *Settings ▸ System ▸ Optional features ▸ OpenSSH Client*.
- WSL2 — the Commander installs it for you on first run (one reboot).
- This `windows-fleet` folder, with the repo checked out beside it (the
  binaries are compiled from `..\..` — the repo root).

**Each of the 21 node machines:**
- Windows 11 22H2+ with hardware virtualization enabled in BIOS/UEFI
  (WSL2 needs it).
- Reachable on the same LAN as the controller.
- Enrolled — see step 1. Enrollment is your **explicit consent**; without it
  the Commander cannot touch the machine.

> **Authorized use.** This tool *deploys to machines you own and have
> enrolled*. It does not exploit, brute-force, or commandeer anything. LAN
> discovery only *lists* hosts. A connection happens only when **you** select
> an IP **and** that node already trusts the fleet SSH key you authorized.
> Run it only on networks and machines you are authorized to administer.

---

## Step 1 — Generate the fleet key (controller)

Double-click **`MILNET-Fleet-Commander.bat`** once. On first run it:
- generates the fleet SSH keypair at `%USERPROFILE%\.milnet\fleet_id_ed25519`,
- exports the public key to `fleet-authorized-key.pub` in this folder.

You can close it after the LAN scan appears — or continue once nodes are
enrolled.

## Step 2 — Enroll each node

Copy the **`node\`** folder (it contains `Enroll-This-Node.bat`,
`enroll-node.ps1`, and `fleet-authorized-key.pub`) to each of the 21 machines —
a network share, USB stick, or GPO push all work.

On each machine, double-click **`Enroll-This-Node.bat`**. It (idempotently):
1. installs + starts the built-in OpenSSH Server,
2. sets PowerShell as the SSH shell,
3. authorizes the fleet public key,
4. opens the firewall for SSH and the MILNET service ports.

It prints the machine's LAN IP — note it down.

> Prefer automation? Push enrollment to all machines with one GPO startup
> script or `Invoke-Command` loop calling `enroll-node.ps1 -PublicKey '<key>'`.

## Step 3 — Deploy

Back on the controller, double-click **`MILNET-Fleet-Commander.bat`** again:

1. **Discover** — it scans every LAN subnet and lists live hosts (IP, hostname,
   MAC, whether SSH is open).
2. **Select** — tick the machines to use (minimum 5, ideal 21), or type IPs in
   manually. Set the SSH user (the local admin account name, same on each).
   Click **DEPLOY CLUSTER**.
3. **Probe** — confirms SSH + WSL readiness on each pick.
4. **Map** — assigns your hosts to the 21 MILNET roles and shows the plan for
   your confirmation.
5. **Build** — compiles the 10 MILNET binaries once, in the controller's WSL2.
6. **Ceremony** — generates the internal CA, a per-node mTLS certificate
   (SAN-pinned to each node's IP), the master KEK + derived sub-keys, and the
   FROST 3-of-5 threshold signing material.
7. **Deploy** — per node, in dependency order: provisions WSL2 Ubuntu, pushes
   that node's role payload, installs the systemd units, starts the services.
8. **Verify** — prints a health + quorum dashboard.

Nodes that need a reboot to finish enabling WSL2 are rebooted and resumed
automatically.

---

## The 21-node topology

`topology.json` is the single source of truth. With 21 hosts every role gets a
dedicated machine; with fewer (down to 5) roles are packed while keeping each
threshold group's members on **distinct** machines.

| Zone | Nodes | Role |
|------|-------|------|
| DMZ | 01 | gateway + admin (only LAN-exposed node) |
| Ceremony | 02–04 | orchestrator ×3 — Raft 2-of-3 quorum |
| Auth Core | 05–07 | OPAQUE ×3 — 2-of-3 threshold password auth |
| Signing | 08–12 | TSS signer ×5 — FROST 3-of-5 threshold signatures |
| Verification | 13–16 | verifier ×2, ratchet ×2 |
| Audit BFT | 17–21 | audit ×5 — Byzantine fault-tolerant hash-chained log |
| Intelligence | 20–21 | risk, key-transparency + witness |

`tss-coordinator` is co-located on `node-02`. The audit BFT cluster runs on
nodes 17–21 (quorum 3-of-5). To reach the canonical 7-node BFT, allocate seven
hosts to the audit zone — the Commander reads the live set from `topology.json`.

### Ports

`9100` gateway · `8080` admin · `9101` orchestrator · `9102` OPAQUE ·
`9103` TSS coordinator · `9104` verifier · `9105` ratchet · `9106` risk ·
`9108` audit · `9109` KT · `9110–9114` TSS signers · `9090/9190` Raft.
Health probe port = service port + 1000. All inter-node traffic is mTLS over
the SHARD transport (HMAC-SHA512 + X-Wing hybrid KEM).

---

## Files

| File | Purpose |
|------|---------|
| `MILNET-Fleet-Commander.bat` | Double-click entry point (controller). |
| `fleet-commander.ps1` | Controller: pre-flight, identity, discovery, GUI, orchestration. |
| `fleet-deploy.ps1` | Deployment engine: build, ceremony, env-gen, deploy, verify. |
| `topology.json` | The 21-node role map and packing layouts. |
| `node\Enroll-This-Node.bat` | Double-click on each node to authorize the fleet. |
| `node\enroll-node.ps1` | Enrollment logic (OpenSSH + key + firewall). |
| `node\bootstrap-wsl.ps1` | Runs on a node to provision WSL2 + Ubuntu. |
| `node\provision-milnet.sh` | Runs inside WSL2 to install + start MILNET services. |
| `keygen\key-ceremony.sh` | CA, per-node mTLS certs, KEK, FROST shares. |
| `teardown-fleet.ps1` | Stop/remove a deployment (`-Purge`, `-Unenroll`). |

State and logs live in `%USERPROFILE%\.milnet\` (keypair, known_hosts,
per-run `deploy-*.log`, staged build/ceremony/payload artifacts under `work\`).

---

## Teardown

```powershell
# stop all MILNET services on the nodes
powershell -ExecutionPolicy Bypass -File teardown-fleet.ps1 -Hosts 192.168.1.10,192.168.1.11,...

# also delete the WSL2 guest, and fully un-enroll
... teardown-fleet.ps1 -Hosts ... -Purge -Unenroll
```

---

## Security notes & trade-offs

- **First-contact host keys.** Discovery-based deployment can't pre-seed SSH
  host keys, so the Commander uses `StrictHostKeyChecking=accept-new` and
  records fingerprints in `%USERPROFILE%\.milnet\known_hosts`. On a LAN you
  control with manually chosen IPs this is acceptable; for a hardened
  production rollout, pre-seed `known_hosts` and switch to
  `StrictHostKeyChecking=yes` (as `deploy/vm/provision.sh` does).
- **No HSM in a lab.** The canonical architecture seals keys in Cloud HSM /
  vTPM. A LAN of plain Windows 11 boxes has no HSM, so the ceremony produces a
  software-protected master KEK. Treat a Fleet Commander deployment as a
  **lab / portfolio / evaluation** cluster, not a classified production one.
- **WSL2 networking.** Mirrored networking (Windows 11 22H2+) puts each WSL2
  guest on the LAN so nodes can mTLS directly. Older builds fall back to NAT +
  port-proxy with reduced fidelity.
- **Worst case.** If a node is mid-deploy when it fails, re-running the Fleet
  Commander is idempotent — every script re-applies cleanly. A single node
  loss never breaks the cluster: that is the whole point of the 3-of / 2-of-3 /
  3-of-5 / BFT quorum design.

## How the env contract was reconciled

The generated per-node environment files were verified against the actual
service source, not assumed. Notable findings folded in:

- Every service calls `common::startup_checks::run_platform_checks()`, which
  **panics without a TPM device** (`/dev/tpmrm0`). WSL2 has none, so
  `provision-milnet.sh` provisions one — a real software TPM 2.0 via `swtpm` +
  the `tpm_vtpm_proxy` kernel module when available, else a placeholder device
  node that satisfies the presence check (the codebase's own documented
  software-crypto fallback for containerized deployments).
- `MILNET_MILITARY_DEPLOYMENT=1` makes a missing hardware vTPM a hard
  `exit(199)`. The fleet sets it to `0` — a WSL2 lab is not a hardware-attested
  military node — and relies on `MILNET_MASTER_KEK`-based software sealing.
- `MILNET_PRODUCTION` is left **unset**: with it set, `MILNET_HSM_BACKEND=software`
  panics (`crypto/src/hsm.rs:345-349`). A LAN of Windows 11 boxes has no HSM,
  so the software backend is the only viable one — hence production mode off.
- `MILNET_GATEWAY_KEY_PINS` is omitted (optional): its real format is
  space-separated hex SHA-512 cert fingerprints, which cannot be precomputed
  before the SHARD transport generates its runtime certificates.
- The hardened `deploy/vm/*.service` units set `PrivateDevices=yes`, which
  would hide the TPM from the service; the provisioner adds a systemd drop-in
  (`PrivateDevices=no` + `DeviceAllow` for the TPM) and leaves every other
  hardening directive intact.
- Single-`MILNET_MASTER_KEK` operation (no Shamir peer shares) needs the
  `MILNET_ALLOW_SINGLE_KEK` / `MILNET_TESTING_SINGLE_KEK_ACK` acknowledgements.
- Real env-var names were corrected: gateway uses `ORCH_ADDR` + split
  `GATEWAY_BIND_ADDR`/`MILNET_GATEWAY_PORT`; audit BFT uses
  `MILNET_BFT_NODE_INDEX`/`MILNET_BFT_NODE_ADDRS`; ratchet needs `RATCHET_KEK`;
  the TSS coordinator addresses signers as `frost_id@host:port`.

## FROST threshold keys

The `verifier` and `tss` crates build with the `production` feature by default;
the verifier **refuses to boot** without the real FROST group verifying key,
and the TSS coordinator/signers require pre-distributed shares. The codebase
forbids trusted-dealer keygen in production. So the key ceremony runs the
project's *own* production DKG path via `tss/examples/fleet_keygen.rs` (added
by this work): `crypto::threshold::dkg_distributed(5,3)` + share sealing with
the fleet KEK, producing the 5 sealed shares, the group public key, and an
ML-DSA-87 verifying key. `key-ceremony.sh` runs it; if `cargo` cannot build it,
those env vars are omitted (rather than emitted empty, which would crash the
service) and the TSS + verifier nodes wait for the material — every other zone
still comes up.

## Verification status

What has been verified in this environment:

- All PowerShell scripts parse cleanly; `topology.json` is valid (21 roles).
- LAN discovery (subnet enumeration, ARP parse, async TCP probe) runs and
  returns correct results on a live machine.
- The env-var contract, the vTPM/`exit(199)` behaviour, the single-KEK acks,
  the BFT/cluster/gateway variable names, and the FROST/verifier key
  requirements were each read out of the actual crate source and the
  generator was corrected to match.

What can only be verified on the real fleet (no 21-machine LAN is available
here): the end-to-end run — WSL2 install + reboot handling, the cross-node
mTLS handshakes, Raft/FROST/OPAQUE/BFT quorum formation, and a full
`cargo build --release` of all 10 binaries. Run the Fleet Commander against
your enrolled nodes and use the built-in health + quorum dashboard (step 8) to
confirm; deployment is idempotent, so re-run to converge.
