# MILNET on k3s — Threshold-KEK Distributed Deployment Design

Status: design for review. Not yet executed. Authored as the deliverable for
running MILNET on k3s with **no single key anywhere** and **each pod acting as
a distinct cluster node**, with all production hardening retained.

---

## 1. Goal and constraints

Deploy the MILNET SSO system on k3s such that:

- **No single key.** The master KEK is never a single artifact. It is split
  3-of-5 via Shamir over GF(256) with hash-based VSS commitments. The KEK is
  **never reconstructed** at runtime — the system's *threshold KDF* mode has
  each node compute a partial and combine partials via HKDF.
- **Pods are nodes.** Each MILNET cluster node is one k3s pod: its own network
  namespace, IP, hostname, and process space — genuinely a separate machine to
  the software. Nodes peer over the cluster network with mutual ML-DSA-87
  attestation.
- **Hardening retained.** `MILNET_MILITARY_DEPLOYMENT`, STIG kernel gates,
  measured boot, mlock, FROST 3-of-5 signing — none are bypassed. Gates are
  *satisfied*, not disabled.

This design supersedes the laptop bring-up, which only validated the build and
the single-node path. The single-node path required disabling hardening; this
design does not.

---

## 2. Why a single k3s node was not enough

MILNET fails-closed: a service refuses to start unless it can *verify* its
security preconditions. On a single-node laptop the following gates correctly
fired (each is the system working as designed):

| Gate | Code | Requirement |
|---|---|---|
| Cluster quorum | `common/src/cluster.rs:499` | ≥2 peers → 3-node minimum |
| Distributed startup | `common/src/distributed_startup.rs` | ≥2 attested peers (`min_peers: 2`) |
| Threshold KEK | `common/src/sealed_keys.rs:153` | `MILNET_KEK_SHARE` per node |
| STIG kernel | `common/src/startup_checks.rs` | `kernel.yama.ptrace_scope ≥ 2` |
| vTPM | `common/src/startup_checks.rs:108` | `/dev/tpmrm0` present |
| KT epoch keys | `kt` service | sealed epoch seed provisioned |

This design satisfies every one of them.

---

## 3. Topology — pod = node = machine

### 3.1 The node-pod model

A MILNET *node* is a machine. In the repo's fleet that is one of up to **21**
Windows hosts, each running the full MILNET service set under systemd. The
faithful k3s equivalent: **one pod = one node = one machine.**

The cluster is a single StatefulSet, `milnet-node`, with **N replicas**:

- **N = 5 minimum** — the 3-of-5 threshold needs five share-holders
- **N = 21** for the full fleet
- pod ordinal `i` → node index `i+1` → KEK share index `((i mod 5) + 1)`

Each node-pod holds the ~10 MILNET service **containers** for that node
(gateway, orchestrator, opaque, verifier, ratchet, risk, audit, kt, admin,
tss-coordinator), plus tss-signer where assigned. All containers in a pod share
that pod's network namespace, IP, hostname, **one KEK share**, and **one mTLS
identity** — exactly as the services on a physical node would. A service uses
*its node's* share, never a per-service share.

**Pod count = N (5 to 21).** Never 55. (An earlier draft wrongly made each
service its own 5-replica StatefulSet — 10×5 ≈ 55 — this section corrects it.)

### 3.2 How the threshold quorum forms

Nodes peer over the `milnet-node` **headless Service** DNS. To derive the KEK,
a node uses its own partial plus **two peer partials** received over mTLS from
*other nodes* (`distributed_startup.rs`) — never other replicas of one service.
3 partials → 3-of-5 threshold KDF → KEK derived, never reconstructed whole.
FROST 3-of-5 signing maps the same way across five signer nodes. The
distributed-startup quorum (`min_peers: 2`) is satisfied because every node
sees ≥4 peers.

`cached_master_kek_threshold_kdf()` runs inside each service process and reads
`MILNET_KEK_SHARE` from its environment — so every container in a node-pod
inherits that node's single share via the shared pod env (see §6).

### 3.3 Resource footprint

| Cluster | Node-pods | Service containers | Approx RAM |
|---|---|---|---|
| Minimum (3-of-5) | **5** | ~50 | ~3–5 GB |
| Full fleet | **21** | ~210 | ~14–20 GB |

Pod count equals node count. A **5-node cluster (5 pods)** satisfies every gate
and is the recommended test size. The 8 GB / 2-core laptop is a build host
only — even 5 node-pods with ~50 hardened containers is marginal on it.

---

## 4. Key material and the ceremony

### 4.1 KEK ceremony (offline, one-time)

Tool: `common/examples/kek_ceremony.rs` (run via `run-ceremony.sh`).

It generates a fresh master KEK, performs `split_secret_with_commitments(&kek,
3, 5)`, **zeroizes the master**, and writes only:

- `kek-share-1.hex` .. `kek-share-5.hex` — one Shamir share per node
- `vss-commitments.hex` — VSS commitments, distributed to **all** nodes

The master KEK never touches disk. No file, and no fewer than 3 shares, can
reconstruct it.

### 4.2 FROST signing keys, mTLS CA, sub-keys, KT key

These are produced by the repo's existing ceremony,
`deploy/windows-fleet/keygen/key-ceremony.sh` + `cargo run --example
fleet_keygen -p tss`:

- internal mTLS CA + per-node certs (SHARD transport, peer attestation)
- FROST 3-of-5 sealed signer shares + group verifying key
- `kt-hmac`, `shard-hmac`, `receipt-signing`, `audit-hmac`, sub-keys

Run `key-ceremony.sh` with `--threshold-kek` semantics: skip its
`master_kek.hex` / `MILNET_ALLOW_SINGLE_KEK` step and substitute the threshold
ceremony from 4.1. (The two ceremonies are otherwise independent.)

### 4.3 Secrets in k3s

| Secret | Contents | Mounted into |
|---|---|---|
| `milnet-kek-shares` | `share-1`..`share-5` (hex) | all service StatefulSets |
| `milnet-vss-commitments` | `MILNET_VSS_COMMITMENTS` | all service StatefulSets |
| `milnet-mtls-ca` | CA cert + per-node cert/key | all (SHARD mTLS) |
| `milnet-frost-shares` | `signer-1`..`signer-5` sealed | `tss-signer` |
| `milnet-kt-keys` | `kt-epoch-<N>` sealed seed | `kt` |
| `milnet-database` | DB URL/password | DB-using services |

For a real deployment, source these via **External Secrets + Vault** (the repo
already has `deploy/kubernetes/external-secrets/`), not raw `Secret` objects.
For a lab cluster, raw Secrets created by `run-ceremony.sh` are acceptable.

---

## 5. Per-node environment contract

Each pod receives (via the ordinal→share entrypoint, see §6):

```
MILNET_KEK_SHARE          = <hex of share (ordinal+1)>     # this node only
MILNET_KEK_SHARE_INDEX    = <ordinal+1>                    # 1..5
MILNET_VSS_COMMITMENTS    = <commitments hex>              # same for all
MILNET_NODE_ID            = <stable per pod, e.g. UUIDv5(pod-name)>
MILNET_CLUSTER_PEERS      = <other replicas' host:port, comma-separated>
MILNET_THRESHOLD_KDF_CONTEXT = milnet-kek-v1               # optional
MILNET_THRESHOLD_KDF_SALT    = milnet-threshold-kdf-salt-v1 # optional
```

MUST NOT be set (the code rejects these, by design):

```
MILNET_KEK_PEER_SHARES        # all shares on one node = exit 199
MILNET_ALLOW_SINGLE_KEK       # single-KEK opt-out — not used here
MILNET_MLP_MODE_ACK           # single-KEK opt-out — not used here
```

Peer *partials* (`MILNET_KEK_PEER_PARTIALS`) are NOT pre-set: they are received
at runtime over mTLS by `distributed_startup.rs`. Each node sends only its
partial (a one-way HKDF image of its share), never the share itself.

---

## 6. Ordinal → share selection (no image rebuild)

The runtime images have a fixed `/service` entrypoint. Every service container
in a node-pod overrides its `command` with the same 3-line shell wrapper (the
`debian-bookworm-slim` runtime has `/bin/sh`) so all containers in the pod pick
up *that node's* single share:

```yaml
command: ["/bin/sh","-c"]
args:
  - |
    ord="${HOSTNAME##*-}"; idx=$(( ord % 5 + 1 ))
    export MILNET_KEK_SHARE="$(cat /etc/milnet/kek/share-${idx})"
    export MILNET_KEK_SHARE_INDEX="${idx}"
    exec /service
```

`milnet-kek-shares` is mounted read-only at `/etc/milnet/kek/`. `HOSTNAME` is
the node-pod name (`milnet-node-<ordinal>`), so the share index is pinned to
the node ordinal and stable across restarts — as StatefulSets guarantee. With
N>5, `ord % 5` reuses the five share indices across the extra nodes.

`MILNET_CLUSTER_PEERS` is built from the `milnet-node` headless Service:
`milnet-node-0.milnet-node..svc:<port> , milnet-node-1.milnet-node..:<port> ,
...` for all N nodes (the pod's own entry is harmless; the code filters self).

---

## 7. Kernel and platform hardening (the k3s node)

Applied once to every k3s node's kernel — these *raise* the security posture:

```
kernel.yama.ptrace_scope = 2        # STIG KERNEL-002
kernel.unprivileged_bpf_disabled = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
```

Persist via `/etc/sysctl.d/99-milnet-stig.conf`. On WSL2 these apply to the
WSL kernel; on a real node, to the host.

**vTPM.** `startup_checks.rs` requires `/dev/tpmrm0`. Provide a real software
TPM 2.0 with `swtpm` + the `tpm_vtpm_proxy` kernel module, exposed to pods as a
`hostPath` CharDevice volume. This is the same class of virtual TPM used by GCP
and Azure Shielded VMs — legitimate, not a bypass. If the node kernel lacks
`tpm_vtpm_proxy`, the only correct alternatives are a node with a hardware TPM
or a kernel rebuilt with `CONFIG_TCG_VTPM_PROXY`. The vTPM panic must **not**
be patched out in this design — it is satisfied with a real (virtual) TPM.

---

## 8. Deploy order

1. Harden kernel (`sysctl`), provision swtpm, verify `/dev/tpmrm0`.
2. Run KEK ceremony (§4.1) and repo ceremony (§4.2) on a trusted host.
3. Create k3s Secrets (§4.3) — ideally via External Secrets/Vault.
4. `kubectl apply` namespace, ConfigMap (no single-KEK flags), the
   `milnet-node` headless Service, then the `milnet-node` StatefulSet (N
   replicas, each pod a node holding ~10 service containers).
5. The StatefulSet rolls out node 0→N-1; the node-pods form the cluster,
   attest peers over mTLS, exchange KEK partials, derive the KEK 3-of-5.
6. tss-signer (FROST shares) and `kt` (epoch keys) run as containers on the
   nodes assigned those roles; gateway TLS terminates on each node.
7. Verify: `verify_distributed_cluster` passes, pods Ready, cross-node mTLS.

---

## 9. Files in this directory

| File | Purpose |
|---|---|
| `DESIGN.md` | this document |
| `README.md` | step-by-step operator runbook |
| `run-ceremony.sh` | runs the KEK ceremony tool, builds k3s Secret YAML |
| `node-statefulset.yaml` | the `milnet-node` StatefulSet — pod = node = machine |
| `../../../common/examples/kek_ceremony.rs` | the threshold-KEK ceremony tool |

---

## 10. Open items to confirm before executing

1. **swtpm on the target kernel.** Confirm `tpm_vtpm_proxy` is available, or
   choose hardware-TPM nodes. This is the one piece that can hard-block.
2. **Node count N.** This design uses one `milnet-node` StatefulSet of N pods
   (5 ≤ N ≤ 21), each pod a node running ~10 service containers — matching the
   repo's 21-node fleet. Confirm the exact service→node role assignment in
   `deploy/windows-fleet/` (do all nodes run all services, or are some nodes
   signer-only / gateway-only?). The template assumes every node runs the full
   set; trim per-node containers if the fleet uses role-specialised nodes.
3. **KT epoch cadence.** `kt` needs the epoch seed for the *current* epoch
   provisioned ahead of the epoch boundary; automate re-provisioning.
4. **Footprint.** N = 5 (≈5 pods, lab/minimum) or N = 21 (≈21 pods, full
   fleet) per §3.3. Pod count is always N, never a multiple of the services.
