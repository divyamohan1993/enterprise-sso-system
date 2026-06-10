# MILNET on k3s — Threshold-KEK Deployment Runbook

Operator runbook for deploying MILNET on k3s with **no single key** and
**each pod a distinct cluster node**. Read `DESIGN.md` first for the rationale
and topology. Nothing here disables hardening — every gate is *satisfied*.

## Prerequisites

- A k3s cluster sized for **N node-pods** (one pod per node): ≈3–5 GB for a
  5-node minimum cluster, ≈14–20 GB for the full 21-node fleet. Pod count =
  node count, never a multiple of the service count. See `DESIGN.md` §3.3.
- The 10 service images built and imported (`localhost/milnet/<svc>:dev`).
- Rust toolchain on the ceremony host (`cargo`, edition 2021, rust 1.88).
- For the vTPM gate: a node with a TPM, or `swtpm` + `tpm_vtpm_proxy`.

## Step 1 — Harden the k3s node kernel

On every k3s node (raises posture; satisfies the STIG gate):

```sh
sudo tee /etc/sysctl.d/99-milnet-stig.conf >/dev/null <<'EOF'
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF
sudo sysctl --system
```

## Step 2 — Provision the vTPM

Provide a real (virtual) TPM 2.0 — the same mechanism cloud Shielded VMs use:

```sh
sudo apt-get install -y swtpm swtpm-tools
sudo modprobe tpm_vtpm_proxy            # must succeed; else use a HW-TPM node
# run swtpm in --vtpm-proxy mode; it prints the spawned /dev/tpmN device
```

Expose the device to pods as a `hostPath` CharDevice volume mounted at
`/dev/tpmrm0`. If `tpm_vtpm_proxy` is unavailable, the node kernel must be
rebuilt with `CONFIG_TCG_VTPM_PROXY`, or use hardware-TPM nodes. Do **not**
patch out the vTPM check — satisfy it.

## Step 3 — KEK ceremony (trusted host, one-time)

```sh
cd deploy/kubernetes/threshold
./run-ceremony.sh 3 5            # 3-of-5;  use "3 3" for the lab variant
```

This runs `common/examples/kek_ceremony.rs`: it generates a master KEK,
Shamir-splits it 3-of-5 with VSS commitments, **zeroizes the master**, and
writes the 5 shares + commitments + a k3s Secret manifest. The master KEK is
never written to disk.

> If the example fails to compile because `getrandom`/`zeroize` are not direct
> deps of `common`, add them to `common/Cargo.toml` `[dev-dependencies]` (both
> are already workspace dependencies) and re-run.

## Step 4 — FROST / mTLS / sub-key ceremony

Run the repo's existing ceremony for the non-KEK material (FROST 3-of-5 signer
shares, internal mTLS CA + per-node certs, `kt-hmac`, sub-keys):

```sh
deploy/windows-fleet/keygen/key-ceremony.sh <out> <bin> <repo> <node-ips...>
```

Skip its single `master_kek.hex` step — the threshold KEK from Step 3 replaces
it. Keep its CA, per-node certs, FROST shares, and KT key outputs.

## Step 5 — Create k3s Secrets

Lab cluster:

```sh
kubectl apply -f kek-ceremony-out/milnet-kek-secrets.yaml
kubectl -n milnet create secret generic milnet-mtls-ca   --from-file=<ca+certs>
kubectl -n milnet create secret generic milnet-frost-shares --from-file=<frost>
kubectl -n milnet create secret generic milnet-kt-keys   --from-file=<kt seed>
shred -u kek-ceremony-out/kek-share-*.hex kek-ceremony-out/milnet-kek-secrets.yaml
```

Production: load the shares into Vault and use the existing
`deploy/kubernetes/external-secrets/` ExternalSecret objects — never raw
Secret YAML.

## Step 6 — ConfigMap (no single-KEK flags)

Apply `deploy/kubernetes/mvp/configmap.yaml` **without**
`MILNET_ALLOW_SINGLE_KEK` / `MILNET_MLP_MODE_ACK` / `MILNET_MILITARY_DEPLOYMENT=0`.
Threshold KDF activates automatically when `MILNET_KEK_SHARE` is present.

## Step 7 — Deploy the node StatefulSet

The whole cluster is one manifest, `node-statefulset.yaml` — the `milnet-node`
StatefulSet where each pod is a node holding all ~10 service containers. Set
`replicas` to your node count N (5 minimum, up to 21), then apply:

```sh
# choose N: 5 for the minimum cluster, up to 21 for the full fleet
sed -e 's/^  replicas: 5 .*/  replicas: 5/' node-statefulset.yaml | kubectl apply -f -
```

For N > 5, also extend the `MILNET_CLUSTER_PEERS` list in the manifest to all N
`milnet-node-<i>` DNS names. Then deploy Postgres, and (if using a separate
signer tier) the `milnet-signer` StatefulSet of exactly 5 replicas.

## Step 8 — Verify

```sh
kubectl -n milnet get pods                       # all Ready
kubectl -n milnet logs <svc>-0 | grep -E 'threshold|quorum|attestation'
```

Expect each service's 5 pods to: select distinct share indices, attest peers
over mTLS, exchange KEK partials, log threshold-KDF success, and pass
`verify_distributed_cluster`. Then run inter-service connectivity checks.

## What is NOT done

This is the **design + tooling**. It has not been executed end to end — the
build host (an 8 GB / 2-core laptop with an unstable WSL/Docker environment)
cannot comfortably run even a 5-node cluster (~50 hardened service containers).
Execute on a cluster that meets the §3.3 footprint, after confirming the open
items in `DESIGN.md` §10 — chiefly the vTPM mechanism and the exact
service→node role assignment for the 21-node fleet.
