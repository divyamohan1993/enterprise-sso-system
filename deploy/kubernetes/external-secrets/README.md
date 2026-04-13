# MILNET External Secrets Operator integration

Pulls all sensitive material (master KEK, TSS shares, PQ signing keys) from
HashiCorp Vault into the cluster as Kubernetes Secrets. Secrets are never
checked into git, never written to disk on operator workstations, and never
exposed to etcd in cleartext.

## Threat model

- etcd at rest: encrypted with AES-256-GCM using a KMS plugin (see "etcd
  encryption" below).
- etcd in transit: peer + client TLS mandatory.
- Vault: backed by an HSM-rooted unseal key, audit log shipped to the SIEM.

## Components

- `external-secrets-operator.yaml` — install reference for ESO v0.10+.
- `secret-store-vault.yaml` — `ClusterSecretStore` pointing at the Vault PQ
  endpoint, authenticating via Kubernetes ServiceAccount JWT.
- `externalsecret-master-kek.yaml` — maps `secret/milnet/prod/master-kek` ->
  `milnet-master-kek` Secret with key `MILNET_MASTER_KEK`.
- `externalsecret-tss-shares.yaml` — maps the 5 FROST shares to per-signer
  Secrets `milnet-tss-share-{0..4}`.
- `externalsecret-pq-signing-keys.yaml` — ML-DSA + SLH-DSA signing key
  material for the verifier and KT services.

## etcd encryption (operator runbook section)

The cluster API server MUST be started with an
`--encryption-provider-config` pointing at a config that uses an AES-GCM
provider backed by a KMS plugin. Example:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          name: vault-kms
          endpoint: unix:///var/run/kmsplugin/socket.sock
          cachesize: 1000
          timeout: 3s
      - aescbc:
          keys:
            - name: fallback
              secret: <base64-of-32-byte-key-from-HSM>
      - identity: {}
```

Verify with:

```sh
ETCDCTL_API=3 etcdctl --endpoints=https://etcd:2379 \
    get /registry/secrets/milnet/milnet-master-kek | hexdump -C | head
```

The output MUST start with `k8s:enc:` — never raw protobuf.

## Migration 007 (audit envelope encryption)

Migration `migrations/007_encrypt_audit_data.sql` requires the
`audit_envelope_encrypt(bytea, int)` function to be registered in the target
PostgreSQL instance before the migration runs. The function is installed by
the orchestrator init container at first deployment using the master KEK
fetched via this ExternalSecret. The migration will hard-fail if the function
is missing.

## Rotation

Vault paths under `secret/milnet/prod/*` are rotated quarterly per the
SIEM webhook runbook (`deploy/vm/runbooks/siem-webhook-rotate.md`). The
ExternalSecret `refreshInterval: 1h` triggers a re-fetch within an hour of
rotation; downstream pods consume the new value via the projected volume on
next restart (deployment rollout).
