# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-06-10

Post-audit hardening, Wave 1. A 10-domain code audit (root + bit-clone + APT +
quantum threat model) found that strong security mechanisms existed in-tree but
the live paths bypassed them. Wave 1 wires them in and closes 5 CRITICAL + several
HIGH findings. Every change is fail-closed and was verified by building + testing
on a Linux host (`RUST_MIN_STACK=8388608` for the PQ suites).

### Security

- **crypto (PQC core)** — closes "no real PQ KATs" (CRITICAL) and the non-standard
  X-Wing combiner (HIGH):
  - X-Wing combiner rebuilt to the IETF construction
    `SHA3-256(ss_M || ss_X || ct_X || pk_X || "MILNET-XWING-v2")`, restoring the
    MAL-BIND-K-CT / MAL-BIND-K-PK binding the previous HKDF-of-secrets combiner
    dropped. ML-KEM-1024 retained for CNSA 2.0 Level 5 ("X-Wing-1024" variant);
    32-byte IETF secret expanded to MILNET's 64-byte `SharedSecret` via one
    domain-separated SHA3-512 (downstream unchanged). Follows
    draft-connolly-cfrg-xwing-kem §5.3.
  - Real fixed-input → fixed-output Known-Answer Tests for ML-KEM-1024 (FIPS 203,
    NIST ACVP vectors) and ML-DSA-87 (FIPS 204, IETF LAMPS vector), wired into
    `run_startup_kats()` so a wrong/backdoored primitive output fails closed.
    (Previous "KATs" were roundtrip self-tests a buggy impl could pass.)
  - Fail-closed algorithm selection under `MILNET_MILITARY_DEPLOYMENT=1`: KEM
    locked to hybrid X-Wing-1024 (ignores `MILNET_PQ_KEM_ONLY` downgrade) and
    signatures locked to ML-DSA-87 — a compromised node cannot strip the hedge.
- **common/sealed_keys + platform_integrity (master KEK)** — closes the
  env-sourced master KEK / dead vTPM-sealing CRITICAL:
  - In military mode the master KEK / per-node KEK share is now recovered ONLY by
    unsealing a TPM blob bound to measured-boot PCRs (sha256:0,2,4,7) via the
    now-wired `tpm_seal/tpm_unseal`, never from `MILNET_MASTER_KEK`/`MILNET_KEK_SHARE`
    env. `cached_master_kek` delegates so all ~25 direct callers route through the
    vTPM. Fail-closed `exit(199)` on env-KEK present (clone indicator) / no TPM /
    missing blob / unseal failure / PCR mismatch. New `seal_master_kek_to_tpm`
    ceremony helper + `common/examples/seal_kek_ceremony.rs`. Residual (tracked):
    a same-host root still satisfies the live PCR policy — deeper fix is SEV-SNP/TDX
    attestation-bound key release.
- **opaque (clone resistance)** — closes weak-Argon2 (CRITICAL), RAM-clone OPRF-seed
  recovery (HIGH), and restart-lockout DoS (HIGH):
  - Production OPAQUE KSF raised to Argon2id v19, 64 MiB / t=3 / p=4 (was the
    library-default 19 MiB / t=2). The OPRF `ServerSetup` seed is now sealed
    (AES-256-GCM under a master-KEK HKDF subkey), persisted, and only transiently
    unsealed per request — no long-lived plaintext seed in RAM; fail-closed on
    tamper (never regenerates, which would lock out all users).
- **common/cac_auth (CAC/PIV)** — closes the authentication-bypass + OCSP-stub
  CRITICALs:
  - `authenticate()` now performs real RFC 5280 §6.1 path validation (chain to a
    trusted DoD anchor with issuer-signature verification, validity window,
    id-kp-clientAuth EKU, BasicConstraints, name chaining, required policy OIDs)
    BEFORE trusting the cert; clearance is read only from the validated cert. A
    self-signed cert can no longer self-assert TOP SECRET. `verify_ocsp_signature`
    replaced (was: accept any DER SEQUENCE) with real RFC 6960 BasicOCSPResponse
    signature verification; revoked ⇒ reject, undetermined ⇒ reject in military
    mode. X.509 parsing via `x509-cert`, all signature verification via the FIPS
    `aws-lc-rs` backend (RSA-PKCS1 SHA-256/384/512 + ECDSA P-256/P-384); the
    Marvin-vulnerable `rsa` crate is not used.

### Changed

- **Dockerfile**: set `RUST_MIN_STACK=8388608` in the runtime image — PQ
  operations (ML-KEM-1024 / ML-DSA-87 / X-Wing) can overflow the default 2 MiB
  tokio worker / `spawn_blocking` stack; this matches the CI floor and prevents a
  PQ op aborting a service thread in production.

### Security — Wave 2A (distribution / no single point of failure)

Wave 2 wires the secure distributed mechanisms so a compromised or cloned single
node cannot subvert the cluster. Closes 2 CRITICAL + HIGH/MED consensus & session
findings. Verified at code + real-swtpm level (1751/1751 common tests single-threaded;
production wiring into the service mains is tracked as a follow-up integration).

- **common/distributed_startup + cluster + raft (per-node Raft identity)** — closes
  the cluster-wide shared-HMAC CRITICAL (one node could forge consensus as ANY
  NodeId → fake quorum):
  - Every Raft message is now signed with the sender's per-node ML-DSA-87 key over
    the full message and verified against the sender's PINNED verifying key; a
    compromised node can forge only AS ITSELF. Fail-closed: unpinned sender / bad
    signature ⇒ drop + SIEM critical.
  - The per-node signing key is INDEPENDENT (fresh CSPRNG, NOT KEK-derived) and
    TPM-SEALED to each node's measured-boot PCRs (0,2,4,7) via the wired
    `Tpm2ToolsKekSealer` — UNSEAL-ONLY at runtime; key generation is an operator
    ceremony (`sealed_keys::seal_node_identity_to_tpm`). Root on node A unseals only
    A's key (forges only as A; a quorum forgery needs root on ≥quorum DISTINCT TPMs),
    and a clone on different hardware cannot unseal it. Proven on swtpm: seal/unseal
    succeed on the genuine boot chain, and after `tpm2_pcrextend` the loader fails
    closed (exit 199). KEK-derived identity remains a NON-military / dev fallback only.
  - Entry-signature hardening (HIGH): security-critical Raft entries verify against
    the COMMAND SUBJECT's key (not just the leader's), and military mode REJECTS
    unsigned / unknown-signer entries in both `handle_append_entries` and
    `handle_install_snapshot` (closing the silent-accept hole).
  - Attestation, Raft transport, and revocation share ONE `NodeId`-keyed identity +
    pinned-VK registry: `PeerAttestation` publishes the node's TPM-sealed verifying
    key COVERED by the attestation signature (no in-transit swap), and a shared
    `cluster::canonical_node_id` (UUID / 0x-hex / deterministic `Uuid::new_v5`
    fallback) makes the attestation NodeId == the transport NodeId for any
    `MILNET_NODE_ID`.
- **common/distributed_session + persistent_session + gossip (cross-node revocation)**
  — closes the "session revocation fails open / does not propagate" CRITICAL (F3) and
  HIGH (F9 any-node-mints, F7 unverified gossip):
  - Revocation is a per-user WATERMARK: the read path denies any session created
    at/before the user's revocation watermark, honored cluster-wide even where the
    session was never locally cached. `RevocationCoordinator` signs + broadcasts a
    `SessionInvalidationEvent`; the receive side verifies and applies the watermark.
  - Fail-CLOSED under partition for high-tier sessions (Tier 1/2 denied when a node
    cannot confirm non-revocation) instead of failing open until TTL.
  - Invalidation events are signed with the per-node ML-DSA key (origin attribution;
    a non-originating node cannot mint events for another) and domain-separated
    (`MILNET-SESSION-REVOKE-v1`) from the Raft transport signature to prevent
    cross-protocol signature confusion. The legacy shared-HMAC processor is
    deprecated. Gossip `handle_message` now verifies signatures before applying
    membership/piggyback updates (F7).

### Build — Wave 2A

- Root `Cargo.toml`: enable the `uuid` `v5` feature (deterministic node-id fallback
  for non-UUID `MILNET_NODE_ID` deploy values; aligns runtime with the documented
  k8s `UUIDv5(pod-name)` scheme).

## [Unreleased] - 2026-05-16

### Added

- **deploy/windows-fleet**: Windows Fleet Commander — a double-click mechanism
  to deploy the full 21-node MILNET SSO cluster across Windows 11 machines on a
  LAN. `MILNET-Fleet-Commander.bat` launches a PowerShell controller that
  discovers LAN hosts, presents a selection GUI, maps the chosen IPs onto the
  21-role topology (`topology.json`), compiles the 10 service binaries once in
  the controller's WSL2, runs a quantum-safe key ceremony (internal CA,
  per-node SAN-pinned mTLS certs, master KEK + HKDF sub-keys, FROST 3-of-5
  shares), and provisions each node: SSH in, install WSL2 Ubuntu with mirrored
  networking + systemd, push the role payload, start the hardened systemd
  units. Includes per-node enrollment (`node/Enroll-This-Node.bat`), an in-WSL
  provisioner, a health + Raft/FROST/OPAQUE/BFT quorum dashboard, and an
  idempotent teardown script. Inter-node traffic is mTLS over the SHARD
  transport. Nodes must be explicitly enrolled (SSH-key authorized) before the
  controller can deploy to them — discovery only lists hosts.
- **tss**: `examples/fleet_keygen.rs` — offline FROST 3-of-5 + ML-DSA-87 key
  ceremony helper used by the Windows Fleet Commander. Runs the production
  Pedersen DKG (`crypto::threshold::dkg_distributed`) and `seal_signer_share`
  so the sealed shares, group public key, and PQ verifying key match exactly
  what the deployed `tss` and `verifier` services consume.

## [0.5.0] - 2026-05-16

Workspace-wide security hardening pass across all 22 service/protocol crates.

### Security

- **authsrv**: removed the anonymous-subject login path; `/authorize` now requires
  an authenticated server-side login session. `id_token`/`access_token` are now
  ML-DSA-87 (FIPS 204) signed JWTs and JWKS publishes real verifying-key material.
  `/token` validates `client_id`/`redirect_uri` against the original request and
  requires client authentication (Argon2id) for all grant types. `/userinfo`
  performs full RFC 9449 DPoP proof-JWT verification; the access token is now
  DPoP-bound at `/token` issuance. `/revoke` and `/introspect` require client
  authentication; `/end_session` validates `post_logout_redirect_uri` against a
  per-client allowlist. CSPRNG failures now propagate instead of yielding
  predictable all-zero tokens.
- **admin**: closed the RBAC bypass on user-token requests — every route now
  enforces its required role; destructive operations (`delete_user`,
  `delete_portal`, `enroll_device`, `recovery_revoke_all`, ceremony
  initiate/approve) gained explicit role checks. `delete_user` now requires a
  SuperAdmin role plus an approved, single-use multi-person ceremony bound to the
  target user. `revoke_token` requires authentication and is audit-logged.
- **orchestrator**: the idempotency cache is now keyed on a secret-bound hash
  instead of the gateway-supplied correlation id, closing a token-replay window.
  Receipt verification requires the ML-DSA-87 signature (no longer satisfiable by
  HMAC alone).
- **crypto**: unsound zero-knowledge range/audit proofs now fail closed. FROST
  threshold signing nonces are never placed on the wire; the persisted nonce
  counter now deterministically seeds the nonce CSPRNG. Key-transparency consensus
  signing keys are provisioned per host instead of being co-derived from a single
  master key; persisted signed-tree-head entries are signature- and chain-verified
  on load. The distributed OPAQUE threshold mode fails closed pending a sound
  threshold-OPRF construction.
- **audit-witness**: added anti-replay/equivocation defence (fsynced append-only
  journal), domain-separated checkpoint signatures, per-connection timeouts and
  request-size caps, and removed panic-on-input paths.
- **sso-protocol**: refresh-token store keys consistently by token hash so tokens
  survive a restart; the JTI replay store no longer panics under an async runtime
  and now fails closed on database error; PKCE verification is constant-time
  regardless of input length.
- **offline-jwt**: enforces `alg` binding against the key, rejects `none`, and
  applies an RFC 8725 algorithm allowlist; added `iss`/`aud`/`nbf` validation and
  CRL freshness checks.
- **threat-intel**: API keys moved out of URL query strings into headers; added
  SSRF protection (rejects private/reserved IP ranges) and outbound request
  timeouts.
- **siem-cef-leef**: CEF/LEEF escapers now escape newline/carriage-return in
  headers and values and sanitize extension keys, preventing log-injection.
- **risk**: military mode no longer falls back to a hardcoded baseline HMAC key.
- **stig-checks**: performs real system inspection; unobserved controls report
  "not checked" instead of fabricating a pass.
- **fido**: persistent credential storage round-trips full security state
  (AAGUID, clone flag, PQ attestation); authentication verification requires
  challenge and origin binding.
- **verifier**: token verification with ratchet state now threads the real client
  DPoP key; ceremony binding is enforced fail-closed.
- **common**: 2-of-3 KEK reconstruction verifies VSS share commitments; duress PIN
  hashing upgraded to Argon2id; secret-loader authenticates its peer over the
  socket; checkpoint-signature verification uses the correct domain-bound context.

### Fixed

- **fuzz**: registered eight signature-tamper / trust-bypass fuzz harnesses that
  were present but unbuilt.
- **dudect-harness**: constant-time tests now exercise the real production
  functions instead of local shims.
- **logout-bch**, **ratchet**, **gateway**: back-channel logout URI scheme
  validation; post-restart PQ-freshness re-evaluation; assorted hardening
  (memory locking, key zeroization, atomic connection accounting).
- **gateway**: the local rate-limiter's count-min-sketch flood pre-filter no
  longer permanently denies an IP after it makes `limit` lifetime requests. The
  sketch accumulates over its seed-rotation period, which spans many rate-limit
  windows; it is now gated on a genuine-flood threshold rather than the
  per-window limit, so ordinary limit exhaustion and retries are governed by the
  authoritative per-window counter (which resets correctly and refunds denied
  requests). The sketch remains a cheap lock-free backstop for true floods.
- **kt**: the checkpoint tamper-detection regression test now tampers signed
  content (the Merkle root) so all quorum signatures fail, rather than flipping
  a single signature that a threshold quorum tolerates by design.
- Verified the entire workspace compiles on the Linux target
  (`cargo check --workspace --all-targets`) and corrected build/test issues
  surfaced by that verification.

### Changed

- Deployment contract: key-transparency consensus nodes now require an
  independently provisioned per-node signing secret and a node-index environment
  variable; the distributed OPAQUE service defaults to single-server mode; an
  existing key-transparency signed-tree-head log must be re-established from a
  trusted checkpoint when upgrading across this release.

## [0.4.0] - 2026-03-26

### Added

- Hyper-distributed 21-VM architecture across 8 isolated security zones
- Each VM is an independent security domain with zero shared credentials
- AMD SEV-SNP Confidential Computing for all VMs holding secrets
- Shamir 3-of-5 master KEK split across Cloud HSM + vTPMs + cold storage
- Auto-mutating Moving Target Defense (keys/30s, ports/6h, certs/24h, shares/7d)
- SHARD-QS triple-layer inter-VM encryption (VPC wire + mTLS 1.3 + X-Wing KEM)
- ML-DSA-87 mutual authentication on all inter-VM connections
- vTPM remote attestation with continuous re-verification (hourly)
- Cloud Armor WAF with OWASP CRS 3.3, adaptive protection, geo-blocking
- VPC Service Controls perimeter for API-level isolation
- Binary Authorization with Cloud KMS signed attestations
- C2 Spot MIG autoscaling (1-50 instances) for gateway

### Removed

- All Docker configurations (Dockerfile, Dockerfile.deploy, docker-compose.yml, .dockerignore)
- All Kubernetes manifests (deployments, services, network policies, RBAC, etc.)
- All Terraform configurations (GCE multi-VM, GCP India, AWS GovCloud, base)
- All bare-metal deployment scripts (systemd units, env files, nftables, sysctl)
- GCE deployment pipeline (build-and-push, rolling update, health checks)
- Infrastructure monitoring configs (Prometheus, Grafana, Fluent Bit, WAF rules)
- Docker entrypoint and container-based deployment model
- Old monolithic ARCHITECTURE.md

### Changed

- Deployment model: Docker/K8s/single-VM to native systemd on 21 isolated GCP VMs
- Inter-VM communication: plain SHARD mTLS to SHARD-QS (quantum-safe triple-layer)
- FROST topology: co-located 5 nodes to 5 separate Confidential VMs across 3 AZs
- OPAQUE topology: single-server to 2-of-3 Shamir threshold across 3 Confidential VMs
- Audit topology: single BFT cluster to 7 nodes across 3 availability zones
- Database: single PostgreSQL to 3-node cluster (sync + async replication) with CMEK
- Gateway: fixed VM to C2 Spot MIG with autoscaling (10 logins/month to 10K/sec)

## [0.3.0] - 2026-03-25

### Added

- FIPS 140-3 runtime toggle with cryptographic activation proof
- AEGIS-256 symmetric encryption (RFC 9312) as non-FIPS default
- AES-256-GCM FIPS fallback with algorithm-ID byte versioning
- Dual KSF abstraction: Argon2id (default) + PBKDF2-SHA512 (FIPS)
- FIPS Known Answer Tests (KATs) for PBKDF2, AEGIS-256, SHA-2, SHA-3
- ML-DSA-87 upgrade for DPoP proofs, receipt signing, KT tree heads (CNSA 2.0 Level 5)
- DPoP key hash upgraded to SHA-512 (64 bytes)
- CAC/PIV PKCS#11 module with card types and session management
- CAC/PIV authentication flow with certificate chain validation
- Compliance policy engine for DoD (STIG, CMMC, FedRAMP) and Indian govt (CERT-In, DPDP, MeitY)
- Data residency validation for India and GovCloud regions
- Compliance-aware audit retention (CERT-In 365-day, DoD 2555-day minimums)
- PII field encryption enforcement for DPDP Act compliance
- STIG/CIS benchmark auditor with 16 automated checks
- CMMC 2.0 Level 3 practice assessor with 20+ practices
- SIEM webhook integration with event batching and flush
- Searchable symmetric encryption (blind index) for zero-trust database queries
- Honey encryption with plausible data distributions
- Post-quantum blockchain with ML-DSA-87 signatures and BFT finality
- Adaptive cryptographic framework with risk-driven algorithm escalation
- Zero-knowledge proofs for classification, compliance, and audit integrity
- Proactive FROST share refresh for compromised-share expiry
- SLH-DSA stateless hash-based signatures (FIPS 205)
- LMS/XMSS stateful hash-based signatures (SP 800-208)
- 60+ chaos/failure injection tests across crypto, auth, BFT, compliance, PQ
- 24 hardening patches for total-compromise threat model
- Mandatory audience claim enforcement in token verification

### Changed

- Symmetric encryption default: AES-256-GCM to AEGIS-256 (AES-GCM as FIPS fallback)
- OPAQUE cipher suite: added FIPS variant with PBKDF2-SHA512 (210,000 iterations)
- Seal and envelope encryption upgraded to AEGIS-256 with legacy AES-GCM compatibility
- SHARD IPC encryption upgraded to AEGIS-256
- Backup encryption upgraded to AEGIS-256
- Attestation hashing made FIPS-aware
- X-Wing KEM upgraded from ML-KEM-768 to ML-KEM-1024 (CNSA 2.0 Suite Level 5)

### Fixed

- Stabilized flaky FIPS toggle and AEGIS default tests for parallel execution
- Stabilized attestation test for parallel FIPS mode races
- Corrected AuditEventType variant names in attack simulation tests
- CSPRNG entropy in ratchet attack tests to pass quality check
- All test TokenClaims constructors set mandatory `aud` claim
- Audience set in AuthRequest/OrchestratorRequest test helpers

## [0.2.0] - 2026-03-22

### Added

- Distributed FROST signing wired into TSS runtime via SHARD
- Session ratcheting wired with create/advance/tag via SHARD protocol
- Risk scoring computed on every authentication (step-up at 0.6, termination at 0.8)
- BFT audit: 7-node cluster with ML-DSA-65 signed entries, quorum of 5
- Key transparency: periodic ML-DSA-65 signed tree heads every 60 seconds
- Verifier service: full SHARD listener with token verification
- Witness checkpoints: periodic ML-DSA-65 signed audit+KT root snapshots every 5 minutes
- X-Wing hybrid KEM for post-quantum session key establishment in gateway
- Secret persistence: `key_material` and `shard_sequences` PostgreSQL tables
- Multi-person ceremonies: Level 3 requires 2 approvers, Level 4 requires 3
- Duress PIN: registration endpoint with silent lockdown on detection
- FIDO2 ceremony check for Tier 1 users with registered credentials
- DPoP channel binding: real client public key extracted from auth payload
- Token expiry enforcement: tier-based lifetimes (T1:5m, T2:10m, T3:15m, T4:2m)
- Login rate limiting: 5 attempts per 30 minutes per username
- PKCE validation: `code_challenge_method` must be `S256`
- Google OAuth: federated login with auto-enrollment as Tier 4
- Public integration docs page with code samples (Python, Node.js, Java, Go, Rust, PHP, .NET)
- `/oauth/jwks` JWKS endpoint
- `/api/user/profile` endpoint
- `/oauth/userinfo` returns real user data from database

### Fixed

- Panic on Google user creation failure replaced with HTTP 500 response
- Google auto-enrollment tier corrected from 2 to 4 (minimal access)
- All unused import warnings resolved
- Compiler warnings reduced to zero

## [0.1.0] - 2026-03-21

### Added

- 1,597-line architecture specification with 8 appendices (A-H)
- TLA+ formal model with safety and liveness property verification
- 169 attack vectors identified across 6 review rounds, all mitigated
- 13 Rust crates: common, crypto, shard, gateway, orchestrator, opaque, tss, verifier, ratchet, audit, kt, risk, e2e
- X-Wing hybrid KEM combiner (ML-KEM-768 + X25519)
- FROST 3-of-5 threshold signing via frost-ristretto255 2.2
- OPAQUE password authentication with Argon2id (64 MiB, 3 iterations, 4 parallelism)
- SHARD IPC protocol with HMAC-SHA512 authentication and replay protection
- Bastion Gateway with hash puzzle challenge (PoW)
- Ceremony state machine (PendingOpaque -> PendingTss -> Complete)
- Receipt chain signing and validation
- O(1) token signature verification
- Forward-secret session ratcheting (HKDF-SHA512, 30-second epochs, +-3 lookahead)
- Hash-chained append-only audit log with tamper detection
- SHA3-256 Merkle tree for Key Transparency
- Risk scoring engine (6 weighted signals, 4 levels, 4 device tiers)
- 4 ceremony tiers (Sovereign, Operational, Sensor, Emergency)
- 5 action-level classifications (Read, Modify, Privileged, Critical, Sovereign)
- Multi-source entropy combiner (NIST SP 800-90B compliant)
- Constant-time comparison utilities (subtle::ConstantTimeEq)
- 11 domain separation prefixes preventing cross-protocol injection
- Module communication matrix: 18 permitted channels enforced
- 190+ tests including e2e ceremony flows and attack simulations
- GitHub Actions CI pipeline (fmt, clippy, test)
- Dependabot for weekly cargo dependency scanning
- cargo-deny configured (advisories, licenses, bans, sources)

[0.4.0]: https://github.com/divyamohan1993/enterprise-sso-system/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/divyamohan1993/enterprise-sso-system/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/divyamohan1993/enterprise-sso-system/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/divyamohan1993/enterprise-sso-system/releases/tag/v0.1.0
