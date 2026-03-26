# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
