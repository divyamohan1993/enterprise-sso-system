# NIST SP 800-53 Rev 5 Control Mapping

**System:** MILNET SSO (enterprise-sso-system)
**Date:** 2026-03-22
**Revision:** 1.0
**Assessor:** Compliance review (internal)

This document maps relevant NIST SP 800-53 Revision 5 security controls to the MILNET SSO system implementation. Status values:

- **Implemented** -- Control is fully addressed in code and operational.
- **Partial** -- Control is partially addressed; gaps are noted.
- **Planned** -- Control is designed but not yet implemented.
- **N/A** -- Control is not applicable to this system component.

---

## AC -- Access Control

| Control ID | Control Name | Status | Implementation Notes | File References |
|------------|-------------|--------|---------------------|-----------------|
| AC-2 | Account Management | Partial | User accounts managed via admin REST API. Account creation, modification, deletion supported. No automated account review/disable workflow. | `admin/src/routes.rs` |
| AC-2(1) | Automated System Account Management | Planned | No automated periodic review of accounts. Admin must manually audit. | -- |
| AC-2(2) | Automated Temporary and Emergency Accounts | Implemented | Tier 4 (Emergency) tokens expire in 2 minutes. Google OAuth auto-enrolls at Tier 4 (minimal access). | `common/src/config.rs:100`, `admin/src/routes.rs` |
| AC-2(4) | Automated Audit Actions | Implemented | All account events (create, modify, delete, login, logout, lockout) are written to the hash-chained audit log. | `audit/src/log.rs`, `admin/src/routes.rs` |
| AC-3 | Access Enforcement | Implemented | 4-tier authentication ceremony model. 5-level action authorization (Read through Sovereign). Token claims include tier; verifier enforces tier-based access. | `common/src/config.rs`, `verifier/src/lib.rs`, `orchestrator/src/lib.rs` |
| AC-3(8) | Revocation of Access Authorizations | Implemented | Session revocation on duress PIN detection. Admin can revoke sessions. Token expiry enforced (5min to 15min depending on tier). | `admin/src/routes.rs` |
| AC-4 | Information Flow Enforcement | Implemented | Module communication matrix enforces 18 permitted channels out of 72 possible. SHARD protocol authenticates all IPC. | `common/src/lib.rs`, `shard/src/lib.rs` |
| AC-6 | Least Privilege | Implemented | Process isolation: each crate runs as a separate binary with its own trust boundary. Gateway holds zero secrets. Orchestrator holds no keys. | All crate `main.rs` files |
| AC-6(1) | Authorize Access to Security Functions | Implemented | Critical actions (Level 3) require two-person ceremony. Sovereign actions (Level 4) require three-person ceremony plus 15-min cooling period. Max 1 Level-4 action per 72 hours. | `common/src/config.rs:101-102`, `admin/src/routes.rs` |
| AC-6(9) | Log Use of Privileged Functions | Implemented | All privileged actions logged to audit system with ML-DSA-65 signed entries in BFT cluster. | `audit/src/bft.rs`, `audit/src/log.rs` |
| AC-7 | Unsuccessful Logon Attempts | Implemented | 5 failed attempts triggers 30-minute lockout per username. Configurable via `SecurityConfig`. | `common/src/config.rs:95-96`, `admin/src/routes.rs` |
| AC-8 | System Use Notification | N/A | Banner/notification is a deployment concern, not application logic. | -- |
| AC-10 | Concurrent Session Control | Implemented | `max_concurrent_sessions_per_user` defaults to 3. Configurable in `SecurityConfig`. | `common/src/config.rs:119` |
| AC-11 | Device Lock / Session Lock | Implemented | Token expiry enforced (5-15 min by tier). 8-hour mandatory re-authentication ceiling. Ratchet epoch advancement invalidates stale sessions. | `common/src/config.rs:88`, `ratchet/src/chain.rs` |
| AC-12 | Session Termination | Implemented | Sessions terminated on: token expiry, risk score >= 0.8 (Critical), duress PIN detection, forced re-auth after 4 hours. | `common/src/config.rs:117`, `risk/src/lib.rs` |
| AC-17 | Remote Access | Partial | All access is via SHARD IPC or HTTPS. TLS (rustls 0.23) is in dependencies but transport is currently plain TCP for inter-service communication. | `gateway/Cargo.toml`, `Cargo.toml:52-53` |
| AC-17(2) | Protection of Confidentiality / Integrity Using Encryption | Partial | HMAC-SHA512 authentication on all IPC (integrity). X-Wing hybrid KEM for session key establishment. TLS not yet wired for inter-service transport. | `shard/src/lib.rs`, `crypto/src/xwing.rs` |

---

## AU -- Audit and Accountability

| Control ID | Control Name | Status | Implementation Notes | File References |
|------------|-------------|--------|---------------------|-----------------|
| AU-2 | Event Logging | Implemented | Audit events cover: authentication success/failure, account changes, session operations, privilege escalation, duress detection, key rotation, ceremony initiation/approval. | `audit/src/log.rs` |
| AU-3 | Content of Audit Records | Implemented | Each AuditEntry includes: timestamp, event type, user identity, session ID, outcome, previous entry hash. All forensically significant fields included in hash. | `common/src/lib.rs` (AuditEntry type) |
| AU-3(1) | Additional Audit Information | Implemented | Risk scoring signals (device, geo-velocity, network, time, access patterns, failed attempts) logged alongside auth events. | `risk/src/lib.rs` |
| AU-4 | Audit Log Storage Capacity | Partial | BFT audit cluster replicates to 7 nodes. However, no automated log rotation or capacity management is implemented. In-memory audit log in admin routes has no eviction. | `audit/src/bft.rs` |
| AU-5 | Response to Audit Processing Failures | Implemented | `audit_degradation_max_secs` (30 min) enforced. If audit subsystem is degraded beyond this threshold, human authentication is required. Entropy failure triggers fail-closed behavior. | `common/src/config.rs:105` |
| AU-6 | Audit Record Review, Analysis, and Reporting | Partial | Audit log is viewable via admin API. No automated analysis, correlation, or alerting. | `admin/src/routes.rs` |
| AU-8 | Time Stamps | Implemented | All audit entries, tokens, and receipts include timestamps. SHARD protocol enforces +/-2 second timestamp tolerance for replay protection. | `shard/src/lib.rs` |
| AU-9 | Protection of Audit Information | Implemented | Audit log is hash-chained (SHA-256 domain-separated). BFT cluster entries are ML-DSA-65 signed. Tamper detection via chain verification. | `audit/src/log.rs`, `audit/src/bft.rs` |
| AU-9(2) | Store on Separate Physical Systems | Implemented | 7-node BFT cluster architecture; quorum of 5 required for commit. Tolerates 2 Byzantine nodes. | `audit/src/bft.rs` |
| AU-10 | Non-repudiation | Implemented | ML-DSA-65 post-quantum signatures on BFT audit entries. FROST threshold signatures on tokens (3-of-5 required). DPoP channel binding for token possession. | `crypto/src/pq_sign.rs`, `crypto/src/threshold.rs`, `crypto/src/dpop.rs` |
| AU-12 | Audit Record Generation | Implemented | Audit entries generated at: gateway (puzzle), orchestrator (ceremony), OPAQUE (auth), TSS (signing), risk (scoring), admin (management). All modules emit to audit service. | All service crates |

---

## IA -- Identification and Authentication

| Control ID | Control Name | Status | Implementation Notes | File References |
|------------|-------------|--------|---------------------|-----------------|
| IA-2 | Identification and Authentication (Organizational Users) | Implemented | OPAQUE protocol (RFC 9497) for server-blind password authentication. Google OAuth for federated identity. FIDO2/WebAuthn for Tier 1. | `opaque/src/opaque_impl.rs`, `fido/src/lib.rs` |
| IA-2(1) | Multi-Factor Authentication to Privileged Accounts | Implemented | Tier 1 (Sovereign): OPAQUE + FIDO2 + Risk scoring. Tier 2 (Operational): OPAQUE + TOTP + Risk scoring. | `orchestrator/src/lib.rs` |
| IA-2(2) | Multi-Factor Authentication to Non-Privileged Accounts | Implemented | Tier 3 requires PSK/HMAC + Attestation. Tier 4 requires Shamir 7-of-13 + OOB verification. | `orchestrator/src/lib.rs` |
| IA-2(6) | Access to Accounts -- Separate Device | Partial | FIDO2 hardware keys supported for Tier 1. Device tier enforcement is server-determined. Full WebAuthn signature verification is pending (credential-exists check only). | `fido/src/verification.rs`, `fido/src/registration.rs` |
| IA-2(8) | Access to Accounts -- Replay Resistant | Implemented | SHARD protocol uses monotonic sequence counters for replay protection. Receipts have 30-second TTL. Nonces in FROST signing prevent replay. | `shard/src/lib.rs`, `crypto/src/threshold.rs` |
| IA-4 | Identifier Management | Implemented | User identifiers are UUIDs. Device IDs assigned during enrollment. Session IDs are cryptographic random. | `common/src/lib.rs` |
| IA-5 | Authenticator Management | Implemented | Passwords processed via OPAQUE (server never sees plaintext). Key material protected with `zeroize` + `ZeroizeOnDrop` + `mlock`. Sealed key storage via AES-256-GCM envelope encryption. | `opaque/src/store.rs`, `crypto/src/seal.rs`, `crypto/src/memguard.rs` |
| IA-5(1) | Password-Based Authentication | Implemented | OPAQUE protocol eliminates server-side password storage. The server stores a cryptographic envelope, never a password hash. OPRF prevents offline dictionary attacks against the server's stored data. | `opaque/src/opaque_impl.rs`, `opaque/src/store.rs` |
| IA-5(2) | Public Key-Based Authentication | Implemented | FROST 3-of-5 threshold EdDSA signing. ML-DSA-87 post-quantum signatures. FIDO2/WebAuthn credential management. DPoP key binding. | `crypto/src/threshold.rs`, `crypto/src/pq_sign.rs`, `fido/src/lib.rs`, `crypto/src/dpop.rs` |
| IA-5(13) | Expiration of Cached Authenticators | Implemented | Ratchet keys advance every 10 seconds (configurable). Previous keys securely erased via `zeroize`. 8-hour max session. | `ratchet/src/chain.rs`, `common/src/config.rs:89` |
| IA-6 | Authentication Feedback | Implemented | Constant-time comparison (`subtle::ConstantTimeEq`) prevents timing side-channels. Error messages do not disclose which factor failed. | `crypto/src/ct.rs` |
| IA-8 | Identification and Authentication (Non-Organizational Users) | Implemented | Google OAuth federated login. Auto-enrolled at Tier 4 (minimal access) pending admin approval. | `admin/src/routes.rs` |
| IA-11 | Re-Authentication | Implemented | Step-up re-auth triggered at risk score >= 0.6 (High). Forced re-auth after `max_session_age_forced_reauth_secs` (4 hours). Level 2+ actions require fresh DPoP. | `common/src/config.rs:117`, `risk/src/lib.rs` |
| IA-12 | Identity Proofing | Partial | No formal identity proofing workflow. User creation is admin-managed. Google OAuth provides email-verified identity. | -- |

---

## SC -- System and Communications Protection

| Control ID | Control Name | Status | Implementation Notes | File References |
|------------|-------------|--------|---------------------|-----------------|
| SC-4 | Information in Shared Resources | Implemented | Key material zeroized on drop (`zeroize`, `ZeroizeOnDrop`). Memory-locked buffers (`mlock`) prevent swap. Core dumps disabled (`PR_SET_DUMPABLE, 0`). Debug output redacted for `SecretBuffer`. | `crypto/src/memguard.rs`, `crypto/src/seal.rs`, `crypto/src/xwing.rs` |
| SC-7 | Boundary Protection | Implemented | Gateway is bastion entry point holding zero secrets. Adaptive hash puzzle (PoW) for DDoS mitigation. Module communication matrix restricts channels. | `gateway/src/lib.rs`, `common/src/lib.rs` |
| SC-8 | Transmission Confidentiality and Integrity | Partial | SHARD IPC provides HMAC-SHA512 integrity. X-Wing KEM provides session confidentiality. TLS 1.3 (rustls) is in dependencies but not yet wired for inter-service transport. | `shard/src/lib.rs`, `crypto/src/xwing.rs`, `Cargo.toml:52` |
| SC-8(1) | Cryptographic Protection | Implemented | HMAC-SHA512 for IPC integrity. X-Wing hybrid KEM (ML-KEM-1024 + X25519) for key exchange. AES-256-GCM for envelope encryption. | `shard/src/lib.rs`, `crypto/src/xwing.rs`, `crypto/src/seal.rs` |
| SC-10 | Network Disconnect | Implemented | Sessions expire per tier (5-15 min). 8-hour absolute ceiling. Ratchet advancement invalidates stale sessions. Risk-based session termination. | `common/src/config.rs` |
| SC-12 | Cryptographic Key Establishment and Management | Implemented | Key hierarchy: Master Key -> KEKs (per-purpose) -> DEKs (per-record). HKDF-SHA512 derivation. AES-256-GCM wrapping. `ProductionKeySource` trait for HSM integration. Key rotation support. PostgreSQL persistence for key material. | `crypto/src/seal.rs` |
| SC-12(1) | Availability | Partial | FROST 3-of-5 threshold means system can tolerate loss of 2 signing nodes. Key persistence in PostgreSQL. No automated key backup/recovery procedure documented. | `crypto/src/threshold.rs` |
| SC-12(2) | Symmetric Keys | Implemented | HKDF-SHA512 for key derivation. AES-256-GCM for wrapping. Domain-separated derivation prevents cross-purpose key use. | `crypto/src/seal.rs` |
| SC-12(3) | Asymmetric Keys | Implemented | FROST EdDSA (Ristretto255) for threshold signing. ML-DSA-87 for post-quantum signatures. X25519 + ML-KEM-1024 for hybrid KEM. | `crypto/src/threshold.rs`, `crypto/src/pq_sign.rs`, `crypto/src/xwing.rs` |
| SC-13 | Cryptographic Protection | Implemented | SHA-256, SHA-512, SHA3-256 hashing. HMAC-SHA512 authentication. AES-256-GCM encryption. HKDF-SHA512 derivation. FROST EdDSA signing. ML-DSA-87 PQ signatures. ML-KEM-1024 PQ KEM. X25519 classical KEM. | `crypto/src/*` |
| SC-17 | Public Key Infrastructure Certificates | Partial | OIDC JWKS endpoint serves public keys. RS256 JWT signing. No full PKI certificate management (not applicable to SSO token model). | `sso-protocol/src/tokens.rs` |
| SC-23 | Session Authenticity | Implemented | FROST threshold-signed tokens. DPoP channel binding. Ratchet epoch tags. Receipt chain validation (session ID, hash linkage, signatures). | `tss/src/lib.rs`, `crypto/src/dpop.rs`, `ratchet/src/chain.rs` |
| SC-28 | Protection of Information at Rest | Implemented | Sealed key storage: AES-256-GCM with AAD (`MILNET-SEAL-v1`). HKDF-derived KEKs per purpose. `require_encryption_at_rest` and `require_sealed_keys` config flags default to true. | `crypto/src/seal.rs`, `common/src/config.rs:108-109` |
| SC-28(1) | Cryptographic Protection | Implemented | AES-256-GCM envelope encryption for all key material at rest. Random 12-byte nonces. Authenticated encryption with associated data. | `crypto/src/seal.rs` |

---

## SI -- System and Information Integrity

| Control ID | Control Name | Status | Implementation Notes | File References |
|------------|-------------|--------|---------------------|-----------------|
| SI-2 | Flaw Remediation | Implemented | cargo-deny for dependency scanning. Dependabot for weekly vulnerability scanning. Zero CVEs in current dependency tree. CI pipeline with clippy warnings as errors. | `deny.toml`, `.github/workflows/` |
| SI-4 | System Monitoring | Partial | Risk engine provides real-time 6-signal scoring. Audit log captures all security events. No external SIEM integration or automated alerting. | `risk/src/lib.rs`, `audit/src/log.rs` |
| SI-6 | Security and Privacy Function Verification | Implemented | 190+ tests across 13 crates. E2E ceremony flow tests. 37 attack simulation tests. Canary integrity checks on memory buffers. Entropy health self-tests (repetition count, adaptive proportion). | `e2e/src/lib.rs`, `crypto/src/memguard.rs`, `crypto/src/entropy.rs` |
| SI-7 | Software, Firmware, and Information Integrity | Implemented | Binary attestation support (`require_binary_attestation` config). Hash-chained audit log detects tampering. Key transparency Merkle tree for credential integrity. | `common/src/config.rs:111`, `audit/src/log.rs`, `kt/src/lib.rs` |
| SI-7(1) | Integrity Checks | Implemented | Audit chain verification detects insertion, deletion, and modification. Constant-time Merkle inclusion proofs. Receipt chain hash linkage validation. | `audit/src/log.rs`, `kt/src/lib.rs`, `tss/src/lib.rs` |
| SI-10 | Information Input Validation | Implemented | PKCE `code_challenge_method` must be `S256`. Strict redirect URI matching. Receipt TTL validation. Timestamp bounds checking (+/-2s for SHARD, future-timestamp rejection for receipts). | `sso-protocol/src/pkce.rs`, `common/src/config.rs:75` |
| SI-11 | Error Handling | Implemented | Custom error types in every crate. No internal state leaked in error messages. Panic on canary violation includes zeroization before abort. Fail-closed on entropy failure. | `crypto/src/memguard.rs`, `crypto/src/entropy.rs` |
| SI-16 | Memory Protection | Implemented | `mlock` prevents swap. `MADV_DONTDUMP` excludes from core dumps. `PR_SET_DUMPABLE` disables core dumps process-wide. `PR_SET_NO_NEW_PRIVS` prevents privilege escalation. Canary words detect buffer overflows. `zeroize` on drop for all secret material. | `crypto/src/memguard.rs` |

---

## Identified Gaps

| Gap ID | Control(s) | Description | Severity | Remediation |
|--------|-----------|-------------|----------|-------------|
| GAP-01 | AC-17, SC-8 | Inter-service transport is plain TCP with HMAC integrity but no TLS encryption. rustls is in dependencies but not wired. | High | Wire PQ-hybrid TLS (rustls + X25519MLKEM768) for all SHARD connections. |
| GAP-02 | AU-4 | No automated audit log rotation or capacity management. In-memory structures grow unbounded. | Medium | Implement TTL eviction and log rotation policies. |
| GAP-03 | AU-6 | No automated audit analysis, correlation, or alerting. Manual review only. | Medium | Integrate with external SIEM or build alerting rules. |
| GAP-04 | IA-2(6) | FIDO2 WebAuthn is credential-exists check only; full signature verification not implemented. | High | Complete WebAuthn assertion verification per W3C spec. |
| GAP-05 | IA-12 | No formal identity proofing workflow beyond admin-managed account creation. | Medium | Implement identity proofing for initial enrollment. |
| GAP-06 | SC-12(1) | No automated key backup/recovery procedure. FROST threshold provides availability (3-of-5), but no documented DR process. | Medium | Document and implement key ceremony backup procedures. |
| GAP-07 | SI-4 | No external SIEM integration or automated security alerting. | Medium | Build alerting hooks or integrate with external monitoring. |
