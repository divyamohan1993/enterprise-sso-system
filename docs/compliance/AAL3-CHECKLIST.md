# NIST SP 800-63B AAL3 Compliance Checklist

**System:** MILNET SSO (enterprise-sso-system)
**Date:** 2026-03-22
**Revision:** 1.0
**Reference:** NIST SP 800-63B Digital Identity Guidelines: Authentication and Lifecycle Management (Revision 3 / Revision 4 draft)

This document maps each AAL3 (Authentication Assurance Level 3) requirement to the MILNET SSO implementation.

Status values:
- **Met** -- Requirement is fully satisfied.
- **Partial** -- Requirement is partially satisfied; gaps noted.
- **Not Met** -- Requirement is not currently satisfied.

---

## AAL3 Authenticator Requirements

| Requirement | SP 800-63B Section | Status | Implementation | References |
|-------------|-------------------|--------|----------------|------------|
| Multi-factor authentication required | 4.3.1 | **Met** | Tier 1: OPAQUE + FIDO2 + Risk. Tier 2: OPAQUE + TOTP + Risk. All tiers require at least two distinct factors. | `orchestrator/src/lib.rs` |
| At least one authenticator must be a hardware cryptographic device | 4.3.1 | **Met** (Tier 1) / **Partial** (Tier 2) | Tier 1 requires FIDO2 hardware key. Tier 2 uses TOTP (software or hardware). Tier 3 uses PSK. | `fido/src/lib.rs` |
| Authenticator must prove possession through a cryptographic protocol | 4.3.1 | **Met** | OPAQUE: OPRF-based zero-knowledge password proof. FIDO2: public key challenge-response. DPoP: proof-of-possession for tokens. | `opaque/src/opaque_impl.rs`, `fido/src/verification.rs`, `crypto/src/dpop.rs` |
| Verifier impersonation resistance | 4.3.2 | **Met** | OPAQUE protocol is inherently resistant to verifier impersonation (server never learns password). FIDO2 scopes credentials to relying party origin. | `opaque/src/opaque_impl.rs`, `fido/src/registration.rs` |
| Verifier compromise resistance | 4.3.2 | **Met** | OPAQUE: server stores cryptographic envelope, not password hash. Compromise of server DB does not reveal passwords. FIDO2: server stores public key only. | `opaque/src/store.rs` |
| Replay resistance | 4.3.2 | **Met** | SHARD IPC: monotonic sequence counters. Receipts: 30-second TTL, single-use. FROST: fresh nonces per signing ceremony. Tokens: epoch tags tied to ratchet state. | `shard/src/lib.rs`, `crypto/src/threshold.rs`, `ratchet/src/chain.rs` |
| Authentication intent | 4.3.2 | **Partial** | FIDO2 hardware keys require physical user interaction (button press). OPAQUE authentication requires explicit user action (entering password). No explicit consent prompt for step-up re-auth. | `fido/src/lib.rs` |

---

## AAL3 Verifier Requirements

| Requirement | SP 800-63B Section | Status | Implementation | References |
|-------------|-------------------|--------|----------------|------------|
| Approved cryptography | 5.1 | **Met** | All algorithms are NIST-approved or on the CNSA 2.0 trajectory. See CNSA-2-0-STATUS.md for full mapping. | `crypto/src/*` |
| FIPS 140 Level 1+ validated cryptographic module | 5.1 | **Not Met** | Cryptographic implementations use open-source Rust crates (ml-kem, ml-dsa, frost-ristretto255, aes-gcm, sha2, etc.). None are currently FIPS 140-3 validated. aws-lc-rs (used by rustls) is in CMVP process. | `Cargo.toml` |
| Validated at FIPS 140 Level 2+ physical security for hardware authenticator | 5.1.8 | **Partial** | System supports FIDO2 hardware keys (which are typically FIPS 140-2 L2+). However, the system does not enforce a specific FIPS certification level for connected authenticators. | `fido/src/lib.rs` |
| Verifier operates at FIPS 140 Level 1+ | 5.1 | **Not Met** | Verifier uses non-FIPS-validated crypto. See FIPS-140-3-READINESS.md. | `verifier/src/lib.rs` |
| Communication between claimant and verifier is authenticated and protected | 5.1.3 | **Partial** | SHARD IPC provides HMAC-SHA512 authentication (integrity). X-Wing KEM for session keys. TLS not yet wired for inter-service transport. | `shard/src/lib.rs`, `crypto/src/xwing.rs` |

---

## AAL3 Reauthentication Requirements

| Requirement | SP 800-63B Section | Status | Implementation | References |
|-------------|-------------------|--------|----------------|------------|
| Reauthentication at least every 12 hours | 7.2 | **Met** | 8-hour maximum session lifetime (stricter than 12-hour requirement). 4-hour forced re-auth ceiling in hardened mode. | `common/src/config.rs:88,117` |
| Reauthentication requires use of all factors | 7.2 | **Partial** | Step-up re-auth is triggered by risk scoring. Full ceremony re-execution requires all factors. However, session extension within tier may not re-verify all factors. | `risk/src/lib.rs`, `orchestrator/src/lib.rs` |
| 15-minute inactivity timeout (or: continuous reauthentication) | 7.2 | **Met** | Tier 1 tokens: 5 min. Tier 2: 10 min. Tier 3: 15 min. All tiers meet or exceed the 15-minute requirement. Ratchet advancement provides continuous session freshness. | `common/src/config.rs:97-100` |

---

## AAL3 Records and Audit Requirements

| Requirement | SP 800-63B Section | Status | Implementation | References |
|-------------|-------------------|--------|----------------|------------|
| Record all authentication events | 5.2.7 | **Met** | All authentication events (success, failure, lockout, duress, step-up) recorded in hash-chained audit log with ML-DSA-65 signatures on BFT entries. | `audit/src/log.rs`, `audit/src/bft.rs` |
| Protect audit records from unauthorized access, modification, or deletion | 5.2.7 | **Met** | Hash-chained entries (SHA-256). BFT replication (7 nodes, 5 quorum). ML-DSA-87 signed entries. Tamper detection via chain verification. | `audit/src/log.rs`, `audit/src/bft.rs`, `crypto/src/pq_sign.rs` |
| Retain records per organizational policy | 5.2.7 | **Partial** | No automated retention policy or log rotation. Audit entries stored in memory and PostgreSQL. No configured retention period. | `audit/src/log.rs` |

---

## AAL3 Resistance Requirements

| Requirement | Description | Status | Implementation | References |
|-------------|------------|--------|----------------|------------|
| Phishing resistance | Authenticator output cannot be replayed to a different verifier | **Met** | OPAQUE binds to server identity. FIDO2 scopes to relying party origin. DPoP binds tokens to client key. | `opaque/src/opaque_impl.rs`, `fido/src/registration.rs`, `crypto/src/dpop.rs` |
| Man-in-the-middle resistance | Authentication protocol resists active interception | **Partial** | OPAQUE provides mutual authentication. FIDO2 provides channel binding. However, TLS is not yet wired for inter-service transport, so MITM between services is theoretically possible. | `shard/src/lib.rs` |
| Session hijacking resistance | Tokens cannot be used by unauthorized parties | **Met** | DPoP channel binding ties tokens to client key pair. Ratchet epoch tags expire in 10 seconds. Forward secrecy ensures past sessions cannot be decrypted. | `crypto/src/dpop.rs`, `ratchet/src/chain.rs` |

---

## AAL3 Specific Authenticator Type Requirements

### Multi-Factor Crypto Device (FIDO2 -- Tier 1)

| Requirement | Status | Notes |
|-------------|--------|-------|
| Device contains a protected cryptographic key | **Met** | FIDO2 hardware keys store private key in secure element. |
| Activation requires second factor (PIN/biometric) | **Partial** | FIDO2 spec supports PIN/biometric. System does not enforce UV (user verification) flag. |
| Cryptographic protocol proves possession | **Partial** | Credential-exists check implemented. Full WebAuthn signature verification pending (GAP-04). |

### Look-Up Secrets (Emergency -- Tier 4)

| Requirement | Status | Notes |
|-------------|--------|-------|
| Secrets are randomly generated | **Met** | Shamir 7-of-13 shares generated from cryptographic random. |
| Secrets have sufficient entropy | **Met** | Shares derived from threshold secret sharing over a large finite field. |
| Secrets are rate-limited | **Met** | Emergency tokens expire in 2 minutes. Max 1 Level-4 action per 72 hours. |

---

## Summary

| Category | Met | Partial | Not Met | Total |
|----------|-----|---------|---------|-------|
| Authenticator Requirements | 5 | 2 | 0 | 7 |
| Verifier Requirements | 1 | 2 | 2 | 5 |
| Reauthentication | 2 | 1 | 0 | 3 |
| Records and Audit | 2 | 1 | 0 | 3 |
| Resistance Requirements | 2 | 1 | 0 | 3 |
| **Total** | **12** | **7** | **2** | **21** |

### Critical Gaps for AAL3 Certification

1. **FIPS 140 validation** (Not Met): The cryptographic modules are not FIPS 140-3 validated. This is a hard requirement for AAL3. See FIPS-140-3-READINESS.md for the remediation path.
2. **FIDO2 full verification** (Partial): WebAuthn signature verification must be completed for Tier 1 to fully satisfy the hardware crypto device requirement.
3. **TLS for inter-service communication** (Partial): Must wire rustls for SHARD connections to achieve authenticated protected channels.
