# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development

**Goal:** Fix all critical, severe, and important security findings from the 10-agent audit to make the SSO system defensible under total infrastructure compromise.

**Architecture:** Subsystem-by-subsystem hardening in dependency order. Each phase makes one layer bulletproof before the next begins.

**Tech Stack:** Rust 1.88, tokio, rustls, frost-ristretto255, ml-kem, ml-dsa, opaque-ke, sqlx, aes-gcm, aegis

---

## Phase 1: Crypto Foundation

1. Fix FIPS KATs: HKDF-SHA512 must fail-hard on mismatch (not warn). ML-DSA-87, ML-KEM-1024, AEGIS-256 need fixed test vectors, not roundtrip tests.
2. Fix XWingKeyPair::Drop: use `core::ptr::write_volatile` + compiler fence for ML-KEM dk zeroization.
3. Fix X25519 zeroization: call `self.x25519_secret.zeroize()` explicitly (not assignment).
4. Make entropy health process-global: replace `thread_local!` with `Arc<Mutex<EntropyHealth>>`.
5. Remove hardcoded dev seed: require explicit `MILNET_MASTER_SEED` in all modes, panic if absent.
6. HSM: mark software backend honestly (remove fake PKCS#11/KMS/TPM simulation claims).
7. Fix SecretVec::Drop: save original `len` at construction, use it for `munlock`.
8. Remove legacy AES-GCM decrypt fallback (`_ =>` catch-all in symmetric.rs).
9. Fix FROST `threshold_sign`: accept signer indices, not always first-N.
10. HsmConfig: manual Debug that redacts PIN, ZeroizeOnDrop on PIN field.

## Phase 2: Transport/Network Security

1. Gateway: wrap external listener in `TlsAcceptor` (rustls).
2. Remove `TransportStream::Plain` variant entirely from shard/transport.rs.
3. TLS config: `.with_protocol_versions(&[&rustls::version::TLS13])` and `.with_cipher_suites(&[TLS13_AES_256_GCM_SHA384])`.
4. Make `pin_set` and `identity_map` non-optional (required) on ServerTlsConfig/ClientTlsConfig.
5. TlsShardListener: add post-handshake cert pinning + module identity verification.
6. Replace `fetch_kt_root_http` (plaintext) with SHARD transport call.
7. Audit service: use `sender` identity from mTLS, not discard with `_`.
8. Redis: enforce `rediss://` in production mode.

## Phase 3: Distributed Consensus & Threshold

1. OPAQUE: wire threshold OPRF into production auth — remove monolithic ServerSetup path.
2. Fix `partial_evaluate`: compute `blinded_element * share_scalar`, not return raw share bytes.
3. FROST DKG: replace `generate_with_dealer` with real 2-round Pedersen DKG via SHARD.
4. BFT Audit: wire `PqBlockchain` into running service, replace `BftAuditCluster`.
5. Add equivocation detection: track `(slot, signer_id, hash)` tuples.
6. Block `single-process` mode in production unconditionally — remove override env var.

## Phase 4: Session/Token Security

1. OIDC: add `exp` check in `verify_id_token_inner`.
2. DPoP: implement RFC 9449 proof JWTs with `htm`/`htu`/`iat`/`jti` + replay cache.
3. JTI tracking: bounded HashSet with TTL eviction.
4. Token revocation: SHARD broadcast to all verifier instances.
5. Device fingerprint: enforce in `get_session`.
6. DistributedSessionStore: back with PostgreSQL via sqlx.
7. Ratchet: store epoch counter only, derive key from master + epoch via HKDF.

## Phase 5: Data Protection & Key Management

1. Wire envelope.rs DEK/KEK into encrypted_db.rs — per-row DEK.
2. Key rotation: add `key_version` column, concurrent decryption, re-encryption pipeline.
3. Call `harden_process()` at startup in every service main.rs.
4. Recovery rate limiter: persist to PostgreSQL.
5. Adopt SecretBuffer/mlock for MasterKey, DerivedKek, DataEncryptionKey, SharedHmacKey.

## Phase 6: Compliance & Hardening

1. STIG: `run_stig_audit()` panics on Cat I in production.
2. SIEM webhook: implement HTTPS POST.
3. vTPM absence is fatal in production.
4. Measured boot: verify attestation via SHARD before node participation.
5. TLS cipher restriction at SHARD level.
6. Remove `MILNET_TSS_SINGLE_PROCESS_OVERRIDE` env var.
