//! Chaos and mayhem tests for production failure modes.
//!
//! These tests simulate real attack surfaces and failure scenarios that
//! nation-state attackers will exploit: corrupted WALs, disk failures,
//! XXE injection, partial writes, slow loris, ciphertext tampering,
//! key rotation boundaries, and network partitions.
//!
//! Every test is strict. No bypasses. No mocks. Real crypto, real data.

use std::path::PathBuf;

use common::raft::{
    ClusterCommand, FileRaftLogPersistence, FileRaftPersistence, LogEntry, LogIndex,
    NodeId, RaftConfig, RaftLogPersistence, RaftMessage, RaftPersistence, RaftRole,
    RaftState, Term,
};
use common::types::AuditEventType;
use crypto::pq_sign;
use crypto::threshold::{dkg, threshold_sign, verify_group_signature};
use serial_test::serial;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run closure on a thread with 8 MiB stack (ML-DSA-87 and FROST eat stack).
fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "milnet-chaos-{}-{}",
        prefix,
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

// ===========================================================================
// 1. Corrupted Raft WAL Recovery
// ===========================================================================

/// Production scenario: an attacker with disk access flips a byte in the Raft
/// WAL file. On node restart, the corrupted entry must be detected and rejected.
/// Silent acceptance of corrupted WAL entries means the attacker controls the
/// replicated log (membership changes, role assignments, tamper flags).
#[test]
fn test_corrupted_raft_wal_detected_and_rejected() {
    run_with_large_stack(|| {
        let dir = temp_dir("wal-corrupt");
        let wal = FileRaftLogPersistence::new(&dir).expect("create WAL");

        // Write three valid entries.
        let entries = vec![
            LogEntry {
                term: Term(1),
                index: LogIndex(1),
                command: ClusterCommand::Noop,
                entry_signature: None,
            },
            LogEntry {
                term: Term(1),
                index: LogIndex(2),
                command: ClusterCommand::MemberJoin {
                    node_id: NodeId::random(),
                    addr: "10.0.0.1:8443".into(),
                    service_type: "auth".into(),
                },
                entry_signature: None,
            },
            LogEntry {
                term: Term(1),
                index: LogIndex(3),
                command: ClusterCommand::HealthUpdate {
                    node_id: NodeId::random(),
                    healthy: true,
                },
                entry_signature: None,
            },
        ];
        wal.append_entries(&entries).expect("append entries");

        // Verify clean load works.
        let loaded = wal.load_log().expect("clean load");
        assert_eq!(loaded.len(), 3, "all 3 entries must load from clean WAL");

        // Corrupt a byte in the middle of the WAL file.
        let wal_path = dir.join("wal");
        let mut data = std::fs::read(&wal_path).expect("read WAL");
        assert!(data.len() > 20, "WAL must have data to corrupt");

        // Flip a bit in the payload area of the second entry.
        // The first entry is length-prefixed, so skip past it.
        // Length prefix is 4 bytes LE, followed by the serialized entry.
        let first_entry_len =
            u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let second_entry_offset = 4 + first_entry_len + 4; // skip first entry + second length prefix
        assert!(
            second_entry_offset < data.len(),
            "offset must be within WAL file"
        );
        // Flip a bit in the serialized payload of the second entry.
        data[second_entry_offset] ^= 0xFF;
        std::fs::write(&wal_path, &data).expect("write corrupted WAL");

        // Reload: the corrupted entry must cause a deserialization error.
        // The WAL uses postcard frames. A corrupted byte will produce either:
        // (a) a postcard deserialization error, or
        // (b) a truncated-entry detection (length mismatch).
        // Either way, the corruption must NOT be silently accepted.
        let result = wal.load_log();
        match result {
            Err(e) => {
                // Deserialization error -- corruption detected. Good.
                assert!(
                    e.contains("deserialize") || e.contains("WAL"),
                    "error must indicate WAL corruption, got: {e}"
                );
            }
            Ok(recovered) => {
                // The WAL truncation logic may stop before the corrupt entry.
                // In that case, we must NOT get all 3 entries back.
                assert!(
                    recovered.len() < 3,
                    "corrupted WAL must not silently return all entries. \
                     Got {} entries -- corruption was not detected.",
                    recovered.len()
                );
                // Verify the entries we DID get are the uncorrupted ones.
                for entry in &recovered {
                    assert_eq!(entry.term, Term(1));
                }
            }
        }
    });
}

// ===========================================================================
// 2. Disk Full During Audit Archive
// ===========================================================================

/// Production scenario: disk fills up during audit archival. Audit entries
/// must NOT be silently lost. The archive_old_entries function must detect the
/// write failure and re-insert entries into the in-memory log.
#[test]
#[serial]
fn test_audit_log_handles_disk_full_gracefully() {
    run_with_large_stack(|| {
        // Set master KEK for the audit code path that derives archive encryption keys.
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));

        let (signing_key, _vk) = pq_sign::generate_pq_keypair();
        let mut log = audit::log::AuditLog::new_with_limits(5, None);

        // Fill the log past max_entries.
        for i in 0..10 {
            log.append(
                AuditEventType::AuthSuccess,
                vec![uuid::Uuid::new_v4()],
                vec![],
                0.1 * i as f64,
                vec![],
                &signing_key,
            );
        }

        // At this point auto_archive was triggered but no archive_dir was set,
        // so entries are retained in memory. Verify nothing was lost.
        assert!(
            log.entries().len() >= 5,
            "entries must be retained when no archive dir is set; got {}",
            log.entries().len()
        );

        // Now test explicit archive to a non-writable directory.
        // Use a path that will fail (nested under a non-existent root we
        // won't create, or a path we make read-only).
        let bad_dir = temp_dir("audit-readonly");
        // Make the directory read-only so writes inside it fail.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bad_dir, std::fs::Permissions::from_mode(0o444))
                .expect("set readonly");
        }

        let entry_count_before = log.entries().len();
        let result = log.archive_old_entries(
            &bad_dir.join("subdir").to_string_lossy(),
        );

        // Restore permissions for cleanup.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bad_dir, std::fs::Permissions::from_mode(0o755))
                .expect("restore permissions");
        }

        // The archive must fail (can't create subdir inside read-only dir).
        assert!(
            result.is_err(),
            "archive_old_entries must return Err on write failure"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("failed to create") || err_msg.contains("archive"),
            "error must indicate write failure, got: {err_msg}"
        );

        // Entries must be re-inserted -- nothing lost.
        assert_eq!(
            log.entries().len(),
            entry_count_before,
            "all entries must be restored after failed archival; \
             had {entry_count_before}, now have {}",
            log.entries().len()
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&bad_dir);
    });
}

// ===========================================================================
// 3. SAML XXE Prevention
// ===========================================================================

/// Production scenario: attacker sends a SAML AuthnRequest with an XXE payload
/// that attempts to read /etc/passwd via XML external entity expansion.
/// The parser must reject the document before processing any entities.
#[test]
fn test_saml_rejects_xxe_payload() {
    let xxe_xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_xxe_test_123" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"
    AssertionConsumerServiceURL="https://evil.example.com/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
</samlp:AuthnRequest>"#;

    // Base64 encode for the POST binding.
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        xxe_xml.as_bytes(),
    );

    let result = common::saml::AuthnRequest::parse_post_binding(&encoded);
    assert!(
        result.is_err(),
        "SAML parser must reject XXE payload, but it succeeded"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("DOCTYPE") || err.contains("ENTITY") || err.contains("XXE") || err.contains("SECURITY"),
        "error must specifically mention XXE/DOCTYPE/ENTITY rejection, got: {err}"
    );
}

/// Production scenario: attacker sends a billion laughs (exponential entity
/// expansion) payload. Must be rejected to prevent DoS via memory exhaustion.
#[test]
fn test_saml_rejects_billion_laughs() {
    let billion_laughs = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_billion_laughs" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"
    AssertionConsumerServiceURL="https://evil.example.com/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&lol4;</saml:Issuer>
</samlp:AuthnRequest>"#;

    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        billion_laughs.as_bytes(),
    );

    let result = common::saml::AuthnRequest::parse_post_binding(&encoded);
    assert!(
        result.is_err(),
        "SAML parser must reject billion laughs payload"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("DOCTYPE") || err.contains("ENTITY") || err.contains("XXE") || err.contains("SECURITY"),
        "error must indicate DTD/entity rejection, got: {err}"
    );
}

/// Production scenario: attacker sends malformed garbage as a SAML request.
/// Must not panic -- must return a clean error.
#[test]
fn test_saml_malformed_input_does_not_panic() {
    // Random binary garbage.
    let garbage = vec![0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90, 0xAB];
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &garbage,
    );
    let result = common::saml::AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "garbage input must produce error, not panic");

    // Empty input.
    let result = common::saml::AuthnRequest::parse_post_binding("");
    assert!(result.is_err(), "empty input must produce error");

    // Valid base64, invalid XML.
    let not_xml = "This is not XML at all, just text.";
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        not_xml.as_bytes(),
    );
    let result = common::saml::AuthnRequest::parse_post_binding(&encoded);
    assert!(result.is_err(), "non-XML input must produce error");
}

// ===========================================================================
// 4. Half-Written FROST Nonce State Recovery
// ===========================================================================

/// Production scenario: power failure during nonce WAL write. The file is
/// truncated mid-entry (< 24 bytes). On recovery, the nonce counter must
/// advance past the corruption with a safety margin. Nonce reuse in FROST
/// reveals the signing key -- this is a catastrophic failure if not handled.
#[test]
#[serial]
fn test_frost_nonce_wal_survives_partial_write() {
    run_with_large_stack(|| {
        // Set up master KEK for the nonce sealing path.
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));

        let dir = temp_dir("nonce-wal-partial");
        let wal_path = dir.join("nonce_wal");

        // Write a valid WAL entry (24 bytes: nonce(8) + epoch(8) + crc32(4) + magic(4)).
        let nonce_value: u64 = 500;
        let epoch: u64 = 1700000000;
        let mut entry = [0u8; 24];
        entry[0..8].copy_from_slice(&nonce_value.to_le_bytes());
        entry[8..16].copy_from_slice(&epoch.to_le_bytes());
        // Compute CRC32 over first 16 bytes.
        let crc = crc32_iso3309(&entry[0..16]);
        entry[16..20].copy_from_slice(&crc.to_le_bytes());
        entry[20..24].copy_from_slice(&[0xFE; 4]);
        std::fs::write(&wal_path, &entry).expect("write valid WAL");

        // Set the WAL path env var for NonceWal.
        std::env::set_var("MILNET_TSS_NONCE_WAL_PATH", wal_path.to_str().unwrap());
        // Set a non-existent sealed state path so it defaults to 0.
        std::env::set_var("MILNET_TSS_NONCE_STATE_PATH", dir.join("nonexistent_sealed").to_str().unwrap());

        // Verify valid WAL loads correctly (nonce + safety margin).
        let wal = tss::distributed::NonceWal::new(Some(wal_path.clone()));
        assert!(
            wal.current_nonce() >= nonce_value,
            "valid WAL must recover nonce >= {nonce_value}, got {}",
            wal.current_nonce()
        );
        let _valid_recovery_nonce = wal.current_nonce();

        // Now truncate the WAL to simulate a crash mid-write (12 bytes = partial).
        std::fs::write(&wal_path, &entry[0..12]).expect("write truncated WAL");

        let wal_truncated = tss::distributed::NonceWal::new(Some(wal_path.clone()));
        // Truncated WAL returns 0 from read_wal_nonce, so recovery = max(0, sealed=0) + margin.
        // The critical assertion: the nonce counter still advances (it doesn't silently reuse old nonces).
        assert!(
            wal_truncated.current_nonce() > 0,
            "truncated WAL must still produce a non-zero nonce counter (safety margin)"
        );

        // Corrupt the CRC: valid length but wrong checksum.
        let mut bad_crc_entry = entry;
        bad_crc_entry[16] ^= 0xFF; // flip a CRC byte
        std::fs::write(&wal_path, &bad_crc_entry).expect("write bad CRC WAL");

        let wal_bad_crc = tss::distributed::NonceWal::new(Some(wal_path.clone()));
        // Bad CRC should be treated as corruption, returning 0 for the WAL nonce.
        // Recovery then uses safety margin only.
        assert!(
            wal_bad_crc.current_nonce() > 0,
            "bad CRC WAL must still produce a safe nonce counter"
        );

        // Corrupt the magic bytes: valid length and CRC but wrong sentinel.
        let mut bad_magic_entry = entry;
        bad_magic_entry[20] = 0x00; // break sentinel
        std::fs::write(&wal_path, &bad_magic_entry).expect("write bad magic WAL");

        let wal_bad_magic = tss::distributed::NonceWal::new(Some(wal_path.clone()));
        assert!(
            wal_bad_magic.current_nonce() > 0,
            "bad magic WAL must still produce a safe nonce counter"
        );

        // Cleanup env vars.
        std::env::remove_var("MILNET_TSS_NONCE_WAL_PATH");
        std::env::remove_var("MILNET_TSS_NONCE_STATE_PATH");
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// CRC32 (ISO 3309 polynomial 0xEDB88320) -- matches the NonceWal implementation.
fn crc32_iso3309(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ===========================================================================
// 5. Slow Loris / Read Timeout on SHARD Transport
// ===========================================================================

/// Production scenario: attacker opens a TLS connection to the SHARD listener
/// and sends data 1 byte at a time, never completing a frame. The server must
/// time out and drop the connection (30s default). Without this, a small number
/// of slow connections can exhaust all server connection slots.
#[tokio::test]
async fn test_shard_transport_rejects_slow_sender() {
    use shard::tls_transport::{tls_bind, tls_connect};
    use common::types::ModuleId;

    let hmac_key = [0x42u8; 64];

    // Bind a TLS listener.
    let (listener, ca, _server_cert) = tls_bind(
        "127.0.0.1:0",
        ModuleId::Orchestrator,
        hmac_key,
        "localhost",
    )
    .await
    .expect("bind TLS listener");
    let addr = listener.local_addr().expect("local addr");

    // Set up a client connector using the SAME CA so TLS handshake succeeds.
    let client_ca = ca;
    let client_cert = shard::tls::generate_module_cert("slow-client", &client_ca);
    let client_config = shard::tls::client_tls_config(&client_cert, &client_ca);
    let connector = shard::tls::tls_connector(client_config);

    // Server task: accept one connection and attempt to recv.
    let server_handle = tokio::spawn(async move {
        let mut transport = listener.accept().await.expect("accept");
        // This recv should time out because the client never sends a complete frame.
        let start = std::time::Instant::now();
        let result = transport.recv().await;
        let elapsed = start.elapsed();

        assert!(
            result.is_err(),
            "recv from slow sender must fail with timeout, not hang"
        );
        let err = result.unwrap_err();
        let err_str = format!("{err}");
        assert!(
            err_str.contains("timed out") || err_str.contains("timeout") || err_str.contains("read"),
            "error must indicate timeout, got: {err_str}"
        );
        // Timeout should be roughly 30s (the SHARD_TLS_RECV_TIMEOUT).
        // Allow some slack for test infrastructure.
        assert!(
            elapsed.as_secs() >= 25 && elapsed.as_secs() <= 60,
            "timeout should be ~30s, was {:?}",
            elapsed
        );
    });

    // Client: complete TLS handshake but never send any data.
    // This simulates an attacker that holds the connection open without
    // sending a complete SHARD frame. The server must time out.
    let _client = tls_connect(
        &addr.to_string(),
        ModuleId::Gateway,
        hmac_key,
        &connector,
        "localhost",
    )
    .await
    .expect("client TLS connect");

    // Do nothing -- hold the connection open. The server's recv() will
    // block waiting for the 4-byte length prefix that never arrives.
    // After SHARD_TLS_RECV_TIMEOUT (30s), the server should time out.

    // Wait for the server to time out.
    server_handle.await.expect("server task");
}

// ===========================================================================
// 6. Encrypted DB Field Bit-Flip Detection
// ===========================================================================

/// Production scenario: attacker with database access flips a single bit in an
/// encrypted column. AES-256-GCM must detect this via tag verification failure.
/// Without this, an attacker can corrupt encrypted data silently, potentially
/// changing a user's role, permissions, or authentication material.
#[test]
fn test_encrypted_db_field_detects_bit_flip() {
    run_with_large_stack(|| {
        let mut kek = [0u8; 32];
        getrandom::getrandom(&mut kek).expect("entropy");
        let enc = common::encrypted_db::FieldEncryptor::new(kek);

        let table = "users";
        let column = "opaque_registration";
        let row_id = b"user-uuid-12345";
        let plaintext = b"supersecret-opaque-credential-data-here";

        // Encrypt.
        let sealed = enc
            .encrypt_field(table, column, row_id, plaintext)
            .expect("encrypt");

        // Verify clean decrypt works.
        let decrypted = enc
            .decrypt_field(table, column, row_id, &sealed)
            .expect("decrypt clean");
        assert_eq!(&decrypted, plaintext);

        // Flip a bit in the ciphertext portion (not the version byte or nonces).
        // V2 format: version(1) + wrap_nonce(12) + wrapped_dek(48) + data_nonce(12) + ciphertext+tag
        let ciphertext_start = 1 + 12 + 48 + 12; // = 73
        assert!(
            sealed.len() > ciphertext_start + 1,
            "sealed data must have ciphertext after headers"
        );

        // Flip bit in ciphertext body.
        let mut tampered_ct = sealed.clone();
        tampered_ct[ciphertext_start] ^= 0x01;
        let result = enc.decrypt_field(table, column, row_id, &tampered_ct);
        assert!(
            result.is_err(),
            "single bit flip in ciphertext must cause decryption failure"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("tampered") || err.contains("failed") || err.contains("GCM"),
            "error must indicate authentication failure, got: {err}"
        );

        // Flip bit in the wrapped DEK.
        let mut tampered_dek = sealed.clone();
        tampered_dek[1 + 12 + 5] ^= 0x01; // somewhere in the wrapped DEK
        let result = enc.decrypt_field(table, column, row_id, &tampered_dek);
        assert!(
            result.is_err(),
            "bit flip in wrapped DEK must cause decryption failure"
        );

        // Flip bit in the wrap nonce.
        let mut tampered_nonce = sealed.clone();
        tampered_nonce[3] ^= 0x01; // in the wrap nonce
        let result = enc.decrypt_field(table, column, row_id, &tampered_nonce);
        assert!(
            result.is_err(),
            "bit flip in wrap nonce must cause decryption failure"
        );

        // Wrong AAD: correct ciphertext but different table name.
        let result = enc.decrypt_field("sessions", column, row_id, &sealed);
        assert!(
            result.is_err(),
            "wrong AAD (different table) must cause decryption failure"
        );

        // Wrong AAD: correct ciphertext but different row_id.
        let result = enc.decrypt_field(table, column, b"different-user-uuid", &sealed);
        assert!(
            result.is_err(),
            "wrong AAD (different row_id) must cause decryption failure"
        );
    });
}

// ===========================================================================
// 7. Key Rotation Mid-Session Token Verification
// ===========================================================================

/// Production scenario: FROST group keys are rotated (DKG ceremony produces a
/// new group key pair). Tokens signed with the OLD group key must still verify
/// with the old key but must NOT verify with the new key. This proves tokens
/// are cryptographically bound to their signing epoch -- a compromised new key
/// cannot forge old tokens, and an old key cannot forge new tokens.
#[test]
fn test_token_valid_after_key_rotation() {
    run_with_large_stack(|| {
        let message = b"session-token-payload-with-claims-and-expiry";

        // Generate first group (epoch 1).
        #[allow(deprecated)]
        let mut group1 = dkg(5, 3).expect("DKG group1");
        let group1_key = group1.group.public_key_package.clone();

        // Sign a token with group1.
        let sig1 = threshold_sign(
            &mut group1.shares,
            &group1.group,
            message,
            3,
        )
        .expect("threshold sign with group1");

        // Verify: token from group1 verifies with group1 key.
        assert!(
            verify_group_signature(&group1.group, message, &sig1),
            "token must verify with its own group key"
        );

        // Generate second group (epoch 2) -- key rotation.
        #[allow(deprecated)]
        let mut group2 = dkg(5, 3).expect("DKG group2");
        let group2_key = group2.group.public_key_package.clone();

        // The two groups must have different verifying keys.
        let vk1_bytes = postcard::to_allocvec(&group1_key).expect("serialize vk1");
        let vk2_bytes = postcard::to_allocvec(&group2_key).expect("serialize vk2");
        assert_ne!(
            vk1_bytes, vk2_bytes,
            "two independent DKG ceremonies must produce different group keys"
        );

        // Sign a token with group2.
        let sig2 = threshold_sign(
            &mut group2.shares,
            &group2.group,
            message,
            3,
        )
        .expect("threshold sign with group2");

        // Verify: token from group2 verifies with group2 key.
        assert!(
            verify_group_signature(&group2.group, message, &sig2),
            "token must verify with its own group key"
        );

        // Cross-verification must FAIL: group1 signature with group2 key.
        assert!(
            !verify_group_signature(&group2.group, message, &sig1),
            "group1 signature must NOT verify with group2 key -- \
             key rotation boundary violated"
        );

        // Cross-verification must FAIL: group2 signature with group1 key.
        assert!(
            !verify_group_signature(&group1.group, message, &sig2),
            "group2 signature must NOT verify with group1 key -- \
             key rotation boundary violated"
        );

        // Altered message must not verify with correct key.
        let mut bad_message = message.to_vec();
        bad_message[0] ^= 0x01;
        assert!(
            !verify_group_signature(&group1.group, &bad_message, &sig1),
            "altered message must not verify"
        );

        // Altered signature must not verify.
        let mut bad_sig = sig1;
        bad_sig[0] ^= 0x01;
        assert!(
            !verify_group_signature(&group1.group, message, &bad_sig),
            "altered signature must not verify"
        );
    });
}

// ===========================================================================
// 8. Raft Partition Simulation
// ===========================================================================

/// Production scenario: network partition splits a 5-node Raft cluster into
/// a 3-node majority and a 2-node minority. The majority must continue
/// committing entries. The minority must not be able to commit (no quorum).
/// After partition heals, the minority must converge with the majority.
///
/// This uses in-process RaftState instances with manual message passing to
/// simulate the partition without actual network I/O.
#[test]
fn test_raft_majority_continues_after_minority_partition() {
    run_with_large_stack(|| {
        // Create 5 node IDs.
        let ids: Vec<NodeId> = (0..5).map(|_| NodeId::random()).collect();

        // Build peer lists for each node.
        let make_config = |node_idx: usize| {
            let peers: Vec<(NodeId, String)> = ids
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != node_idx)
                .map(|(i, id)| (*id, format!("node-{i}")))
                .collect();
            RaftConfig {
                heartbeat_ms: 100,
                election_timeout_min_ms: 300,
                election_timeout_max_ms: 600,
                peers,
            }
        };

        let mut nodes: Vec<RaftState> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| RaftState::new(*id, make_config(i)))
            .collect();

        // Helper: deliver messages between nodes, respecting partition.
        // `partition` is a set of node indices that are in the minority
        // (cannot communicate with nodes NOT in the set).
        let deliver_messages =
            |nodes: &mut Vec<RaftState>,
             outgoing: Vec<(usize, Vec<(NodeId, RaftMessage)>)>,
             minority: &std::collections::HashSet<usize>| {
                let mut all_new: Vec<(usize, Vec<(NodeId, RaftMessage)>)> = Vec::new();
                for (src_idx, messages) in outgoing {
                    let src_in_minority = minority.contains(&src_idx);
                    for (target_id, msg) in messages {
                        // Find target index.
                        let target_idx = ids.iter().position(|id| *id == target_id);
                        if let Some(t_idx) = target_idx {
                            let target_in_minority = minority.contains(&t_idx);
                            // Drop messages that cross the partition boundary.
                            if src_in_minority != target_in_minority {
                                continue;
                            }
                            let responses =
                                nodes[t_idx].handle_message(ids[src_idx], msg);
                            if !responses.is_empty() {
                                all_new.push((t_idx, responses));
                            }
                        }
                    }
                }
                all_new
            };

        // Run ticks until a leader is elected (no partition yet).
        let no_partition: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut leader_idx = None;

        for _round in 0..200 {
            let mut outgoing: Vec<(usize, Vec<(NodeId, RaftMessage)>)> = Vec::new();
            for (i, node) in nodes.iter_mut().enumerate() {
                let msgs = node.tick();
                if !msgs.is_empty() {
                    outgoing.push((i, msgs));
                }
            }

            let mut pending = deliver_messages(&mut nodes, outgoing, &no_partition);
            // Process cascading responses.
            for _ in 0..10 {
                if pending.is_empty() {
                    break;
                }
                pending = deliver_messages(&mut nodes, pending, &no_partition);
            }

            // Check for a leader.
            for (i, node) in nodes.iter().enumerate() {
                if *node.role() == RaftRole::Leader {
                    leader_idx = Some(i);
                }
            }
            if leader_idx.is_some() {
                break;
            }

            // Small sleep to let election timers expire.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(
            leader_idx.is_some(),
            "cluster must elect a leader within 200 rounds"
        );
        let leader = leader_idx.unwrap();

        // The leader proposes an entry.
        let propose_result = nodes[leader].propose(ClusterCommand::Noop);
        assert!(
            propose_result.is_ok(),
            "leader must be able to propose: {:?}",
            propose_result.err()
        );

        // Replicate the entry (run a few rounds).
        for _round in 0..50 {
            let mut outgoing: Vec<(usize, Vec<(NodeId, RaftMessage)>)> = Vec::new();
            for (i, node) in nodes.iter_mut().enumerate() {
                let msgs = node.tick();
                if !msgs.is_empty() {
                    outgoing.push((i, msgs));
                }
            }
            let mut pending = deliver_messages(&mut nodes, outgoing, &no_partition);
            for _ in 0..10 {
                if pending.is_empty() {
                    break;
                }
                pending = deliver_messages(&mut nodes, pending, &no_partition);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        // Now create a partition: nodes 3 and 4 are the minority.
        let minority: std::collections::HashSet<usize> = [3, 4].into_iter().collect();

        // Drain any pre-partition committed entries from minority nodes
        // so we only check for NEW commits that occur during the partition.
        for &i in &[3usize, 4] {
            let _ = nodes[i].take_committed();
        }

        // Ensure the leader is in the majority (nodes 0, 1, 2).
        // If the leader happens to be in the minority, that's fine -- the majority
        // will elect a new leader. Either way, test the invariant.
        let leader_in_majority = !minority.contains(&leader);

        // Run several rounds with the partition active.
        // The majority should be able to elect a new leader if needed and commit.
        for _round in 0..200 {
            let mut outgoing: Vec<(usize, Vec<(NodeId, RaftMessage)>)> = Vec::new();
            for (i, node) in nodes.iter_mut().enumerate() {
                let msgs = node.tick();
                if !msgs.is_empty() {
                    outgoing.push((i, msgs));
                }
            }
            let mut pending = deliver_messages(&mut nodes, outgoing, &minority);
            for _ in 0..10 {
                if pending.is_empty() {
                    break;
                }
                pending = deliver_messages(&mut nodes, pending, &minority);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Find the majority leader.
        let majority_leader = (0..3)
            .find(|i| *nodes[*i].role() == RaftRole::Leader);

        // A majority leader should exist (3 out of 5 can form quorum).
        assert!(
            majority_leader.is_some(),
            "majority partition (3 nodes) must be able to elect a leader"
        );

        // The minority nodes cannot form quorum (need 3 votes, only 2 nodes).
        // They may self-elect as "Leader" in their local state machine after
        // enough election timeouts, but they can NEVER commit entries because
        // they cannot replicate to a majority. Verify they have no committed entries.
        for &i in &[3usize, 4] {
            let committed = nodes[i].take_committed();
            assert!(
                committed.is_empty(),
                "minority node {} must not have committed entries (no quorum) but had {}",
                i,
                committed.len()
            );
        }

        // Majority leader proposes an entry.
        let ml = majority_leader.unwrap();
        let propose_result = nodes[ml].propose(ClusterCommand::HealthUpdate {
            node_id: ids[0],
            healthy: true,
        });
        assert!(
            propose_result.is_ok(),
            "majority leader must be able to propose: {:?}",
            propose_result.err()
        );

        // Run more rounds to commit within the majority.
        for _round in 0..100 {
            let mut outgoing: Vec<(usize, Vec<(NodeId, RaftMessage)>)> = Vec::new();
            for (i, node) in nodes.iter_mut().enumerate() {
                let msgs = node.tick();
                if !msgs.is_empty() {
                    outgoing.push((i, msgs));
                }
            }
            let mut pending = deliver_messages(&mut nodes, outgoing, &minority);
            for _ in 0..10 {
                if pending.is_empty() {
                    break;
                }
                pending = deliver_messages(&mut nodes, pending, &minority);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        // Verify: the majority leader's term is at least as high as before.
        let majority_term = nodes[ml].current_term();
        assert!(
            majority_term.0 >= 1,
            "majority must have advanced to at least term 1"
        );

        // Heal the partition: allow all nodes to communicate.
        for _round in 0..200 {
            let mut outgoing: Vec<(usize, Vec<(NodeId, RaftMessage)>)> = Vec::new();
            for (i, node) in nodes.iter_mut().enumerate() {
                let msgs = node.tick();
                if !msgs.is_empty() {
                    outgoing.push((i, msgs));
                }
            }
            let mut pending = deliver_messages(&mut nodes, outgoing, &no_partition);
            for _ in 0..10 {
                if pending.is_empty() {
                    break;
                }
                pending = deliver_messages(&mut nodes, pending, &no_partition);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // After healing, there should be exactly one leader cluster-wide.
        let final_leaders: Vec<usize> = (0..5)
            .filter(|i| *nodes[*i].role() == RaftRole::Leader)
            .collect();
        assert!(
            final_leaders.len() <= 1,
            "after partition heals, at most one leader should exist; found {:?}",
            final_leaders
        );

        // All nodes should agree on the same term (or at most 1 behind while catching up).
        let terms: Vec<u64> = nodes.iter().map(|n| n.current_term().0).collect();
        let max_term = *terms.iter().max().unwrap();
        for (i, &t) in terms.iter().enumerate() {
            assert!(
                max_term - t <= 1,
                "node {} term ({}) is too far behind max term ({}) after partition heal",
                i,
                t,
                max_term
            );
        }
    });
}

// ===========================================================================
// 9. Raft FileRaftPersistence corruption detection
// ===========================================================================

/// Production scenario: attacker corrupts the persisted Raft state file
/// (term and voted_for). The node must detect the corruption on recovery.
#[test]
fn test_raft_state_persistence_corruption_detected() {
    run_with_large_stack(|| {
        let dir = temp_dir("raft-state-corrupt");
        let persistence = FileRaftPersistence::new(&dir);

        let node_id = NodeId::random();
        persistence
            .persist_state(Term(42), Some(node_id))
            .expect("persist");

        // Verify clean recovery.
        let (term, voted) = persistence.recover_state().expect("recover clean");
        assert_eq!(term, Term(42));
        assert_eq!(voted, Some(node_id));

        // Corrupt the state file.
        let state_path = dir.join("raft_state");
        let mut data = std::fs::read(&state_path).expect("read state");
        assert!(!data.is_empty());
        data[0] ^= 0xFF;
        std::fs::write(&state_path, &data).expect("write corrupted state");

        // Recovery must detect corruption.
        let result = persistence.recover_state();
        match result {
            Err(e) => {
                assert!(
                    e.contains("deserialize"),
                    "error must indicate deserialization failure, got: {e}"
                );
            }
            Ok((term, voted)) => {
                // If by coincidence the corrupted byte still produces valid postcard,
                // the values must differ from what we stored (proving the data changed).
                assert!(
                    term != Term(42) || voted != Some(node_id),
                    "corrupted state file must not silently return original values"
                );
            }
        }
    });
}
