#![forbid(unsafe_code)]
//! audit: Audit Log (BFT) service entry point.
//!
//! # 11-VM deployment topology (D2, production/military)
//!
//! The BFT audit cluster tolerates f=3 Byzantine faults with n=11 nodes and a
//! quorum of 2f+1 = 7. For the f=3 guarantee to hold, each node MUST be its
//! own failure domain — running all 11 nodes in a single process (the default
//! dev configuration) gives zero real Byzantine fault tolerance because any
//! compromise of the process owns every node.
//!
//! Production deploys the audit service 11 times, once per VM, each pinned to
//! its own node index:
//!
//! | VM          | Env                          | Role                      |
//! |-------------|------------------------------|---------------------------|
//! | audit-00    | `MILNET_BFT_NODE_INDEX=0`    | Audit replica 0           |
//! | audit-01    | `MILNET_BFT_NODE_INDEX=1`    | Audit replica 1           |
//! | ...         | ...                          | ...                       |
//! | audit-10    | `MILNET_BFT_NODE_INDEX=10`   | Audit replica 10          |
//!
//! Each process sets `MILNET_BFT_STANDALONE=1` (or simply exports
//! `MILNET_BFT_NODE_INDEX`, which implies it) and configures the peer list via
//! `MILNET_BFT_NODE_ADDRS=<csv of peer SHARD mTLS addresses>`. Nodes
//! communicate via the SHARD mTLS transport — they do NOT share an address
//! space, and a compromise of a single VM quarantines at most one node.
//!
//! See `audit::bft::BftStandaloneMode` for the selector used at runtime.
//!
//! Single-process mode is still supported for local development (`cargo run`
//! / integration tests with `MILNET_BFT_SINGLE_PROCESS_ACK=1`).
//!
//! Persistence layout under `AUDIT_DATA_DIR` (default `/var/lib/milnet/audit`):
//!
//!   audit.jsonl              — primary append-only audit log (JSON lines)
//!   signing_seed.bin         — 32-byte seed for deterministic ML-DSA-87 keypair
//!   verifying_key.bin        — encoded ML-DSA-87 verifying key (for external parties)
//!   witness_seed.bin         — 32-byte seed for witness checkpoint signing keypair
//!   witness_verifying_key.bin — encoded witness ML-DSA-87 verifying key
//!   witness_checkpoints.jsonl — persisted witness checkpoints
//!   bft_nodes/node_0.jsonl   — per-BFT-node persistence files
//!   bft_nodes/node_1.jsonl
//!   ...

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use audit::log::{AuditRequest, AuditResponse};

/// Default base directory for audit data persistence.
const DEFAULT_DATA_DIR: &str = "/var/lib/milnet/audit";

#[tokio::main]
async fn main() {
    // MUST be first: harden process before any allocation that could hold a secret.
    crypto::process_harden::harden_early();
    tracing_subscriber::fmt::init();

    // Anchor monotonic time before any crypto/auth operations.
    common::secure_time::init_time_anchor();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "audit",
        9108,
        _platform_report.binary_hash,
    );

    // Initialize master KEK via distributed threshold reconstruction (3-of-5 Shamir)
    let _kek = common::sealed_keys::get_master_kek();

    // Initialize structured JSON logging for production observability
    common::structured_logging::init(common::structured_logging::ServiceMeta {
        service_name: "audit".to_string(),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        instance_id: uuid::Uuid::new_v4().to_string(),
        project_id: std::env::var("GCP_PROJECT_ID").unwrap_or_else(|_| "milnet-sso".to_string()),
    });

    // Verify binary integrity at startup
    let build_info = common::embed_build_info!();
    tracing::info!(
        git_commit = %build_info.git_commit,
        build_time = %build_info.build_time,
        "build manifest verified"
    );

    // Initialize health monitor for peer service tracking
    let _health_monitor = std::sync::Arc::new(common::health::HealthMonitor::new());

    // Initialize metrics counters
    let _auth_counter = common::metrics::Counter::new("auth_attempts", "Total authentication attempts");
    let _error_counter = common::metrics::Counter::new("errors", "Total errors");

    // Initialize authenticated time source
    let _secure_time = common::secure_time::SecureTimeProvider::new(
        common::secure_time::AuthenticatedTimeConfig::default(),
    );

    // Verify CNSA 2.0 compliance at startup
    assert!(common::cnsa2::is_cnsa2_compliant(), "CNSA 2.0 compliance check failed");
    tracing::info!("CNSA 2.0 compliance verified");

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let _health_handle = common::health::spawn_health_endpoint(
        "audit".to_string(),
        9108,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "audit_service".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    tracing::info!("Audit service starting");

    // Resolve persistence directory.
    let data_dir = PathBuf::from(
        std::env::var("AUDIT_DATA_DIR").unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string()),
    );
    ensure_dir(&data_dir);

    // ── Signing key persistence ──────────────────────────────────────────
    // Persist the 32-byte seed so the same ML-DSA-87 keypair is re-derived
    // across restarts. The encoded verifying key is written alongside for
    // external verification.
    let signing_seed_path = data_dir.join("signing_seed.bin");
    let verifying_key_path = data_dir.join("verifying_key.bin");
    let (pq_signing_key, _pq_verifying_key) =
        load_or_generate_keypair(&signing_seed_path, &verifying_key_path);

    // ── D1: Witness signing is performed out-of-process ─────────────────
    // The witness signing key is owned by the `audit-witness` binary and
    // never loaded into the audit process. We open a connection to its UDS
    // here so the periodic checkpoint task can request signatures.
    let witness_sock_path = std::env::var("MILNET_AUDIT_WITNESS_SOCK")
        .unwrap_or_else(|_| "/run/milnet/audit-witness.sock".to_string());
    if !std::path::Path::new(&witness_sock_path).exists() {
        tracing::warn!(
            "audit-witness socket {:?} not present; checkpoints will be skipped \
             until the witness binary is started",
            witness_sock_path
        );
    }

    // ── BFT cluster with per-node persistence ────────────────────────────
    let bft_dir = data_dir.join("bft_nodes");
    ensure_dir(&bft_dir);
    let audit_cluster =
        audit::bft::BftAuditCluster::new_with_persistence(11, pq_signing_key, &bft_dir);
    let cluster = Arc::new(RwLock::new(audit_cluster));

    // ── Witness checkpoint log with persistence ──────────────────────────
    let witness_file = data_dir.join("witness_checkpoints.jsonl");
    let witness_log = Arc::new(Mutex::new(
        load_witness_log(&witness_file),
    ));

    // Track the last known KT root for witness checkpoints.
    // The KT tree lives in a separate service; we fetch its root via a minimal
    // HTTP GET over TCP. Falls back to the last known root (marked stale) when
    // the KT service is unreachable.
    let last_known_kt_root: Arc<Mutex<([u8; 64], bool)>> =
        Arc::new(Mutex::new(([0u8; 64], false))); // (root, is_fresh)

    // Spawn periodic witness checkpoint generation every 300 seconds (5 min).
    {
        let cluster = cluster.clone();
        let witness_log = witness_log.clone();
        let witness_file = witness_file.clone();
        let last_known_kt_root = last_known_kt_root.clone();
        tokio::spawn(async move {
            let kt_addr = std::env::var("KT_ADDR").unwrap_or_else(|_| "127.0.0.1:9109".to_string());

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let c = cluster.read().await;
                // Find the first honest (non-Byzantine) node with at least one log entry.
                let audit_root = c.nodes.iter()
                    .find(|n| !n.is_byzantine && !n.log.is_empty())
                    .map(|n| audit::log::hash_entry(&n.log.entries()[n.log.len() - 1]));

                if let Some(audit_root) = audit_root {
                    // Fetch the current KT root from the KT service via minimal HTTP GET.
                    let (kt_root, kt_fresh) = match fetch_kt_root_http(&kt_addr).await {
                        Ok(root) => {
                            let mut cached = last_known_kt_root.lock().await;
                            *cached = (root, true);
                            (root, true)
                        }
                        Err(e) => {
                            tracing::warn!("Failed to fetch KT root from {}: {}; using last known root (stale)", kt_addr, e);
                            let cached = last_known_kt_root.lock().await;
                            (cached.0, false)
                        }
                    };

                    let staleness_flag = if kt_fresh { "fresh" } else { "stale" };

                    let mut wl = witness_log.lock().await;
                    let sock_path = witness_sock_path.clone();
                    wl.add_signed_checkpoint(audit_root, kt_root, |data| {
                        // D1: ask the out-of-process witness to sign the
                        // SHA-256 hash of the canonical checkpoint payload.
                        // We hash here rather than sending the full payload
                        // so the witness API stays a fixed 32-byte input.
                        use sha2::{Digest, Sha256};
                        let h = Sha256::digest(data);
                        match witness_sign_via_uds(&sock_path, h.as_slice()) {
                            Ok(sig) => sig,
                            Err(e) => {
                                tracing::error!(
                                    "audit-witness UDS sign failed ({}): emitting empty \
                                     signature -- checkpoint will fail verification",
                                    e
                                );
                                Vec::new()
                            }
                        }
                    });

                    // Persist the new checkpoint.
                    if let Some(cp) = wl.latest() {
                        if let Err(e) = append_witness_checkpoint(&witness_file, cp) {
                            tracing::error!("Failed to persist witness checkpoint: {}", e);
                        }
                    }

                    tracing::info!(
                        "Witness checkpoint #{} generated (audit_root={}, kt_root={}, kt_status={})",
                        wl.len(),
                        hex::encode(audit_root),
                        hex::encode(&kt_root[..8]),
                        staleness_flag,
                    );
                } else {
                    tracing::debug!("Witness checkpoint skipped: no audit entries yet");
                }
            }
        });
    }

    // SECURITY: Remove ALL sensitive env vars from /proc/PID/environ IMMEDIATELY
    // after the last env var read. Secrets must not linger in the process environment
    // any longer than necessary to prevent leakage via /proc/PID/environ or
    // child process inheritance.
    common::startup_checks::sanitize_environment();

    let addr = std::env::var("MILNET_AUDIT_LISTEN_ADDR")
        .or_else(|_| std::env::var("AUDIT_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1:9108".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        match shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Audit, hmac_key, "audit")
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("FATAL: Audit service failed to bind TLS listener: {e}");
                std::process::exit(1);
            }
        };

    // D10: Start shared admission controller (dedup + per-tenant throttle).
    let admission = audit::throttle::AdmissionControl::new();
    admission.spawn_eviction_task();

    tracing::info!("Audit service listening on {addr} (mTLS)");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let cluster = cluster.clone();
            let admission = admission.clone();
            tokio::spawn(async move {
                while let Ok((sender, payload)) = transport.recv().await {
                    let response = match postcard::from_bytes::<AuditRequest>(&payload) {
                        Ok(req) => {
                            // Verify the sender is an authorized module
                            let authorized_senders = [
                                common::types::ModuleId::Orchestrator,
                                common::types::ModuleId::Opaque,
                                common::types::ModuleId::Tss,
                                common::types::ModuleId::Verifier,
                                common::types::ModuleId::Admin,
                                common::types::ModuleId::Gateway,
                                common::types::ModuleId::Ratchet,
                                common::types::ModuleId::Risk,
                            ];
                            if !authorized_senders.contains(&sender) {
                                tracing::error!(
                                    sender = ?sender,
                                    "SECURITY: unauthorized module attempted to submit audit entry"
                                );
                                continue;
                            }
                            tracing::debug!(sender = ?sender, event_type = ?req.event_type, "audit entry from verified sender");

                            // D10: admission control — dedup + per-tenant throttle.
                            let tenant_id = req.tenant_id.unwrap_or(uuid::Uuid::nil());
                            let idemp_id = req.idempotency_event_id;
                            let idemp_sig = req.idempotency_signature.clone();
                            match admission.check(tenant_id, idemp_id, &idemp_sig).await {
                                audit::throttle::AdmissionDecision::DuplicateIgnored => {
                                    // Silent idempotent success — no new chain entry.
                                    let resp = AuditResponse {
                                        success: true,
                                        event_id: idemp_id,
                                        error: None,
                                    };
                                    if let Ok(resp_bytes) = postcard::to_allocvec(&resp) {
                                        let _ = transport.send(&resp_bytes).await;
                                    }
                                    continue;
                                }
                                audit::throttle::AdmissionDecision::ThrottleExceeded => {
                                    let resp = AuditResponse {
                                        success: false,
                                        event_id: None,
                                        error: Some(format!(
                                            "per-tenant throttle exceeded for tenant {}",
                                            tenant_id
                                        )),
                                    };
                                    if let Ok(resp_bytes) = postcard::to_allocvec(&resp) {
                                        let _ = transport.send(&resp_bytes).await;
                                    }
                                    continue;
                                }
                                audit::throttle::AdmissionDecision::Accept => {}
                            }

                            let mut c = cluster.write().await;
                            match c.propose_entry(
                                req.event_type,
                                req.user_ids,
                                req.device_ids,
                                req.risk_score,
                                vec![],
                                req.classification,
                            ) {
                                Ok(_entry_hash) => {
                                    // D10: record the commit so replays within
                                    // the TTL hit the idempotent-replay path.
                                    admission.record_commit(idemp_id, &idemp_sig).await;
                                    AuditResponse {
                                        success: true,
                                        event_id: Some(idemp_id.unwrap_or_else(uuid::Uuid::new_v4)),
                                        error: None,
                                    }
                                },
                                Err(e) => AuditResponse {
                                    success: false,
                                    event_id: None,
                                    error: Some(e),
                                },
                            }
                        }
                        Err(e) => AuditResponse {
                            success: false,
                            event_id: None,
                            error: Some(format!("deserialization error: {e}")),
                        },
                    };
                    if let Ok(resp_bytes) = postcard::to_allocvec(&response) {
                        if let Err(e) = transport.send(&resp_bytes).await {
                            tracing::warn!("audit: failed to send response: {e}");
                        }
                    }
                }
            });
        }
    }
}

// ── D1: out-of-process witness signature client ─────────────────────────

/// Connect to the audit-witness UDS, submit a 32-byte hash, and return the
/// ML-DSA-87 signature bytes. Any error (socket missing, malformed reply,
/// hex decode failure) is returned to the caller.
fn witness_sign_via_uds(sock_path: &str, hash: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    if hash.len() != 32 {
        return Err(format!("expected 32-byte hash, got {}", hash.len()));
    }
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("connect {sock_path}: {e}"))?;
    let req = format!("SIGN {}\n", hex::encode(hash));
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read: {e}"))?;
    let line = line.trim();
    let sig_hex = line
        .strip_prefix("SIG ")
        .ok_or_else(|| format!("unexpected response: {}", line))?;
    hex::decode(sig_hex).map_err(|e| format!("hex decode: {e}"))
}

// ── KT root fetch ───────────────────────────────────────────────────────

/// Fetch the current KT Merkle root from the Key Transparency service via
/// a minimal HTTP/1.1 GET request over TCP. Returns a 64-byte SHA-512 root
/// hash on success.
///
/// This avoids pulling in a full HTTP client crate (reqwest/hyper) since this
/// is the only outgoing HTTP call in the audit service.
async fn fetch_kt_root_http(addr: &str) -> Result<[u8; 64], String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| "connection timeout".to_string())?
    .map_err(|e| format!("connect: {e}"))?;

    let request = format!(
        "GET /api/kt/root HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        addr,
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = Vec::with_capacity(4096);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut buf),
    )
    .await
    .map_err(|_| "read timeout".to_string())?
    .map_err(|e| format!("read: {e}"))?;

    let response = String::from_utf8_lossy(&buf);
    // Find the JSON body after the blank line separating headers from body.
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| "malformed HTTP response: no body".to_string())?;

    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parse JSON: {e}"))?;

    let root_hex = json
        .get("root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'root' field in KT response".to_string())?;

    let bytes = hex::decode(root_hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 64 {
        return Err(format!("KT root is {} bytes, expected 64", bytes.len()));
    }

    let mut root = [0u8; 64];
    root.copy_from_slice(&bytes);
    Ok(root)
}

// ── Persistence helpers ─────────────────────────────────────────────────

/// Create a directory (and parents) if it does not already exist.
fn ensure_dir(dir: &Path) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::error!("Failed to create directory {:?}: {}", dir, e);
    }
}

/// Load an existing 32-byte seed from disk, or generate a fresh one and persist it.
/// Also writes/overwrites the encoded verifying key so external parties can verify.
fn load_or_generate_keypair(
    seed_path: &Path,
    vk_path: &Path,
) -> (crypto::pq_sign::PqSigningKey, crypto::pq_sign::PqVerifyingKey) {
    use ml_dsa::{KeyGen, MlDsa87};
    use zeroize::Zeroize;

    let mut seed = [0u8; 32];

    match std::fs::read(seed_path) {
        Ok(data) if data.len() == 32 => {
            // Backward compatibility: unencrypted legacy seed (exactly 32 bytes).
            // Re-encrypt it with the master KEK before proceeding.
            seed.copy_from_slice(&data);
            tracing::warn!(
                "Loaded UNENCRYPTED legacy seed from {:?}; re-encrypting with KEK",
                seed_path,
            );
            persist_seed(seed_path, &seed);
            tracing::info!("Legacy seed at {:?} has been sealed with KEK", seed_path);
        }
        Ok(data) if data.len() >= 12 + 16 + 32 => {
            // Sealed (encrypted) seed — decrypt with master KEK.
            match unseal_seed(&data) {
                Ok(unsealed) => {
                    seed = unsealed;
                    tracing::info!("Loaded and decrypted sealed ML-DSA-87 seed from {:?}", seed_path);
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to unseal seed from {:?}: {}; generating new keypair",
                        seed_path, e
                    );
                    getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
                    tracing::error!("FATAL: CSPRNG failure for audit seed generation: {e}");
                    std::process::exit(1);
                });
                    persist_seed(seed_path, &seed);
                }
            }
        }
        Ok(data) => {
            tracing::warn!(
                "Seed file {:?} has unexpected length {} (expected sealed >=60 or legacy 32); generating new seed",
                seed_path,
                data.len()
            );
            getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
                    tracing::error!("FATAL: CSPRNG failure for audit seed generation: {e}");
                    std::process::exit(1);
                });
            persist_seed(seed_path, &seed);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("No seed file at {:?}; generating new ML-DSA-87 keypair", seed_path);
            getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
                    tracing::error!("FATAL: CSPRNG failure for audit seed generation: {e}");
                    std::process::exit(1);
                });
            persist_seed(seed_path, &seed);
        }
        Err(e) => {
            tracing::error!(
                "Failed to read seed file {:?}: {}; generating ephemeral keypair",
                seed_path, e
            );
            getrandom::getrandom(&mut seed).unwrap_or_else(|e| {
                    tracing::error!("FATAL: CSPRNG failure for audit seed generation: {e}");
                    std::process::exit(1);
                });
            // Do not persist if we cannot read — might be a permission issue
            // that would also prevent writing.
        }
    }

    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();

    let signing_key = kp.signing_key().clone();
    let verifying_key = kp.verifying_key().clone();

    // Persist the encoded verifying key for external consumers.
    persist_verifying_key(vk_path, &verifying_key);

    (signing_key, verifying_key)
}

/// Encrypt a 32-byte seed with AES-256-GCM using a key derived from the master KEK.
fn seal_seed(seed: &[u8; 32]) -> Vec<u8> {
    let master_kek = common::sealed_keys::cached_master_kek();
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-AUDIT-SEED-SEAL-v1"), master_kek);
    let mut seal_key = [0u8; 32];
    if let Err(e) = hk.expand(b"audit-signing-seed", &mut seal_key) {
        tracing::error!("FATAL: HKDF-SHA512 expand failed for audit seed seal: {e}");
        std::process::exit(1);
    }

    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    let cipher = Aes256Gcm::new_from_slice(&seal_key).unwrap_or_else(|_| {
        tracing::error!("FATAL: AES-256-GCM key init failed for audit seed seal");
        std::process::exit(1);
    });
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).unwrap_or_else(|e| {
        tracing::error!("FATAL: CSPRNG failure for audit seed seal nonce: {e}");
        std::process::exit(1);
    });
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, seed.as_ref()).unwrap_or_else(|e| {
        tracing::error!("FATAL: AES-256-GCM encrypt failed for audit seed seal: {e}");
        std::process::exit(1);
    });

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    use zeroize::Zeroize;
    seal_key.zeroize();
    out
}

/// Decrypt a sealed seed back to a 32-byte seed.
fn unseal_seed(sealed: &[u8]) -> Result<[u8; 32], String> {
    if sealed.len() < 12 + 16 + 32 {
        return Err("sealed data too short".into());
    }
    let master_kek = common::sealed_keys::cached_master_kek();
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-AUDIT-SEED-SEAL-v1"), master_kek);
    let mut seal_key = [0u8; 32];
    if let Err(e) = hk.expand(b"audit-signing-seed", &mut seal_key) {
        return Err(format!("HKDF-SHA512 expand failed for audit unseal: {e}"));
    }

    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    let cipher = match Aes256Gcm::new_from_slice(&seal_key) {
        Ok(c) => c,
        Err(_) => return Err("AES-256-GCM key init failed for audit unseal".into()),
    };
    use zeroize::Zeroize;
    seal_key.zeroize();
    let nonce = Nonce::from_slice(&sealed[..12]);
    let plaintext = cipher.decrypt(nonce, &sealed[12..])
        .map_err(|_| "seed decryption failed — file may be tampered".to_string())?;
    if plaintext.len() != 32 {
        return Err(format!("wrong seed length: {} (expected 32)", plaintext.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

/// Write a sealed (encrypted) seed to disk atomically with 3-generation rotation.
///
/// SECURITY (D15): Writes go to `<path>.tmp`, are fsynced, then atomically
/// renamed over the destination. Before the rename, the existing `<path>`
/// is rotated through `<path>.gen-1` and `<path>.gen-2` so that two prior
/// generations are kept on disk for disaster recovery. The parent directory
/// is fsynced after the rename so the directory entry is durable.
fn persist_seed(path: &Path, seed: &[u8; 32]) {
    use std::io::Write;
    let sealed = seal_seed(seed);

    // Rotate generations: gen-1 -> gen-2, current -> gen-1
    let gen1 = path.with_extension("gen-1");
    let gen2 = path.with_extension("gen-2");
    if gen1.exists() {
        if let Err(e) = std::fs::rename(&gen1, &gen2) {
            tracing::warn!("seed gen-1 -> gen-2 rotate failed for {:?}: {}", path, e);
        }
    }
    if path.exists() {
        if let Err(e) = std::fs::rename(path, &gen1) {
            tracing::warn!("seed current -> gen-1 rotate failed for {:?}: {}", path, e);
        }
    }

    let tmp = path.with_extension("tmp");
    let open_res = {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        opts.open(&tmp)
    };
    match open_res {
        Ok(mut f) => {
            if let Err(e) = f.write_all(&sealed) {
                tracing::error!("FATAL: failed to write sealed seed tmp {:?}: {}", tmp, e);
                std::process::exit(1);
            }
            if let Err(e) = f.sync_all() {
                tracing::error!("FATAL: failed to fsync sealed seed tmp {:?}: {}", tmp, e);
                std::process::exit(1);
            }
            drop(f);
            if let Err(e) = std::fs::rename(&tmp, path) {
                tracing::error!("FATAL: atomic rename of sealed seed failed {:?} -> {:?}: {}", tmp, path, e);
                std::process::exit(1);
            }
            // fsync parent directory so the rename is durable
            if let Some(parent) = path.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
            tracing::info!("Persisted sealed ML-DSA-87 seed to {:?} (atomic, 3-gen)", path);
        }
        Err(e) => {
            tracing::error!("FATAL: failed to open sealed seed tmp {:?}: {}", tmp, e);
            std::process::exit(1);
        }
    }
}

/// Persist the ML-DSA-87 verifying key in its encoded form.
fn persist_verifying_key(path: &Path, vk: &crypto::pq_sign::PqVerifyingKey) {
    use std::io::Write;

    let encoded = vk.encode();
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(encoded.as_ref()) {
                tracing::error!("Failed to write verifying key to {:?}: {}", path, e);
            } else if let Err(e) = f.sync_all() {
                tracing::error!("Failed to sync verifying key file {:?}: {}", path, e);
            } else {
                // Set restrictive permissions (owner read/write only)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o600);
                    if let Err(e) = std::fs::set_permissions(path, perms) {
                        tracing::error!("Failed to set permissions on {:?}: {}", path, e);
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to open verifying key file {:?}: {}", path, e);
        }
    }
}

/// Load witness checkpoints from a JSONL file and rebuild the WitnessLog.
fn load_witness_log(path: &Path) -> common::witness::WitnessLog {
    use std::io::{BufRead, BufReader};

    let mut log = common::witness::WitnessLog::new();

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return log,
        Err(e) => {
            tracing::error!("Failed to open witness checkpoint file {:?}: {}", path, e);
            return log;
        }
    };

    let reader = BufReader::new(file);
    let mut count = 0usize;
    for (line_num, line) in reader.lines().enumerate() {
        match line {
            Ok(text) => {
                let text = text.trim().to_string();
                if text.is_empty() {
                    continue;
                }
                match serde_json::from_str::<common::witness::WitnessCheckpoint>(&text) {
                    Ok(cp) => {
                        log.add_checkpoint(cp.audit_root, cp.kt_root, cp.signature);
                        count += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Skipping malformed witness checkpoint on line {}: {}",
                            line_num + 1, e
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("I/O error reading witness checkpoints line {}: {}", line_num + 1, e);
            }
        }
    }

    if count > 0 {
        tracing::info!("Reloaded {} witness checkpoints from {:?}", count, path);
    }
    log
}

/// Append a single witness checkpoint as a JSON line.
fn append_witness_checkpoint(
    path: &Path,
    cp: &common::witness::WitnessCheckpoint,
) -> std::io::Result<()> {
    use std::io::Write;

    let json = serde_json::to_string(cp).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", json)?;
    // SECURITY (D7): full fsync (data + metadata) — sync_data alone is
    // insufficient against power-loss because metadata may not be persisted.
    file.sync_all()?;
    drop(file);
    // Also fsync the parent directory so the file entry itself is durable.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
