#![forbid(unsafe_code)]
//! audit: Audit Log (BFT) service entry point.
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
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

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
    let (pq_signing_key, pq_verifying_key) =
        load_or_generate_keypair(&signing_seed_path, &verifying_key_path);

    // ── Witness signing key persistence ──────────────────────────────────
    let witness_seed_path = data_dir.join("witness_seed.bin");
    let witness_vk_path = data_dir.join("witness_verifying_key.bin");
    let (witness_signing_key, _witness_verifying_key) =
        load_or_generate_keypair(&witness_seed_path, &witness_vk_path);

    // ── BFT cluster with per-node persistence ────────────────────────────
    let bft_dir = data_dir.join("bft_nodes");
    ensure_dir(&bft_dir);
    let audit_cluster =
        audit::bft::BftAuditCluster::new_with_persistence(7, pq_signing_key, &bft_dir);
    let cluster = Arc::new(RwLock::new(audit_cluster));

    // ── Witness checkpoint log with persistence ──────────────────────────
    let witness_file = data_dir.join("witness_checkpoints.jsonl");
    let witness_log = Arc::new(Mutex::new(
        load_witness_log(&witness_file),
    ));

    // Spawn periodic witness checkpoint generation every 300 seconds (5 min).
    {
        let cluster = cluster.clone();
        let witness_log = witness_log.clone();
        let witness_file = witness_file.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let c = cluster.read().await;
                // Find the first honest (non-Byzantine) node with at least one log entry.
                let audit_root = c.nodes.iter()
                    .find(|n| !n.is_byzantine && !n.log.is_empty())
                    .map(|n| audit::log::hash_entry(&n.log.entries()[n.log.len() - 1]));

                if let Some(audit_root) = audit_root {
                    // KT root placeholder: the Key Transparency tree lives in a separate service.
                    // TODO: fetch real KT root from the KT service once integrated.
                    let kt_root = [0u8; 64];

                    let mut wl = witness_log.lock().await;
                    wl.add_signed_checkpoint(audit_root, kt_root, |data| {
                        crypto::pq_sign::pq_sign_raw(&witness_signing_key, data)
                    });

                    // Persist the new checkpoint.
                    if let Some(cp) = wl.latest() {
                        if let Err(e) = append_witness_checkpoint(&witness_file, cp) {
                            tracing::error!("Failed to persist witness checkpoint: {}", e);
                        }
                    }

                    tracing::info!(
                        "Witness checkpoint #{} generated (audit_root={}, kt_root=placeholder)",
                        wl.len(),
                        hex::encode(audit_root),
                    );
                } else {
                    tracing::debug!("Witness checkpoint skipped: no audit entries yet");
                }
            }
        });
    }

    let addr = std::env::var("AUDIT_ADDR").unwrap_or_else(|_| "127.0.0.1:9108".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Audit, hmac_key, "audit")
            .await
            .unwrap();

    tracing::info!("Audit service listening on {addr} (mTLS)");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let cluster = cluster.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    let response = match postcard::from_bytes::<AuditRequest>(&payload) {
                        Ok(req) => {
                            let mut c = cluster.write().await;
                            match c.propose_entry(
                                req.event_type,
                                req.user_ids,
                                req.device_ids,
                                req.risk_score,
                                vec![],
                            ) {
                                Ok(_entry_hash) => AuditResponse {
                                    success: true,
                                    event_id: Some(uuid::Uuid::new_v4()),
                                    error: None,
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
                        let _ = transport.send(&resp_bytes).await;
                    }
                }
            });
        }
    }
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
            seed.copy_from_slice(&data);
            tracing::info!("Loaded ML-DSA-87 seed from {:?}", seed_path);
        }
        Ok(data) => {
            tracing::warn!(
                "Seed file {:?} has unexpected length {} (expected 32); generating new seed",
                seed_path,
                data.len()
            );
            getrandom::getrandom(&mut seed).expect("getrandom failed");
            persist_seed(seed_path, &seed);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("No seed file at {:?}; generating new ML-DSA-87 keypair", seed_path);
            getrandom::getrandom(&mut seed).expect("getrandom failed");
            persist_seed(seed_path, &seed);
        }
        Err(e) => {
            tracing::error!(
                "Failed to read seed file {:?}: {}; generating ephemeral keypair",
                seed_path, e
            );
            getrandom::getrandom(&mut seed).expect("getrandom failed");
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

/// Write a 32-byte seed to disk with restrictive permissions.
fn persist_seed(path: &Path, seed: &[u8; 32]) {
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(seed) {
                tracing::error!("Failed to write seed to {:?}: {}", path, e);
            } else if let Err(e) = f.sync_all() {
                tracing::error!("Failed to sync seed file {:?}: {}", path, e);
            } else {
                tracing::info!("Persisted ML-DSA-87 seed to {:?}", path);
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
            tracing::error!("Failed to open seed file {:?} for writing: {}", path, e);
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
    file.sync_data()?;
    Ok(())
}
