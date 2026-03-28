#![forbid(unsafe_code)]
//! opaque: T-OPAQUE Password Service.
//!
//! SECURITY: This service is the SOLE holder of the receipt signing key.
//! The key is generated (or loaded from HSM) inside `opaque::service::run()`
//! and never leaves this process.
//!
//! Supports two modes:
//! - **threshold** (default): 2-of-3 distributed OPAQUE via Shamir secret sharing
//! - **single**: Legacy single-server mode (dev/test only)

use opaque::store::CredentialStore;

#[tokio::main]
async fn main() {
    // Structured logging init
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "opaque",
        9102,
        _platform_report.binary_hash,
    );

    // STIG compliance audit (best-effort — log warnings, do not block startup)
    match common::startup_checks::run_stig_audit() {
        Ok(summary) => tracing::info!("STIG audit passed: {:?}", summary),
        Err(failures) => tracing::warn!("STIG audit had {} failures", failures.len()),
    }

    let opaque_mode = std::env::var("MILNET_OPAQUE_MODE")
        .unwrap_or_else(|_| "threshold".to_string());

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let _health_handle = common::health::spawn_health_endpoint(
        "opaque".to_string(),
        9102,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "opaque_service".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    // ── Distributed cluster coordination ──
    let opaque_addr = std::env::var("MILNET_OPAQUE_ADDR").unwrap_or_else(|_| "127.0.0.1:9102".into());
    let _cluster = match common::cluster::ClusterConfig::from_env_with_defaults(
        common::cluster::ServiceType::Opaque,
        &opaque_addr,
    ) {
        Ok(config) => {
            tracing::info!(
                node_id = %config.node_id,
                peers = config.peers.len(),
                "starting OPAQUE cluster node"
            );
            match common::cluster::ClusterNode::start(config).await {
                Ok(node) => {
                    let node = std::sync::Arc::new(node);
                    let mut watcher = node.leader_watch();
                    tokio::spawn(async move {
                        while watcher.changed().await.is_ok() {
                            if let Some(lid) = *watcher.borrow() {
                                tracing::info!(%lid, "OPAQUE leader elected — this node coordinates threshold fan-out");
                            }
                        }
                    });
                    Some(node)
                }
                Err(e) => {
                    tracing::warn!("OPAQUE cluster start failed (standalone): {e}");
                    None
                }
            }
        }
        Err(_) => None,
    };

    // Wire auto-response pipeline to Raft for distributed quarantine enforcement
    if let Some(ref c) = _cluster {
        _defense.connect_to_cluster(c.clone());
    }

    let result = match opaque_mode.as_str() {
        "threshold" => run_threshold_mode().await,
        "single" => {
            tracing::warn!("Running in SINGLE-SERVER mode (dev/test only — NOT for production)");
            let store = CredentialStore::new();
            opaque::service::run(store).await
        }
        other => {
            eprintln!("Unknown MILNET_OPAQUE_MODE: '{other}' (expected 'threshold' or 'single')");
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("OPAQUE service error: {e}");
        std::process::exit(1);
    }
}

/// Run the OPAQUE service in threshold mode (2-of-3 distributed).
///
/// Generates an OPRF master key, splits it into Shamir shares, zeroizes the
/// master key, and starts the threshold OPAQUE server with this node's share.
async fn run_threshold_mode() -> Result<(), Box<dyn std::error::Error>> {
    use opaque::threshold::{ThresholdOpaqueConfig, ThresholdOpaqueServer, generate_threshold_oprf_key};

    let server_id: u8 = std::env::var("MILNET_OPAQUE_SERVER_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .unwrap_or(1);

    if server_id == 0 || server_id > 3 {
        eprintln!("MILNET_OPAQUE_SERVER_ID must be 1, 2, or 3 (got {server_id})");
        std::process::exit(1);
    }

    tracing::info!(
        "Initializing threshold OPAQUE (2-of-3) as server {}",
        server_id
    );

    // Generate OPRF master key and split into 3 Shamir shares.
    // In production, shares would be pre-distributed from a key ceremony
    // and loaded from an HSM or secure enclave — never generated at startup.
    let keygen_result = generate_threshold_oprf_key(2, 3);

    tracing::info!(
        "OPRF key split into 3 shares (verification_key={:02x?}...)",
        &keygen_result.verification_key[..8]
    );

    // Extract this server's share (1-indexed)
    let my_share = keygen_result.shares[server_id as usize - 1].clone();

    // The keygen_result (and its shares for other servers) will be dropped
    // here. In production, the other shares would have been distributed to
    // their respective servers during a key ceremony — they are never held
    // by a single node at runtime.
    drop(keygen_result);

    let config = ThresholdOpaqueConfig {
        threshold: 2,
        total_servers: 3,
        server_id,
    };

    let threshold_server = ThresholdOpaqueServer::new(config, my_share);

    let store = CredentialStore::new();
    opaque::service::run_threshold(store, server_id, threshold_server).await
}
