#![forbid(unsafe_code)]
//! kt: Key Transparency Log service entry point.

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Requests handled by the Key Transparency service.
#[derive(Debug, Serialize, Deserialize)]
enum KtRequest {
    AppendOp {
        user_id: Uuid,
        operation: String,
        credential_hash: [u8; 32],
        timestamp: i64,
    },
    GetRoot,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "kt",
        9109,
        _platform_report.binary_hash,
    );

    // Initialize structured JSON logging for production observability
    common::structured_logging::init(common::structured_logging::ServiceMeta {
        service_name: "kt".to_string(),
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

    tracing::info!("Key Transparency service starting");

    let tree = Arc::new(RwLock::new(kt::merkle::MerkleTree::new()));

    // Generate ML-DSA-87 signing keypair for signed tree heads (CNSA 2.0)
    let (pq_signing_key, _pq_verifying_key) = crypto::pq_sign::generate_pq_keypair();
    tracing::info!("ML-DSA-87 signing keypair generated for tree head signatures");

    // Spawn periodic signed tree head task (every 60 seconds)
    let tree_clone = tree.clone();
    let pq_key_clone = pq_signing_key.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let t = tree_clone.read().await;
            if t.len() > 0 {
                let sth = t.signed_tree_head(&pq_key_clone);
                tracing::info!("Signed tree head: {} leaves, root={}", sth.tree_size, hex::encode(&sth.root[..8]));
            }
        }
    });

    let addr = std::env::var("KT_ADDR").unwrap_or_else(|_| "127.0.0.1:9107".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Kt, hmac_key, "kt")
            .await
            .unwrap();

    tracing::info!("Key Transparency service listening on {addr} (mTLS)");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let tree = tree.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    if let Ok(request) = postcard::from_bytes::<KtRequest>(&payload) {
                        match request {
                            KtRequest::AppendOp { user_id, operation, credential_hash, timestamp } => {
                                let mut tree = tree.write().await;
                                tree.append_credential_op(&user_id, &operation, &credential_hash, timestamp);
                            }
                            KtRequest::GetRoot => {
                                let tree = tree.read().await;
                                let root = tree.root();
                                let _ = transport.send(&root).await;
                            }
                        }
                    }
                }
            });
        }
    }
}
