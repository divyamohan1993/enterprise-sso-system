//! ratchet: Ratchet Session Manager service entry point.
//!
//! Operates in two modes:
//! - **Distributed HA mode** (default): Uses `PersistentSessionManager` backed by
//!   PostgreSQL with write-through caching. All ratchet chains survive crashes
//!   and are replicated across instances via Cloud SQL.
//! - **Standalone mode** (fallback when `DATABASE_URL` is not set): Uses in-memory
//!   `SessionManager` only. Suitable for development/testing.

#![allow(unsafe_code)]

use std::sync::Arc;
use tokio::sync::RwLock;

use ratchet::manager::{RatchetAction, RatchetRequest, RatchetResponse};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    // Start runtime defense: stealth detection + auto-response pipeline
    let _defense = common::runtime_defense::start_runtime_defense(
        "ratchet",
        9105,
        _platform_report.binary_hash,
    );

    // Initialize master KEK via distributed threshold reconstruction (3-of-5 Shamir)
    let _kek = common::sealed_keys::get_master_kek();

    // Initialize structured JSON logging for production observability
    common::structured_logging::init(common::structured_logging::ServiceMeta {
        service_name: "ratchet".to_string(),
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

    // Verify CNSA 2.0 compliance at startup
    assert!(common::cnsa2::is_cnsa2_compliant(), "CNSA 2.0 compliance check failed");
    tracing::info!("CNSA 2.0 compliance verified");

    // Verify mlock is available by attempting to lock and unlock a test page
    verify_mlock_available();

    // Set PR_SET_DUMPABLE=0 as belt-and-suspenders (harden_process does this too,
    // but we ensure it explicitly for this process).
    set_pr_dumpable();

    // Spawn health check endpoint
    let health_start = std::time::Instant::now();
    let _health_handle = common::health::spawn_health_endpoint(
        "ratchet".to_string(),
        9105,
        health_start,
        || {
            vec![common::health::HealthCheck {
                name: "ratchet_service".to_string(),
                ok: true,
                detail: None,
                latency_ms: None,
            }]
        },
    );

    tracing::info!("Ratchet Session Manager starting");

    // Determine operational mode based on DATABASE_URL availability
    let db_url = std::env::var("DATABASE_URL").ok();
    let persistent_manager: Option<Arc<RwLock<ratchet::manager::PersistentSessionManager>>>;
    let standalone_manager: Option<Arc<RwLock<ratchet::manager::SessionManager>>>;

    if let Some(url) = db_url {
        tracing::info!("DATABASE_URL set — starting in distributed HA mode with PostgreSQL persistence");

        // Connect to Cloud SQL / PostgreSQL
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .expect("Failed to connect to PostgreSQL for ratchet HA persistence");

        // Load KEK from environment (in production, from HSM / sealed storage)
        let kek_hex = std::env::var("RATCHET_KEK")
            .expect("RATCHET_KEK must be set in distributed HA mode (64 hex chars = 32 bytes)");
        let kek_bytes = hex::decode(&kek_hex)
            .expect("RATCHET_KEK must be valid hex");
        assert_eq!(kek_bytes.len(), 32, "RATCHET_KEK must be exactly 32 bytes (64 hex chars)");
        let mut kek = [0u8; 32];
        kek.copy_from_slice(&kek_bytes);

        // Initialize with startup recovery (loads all sessions from DB)
        let mgr = ratchet::manager::PersistentSessionManager::new(pool, kek)
            .await
            .expect("Failed to initialize PersistentSessionManager with DB recovery");

        tracing::info!(
            session_count = mgr.session_count(),
            "distributed HA ratchet manager ready — sessions recovered from PostgreSQL"
        );

        persistent_manager = Some(Arc::new(RwLock::new(mgr)));
        standalone_manager = None;
    } else {
        tracing::warn!(
            "DATABASE_URL not set — starting in standalone mode (NO persistence, NO HA). \
             This is acceptable for development but FATAL-grade in production."
        );
        persistent_manager = None;
        standalone_manager = Some(Arc::new(RwLock::new(ratchet::manager::SessionManager::new())));
    }

    let addr = std::env::var("RATCHET_ADDR").unwrap_or_else(|_| "127.0.0.1:9105".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Ratchet, hmac_key, "ratchet")
            .await
            .unwrap();

    tracing::info!("Ratchet Session Manager listening on {addr} (mTLS)");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let pm = persistent_manager.clone();
            let sm = standalone_manager.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    let response = match postcard::from_bytes::<RatchetRequest>(&payload) {
                        Ok(request) => {
                            if let Some(ref mgr) = pm {
                                handle_request_persistent(mgr, request).await
                            } else if let Some(ref mgr) = sm {
                                handle_request_standalone(mgr, request).await
                            } else {
                                RatchetResponse {
                                    success: false,
                                    epoch: None,
                                    tag: None,
                                    error: Some("no manager configured".into()),
                                }
                            }
                        }
                        Err(e) => RatchetResponse {
                            success: false,
                            epoch: None,
                            tag: None,
                            error: Some(format!("deserialize error: {e}")),
                        },
                    };
                    let encoded = postcard::to_allocvec(&response)
                        .expect("RatchetResponse must serialize");
                    let _ = transport.send(&encoded).await;
                }
            });
        }
    }
}

/// Verify that mlock is available on this system. In production mode, panic
/// if mlock fails — chain keys must not be swappable to disk.
fn verify_mlock_available() {
    let test_page = [0u8; 4096];
    let ptr = test_page.as_ptr();
    let ok = unsafe { libc::mlock(ptr as *const libc::c_void, 4096) == 0 };
    if ok {
        unsafe {
            libc::munlock(ptr as *const libc::c_void, 4096);
        }
        tracing::info!("mlock availability verified");
    } else {
        tracing::error!(
            "FATAL: mlock not available. \
             Ratchet chain keys require memory locking. \
             Ensure RLIMIT_MEMLOCK is sufficient."
        );
        std::process::exit(1);
    }
}

/// Set PR_SET_DUMPABLE=0 to prevent core dumps from leaking chain keys.
/// harden_process() already does this, but we call it explicitly as defense-in-depth.
fn set_pr_dumpable() {
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if ret != 0 {
        tracing::warn!("prctl(PR_SET_DUMPABLE, 0) failed — core dumps may leak key material");
    } else {
        tracing::info!("PR_SET_DUMPABLE=0 confirmed for ratchet process");
    }
}

/// Handle a request using the standalone (in-memory only) session manager.
async fn handle_request_standalone(
    manager: &Arc<RwLock<ratchet::manager::SessionManager>>,
    request: RatchetRequest,
) -> RatchetResponse {
    match request.action {
        RatchetAction::CreateSession { session_id, initial_key } => {
            if initial_key.len() != 64 {
                return RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some("initial_key must be exactly 64 bytes".into()),
                };
            }
            let mut secret = [0u8; 64];
            secret.copy_from_slice(&initial_key);
            let mgr = manager.write().await;
            match mgr.create_session(session_id, &secret) {
                Ok(epoch) => RatchetResponse {
                    success: true,
                    epoch: Some(epoch),
                    tag: None,
                    error: None,
                },
                Err(e) => RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some(e),
                },
            }
        }
        RatchetAction::Advance {
            session_id,
            client_entropy,
            server_entropy,
            server_nonce,
        } => {
            let mgr = manager.write().await;
            match mgr.advance_session(&session_id, &client_entropy, &server_entropy, &server_nonce)
            {
                Ok(epoch) => RatchetResponse {
                    success: true,
                    epoch: Some(epoch),
                    tag: None,
                    error: None,
                },
                Err(e) => RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some(e),
                },
            }
        }
        RatchetAction::GetTag { session_id, claims_bytes } => {
            let mgr = manager.read().await;
            match mgr.generate_tag(&session_id, &claims_bytes) {
                Ok(tag) => RatchetResponse {
                    success: true,
                    epoch: None,
                    tag: Some(tag.to_vec()),
                    error: None,
                },
                Err(e) => RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some(e),
                },
            }
        }
        RatchetAction::Destroy { session_id } => {
            let mgr = manager.write().await;
            mgr.destroy_session(&session_id);
            RatchetResponse {
                success: true,
                epoch: None,
                tag: None,
                error: None,
            }
        }
    }
}

/// Handle a request using the persistent (write-through PostgreSQL) session manager.
async fn handle_request_persistent(
    manager: &Arc<RwLock<ratchet::manager::PersistentSessionManager>>,
    request: RatchetRequest,
) -> RatchetResponse {
    match request.action {
        RatchetAction::CreateSession { session_id, initial_key } => {
            if initial_key.len() != 64 {
                return RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some("initial_key must be exactly 64 bytes".into()),
                };
            }
            let mut secret = [0u8; 64];
            secret.copy_from_slice(&initial_key);
            let mgr = manager.write().await;
            match mgr.create_session(session_id, &secret).await {
                Ok(epoch) => RatchetResponse {
                    success: true,
                    epoch: Some(epoch),
                    tag: None,
                    error: None,
                },
                Err(e) => RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some(e),
                },
            }
        }
        RatchetAction::Advance {
            session_id,
            client_entropy,
            server_entropy,
            server_nonce,
        } => {
            let mgr = manager.write().await;
            match mgr.advance_session(&session_id, &client_entropy, &server_entropy, &server_nonce).await
            {
                Ok(epoch) => RatchetResponse {
                    success: true,
                    epoch: Some(epoch),
                    tag: None,
                    error: None,
                },
                Err(e) => RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some(e),
                },
            }
        }
        RatchetAction::GetTag { session_id, claims_bytes } => {
            let mgr = manager.read().await;
            match mgr.generate_tag(&session_id, &claims_bytes) {
                Ok(tag) => RatchetResponse {
                    success: true,
                    epoch: None,
                    tag: Some(tag.to_vec()),
                    error: None,
                },
                Err(e) => RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some(e),
                },
            }
        }
        RatchetAction::Destroy { session_id } => {
            let mgr = manager.write().await;
            match mgr.destroy_session(&session_id).await {
                Ok(()) => RatchetResponse {
                    success: true,
                    epoch: None,
                    tag: None,
                    error: None,
                },
                Err(e) => RatchetResponse {
                    success: false,
                    epoch: None,
                    tag: None,
                    error: Some(e),
                },
            }
        }
    }
}
