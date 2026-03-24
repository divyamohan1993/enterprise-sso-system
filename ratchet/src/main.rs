//! ratchet: Ratchet Session Manager service entry point.

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

    // Verify mlock is available by attempting to lock and unlock a test page
    verify_mlock_available();

    // Set PR_SET_DUMPABLE=0 as belt-and-suspenders (harden_process does this too,
    // but we ensure it explicitly for this process).
    set_pr_dumpable();

    tracing::info!("Ratchet Session Manager starting");

    let manager = Arc::new(RwLock::new(ratchet::manager::SessionManager::new()));

    let addr = std::env::var("RATCHET_ADDR").unwrap_or_else(|_| "127.0.0.1:9105".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let (listener, _ca, _cert_key) =
        shard::tls_transport::tls_bind(&addr, common::types::ModuleId::Ratchet, hmac_key, "ratchet")
            .await
            .unwrap();

    tracing::info!("Ratchet Session Manager listening on {addr} (mTLS)");
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let manager = manager.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    let response = match postcard::from_bytes::<RatchetRequest>(&payload) {
                        Ok(request) => handle_request(&manager, request).await,
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
        if common::sealed_keys::is_production() {
            panic!(
                "FATAL: mlock not available in production mode. \
                 Ratchet chain keys require memory locking. \
                 Ensure RLIMIT_MEMLOCK is sufficient."
            );
        }
        tracing::warn!(
            "mlock not available — chain keys may be swappable to disk. \
             This is acceptable in development but FATAL in production."
        );
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

async fn handle_request(
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
            let epoch = mgr.create_session(session_id, &secret);
            RatchetResponse {
                success: true,
                epoch: Some(epoch),
                tag: None,
                error: None,
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
