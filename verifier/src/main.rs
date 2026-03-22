#![forbid(unsafe_code)]
//! verifier: Credential Verifier (O(1) token verification) — SHARD service.

use common::revocation::RevocationList;
use common::types::ModuleId;
use frost_ristretto255::keys::PublicKeyPackage;
use std::sync::Arc;
use tokio::sync::Mutex;
use verifier::{
    RevokeResponse, VerifierMessage, VerifyResponse,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Platform integrity: vTPM check, process hardening, self-attestation, monitor
    let (_platform_report, _monitor_handle, _monitor) =
        common::startup_checks::run_platform_checks(crypto::memguard::harden_process);

    tracing::info!("verifier starting");

    // 1. Load group verifying key from env (hex-encoded postcard bytes)
    let group_key: PublicKeyPackage = match std::env::var("MILNET_GROUP_VERIFYING_KEY") {
        Ok(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).expect("MILNET_GROUP_VERIFYING_KEY: invalid hex");
            postcard::from_bytes(&bytes).expect("MILNET_GROUP_VERIFYING_KEY: invalid PublicKeyPackage")
        }
        Err(_) => {
            tracing::warn!(
                "MILNET_GROUP_VERIFYING_KEY not set; generating ephemeral test key (NOT for production)"
            );
            let dkg = crypto::threshold::dkg(5, 3);
            dkg.group.public_key_package
        }
    };

    // 2. Load PQ verifying key from env (hex-encoded ML-DSA-65 encoded key bytes)
    let pq_key: crypto::pq_sign::PqVerifyingKey = match std::env::var("MILNET_PQ_VERIFYING_KEY") {
        Ok(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).expect("MILNET_PQ_VERIFYING_KEY: invalid hex");
            let encoded = crypto::pq_sign::PqEncodedVerifyingKey::try_from(bytes.as_slice())
                .expect("MILNET_PQ_VERIFYING_KEY: wrong length for ML-DSA-65 verifying key");
            crypto::pq_sign::PqVerifyingKey::decode(&encoded)
        }
        Err(_) => {
            tracing::warn!(
                "MILNET_PQ_VERIFYING_KEY not set; generating ephemeral test key (NOT for production)"
            );
            let (_sk, vk) = crypto::pq_sign::generate_pq_keypair();
            vk
        }
    };

    // 3. Initialize shared revocation list
    let revocation_list = Arc::new(Mutex::new(RevocationList::new()));

    // 4. Spawn periodic cleanup task (every 10 minutes)
    {
        let rl = Arc::clone(&revocation_list);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                let mut rl = rl.lock().await;
                let before = rl.len();
                rl.cleanup();
                let after = rl.len();
                if before != after {
                    tracing::info!(
                        "revocation list cleanup: removed {} expired entries ({} remaining)",
                        before - after,
                        after
                    );
                }
            }
        });
    }

    // 5. Bind SHARD listener
    let addr = std::env::var("VERIFIER_ADDR").unwrap_or_else(|_| "127.0.0.1:9104".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let listener =
        shard::transport::ShardListener::bind(&addr, ModuleId::Verifier, hmac_key)
            .await
            .expect("failed to bind verifier SHARD listener");

    tracing::info!("verifier listening on {addr}");

    // TODO: Implement ratchet heartbeat with config.verifier_staleness_timeout_secs (60s)
    // Reject all tokens if Ratchet Manager doesn't respond within timeout

    // 6. Accept connections and handle verify/revoke messages
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let group_key = group_key.clone();
            let pq_key = pq_key.clone();
            let rl = Arc::clone(&revocation_list);
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    // Try the new envelope format first, fall back to legacy VerifyRequest
                    let response_bytes = match postcard::from_bytes::<VerifierMessage>(&payload) {
                        Ok(VerifierMessage::Verify(req)) => {
                            let resp = handle_verify(&req.token_bytes, &group_key, &pq_key, &rl).await;
                            postcard::to_allocvec(&resp).ok()
                        }
                        Ok(VerifierMessage::Revoke(req)) => {
                            let resp = handle_revoke(req.token_id, req.reason, &rl).await;
                            postcard::to_allocvec(&resp).ok()
                        }
                        Err(_) => {
                            // Legacy path: try to deserialize as bare VerifyRequest
                            match postcard::from_bytes::<verifier::VerifyRequest>(&payload) {
                                Ok(req) => {
                                    let resp = handle_verify(&req.token_bytes, &group_key, &pq_key, &rl).await;
                                    postcard::to_allocvec(&resp).ok()
                                }
                                Err(e) => {
                                    let resp = VerifyResponse {
                                        valid: false,
                                        claims: None,
                                        error: Some(format!("request deserialization error: {e}")),
                                    };
                                    postcard::to_allocvec(&resp).ok()
                                }
                            }
                        }
                    };

                    if let Some(bytes) = response_bytes {
                        let _ = transport.send(&bytes).await;
                    }
                }
            });
        }
    }
}

/// Handle a token verification request with revocation check.
async fn handle_verify(
    token_bytes: &[u8],
    group_key: &PublicKeyPackage,
    pq_key: &crypto::pq_sign::PqVerifyingKey,
    rl: &Arc<Mutex<RevocationList>>,
) -> VerifyResponse {
    match postcard::from_bytes::<common::types::Token>(token_bytes) {
        Ok(token) => {
            let revocation_list = rl.lock().await;
            match verifier::verify_token_with_revocation(
                &token, group_key, pq_key, &revocation_list,
            ) {
                Ok(claims) => VerifyResponse {
                    valid: true,
                    claims: Some(claims),
                    error: None,
                },
                Err(e) => VerifyResponse {
                    valid: false,
                    claims: None,
                    error: Some(e.to_string()),
                },
            }
        }
        Err(e) => VerifyResponse {
            valid: false,
            claims: None,
            error: Some(format!("token deserialization error: {e}")),
        },
    }
}

/// Handle a token revocation request.
async fn handle_revoke(
    token_id: [u8; 16],
    reason: common::revocation::RevocationReason,
    rl: &Arc<Mutex<RevocationList>>,
) -> RevokeResponse {
    let mut revocation_list = rl.lock().await;
    let success = revocation_list.revoke(token_id);
    if success {
        tracing::warn!(
            token_id = ?token_id,
            reason = ?reason,
            list_size = revocation_list.len(),
            "token revoked"
        );
    }
    RevokeResponse {
        success,
        error: if success {
            None
        } else {
            Some("token already revoked or revocation list at capacity".into())
        },
    }
}
