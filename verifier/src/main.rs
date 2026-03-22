#![forbid(unsafe_code)]
//! verifier: Credential Verifier (O(1) token verification) — SHARD service.

use common::types::ModuleId;
use frost_ristretto255::keys::PublicKeyPackage;
use verifier::{VerifyRequest, VerifyResponse};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
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

    // 3. Bind SHARD listener
    let addr = std::env::var("VERIFIER_ADDR").unwrap_or_else(|_| "127.0.0.1:9104".to_string());
    let hmac_key = crypto::entropy::generate_key_64();
    let listener =
        shard::transport::ShardListener::bind(&addr, ModuleId::Verifier, hmac_key)
            .await
            .expect("failed to bind verifier SHARD listener");

    tracing::info!("verifier listening on {addr}");

    // 4. Accept connections and verify tokens
    loop {
        if let Ok(mut transport) = listener.accept().await {
            let group_key = group_key.clone();
            let pq_key = pq_key.clone();
            tokio::spawn(async move {
                while let Ok((_sender, payload)) = transport.recv().await {
                    let response = match postcard::from_bytes::<VerifyRequest>(&payload) {
                        Ok(req) => {
                            // Deserialize the token from the request's token_bytes
                            match postcard::from_bytes::<common::types::Token>(&req.token_bytes) {
                                Ok(token) => {
                                    match verifier::verify_token(&token, &group_key, &pq_key) {
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
                        Err(e) => VerifyResponse {
                            valid: false,
                            claims: None,
                            error: Some(format!("request deserialization error: {e}")),
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
