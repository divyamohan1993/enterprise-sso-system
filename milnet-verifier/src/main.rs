#![forbid(unsafe_code)]
//! milnet-verifier: Credential Verifier (O(1) token verification).

use ed25519_dalek::VerifyingKey;
fn main() {
    tracing::info!("milnet-verifier starting");

    // In production: load group verifying key from config/env.
    // The key is 32 bytes, provided as a comma-separated byte string or
    // loaded from a key file.
    let group_key_bytes: Option<[u8; 32]> = std::env::var("MILNET_GROUP_VERIFYING_KEY")
        .ok()
        .and_then(|s| {
            let bytes: Vec<u8> = s
                .split(',')
                .filter_map(|b| b.trim().parse::<u8>().ok())
                .collect();
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        });

    match group_key_bytes.and_then(|b| VerifyingKey::from_bytes(&b).ok()) {
        Some(key) => {
            tracing::info!("loaded group verifying key from environment");
            let _key = key; // Would pass to verification service
        }
        None => {
            tracing::warn!(
                "MILNET_GROUP_VERIFYING_KEY not set or invalid; running without verification key"
            );
        }
    }

    println!("milnet-verifier ready");
}
