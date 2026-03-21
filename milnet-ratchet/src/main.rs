#![forbid(unsafe_code)]
//! milnet-ratchet: Ratchet Session Manager service.

use milnet_ratchet::manager::SessionManager;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("milnet-ratchet: starting ratchet session manager");

    let _manager = SessionManager::new();

    tracing::info!("milnet-ratchet: ratchet session manager ready");
}
