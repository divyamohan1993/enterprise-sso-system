#![forbid(unsafe_code)]
//! milnet-opaque: T-OPAQUE Password Service.

use milnet_opaque::store::CredentialStore;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let store = CredentialStore::new();
    if let Err(e) = milnet_opaque::service::run(store).await {
        eprintln!("OPAQUE service error: {e}");
        std::process::exit(1);
    }
}
