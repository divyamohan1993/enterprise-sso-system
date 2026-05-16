//! `authsrv` binary — runs the OIDC AS.
//!
//! TLS is terminated by the gateway; this process speaks HTTP on a loopback
//! socket. SECURITY (P1): the bind address is loopback-only by default so a
//! misconfigured deployment cannot expose credentials over plaintext on a
//! routable interface. Override with `AUTHSRV_BIND` only behind a trusted
//! TLS-terminating proxy.

use authsrv::{router, AsState, ServerConfig};
use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};

/// Default loopback bind address — never a routable interface.
const DEFAULT_BIND: &str = "127.0.0.1:8443";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // MUST be first: harden process before any allocation that could hold a secret.
    crypto::process_harden::harden_early();

    // P2: respect operator log-level controls via RUST_LOG / EnvFilter, and
    // use try_init() so a double-init does not panic.
    let _ = fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .try_init();

    // SECURITY (P0): AsState::new generates the ML-DSA-87 signing key and fails
    // closed if the OS CSPRNG is unavailable — never start with a weak key.
    let state = Arc::new(AsState::new(ServerConfig::default())?);
    let app = router().with_state(state);

    let bind = std::env::var("AUTHSRV_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("authsrv listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
