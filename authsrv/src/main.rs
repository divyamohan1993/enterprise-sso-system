//! `authsrv` binary — OIDC/OAuth 2.1 authorization server.
//!
//! Network exposure is **never** plaintext on the public interface: the binary
//! refuses to bind anything other than a loopback TCP socket
//! (`127.0.0.1`/`[::1]`).  TLS termination and the public listener belong to
//! the gateway pool — see master plan §5 Phase 1.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use authsrv::{router, AsState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

const DEFAULT_BIND: &str = "127.0.0.1:8443";

fn parse_bind(spec: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = spec
        .parse()
        .map_err(|e| format!("MILNET_AUTHSRV_BIND `{spec}` not a valid socket address: {e}"))?;
    let ip = addr.ip();
    let is_loopback = matches!(ip, IpAddr::V4(v4) if v4 == Ipv4Addr::LOCALHOST)
        || matches!(ip, IpAddr::V6(v6) if v6 == Ipv6Addr::LOCALHOST);
    if !is_loopback {
        return Err(format!(
            "MILNET_AUTHSRV_BIND refuses non-loopback bind `{spec}` — only \
             127.0.0.1 or [::1] are accepted (master plan D-11/D-12)"
        ));
    }
    Ok(addr)
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,authsrv=info"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

fn fatal(msg: &str) -> ! {
    eprintln!("authsrv FATAL: {msg}");
    tracing::error!(target: "siem", "SIEM:CRITICAL authsrv startup aborted: {msg}");
    std::process::exit(1)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Order is load-bearing: process-level hardening (no_new_privs / dumpable=0
    // / RLIMIT_CORE=0) MUST land before the allocator touches a secret.
    if !crypto::process_harden::harden_early() {
        fatal("crypto::process_harden::harden_early failed (kernel rejected hardening primitives)");
    }

    // Anchor monotonic time before any token, code, or audit timestamp is
    // produced.  After this, `secure_now_secs_i64()` is monotonic-anchored
    // and immune to wall-clock manipulation post-startup.
    common::secure_time::init_time_anchor();

    // Entropy + FIPS KATs gate the binary: a stuck RNG or a failed KAT must
    // refuse to serve, never silently degrade.
    crypto::entropy::startup_entropy_health_check();
    crypto::fips_kat::run_startup_kats_or_panic();

    // Initialise the crate-wide DRBG before seccomp narrows the syscall set
    // (the DRBG seed gathering uses entropy syscalls).
    if let Err(e) = authsrv::init_drbg() {
        fatal(&format!("DRBG init failed: {e}"));
    }

    // seccomp filter — applied after early initialisation so the syscall set
    // is settled but before we open the listening socket.
    if !crypto::seccomp::apply_seccomp_filter() {
        tracing::warn!(
            target: "siem",
            "SIEM:HIGH seccomp filter unavailable — continuing with degraded syscall isolation"
        );
    }

    init_tracing();

    common::structured_logging::init(common::structured_logging::ServiceMeta {
        service_name: "authsrv".into(),
        service_version: env!("CARGO_PKG_VERSION").into(),
        instance_id: uuid::Uuid::new_v4().to_string(),
        project_id: std::env::var("GCP_PROJECT_ID").unwrap_or_else(|_| "milnet-sso".into()),
    });

    let bind_spec = std::env::var("MILNET_AUTHSRV_BIND").unwrap_or_else(|_| DEFAULT_BIND.into());
    let addr = match parse_bind(&bind_spec) {
        Ok(t) => t,
        Err(e) => fatal(&e),
    };

    let state = Arc::new(AsState::default());
    let app = router().with_state(state);

    // Standalone health endpoint: gated behind MILNET_HEALTH_TOKEN so a probe
    // cannot disclose topology without authentication.  Failures are non-fatal.
    let _health = common::health::spawn_health_endpoint(
        "authsrv".into(),
        7443,
        std::time::Instant::now(),
        Vec::new,
    );

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => fatal(&format!("bind {addr}: {e}")),
    };
    tracing::info!(target: "siem", addr = %addr, "authsrv listening (loopback TCP)");
    if let Err(e) = axum::serve(listener, app).await {
        fatal(&format!("axum serve: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_v4_accepted() {
        assert!(parse_bind("127.0.0.1:8443").is_ok());
    }

    #[test]
    fn loopback_v6_accepted() {
        assert!(parse_bind("[::1]:8443").is_ok());
    }

    #[test]
    fn wildcard_v4_refused() {
        assert!(parse_bind("0.0.0.0:8443").is_err());
    }

    #[test]
    fn wildcard_v6_refused() {
        assert!(parse_bind("[::]:8443").is_err());
    }

    #[test]
    fn public_ip_refused() {
        assert!(parse_bind("10.1.2.3:8443").is_err());
    }
}
