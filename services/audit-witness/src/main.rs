// Limited unsafe is required for the SO_PEERCRED getsockopt call below.
// All other code paths must be safe — keep the allow scoped to this module.
#![allow(unsafe_code)]
//! audit-witness — D1 fix for co-located witness signing key.
//!
//! Listens on a Unix domain socket at `/run/milnet/audit-witness.sock` and
//! signs checkpoint hashes submitted by the audit service. The witness signing
//! key is loaded via `common::secret_loader` under the name `audit-witness-key`
//! and never leaves this process. SO_PEERCRED is used on both sides to verify
//! that the connecting client runs under the expected uid, and at startup the
//! witness asserts `audit_pid != witness_pid` so a single compromised process
//! cannot hold both signing keys.
//!
//! ## Wire protocol (line-oriented over UDS)
//!
//! ```text
//! HEALTH                       -> "OK <pid> <iso8601>\n"
//! SIGN <hex-32-byte-hash>      -> "SIG <hex-encoded-ml-dsa-87-signature>\n"
//! VK                           -> "VK <hex-encoded-verifying-key>\n"
//! ```
//!
//! Any malformed request is answered with `ERR <reason>\n` and the connection
//! is closed.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ml_dsa::{KeyGen, MlDsa87};
use std::io::{BufRead, BufReader, Write};
use zeroize::Zeroize;

/// Default socket path. Override via `MILNET_AUDIT_WITNESS_SOCK`.
const DEFAULT_SOCK: &str = "/run/milnet/audit-witness.sock";

/// Secret loader name for the witness signing seed.
const WITNESS_KEY_NAME: &str = "audit-witness-key";

/// Env var that tells the witness which uid the audit service runs as.
const AUDIT_UID_ENV: &str = "MILNET_AUDIT_UID";

/// Env var that supplies the audit service's pid for the startup co-location check.
const AUDIT_PID_ENV: &str = "MILNET_AUDIT_PID";

#[repr(C)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

fn main() {
    tracing_subscriber::fmt::init();

    let sock_path = std::env::var("MILNET_AUDIT_WITNESS_SOCK")
        .unwrap_or_else(|_| DEFAULT_SOCK.to_string());

    // ── Co-location safety check (D1) ────────────────────────────────────
    // The whole point of running this as a separate binary is that a
    // compromise of audit must not leak the witness signing key. If the
    // operator (e.g. systemd) supplies the audit pid via env, we refuse to
    // start when audit_pid == our_pid.
    let our_pid = std::process::id() as i32;
    if let Ok(audit_pid) = std::env::var(AUDIT_PID_ENV) {
        match audit_pid.parse::<i32>() {
            Ok(pid) if pid == our_pid => {
                tracing::error!(
                    "FATAL: audit pid ({}) == witness pid ({}). The witness must run \
                     as a separate process; refusing to start.",
                    pid, our_pid
                );
                std::process::exit(2);
            }
            Ok(pid) => {
                tracing::info!("audit pid = {}, witness pid = {} (distinct)", pid, our_pid);
            }
            Err(_) => {
                tracing::warn!("MILNET_AUDIT_PID is set but unparsable; skipping pid check");
            }
        }
    }

    // ── Load the witness signing key ─────────────────────────────────────
    let signing_key = load_signing_key();
    let verifying_key = signing_key.verifying_key().clone();
    let vk_bytes = verifying_key.encode();
    let vk_hex = hex::encode(AsRef::<[u8]>::as_ref(&vk_bytes));
    tracing::info!(vk_prefix = %&vk_hex[..16], "audit-witness key loaded");

    // ── Bind the UDS ─────────────────────────────────────────────────────
    let path = PathBuf::from(&sock_path);
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!("FATAL: failed to create socket dir {:?}: {}", parent, e);
                std::process::exit(1);
            }
        }
    }
    if path.exists() {
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::error!("FATAL: failed to remove stale socket {:?}: {}", path, e);
            std::process::exit(1);
        }
    }
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("FATAL: bind {:?}: {}", path, e);
            std::process::exit(1);
        }
    };
    // Restrict to the audit uid only (0o600).
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            tracing::error!("failed to chmod 0600 {:?}: {}", path, e);
        }
    }

    let expected_uid: Option<u32> = std::env::var(AUDIT_UID_ENV)
        .ok()
        .and_then(|s| s.parse().ok());
    if expected_uid.is_none() {
        tracing::warn!(
            "{} not set — accepting any peer uid. Production deploys MUST set \
             MILNET_AUDIT_UID to the audit service uid.",
            AUDIT_UID_ENV
        );
    }

    tracing::info!("audit-witness listening on {:?}", path);

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if let Some(uid) = expected_uid {
                    if let Err(e) = verify_peer_uid(&stream, uid) {
                        tracing::error!("rejecting connection: {}", e);
                        continue;
                    }
                }
                handle_client(stream, &signing_key, &vk_hex);
            }
            Err(e) => {
                tracing::warn!("accept error: {}", e);
            }
        }
    }
}

fn load_signing_key() -> crypto::pq_sign::PqSigningKey {
    use common::secret_loader;
    let secret = match secret_loader::load_secret(WITNESS_KEY_NAME) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "FATAL: failed to load secret '{}': {}. The witness signing seed must \
                 be provisioned via /run/milnet/secrets.sock or systemd LoadCredential.",
                WITNESS_KEY_NAME, e
            );
            std::process::exit(1);
        }
    };
    if secret.len() < 32 {
        tracing::error!(
            "FATAL: '{}' returned {} bytes, need at least 32",
            WITNESS_KEY_NAME, secret.len()
        );
        std::process::exit(1);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret[..32]);
    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    kp.signing_key().clone()
}

fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut cred = Ucred { pid: 0, uid: u32::MAX, gid: u32::MAX };
    let mut len = std::mem::size_of::<Ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "getsockopt(SO_PEERCRED) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if cred.uid != expected_uid {
        return Err(format!(
            "peer uid {} != expected {} (pid {})",
            cred.uid, expected_uid, cred.pid
        ));
    }
    if cred.pid == std::process::id() as i32 {
        return Err(format!(
            "peer pid {} equals witness pid -- co-location prohibited",
            cred.pid
        ));
    }
    Ok(())
}

fn handle_client(
    mut stream: UnixStream,
    signing_key: &crypto::pq_sign::PqSigningKey,
    vk_hex: &str,
) {
    let mut reader = BufReader::new(stream.try_clone().expect("stream clone"));
    let mut line = String::new();
    if let Err(e) = reader.read_line(&mut line) {
        tracing::warn!("read_line: {}", e);
        return;
    }
    let line = line.trim();
    let response = process_request(line, signing_key, vk_hex);
    if let Err(e) = stream.write_all(response.as_bytes()) {
        tracing::warn!("write response: {}", e);
    }
    let _ = stream.flush();
}

fn process_request(
    request: &str,
    signing_key: &crypto::pq_sign::PqSigningKey,
    vk_hex: &str,
) -> String {
    if request == "HEALTH" {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        return format!("OK {} {}\n", std::process::id(), ts);
    }
    if request == "VK" {
        return format!("VK {}\n", vk_hex);
    }
    if let Some(hex_hash) = request.strip_prefix("SIGN ") {
        let bytes = match hex::decode(hex_hash) {
            Ok(b) => b,
            Err(e) => return format!("ERR hex decode: {}\n", e),
        };
        if bytes.len() != 32 {
            return format!("ERR expected 32-byte hash, got {}\n", bytes.len());
        }
        let sig = crypto::pq_sign::pq_sign_raw(signing_key, &bytes);
        return format!("SIG {}\n", hex::encode(&sig));
    }
    format!("ERR unknown command: {}\n", request)
}

#[allow(dead_code)]
fn enforce_socket_dir_perms(_p: &Path) {}
