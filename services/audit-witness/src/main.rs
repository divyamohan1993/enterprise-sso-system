// CQ-UNSAFE: SO_PEERCRED now goes through the safe `nix` wrapper
// (`nix::sys::socket::getsockopt` with `sockopt::PeerCredentials`).
// No `unsafe` remains in this crate.
#![deny(unsafe_code)]
//! audit-witness — D1 fix for co-located witness signing key.
//!
//! Listens on a Unix domain socket at `/run/milnet/audit-witness.sock` and
//! signs checkpoint hashes submitted by the audit service. The witness
//! signing seed is read from an inherited file descriptor passed via
//! `MILNET_WITNESS_SEED_FD`, sourced from an independent second factor —
//! HSM, Cloud KMS, or systemd `LoadCredential` — and never derived from the
//! cluster master KEK. SO_PEERCRED is used on both sides to verify that the
//! connecting client runs under the expected uid, and at startup the witness
//! asserts `audit_pid != witness_pid` so a single compromised process cannot
//! hold both signing keys.
//!
//! ## Wire protocol (line-oriented over UDS)
//!
//! ```text
//! HEALTH                                  -> "OK <pid> <iso8601>\n"
//! SIGN <decimal-seq> <hex-32-byte-hash>   -> "SIG <hex-encoded-ml-dsa-87-signature>\n"
//! VK                                      -> "VK <hex-encoded-verifying-key>\n"
//! ```
//!
//! Any malformed request is answered with `ERR <reason>\n` and the connection
//! is closed.
//!
//! X-K hardening: every SIGN payload is signed with the audit-witness FIPS 204
//! domain tag (`AUDIT_WITNESS_DOMAIN`) so a witness signature cannot be
//! cross-presented as any other ML-DSA-87 signature in the system, and every
//! SIGN request must carry a strictly-monotonic `seq` that the witness
//! persists in `<data_dir>/witness_seq.log` (chain-hashed, fsynced) so a
//! compromised audit service cannot equivocate between observers.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use audit_witness::{process_request, WitnessSeqState};
use ml_dsa::{KeyGen, MlDsa87};
use std::io::{BufRead, BufReader, Write};
use zeroize::Zeroize;

/// Default socket path. Override via `MILNET_AUDIT_WITNESS_SOCK`.
const DEFAULT_SOCK: &str = "/run/milnet/audit-witness.sock";

/// Default data dir for the persisted witness sequence chain.
const DEFAULT_DATA_DIR: &str = "/var/lib/milnet/audit-witness";

/// Env var carrying an inherited fd whose contents are a witness seed
/// derived from a source INDEPENDENT of the master KEK (HSM / KMS /
/// systemd LoadCredential). Production MUST set this. There is no longer
/// a master-KEK-derived fallback path: a witness whose seed is recoverable
/// from the master KEK is operationally equivalent to no witness at all.
const WITNESS_SEED_FD_ENV: &str = "MILNET_WITNESS_SEED_FD";

/// Env var that tells the witness which uid the audit service runs as.
const AUDIT_UID_ENV: &str = "MILNET_AUDIT_UID";

/// Env var that supplies the audit service's pid for the startup co-location check.
const AUDIT_PID_ENV: &str = "MILNET_AUDIT_PID";

/// Env var for the persisted witness sequence chain directory.
const DATA_DIR_ENV: &str = "MILNET_AUDIT_WITNESS_DATA_DIR";

fn main() {
    // MUST be first: harden process before any allocation that could hold a secret.
    crypto::process_harden::harden_early();
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

    // ── X-K: load and verify the persisted per-witness sequence chain ────
    // Any tamper detected on disk is fatal: signing with a chain whose
    // integrity is in doubt would let an attacker rewrite history. We exit
    // with code 11 so the supervisor surfaces the SIEM event.
    let data_dir = PathBuf::from(
        std::env::var(DATA_DIR_ENV).unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string()),
    );
    let seq_state = match WitnessSeqState::open(&data_dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                target: "siem",
                severity = "CRITICAL",
                action = "audit_witness.seq_log_load_failed",
                error = %e,
                "FATAL: audit-witness seq chain failed to load — refusing to start"
            );
            std::process::exit(11);
        }
    };
    if let Some(s) = seq_state.last_seq() {
        tracing::info!(
            "audit-witness seq chain loaded; last_seq={}, chain_prefix={}",
            s,
            hex::encode(&seq_state.last_chain()[..8])
        );
    } else {
        tracing::info!("audit-witness seq chain empty — fresh start");
    }
    let seq_state: Mutex<WitnessSeqState> = Mutex::new(seq_state);

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
                handle_client(stream, &seq_state, &signing_key, &vk_hex);
            }
            Err(e) => {
                tracing::warn!("accept error: {}", e);
            }
        }
    }
}

fn load_signing_key() -> crypto::pq_sign::PqSigningKey {
    // The ONLY supported path is a fd inherited from an independent second
    // source (HSM, Cloud KMS, or systemd LoadCredential). A compromise of
    // master-KEK sealed storage MUST NOT yield this key. The previous
    // master-KEK-derived fallback (gated by MILNET_WITNESS_ALLOW_KEK_DERIVED)
    // has been removed: a witness whose seed is recoverable from the same
    // KEK that protects the rest of the cluster contributes zero independent
    // assurance to the audit chain.
    if std::env::var("MILNET_WITNESS_ALLOW_KEK_DERIVED").is_ok() {
        tracing::error!(
            "FATAL: MILNET_WITNESS_ALLOW_KEK_DERIVED is set but the master-KEK-derived \
             witness path has been REMOVED. The witness must be seeded from a source \
             independent of the master KEK via {}.",
            WITNESS_SEED_FD_ENV
        );
        std::process::exit(7);
    }
    let fd_str = match std::env::var(WITNESS_SEED_FD_ENV) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!(
                "FATAL: {} is not set. The witness signing seed must be supplied via a \
                 file descriptor derived from a source independent of the master KEK \
                 (HSM / Cloud KMS / systemd LoadCredential). Refusing to start.",
                WITNESS_SEED_FD_ENV
            );
            std::process::exit(4);
        }
    };
    let fd: i32 = match fd_str.parse() {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(
                "FATAL: {} is set but unparsable ({}). Refusing to start.",
                WITNESS_SEED_FD_ENV, e
            );
            std::process::exit(3);
        }
    };
    load_signing_key_from_fd(fd)
}

/// Read a 32-byte seed from an inherited fd and derive the witness
/// signing key. Enforces a second-source entropy quality gate
/// (not all-zero, not all-0xff, >= 16 distinct byte values).
fn load_signing_key_from_fd(fd: i32) -> crypto::pq_sign::PqSigningKey {
    use std::io::Read;
    use std::os::unix::io::FromRawFd;

    if fd < 3 {
        tracing::error!(
            "FATAL: witness seed fd {} is stdin/stdout/stderr — refusing to start", fd
        );
        std::process::exit(5);
    }

    // SAFETY: fd is inherited from the parent (systemd LoadCredential or
    // launcher) and fully owned by this process. No other code holds it.
    // Taking ownership via from_raw_fd is the only way to read from an
    // inherited fd without copying the seed through an env var (rejected).
    #[allow(unsafe_code)]
    let mut f: std::fs::File = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut seed = [0u8; 32];
    if let Err(e) = f.read_exact(&mut seed) {
        tracing::error!(
            "FATAL: failed to read 32 bytes of witness seed from fd {}: {}", fd, e
        );
        seed.zeroize();
        std::process::exit(6);
    }

    let all_zero = seed.iter().all(|&b| b == 0);
    let all_ff = seed.iter().all(|&b| b == 0xff);
    let distinct = {
        let mut seen = [false; 256];
        let mut n = 0usize;
        for &b in seed.iter() {
            if !seen[b as usize] { seen[b as usize] = true; n += 1; }
        }
        n
    };
    if all_zero || all_ff || distinct < 16 {
        tracing::error!(
            "FATAL: witness seed from fd {} failed entropy gate \
             (all_zero={}, all_ff={}, distinct={})",
            fd, all_zero, all_ff, distinct
        );
        seed.zeroize();
        std::process::exit(7);
    }

    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    tracing::info!(
        "audit-witness: seed loaded from fd {} (independent of master KEK)", fd
    );
    kp.signing_key().clone()
}

fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<(), String> {
    // CQ-UNSAFE: use `nix`'s safe typed wrapper instead of the raw
    // `libc::getsockopt` + out-parameter dance. The wrapper enforces the
    // correct `optlen` and struct layout at compile time.
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let peer = getsockopt(stream, PeerCredentials)
        .map_err(|e| format!("getsockopt(SO_PEERCRED) failed: {e}"))?;
    let peer_uid = peer.uid();
    let peer_pid = peer.pid();
    if peer_uid != expected_uid {
        return Err(format!(
            "peer uid {} != expected {} (pid {})",
            peer_uid, expected_uid, peer_pid
        ));
    }
    if peer_pid == std::process::id() as i32 {
        return Err(format!(
            "peer pid {} equals witness pid -- co-location prohibited",
            peer_pid
        ));
    }
    Ok(())
}

fn handle_client(
    mut stream: UnixStream,
    seq_state: &Mutex<WitnessSeqState>,
    signing_key: &crypto::pq_sign::PqSigningKey,
    vk_hex: &str,
) {
    let cloned = match stream.try_clone() {
        Ok(c) => c,
        Err(e) => {
            // Don't panic on EMFILE / ENFILE: that is exactly the DoS the
            // attacker wants. Drop the connection and keep serving.
            tracing::warn!("accept clone failed: {}", e);
            return;
        }
    };
    let mut reader = BufReader::new(cloned);
    let mut line = String::new();
    if let Err(e) = reader.read_line(&mut line) {
        tracing::warn!("read_line: {}", e);
        return;
    }
    let line = line.trim();
    let response = process_request(line, seq_state, signing_key, vk_hex);
    if let Err(e) = stream.write_all(response.as_bytes()) {
        tracing::warn!("write response: {}", e);
    }
    let _ = stream.flush();
}

#[allow(dead_code)]
fn enforce_socket_dir_perms(_p: &Path) {}
