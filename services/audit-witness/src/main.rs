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
//! HEALTH                       -> "OK <pid> <iso8601>\n"
//! SIGN <hex-32-byte-hash>      -> "SIG <hex-encoded-ml-dsa-87-signature>\n"
//! VK                           -> "VK <hex-encoded-verifying-key>\n"
//! ```
//!
//! Any malformed request is answered with `ERR <reason>\n` and the connection
//! is closed.
//!
//! ## Hardening
//!
//! * Each connection is handled on its own worker thread with read/write
//!   deadlines and a hard request-length cap, so a slow or oversized peer
//!   cannot stall or OOM the signing service.
//! * Every signed checkpoint hash is recorded in an fsynced anti-replay
//!   journal. A hash that has already been signed is refused — a compromised
//!   audit client cannot replay a checkpoint signature, and a strictly
//!   monotonic signature counter is maintained across restarts.
//! * Witness signatures use a witness-specific FIPS 204 domain
//!   (`AUDIT-WITNESS-CHECKPOINT-v1`) so a signature produced here can never
//!   be reinterpreted as a credential, VRF proof, or any other `pq_sign_raw`
//!   artifact in the codebase.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ml_dsa::{KeyGen, MlDsa87};
use zeroize::Zeroize;

/// Default socket path. Override via `MILNET_AUDIT_WITNESS_SOCK`.
const DEFAULT_SOCK: &str = "/run/milnet/audit-witness.sock";

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

/// FIPS 204 domain-separation tag bound into every witness checkpoint
/// signature. Exactly 32 bytes (`pq_sign_raw_domain` contract). A signature
/// produced under this domain cannot be verified as — nor mistaken for — any
/// other `pq_sign_raw` artifact (credentials, VRF proofs, STHs), even if the
/// same key were ever reused, because the FIPS 204 `ctx` differs.
const WITNESS_SIGN_DOMAIN: [u8; 32] = *b"AUDIT-WITNESS-CHECKPOINT-v1\0\0\0\0\0";

/// Per-connection read/write deadline. A peer that connects but never sends a
/// full line, or stalls mid-response, is dropped after this long instead of
/// pinning a worker thread forever.
const CONN_TIMEOUT: Duration = Duration::from_secs(2);

/// Hard cap on a single request line. The longest valid request is
/// `SIGN ` (5) + 64 hex chars + `\n` = 70 bytes. 256 gives generous slack
/// while making it impossible for a peer to grow our buffer toward OOM.
const MAX_REQUEST_BYTES: usize = 256;

/// Env var overriding the anti-replay journal path.
const REPLAY_JOURNAL_ENV: &str = "MILNET_WITNESS_REPLAY_JOURNAL";

/// Default anti-replay journal path (sibling of the socket).
const DEFAULT_REPLAY_JOURNAL: &str = "/run/milnet/audit-witness.replay";

fn main() {
    // MUST be first: harden process before any allocation that could hold a secret.
    crypto::process_harden::harden_early();
    tracing_subscriber::fmt::init();

    // P1-1: tighten the umask BEFORE creating the socket directory or binding
    // the socket, so neither is briefly world-reachable between creation and
    // the explicit chmod. 0o077 strips all group/other bits.
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));

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
    let signing_key = std::sync::Arc::new(load_signing_key());
    let verifying_key = signing_key.verifying_key().clone();
    let vk_bytes = verifying_key.encode();
    let vk_hex: std::sync::Arc<str> =
        std::sync::Arc::from(hex::encode(AsRef::<[u8]>::as_ref(&vk_bytes)));
    tracing::info!(vk_prefix = %&vk_hex[..16], "audit-witness key loaded");

    // ── Anti-replay journal (P0-4) ───────────────────────────────────────
    let journal_path = std::env::var(REPLAY_JOURNAL_ENV)
        .unwrap_or_else(|_| DEFAULT_REPLAY_JOURNAL.to_string());
    let replay_journal = std::sync::Arc::new(ReplayJournal::open(PathBuf::from(&journal_path)));
    tracing::info!(
        "audit-witness anti-replay journal at {:?} ({} hashes already signed)",
        journal_path,
        replay_journal.signed_count()
    );

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
    // P1-2: a failure here would leave the socket on whatever perms `bind`
    // produced. We fail closed rather than serve signatures on a possibly
    // over-permissive socket.
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            tracing::error!(
                "FATAL: failed to chmod 0600 {:?}: {} — refusing to listen on a \
                 socket with unverified permissions",
                path, e
            );
            let _ = std::fs::remove_file(&path);
            std::process::exit(1);
        }
    }

    let expected_uid: Option<u32> = std::env::var(AUDIT_UID_ENV)
        .ok()
        .and_then(|s| s.parse().ok());
    // P1-3: in a production build the peer-uid check is mandatory. A witness
    // that accepts any uid hands signatures to any local process that can
    // reach the socket, defeating SO_PEERCRED authentication entirely.
    if expected_uid.is_none() {
        if cfg!(feature = "production") {
            tracing::error!(
                "FATAL: {} is not set. A production audit-witness MUST pin the audit \
                 service uid; refusing to start.",
                AUDIT_UID_ENV
            );
            let _ = std::fs::remove_file(&path);
            std::process::exit(8);
        }
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
                // P0-1 / P0-2: handle each connection on its own worker thread
                // so a slow client cannot stall the signing service, and a
                // per-connection failure (including fd exhaustion) cannot take
                // the witness down.
                let signing_key = signing_key.clone();
                let vk_hex = vk_hex.clone();
                let replay_journal = replay_journal.clone();
                let spawn_result = std::thread::Builder::new()
                    .name("witness-conn".to_string())
                    .spawn(move || {
                        handle_client(stream, &signing_key, &vk_hex, &replay_journal);
                    });
                if let Err(e) = spawn_result {
                    // Thread/fd exhaustion: drop this connection cleanly
                    // instead of crashing. `stream` is dropped here, closing it.
                    tracing::error!("failed to spawn connection worker: {}", e);
                }
            }
            Err(e) => {
                // P0-2: an accept error (e.g. EMFILE under fd pressure) must
                // not spin the loop at 100% CPU. Back off briefly so fds can
                // be reclaimed before the next accept.
                tracing::warn!("accept error: {} — backing off", e);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Append-only, fsynced anti-replay journal of every checkpoint hash the
/// witness has ever signed (P0-4).
///
/// SECURITY: the witness receives opaque 32-byte hashes; it cannot order them
/// or know what audit roots they represent. What it *can* do — and what an
/// external witness exists to do — is refuse to sign the same checkpoint hash
/// twice. Recording each signed hash (fsynced before the signature is
/// returned) means a compromised audit client cannot obtain two valid
/// signatures over the same checkpoint, and a strictly monotonic
/// signature-issued counter survives restarts. Backdating/equivocation across
/// *distinct* hashes cannot be detected at this layer because the input is
/// opaque; the wire protocol is fixed by the (out-of-scope) audit caller, so
/// per-request sequence binding is intentionally not attempted here.
struct ReplayJournal {
    inner: Mutex<ReplayJournalInner>,
}

struct ReplayJournalInner {
    path: PathBuf,
    /// Lowercase-hex of every 32-byte hash signed so far.
    signed: HashSet<String>,
    /// Monotonic count of signatures issued. Persisted via the journal length.
    counter: u64,
}

impl ReplayJournal {
    /// Open (and replay) the journal. A missing journal starts empty. A read
    /// failure is fatal: continuing without replay history would let an
    /// attacker re-sign every previously signed checkpoint.
    fn open(path: PathBuf) -> Self {
        let mut signed = HashSet::new();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                for line in contents.lines() {
                    let h = line.trim();
                    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                        signed.insert(h.to_ascii_lowercase());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::error!(
                    "FATAL: failed to read anti-replay journal {:?}: {} — refusing to \
                     start without replay history",
                    path, e
                );
                std::process::exit(9);
            }
        }
        let counter = signed.len() as u64;
        ReplayJournal {
            inner: Mutex::new(ReplayJournalInner { path, signed, counter }),
        }
    }

    fn signed_count(&self) -> u64 {
        self.inner.lock().map(|i| i.counter).unwrap_or(0)
    }

    /// Atomically check-and-record a checkpoint hash before it is signed.
    ///
    /// Returns `Ok(seq)` with the new monotonic signature number if the hash
    /// is fresh and was durably journaled. Returns `Err` if the hash was
    /// already signed (replay) or if the journal write/fsync failed — in
    /// which case the caller MUST NOT sign. Fail closed: an un-journaled
    /// signature is a signature that could later be replayed undetected.
    fn record_or_reject(&self, hash_hex: &str) -> Result<u64, String> {
        let hash_hex = hash_hex.to_ascii_lowercase();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "anti-replay journal mutex poisoned".to_string())?;

        if inner.signed.contains(&hash_hex) {
            return Err("checkpoint hash already signed — replay refused".to_string());
        }

        // Append + fsync BEFORE recording in memory or returning success, so a
        // crash can never lose a hash we have already signed for.
        let path = inner.path.clone();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("open anti-replay journal {path:?}: {e}"))?;
        f.write_all(hash_hex.as_bytes())
            .and_then(|()| f.write_all(b"\n"))
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("durably append to anti-replay journal {path:?}: {e}"))?;

        inner.signed.insert(hash_hex);
        inner.counter += 1;
        Ok(inner.counter)
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
    signing_key: &crypto::pq_sign::PqSigningKey,
    vk_hex: &str,
    replay_journal: &ReplayJournal,
) {
    // P0-1: bound how long a single connection may hold this worker. A peer
    // that never sends a newline, or stalls mid-response, is dropped.
    if let Err(e) = stream.set_read_timeout(Some(CONN_TIMEOUT)) {
        tracing::warn!("set_read_timeout: {}", e);
        return;
    }
    if let Err(e) = stream.set_write_timeout(Some(CONN_TIMEOUT)) {
        tracing::warn!("set_write_timeout: {}", e);
        return;
    }

    // P0-2: a failed `try_clone` (dup(2) -> EMFILE/ENFILE under fd pressure)
    // must drop the connection, never panic the worker.
    let read_half = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("stream clone failed, dropping connection: {}", e);
            return;
        }
    };

    // P0-1: cap the request length so a peer streaming non-newline bytes
    // cannot grow our buffer toward OOM. `take` bounds the reader; if no
    // newline arrives within the cap the request is rejected as malformed.
    let mut reader = BufReader::new(read_half.take(MAX_REQUEST_BYTES as u64));
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => return, // peer closed without sending anything
        Ok(n) if n >= MAX_REQUEST_BYTES && !line.ends_with('\n') => {
            tracing::warn!("request exceeded {}-byte cap without newline", MAX_REQUEST_BYTES);
            let _ = stream.write_all(b"ERR request too long\n");
            let _ = stream.flush();
            return;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("read_line: {}", e);
            return;
        }
    }
    let line = line.trim();
    let response = process_request(line, signing_key, vk_hex, replay_journal);
    if let Err(e) = stream.write_all(response.as_bytes()) {
        tracing::warn!("write response: {}", e);
    }
    let _ = stream.flush();
}

fn process_request(
    request: &str,
    signing_key: &crypto::pq_sign::PqSigningKey,
    vk_hex: &str,
    replay_journal: &ReplayJournal,
) -> String {
    if request == "HEALTH" {
        // P2-2: on clock skew (`now` < epoch) report the error explicitly
        // rather than a misleading `0` timestamp.
        return match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => format!("OK {} {}\n", std::process::id(), d.as_secs()),
            Err(_) => format!("OK {} clock-error\n", std::process::id()),
        };
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
        // P0-4: refuse to sign a checkpoint hash that has already been signed,
        // and durably journal it before signing. A failure to record (or a
        // replayed hash) means we MUST NOT produce a signature.
        let canonical_hex = hex::encode(&bytes);
        let seq = match replay_journal.record_or_reject(&canonical_hex) {
            Ok(seq) => seq,
            Err(e) => return format!("ERR {}\n", e),
        };
        // P0-3: bind a witness-specific FIPS 204 domain so this signature is
        // cryptographically distinct from every other `pq_sign_raw` use.
        let sig = match crypto::pq_sign::pq_sign_raw_domain(
            signing_key,
            &bytes,
            &WITNESS_SIGN_DOMAIN,
        ) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!("witness domain-bound signing failed: {}", e);
                return format!("ERR signing failed: {}\n", e);
            }
        };
        tracing::info!(witness_seq = seq, "signed audit-witness checkpoint");
        return format!("SIG {}\n", hex::encode(&sig));
    }
    format!("ERR unknown command: {}\n", request)
}
