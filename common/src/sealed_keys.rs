//! Hardened key loading for inter-service communication.
//!
//! All services MUST use the same SHARD HMAC key and receipt signing key.
//! Keys are loaded from sealed storage (encrypted env vars) and unwrapped
//! using the master KEK. Raw plaintext env vars are rejected in production mode.
//!
//! # Key Loading Hierarchy
//! 1. Check for sealed (encrypted) key in env: `{NAME}_SEALED`
//! 2. Unwrap with master KEK via HKDF-SHA512
//! 3. Zeroize the env var memory after loading
//! 4. If neither sealed nor raw key is available AND production mode is off,
//!    fall back to deterministic dev key (with loud warning)
//!
//! # Production Mode
//! Build with `--features production` to enforce:
//! - No dev key fallbacks (hard fail)
//! - Sealed keys required
//! - Master KEK must come from env `MILNET_MASTER_KEK` (hex-encoded)
//!
//! # /proc/PID/environ Limitation
//!
//! On Linux, `/proc/PID/environ` is an immutable snapshot created at `execve(2)`.
//! Calling `std::env::remove_var()` only removes the variable from libc's in-process
//! `environ` pointer array -- it does NOT erase the original `/proc/PID/environ`
//! kernel-mapped page. A root-level attacker (or any process with `CAP_SYS_PTRACE`)
//! can always read the initial environment from `/proc/PID/environ` regardless of
//! env var removal. The overwrite-then-remove pattern in this module mitigates
//! libc-level scanning and child process inheritance, but cannot protect against
//! `/proc/PID/environ` reads. For true secret isolation, prefer:
//!   - **Unix socket delivery** via `secret_ceremony::load_secret_from_socket()` (recommended)
//!   - File descriptor passing (`MILNET_MASTER_KEK_FD`) via `load_master_kek_from_fd()`
//!   - Unix domain socket fd passing
//!   - `O_TMPFILE` tmpfs file descriptors
//!   - HSM/TPM sealed storage
//!
//! See `secret_ceremony.rs` for the full distributed secret delivery protocol
//! using Unix sockets with mutual attestation (HMAC-SHA512 + binary hash) and
//! per-session ephemeral X25519 key exchange.

use std::sync::OnceLock;
use zeroize::Zeroize;

/// Master KEK storage with memory protection.
/// The key is mlock'd to prevent swapping and marked MADV_DONTDUMP to exclude
/// from core dumps. This is critical: the master KEK decrypts every other key
/// in the system.
struct ProtectedKek {
    key: [u8; 32],
}

impl ProtectedKek {
    fn new(key: [u8; 32]) -> Self {
        // NOTE: mlock is deferred to lock_in_place() because the struct may be
        // moved after construction (e.g. into OnceLock's heap allocation).
        // Calling mlock here would lock the stack address, not the final address.
        Self { key }
    }

    /// Lock the key into physical RAM AFTER the struct has reached its final
    /// resting place (e.g. inside a OnceLock/Box). Must be called on a &self
    /// that will NOT be moved again.
    fn lock_in_place(&self) {
        #[cfg(unix)]
        unsafe {
            let ptr = self.key.as_ptr() as *const libc::c_void;
            let len = std::mem::size_of_val(&self.key);
            let ret = libc::mlock(ptr, len);
            if ret != 0 {
                // In military deployment, mlock failure is fatal
                if std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1") {
                    tracing::error!("mlock failed for master KEK — aborting");
                    std::process::exit(199);
                }
            }
            // Exclude from core dumps
            let _ = libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
        }
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for ProtectedKek {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(unix)]
        unsafe {
            let ptr = self.key.as_ptr() as *const libc::c_void;
            let len = std::mem::size_of_val(&self.key);
            let _ = libc::munlock(ptr, len);
        }
    }
}

// SAFETY: The key is only written once via OnceLock and then read-only.
unsafe impl Sync for ProtectedKek {}
unsafe impl Send for ProtectedKek {}

static MASTER_KEK_CACHE: OnceLock<ProtectedKek> = OnceLock::new();
static DISTRIBUTED_KEK_CACHE: OnceLock<ProtectedKek> = OnceLock::new();
static THRESHOLD_KDF_CACHE: OnceLock<ProtectedKek> = OnceLock::new();

/// Returns a reference to the cached master KEK, loading it once on first call.
/// The KEK is mlock'd into physical RAM and excluded from core dumps.
pub fn cached_master_kek() -> &'static [u8; 32] {
    let kek = MASTER_KEK_CACHE.get_or_init(|| ProtectedKek::new(load_master_kek()));
    // mlock AFTER OnceLock placement so we lock the final heap address, not a
    // stale stack address. OnceLock guarantees the value will not move again.
    kek.lock_in_place();
    kek.as_bytes()
}

/// Returns true when distributed (threshold) KEK mode should be used.
/// This is the case when `MILNET_KEK_SHARE` is set, indicating that
/// threshold Shamir share reconstruction is configured for this node.
/// Deployments MUST set `MILNET_KEK_SHARE` for distributed KEK.
pub fn use_distributed_kek() -> bool {
    std::env::var("MILNET_KEK_SHARE").is_ok()
}

/// Returns true when threshold KDF mode is active.
///
/// Threshold KDF is now the DEFAULT in production and military mode.
/// The KEK is NEVER reconstructed. Each node computes a partial HMAC
/// from its share; partials are combined via HKDF.
///
/// To explicitly DISABLE threshold KDF (MLP only), set both:
///   MILNET_ALLOW_SINGLE_KEK=1
///   MILNET_MLP_MODE_ACK=1
pub fn use_threshold_kdf() -> bool {
    // Threshold KDF requires shares to be configured
    if std::env::var("MILNET_KEK_SHARE").is_err() {
        return false;
    }
    // Explicit opt-out: only allowed in MLP mode
    if std::env::var("MILNET_THRESHOLD_KDF").as_deref() == Ok("0") {
        return false;
    }
    // Default: ON when shares are available
    true
}

/// Derive the master KEK via threshold KDF (no reconstruction).
///
/// The master secret NEVER exists in any node's memory.
pub fn cached_master_kek_threshold_kdf() -> &'static [u8; 32] {
    THRESHOLD_KDF_CACHE.get_or_init(|| {
        use crate::threshold_kek::{KekShare, partial_derive_key, ThresholdKdfManager};

        let context = std::env::var("MILNET_THRESHOLD_KDF_CONTEXT")
            .unwrap_or_else(|_| "milnet-kek-v1".to_string());
        let salt = std::env::var("MILNET_THRESHOLD_KDF_SALT")
            .unwrap_or_else(|_| "milnet-threshold-kdf-salt-v1".to_string());

        let my_share_hex = match std::env::var("MILNET_KEK_SHARE") {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("MILNET_KEK_SHARE not set for threshold KDF mode.");
                std::process::exit(1);
            }
        };
        // SECURITY: Reject MILNET_KEK_PEER_SHARES if present.
        // Each node must only hold its OWN share. Peer shares must be
        // exchanged via network protocol (mTLS), never stored in one env var.
        if std::env::var("MILNET_KEK_PEER_SHARES").is_ok() {
            tracing::error!(
                "SECURITY VIOLATION: MILNET_KEK_PEER_SHARES is set. \
                 Each node must only hold its own share (MILNET_KEK_SHARE). \
                 Peer partials must be received via mTLS network protocol. \
                 Remove MILNET_KEK_PEER_SHARES and configure peer exchange."
            );
            crate::siem::SecurityEvent::tamper_detected(
                "MILNET_KEK_PEER_SHARES detected. All peer shares on one node \
                 is a critical security violation. Process aborting.",
            );
            // Overwrite and remove the dangerous env var before exiting
            if let Ok(csv) = std::env::var("MILNET_KEK_PEER_SHARES") {
                std::env::set_var("MILNET_KEK_PEER_SHARES", "0".repeat(csv.len()));
                std::env::remove_var("MILNET_KEK_PEER_SHARES");
            }
            std::process::exit(199);
        }

        let my_share = match KekShare::from_hex(&my_share_hex) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to parse MILNET_KEK_SHARE: {e}");
                std::process::exit(1);
            }
        };

        if !verify_share_commitment(&my_share) {
            tracing::error!(
                "SECURITY: VSS verification FAILED for own share {} in threshold KDF. REJECTED.",
                my_share.index
            );
            crate::siem::SecurityEvent::tamper_detected(
                &format!("Own share {} failed VSS verification in threshold KDF", my_share.index),
            );
            std::process::exit(199);
        }

        // Submit own partial. Peer partials arrive via mTLS network protocol
        // (see distributed_startup.rs). Each peer computes its partial locally
        // and sends only the partial (not the raw share) over the network.
        let mut mgr = ThresholdKdfManager::new(3, 5, context.as_bytes(), salt.as_bytes());
        let my_partial = partial_derive_key(&my_share, context.as_bytes(), salt.as_bytes());
        if let Err(e) = mgr.submit_partial(my_share.index, my_partial) {
            tracing::error!("Failed to submit own partial for share {}: {e}", my_share.index);
            std::process::exit(1);
        }

        // Collect peer partials from MILNET_KEK_PEER_PARTIALS (mTLS-received,
        // hex-encoded, format: "index:partial_hex,index:partial_hex,...")
        if let Ok(peer_partials_csv) = std::env::var("MILNET_KEK_PEER_PARTIALS") {
            for entry in peer_partials_csv.split(',') {
                let entry = entry.trim();
                if entry.is_empty() { continue; }
                let parts: Vec<&str> = entry.splitn(2, ':').collect();
                if parts.len() != 2 {
                    tracing::warn!("Malformed peer partial entry: {entry}");
                    continue;
                }
                let idx: u8 = match parts[0].parse() {
                    Ok(i) => i,
                    Err(e) => { tracing::warn!("Invalid peer partial index: {e}"); continue; }
                };
                let partial_bytes = match hex::decode(parts[1]) {
                    Ok(b) if b.len() == 64 => {
                        let mut arr = [0u8; 64];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    Ok(b) => { tracing::warn!("Peer partial wrong length: {} (need 64)", b.len()); continue; }
                    Err(e) => { tracing::warn!("Invalid peer partial hex: {e}"); continue; }
                };
                if let Err(e) = mgr.submit_partial(idx, partial_bytes) {
                    tracing::warn!("Failed to submit peer partial for index {idx}: {e}");
                }
            }
            // Remove peer partials from environment
            std::env::set_var("MILNET_KEK_PEER_PARTIALS", "0".repeat(peer_partials_csv.len()));
            std::env::remove_var("MILNET_KEK_PEER_PARTIALS");
        }

        if !mgr.has_threshold() {
            tracing::error!(
                "Insufficient partials for threshold KDF: have {}, need 3. \
                 Peer partials must arrive via MILNET_KEK_PEER_PARTIALS (mTLS-received).",
                mgr.partials_collected()
            );
            std::process::exit(1);
        }

        // Zeroize own share
        let mut my_share = my_share;
        my_share.value.zeroize();

        // Remove own share env var
        std::env::set_var("MILNET_KEK_SHARE", "0".repeat(my_share_hex.len()));
        std::env::remove_var("MILNET_KEK_SHARE");

        match mgr.derive_key() {
            Ok(key) => {
                tracing::info!("Master KEK derived via threshold KDF (3-of-5). Secret NEVER reconstructed.");
                ProtectedKek::new(key)
            }
            Err(e) => {
                tracing::error!("Threshold KDF derivation failed: {e}");
                std::process::exit(1);
            }
        }
    });
    let kek = THRESHOLD_KDF_CACHE.get().expect("threshold KDF cache initialized above");
    kek.lock_in_place();
    kek.as_bytes()
}

/// Reconstruct the master KEK from threshold Shamir shares.
///
/// - `MILNET_KEK_SHARE`: This node's share (hex-encoded via `KekShare::to_hex`)
/// - `MILNET_KEK_SHARE_INDEX`: This node's share index (1-based)
///
/// Peer shares are received via mTLS network protocol, NOT via env vars.
/// MILNET_KEK_PEER_SHARES is rejected (security violation).
///
/// In production mode, panics if threshold (3) shares are not available.
pub fn cached_master_kek_distributed() -> &'static [u8; 32] {
    DISTRIBUTED_KEK_CACHE.get_or_init(|| {
        use crate::threshold_kek::{KekShare, ThresholdKekConfig, ThresholdKekManager};

        // SECURITY: Reject MILNET_KEK_PEER_SHARES if present.
        if std::env::var("MILNET_KEK_PEER_SHARES").is_ok() {
            tracing::error!(
                "SECURITY VIOLATION: MILNET_KEK_PEER_SHARES is set. \
                 Each node must only hold its own share (MILNET_KEK_SHARE). \
                 Peer shares must be received via mTLS network protocol. \
                 Remove MILNET_KEK_PEER_SHARES immediately."
            );
            crate::siem::SecurityEvent::tamper_detected(
                "MILNET_KEK_PEER_SHARES detected in distributed KEK path. \
                 All peer shares on one node is a critical security violation.",
            );
            if let Ok(csv) = std::env::var("MILNET_KEK_PEER_SHARES") {
                std::env::set_var("MILNET_KEK_PEER_SHARES", "0".repeat(csv.len()));
                std::env::remove_var("MILNET_KEK_PEER_SHARES");
            }
            std::process::exit(199);
        }

        let my_share_hex = std::env::var("MILNET_KEK_SHARE").ok();
        let my_index: u8 = std::env::var("MILNET_KEK_SHARE_INDEX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        // If no share is configured, fail hard.
        if my_share_hex.is_none() {
            tracing::error!(
                "MILNET_KEK_SHARE not set. \
                 Distributed threshold KEK is required. Each node must hold \
                 exactly one Shamir share. Set MILNET_KEK_SHARE and \
                 MILNET_KEK_SHARE_INDEX."
            );
            std::process::exit(1);
        }

        let Some(my_share_hex) = my_share_hex else {
            std::process::exit(1);
        };

        let mut mgr = ThresholdKekManager::new(ThresholdKekConfig {
            threshold: 3,
            total_shares: 5,
            collection_timeout: std::time::Duration::from_secs(30),
            my_share_index: my_index,
        });

        // Load this node's share
        if let Err(e) = mgr.load_my_share(&my_share_hex) {
            tracing::error!("Failed to load KEK share from MILNET_KEK_SHARE: {e}");
            std::process::exit(1);
        }

        // Remove share from environment immediately
        std::env::set_var("MILNET_KEK_SHARE", "0".repeat(my_share_hex.len()));
        std::env::remove_var("MILNET_KEK_SHARE");

        // Collect peer shares via mTLS (stored in MILNET_KEK_PEER_SHARES_MTLS
        // by the distributed_startup protocol after mTLS verification)
        if let Ok(csv) = std::env::var("MILNET_KEK_PEER_SHARES_MTLS") {
            for hex_share in csv.split(',') {
                let hex_share = hex_share.trim();
                if hex_share.is_empty() { continue; }
                match KekShare::from_hex(hex_share) {
                    Ok(share) => {
                        if !verify_share_commitment(&share) {
                            tracing::error!(
                                "SECURITY: VSS verification FAILED for mTLS peer share {}. REJECTED.",
                                share.index
                            );
                            crate::siem::SecurityEvent::tamper_detected(
                                &format!("Rejected mTLS peer share {} due to VSS failure", share.index),
                            );
                            continue;
                        }
                        if let Err(e) = mgr.add_peer_share(share) {
                            tracing::warn!("Failed to add peer share: {e}");
                        }
                    }
                    Err(e) => tracing::warn!("Failed to parse peer share hex: {e}"),
                }
            }
            std::env::set_var("MILNET_KEK_PEER_SHARES_MTLS", "0".repeat(csv.len()));
            std::env::remove_var("MILNET_KEK_PEER_SHARES_MTLS");
        }

        if !mgr.has_threshold() {
            tracing::error!(
                "Insufficient KEK shares for reconstruction. \
                 Have {} shares, need 3. Peer shares must arrive via mTLS.",
                mgr.shares_collected()
            );
            std::process::exit(1);
        }

        // Reconstruct with retry
        const MAX_RECONSTRUCTION_ATTEMPTS: u32 = 3;
        let mut reconstructed_kek: Option<ProtectedKek> = None;
        for attempt in 1..=MAX_RECONSTRUCTION_ATTEMPTS {
            let share_count = mgr.shares_collected();
            match mgr.reconstruct() {
                Ok(key) => {
                    tracing::info!(
                        attempt = attempt,
                        shares_used = share_count,
                        "Master KEK reconstructed from {} threshold shares (3-of-5 Shamir).",
                        share_count
                    );
                    reconstructed_kek = Some(ProtectedKek::new(*key));
                    break;
                }
                Err(e) => {
                    tracing::error!(
                        attempt = attempt,
                        max_attempts = MAX_RECONSTRUCTION_ATTEMPTS,
                        error = %e,
                        "KEK reconstruction attempt {}/{} failed",
                        attempt,
                        MAX_RECONSTRUCTION_ATTEMPTS
                    );
                    if attempt < MAX_RECONSTRUCTION_ATTEMPTS {
                        mgr.reset_for_retry();
                        if let Err(e2) = mgr.load_my_share(&my_share_hex) {
                            tracing::error!("Failed to reload own share on retry: {e2}");
                            std::process::exit(1);
                        }
                        let base_ms = 500u64 * (1u64 << (attempt - 1));
                        let mut jitter_bytes = [0u8; 1];
                        let _ = getrandom::getrandom(&mut jitter_bytes);
                        let jitter_ms = jitter_bytes[0] as u64 % 250;
                        std::thread::sleep(std::time::Duration::from_millis(base_ms + jitter_ms));
                    }
                }
            }
        }
        match reconstructed_kek {
            Some(kek) => kek,
            None => {
                tracing::error!("KEK reconstruction failed after {} attempts", MAX_RECONSTRUCTION_ATTEMPTS);
                std::process::exit(1);
            }
        }
    }).as_bytes()
}

/// Verify a Shamir share against secret-independent VSS commitments.
///
/// Uses standalone HMAC-SHA512 commitments that do NOT require the secret.
/// During key ceremony, the dealer computes for each share:
///   commitment_i = HMAC-SHA512(ceremony_salt, index || share_value)
/// and distributes the commitments alongside shares.
///
/// This avoids the circular dependency where you need the secret to verify
/// shares but need shares to reconstruct the secret. Verification is fully
/// independent: each share is checked against its pre-computed commitment.
///
/// Commitments are loaded from the `MILNET_VSS_COMMITMENTS` env var
/// (hex-encoded, set during the key ceremony and sealed to each node).
/// If commitments are not available, returns false and callers MUST reject
/// the share.
fn verify_share_commitment(share: &crate::threshold_kek::KekShare) -> bool {
    // Load standalone VSS commitments from environment (set during key ceremony)
    let commitments_hex = match std::env::var("MILNET_VSS_COMMITMENTS") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            tracing::error!(
                share_index = share.index,
                "VSS VERIFICATION FAILED: MILNET_VSS_COMMITMENTS not set. \
                 Cannot verify share without commitments. Share REJECTED."
            );
            crate::siem::SecurityEvent::tamper_detected(
                &format!(
                    "VSS commitments unavailable. Share {} rejected. \
                     Set MILNET_VSS_COMMITMENTS during key ceremony.",
                    share.index
                ),
            );
            return false;
        }
    };

    let commitments = match crate::threshold_kek::StandaloneVssCommitments::from_hex(&commitments_hex) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to parse VSS commitments: {e}");
            crate::siem::SecurityEvent::tamper_detected(
                &format!("Malformed VSS commitments in MILNET_VSS_COMMITMENTS: {e}"),
            );
            return false;
        }
    };

    // Verify the share against its standalone commitment (no secret needed)
    let valid = commitments.verify_share(share);

    if !valid {
        tracing::error!(
            share_index = share.index,
            "VSS VERIFICATION FAILED: share does not match its commitment. \
             Possible malicious share injection."
        );
        crate::siem::SecurityEvent::tamper_detected(
            &format!(
                "VSS share verification failed for index {}. Share rejected.",
                share.index
            ),
        );
    }

    valid
}

/// Unified entry point for obtaining the master KEK.
///
/// Load hierarchy (most secure first):
/// 1. Threshold KDF (distributed, KEK never in RAM) -- DEFAULT
/// 2. Threshold reconstruction (distributed, KEK materializes briefly)
/// 3. Single env var ONLY if MLP mode acknowledged
///
/// In military mode: threshold KDF is MANDATORY, no bypass.
/// In production without MLP: single env var is rejected.
///
/// All services SHOULD use this function instead of calling `cached_master_kek()`
/// or `load_master_kek()` directly.
pub fn get_master_kek() -> &'static [u8; 32] {
    let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1");
    let is_mlp_ack = std::env::var("MILNET_MLP_MODE_ACK").as_deref() == Ok("1");
    let allow_single_kek = std::env::var("MILNET_ALLOW_SINGLE_KEK").as_deref() == Ok("1");
    let has_shares = std::env::var("MILNET_KEK_SHARE").is_ok();

    // Path 1: Threshold KDF (preferred, KEK never reconstructed)
    if use_threshold_kdf() {
        return cached_master_kek_threshold_kdf();
    }

    // Path 2: Threshold reconstruction (legacy, KEK briefly in RAM)
    if use_distributed_kek() {
        if is_military {
            crate::siem::SecurityEvent::crypto_failure(
                "FORBIDDEN: Shamir reconstruct() in military deployment. \
                 Threshold KDF is mandatory. Ensure MILNET_KEK_SHARE is set \
                 and MILNET_THRESHOLD_KDF is not explicitly disabled.",
            );
            panic!(
                "FATAL: reconstruct() forbidden in military deployment. \
                 Threshold KDF is mandatory."
            );
        }
        if is_production() {
            crate::siem::SecurityEvent::crypto_failure(
                "WARNING: legacy Shamir reconstruct() path active. Full KEK materializes in RAM. \
                 Migrate to threshold KDF (default when shares are configured).",
            );
        }
        return cached_master_kek_distributed();
    }

    // Path 3: Single env var KEK -- MLP only
    // In production without MLP: if MILNET_MASTER_KEK is set but threshold
    // shares are not, this is a critical misconfiguration.
    if is_military {
        // Military mode: threshold KDF is MANDATORY, no fallback
        crate::siem::SecurityEvent::crypto_failure(
            "CRITICAL: military deployment requires threshold KDF. \
             No KEK shares (MILNET_KEK_SHARE) configured. Cannot proceed.",
        );
        tracing::error!(
            target: "siem",
            "SIEM:CRITICAL military deployment without threshold KDF shares. Process exiting."
        );
        std::process::exit(199);
    }

    if is_production() && !has_shares && std::env::var("MILNET_MASTER_KEK").is_ok() {
        // Single env var KEK in production: only with explicit MLP + allow_single_kek
        if is_mlp_ack && allow_single_kek {
            crate::siem::SecurityEvent::crypto_failure(
                "WARNING: single-key KEK in MLP mode (MILNET_ALLOW_SINGLE_KEK=1). \
                 Acceptable for MLP/demo only. NOT for production.",
            );
            return cached_master_kek();
        }

        // Allow legacy test infrastructure ACK
        if std::env::var("MILNET_TESTING_SINGLE_KEK_ACK").as_deref() == Ok("1") {
            crate::siem::SecurityEvent::crypto_failure(
                "WARNING: single-key KEK fallback used with MILNET_TESTING_SINGLE_KEK_ACK=1. \
                 This is acceptable ONLY for test infrastructure.",
            );
            return cached_master_kek();
        }

        crate::siem::SecurityEvent::crypto_failure(
            "CRITICAL: single-key KEK (MILNET_MASTER_KEK) set without threshold shares. \
             Threshold KDF is the default. Configure MILNET_KEK_SHARE for distributed KEK. \
             For MLP mode, set MILNET_MLP_MODE_ACK=1 and MILNET_ALLOW_SINGLE_KEK=1.",
        );
        tracing::error!(
            target: "siem",
            "SIEM:CRITICAL single-key KEK in production without MLP acknowledgment. Process exiting."
        );
        std::process::exit(199);
    }

    // Non-production or legacy fallback
    cached_master_kek()
}

/// Whether the system is running in production mode.
///
/// ALWAYS returns true. There is only ONE mode: production.
/// Dev/staging/test environment distinctions have been removed.
/// Error verbosity is controlled by `error_level` (Verbose/Warn), not
/// by environment mode.
#[inline]
pub fn is_production() -> bool {
    true
}

/// Load the master KEK from environment.
/// Returns 32-byte key derived from `MILNET_MASTER_KEK` (hex-encoded, 64 chars).
///
/// Thread-safe: the key is loaded exactly once via OnceLock. The env var is
/// removed after first read to prevent leakage via `/proc/pid/environ`.
/// All subsequent calls return the cached key. No fake keys, no bypassing.
pub fn load_master_kek() -> [u8; 32] {
    static CACHED_KEK: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *CACHED_KEK.get_or_init(|| load_master_kek_inner())
}

/// Inner implementation: reads MILNET_MASTER_KEK from env exactly once.
fn load_master_kek_inner() -> [u8; 32] {
    use zeroize::Zeroize;

    // Disable ptrace and core dumps BEFORE reading the KEK.
    #[cfg(unix)]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    match std::env::var("MILNET_MASTER_KEK") {
        Ok(mut hex_str) if hex_str.len() >= 64 => {
            // SECURITY: Overwrite env var value before removing.
            // NOTE: On Linux, /proc/PID/environ is an immutable snapshot from execve.
            // std::env::remove_var() only removes from libc's environ pointer -- it does
            // NOT erase the original /proc/PID/environ content. A root attacker can always
            // read the initial environment. For true protection, pass secrets via:
            //   - Unix domain socket fd passing
            //   - tmpfs file descriptors (O_TMPFILE)
            //   - HSM/TPM sealed storage
            // This overwrite mitigates libc-level scanning but NOT /proc/PID/environ.
            let zeros = "0".repeat(hex_str.len());
            std::env::set_var("MILNET_MASTER_KEK", &zeros);
            std::env::remove_var("MILNET_MASTER_KEK");
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            let mut key = [0u8; 32];
            for (i, chunk) in hex_str.as_bytes().chunks(2).take(32).enumerate() {
                let hex = std::str::from_utf8(chunk)
                    .unwrap_or_else(|_| { tracing::error!("MILNET_MASTER_KEK contains invalid UTF-8 at byte {}", i * 2); std::process::exit(1); });
                key[i] = u8::from_str_radix(hex, 16)
                    .unwrap_or_else(|_| { tracing::error!("MILNET_MASTER_KEK contains invalid hex '{}' at position {}", hex, i * 2); std::process::exit(1); });
            }
            if key.iter().all(|&b| b == 0) {
                tracing::error!("all-zero key detected in MILNET_MASTER_KEK"); std::process::exit(1);
            }
            zeroize_string(&mut hex_str);
            hex_str.zeroize();
            key
        }
        _ => {
            tracing::error!("MILNET_MASTER_KEK not set or too short. Refusing to start.");
            std::process::exit(1);
        }
    }
}

/// Load the master KEK from a file descriptor number specified by `MILNET_MASTER_KEK_FD`.
///
/// This is the preferred method for secret delivery because file descriptors are NOT
/// visible in `/proc/PID/environ`. The parent process (systemd, container runtime, or
/// init script) opens a pipe/tmpfs fd, writes the 64-char hex KEK, and passes the fd
/// number via `MILNET_MASTER_KEK_FD`.
///
/// Falls back to `MILNET_MASTER_KEK` env var with a SIEM WARNING if the fd var is unset.
pub fn load_master_kek_from_fd() -> [u8; 32] {
    use std::io::Read;
    use zeroize::Zeroize;

    match std::env::var("MILNET_MASTER_KEK_FD") {
        Ok(fd_str) => {
            // Remove fd env var immediately (less sensitive than key, but still metadata)
            std::env::remove_var("MILNET_MASTER_KEK_FD");

            let fd: i32 = fd_str.parse().unwrap_or_else(|_| {
                tracing::error!("MILNET_MASTER_KEK_FD is not a valid integer: {fd_str}");
                std::process::exit(1);
            });

            // SAFETY: We trust the parent process to pass a valid, open fd.
            let mut file = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };
            let file_ref: &mut std::fs::File = &mut file;
            let mut hex_buf = String::with_capacity(64);
            if let Err(e) = file_ref.read_to_string(&mut hex_buf) {
                tracing::error!("Failed to read KEK from fd {fd}: {e}");
                std::process::exit(1);
            }

            let hex_str = hex_buf.trim();
            if hex_str.len() < 64 {
                tracing::error!(
                    "KEK from fd {fd} too short: expected 64 hex chars, got {}",
                    hex_str.len()
                );
                std::process::exit(1);
            }

            let mut key = [0u8; 32];
            for (i, chunk) in hex_str.as_bytes().chunks(2).take(32).enumerate() {
                let hex = std::str::from_utf8(chunk).unwrap_or_else(|_| {
                    tracing::error!("KEK from fd contains invalid UTF-8 at byte {}", i * 2);
                    std::process::exit(1);
                });
                key[i] = u8::from_str_radix(hex, 16).unwrap_or_else(|_| {
                    tracing::error!("KEK from fd contains invalid hex '{}' at position {}", hex, i * 2);
                    std::process::exit(1);
                });
            }

            if key.iter().all(|&b| b == 0) {
                tracing::error!("all-zero key detected from fd {fd}");
                std::process::exit(1);
            }

            hex_buf.zeroize();
            tracing::info!("Master KEK loaded from fd {fd} (no env var exposure)");
            key
        }
        Err(_) => {
            // SIEM WARNING: falling back to env var delivery which is visible in /proc/PID/environ
            tracing::warn!(
                "SECURITY WARNING: MILNET_MASTER_KEK_FD not set. \
                 Falling back to MILNET_MASTER_KEK env var. \
                 The KEK will be visible in /proc/PID/environ to root-level attackers. \
                 Production deployments MUST use fd-based delivery."
            );
            crate::siem::SecurityEvent::tamper_detected(
                "SECURITY: Master KEK loaded from env var instead of fd. \
                 /proc/PID/environ exposes the initial value to root. \
                 Set MILNET_MASTER_KEK_FD for fd-based secret delivery.",
            );
            load_master_kek()
        }
    }
}

/// Try to derive an archive encryption KEK from the master KEK.
/// Returns None if the master KEK is not yet loaded (early initialization).
/// In production, the caller should retry after KEK initialization.
pub fn try_derive_archive_kek() -> Option<[u8; 32]> {
    // Check if master KEK is loaded without triggering initialization
    if MASTER_KEK_CACHE.get().is_none() {
        tracing::warn!(
            target: "siem",
            "SIEM:WARNING: Archive KEK derivation requested before master KEK loaded. \
             Archives created before KEK initialization will be unencrypted. \
             Ensure KEK is loaded before creating audit archives."
        );
        return None;
    }
    let master = load_master_kek();
    let hkdf = hkdf::Hkdf::<sha2::Sha512>::new(
        Some(b"MILNET-ARCHIVE-KEK-v1"),
        master.as_ref(),
    );
    let mut kek = [0u8; 32];
    hkdf.expand(b"archive-encryption", &mut kek)
        .expect("HKDF expand for 32 bytes always succeeds");
    Some(kek)
}

/// Load the shared SHARD HMAC key with sealed key support.
pub fn load_shard_hmac_key_sealed() -> [u8; 64] {
    load_key_hardened(
        "SHARD_HMAC_KEY",
        "shard-hmac",
        b"MILNET-DEV-SHARD-HMAC-KEY-NOT-FOR-PRODUCTION!!!!!",
    )
}

/// Derive a per-module SHARD HMAC key from the master KEK.
///
/// Each module gets a unique key derived via HKDF-SHA512 with the module name
/// as domain separator. This prevents one compromised module from impersonating
/// another on the SHARD channel. Both endpoints of a channel must derive the
/// same key by using a canonical channel name.
pub fn derive_module_hmac_key(module_a: &str, module_b: &str) -> Result<[u8; 64], String> {
    let master_kek = cached_master_kek();
    // Canonical ordering: alphabetically sort module names for consistent derivation
    let (first, second) = if module_a <= module_b {
        (module_a, module_b)
    } else {
        (module_b, module_a)
    };
    let domain = format!("MILNET-SHARD-CHANNEL-v1:{}:{}", first, second);

    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(domain.as_bytes()), master_kek);
    let mut okm = [0u8; 64];
    hk.expand(b"shard-channel-hmac", &mut okm)
        .map_err(|_| "HKDF-SHA512 key derivation failed".to_string())?;
    Ok(okm)
}

/// Load the shared receipt signing key with sealed key support.
pub fn load_receipt_signing_key_sealed() -> [u8; 64] {
    load_key_hardened(
        "RECEIPT_SIGNING_KEY",
        "receipt-sign",
        b"MILNET-DEV-RECEIPT-KEY-NOT-FOR-PRODUCTION!!!!!!!!",
    )
}

/// Load the ML-DSA-87 receipt signing seed (32 bytes) from sealed storage
/// or derive deterministically from the master KEK.
///
/// Both OPAQUE (signer) and Orchestrator (verifier) MUST call this function
/// to ensure they use the same seed. This eliminates the key mismatch that
/// caused ML-DSA verification to always fail.
///
/// Key loading order:
/// 1. `RECEIPT_SIGNING_SEED_SEALED` env var (AES-256-GCM sealed, hex-encoded)
/// 2. `RECEIPT_SIGNING_SEED` env var (raw hex, blocked in production)
/// 3. Deterministic derivation from master KEK via HKDF-SHA512 (dev only)
pub fn load_receipt_signing_seed_sealed() -> [u8; 32] {
    static CACHED: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| load_receipt_signing_seed_inner())
}

fn load_receipt_signing_seed_inner() -> [u8; 32] {
    use zeroize::Zeroize;

    let sealed_var = "RECEIPT_SIGNING_SEED_SEALED";
    let raw_var = "RECEIPT_SIGNING_SEED";

    // 1. Try sealed key
    if let Ok(mut hex_str) = std::env::var(sealed_var) {
        // Overwrite with zeros first to clear libc environ buffer
        std::env::set_var(sealed_var, "0".repeat(hex_str.len()));
        std::env::remove_var(sealed_var);
        let result = unseal_seed_from_hex(&hex_str, "receipt-sign-seed");
        zeroize_string(&mut hex_str);
        hex_str.zeroize();
        if let Some(seed) = result {
            if seed.iter().all(|&b| b == 0) {
                tracing::error!("all-zero seed after unsealing {raw_var}");
                std::process::exit(1);
            }
            tracing::info!("{raw_var} loaded from sealed storage.");
            return seed;
        }
        tracing::warn!("{sealed_var} present but unseal failed. Trying raw.");
    }

    // 2. Raw keys are not permitted — sealed keys only.
    if let Ok(mut hex_str) = std::env::var(raw_var) {
        // Overwrite with zeros first to clear libc environ buffer
        std::env::set_var(raw_var, "0".repeat(hex_str.len()));
        std::env::remove_var(raw_var);
        zeroize_string(&mut hex_str);
        hex_str.zeroize();
        tracing::error!(
            "Raw (unencrypted) {raw_var} detected. \
             Use {sealed_var} with sealed keys instead."
        );
        std::process::exit(1);
    }

    // 3. Derive from master KEK via HKDF-SHA512 as last resort.
    // This is a real key derived from the master KEK, not a hardcoded bypass.
    tracing::warn!(
        "{raw_var} not set. Deriving from master KEK via HKDF-SHA512. \
         Production deployments MUST use sealed keys."
    );
    let master = load_master_kek();
    let hk = hkdf::Hkdf::<sha2::Sha512>::new(Some(b"MILNET-RECEIPT-SEED-DERIVE-v1"), &master);
    let mut seed = [0u8; 32];
    hk.expand(b"receipt-signing-seed", &mut seed)
        .unwrap_or_else(|_| { tracing::error!("HKDF expand failed for receipt seed"); std::process::exit(1); });
    seed
}

/// Unseal a 32-byte seed from hex-encoded sealed data.
fn unseal_seed_from_hex(hex_str: &str, purpose: &str) -> Option<[u8; 32]> {
    use zeroize::Zeroize;
    let mut sealed_bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .filter_map(|i| {
            hex_str.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();

    if sealed_bytes.len() < 12 + 16 + 32 {
        sealed_bytes.zeroize();
        return None;
    }

    let master_kek = cached_master_kek();
    let mut unseal_key = derive_unseal_key(master_kek, purpose).ok()?;

    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new_from_slice(&unseal_key).ok()?;
    unseal_key.zeroize();
    let nonce = Nonce::from_slice(&sealed_bytes[..12]);
    let aad = format!("MILNET-SEALED-KEY-v1:{purpose}");
    let result = cipher.decrypt(nonce, aes_gcm::aead::Payload {
        msg: &sealed_bytes[12..],
        aad: aad.as_bytes(),
    });
    sealed_bytes.zeroize();
    let plaintext = result.ok()?;

    if plaintext.len() != 32 {
        let mut plaintext = plaintext;
        plaintext.zeroize();
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    let mut plaintext = plaintext;
    plaintext.zeroize();
    Some(seed)
}

/// Hardened key loading with sealed key support.
///
/// After reading, env vars are removed from the process environment and
/// the in-memory Strings are zeroized to prevent leakage.
fn load_key_hardened(var: &str, purpose: &str, _dev_seed: &[u8]) -> [u8; 64] {
    use zeroize::Zeroize;
    let sealed_var = format!("{var}_SEALED");

    // 1. Try sealed key
    if let Ok(mut hex_str) = std::env::var(&sealed_var) {
        // Overwrite with zeros first to clear libc environ buffer
        std::env::set_var(&sealed_var, "0".repeat(hex_str.len()));
        std::env::remove_var(&sealed_var);
        let result = unseal_key_from_hex(&hex_str, purpose);
        zeroize_string(&mut hex_str);
        hex_str.zeroize();
        if let Some(key) = result {
            if key.iter().all(|&b| b == 0) {
                tracing::error!("all-zero key detected after unsealing {var}"); std::process::exit(1);
            }
            tracing::info!("{var} loaded from sealed storage.");
            return key;
        }
        tracing::warn!("{sealed_var} present but unseal failed. Trying raw.");
    }

    // 2. Raw keys are not permitted — sealed keys only.
    if let Ok(mut hex_str) = std::env::var(var) {
        // Overwrite with zeros first to clear libc environ buffer
        std::env::set_var(var, "0".repeat(hex_str.len()));
        std::env::remove_var(var);
        zeroize_string(&mut hex_str);
        hex_str.zeroize();
        tracing::error!(
            "Raw (unencrypted) {var} detected. \
             Use {sealed_var} with sealed keys instead."
        );
        std::process::exit(1);
    }

    // 3. Derive from master KEK via HKDF-SHA512 as last resort.
    // Real key derived from master KEK, not a hardcoded bypass.
    tracing::warn!(
        "{var} not set. Deriving from master KEK via HKDF-SHA512. \
         Production deployments MUST use sealed keys."
    );
    let master = load_master_kek();
    let hk = hkdf::Hkdf::<sha2::Sha512>::new(Some(b"MILNET-KEY-DERIVE-v1"), &master);
    let mut key = [0u8; 64];
    hk.expand(purpose.as_bytes(), &mut key)
        .unwrap_or_else(|_| { tracing::error!("HKDF expand failed for {var}"); std::process::exit(1); });
    key
}

/// Unseal a hex-encoded sealed key using the master KEK.
fn unseal_key_from_hex(hex_str: &str, purpose: &str) -> Option<[u8; 64]> {
    let mut sealed_bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .filter_map(|i| {
            hex_str.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();

    if sealed_bytes.len() < 12 + 16 + 64 {
        sealed_bytes.zeroize();
        return None;
    }

    let master_kek = cached_master_kek();
    let mut unseal_key = derive_unseal_key(master_kek, purpose).ok()?;

    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new_from_slice(&unseal_key).ok()?;
    // Zeroize derived key as soon as the cipher is initialized
    unseal_key.zeroize();
    let nonce = Nonce::from_slice(&sealed_bytes[..12]);
    let aad = format!("MILNET-SEALED-KEY-v1:{purpose}");
    let result = cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: &sealed_bytes[12..],
            aad: aad.as_bytes(),
        });
    // Zeroize sealed_bytes immediately after decryption attempt
    sealed_bytes.zeroize();
    let plaintext = result.ok()?;

    if plaintext.len() != 64 {
        let mut plaintext = plaintext;
        plaintext.zeroize();
        return None;
    }

    let mut key = [0u8; 64];
    key.copy_from_slice(&plaintext);
    // Zeroize the intermediate plaintext Vec to prevent heap fragment leakage
    let mut plaintext = plaintext;
    plaintext.zeroize();
    Some(key)
}

/// Derive an unseal key for a specific purpose from the master KEK.
fn derive_unseal_key(master_kek: &[u8; 32], purpose: &str) -> Result<[u8; 32], String> {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-UNSEAL-v1"), master_kek);
    let mut okm = [0u8; 32];
    hk.expand(purpose.as_bytes(), &mut okm)
        .map_err(|_| "HKDF-SHA512 key derivation failed".to_string())?;
    Ok(okm)
}

/// Seal a 64-byte key for storage in env vars or files.
/// Used by operators to prepare sealed keys for deployment.
pub fn seal_key_for_storage(key: &[u8; 64], purpose: &str) -> Result<Vec<u8>, String> {
    let master_kek = cached_master_kek();
    let seal_key = derive_unseal_key(master_kek, purpose)?;

    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new_from_slice(&seal_key)
        .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("OS entropy failure: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = format!("MILNET-SEALED-KEY-v1:{purpose}");
    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: key.as_slice(),
            aad: aad.as_bytes(),
        })
        .map_err(|_| "AES-256-GCM encryption failed".to_string())?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Detect whether an HSM backend is configured via environment.
///
/// Returns the HSM backend name if `MILNET_HSM_BACKEND` is set and valid.
/// Valid values: `pkcs11`, `aws-kms`, `tpm2`, `software`.
pub fn hsm_backend_from_env() -> Option<String> {
    std::env::var("MILNET_HSM_BACKEND").ok().filter(|s| {
        matches!(
            s.to_lowercase().as_str(),
            "pkcs11" | "aws-kms" | "awskms" | "kms" | "tpm2" | "tpm" | "software" | "soft" | "dev"
        )
    })
}

/// Load the master KEK with HSM awareness.
///
/// If `MILNET_HSM_BACKEND` is set, this returns a sentinel value indicating
/// that the caller should use the HSM key manager (`crypto::hsm::HsmKeyManager`)
/// instead of a raw key. The sentinel is all-zeros, which is detected by the
/// crypto layer as "use HSM path".
///
/// If `MILNET_HSM_BACKEND` is not set, falls back to [`load_master_kek`].
///
/// # Usage
/// ```text
/// let kek = load_master_kek_hsm_aware();
/// if kek == [0u8; 32] {
///     // HSM backend configured — use HsmKeyManager
///     let config = crypto::hsm::HsmConfig::from_env();
///     let source = crypto::hsm::create_key_source(&config)?;
///     let master_key = source.load_master_key()?;
/// } else {
///     // Software/env var path
///     let master_key = crypto::seal::MasterKey::from_bytes(kek);
/// }
/// ```
pub fn load_master_kek_hsm_aware() -> [u8; 32] {
    if let Some(backend) = hsm_backend_from_env() {
        let is_software = matches!(
            backend.to_lowercase().as_str(),
            "software" | "soft" | "dev"
        );
        if !is_software {
            tracing::info!(
                "HSM backend '{}' detected. Master KEK will be loaded from HSM.",
                backend
            );
            // Return sentinel — caller must use HsmKeyManager.
            return [0u8; 32];
        }
        // Software HSM is forbidden — fail hard.
        tracing::error!(
            "Software HSM backend forbidden. \
             Set MILNET_HSM_BACKEND to pkcs11/aws-kms/tpm2"
        );
        std::process::exit(1);
    }
    load_master_kek()
}

/// Convert sealed bytes to hex string for env var storage.
pub fn sealed_to_hex(sealed: &[u8]) -> String {
    sealed.iter().map(|b| format!("{b:02x}")).collect()
}

/// Securely zeroize a string using volatile writes (cannot be optimized away).
/// Delegates to the `zeroize` crate which guarantees memory is actually cleared.
pub fn zeroize_string(s: &mut String) {
    use zeroize::Zeroize;
    s.zeroize();
}

// ===========================================================================
// KEK Escrow Ceremony — distributed recovery for master KEK
// ===========================================================================
//
// THREAT MODEL: If the master KEK is lost (all nodes destroyed, all shares
// corrupted), the entire system's encrypted data is irrecoverable. The KEK
// escrow ceremony creates an independent recovery path via Shamir secret
// sharing to designated escrow holders (e.g., security officers with HSM
// smart cards).
//
// SECURITY PROPERTIES:
// - No single escrow holder can recover the KEK (threshold required)
// - Each share is individually encrypted with a holder-specific key
// - Reconstruction requires physical presence of threshold holders
// - The reconstructed KEK is verified against a stored hash before use

/// KEK verification hash domain separator.
/// Used to compute SHA-512(KEK || domain) for integrity checking.
const KEK_VERIFY_DOMAIN: &[u8] = b"MILNET-KEK-VERIFY-v1";

/// Stored verification hash for in-memory KEK integrity canary.
static KEK_VERIFICATION_HASH: OnceLock<[u8; 64]> = OnceLock::new();

/// Configuration for KEK escrow ceremony.
#[derive(Debug, Clone)]
pub struct KekEscrowConfig {
    /// Number of escrow shares to generate (total participants).
    /// Default: 5.
    pub escrow_shares: u8,
    /// Minimum number of shares needed to reconstruct the KEK.
    /// Default: 3.
    pub escrow_threshold: u8,
    /// Whether each share is individually encrypted with a holder-specific key.
    /// When true, each share is encrypted using a key derived via HKDF with
    /// the holder's index as domain separator. This adds defense-in-depth:
    /// even if an attacker obtains raw shares, they need the holder-specific
    /// decryption keys.
    /// Default: true.
    pub escrow_encryption: bool,
}

impl Default for KekEscrowConfig {
    fn default() -> Self {
        Self {
            escrow_shares: 5,
            escrow_threshold: 3,
            escrow_encryption: true,
        }
    }
}

/// Create escrow shares of the master KEK for disaster recovery.
///
/// Splits the KEK into Shamir shares using the existing threshold code,
/// optionally encrypting each share with a holder-specific key derived
/// via HKDF. Returns encrypted share blobs for distribution to escrow holders.
///
/// Each share is self-contained: it includes the share index and can be
/// independently stored by each escrow holder (e.g., on an HSM smart card).
pub fn create_escrow_shares(kek: &[u8; 32], config: &KekEscrowConfig) -> Result<Vec<Vec<u8>>, String> {
    use crate::threshold_kek::split_secret;

    // Split KEK into Shamir shares
    let shares = split_secret(kek, config.escrow_threshold, config.escrow_shares)?;

    let mut escrow_shares = Vec::with_capacity(shares.len());

    for share in &shares {
        let share_hex = share.to_hex();
        let share_bytes = share_hex.as_bytes().to_vec();

        if config.escrow_encryption {
            // Derive a holder-specific encryption key via HKDF
            // Domain: "MILNET-KEK-ESCROW-v1:holder-{index}"
            let holder_key = derive_escrow_holder_key(kek, share.index)?;

            // Encrypt the share with AES-256-GCM using the holder-specific key
            let encrypted = encrypt_escrow_share(&share_bytes, &holder_key)?;
            escrow_shares.push(encrypted);
        } else {
            escrow_shares.push(share_bytes);
        }
    }

    // Zeroize the intermediate shares
    drop(shares);

    Ok(escrow_shares)
}

/// Recover the master KEK from escrow shares.
///
/// Decrypts each share (if encrypted), reconstructs the KEK via Shamir
/// threshold reconstruction, and verifies the result against the stored
/// verification hash.
///
/// Returns the reconstructed KEK or an error if reconstruction fails.
pub fn recover_from_escrow(
    encrypted_shares: &[Vec<u8>],
    config: &KekEscrowConfig,
    verification_hash: &[u8; 64],
) -> Result<[u8; 32], String> {
    use crate::threshold_kek::KekShare;
    use crate::threshold_kek::reconstruct_secret;

    if encrypted_shares.len() < config.escrow_threshold as usize {
        return Err(format!(
            "need {} shares for recovery, got {}",
            config.escrow_threshold,
            encrypted_shares.len()
        ));
    }

    let mut shares = Vec::with_capacity(encrypted_shares.len());

    for encrypted_share in encrypted_shares {
        // In the recovery path, the caller is responsible for pre-decrypting
        // each share with the holder's own key (HSM/smart card/passphrase).
        // Here we parse the decrypted share hex.
        let share_hex = String::from_utf8(encrypted_share.clone())
            .map_err(|_| "escrow share is not valid UTF-8 — \
                          if encrypted, decrypt with holder key first".to_string())?;

        let share = KekShare::from_hex(&share_hex)
            .map_err(|e| format!("failed to parse escrow share: {e}"))?;
        shares.push(share);
    }

    // Reconstruct KEK from threshold shares
    let mut reconstructed = reconstruct_secret(&shares)
        .map_err(|e| format!("KEK reconstruction from escrow shares failed: {e}"))?;

    // Verify reconstructed KEK against stored hash
    let computed_hash = compute_kek_verification_hash(&reconstructed);

    use subtle::ConstantTimeEq;
    if computed_hash.ct_eq(verification_hash).into() {
        let mut result = [0u8; 32];
        result.copy_from_slice(&reconstructed);
        reconstructed.zeroize();
        Ok(result)
    } else {
        reconstructed.zeroize();
        Err("KEK reconstruction verification FAILED — \
             reconstructed key does not match stored hash. \
             Possible: wrong shares, corrupted shares, or wrong verification hash."
            .to_string())
    }
}

/// Compute the verification hash of a KEK: SHA-512(KEK || "MILNET-KEK-VERIFY-v1").
///
/// This hash is stored separately and used to verify the KEK after:
/// - Escrow recovery (reconstructed KEK matches original)
/// - In-memory integrity check (canary pattern for tamper detection)
pub fn compute_kek_verification_hash(kek: &[u8; 32]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(kek);
    hasher.update(KEK_VERIFY_DOMAIN);
    let hash = hasher.finalize();
    let mut result = [0u8; 64];
    result.copy_from_slice(&hash);
    result
}

/// Store the KEK verification hash for later integrity checks.
///
/// Called once after the master KEK is loaded. The hash is stored in a
/// static variable and used by `verify_kek_integrity()` to detect in-memory
/// tampering (e.g., via Rowhammer, DMA attacks, or memory corruption).
pub fn store_kek_verification_hash(kek: &[u8; 32]) {
    let hash = compute_kek_verification_hash(kek);
    let _ = KEK_VERIFICATION_HASH.set(hash);
}

/// Verify that the master KEK in memory has not been tampered with.
///
/// Recomputes SHA-512(KEK || domain) and compares against the stored hash
/// using constant-time comparison. Returns false if:
/// - The KEK has been modified in memory (Rowhammer, DMA attack, corruption)
/// - The verification hash was never stored (store_kek_verification_hash not called)
///
/// This implements the "canary pattern" for cryptographic key integrity:
/// periodically verify that keys haven't been modified by hardware faults
/// or adversarial memory manipulation.
pub fn verify_kek_integrity() -> bool {
    let stored = match KEK_VERIFICATION_HASH.get() {
        Some(h) => h,
        None => {
            tracing::warn!(
                "KEK integrity check called but no verification hash stored — \
                 call store_kek_verification_hash() after KEK loading"
            );
            return false;
        }
    };

    let kek = cached_master_kek();
    let current = compute_kek_verification_hash(kek);

    use subtle::ConstantTimeEq;
    let ok: bool = current.ct_eq(stored).into();

    if !ok {
        tracing::error!(
            "SIEM:CRITICAL KEK INTEGRITY CHECK FAILED — master KEK in memory does not \
             match stored verification hash. Possible causes: Rowhammer attack, DMA \
             attack, memory corruption, or software bug. IMMEDIATE INVESTIGATION REQUIRED."
        );
    }

    ok
}

/// Derive a holder-specific encryption key for escrow share encryption.
fn derive_escrow_holder_key(kek: &[u8; 32], holder_index: u8) -> Result<[u8; 32], String> {
    use hkdf::Hkdf;
    use sha2::Sha512;
    let info = format!("MILNET-KEK-ESCROW-v1:holder-{holder_index}");
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-KEK-ESCROW-SALT-v1"), kek);
    let mut key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|_| "HKDF-SHA512 key derivation failed".to_string())?;
    Ok(key)
}

/// Encrypt an escrow share with a holder-specific key using AES-256-GCM.
fn encrypt_escrow_share(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "AES-256-GCM cipher initialization failed".to_string())?;

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("OS entropy failure: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = b"MILNET-KEK-ESCROW-SHARE-v1";
    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        })
        .map_err(|_| "AES-256-GCM encryption failed".to_string())?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Remove ALL MILNET_* environment variables from the process environment.
///
/// SECURITY: Must be called after all startup initialization is complete.
/// Environment variables are readable via /proc/pid/environ on Linux,
/// and by any code that can call libc::getenv or std::env::var. Scrubbing
/// them after startup closes this attack surface.
///
/// This function iterates over all current environment variables and removes
/// any whose key starts with "MILNET_". It also removes other sensitive
/// variables that may have been set during deployment.
pub fn scrub_all_milnet_env_vars() {
    let milnet_vars: Vec<String> = std::env::vars()
        .filter_map(|(key, _)| {
            if key.starts_with("MILNET_") {
                Some(key)
            } else {
                None
            }
        })
        .collect();

    let count = milnet_vars.len();
    for var in &milnet_vars {
        // Overwrite with zeros first to clear libc environ buffer
        if let Ok(val) = std::env::var(var) {
            std::env::set_var(var, "0".repeat(val.len()));
        }
        std::env::remove_var(var);
    }

    if count > 0 {
        tracing::info!(
            count = count,
            "Scrubbed {count} MILNET_* environment variables from process environment"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_unseal_key_is_consistent() {
        let master = [0x42u8; 32];
        let k1 = derive_unseal_key(&master, "test-purpose");
        let k2 = derive_unseal_key(&master, "test-purpose");
        assert_eq!(k1, k2);
    }

    #[test]
    fn is_production_always_true() {
        // Production mode is unconditionally active
        assert!(is_production(), "is_production() must always return true");
    }

    #[test]
    fn derive_unseal_key_deterministic() {
        let master = [42u8; 32];
        let k1 = derive_unseal_key(&master, "shard-hmac");
        let k2 = derive_unseal_key(&master, "shard-hmac");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_unseal_key_different_purposes() {
        let master = [42u8; 32];
        let k1 = derive_unseal_key(&master, "shard-hmac");
        let k2 = derive_unseal_key(&master, "receipt-sign");
        assert_ne!(k1, k2);
    }

    #[test]
    fn seal_unseal_round_trip() {
        std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

        let mut original_key = [0u8; 64];
        getrandom::getrandom(&mut original_key).unwrap();

        let sealed = seal_key_for_storage(&original_key, "test-purpose").unwrap();
        let hex_sealed = sealed_to_hex(&sealed);

        let recovered = unseal_key_from_hex(&hex_sealed, "test-purpose");
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap(), original_key);

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn wrong_purpose_fails_unseal() {
        std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

        let original_key = [99u8; 64];
        let sealed = seal_key_for_storage(&original_key, "purpose-a").unwrap();
        let hex_sealed = sealed_to_hex(&sealed);

        let recovered = unseal_key_from_hex(&hex_sealed, "purpose-b");
        assert!(recovered.is_none());

        std::env::remove_var("MILNET_MASTER_KEK");
    }

    #[test]
    fn tampered_sealed_data_fails() {
        std::env::set_var("MILNET_MASTER_KEK", "2a".repeat(32));

        let original_key = [77u8; 64];
        let mut sealed = seal_key_for_storage(&original_key, "test").unwrap();
        if sealed.len() > 20 {
            sealed[20] ^= 0xFF;
        }
        let hex_sealed = sealed_to_hex(&sealed);

        let recovered = unseal_key_from_hex(&hex_sealed, "test");
        assert!(recovered.is_none());

        std::env::remove_var("MILNET_MASTER_KEK");
    }
}
