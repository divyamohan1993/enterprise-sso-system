//! Hardened key loading for inter-service communication.
//!
//! All services MUST use the same SHARD HMAC key and receipt signing key.
//! Keys are loaded from sealed storage (encrypted env vars) and unwrapped
//! using the master KEK. Raw plaintext env vars are rejected in production mode.
//!
//! # CAT-H-followup: RES-BOOT degraded-mode fallback (NOT YET IMPLEMENTED)
//!
//! The RES-BOOT fix spec calls for a graceful fallback path when the
//! quorum-of-peers unsealing path is unreachable at startup: cache the
//! unsealed KEK in a TPM-sealed tmpfs file that survives brief restarts
//! (1-hour auto-expiry), emit a SIEM degraded-mode alert on use, and
//! proceed. On subsequent restarts if quorum is still unreachable, unseal
//! the snapshot via `tpm2_unseal` and continue.
//!
//! This is NOT YET implemented. The current cluster-reconstruction code
//! path in `common/src/cluster.rs:~805` panics if quorum is unreachable;
//! that behaviour is retained for now. Implementation requires:
//! - A new `tpm_sealed_snapshot` submodule that wraps `tpm2_seal` /
//!   `tpm2_unseal` via the `tpm2-tss` crate (already in the workspace).
//! - tmpfs mount at `/run/milnet/kek-snapshot` with 0600 perms.
//! - SIEM event emission on both write and degraded-mode use.
//! - Auto-expiry by writing an HMAC-signed timestamp alongside the blob
//!   and refusing to unseal it if the timestamp is older than 1 hour.
//!
//! Deferred out of the current CAT-H pass by team-lead direction.
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
///
/// SECURITY (anti-clone): in MILITARY mode this delegates to [`get_master_kek`]
/// so that callers which historically invoke `cached_master_kek()` directly
/// (admin/audit/tss/kt/shard/…) ALSO source key material from the vTPM, never
/// from the environment. Without this delegation a direct caller would hit
/// `load_master_kek()` and read `MILNET_MASTER_KEK` from env — exactly the
/// clone-reproducible path this fix closes. The signature is unchanged. There
/// is no recursion: `get_master_kek`'s military Path 0 never calls back into
/// `cached_master_kek`, and its non-military fallback (which does) is only
/// reached when this guard is inactive.
pub fn cached_master_kek() -> &'static [u8; 32] {
    if std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1") {
        return get_master_kek();
    }
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

// ===========================================================================
// vTPM-sealed master KEK acquisition (military mode anti-clone binding)
// ===========================================================================
//
// THREAT MODEL — VM/disk clone on different hardware:
//   The pre-existing KEK acquisition paths (single `MILNET_MASTER_KEK`,
//   threshold `MILNET_KEK_SHARE`) all source key material from the process
//   ENVIRONMENT. An attacker who clones the VM image / disk reproduces those
//   env vars verbatim and the clone derives the *same* KEK on *different*
//   hardware. The KEK is the root of the whole key hierarchy, so a clone
//   decrypts everything. This is the #1 clone-resistance defect.
//
// FIX — bind KEK material to THIS platform's vTPM:
//   In military deployment (`MILNET_MILITARY_DEPLOYMENT=1`) the KEK (or this
//   node's Shamir share) is recovered exclusively by UNSEALING a TPM-sealed
//   blob whose policy is bound to the measured-boot PCR set (0,2,4,7 — see
//   `platform_integrity::MASTER_KEK_PCR_LIST`). The sealed object is encrypted
//   under the TPM's Storage Root Key, which never leaves the chip
//   (TPM 2.0 Library Spec Part 1, §23 "Protected Storage"; §14 "Object
//   Hierarchy"). `tpm2_unseal` is gated by a `TPM2_PolicyPCR` session
//   (Part 3, `TPM2_PolicyPCR`; Part 1, §23.7 "Enhanced Authorization"), so a
//   clone on different firmware/bootloader/Secure-Boot state produces a
//   different policy digest and the TPM refuses to release the secret.
//   tpm2-tools workflow per the tpm2-software project's sealing guide
//   (`tpm2_createprimary` → `tpm2_create -L policy` → `tpm2_load` →
//   `tpm2_unseal`).
//
// FAIL-CLOSED:
//   Military mode + (no vTPM | missing sealed blob | unseal failure | PCR
//   mismatch | env KEK material present) ⇒ REFUSE: emit a SIEM critical and
//   `std::process::exit(199)`. Env-sourced KEK material is FORBIDDEN in
//   military mode; its presence is treated as a clone/misconfiguration
//   indicator, never used. The non-military / MLP env + threshold paths are
//   unchanged.
//
// HONEST RESIDUAL (anti-clone is NOT anti-root):
//   PCR sealing defeats a clone on DIFFERENT hardware. It does NOT defeat a
//   same-host attacker who already has root on the GENUINE node: such an
//   attacker satisfies the live PCR policy and can invoke `tpm2_unseal`
//   directly (or read the in-process share, see the env-injection note in
//   `military_unseal_share_into_env`). Closing that gap requires confidential
//   computing (AMD SEV-SNP / Intel TDX) with key release bound to a remote
//   attestation of the workload measurement, so the secret is only released
//   inside an attested, memory-encrypted enclave. That is a follow-up and is
//   OUT OF SCOPE for this wiring. See `kek-tpm-changelog.md`.

/// Abstraction over the TPM seal/unseal of master-KEK material.
///
/// The production implementation ([`Tpm2ToolsKekSealer`]) shells out to
/// tpm2-tools via [`crate::platform_integrity`]. The trait exists so the
/// **gating decisions** (which path is taken, and the fail-closed refusals)
/// can be unit-tested against an in-memory software TPM without real hardware
/// — `team-lead` exercises the real `Tpm2ToolsKekSealer` path on the OCI host
/// with `swtpm`.
pub trait TpmKekSealer {
    /// Seal `secret` to the TPM under the master-KEK PCR policy, persisting the
    /// blob under `name`.
    fn seal(&self, name: &str, secret: &[u8]) -> Result<(), String>;
    /// Unseal the blob previously stored under `name`. Returns an error if the
    /// blob is missing, the TPM is unavailable, or the PCR policy is not
    /// satisfied (clone on different hardware / changed boot chain).
    fn unseal(&self, name: &str) -> Result<Vec<u8>, String>;
    /// Whether a sealed blob already exists for `name` (used by the ceremony to
    /// avoid clobbering, and by the gating logic to detect first-boot).
    fn blob_exists(&self, name: &str) -> bool;
    /// Whether a usable vTPM is present on this platform.
    fn tpm_available(&self) -> bool;
}

/// Production sealer: binds KEK material to the vTPM via tpm2-tools, sealing to
/// the measured-boot PCR set ([`crate::platform_integrity::MASTER_KEK_PCR_LIST`]).
pub struct Tpm2ToolsKekSealer {
    sealed_dir: Option<String>,
}

impl Tpm2ToolsKekSealer {
    /// Construct a sealer, reading the sealed-blob directory from
    /// `MILNET_SEALED_KEK_DIR` (falling back to the platform default
    /// `/var/lib/milnet/sealed`).
    pub fn from_env() -> Self {
        let sealed_dir = std::env::var("MILNET_SEALED_KEK_DIR").ok();
        Self { sealed_dir }
    }

    fn dir(&self) -> Option<&str> {
        self.sealed_dir.as_deref()
    }
}

impl TpmKekSealer for Tpm2ToolsKekSealer {
    fn seal(&self, name: &str, secret: &[u8]) -> Result<(), String> {
        crate::platform_integrity::tpm_seal_with_pcrs(
            name,
            secret,
            self.dir(),
            crate::platform_integrity::MASTER_KEK_PCR_LIST,
        )
        .map_err(|e| e.to_string())
    }

    fn unseal(&self, name: &str) -> Result<Vec<u8>, String> {
        crate::platform_integrity::tpm_unseal_with_pcrs(
            name,
            self.dir(),
            crate::platform_integrity::MASTER_KEK_PCR_LIST,
        )
        .map_err(|e| e.to_string())
    }

    fn blob_exists(&self, name: &str) -> bool {
        crate::measured_boot::sealed_blob_exists(name, self.dir())
    }

    fn tpm_available(&self) -> bool {
        // SECURITY: probe WITHOUT side effects. `platform_integrity::
        // verify_tpm_present()` itself calls `process::exit(199)` in military
        // mode when no TPM is found — calling it here would short-circuit the
        // env-material-first refusal ordering and rob us of our own SIEM
        // message. A direct device-node check is the same presence signal with
        // no exit. (`/dev/tpmrm0` = TPM 2.0 resource-manager node, preferred;
        // `/dev/tpm0` = raw node.)
        std::path::Path::new("/dev/tpmrm0").exists()
            || std::path::Path::new("/dev/tpm0").exists()
    }
}

/// Which kind of material the master-KEK sealed blob holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedKekMode {
    /// The blob is the full 32-byte master KEK (single-KEK military node).
    SingleKek,
    /// The blob is this node's Shamir KEK share; the master is then derived via
    /// the threshold-KDF path (the master is NEVER reconstructed).
    Share,
}

/// Sealed-blob names. Distinct from FROST/legacy names so KEK sealing has its
/// own PCR-bound object and lifecycle.
pub const SEALED_KEK_SINGLE_NAME: &str = "master-kek-tpm";
pub const SEALED_KEK_SHARE_NAME: &str = "kek-share-tpm";

/// The decision the military KEK loader makes BEFORE touching key material.
///
/// Pure and side-effect-free so it is exhaustively unit-testable. The thin
/// wrapper `acquire_military_kek` maps each refusal variant to a SIEM
/// event + `exit(199)`, and each proceed variant to the corresponding unseal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MilitaryKekDecision {
    /// Not military mode — caller falls through to the legacy env/threshold
    /// hierarchy unchanged.
    NotMilitary,
    /// Refuse: env-sourced KEK material is present in military mode (clone /
    /// misconfiguration indicator). `which` names the offending variable(s).
    RefuseEnvMaterialPresent { which: &'static str },
    /// Refuse: no vTPM is available, so the KEK cannot be bound to hardware.
    RefuseNoTpm,
    /// Refuse: the sealed blob for the selected mode is missing (the seal
    /// ceremony has not been run on this node, or the blob was deleted).
    RefuseSealedBlobMissing { mode: SealedKekMode },
    /// Proceed: unseal `mode`'s blob from the TPM and use it.
    Proceed { mode: SealedKekMode },
}

/// Decide how a MILITARY-mode node must obtain its master KEK.
///
/// Inputs are passed explicitly (rather than read from the environment inside)
/// so the decision table can be unit-tested deterministically:
///   - `is_military`:        `MILNET_MILITARY_DEPLOYMENT == 1`
///   - `master_kek_in_env`:  `MILNET_MASTER_KEK` is set
///   - `share_in_env`:       `MILNET_KEK_SHARE` is set
///   - `tpm_available`:      a usable vTPM is present
///   - `mode`:               sealing mode for this node (single vs share)
///   - `single_blob_exists` / `share_blob_exists`: sealed-blob presence
///
/// Order of checks is security-critical and is asserted by the unit tests:
///   1. env material present  → refuse (do NOT fall back to it, do NOT unseal)
///   2. no TPM                → refuse
///   3. selected blob missing → refuse
///   4. otherwise             → proceed (unseal)
#[allow(clippy::too_many_arguments)]
pub fn decide_military_kek_source(
    is_military: bool,
    master_kek_in_env: bool,
    share_in_env: bool,
    tpm_available: bool,
    mode: SealedKekMode,
    single_blob_exists: bool,
    share_blob_exists: bool,
) -> MilitaryKekDecision {
    if !is_military {
        return MilitaryKekDecision::NotMilitary;
    }

    // 1. Env-sourced KEK material is FORBIDDEN in military mode. Its presence
    //    means either a cloned image carrying baked-in secrets or an operator
    //    misconfiguration. Either way: refuse, never consume it.
    if master_kek_in_env && share_in_env {
        return MilitaryKekDecision::RefuseEnvMaterialPresent {
            which: "MILNET_MASTER_KEK and MILNET_KEK_SHARE",
        };
    }
    if master_kek_in_env {
        return MilitaryKekDecision::RefuseEnvMaterialPresent { which: "MILNET_MASTER_KEK" };
    }
    if share_in_env {
        return MilitaryKekDecision::RefuseEnvMaterialPresent { which: "MILNET_KEK_SHARE" };
    }

    // 2. No vTPM ⇒ no hardware binding possible ⇒ refuse.
    if !tpm_available {
        return MilitaryKekDecision::RefuseNoTpm;
    }

    // 3. The sealed blob for the selected mode must exist.
    let blob_present = match mode {
        SealedKekMode::SingleKek => single_blob_exists,
        SealedKekMode::Share => share_blob_exists,
    };
    if !blob_present {
        return MilitaryKekDecision::RefuseSealedBlobMissing { mode };
    }

    // 4. All preconditions satisfied: unseal.
    MilitaryKekDecision::Proceed { mode }
}

/// Determine this node's sealing mode from configuration.
///
/// `MILNET_SEALED_KEK_MODE = "single" | "share"`. Defaults to `Share` because
/// threshold KDF is the mandatory distributed military posture; a node is only
/// `SingleKek` when explicitly configured (e.g. a single-node enclave whose KEK
/// is TPM-sealed rather than env-sourced).
pub fn sealed_kek_mode_from_env() -> SealedKekMode {
    match std::env::var("MILNET_SEALED_KEK_MODE").as_deref() {
        Ok("single") => SealedKekMode::SingleKek,
        _ => SealedKekMode::Share,
    }
}

/// Compute the [`MilitaryKekDecision`] for the current process using `sealer`
/// to probe TPM availability and blob presence. Reads the env predicates here
/// so the pure [`decide_military_kek_source`] stays test-only-input.
fn current_military_kek_decision(sealer: &dyn TpmKekSealer) -> MilitaryKekDecision {
    let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1");
    if !is_military {
        return MilitaryKekDecision::NotMilitary;
    }
    let master_kek_in_env = std::env::var("MILNET_MASTER_KEK").is_ok();
    let share_in_env = std::env::var("MILNET_KEK_SHARE").is_ok();
    let mode = sealed_kek_mode_from_env();

    // SECURITY ORDERING: resolve the env-material refusal BEFORE probing the
    // sealer. `sealer.blob_exists` is harmless, but probing must not be allowed
    // to change the outcome when env material is present — a clone carrying
    // baked-in `MILNET_MASTER_KEK` / `MILNET_KEK_SHARE` must be refused FIRST.
    // We pass placeholder probe inputs here because the pure function returns
    // a `RefuseEnvMaterialPresent` before it consults them; we then re-run with
    // real probe values only once env material is ruled out.
    let pre = decide_military_kek_source(
        is_military, master_kek_in_env, share_in_env,
        /*tpm=*/ true, mode, /*single=*/ true, /*share=*/ true,
    );
    if matches!(pre, MilitaryKekDecision::RefuseEnvMaterialPresent { .. }) {
        return pre;
    }

    // No env material: now it is safe to probe the TPM and sealed blobs.
    let tpm_available = sealer.tpm_available();
    let single_blob_exists = sealer.blob_exists(SEALED_KEK_SINGLE_NAME);
    let share_blob_exists = sealer.blob_exists(SEALED_KEK_SHARE_NAME);
    decide_military_kek_source(
        is_military,
        master_kek_in_env,
        share_in_env,
        tpm_available,
        mode,
        single_blob_exists,
        share_blob_exists,
    )
}

/// SIEM-log a military KEK refusal and terminate the process (exit 199),
/// matching the fail-closed pattern used elsewhere in this module.
fn refuse_military_kek(reason: &str) -> ! {
    crate::siem::SecurityEvent::crypto_failure(reason);
    tracing::error!(
        target: "siem",
        "SIEM:CRITICAL military KEK acquisition refused: {reason}. Process exiting (199)."
    );
    std::process::exit(199);
}

/// Unseal this node's Shamir share from the TPM and inject it into
/// `MILNET_KEK_SHARE` so the existing threshold-KDF path consumes it.
///
/// SECURITY NOTE (in-process env injection):
///   The threshold-KDF loader (`cached_master_kek_threshold_kdf`) reads the
///   share from `MILNET_KEK_SHARE` and immediately overwrites + removes it. We
///   set that var here ONLY with TPM-unsealed bytes, never from the deploy
///   environment, and only for the few microseconds until the loader scrubs
///   it. The transient `/proc/self/environ` exposure window is bounded by the
///   SAME residual already documented for this module: a same-host root
///   attacker who could read `/proc/self/environ` in that window can also call
///   `tpm2_unseal` directly, so this injection adds no exposure beyond the
///   accepted anti-clone-not-anti-root boundary. The alternative — changing the
///   signature of the public threshold-KDF loader — was rejected to preserve a
///   stable `get_master_kek` API for all callers.
fn military_unseal_share_into_env(sealer: &dyn TpmKekSealer) {
    let share_bytes = match sealer.unseal(SEALED_KEK_SHARE_NAME) {
        Ok(b) => b,
        Err(e) => refuse_military_kek(&format!(
            "vTPM unseal of KEK share '{SEALED_KEK_SHARE_NAME}' failed \
             (missing blob, PCR mismatch — clone on different hardware — or TPM error): {e}"
        )),
    };
    // The sealed share blob holds the hex form produced by `KekShare::to_hex`
    // (66 ASCII hex chars). Consume the Vec into a String (no extra copy of the
    // secret); on the success path the String is the only live copy and is
    // scrubbed below.
    let mut share_hex = match String::from_utf8(share_bytes) {
        Ok(s) => s,
        Err(_) => refuse_military_kek(
            "vTPM-unsealed KEK share is not valid UTF-8 hex — refusing to start",
        ),
    };
    let trimmed = share_hex.trim().to_string();
    zeroize_string(&mut share_hex);
    let mut share_hex = trimmed;
    // Validate it really is a Shamir share before injecting it anywhere.
    if crate::threshold_kek::KekShare::from_hex(&share_hex).is_err() {
        zeroize_string(&mut share_hex);
        refuse_military_kek(
            "vTPM-unsealed KEK share failed to parse as a Shamir share — refusing to start",
        );
    }
    // Inject for the threshold-KDF loader, which reads and scrubs it. See the
    // in-process env-injection SECURITY NOTE on this function.
    std::env::set_var("MILNET_KEK_SHARE", &share_hex);
    zeroize_string(&mut share_hex);
}

/// Unseal the full 32-byte master KEK from the TPM (single-KEK military node).
fn military_unseal_single_kek(sealer: &dyn TpmKekSealer) -> [u8; 32] {
    let mut unsealed = match sealer.unseal(SEALED_KEK_SINGLE_NAME) {
        Ok(b) => b,
        Err(e) => refuse_military_kek(&format!(
            "vTPM unseal of master KEK '{SEALED_KEK_SINGLE_NAME}' failed \
             (missing blob, PCR mismatch — clone on different hardware — or TPM error): {e}"
        )),
    };
    if unsealed.len() != 32 {
        let len = unsealed.len();
        unsealed.zeroize();
        refuse_military_kek(&format!(
            "vTPM-unsealed master KEK has wrong length {len} (expected 32) — refusing to start"
        ));
    }
    if unsealed.iter().all(|&b| b == 0) {
        unsealed.zeroize();
        refuse_military_kek("vTPM-unsealed master KEK is all-zero — refusing to start");
    }
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&unsealed);
    unsealed.zeroize();
    kek
}

/// Acquire the master KEK in MILITARY mode from the vTPM, or refuse.
///
/// This is the ONLY military KEK source. It enforces the [`MilitaryKekDecision`]
/// table, then either:
///   - `SingleKek`: caches the TPM-unsealed 32-byte KEK and returns it, or
///   - `Share`:     injects the TPM-unsealed share into `MILNET_KEK_SHARE` and
///                  routes through the existing threshold-KDF derivation.
///
/// Returns `None` when not in military mode (caller proceeds with the legacy
/// hierarchy). Never returns env-sourced key material in military mode.
fn acquire_military_kek(sealer: &dyn TpmKekSealer) -> Option<&'static [u8; 32]> {
    match current_military_kek_decision(sealer) {
        MilitaryKekDecision::NotMilitary => None,
        MilitaryKekDecision::RefuseEnvMaterialPresent { which } => refuse_military_kek(&format!(
            "env-sourced KEK material ({which}) present in military deployment. \
             The master KEK MUST be vTPM-sealed (anti-clone). A cloned image \
             carrying baked-in KEK material is refused. Remove the env var(s) \
             and seal the KEK to this node's TPM via the seal ceremony."
        )),
        MilitaryKekDecision::RefuseNoTpm => refuse_military_kek(
            "no vTPM available in military deployment. The master KEK MUST be \
             sealed to and unsealed from a TPM bound to measured-boot PCRs. \
             A node without a vTPM cannot provide clone resistance.",
        ),
        MilitaryKekDecision::RefuseSealedBlobMissing { mode } => refuse_military_kek(&format!(
            "no TPM-sealed KEK blob found for mode {mode:?}. Run the seal \
             ceremony (seal_master_kek_to_tpm) on THIS node before starting. \
             Env-sourced KEK material is forbidden in military mode."
        )),
        MilitaryKekDecision::Proceed { mode } => match mode {
            SealedKekMode::Share => {
                // Fast path: if the threshold-KDF master is already derived and
                // cached, don't re-unseal the share on every call.
                if THRESHOLD_KDF_CACHE.get().is_some() {
                    return Some(cached_master_kek_threshold_kdf());
                }
                military_unseal_share_into_env(sealer);
                // Route through the existing threshold-KDF path, which now reads
                // the TPM-unsealed share we just injected and scrubs it.
                Some(cached_master_kek_threshold_kdf())
            }
            SealedKekMode::SingleKek => {
                // Fast path: if already unsealed+cached, don't re-invoke the TPM
                // on every call (cached_master_kek delegates here in military
                // mode). The cache is write-once via OnceLock.
                if let Some(cached) = MASTER_KEK_CACHE.get() {
                    cached.lock_in_place();
                    return Some(cached.as_bytes());
                }
                let kek = military_unseal_single_kek(sealer);
                let cached = MASTER_KEK_CACHE.get_or_init(|| ProtectedKek::new(kek));
                cached.lock_in_place();
                Some(cached.as_bytes())
            }
        },
    }
}

/// CEREMONY: seal the master KEK material to THIS node's vTPM.
///
/// Run ONCE per node, by an operator, BEFORE the service starts in military
/// mode. Produces the PCR-bound sealed blob that `get_master_kek` will later
/// unseal. The blob is written under `MILNET_SEALED_KEK_DIR` (default
/// `/var/lib/milnet/sealed`).
///
/// - `SealedKekMode::SingleKek`: `material` is the 32-byte master KEK.
/// - `SealedKekMode::Share`:     `material` is this node's `KekShare` in the
///   66-char hex form returned by `KekShare::to_hex` (ASCII bytes).
///
/// After this succeeds, the corresponding env var (`MILNET_MASTER_KEK` /
/// `MILNET_KEK_SHARE`) MUST be removed from the deployment so the node sources
/// its KEK exclusively from the TPM. Sealing binds to
/// [`crate::platform_integrity::MASTER_KEK_PCR_LIST`]; if the boot chain later
/// changes (legitimate firmware update), re-run this ceremony.
pub fn seal_master_kek_to_tpm(
    sealer: &dyn TpmKekSealer,
    mode: SealedKekMode,
    material: &[u8],
) -> Result<(), String> {
    if !sealer.tpm_available() {
        return Err(
            "cannot seal KEK: no vTPM present. Sealing requires a TPM bound to \
             measured-boot PCRs."
                .to_string(),
        );
    }
    let name = match mode {
        SealedKekMode::SingleKek => {
            if material.len() != 32 {
                return Err(format!(
                    "SingleKek sealing expects a 32-byte KEK, got {} bytes",
                    material.len()
                ));
            }
            SEALED_KEK_SINGLE_NAME
        }
        SealedKekMode::Share => {
            // Validate the share parses before sealing so we never seal garbage.
            let hex = std::str::from_utf8(material)
                .map_err(|_| "Share sealing expects ASCII hex KekShare bytes".to_string())?;
            crate::threshold_kek::KekShare::from_hex(hex.trim())
                .map_err(|e| format!("Share sealing: material is not a valid KekShare: {e}"))?;
            SEALED_KEK_SHARE_NAME
        }
    };
    sealer.seal(name, material)?;
    tracing::info!(
        "ceremony: sealed master-KEK material (mode={:?}) to vTPM as '{}' \
         under measured-boot PCR policy",
        mode,
        name,
    );
    Ok(())
}

// ── Per-node identity seed (INDEPENDENT of the KEK; anti-root) ───────────────

/// Sealed-blob name for a node's INDEPENDENT ML-DSA-87 identity seed.
///
/// PER-NODE name (`node-identity-<node_id>`) so each node's identity seed is a
/// distinct PCR-bound object. Distinct from the KEK blob names so the node
/// identity has its own lifecycle and never collides with KEK material.
pub fn sealed_node_identity_name(node_id: &str) -> String {
    format!("node-identity-{node_id}")
}

/// CEREMONY: generate a fresh INDEPENDENT per-node ML-DSA-87 identity seed and
/// seal it to THIS node's vTPM (PCR 0,2,4,7). Run ONCE per node, by an operator,
/// BEFORE the service starts in military mode.
///
/// The seed is random CSPRNG output, NOT derived from the master KEK — this is
/// the anti-root property: a KEK holder cannot reconstruct another node's seed.
/// Returns the generated seed so the operator can derive and publish the
/// corresponding verifying key (peers PIN that VK at cluster join). The seed
/// itself is sealed and never leaves the node; callers MUST zeroize the returned
/// copy once they have derived the VK.
///
/// Sealing binds to [`crate::platform_integrity::MASTER_KEK_PCR_LIST`]; if the
/// boot chain later changes (legitimate firmware update), re-run this ceremony.
pub fn seal_node_identity_to_tpm(
    sealer: &dyn TpmKekSealer,
    node_id: &str,
) -> Result<[u8; 32], String> {
    use zeroize::Zeroize;
    if !sealer.tpm_available() {
        return Err(
            "cannot seal node identity: no vTPM present. The per-node identity \
             signing key MUST be sealed to a TPM bound to measured-boot PCRs."
                .to_string(),
        );
    }
    let name = sealed_node_identity_name(node_id);

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| format!("CSPRNG failure generating per-node identity seed: {e}"))?;
    if seed.iter().all(|&b| b == 0) {
        seed.zeroize();
        return Err("generated per-node identity seed is all-zero (CSPRNG fault)".to_string());
    }
    if let Err(e) = sealer.seal(&name, &seed) {
        seed.zeroize();
        return Err(format!(
            "failed to TPM-seal generated per-node identity seed '{name}': {e}"
        ));
    }
    tracing::info!(
        "ceremony: generated + sealed INDEPENDENT per-node identity seed to vTPM \
         as '{}' (PCR-bound; publish the derived verifying key for peer pinning)",
        name,
    );
    Ok(seed)
}

/// Load THIS node's INDEPENDENT per-node ML-DSA-87 identity seed by UNSEALING it
/// from the vTPM (military mode). UNSEAL-ONLY — it never generates a key.
///
/// FAIL-CLOSED (refuses via [`refuse_military_kek`], process exits 199) when:
/// * no vTPM is present,
/// * the per-node sealed blob is ABSENT (run [`seal_node_identity_to_tpm`] first),
/// * the unseal fails (PCR mismatch — clone on different hardware — or TPM error),
/// * the unsealed seed is not exactly 32 bytes or is all-zero.
///
/// The seed is INDEPENDENT of the master KEK (sealed CSPRNG output), so a KEK
/// holder cannot derive it. A KEK-derived or env-sourced fallback is NEVER used
/// in military mode — that is the entire point (it would re-introduce the shared
/// single point of failure under a root-on-any-node threat model).
///
/// This loader is for MILITARY mode only; non-military/dev code derives its
/// identity from the KEK (see `distributed_startup::NodeIdentity::for_node`).
pub fn load_node_identity_seed_sealed(node_id: &str) -> [u8; 32] {
    match load_node_identity_seed_inner(&Tpm2ToolsKekSealer::from_env(), node_id) {
        Ok(seed) => seed,
        Err(reason) => refuse_military_kek(&format!(
            "per-node identity seed acquisition failed for '{node_id}': {reason}"
        )),
    }
}

/// Testable core of [`load_node_identity_seed_sealed`]: unseal-only, fail-closed.
/// Takes the sealer so unit tests can inject a software TPM mock. Returns `Err`
/// (the public wrapper turns it into a process refusal) on any failure.
fn load_node_identity_seed_inner(
    sealer: &dyn TpmKekSealer,
    node_id: &str,
) -> Result<[u8; 32], String> {
    use zeroize::Zeroize;
    if !sealer.tpm_available() {
        return Err(
            "no vTPM available — the per-node identity signing key MUST be \
             unsealed from this node's TPM (anti-clone, anti-root)."
                .to_string(),
        );
    }
    let name = sealed_node_identity_name(node_id);
    if !sealer.blob_exists(&name) {
        return Err(format!(
            "no sealed per-node identity blob '{name}'. Run the seal ceremony \
             (seal_node_identity_to_tpm) on THIS node before starting. A \
             KEK-derived/env fallback is forbidden in military mode."
        ));
    }
    let mut unsealed = sealer.unseal(&name).map_err(|e| {
        format!(
            "vTPM unseal of per-node identity '{name}' failed (PCR mismatch — \
             clone on different hardware — corrupt blob, or TPM error): {e}"
        )
    })?;
    if unsealed.len() != 32 {
        let len = unsealed.len();
        unsealed.zeroize();
        return Err(format!(
            "vTPM-unsealed per-node identity seed has wrong length {len} (expected 32)"
        ));
    }
    if unsealed.iter().all(|&b| b == 0) {
        unsealed.zeroize();
        return Err("vTPM-unsealed per-node identity seed is all-zero".to_string());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&unsealed);
    unsealed.zeroize();
    tracing::info!(
        target: "siem",
        "per-node ML-DSA-87 identity seed unsealed from vTPM '{}' (PCR-bound, \
         independent of KEK)",
        name,
    );
    Ok(seed)
}

/// Unified entry point for obtaining the master KEK.
///
/// Load hierarchy (most secure first):
/// 0. **Military mode**: vTPM-sealed KEK / share, bound to measured-boot PCRs.
///    This is the ONLY military path; env-sourced material is refused.
/// 1. Threshold KDF (distributed, KEK never in RAM) -- DEFAULT (non-military)
/// 2. Threshold reconstruction (distributed, KEK materializes briefly)
/// 3. Single env var ONLY if MLP mode acknowledged
///
/// In military mode: vTPM sealing is MANDATORY, no env bypass.
/// In production without MLP: single env var is rejected.
///
/// All services SHOULD use this function instead of calling `cached_master_kek()`
/// or `load_master_kek()` directly.
pub fn get_master_kek() -> &'static [u8; 32] {
    // Path 0: Military mode MUST source KEK material from the vTPM (anti-clone).
    // Returns Some(..) when military; refuses (exit 199) on any TPM failure or
    // if env-sourced KEK material is present. Returns None when not military, in
    // which case we fall through to the unchanged legacy hierarchy below.
    if let Some(kek) = acquire_military_kek(&Tpm2ToolsKekSealer::from_env()) {
        return kek;
    }

    // NOTE: In military mode, Path 0 above has already returned (Some) or
    // refused (exit 199), so execution only reaches here in NON-military mode.
    // The `is_military` guards below are retained as defense-in-depth: a
    // belt-and-suspenders fail-closed backstop should Path 0 ever be altered.
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

// ===========================================================================
// C2: 2-of-3 KEK Threshold Unseal (HSM-backed + UDS dev fallback)
// ===========================================================================
//
// CRITICAL PROPERTY: the master KEK is NEVER held by any single entity. It is
// always reconstructed 2-of-3 at the moment of use, from:
//
//   - Production (military mode): three independent PKCS#11 HSM slots, each
//     holding one Shamir share of the KEK. Any two slots can unseal.
//     Implemented via the `cryptoki` crate (workspace feature `cac`).
//
//   - Non-HSM dev: three helper processes, each bound to an authenticated
//     Unix Domain Socket on tmpfs. Each helper serves one share; the client
//     verifies the helper's identity via SO_PEERCRED (uid + pid), then
//     collects 2 partial shares and runs Shamir reconstruction locally.
//
// In military mode, the UDS fallback is refused: process aborts if no HSM
// backend is configured.
//
// The outputs of both backends are indistinguishable to downstream callers —
// each returns the fully reconstructed 32-byte KEK plus a domain-tagged
// verification hash used by the KEK canary path.

/// Environment variables consulted by the 2-of-3 unseal path.
///
/// - `MILNET_KEK2OF3_BACKEND`    : `pkcs11` (default in military) or `uds`
/// - `MILNET_KEK2OF3_PKCS11_LIB` : path to the PKCS#11 library (.so)
/// - `MILNET_KEK2OF3_PKCS11_SLOTS`: comma-separated list of 3 slot ids
/// - `MILNET_KEK2OF3_PKCS11_PINS`: comma-separated list of 3 slot PINs
/// - `MILNET_KEK2OF3_UDS_PATHS`  : comma-separated list of 3 UDS paths
/// - `MILNET_KEK2OF3_UDS_UIDS`   : comma-separated list of 3 expected helper uids
///
/// Exactly 3 entries required in each slot/pin/path list. Threshold is 2.
const C2_THRESHOLD: u8 = 2;
const C2_TOTAL: u8 = 3;

/// The result of a 2-of-3 unseal: the 32-byte KEK plus an audit tag.
pub struct KekUnsealResult {
    pub kek: [u8; 32],
    /// Domain-tagged SHA-512 of the KEK for canary / verification.
    pub verify_hash: [u8; 64],
    pub backend: &'static str,
}

impl Zeroize for KekUnsealResult {
    fn zeroize(&mut self) {
        self.kek.zeroize();
        self.verify_hash.zeroize();
    }
}

impl Drop for KekUnsealResult {
    fn drop(&mut self) {
        self.kek.zeroize();
    }
}

fn is_military_mode() -> bool {
    std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1")
}

fn kek_verify_hash(kek: &[u8; 32]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(b"MILNET-KEK-2OF3-VERIFY-v1");
    h.update(kek);
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// Perform a 2-of-3 KEK unseal. Returns the reconstructed KEK.
///
/// In military mode: requires PKCS#11 backend. Panics if unavailable.
/// Outside military mode: falls back to UDS helpers if PKCS#11 is not configured.
pub fn unseal_kek_2of3() -> Result<KekUnsealResult, String> {
    let backend = std::env::var("MILNET_KEK2OF3_BACKEND")
        .unwrap_or_else(|_| {
            if is_military_mode() { "pkcs11".to_string() } else { "uds".to_string() }
        });

    match backend.as_str() {
        "pkcs11" | "hsm" => {
            #[cfg(feature = "cac")]
            {
                return unseal_kek_2of3_pkcs11();
            }
            #[cfg(not(feature = "cac"))]
            {
                if is_military_mode() {
                    tracing::error!(
                        "C2 FATAL: military mode requires PKCS#11 HSM backend for 2-of-3 KEK unseal, \
                         but this binary was built without the `cac` feature. Refusing to start."
                    );
                    crate::siem::SecurityEvent::crypto_failure(
                        "military mode without PKCS#11 2-of-3 KEK backend: aborting",
                    );
                    std::process::exit(199);
                }
                tracing::warn!(
                    "C2: PKCS#11 backend requested but `cac` feature not compiled; \
                     falling back to UDS helpers (dev only)"
                );
                return unseal_kek_2of3_uds();
            }
        }
        "uds" => {
            if is_military_mode() {
                tracing::error!(
                    "C2 FATAL: UDS fallback for 2-of-3 KEK unseal is FORBIDDEN in military mode. \
                     Configure MILNET_KEK2OF3_BACKEND=pkcs11 with HSM slots."
                );
                crate::siem::SecurityEvent::crypto_failure(
                    "UDS KEK fallback attempted in military mode: aborting",
                );
                std::process::exit(199);
            }
            unseal_kek_2of3_uds()
        }
        other => Err(format!("unknown MILNET_KEK2OF3_BACKEND: {other}")),
    }
}

/// Reconstruct the 32-byte KEK from 2-of-3 shares using the existing
/// Shamir implementation in `threshold_kek`.
///
/// SECURITY (audit common P1): every share is verified against the
/// `StandaloneVssCommitments` (loaded from `MILNET_VSS_COMMITMENTS`, the
/// same source the threshold-KDF path uses) BEFORE reconstruction. Without
/// this, a single malicious or corrupted PKCS#11 slot / UDS helper could
/// hand back a bad share and silently poison the reconstructed KEK —
/// `reconstruct_secret` performs no commitment check of its own. A share
/// that fails verification aborts reconstruction (fail closed).
fn reconstruct_2of3(shares: Vec<crate::threshold_kek::KekShare>) -> Result<[u8; 32], String> {
    if shares.len() < C2_THRESHOLD as usize {
        return Err(format!(
            "need at least {} shares, got {}",
            C2_THRESHOLD,
            shares.len()
        ));
    }
    let chosen = &shares[..C2_THRESHOLD as usize];
    for share in chosen {
        if !verify_share_commitment(share) {
            return Err(
                "C2 2-of-3: a KEK share failed VSS commitment verification — \
                 refusing to reconstruct a potentially poisoned KEK".to_string(),
            );
        }
    }
    crate::threshold_kek::reconstruct_secret(chosen)
}

// --- PKCS#11 backend (feature = "cac") ----------------------------------

#[cfg(feature = "cac")]
fn unseal_kek_2of3_pkcs11() -> Result<KekUnsealResult, String> {
    use cryptoki::context::{CInitializeArgs, Pkcs11};

    let lib_path = std::env::var("MILNET_KEK2OF3_PKCS11_LIB")
        .map_err(|_| "MILNET_KEK2OF3_PKCS11_LIB not set".to_string())?;
    let slots_csv = std::env::var("MILNET_KEK2OF3_PKCS11_SLOTS")
        .map_err(|_| "MILNET_KEK2OF3_PKCS11_SLOTS not set".to_string())?;
    let pins_csv = std::env::var("MILNET_KEK2OF3_PKCS11_PINS")
        .map_err(|_| "MILNET_KEK2OF3_PKCS11_PINS not set".to_string())?;

    let slot_ids: Vec<u64> = slots_csv
        .split(',')
        .map(|s| s.trim().parse::<u64>().map_err(|e| format!("bad slot id: {e}")))
        .collect::<Result<_, _>>()?;
    let pins: Vec<String> = pins_csv.split(',').map(|s| s.trim().to_string()).collect();

    if slot_ids.len() != C2_TOTAL as usize || pins.len() != C2_TOTAL as usize {
        return Err(format!(
            "PKCS#11 2-of-3 requires exactly {} slots and {} pins",
            C2_TOTAL, C2_TOTAL
        ));
    }

    let pkcs11 = Pkcs11::new(&lib_path)
        .map_err(|e| format!("Pkcs11::new({lib_path}): {e}"))?;
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .map_err(|e| format!("PKCS#11 initialize: {e}"))?;

    // Try to read all 3 shares; stop after 2 successes (threshold met).
    let mut shares: Vec<crate::threshold_kek::KekShare> = Vec::new();
    let mut slot_errors: Vec<String> = Vec::new();

    for (i, (&slot_id, pin)) in slot_ids.iter().zip(pins.iter()).enumerate() {
        let share_index = (i as u8) + 1;
        match read_share_from_pkcs11_slot(&pkcs11, slot_id, pin, share_index) {
            Ok(share) => {
                shares.push(share);
                if shares.len() >= C2_THRESHOLD as usize {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(
                    "C2: PKCS#11 slot {slot_id} (share {share_index}) unavailable: {e}"
                );
                slot_errors.push(format!("slot {slot_id}: {e}"));
            }
        }
    }

    if shares.len() < C2_THRESHOLD as usize {
        return Err(format!(
            "PKCS#11 2-of-3 KEK unseal FAILED: only {} shares available (need {}). Errors: {}",
            shares.len(),
            C2_THRESHOLD,
            slot_errors.join("; ")
        ));
    }

    let kek = reconstruct_2of3(shares)?;
    let verify_hash = kek_verify_hash(&kek);
    tracing::info!(
        "C2: KEK reconstructed via 2-of-3 PKCS#11 HSM unseal (slots used: {})",
        C2_THRESHOLD
    );
    Ok(KekUnsealResult {
        kek,
        verify_hash,
        backend: "pkcs11",
    })
}

#[cfg(feature = "cac")]
fn read_share_from_pkcs11_slot(
    pkcs11: &cryptoki::context::Pkcs11,
    slot_id: u64,
    pin: &str,
    share_index: u8,
) -> Result<crate::threshold_kek::KekShare, String> {
    use cryptoki::object::{Attribute, AttributeType};
    use cryptoki::session::UserType;
    use cryptoki::slot::Slot;
    use cryptoki::types::AuthPin;

    let slot = Slot::try_from(slot_id).map_err(|e| format!("invalid slot {slot_id}: {e}"))?;
    let session = pkcs11
        .open_ro_session(slot)
        .map_err(|e| format!("open_ro_session({slot_id}): {e}"))?;
    session
        .login(UserType::User, Some(&AuthPin::new(pin.to_string())))
        .map_err(|e| format!("login({slot_id}): {e}"))?;

    // We store each share as a DATA object labelled
    // "MILNET-KEK-SHARE-v1:<share_index>" containing postcard-serialised
    // `KekShare` bytes.
    let label = format!("MILNET-KEK-SHARE-v1:{}", share_index);
    let template = vec![Attribute::Label(label.clone().into_bytes())];
    let handles = session
        .find_objects(&template)
        .map_err(|e| format!("find_objects({label}): {e}"))?;
    let handle = *handles
        .first()
        .ok_or_else(|| format!("no share object with label {label}"))?;
    let attrs = session
        .get_attributes(handle, &[AttributeType::Value])
        .map_err(|e| format!("get_attributes({label}): {e}"))?;
    let value = attrs
        .into_iter()
        .find_map(|a| if let Attribute::Value(v) = a { Some(v) } else { None })
        .ok_or_else(|| format!("DATA object {label} has no CKA_VALUE"))?;

    let hex_str = std::str::from_utf8(&value)
        .map_err(|e| format!("slot {slot_id} CKA_VALUE not valid UTF-8 hex: {e}"))?;
    let share = crate::threshold_kek::KekShare::from_hex(hex_str.trim())
        .map_err(|e| format!("parse KekShare from slot {slot_id}: {e}"))?;
    if share.index != share_index {
        return Err(format!(
            "slot {slot_id} label says share {share_index} but stored share index is {}",
            share.index
        ));
    }
    Ok(share)
}

// --- UDS helper backend (dev only) --------------------------------------

fn unseal_kek_2of3_uds() -> Result<KekUnsealResult, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let paths_csv = std::env::var("MILNET_KEK2OF3_UDS_PATHS")
        .map_err(|_| "MILNET_KEK2OF3_UDS_PATHS not set".to_string())?;
    let uids_csv = std::env::var("MILNET_KEK2OF3_UDS_UIDS")
        .map_err(|_| "MILNET_KEK2OF3_UDS_UIDS not set".to_string())?;

    let paths: Vec<String> = paths_csv.split(',').map(|s| s.trim().to_string()).collect();
    let uids: Vec<u32> = uids_csv
        .split(',')
        .map(|s| s.trim().parse::<u32>().map_err(|e| format!("bad uid: {e}")))
        .collect::<Result<_, _>>()?;

    if paths.len() != C2_TOTAL as usize || uids.len() != C2_TOTAL as usize {
        return Err(format!(
            "UDS 2-of-3 requires exactly {} paths and {} uids",
            C2_TOTAL, C2_TOTAL
        ));
    }

    let mut shares: Vec<crate::threshold_kek::KekShare> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for (i, (path, &expected_uid)) in paths.iter().zip(uids.iter()).enumerate() {
        let share_index = (i as u8) + 1;
        let mut stream = match UnixStream::connect(path) {
            Ok(s) => s,
            Err(e) => {
                errors.push(format!("connect {path}: {e}"));
                continue;
            }
        };

        if let Err(e) = verify_peer_credentials(&stream, expected_uid) {
            errors.push(format!("{path}: SO_PEERCRED check failed: {e}"));
            continue;
        }

        // Protocol: send request, receive (index:u8 || share_bytes_len:u16 || share_bytes)
        let request = format!("GET_SHARE:{share_index}\n");
        if let Err(e) = stream.write_all(request.as_bytes()) {
            errors.push(format!("{path}: write: {e}"));
            continue;
        }
        // Response: ASCII hex share (66 chars = 2 index + 64 value), newline-terminated.
        let mut body = vec![0u8; 128];
        let n = match stream.read(&mut body) {
            Ok(n) => n,
            Err(e) => {
                errors.push(format!("{path}: read body: {e}"));
                continue;
            }
        };
        body.truncate(n);
        let hex_str = match std::str::from_utf8(&body) {
            Ok(s) => s.trim(),
            Err(e) => {
                errors.push(format!("{path}: not valid utf-8: {e}"));
                continue;
            }
        };
        let share = match crate::threshold_kek::KekShare::from_hex(hex_str) {
            Ok(s) => s,
            Err(e) => {
                errors.push(format!("{path}: parse KekShare: {e}"));
                continue;
            }
        };
        if share.index != share_index {
            errors.push(format!(
                "{path}: serialized share index {} != expected {share_index}",
                share.index
            ));
            continue;
        }
        shares.push(share);
        if shares.len() >= C2_THRESHOLD as usize {
            break;
        }
    }

    if shares.len() < C2_THRESHOLD as usize {
        return Err(format!(
            "UDS 2-of-3 KEK unseal FAILED: {} shares (need {}). Errors: {}",
            shares.len(),
            C2_THRESHOLD,
            errors.join("; ")
        ));
    }

    let kek = reconstruct_2of3(shares)?;
    let verify_hash = kek_verify_hash(&kek);
    tracing::info!(
        "C2: KEK reconstructed via 2-of-3 UDS dev helpers (dev mode only)"
    );
    Ok(KekUnsealResult {
        kek,
        verify_hash,
        backend: "uds",
    })
}

/// SO_PEERCRED verification on a Unix socket. Rejects if the peer uid
/// does not match `expected_uid`.
fn verify_peer_credentials(
    stream: &std::os::unix::net::UnixStream,
    expected_uid: u32,
) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;

    // Safety: libc::getsockopt with SO_PEERCRED is the canonical way to
    // obtain the peer's (pid, uid, gid) on a connected UDS on Linux. We
    // treat the socket fd as borrowed; the struct ucred is POD.
    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    let fd = stream.as_raw_fd();
    let mut cred = Ucred { pid: 0, uid: u32::MAX, gid: u32::MAX };
    let mut len = std::mem::size_of::<Ucred>() as libc::socklen_t;

    // SAFETY: fd is borrowed from an owned UnixStream; &mut cred points to
    // a valid Ucred-sized region; len is initialised to its size. The call
    // writes into cred and len only, and returns a C int.
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
            "getsockopt(SO_PEERCRED) failed: errno {}",
            std::io::Error::last_os_error()
        ));
    }
    if cred.uid != expected_uid {
        return Err(format!(
            "peer uid {} != expected {} (pid {})",
            cred.uid, expected_uid, cred.pid
        ));
    }
    Ok(())
}

/// Verify that the peer of a connected Unix socket is a trusted local
/// identity: either `root` (uid 0) or the same effective uid as this
/// process. Used by the secret loader to authenticate the secrets daemon
/// it connects to, so an unprivileged process that managed to bind a
/// look-alike socket cannot serve forged secrets.
pub(crate) fn verify_uds_peer_is_trusted(
    stream: &std::os::unix::net::UnixStream,
) -> Result<(), String> {
    // SAFETY: geteuid() is a pure syscall taking no arguments and returning
    // the caller's effective uid; it cannot violate memory safety.
    let our_euid = unsafe { libc::geteuid() };
    if verify_peer_credentials(stream, 0).is_ok() {
        return Ok(());
    }
    verify_peer_credentials(stream, our_euid)
        .map_err(|e| format!("secrets socket peer is neither root nor our own uid: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // -----------------------------------------------------------------------
    // Software TPM test double
    // -----------------------------------------------------------------------
    //
    // Simulates the anti-clone PCR binding of a real vTPM WITHOUT hardware, so
    // the gating decisions are testable in CI. Each seal captures the sealer's
    // current "PCR value"; unseal succeeds ONLY if the live PCR value still
    // matches. Mutating `pcr` models a clone on different hardware / a changed
    // boot chain: the captured policy no longer matches and unseal fails closed,
    // exactly like `tpm2_unseal` rejecting a mismatched `tpm2_policypcr` digest.
    // `team-lead` exercises the REAL `Tpm2ToolsKekSealer` against swtpm on OCI.
    struct SoftwareTpmSealer {
        present: bool,
        /// Simulated PCR bank value (changes ⇒ different hardware / boot chain).
        pcr: Mutex<u64>,
        /// name -> (pcr_at_seal, plaintext)
        store: Mutex<HashMap<String, (u64, Vec<u8>)>>,
    }

    impl SoftwareTpmSealer {
        fn new(present: bool) -> Self {
            Self {
                present,
                pcr: Mutex::new(0xA11CE),
                store: Mutex::new(HashMap::new()),
            }
        }
        /// Simulate a clone on different hardware: PCR values differ.
        fn change_pcr(&self) {
            *self.pcr.lock().unwrap() = 0xDEAD_BEEF;
        }
    }

    impl TpmKekSealer for SoftwareTpmSealer {
        fn seal(&self, name: &str, secret: &[u8]) -> Result<(), String> {
            if !self.present {
                return Err("software TPM: not present".into());
            }
            let pcr = *self.pcr.lock().unwrap();
            self.store
                .lock()
                .unwrap()
                .insert(name.to_string(), (pcr, secret.to_vec()));
            Ok(())
        }
        fn unseal(&self, name: &str) -> Result<Vec<u8>, String> {
            if !self.present {
                return Err("software TPM: not present".into());
            }
            let store = self.store.lock().unwrap();
            let (sealed_pcr, data) = store
                .get(name)
                .ok_or_else(|| format!("software TPM: no sealed blob '{name}'"))?;
            let live_pcr = *self.pcr.lock().unwrap();
            if *sealed_pcr != live_pcr {
                // Clone on different hardware: PCR policy not satisfied.
                return Err(format!(
                    "software TPM: PCR mismatch for '{name}' (sealed={sealed_pcr:#x}, \
                     live={live_pcr:#x}) — clone on different hardware, fail closed"
                ));
            }
            Ok(data.clone())
        }
        fn blob_exists(&self, name: &str) -> bool {
            self.present && self.store.lock().unwrap().contains_key(name)
        }
        fn tpm_available(&self) -> bool {
            self.present
        }
    }

    // -----------------------------------------------------------------------
    // PER-NODE IDENTITY SEED — TPM-sealed, INDEPENDENT of the KEK (anti-root)
    // -----------------------------------------------------------------------

    /// Ceremony seals an independent seed; the loader then UNSEALS the SAME seed.
    #[test]
    fn node_identity_ceremony_seal_then_load() {
        let sealer = SoftwareTpmSealer::new(true);
        let node = "00000000-0000-0000-0000-00000000000a";

        // No blob before the ceremony.
        assert!(!sealer.blob_exists(&sealed_node_identity_name(node)));

        let sealed = seal_node_identity_to_tpm(&sealer, node).expect("ceremony should seal");
        assert!(sealed.iter().any(|&b| b != 0), "sealed seed must be non-zero");
        assert!(sealer.blob_exists(&sealed_node_identity_name(node)));

        // Loader unseals the SAME seed.
        let loaded = load_node_identity_seed_inner(&sealer, node).expect("load should unseal");
        assert_eq!(sealed, loaded, "loaded seed must equal the sealed seed");
    }

    /// FAIL-CLOSED: loading with NO prior ceremony (absent blob) refuses
    /// (unseal-only; never auto-generates at runtime).
    #[test]
    fn node_identity_load_absent_blob_fails_closed() {
        let sealer = SoftwareTpmSealer::new(true);
        let r = load_node_identity_seed_inner(&sealer, "node-x");
        assert!(r.is_err(), "absent per-node blob must fail closed");
        assert!(r.unwrap_err().contains("no sealed per-node identity blob"));
    }

    /// FAIL-CLOSED: no vTPM ⇒ both ceremony and loader refuse.
    #[test]
    fn node_identity_no_tpm_fails_closed() {
        let sealer = SoftwareTpmSealer::new(false);
        assert!(seal_node_identity_to_tpm(&sealer, "node-x").is_err());
        let r = load_node_identity_seed_inner(&sealer, "node-x");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("vTPM"));
    }

    /// FAIL-CLOSED: a clone on different hardware cannot unseal (PCR mismatch).
    #[test]
    fn node_identity_clone_pcr_mismatch_fails_closed() {
        let sealer = SoftwareTpmSealer::new(true);
        let node = "node-clone";
        let _ = seal_node_identity_to_tpm(&sealer, node).expect("seal on original hardware");
        // Move the sealed blob to different hardware.
        sealer.change_pcr();
        let r = load_node_identity_seed_inner(&sealer, node);
        assert!(r.is_err(), "clone on different hardware must fail closed");
        assert!(r.unwrap_err().contains("PCR mismatch"));
    }

    /// Two DIFFERENT nodes get INDEPENDENT seeds AND distinct per-node blob names.
    /// This is the anti-root property: root on one node yields only that node's
    /// seed (no shared derivation, no shared blob).
    #[test]
    fn node_identity_seeds_independent_across_nodes() {
        let sealer = SoftwareTpmSealer::new(true);
        let seed_a = seal_node_identity_to_tpm(&sealer, "node-a").unwrap();
        let seed_b = seal_node_identity_to_tpm(&sealer, "node-b").unwrap();
        assert_ne!(seed_a, seed_b, "independent per-node seeds must differ");
        assert_ne!(
            sealed_node_identity_name("node-a"),
            sealed_node_identity_name("node-b"),
            "per-node blob names must differ"
        );
        // Each node loads its OWN seed.
        assert_eq!(load_node_identity_seed_inner(&sealer, "node-a").unwrap(), seed_a);
        assert_eq!(load_node_identity_seed_inner(&sealer, "node-b").unwrap(), seed_b);
    }

    /// The per-node blob name is `node-identity-<node_id>`.
    #[test]
    fn node_identity_blob_name_is_per_node() {
        assert_eq!(sealed_node_identity_name("abc"), "node-identity-abc");
    }

    // -----------------------------------------------------------------------
    // GATING DECISION TABLE — the security core (pure, no process::exit)
    // -----------------------------------------------------------------------

    #[test]
    fn decision_non_military_passes_through() {
        // Not military ⇒ legacy hierarchy, regardless of TPM/env state.
        let d = decide_military_kek_source(
            false, true, true, false, SealedKekMode::Share, false, false,
        );
        assert_eq!(d, MilitaryKekDecision::NotMilitary);
    }

    #[test]
    fn decision_military_with_env_master_kek_refuses() {
        // SECURITY: env-sourced master KEK in military mode MUST be refused,
        // NEVER consumed (a clone carries the same env var). This is the heart
        // of the anti-clone fix.
        let d = decide_military_kek_source(
            true, /*master_in_env=*/ true, false, true, SealedKekMode::SingleKek, true, true,
        );
        assert!(
            matches!(d, MilitaryKekDecision::RefuseEnvMaterialPresent { .. }),
            "env master KEK in military mode must refuse, got {d:?}"
        );
    }

    #[test]
    fn decision_military_with_env_share_refuses() {
        // Even though a share would normally drive threshold KDF, in military
        // mode the share MUST come from the TPM, not the environment.
        let d = decide_military_kek_source(
            true, false, /*share_in_env=*/ true, true, SealedKekMode::Share, true, true,
        );
        assert!(
            matches!(d, MilitaryKekDecision::RefuseEnvMaterialPresent { .. }),
            "env KEK share in military mode must refuse, got {d:?}"
        );
    }

    #[test]
    fn decision_env_material_refused_even_before_tpm_check() {
        // Ordering guarantee: env material is rejected even when there is NO
        // TPM and NO blob — we must not "fall back" to env under any condition.
        let d = decide_military_kek_source(
            true, true, false, /*tpm=*/ false, SealedKekMode::SingleKek, false, false,
        );
        assert!(matches!(
            d,
            MilitaryKekDecision::RefuseEnvMaterialPresent { .. }
        ));
    }

    #[test]
    fn decision_military_no_tpm_refuses() {
        let d = decide_military_kek_source(
            true, false, false, /*tpm=*/ false, SealedKekMode::Share, false, false,
        );
        assert_eq!(d, MilitaryKekDecision::RefuseNoTpm);
    }

    #[test]
    fn decision_military_missing_blob_refuses() {
        // TPM present, no env material, but the seal ceremony never ran.
        let d = decide_military_kek_source(
            true, false, false, true, SealedKekMode::Share,
            /*single_blob=*/ false, /*share_blob=*/ false,
        );
        assert_eq!(
            d,
            MilitaryKekDecision::RefuseSealedBlobMissing { mode: SealedKekMode::Share }
        );
    }

    #[test]
    fn decision_share_mode_ignores_single_blob_presence() {
        // Share mode requires the SHARE blob; a stray single blob must not
        // satisfy it.
        let d = decide_military_kek_source(
            true, false, false, true, SealedKekMode::Share,
            /*single_blob=*/ true, /*share_blob=*/ false,
        );
        assert_eq!(
            d,
            MilitaryKekDecision::RefuseSealedBlobMissing { mode: SealedKekMode::Share }
        );
    }

    #[test]
    fn decision_military_share_proceeds_when_ready() {
        let d = decide_military_kek_source(
            true, false, false, true, SealedKekMode::Share, false, /*share_blob=*/ true,
        );
        assert_eq!(d, MilitaryKekDecision::Proceed { mode: SealedKekMode::Share });
    }

    #[test]
    fn decision_military_single_proceeds_when_ready() {
        let d = decide_military_kek_source(
            true, false, false, true, SealedKekMode::SingleKek, /*single_blob=*/ true, false,
        );
        assert_eq!(d, MilitaryKekDecision::Proceed { mode: SealedKekMode::SingleKek });
    }

    // -----------------------------------------------------------------------
    // Software-TPM seal/unseal round-trip + clone (PCR mismatch) rejection
    // -----------------------------------------------------------------------

    #[test]
    fn software_tpm_single_kek_round_trip() {
        let tpm = SoftwareTpmSealer::new(true);
        let kek = [0x5Au8; 32];
        seal_master_kek_to_tpm(&tpm, SealedKekMode::SingleKek, &kek).unwrap();
        assert!(tpm.blob_exists(SEALED_KEK_SINGLE_NAME));
        let out = tpm.unseal(SEALED_KEK_SINGLE_NAME).unwrap();
        assert_eq!(out, kek.to_vec(), "unseal must recover the sealed KEK");
    }

    #[test]
    fn software_tpm_clone_on_different_hardware_fails_unseal() {
        // ANTI-CLONE: seal on this "hardware", then simulate a clone whose PCRs
        // differ. Unseal MUST fail closed — the whole point of the fix.
        let tpm = SoftwareTpmSealer::new(true);
        let kek = [0x33u8; 32];
        seal_master_kek_to_tpm(&tpm, SealedKekMode::SingleKek, &kek).unwrap();
        tpm.change_pcr(); // clone / different boot chain
        let err = tpm.unseal(SEALED_KEK_SINGLE_NAME).unwrap_err();
        assert!(err.contains("PCR mismatch"), "expected PCR mismatch, got: {err}");
    }

    #[test]
    fn seal_single_kek_rejects_wrong_length() {
        let tpm = SoftwareTpmSealer::new(true);
        let too_short = [0u8; 16];
        let err = seal_master_kek_to_tpm(&tpm, SealedKekMode::SingleKek, &too_short).unwrap_err();
        assert!(err.contains("32-byte"), "got: {err}");
    }

    #[test]
    fn seal_rejects_when_no_tpm() {
        let tpm = SoftwareTpmSealer::new(false);
        let kek = [0u8; 32];
        let err = seal_master_kek_to_tpm(&tpm, SealedKekMode::SingleKek, &kek).unwrap_err();
        assert!(err.contains("no vTPM"), "got: {err}");
    }

    #[test]
    fn seal_share_mode_validates_and_round_trips() {
        // Build a real KekShare and seal its hex form, then unseal it back.
        let shares = crate::threshold_kek::split_secret(&[0x77u8; 32], 3, 5).unwrap();
        let share_hex = shares[0].to_hex();
        let tpm = SoftwareTpmSealer::new(true);
        seal_master_kek_to_tpm(&tpm, SealedKekMode::Share, share_hex.as_bytes()).unwrap();
        assert!(tpm.blob_exists(SEALED_KEK_SHARE_NAME));
        let out = tpm.unseal(SEALED_KEK_SHARE_NAME).unwrap();
        assert_eq!(out, share_hex.as_bytes().to_vec());
        // And the unsealed bytes still parse as a share.
        let parsed = crate::threshold_kek::KekShare::from_hex(
            std::str::from_utf8(&out).unwrap().trim(),
        );
        assert!(parsed.is_ok());
    }

    #[test]
    fn seal_share_mode_rejects_garbage() {
        let tpm = SoftwareTpmSealer::new(true);
        let err = seal_master_kek_to_tpm(&tpm, SealedKekMode::Share, b"not-a-share").unwrap_err();
        assert!(err.contains("not a valid KekShare"), "got: {err}");
    }

    #[test]
    #[serial_test::serial]
    fn sealed_kek_mode_from_env_maps_correctly() {
        // Default posture is distributed (share), per military threshold policy.
        std::env::remove_var("MILNET_SEALED_KEK_MODE");
        assert_eq!(sealed_kek_mode_from_env(), SealedKekMode::Share);

        std::env::set_var("MILNET_SEALED_KEK_MODE", "single");
        assert_eq!(sealed_kek_mode_from_env(), SealedKekMode::SingleKek);

        std::env::set_var("MILNET_SEALED_KEK_MODE", "share");
        assert_eq!(sealed_kek_mode_from_env(), SealedKekMode::Share);

        // Unknown value falls back to the safe default (share).
        std::env::set_var("MILNET_SEALED_KEK_MODE", "bogus");
        assert_eq!(sealed_kek_mode_from_env(), SealedKekMode::Share);

        std::env::remove_var("MILNET_SEALED_KEK_MODE");
    }

    #[test]
    fn master_kek_pcr_list_is_measured_boot_set() {
        // Anti-clone binding uses the full measured-boot PCR set 0,2,4,7.
        assert_eq!(
            crate::platform_integrity::MASTER_KEK_PCR_LIST,
            "sha256:0,2,4,7"
        );
    }

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
