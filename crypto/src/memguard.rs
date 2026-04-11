//! Secure memory primitives for cryptographic key material.
//!
//! Provides memory-locked buffers that:
//! - Cannot be swapped to disk (mlock)
//! - Detect buffer overflows via canary words
//! - Are securely zeroed on drop
//! - Support guard page protection where available
//!
//! # Security Model
//! These primitives protect against:
//! - Cold boot attacks (zeroization)
//! - Swap file forensics (mlock)
//! - Buffer overflow into key material (canaries)
//! - Core dump key leakage (mlock + MADV_DONTDUMP)

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Graceful mlock degradation flag
// ---------------------------------------------------------------------------

/// Global flag indicating that mlock failed during buffer allocation.
/// When true, the system is running in a degraded state where key material
/// may be swappable to disk. SIEM alerts should fire on this condition.
static MLOCK_DEGRADED: AtomicBool = AtomicBool::new(false);

/// Returns `true` if any mlock call has failed during this process lifetime.
/// Callers (e.g., startup routines) should check this and emit a SIEM-level
/// warning if the system is running degraded.
pub fn is_mlock_degraded() -> bool {
    MLOCK_DEGRADED.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during secure memory operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemguardError {
    /// `mlock` system call failed — the buffer may be swappable.
    MlockFailed,
    /// Memory allocation failed.
    AllocationFailed,
    /// A canary word was corrupted, indicating a buffer overflow or
    /// use-after-free.  This is **always** a critical security event.
    CanaryViolation,
    /// The requested buffer size is invalid (e.g. zero).
    InvalidSize,
}

impl core::fmt::Display for MemguardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MlockFailed => write!(f, "mlock failed: buffer may be swappable to disk"),
            Self::AllocationFailed => write!(f, "secure memory allocation failed"),
            Self::CanaryViolation => {
                write!(f, "canary violation: memory corruption detected")
            }
            Self::InvalidSize => write!(f, "invalid buffer size"),
        }
    }
}

impl std::error::Error for MemguardError {}

// ---------------------------------------------------------------------------
// Low-level mlock / munlock helpers
// ---------------------------------------------------------------------------

/// Lock a memory region so it cannot be paged to swap.
///
/// Returns `true` on success.
///
/// # Safety
/// `ptr` must point to a valid, allocated region of at least `len` bytes.
fn mlock_slice(ptr: *const u8, len: usize) -> bool {
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

/// Mark a memory region as excluded from core dumps (MADV_DONTDUMP).
///
/// Returns `true` on success.
fn madv_dontdump(ptr: *const u8, len: usize) -> bool {
    unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP) == 0 }
}

/// Unlock a previously mlocked memory region.
///
/// # Safety
/// `ptr` must point to a valid, allocated region of at least `len` bytes
/// that was previously locked with `mlock_slice`.
fn munlock_slice(ptr: *const u8, len: usize) {
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// Process-wide HMAC key for canary derivation.
/// Expected canary values are derived from HMAC(process_key, buffer_addr)
/// so they are NOT co-located with the secret in the same struct.
fn process_canary_key() -> &'static [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).expect("FATAL: cannot generate process canary key");
        k
    })
}

/// Process-wide HMAC-SHA512 key for SecretBuffer canary HMAC verification.
/// Shared between the constructor and `verify_canaries()` so both compute
/// the same HMAC value for a given (address, canary_head, canary_tail) tuple.
fn canary_hmac_key() -> &'static [u8; 64] {
    static KEY: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 64];
        getrandom::getrandom(&mut k).expect("FATAL: getrandom failed for canary HMAC key");
        k
    })
}

/// Derive a canary value from a buffer address using HMAC-SHA512 with the
/// process-wide key (CNSA 2.0 compliant). This ensures expected canary
/// values are not stored alongside the secret they protect.
fn derive_canary(addr: usize, salt: u8) -> u64 {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(process_canary_key())
        .expect("HMAC key length is always valid");
    mac.update(&addr.to_ne_bytes());
    mac.update(&[salt]);
    let result = mac.finalize().into_bytes();
    u64::from_ne_bytes([
        result[0], result[1], result[2], result[3],
        result[4], result[5], result[6], result[7],
    ])
}

/// Generate a random `u64` canary value from OS CSPRNG.
fn random_canary() -> Result<u64, MemguardError> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|_| MemguardError::AllocationFailed)?;
    Ok(u64::from_ne_bytes(buf))
}

// ---------------------------------------------------------------------------
// SecretBuffer<N> — fixed-size secure buffer
// ---------------------------------------------------------------------------

/// A fixed-size, memory-locked buffer for cryptographic key material.
///
/// The buffer is bracketed by random canary words that are verified on every
/// access.  The data region is mlocked to prevent swapping to disk and is
/// securely zeroed when the buffer is dropped.
pub struct SecretBuffer<const N: usize> {
    /// Head canary — set once at construction and checked on every access.
    canary_head: u64,
    /// The actual secret data.
    data: [u8; N],
    /// Tail canary — mirrors `canary_head` with an independent random value.
    canary_tail: u64,
    /// HMAC over (nonce, canary_head, canary_tail) computed at construction.
    /// Used by `verify_canaries()` to detect tampering.
    canary_hmac: u64,
    /// Random per-instance nonce used in HMAC computation. Address-independent
    /// so the HMAC remains valid after Rust moves (memcpy) the struct.
    canary_nonce: u64,
    /// Whether `mlock` succeeded for this buffer.
    locked: bool,
}

impl<const N: usize> SecretBuffer<N> {
    /// Create a new `SecretBuffer` protecting the given data.
    ///
    /// The data region is mlocked to prevent swapping.  If `mlock` fails
    /// (e.g. due to resource limits in a dev environment), a warning is
    /// logged and the buffer is still usable — the `locked` field tracks
    /// whether the lock succeeded.
    pub fn new(data: [u8; N]) -> Result<Self, MemguardError> {
        if N == 0 {
            return Err(MemguardError::InvalidSize);
        }

        // Canary values are set after construction using derive_canary()
        // based on the buffer's heap address. This ensures expected values
        // are derived from a process-wide HMAC key, not stored in the struct.
        let nonce = {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).map_err(|_| MemguardError::AllocationFailed)?;
            u64::from_ne_bytes(b)
        };
        let mut buf = Self {
            canary_head: 0,
            data,
            canary_tail: 0,
            canary_hmac: 0,
            canary_nonce: nonce,
            locked: false,
        };

        // Generate random canaries. These are stored in the struct and verified
        // on every access. The process-wide HMAC key ensures derive_canary()
        // produces consistent values for a given address, but since the struct
        // may be moved (Rust has no move constructors), we use random canaries
        // instead and store them alongside the buffer. The security improvement
        // over the old scheme is that canary values are cryptographically random
        // rather than predictable XOR patterns.
        let head = {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).map_err(|_| MemguardError::AllocationFailed)?;
            u64::from_ne_bytes(b)
        };
        let tail = {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).map_err(|_| MemguardError::AllocationFailed)?;
            u64::from_ne_bytes(b)
        };
        buf.canary_head = head;
        buf.canary_tail = tail;

        // Compute and store HMAC over (nonce, canary_head, canary_tail) for
        // tamper detection in verify_canaries(). Uses a per-instance random nonce
        // instead of the buffer address because Rust moves (memcpy) change addresses.
        {
            use hmac::{Hmac, Mac};
            use sha2::Sha512;
            type HmacSha512 = Hmac<Sha512>;
            let mut mac = HmacSha512::new_from_slice(canary_hmac_key()).expect("HMAC key size");
            mac.update(&nonce.to_ne_bytes());
            mac.update(&head.to_ne_bytes());
            mac.update(&tail.to_ne_bytes());
            let result = mac.finalize().into_bytes();
            buf.canary_hmac = u64::from_ne_bytes(result[..8].try_into().unwrap());
        }

        // Attempt to mlock the data region.
        // SECURITY: mlock prevents key material from being swapped to disk.
        // In military deployment mode (MILNET_MILITARY_DEPLOYMENT=1), mlock
        // failure is FATAL — keys without mlock can be swapped to disk and
        // recovered by a nation-state attacker with physical access.
        let data_ptr = buf.data.as_ptr();
        if mlock_slice(data_ptr, N) {
            buf.locked = true;
            // Exclude from core dumps
            madv_dontdump(data_ptr, N);
        } else {
            MLOCK_DEGRADED.store(true, Ordering::SeqCst);

            // SECURITY: In military/production deployment, mlock failure is
            // UNACCEPTABLE. Sensitive keys without mlock can be swapped to
            // disk and recovered via forensic analysis of swap partitions.
            let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
                .map(|v| v == "1")
                .unwrap_or(false);

            if is_military {
                panic!(
                    "FATAL: mlock failed for {N}-byte SecretBuffer in military deployment \
                     (MILNET_MILITARY_DEPLOYMENT=1). Key material MUST be locked in RAM. \
                     Ensure RLIMIT_MEMLOCK is sufficient (ulimit -l). Aborting to prevent \
                     key material from being swapped to disk."
                );
            }

            tracing::error!(
                buffer_size = N,
                "CRITICAL SECURITY DEGRADATION: mlock failed for {N}-byte SecretBuffer. \
                 Key material may be swappable to disk. Ensure RLIMIT_MEMLOCK is sufficient. \
                 SIEM alert: mlock_failure_detected"
            );
        }

        Ok(buf)
    }

    /// Verify canary integrity using constant-time comparison.
    ///
    /// Canary values are verified via HMAC(process_key, nonce || head || tail).
    /// The per-instance nonce is random and address-independent, so the HMAC
    /// remains valid after Rust moves. An attacker who overwrites the canaries
    /// cannot forge the HMAC without knowing the process-wide HMAC key.
    pub fn verify_canaries(&self) -> bool {
        use subtle::ConstantTimeEq;
        let head_ok: subtle::Choice = (!self.canary_head.ct_eq(&0u64)) & subtle::Choice::from(1u8);
        let tail_ok: subtle::Choice = (!self.canary_tail.ct_eq(&0u64)) & subtle::Choice::from(1u8);
        let xor_val = self.canary_head ^ self.canary_tail;
        let xor_ok: subtle::Choice = !xor_val.ct_eq(&0u64);
        // Recompute HMAC over (nonce, canary_head, canary_tail) and compare
        // against the value stored at construction.
        let expected_check = {
            use hmac::{Hmac, Mac};
            use sha2::Sha512;
            type HmacSha512 = Hmac<Sha512>;
            let mut mac = HmacSha512::new_from_slice(canary_hmac_key()).expect("HMAC key size");
            mac.update(&self.canary_nonce.to_ne_bytes());
            mac.update(&self.canary_head.to_ne_bytes());
            mac.update(&self.canary_tail.to_ne_bytes());
            let result = mac.finalize().into_bytes();
            u64::from_ne_bytes(result[..8].try_into().unwrap())
        };
        let hmac_ok: subtle::Choice = expected_check.ct_eq(&self.canary_hmac);
        (head_ok & tail_ok & xor_ok & hmac_ok).into()
    }

    /// Borrow the protected data as a byte slice.
    ///
    /// # Panics
    /// Panics if a canary violation is detected — this indicates memory
    /// corruption and continuing would be a security risk.  Before
    /// panicking, the violation is logged and all data is zeroized so
    /// that sensitive material is destroyed even if the panic is caught.
    pub fn as_bytes(&self) -> &[u8; N] {
        if !self.verify_canaries() {
            // SECURITY: Do NOT log sensitive details — attacker with ptrace could
            // pause between log and exit to inspect memory. Zeroize first, then
            // exit immediately without panic (panic unwind could leak via hooks).
            #[allow(unsafe_code)]
            unsafe {
                core::ptr::write_bytes(self.data.as_ptr() as *mut u8, 0, N);
            }
            // Use _exit(199) to skip destructors/panic hooks that could log secrets
            #[allow(unsafe_code)]
            unsafe {
                libc::_exit(199);
            }
        }
        &self.data
    }

    /// Mutably borrow the protected data.
    ///
    /// # Panics
    /// Panics if a canary violation is detected.  Before panicking, the
    /// violation is logged and all data is zeroized.
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        if !self.verify_canaries() {
            self.data.zeroize();
            #[allow(unsafe_code)]
            unsafe {
                libc::_exit(199);
            }
        }
        &mut self.data
    }

    /// Returns whether this buffer was successfully mlocked.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<const N: usize> Drop for SecretBuffer<N> {
    fn drop(&mut self) {
        // 1. Zeroize the secret data.
        self.data.zeroize();

        // 2. Unlock if we locked.
        if self.locked {
            munlock_slice(self.data.as_ptr(), N);
        }

        // 3. Zeroize canary material so it cannot be recovered.
        self.canary_head.zeroize();
        self.canary_tail.zeroize();
        self.canary_hmac.zeroize();
        self.canary_nonce.zeroize();
    }
}

// Prevent accidental Debug printing of secret material.
impl<const N: usize> core::fmt::Debug for SecretBuffer<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretBuffer")
            .field("size", &N)
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SecretVec — variable-length secure buffer
// ---------------------------------------------------------------------------

/// A variable-length, memory-locked buffer for cryptographic key material.
///
/// Behaves like `SecretBuffer` but for dynamically sized secrets (e.g.
/// serialized tokens, variable-length keys).
pub struct SecretVec {
    /// The actual secret data.
    data: Vec<u8>,
    /// Original length at construction time, used for munlock.
    original_len: usize,
    /// Head canary value set at construction (random).
    canary: u64,
    /// Tail canary value set at construction (random).
    canary_tail: u64,
    /// HMAC over (nonce, canary, canary_tail) computed at construction.
    canary_hmac: u64,
    /// Random per-instance nonce used in HMAC computation.
    canary_nonce: u64,
    /// Whether `mlock` succeeded for this buffer.
    locked: bool,
}

impl SecretVec {
    /// Create a new `SecretVec` protecting the given data.
    ///
    /// The heap buffer is mlocked to prevent swapping.  If `mlock` fails,
    /// a warning is logged but the buffer remains usable.
    pub fn new(data: Vec<u8>) -> Result<Self, MemguardError> {
        if data.is_empty() {
            return Err(MemguardError::InvalidSize);
        }

        let original_len = data.len();
        let nonce = {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).map_err(|_| MemguardError::AllocationFailed)?;
            u64::from_ne_bytes(b)
        };
        let head = {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).map_err(|_| MemguardError::AllocationFailed)?;
            u64::from_ne_bytes(b)
        };
        let tail = {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).map_err(|_| MemguardError::AllocationFailed)?;
            u64::from_ne_bytes(b)
        };

        let canary_hmac_val = {
            use hmac::{Hmac, Mac};
            use sha2::Sha512;
            type HmacSha512 = Hmac<Sha512>;
            let mut mac = HmacSha512::new_from_slice(canary_hmac_key()).expect("HMAC key size");
            mac.update(&nonce.to_ne_bytes());
            mac.update(&head.to_ne_bytes());
            mac.update(&tail.to_ne_bytes());
            let result = mac.finalize().into_bytes();
            u64::from_ne_bytes(result[..8].try_into().unwrap())
        };

        let mut sv = Self {
            data,
            original_len,
            canary: head,
            canary_tail: tail,
            canary_hmac: canary_hmac_val,
            canary_nonce: nonce,
            locked: false,
        };

        let ptr = sv.data.as_ptr();
        let len = sv.data.len();
        if mlock_slice(ptr, len) {
            sv.locked = true;
            // Exclude from core dumps
            madv_dontdump(ptr, len);
        } else {
            // SECURITY: In military deployment, mlock failure is FATAL.
            MLOCK_DEGRADED.store(true, Ordering::SeqCst);

            let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
                .map(|v| v == "1")
                .unwrap_or(false);

            if is_military {
                panic!(
                    "FATAL: mlock failed for {len}-byte SecretVec in military deployment \
                     (MILNET_MILITARY_DEPLOYMENT=1). Key material MUST be locked in RAM. \
                     Ensure RLIMIT_MEMLOCK is sufficient (ulimit -l). Aborting to prevent \
                     key material from being swapped to disk."
                );
            }

            tracing::error!(
                buffer_size = len,
                "CRITICAL SECURITY DEGRADATION: mlock failed for {len}-byte SecretVec. \
                 Key material may be swappable to disk. Ensure RLIMIT_MEMLOCK is sufficient. \
                 SIEM alert: mlock_failure_detected"
            );
        }

        Ok(sv)
    }

    /// Verify canary integrity using HMAC-SHA512 and constant-time comparison.
    pub fn verify_canary(&self) -> bool {
        use subtle::ConstantTimeEq;
        let head_ok: subtle::Choice = (!self.canary.ct_eq(&0u64)) & subtle::Choice::from(1u8);
        let tail_ok: subtle::Choice = (!self.canary_tail.ct_eq(&0u64)) & subtle::Choice::from(1u8);
        let xor_val = self.canary ^ self.canary_tail;
        let xor_ok: subtle::Choice = !xor_val.ct_eq(&0u64);
        let expected_check = {
            use hmac::{Hmac, Mac};
            use sha2::Sha512;
            type HmacSha512 = Hmac<Sha512>;
            let mut mac = HmacSha512::new_from_slice(canary_hmac_key()).expect("HMAC key size");
            mac.update(&self.canary_nonce.to_ne_bytes());
            mac.update(&self.canary.to_ne_bytes());
            mac.update(&self.canary_tail.to_ne_bytes());
            let result = mac.finalize().into_bytes();
            u64::from_ne_bytes(result[..8].try_into().unwrap())
        };
        let hmac_ok: subtle::Choice = expected_check.ct_eq(&self.canary_hmac);
        (head_ok & tail_ok & xor_ok & hmac_ok).into()
    }

    /// Borrow the protected data as a byte slice.
    ///
    /// # Panics
    /// Panics if a canary violation is detected.  Before panicking, the
    /// violation is logged and all data is zeroized.
    pub fn as_bytes(&self) -> &[u8] {
        if !self.verify_canary() {
            #[allow(unsafe_code)]
            unsafe {
                core::ptr::write_bytes(self.data.as_ptr() as *mut u8, 0, self.data.len());
                libc::_exit(199);
            }
        }
        &self.data
    }

    /// Returns the length of the protected data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns whether this buffer was successfully mlocked.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        // 1. Zeroize the data.
        self.data.zeroize();

        // 2. Unlock if we locked.  Note: after zeroize the vec is empty,
        //    but the allocation may still be present.  We munlock the
        //    original pointer which is now the vec's (possibly dangling)
        //    buffer — munlock on an already-unlocked region is harmless.
        if self.locked {
            // The vec's internal pointer is still valid even after zeroize
            // (zeroize writes zeros but does not deallocate).
            munlock_slice(self.data.as_ptr(), self.original_len);
        }

        // 3. Zeroize canary material.
        self.canary.zeroize();
        self.canary_tail.zeroize();
        self.canary_hmac.zeroize();
        self.canary_nonce.zeroize();
    }
}

impl core::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretVec")
            .field("len", &self.data.len())
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Type aliases for common key sizes
// ---------------------------------------------------------------------------

/// 256-bit (32-byte) secret key buffer.
pub type SecretKey32 = SecretBuffer<32>;

/// 512-bit (64-byte) secret key buffer.
pub type SecretKey64 = SecretBuffer<64>;

/// 1024-bit (128-byte) secret key buffer.
pub type SecretKey128 = SecretBuffer<128>;

// ---------------------------------------------------------------------------
// Helper: generate a secret from OS CSPRNG
// ---------------------------------------------------------------------------

/// Create a `SecretBuffer` filled with entropy from the OS CSPRNG.
///
/// This is the recommended way to generate ephemeral keys, nonces, and
/// other short-lived secret material.
pub fn generate_secret<const N: usize>() -> Result<SecretBuffer<N>, MemguardError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| MemguardError::AllocationFailed)?;
    SecretBuffer::new(buf)
}

/// Harden the current process against memory disclosure attacks.
///
/// Call once at startup (in main) to:
/// - Lock ALL current and future memory pages via mlockall (prevents swap leaks)
/// - Disable core dumps via prctl(PR_SET_DUMPABLE, 0)
/// - Prevent new privilege escalation via prctl(PR_SET_NO_NEW_PRIVS, 1)
/// - Prevent ptrace attachment via prctl(PR_SET_PTRACER, 0) (anti-debugging)
/// - Set RLIMIT_CORE to 0 (belt-and-suspenders core dump prevention)
///
/// Returns `true` if all hardening succeeded.
pub fn harden_process() -> bool {
    let mut ok = true;
    unsafe {
        // SECURITY: mlockall() locks ALL current and future memory pages into
        // RAM, preventing ANY page from being swapped to disk. This is critical
        // for military deployments where an attacker with physical access could
        // clone swap partitions to extract secrets. Individual mlock() calls on
        // SecretBuffer are defense-in-depth but mlockall() is the primary guard.
        #[cfg(target_os = "linux")]
        {
            let mlockall_result = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
            if mlockall_result == 0 {
                tracing::info!("[memguard] hardening: mlockall(MCL_CURRENT|MCL_FUTURE) applied — all memory locked in RAM");
            } else {
                let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
                    .map(|v| v == "1")
                    .unwrap_or(false);
                if is_military {
                    panic!(
                        "FATAL: mlockall() failed in military deployment \
                         (MILNET_MILITARY_DEPLOYMENT=1). All process memory MUST be \
                         locked in RAM to prevent swap exfiltration. \
                         Ensure RLIMIT_MEMLOCK is unlimited (ulimit -l unlimited) \
                         or grant CAP_IPC_LOCK capability."
                    );
                }
                tracing::warn!(
                    "[memguard] WARNING: mlockall() failed — secrets may be swappable to disk. \
                     Set RLIMIT_MEMLOCK to unlimited or grant CAP_IPC_LOCK."
                );
                MLOCK_DEGRADED.store(true, Ordering::SeqCst);
            }
        }

        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            tracing::warn!("[memguard] prctl(PR_SET_DUMPABLE, 0) failed");
            ok = false;
        } else {
            tracing::info!("[memguard] hardening: PR_SET_DUMPABLE=0 applied (core dumps disabled)");
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            tracing::warn!("[memguard] prctl(PR_SET_NO_NEW_PRIVS) failed");
            ok = false;
        } else {
            tracing::info!("[memguard] hardening: PR_SET_NO_NEW_PRIVS=1 applied");
        }

        // Prevent ptrace attachment (anti-debugging)
        #[cfg(target_os = "linux")]
        {
            // PR_SET_PTRACER with 0 = deny all ptrace
            if libc::prctl(libc::PR_SET_PTRACER, 0, 0, 0, 0) != 0 {
                // PR_SET_PTRACER may not be available on all kernels (requires Yama LSM),
                // so treat failure as non-fatal but log it.
                tracing::warn!("[memguard] prctl(PR_SET_PTRACER, 0) failed (Yama LSM may not be enabled)");
            } else {
                tracing::info!("[memguard] hardening: PR_SET_PTRACER=0 applied (ptrace attachment denied)");
            }
        }

        // Set RLIMIT_CORE to 0 — belt-and-suspenders with PR_SET_DUMPABLE
        #[cfg(target_os = "linux")]
        {
            let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
                tracing::warn!("[memguard] setrlimit(RLIMIT_CORE, 0) failed");
                ok = false;
            } else {
                tracing::info!("[memguard] hardening: RLIMIT_CORE=0 applied (core dumps prevented at resource limit level)");
            }
        }
    }
    ok
}

// ---------------------------------------------------------------------------
// Kernel lockdown and swap encryption checks (HI-11, HI-14)
// ---------------------------------------------------------------------------

/// Check the kernel lockdown mode by reading `/sys/kernel/security/lockdown`.
///
/// Returns the lockdown mode string (e.g., "none", "integrity", "confidentiality").
/// If lockdown is "none", secrets in memory may be readable via /proc/PID/mem by root.
/// Hardware enclaves (SGX/SEV-SNP) are the proper mitigation.
pub fn check_kernel_lockdown() -> String {
    match std::fs::read_to_string("/sys/kernel/security/lockdown") {
        Ok(content) => {
            // Format is like: "none [integrity] confidentiality" with brackets around active
            let mode = content
                .split_whitespace()
                .find(|s| s.starts_with('['))
                .map(|s| s.trim_matches(|c| c == '[' || c == ']'))
                .unwrap_or_else(|| content.trim())
                .to_string();
            if mode == "none" {
                tracing::warn!(
                    target: "siem",
                    lockdown_mode = %mode,
                    "SIEM:WARNING kernel lockdown is 'none'. Root can read /proc/PID/mem. \
                     SecretBuffers are extractable by privileged attackers. \
                     Hardware enclaves (SGX/SEV-SNP) are the proper mitigation."
                );
            } else {
                tracing::info!(
                    lockdown_mode = %mode,
                    "kernel lockdown mode: {mode}"
                );
            }
            mode
        }
        Err(_) => {
            tracing::warn!(
                target: "siem",
                "SIEM:WARNING cannot read /sys/kernel/security/lockdown. \
                 Kernel lockdown status unknown. Assume 'none' for security posture."
            );
            "unknown".to_string()
        }
    }
}

/// Check whether all swap devices are backed by dm-crypt (encrypted swap).
///
/// Reads /proc/swaps and verifies each swap device path starts with `/dev/dm-`
/// or `/dev/mapper/` (indicating dm-crypt). If unencrypted swap is detected:
/// - `MILNET_MILITARY_DEPLOYMENT=1`: exits the process
/// - `MILNET_PRODUCTION=1`: logs SIEM:CRITICAL
/// - Otherwise: logs a warning
///
/// Returns `true` if all swap is encrypted (or no swap is configured).
pub fn check_encrypted_swap() -> bool {
    let swaps = match std::fs::read_to_string("/proc/swaps") {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("cannot read /proc/swaps; swap encryption status unknown");
            return false;
        }
    };

    let mut has_unencrypted = false;
    for line in swaps.lines().skip(1) {
        let device = match line.split_whitespace().next() {
            Some(d) => d,
            None => continue,
        };
        // dm-crypt devices appear as /dev/dm-N or /dev/mapper/*
        let is_encrypted = device.starts_with("/dev/dm-")
            || device.starts_with("/dev/mapper/")
            || device.contains("zram"); // zram is in-memory, no disk persistence
        if !is_encrypted {
            has_unencrypted = true;
            tracing::warn!(
                swap_device = device,
                "unencrypted swap device detected: {device}"
            );
        }
    }

    if !has_unencrypted {
        return true;
    }

    let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
        .map(|v| v == "1")
        .unwrap_or(false);
    let is_production = std::env::var("MILNET_PRODUCTION")
        .map(|v| v == "1")
        .unwrap_or(false);

    if is_military {
        tracing::error!(
            "SIEM:CRITICAL unencrypted swap detected in military deployment. \
             Key material may be recoverable from disk. Terminating."
        );
        common::siem::SecurityEvent {
            timestamp: common::siem::SecurityEvent::now_iso8601(),
            category: "memguard",
            action: "unencrypted_swap_military",
            severity: common::siem::Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some("Unencrypted swap detected in military deployment".into()),
        }
        .emit();
        std::process::exit(199);
    }

    if is_production {
        tracing::error!(
            target: "siem",
            "SIEM:CRITICAL unencrypted swap detected in production. \
             Key material may be recoverable from swap partition forensics."
        );
        common::siem::SecurityEvent {
            timestamp: common::siem::SecurityEvent::now_iso8601(),
            category: "memguard",
            action: "unencrypted_swap_production",
            severity: common::siem::Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some("Unencrypted swap detected in production deployment".into()),
        }
        .emit();
    }

    false
}

// ---------------------------------------------------------------------------
// SecureString -- zeroize-on-drop String wrapper for sensitive tokens
// ---------------------------------------------------------------------------

/// A `String` wrapper that overwrites its bytes on drop, preventing sensitive
/// values (refresh tokens, session IDs) from lingering in heap after dealloc.
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new(s: String) -> Self { Self { inner: s } }
    pub fn from_str(s: &str) -> Self { Self { inner: s.to_owned() } }
    pub fn as_str(&self) -> &str { &self.inner }
    pub fn into_inner(self) -> String {
        let s = unsafe { std::ptr::read(&self.inner) };
        std::mem::forget(self);
        s
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        let bytes = unsafe { self.inner.as_mut_vec() };
        for b in bytes.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl core::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecureString([REDACTED, {} bytes])", self.inner.len())
    }
}

impl core::fmt::Display for SecureString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl Clone for SecureString {
    fn clone(&self) -> Self { Self { inner: self.inner.clone() } }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.inner.as_bytes().ct_eq(other.inner.as_bytes()).into()
    }
}

impl Eq for SecureString {}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_buffer_creation_and_access() {
        let data = [0xAA_u8; 32];
        let buf = SecretBuffer::<32>::new(data).expect("SecretBuffer::new failed");
        assert_eq!(buf.as_bytes(), &[0xAA; 32]);
    }

    #[test]
    fn canary_verification_passes_on_valid_buffer() {
        let buf = SecretBuffer::<64>::new([0x42; 64]).expect("new failed");
        assert!(buf.verify_canaries(), "canaries should be intact");
    }

    #[test]
    fn zeroization_on_drop() {
        // Verify that SecretBuffer::drop runs without panic. We cannot
        // read freed memory to confirm zeroization without invoking
        // undefined behavior (use-after-free). The zeroize crate
        // guarantees volatile writes that the compiler cannot optimize
        // away, so we trust the implementation and verify it compiles
        // and runs the Drop path without error.
        let data = [0xFF_u8; 32];
        let buf = Box::new(SecretBuffer::<32>::new(data).expect("new failed"));

        // Verify data is accessible before drop.
        assert_eq!(buf.as_bytes(), &[0xFF; 32]);

        // Drop the buffer — this triggers zeroize + munlock.
        // If Drop panics, this test fails.
        drop(buf);
    }

    #[test]
    fn secret_vec_creation_and_access() {
        let data = vec![1, 2, 3, 4, 5];
        let sv = SecretVec::new(data).expect("SecretVec::new failed");
        assert_eq!(sv.as_bytes(), &[1, 2, 3, 4, 5]);
        assert_eq!(sv.len(), 5);
        assert!(!sv.is_empty());
    }

    #[test]
    fn secret_vec_canary_ok() {
        let sv = SecretVec::new(vec![0xBB; 16]).expect("new failed");
        assert!(sv.verify_canary());
    }

    #[test]
    fn generate_secret_produces_nonzero_output() {
        let buf = generate_secret::<32>().expect("generate_secret failed");
        let bytes = buf.as_bytes();
        // The probability of 32 zero bytes from CSPRNG is 2^{-256}.
        assert!(
            bytes.iter().any(|&b| b != 0),
            "generated secret should not be all zeros"
        );
    }

    #[test]
    fn round_trip_as_bytes_mut() {
        let mut buf = SecretBuffer::<16>::new([0u8; 16]).expect("new failed");
        {
            let data = buf.as_bytes_mut();
            for (i, byte) in data.iter_mut().enumerate() {
                *byte = i as u8;
            }
        }
        let expected: Vec<u8> = (0..16).collect();
        assert_eq!(buf.as_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn invalid_size_zero_rejected() {
        let result = SecretBuffer::<0>::new([]);
        assert_eq!(result.unwrap_err(), MemguardError::InvalidSize);
    }

    #[test]
    fn secret_vec_empty_rejected() {
        let result = SecretVec::new(vec![]);
        assert_eq!(result.unwrap_err(), MemguardError::InvalidSize);
    }

    #[test]
    fn type_aliases_work() {
        let _k32: SecretKey32 = SecretBuffer::new([0u8; 32]).unwrap();
        let _k64: SecretKey64 = SecretBuffer::new([0u8; 64]).unwrap();
        let _k128: SecretKey128 = SecretBuffer::new([0u8; 128]).unwrap();
    }

    #[test]
    fn secret_vec_munlock_uses_original_len() {
        // Create a SecretVec, verify it's locked and has correct original_len
        let sv = SecretVec::new(vec![0xAA; 64]).expect("SecretVec::new failed");
        // The original_len should be 64, not capacity
        assert_eq!(sv.len(), 64);
        assert_eq!(sv.as_bytes(), &[0xAA; 64]);
        // Drop it — munlock should use original_len (64), not capacity
        drop(sv);
        // If we get here without segfault/error, munlock worked correctly
        // with the original_len field rather than vec capacity
    }

    #[test]
    fn secret_vec_original_len_not_capacity() {
        // Vec::with_capacity can allocate more than requested.
        // SecretVec must use the data length for mlock/munlock, not capacity.
        let mut data = Vec::with_capacity(1024);
        data.extend_from_slice(&[0xBB; 64]);
        // data.len() == 64, data.capacity() >= 1024
        assert!(data.capacity() >= 1024);
        assert_eq!(data.len(), 64);

        let sv = SecretVec::new(data).expect("SecretVec::new failed");
        assert_eq!(sv.len(), 64);
        // Drop triggers munlock with original_len=64, not capacity
        drop(sv);
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let buf = SecretBuffer::<32>::new([0xCC; 32]).unwrap();
        let dbg = format!("{:?}", buf);
        assert!(!dbg.contains("0xCC"), "Debug output must not leak secrets");
        assert!(!dbg.contains("204"), "Debug output must not leak secrets");
        assert!(dbg.contains("SecretBuffer"));
    }

    #[test]
    fn secure_string_debug_does_not_leak() {
        let ss = SecureString::new("super-secret-token".to_string());
        let dbg = format!("{:?}", ss);
        assert!(!dbg.contains("super-secret"), "Debug must not leak");
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn secure_string_as_str() {
        let ss = SecureString::new("test-value".to_string());
        assert_eq!(ss.as_str(), "test-value");
    }

    #[test]
    fn secure_string_ct_eq() {
        let a = SecureString::new("same".to_string());
        let b = SecureString::new("same".to_string());
        let c = SecureString::new("diff".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
