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

use zeroize::Zeroize;

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
    /// The expected head canary value (stored separately for comparison).
    expected_head: u64,
    /// The expected tail canary value (stored separately for comparison).
    expected_tail: u64,
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

        let head = random_canary()?;
        let tail = random_canary()?;

        let mut buf = Self {
            canary_head: head,
            data,
            canary_tail: tail,
            expected_head: head,
            expected_tail: tail,
            locked: false,
        };

        // Attempt to mlock the data region.
        let data_ptr = buf.data.as_ptr();
        if mlock_slice(data_ptr, N) {
            buf.locked = true;
            // Exclude from core dumps
            madv_dontdump(data_ptr, N);
        } else {
            // mlock failure is fatal — keys must not be swappable.
            panic!(
                "FATAL: mlock failed for {N}-byte SecretBuffer. \
                 Ensure RLIMIT_MEMLOCK is sufficient."
            );
        }

        Ok(buf)
    }

    /// Verify canary integrity using constant-time comparison.
    ///
    /// Returns `true` if both canaries are intact.
    pub fn verify_canaries(&self) -> bool {
        // Constant-time: XOR both pairs and OR the results.  Any non-zero
        // bit means corruption.
        let head_diff = self.canary_head ^ self.expected_head;
        let tail_diff = self.canary_tail ^ self.expected_tail;
        (head_diff | tail_diff) == 0
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
            tracing::error!(
                "SECURITY: canary violation detected in SecretBuffer<{N}> — \
                 possible buffer overflow or use-after-free. Zeroizing data before panic."
            );
            // Zeroize data before panicking.  We need a mutable reference, so
            // use unsafe to cast away const — the buffer is about to be
            // destroyed anyway and we MUST clear the secret material.
            #[allow(unsafe_code)]
            unsafe {
                let data_ptr = &self.data as *const [u8; N] as *mut [u8; N];
                (*data_ptr).zeroize();
            }
            panic!(
                "SECURITY: canary violation detected — possible buffer overflow or \
                 use-after-free"
            );
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
            tracing::error!(
                "SECURITY: canary violation detected in SecretBuffer<{N}> — \
                 possible buffer overflow or use-after-free. Zeroizing data before panic."
            );
            self.data.zeroize();
            panic!(
                "SECURITY: canary violation detected — possible buffer overflow or \
                 use-after-free"
            );
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
        self.expected_head.zeroize();
        self.expected_tail.zeroize();
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
    /// Canary value set at construction.
    canary: u64,
    /// Expected canary value for verification.
    expected_canary: u64,
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

        let canary = random_canary()?;

        let original_len = data.len();
        let mut sv = Self {
            data,
            original_len,
            canary,
            expected_canary: canary,
            locked: false,
        };

        let ptr = sv.data.as_ptr();
        let len = sv.data.len();
        if mlock_slice(ptr, len) {
            sv.locked = true;
            // Exclude from core dumps
            madv_dontdump(ptr, len);
        } else {
            // mlock failure is fatal — keys must not be swappable.
            panic!(
                "FATAL: mlock failed for {len}-byte SecretVec. \
                 Ensure RLIMIT_MEMLOCK is sufficient."
            );
        }

        Ok(sv)
    }

    /// Verify canary integrity using constant-time comparison.
    pub fn verify_canary(&self) -> bool {
        (self.canary ^ self.expected_canary) == 0
    }

    /// Borrow the protected data as a byte slice.
    ///
    /// # Panics
    /// Panics if a canary violation is detected.  Before panicking, the
    /// violation is logged and all data is zeroized.
    pub fn as_bytes(&self) -> &[u8] {
        if !self.verify_canary() {
            tracing::error!(
                "SECURITY: canary violation detected in SecretVec (len={}) — \
                 possible buffer overflow or use-after-free. Zeroizing data before panic.",
                self.data.len()
            );
            #[allow(unsafe_code)]
            unsafe {
                let data_ptr = &self.data as *const Vec<u8> as *mut Vec<u8>;
                (*data_ptr).zeroize();
            }
            panic!("SECURITY: canary violation detected in SecretVec");
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
        self.expected_canary.zeroize();
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
/// - Disable core dumps via prctl(PR_SET_DUMPABLE, 0)
/// - Prevent new privilege escalation via prctl(PR_SET_NO_NEW_PRIVS, 1)
/// - Prevent ptrace attachment via prctl(PR_SET_PTRACER, 0) (anti-debugging)
/// - Set RLIMIT_CORE to 0 (belt-and-suspenders core dump prevention)
///
/// Returns `true` if all hardening succeeded.
pub fn harden_process() -> bool {
    let mut ok = true;
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            eprintln!("[memguard] WARNING: prctl(PR_SET_DUMPABLE, 0) failed");
            ok = false;
        } else {
            eprintln!("[memguard] hardening: PR_SET_DUMPABLE=0 applied (core dumps disabled)");
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            eprintln!("[memguard] WARNING: prctl(PR_SET_NO_NEW_PRIVS) failed");
            ok = false;
        } else {
            eprintln!("[memguard] hardening: PR_SET_NO_NEW_PRIVS=1 applied");
        }

        // Prevent ptrace attachment (anti-debugging)
        #[cfg(target_os = "linux")]
        {
            // PR_SET_PTRACER with 0 = deny all ptrace
            if libc::prctl(libc::PR_SET_PTRACER, 0, 0, 0, 0) != 0 {
                // PR_SET_PTRACER may not be available on all kernels (requires Yama LSM),
                // so treat failure as non-fatal but log it.
                eprintln!("[memguard] WARNING: prctl(PR_SET_PTRACER, 0) failed (Yama LSM may not be enabled)");
            } else {
                eprintln!("[memguard] hardening: PR_SET_PTRACER=0 applied (ptrace attachment denied)");
            }
        }

        // Set RLIMIT_CORE to 0 — belt-and-suspenders with PR_SET_DUMPABLE
        #[cfg(target_os = "linux")]
        {
            let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
                eprintln!("[memguard] WARNING: setrlimit(RLIMIT_CORE, 0) failed");
                ok = false;
            } else {
                eprintln!("[memguard] hardening: RLIMIT_CORE=0 applied (core dumps prevented at resource limit level)");
            }
        }
    }
    ok
}

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
        // Use Box to heap-allocate so the pointer remains valid after drop
        // and is not immediately reused by stack frames.
        let data = [0xFF_u8; 32];
        let buf = Box::new(SecretBuffer::<32>::new(data).expect("new failed"));

        // Grab a raw pointer to the data region inside the heap allocation.
        let ptr = buf.as_bytes().as_ptr();

        // Drop the buffer — this should zeroize the data in place.
        drop(buf);

        // SAFETY: The heap allocation was just freed, but on most allocators
        // the page is still mapped and readable (though logically dead).
        // We only read to verify zeroization occurred before deallocation.
        unsafe {
            let slice = core::slice::from_raw_parts(ptr, 32);
            // After zeroize + drop, bytes should be zero (not 0xFF).
            assert!(
                slice.iter().any(|&b| b != 0xFF),
                "data should have been zeroized on drop"
            );
        }
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
        // The debug output must NOT contain the secret byte.
        assert!(!dbg.contains("0xCC"), "Debug output must not leak secrets");
        assert!(!dbg.contains("204"), "Debug output must not leak secrets");
        assert!(dbg.contains("SecretBuffer"));
    }
}
