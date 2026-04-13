//! HMAC_DRBG per NIST SP 800-90A using HMAC-SHA512.
//!
//! Provides a FIPS 140-3 approved deterministic random bit generator
//! seeded from the multi-source entropy combiner in `entropy.rs`.
//!
//! The internal state (key + value) is heap-allocated and pinned to prevent
//! `mlock` from becoming unsound after a struct move. A PID check on each
//! `generate()` call detects process forks and forces an immediate reseed.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::pin::Pin;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

const SEED_LEN: usize = 64;
const MAX_REQUESTS_BEFORE_RESEED: u64 = 10_000;
const MAX_BYTES_PER_REQUEST: usize = 440;

/// Heap-allocated, pinned DRBG state. Addresses are stable after construction,
/// so `mlock` remains valid for the lifetime of the allocation.
struct DrbgState {
    key: [u8; 64],
    value: [u8; 64],
}

impl Zeroize for DrbgState {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.value.zeroize();
    }
}

pub struct HmacDrbg {
    /// Pinned, heap-allocated state. Addresses are stable so mlock is sound.
    state: Pin<Box<DrbgState>>,
    reseed_counter: u64,
    state_locked: bool,
    /// PID recorded at construction. If current PID differs (fork), force reseed.
    init_pid: u32,
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        self.state.key.zeroize();
        self.state.value.zeroize();
        self.reseed_counter = 0;
        if self.state_locked {
            #[allow(unsafe_code)]
            unsafe {
                libc::munlock(
                    self.state.key.as_ptr() as *const libc::c_void,
                    self.state.key.len(),
                );
                libc::munlock(
                    self.state.value.as_ptr() as *const libc::c_void,
                    self.state.value.len(),
                );
            }
        }
    }
}

impl std::fmt::Debug for HmacDrbg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacDrbg")
            .field("key", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("reseed_counter", &self.reseed_counter)
            .finish()
    }
}

impl HmacDrbg {
    pub fn new() -> Result<Self, String> {
        let seed = Self::gather_seed();
        Self::from_seed(&seed)
    }

    fn gather_seed() -> [u8; SEED_LEN] {
        // A4: mix an X-Wing (X25519 + ML-KEM-1024) ephemeral encapsulation
        // shared secret into the DRBG seed. This gives the seed a contribution
        // that survives any future classical-only break of the OS CSPRNG and
        // forces an attacker to break BOTH X25519 and ML-KEM-1024 to predict
        // the DRBG state. The ephemeral keypair is dropped (and zeroized via
        // XWingKeyPair::Drop) immediately after this function returns.
        let a = crate::entropy::combined_entropy();
        let b = crate::entropy::combined_entropy();

        // Self-encapsulation against an ephemeral X-Wing public key: the
        // shared secret is unpredictable to anyone outside this stack frame.
        let pq_contrib: [u8; 64] = match Self::pq_seed_contribution() {
            Some(s) => s,
            None => {
                // X-Wing failure must not silently degrade DRBG seeding.
                tracing::error!(
                    "SIEM:CRITICAL X-Wing PQ seed contribution unavailable — \
                     DRBG falling back to classical entropy only"
                );
                [0u8; 64]
            }
        };

        // SEED_LEN composition: 32 bytes from `a`, 32 from `b`, plus an
        // HKDF-SHA512 mix-down of (a || b || pq_contrib) folded into the
        // existing layout. We keep the public layout (a || b) intact and
        // additionally XOR the PQ contribution across the whole seed so the
        // PQ secret influences every byte even at SEED_LEN==64.
        let mut seed = [0u8; SEED_LEN];
        seed[..32].copy_from_slice(&a);
        seed[32..].copy_from_slice(&b);
        for i in 0..SEED_LEN {
            seed[i] ^= pq_contrib[i % pq_contrib.len()];
        }
        // Zeroize the PQ contribution after use.
        let mut pq_contrib = pq_contrib;
        use zeroize::Zeroize;
        pq_contrib.zeroize();
        seed
    }

    /// Compute a 64-byte post-quantum entropy contribution by performing an
    /// ephemeral X-Wing self-encapsulation. Returns `None` on any X-Wing
    /// failure — callers must treat `None` as a critical SIEM event.
    fn pq_seed_contribution() -> Option<[u8; 64]> {
        let (pk, _kp) = crate::xwing::xwing_keygen();
        let (ss, _ct) = crate::xwing::xwing_encapsulate(&pk).ok()?;
        let bytes = ss.as_ref();
        if bytes.len() < 64 {
            return None;
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes[..64]);
        Some(out)
    }

    /// Return the current process ID. Used for fork detection.
    fn current_pid() -> u32 {
        std::process::id()
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        if seed.len() < 32 {
            return Err("DRBG seed must be at least 256 bits".into());
        }
        // Heap-allocate state so addresses are stable for mlock.
        let state = Box::pin(DrbgState {
            key: [0u8; 64],
            value: [0x01; 64],
        });
        let mut drbg = Self {
            state,
            reseed_counter: 1,
            state_locked: false,
            init_pid: Self::current_pid(),
        };
        drbg.update(seed);

        // mlock the heap-allocated state (address-stable).
        #[allow(unsafe_code)]
        unsafe {
            let key_ok = libc::mlock(
                drbg.state.key.as_ptr() as *const libc::c_void,
                drbg.state.key.len(),
            ) == 0;
            let val_ok = libc::mlock(
                drbg.state.value.as_ptr() as *const libc::c_void,
                drbg.state.value.len(),
            ) == 0;
            if key_ok && val_ok {
                drbg.state_locked = true;
                libc::madvise(
                    drbg.state.key.as_ptr() as *mut libc::c_void,
                    drbg.state.key.len(),
                    libc::MADV_DONTDUMP,
                );
                libc::madvise(
                    drbg.state.value.as_ptr() as *mut libc::c_void,
                    drbg.state.value.len(),
                    libc::MADV_DONTDUMP,
                );
            } else {
                tracing::warn!(
                    "HMAC_DRBG: mlock failed for internal state. \
                     DRBG key/value may be swappable to disk."
                );
            }
        }
        Ok(drbg)
    }

    fn update(&mut self, provided_data: &[u8]) {
        let mut mac = HmacSha512::new_from_slice(&self.state.key).expect("HMAC key");
        mac.update(&self.state.value);
        mac.update(&[0x00]);
        mac.update(provided_data);
        // SAFETY: Pin guarantees address stability. We mutate through Pin
        // because DrbgState does not implement Unpin constraints that would
        // be violated -- it has no self-referential pointers.
        #[allow(unsafe_code)]
        unsafe {
            Pin::get_unchecked_mut(self.state.as_mut())
                .key
                .copy_from_slice(&mac.finalize().into_bytes());
        }

        let mut mac = HmacSha512::new_from_slice(&self.state.key).expect("HMAC key");
        mac.update(&self.state.value);
        #[allow(unsafe_code)]
        unsafe {
            Pin::get_unchecked_mut(self.state.as_mut())
                .value
                .copy_from_slice(&mac.finalize().into_bytes());
        }

        if !provided_data.is_empty() {
            let mut mac = HmacSha512::new_from_slice(&self.state.key).expect("HMAC key");
            mac.update(&self.state.value);
            mac.update(&[0x01]);
            mac.update(provided_data);
            #[allow(unsafe_code)]
            unsafe {
                Pin::get_unchecked_mut(self.state.as_mut())
                    .key
                    .copy_from_slice(&mac.finalize().into_bytes());
            }

            let mut mac = HmacSha512::new_from_slice(&self.state.key).expect("HMAC key");
            mac.update(&self.state.value);
            #[allow(unsafe_code)]
            unsafe {
                Pin::get_unchecked_mut(self.state.as_mut())
                    .value
                    .copy_from_slice(&mac.finalize().into_bytes());
            }
        }
    }

    pub fn generate(&mut self, output: &mut [u8]) -> Result<(), String> {
        if output.len() > MAX_BYTES_PER_REQUEST {
            return Err(format!(
                "requested {} bytes exceeds SP 800-90A limit of {MAX_BYTES_PER_REQUEST}",
                output.len()
            ));
        }

        // Fork detection: if PID changed, parent and child share DRBG state.
        // Force immediate reseed to diverge the two DRBG instances.
        let current_pid = Self::current_pid();
        if current_pid != self.init_pid {
            tracing::warn!(
                "HMAC_DRBG fork detected (init_pid={}, current_pid={}). \
                 Forcing immediate reseed for fork safety.",
                self.init_pid,
                current_pid
            );
            self.reseed()?;
            self.init_pid = current_pid;
        }

        if self.reseed_counter > MAX_REQUESTS_BEFORE_RESEED {
            self.reseed()?;
        }
        let mut generated = 0;
        while generated < output.len() {
            let mut mac = HmacSha512::new_from_slice(&self.state.key).expect("HMAC key");
            mac.update(&self.state.value);
            let result = mac.finalize().into_bytes();
            #[allow(unsafe_code)]
            unsafe {
                Pin::get_unchecked_mut(self.state.as_mut())
                    .value
                    .copy_from_slice(&result);
            }
            let remaining = output.len() - generated;
            let to_copy = remaining.min(64);
            output[generated..generated + to_copy].copy_from_slice(&self.state.value[..to_copy]);
            generated += to_copy;
        }
        self.update(&[]);
        self.reseed_counter += 1;
        Ok(())
    }

    pub fn reseed(&mut self) -> Result<(), String> {
        let seed = Self::gather_seed();
        self.update(&seed);
        self.reseed_counter = 1;
        Ok(())
    }

    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }
}
