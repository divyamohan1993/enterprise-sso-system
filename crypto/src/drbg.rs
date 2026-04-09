//! HMAC_DRBG per NIST SP 800-90A using HMAC-SHA512.
//!
//! Provides a FIPS 140-3 approved deterministic random bit generator
//! seeded from the multi-source entropy combiner in `entropy.rs`.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

const SEED_LEN: usize = 64;
const MAX_REQUESTS_BEFORE_RESEED: u64 = 10_000;
const MAX_BYTES_PER_REQUEST: usize = 440;

#[derive(Zeroize)]
pub struct HmacDrbg {
    key: [u8; 64],
    value: [u8; 64],
    reseed_counter: u64,
    #[zeroize(skip)]
    state_locked: bool,
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        self.key.zeroize();
        self.value.zeroize();
        self.reseed_counter = 0;
        if self.state_locked {
            #[allow(unsafe_code)]
            unsafe {
                libc::munlock(self.key.as_ptr() as *const libc::c_void, self.key.len());
                libc::munlock(self.value.as_ptr() as *const libc::c_void, self.value.len());
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
        let a = crate::entropy::combined_entropy();
        let b = crate::entropy::combined_entropy();
        let mut seed = [0u8; SEED_LEN];
        seed[..32].copy_from_slice(&a);
        seed[32..].copy_from_slice(&b);
        seed
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        if seed.len() < 32 {
            return Err("DRBG seed must be at least 256 bits".into());
        }
        let mut drbg = Self {
            key: [0u8; 64],
            value: [0x01; 64],
            reseed_counter: 1,
            state_locked: false,
        };
        drbg.update(seed);
        #[allow(unsafe_code)]
        unsafe {
            let key_ok = libc::mlock(drbg.key.as_ptr() as *const libc::c_void, drbg.key.len()) == 0;
            let val_ok = libc::mlock(drbg.value.as_ptr() as *const libc::c_void, drbg.value.len()) == 0;
            if key_ok && val_ok {
                drbg.state_locked = true;
                libc::madvise(drbg.key.as_ptr() as *mut libc::c_void, drbg.key.len(), libc::MADV_DONTDUMP);
                libc::madvise(drbg.value.as_ptr() as *mut libc::c_void, drbg.value.len(), libc::MADV_DONTDUMP);
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
        let mut mac = HmacSha512::new_from_slice(&self.key).expect("HMAC key");
        mac.update(&self.value);
        mac.update(&[0x00]);
        mac.update(provided_data);
        self.key.copy_from_slice(&mac.finalize().into_bytes());

        let mut mac = HmacSha512::new_from_slice(&self.key).expect("HMAC key");
        mac.update(&self.value);
        self.value.copy_from_slice(&mac.finalize().into_bytes());

        if !provided_data.is_empty() {
            let mut mac = HmacSha512::new_from_slice(&self.key).expect("HMAC key");
            mac.update(&self.value);
            mac.update(&[0x01]);
            mac.update(provided_data);
            self.key.copy_from_slice(&mac.finalize().into_bytes());

            let mut mac = HmacSha512::new_from_slice(&self.key).expect("HMAC key");
            mac.update(&self.value);
            self.value.copy_from_slice(&mac.finalize().into_bytes());
        }
    }

    pub fn generate(&mut self, output: &mut [u8]) -> Result<(), String> {
        if output.len() > MAX_BYTES_PER_REQUEST {
            return Err(format!(
                "requested {} bytes exceeds SP 800-90A limit of {MAX_BYTES_PER_REQUEST}",
                output.len()
            ));
        }
        if self.reseed_counter > MAX_REQUESTS_BEFORE_RESEED {
            self.reseed()?;
        }
        let mut generated = 0;
        while generated < output.len() {
            let mut mac = HmacSha512::new_from_slice(&self.key).expect("HMAC key");
            mac.update(&self.value);
            self.value.copy_from_slice(&mac.finalize().into_bytes());
            let remaining = output.len() - generated;
            let to_copy = remaining.min(64);
            output[generated..generated + to_copy].copy_from_slice(&self.value[..to_copy]);
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
