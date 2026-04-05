//! HMAC_DRBG per NIST SP 800-90A using HMAC-SHA512.
//!
//! Provides a FIPS 140-3 approved deterministic random bit generator
//! seeded from the multi-source entropy combiner in `entropy.rs`.
//!
//! Instantiation: seed from combined_entropy() (OS CSPRNG + RDRAND + env)
//! Reseed: after MAX_REQUESTS_BEFORE_RESEED operations or on explicit request
//! Generate: HMAC-SHA512 based, 440 bytes max per request per SP 800-90A

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha512 = Hmac<Sha512>;

const SEED_LEN: usize = 64; // 512-bit seed (HMAC-SHA512 output size)
const MAX_REQUESTS_BEFORE_RESEED: u64 = 10_000;
const MAX_BYTES_PER_REQUEST: usize = 440; // SP 800-90A limit

#[derive(ZeroizeOnDrop)]
pub struct HmacDrbg {
    #[zeroize]
    key: [u8; 64],
    #[zeroize]
    value: [u8; 64],
    reseed_counter: u64,
}

// SECURITY: Custom Debug redacts key/value material to prevent log leakage.
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
    /// Instantiate with entropy from the multi-source combiner.
    pub fn new() -> Result<Self, String> {
        let seed = Self::gather_seed();
        Self::from_seed(&seed)
    }

    /// Gather 64 bytes of seed material from the entropy combiner.
    fn gather_seed() -> [u8; SEED_LEN] {
        let a = crate::entropy::combined_entropy();
        let b = crate::entropy::combined_entropy();
        let mut seed = [0u8; SEED_LEN];
        seed[..32].copy_from_slice(&a);
        seed[32..].copy_from_slice(&b);
        seed
    }

    /// Instantiate from provided seed material.
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        if seed.len() < 32 {
            return Err("DRBG seed must be at least 256 bits".into());
        }
        let mut drbg = Self {
            key: [0u8; 64],
            value: [0x01; 64],
            reseed_counter: 1,
        };
        drbg.update(seed);
        Ok(drbg)
    }

    /// SP 800-90A Section 10.1.2.2: HMAC_DRBG_Update
    fn update(&mut self, provided_data: &[u8]) {
        // Step 1: K = HMAC(K, V || 0x00 || provided_data)
        let mut mac = HmacSha512::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&self.value);
        mac.update(&[0x00]);
        mac.update(provided_data);
        self.key.copy_from_slice(&mac.finalize().into_bytes());

        // Step 2: V = HMAC(K, V)
        let mut mac = HmacSha512::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&self.value);
        self.value.copy_from_slice(&mac.finalize().into_bytes());

        if !provided_data.is_empty() {
            // Step 4: K = HMAC(K, V || 0x01 || provided_data)
            let mut mac =
                HmacSha512::new_from_slice(&self.key).expect("HMAC accepts any key length");
            mac.update(&self.value);
            mac.update(&[0x01]);
            mac.update(provided_data);
            self.key.copy_from_slice(&mac.finalize().into_bytes());

            // Step 5: V = HMAC(K, V)
            let mut mac =
                HmacSha512::new_from_slice(&self.key).expect("HMAC accepts any key length");
            mac.update(&self.value);
            self.value.copy_from_slice(&mac.finalize().into_bytes());
        }
    }

    /// SP 800-90A Section 10.1.2.5: HMAC_DRBG_Generate
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
            let mut mac =
                HmacSha512::new_from_slice(&self.key).expect("HMAC accepts any key length");
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

    /// Reseed from the entropy source.
    pub fn reseed(&mut self) -> Result<(), String> {
        let seed = Self::gather_seed();
        self.update(&seed);
        self.reseed_counter = 1;
        Ok(())
    }

    /// Current reseed counter (for monitoring).
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }
}
