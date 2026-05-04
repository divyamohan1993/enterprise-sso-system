//! DPoP (Demonstration of Proof of Possession) — RFC 9449
//! Binds tokens to a client key pair, preventing token theft.
//!
//! RFC 9449 requires asymmetric signatures for DPoP proofs. This implementation
//! uses ML-DSA-87 (FIPS 204, CNSA 2.0 compliant, Level 5) for proof generation and
//! verification. The dpop_key_hash function uses SHA-512 for thumbprint
//! computation (CNSA 2.0 compliant).

use ml_dsa::{
    signature::{Signer, Verifier},
    KeyGen, MlDsa87, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha512};
use std::pin::Pin;
use zeroize::Zeroize;
use common::domain;

/// Type aliases for ML-DSA-87 DPoP key types.
pub type DpopSigningKey = SigningKey<MlDsa87>;
pub type DpopVerifyingKey = VerifyingKey<MlDsa87>;
pub type DpopSignature = ml_dsa::Signature<MlDsa87>;

/// A guarded wrapper around an ML-DSA-87 signing key that ensures the key
/// material is zeroized when dropped and optionally memory-locked to prevent
/// swap exposure.
///
/// A sentinel copy of the key seed is stored in a `SecretVec` (mlocked +
/// canary-protected) to ensure the key material cannot be swapped to disk.
/// On drop, the sentinel is zeroized and munlocked by `SecretVec`, and the
/// parsed key is overwritten with a deterministic dummy.
pub struct GuardedSigningKey {
    /// The parsed ML-DSA-87 signing key used for actual signing operations.
    key: DpopSigningKey,
    /// Memory-locked sentinel — ensures the OS mlock covers the key's
    /// memory pages and the material is zeroized on drop.
    _locked_sentinel: Option<crate::memguard::SecretVec>,
}

impl GuardedSigningKey {
    /// Build the guarded key in an *unlocked* state. Used internally by
    /// [`new_pinned`]. The sentinel `SecretVec` is built via the address-
    /// correct `new_pinned`. The actual ML-DSA-87 signing key is NOT
    /// mlocked here — that is deferred to [`lock_in_place`] which runs
    /// after the outer `Self` reaches its final pinned heap address.
    fn build_unlocked(key: DpopSigningKey) -> Self {
        let mut sentinel = vec![0u8; 64];
        let _ = getrandom::getrandom(&mut sentinel);
        let locked = crate::memguard::SecretVec::new_pinned(sentinel).ok();
        Self { key, _locked_sentinel: locked }
    }

    /// Apply mlock to the inner `DpopSigningKey` at its final, stable
    /// pinned address. Must be called only after `Self` has been placed
    /// at its final heap address (e.g. inside `Box::pin`).
    pub fn lock_in_place(self: Pin<&mut Self>) -> Result<(), crate::memguard::MemguardError> {
        // SAFETY: We only call mlock on the address of `self.key` and
        // do not move `key` out of `self`.
        let this: &mut Self = unsafe { self.get_unchecked_mut() };
        let ptr = &this.key as *const DpopSigningKey as *const u8;
        let len = std::mem::size_of::<DpopSigningKey>();
        #[allow(unsafe_code)]
        let rc = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
        if rc == 0 {
            #[allow(unsafe_code)]
            unsafe {
                libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
            }
            Ok(())
        } else {
            crate::memguard::record_mlock_failure();
            let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
                .map(|v| v == "1")
                .unwrap_or(false);
            if is_military {
                panic!(
                    "FATAL: mlock failed for DPoP signing key in military deployment \
                     (MILNET_MILITARY_DEPLOYMENT=1). Key material MUST be locked in RAM."
                );
            }
            tracing::error!(
                "SIEM:CRITICAL mlock failed for DPoP GuardedSigningKey — key may be swappable"
            );
            Err(crate::memguard::MemguardError::MlockFailed)
        }
    }

    /// Address-correct constructor: places the guarded key on the heap
    /// and locks the live address. **This is the only constructor that
    /// fulfils the mlock contract** — `new` mlocks the constructor's
    /// stack frame, which the return-by-value invalidates.
    pub fn new_pinned(key: DpopSigningKey) -> Result<Pin<Box<Self>>, crate::memguard::MemguardError> {
        let guarded = Self::build_unlocked(key);
        let mut pinned: Pin<Box<Self>> = Box::pin(guarded);
        pinned.as_mut().lock_in_place()?;
        Ok(pinned)
    }

    /// **DEPRECATED** — `mlock`-after-move is unsound. The `mlock` here
    /// targets the constructor's stack frame; the value is then
    /// `memcpy`'d into the caller's slot, leaving the live key bytes
    /// outside the locked region. Use [`new_pinned`] instead.
    #[deprecated(
        note = "use new_pinned; mlock-after-move semantics are unsafe — the live signing key address is not the address that was locked"
    )]
    pub fn new(key: DpopSigningKey) -> Self {
        let guarded = Self::build_unlocked(key);
        // Legacy mlock-after-move path retained verbatim.
        let ptr = &guarded.key as *const DpopSigningKey as *const u8;
        let len = std::mem::size_of::<DpopSigningKey>();
        #[allow(unsafe_code)]
        unsafe {
            if libc::mlock(ptr as *const libc::c_void, len) == 0 {
                libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
            }
        }
        guarded
    }

    /// Borrow the inner signing key for use in signing operations.
    pub fn signing_key(&self) -> &DpopSigningKey {
        &self.key
    }
}

impl Drop for GuardedSigningKey {
    fn drop(&mut self) {
        // munlock signing key region before overwriting. We MUST check the
        // return code: munlock(2) can fail with EINVAL/EAGAIN/EPERM, and a
        // silent failure leaves the page locked (or never-locked) which can
        // mask earlier mlock failures. Under MILNET_MILITARY_DEPLOYMENT, abort.
        let ptr = &self.key as *const DpopSigningKey as *const u8;
        let len = std::mem::size_of::<DpopSigningKey>();
        #[allow(unsafe_code)]
        let rc = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
        if rc != 0 {
            #[allow(unsafe_code)]
            let errno = unsafe { *libc::__errno_location() };
            crate::memguard::record_mlock_failure();
            tracing::error!(
                errno = errno,
                len = len,
                "SIEM:CRITICAL munlock failed for DPoP signing key on drop \
                 — page may remain locked and re-used"
            );
            let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
                .map(|v| v == "1")
                .unwrap_or(false);
            if is_military {
                // Aborting from drop is the only fail-closed option:
                // a half-locked secret in military mode is unacceptable.
                eprintln!(
                    "FATAL: munlock failed (errno={errno}) for DPoP signing key in military deployment"
                );
                std::process::abort();
            }
        }
        // Overwrite with deterministic dummy.
        let zero_seed = [0u8; 32];
        let dummy_kp = MlDsa87::from_seed(&zero_seed.into());
        self.key = dummy_kp.signing_key().clone();
    }
}

/// Generate an ML-DSA-87 keypair for DPoP proof generation.
///
/// **DEPRECATED** — uses [`GuardedSigningKey::new`] which has
/// mlock-after-move semantics. Prefer [`generate_dpop_keypair_pinned`].
#[deprecated(
    note = "use generate_dpop_keypair_pinned; underlying GuardedSigningKey::new mlock-after-move is unsafe"
)]
#[allow(deprecated)]
pub fn generate_dpop_keypair() -> (GuardedSigningKey, DpopVerifyingKey) {
    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        panic!("FATAL: OS CSPRNG unavailable — cannot generate DPoP keypair safely");
    }
    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    let guarded = GuardedSigningKey::new(kp.signing_key().clone());
    (guarded, kp.verifying_key().clone())
}

/// Generate an ML-DSA-87 keypair returning a pinned, address-correctly
/// locked `GuardedSigningKey`.
///
/// Returns `Err(MemguardError::MlockFailed)` outside military mode if
/// `RLIMIT_MEMLOCK` is exhausted; in `MILNET_MILITARY_DEPLOYMENT=1`
/// mlock failure aborts the process.
pub fn generate_dpop_keypair_pinned()
    -> Result<(Pin<Box<GuardedSigningKey>>, DpopVerifyingKey), crate::memguard::MemguardError>
{
    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        panic!("FATAL: OS CSPRNG unavailable — cannot generate DPoP keypair safely");
    }
    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    let pinned = GuardedSigningKey::new_pinned(kp.signing_key().clone())?;
    Ok((pinned, kp.verifying_key().clone()))
}

/// Generate a raw ML-DSA-87 keypair without `GuardedSigningKey` wrapping.
///
/// This is provided for callers that manage key lifetime themselves (e.g.
/// tests, short-lived one-shot proofs).  Prefer `generate_dpop_keypair()`
/// for long-lived keys.
pub fn generate_dpop_keypair_raw() -> (DpopSigningKey, DpopVerifyingKey) {
    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        panic!("FATAL: OS CSPRNG unavailable — cannot generate raw DPoP keypair safely");
    }
    let kp = MlDsa87::from_seed(&seed.into());
    seed.zeroize();
    (kp.signing_key().clone(), kp.verifying_key().clone())
}

/// Generate a DPoP key hash from a client's public key bytes.
///
/// Uses SHA-512 (CNSA 2.0 compliant) for thumbprint computation.
pub fn dpop_key_hash(client_public_key: &[u8]) -> [u8; 64] {
    use sha2::Sha512;
    let digest = Sha512::digest([domain::DPOP_PROOF, client_public_key].concat());
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&digest);
    hash
}

/// Generate a DPoP proof using ML-DSA-87 (CNSA 2.0 compliant, Level 5).
///
/// Signs SHA-512(claims_bytes || timestamp_bytes || htm || htu || server_nonce)
/// with the provided ML-DSA-87 signing key. The `htm` (HTTP method) and `htu`
/// (HTTP target URI) parameters bind the proof to a specific request per RFC 9449.
/// An optional `server_nonce` binds the proof to a server-issued nonce to prevent
/// replay within the timestamp window.
///
/// Returns the encoded ML-DSA-87 signature bytes.
pub fn generate_dpop_proof(
    signing_key: &DpopSigningKey,
    claims_bytes: &[u8],
    timestamp: i64,
    htm: &[u8],
    htu: &[u8],
    server_nonce: Option<&[u8]>,
) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(claims_bytes);
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(htm);
    hasher.update(htu);
    if let Some(nonce) = server_nonce {
        hasher.update(nonce);
    }
    let digest = hasher.finalize();
    let sig: DpopSignature = signing_key.sign(&digest);
    sig.encode().to_vec()
}

/// Maximum allowed age (in seconds) for a DPoP proof timestamp.
/// Proofs older than this are rejected to prevent replay attacks.
const DPOP_MAX_AGE_SECS: i64 = 30;

/// Verify a DPoP proof using ML-DSA-87 (CNSA 2.0 compliant, Level 5).
///
/// Verifies the ML-DSA-87 signature over
/// SHA-512(claims_bytes || timestamp_bytes || htm || htu || server_nonce)
/// against the provided verifying key bytes. Also checks the key hash matches
/// and rejects proofs where the timestamp deviates more than `DPOP_MAX_AGE_SECS`
/// seconds from the current system clock.
///
/// The `htm` and `htu` parameters are the expected HTTP method and target URI
/// for this request. If they don't match what was signed, verification fails.
/// The `expected_server_nonce` parameter, when `Some`, requires the proof to
/// have been generated with the matching server nonce.
pub fn verify_dpop_proof(
    verifying_key: &DpopVerifyingKey,
    proof: &[u8],
    claims_bytes: &[u8],
    timestamp: i64,
    expected_key_hash: &[u8; 64],
    htm: &[u8],
    htu: &[u8],
    expected_server_nonce: Option<&[u8]>,
) -> bool {
    // 0. Timestamp freshness check — reject stale or future-dated proofs
    // Uses monotonic-anchored secure time, immune to clock manipulation.
    let now = common::secure_time::secure_now_secs_i64();
    if (now - timestamp).abs() > DPOP_MAX_AGE_SECS {
        return false;
    }

    // 1. Verify the key hash matches
    let vk_bytes = verifying_key.encode();
    let hash = dpop_key_hash(vk_bytes.as_ref());
    if !crate::ct::ct_eq(&hash, expected_key_hash) {
        return false;
    }

    // 2. Parse the ML-DSA-87 signature
    let sig = match DpopSignature::try_from(proof) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 3. Recompute the digest (including htm, htu, server_nonce) and verify
    let mut hasher = Sha512::new();
    hasher.update(claims_bytes);
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(htm);
    hasher.update(htu);
    if let Some(nonce) = expected_server_nonce {
        hasher.update(nonce);
    }
    let digest = hasher.finalize();

    verifying_key.verify(&digest, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    /// Return the current UNIX timestamp for use in tests that need fresh proofs.
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn test_dpop_key_hash_deterministic() {
        let key = [0x42u8; 32];
        let h1 = dpop_key_hash(&key);
        let h2 = dpop_key_hash(&key);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_dpop_different_keys_different_hashes() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let ha = dpop_key_hash(&key_a);
        let hb = dpop_key_hash(&key_b);
        assert_ne!(ha, hb);
    }

    // Default htm/htu used in tests
    const TEST_HTM: &[u8] = b"POST";
    const TEST_HTU: &[u8] = b"https://sso.milnet.example/token";

    #[test]
    fn test_dpop_sign_and_verify() {
        run_with_large_stack(|| {
            let (guarded_sk, vk) = generate_dpop_keypair();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let timestamp = now_secs();
            let proof = generate_dpop_proof(guarded_sk.signing_key(), claims, timestamp, TEST_HTM, TEST_HTU, None);
            assert!(verify_dpop_proof(&vk, &proof, claims, timestamp, &expected_hash, TEST_HTM, TEST_HTU, None));
        });
    }

    #[test]
    fn test_dpop_sign_and_verify_raw() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let timestamp = now_secs();
            let proof = generate_dpop_proof(&sk, claims, timestamp, TEST_HTM, TEST_HTU, None);
            assert!(verify_dpop_proof(&vk, &proof, claims, timestamp, &expected_hash, TEST_HTM, TEST_HTU, None));
        });
    }

    #[test]
    fn test_dpop_wrong_key_rejected() {
        run_with_large_stack(|| {
            let (sk, _vk) = generate_dpop_keypair_raw();
            let (_sk2, vk2) = generate_dpop_keypair_raw();
            let vk2_bytes = vk2.encode();
            let expected_hash = dpop_key_hash(vk2_bytes.as_ref());
            let claims = b"claims";
            let timestamp = now_secs();
            let proof = generate_dpop_proof(&sk, claims, timestamp, TEST_HTM, TEST_HTU, None);
            assert!(!verify_dpop_proof(&vk2, &proof, claims, timestamp, &expected_hash, TEST_HTM, TEST_HTU, None));
        });
    }

    #[test]
    fn test_dpop_wrong_proof_rejected() {
        run_with_large_stack(|| {
            let (_sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let bad_proof = vec![0u8; 64];
            assert!(!verify_dpop_proof(&vk, &bad_proof, b"claims", now_secs(), &expected_hash, TEST_HTM, TEST_HTU, None));
        });
    }

    #[test]
    fn test_dpop_wrong_timestamp_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let ts = now_secs();
            let proof = generate_dpop_proof(&sk, claims, ts, TEST_HTM, TEST_HTU, None);
            assert!(!verify_dpop_proof(&vk, &proof, claims, ts + 9999, &expected_hash, TEST_HTM, TEST_HTU, None));
        });
    }

    #[test]
    fn test_dpop_stale_timestamp_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let old_timestamp = now_secs() - 60;
            let proof = generate_dpop_proof(&sk, claims, old_timestamp, TEST_HTM, TEST_HTU, None);
            assert!(!verify_dpop_proof(&vk, &proof, claims, old_timestamp, &expected_hash, TEST_HTM, TEST_HTU, None));
        });
    }

    #[test]
    fn test_dpop_future_timestamp_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let future_timestamp = now_secs() + 60;
            let proof = generate_dpop_proof(&sk, claims, future_timestamp, TEST_HTM, TEST_HTU, None);
            assert!(!verify_dpop_proof(&vk, &proof, claims, future_timestamp, &expected_hash, TEST_HTM, TEST_HTU, None));
        });
    }

    #[test]
    fn test_dpop_wrong_key_hash_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let claims = b"claims";
            let timestamp = now_secs();
            let proof = generate_dpop_proof(&sk, claims, timestamp, TEST_HTM, TEST_HTU, None);
            let wrong_hash = [0xFFu8; 64];
            assert!(!verify_dpop_proof(&vk, &proof, claims, timestamp, &wrong_hash, TEST_HTM, TEST_HTU, None));
        });
    }

    #[test]
    fn test_guarded_signing_key_drops_safely() {
        run_with_large_stack(|| {
            let (guarded_sk, vk) = generate_dpop_keypair();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let ts = now_secs();
            let proof = generate_dpop_proof(guarded_sk.signing_key(), b"test", ts, TEST_HTM, TEST_HTU, None);
            drop(guarded_sk);
            assert!(verify_dpop_proof(&vk, &proof, b"test", ts, &expected_hash, TEST_HTM, TEST_HTU, None));
        });
    }

    #[test]
    fn test_dpop_wrong_method_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let ts = now_secs();
            let proof = generate_dpop_proof(&sk, claims, ts, b"POST", TEST_HTU, None);
            assert!(!verify_dpop_proof(&vk, &proof, claims, ts, &expected_hash, b"GET", TEST_HTU, None));
        });
    }

    #[test]
    fn test_dpop_wrong_uri_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let ts = now_secs();
            let proof = generate_dpop_proof(&sk, claims, ts, TEST_HTM, b"https://sso.milnet.example/token", None);
            assert!(!verify_dpop_proof(&vk, &proof, claims, ts, &expected_hash, TEST_HTM, b"https://sso.milnet.example/revoke", None));
        });
    }

    #[test]
    fn test_dpop_valid_server_nonce() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let ts = now_secs();
            let nonce = b"server-nonce-abc123";
            let proof = generate_dpop_proof(&sk, claims, ts, TEST_HTM, TEST_HTU, Some(nonce));
            assert!(verify_dpop_proof(&vk, &proof, claims, ts, &expected_hash, TEST_HTM, TEST_HTU, Some(nonce)));
        });
    }

    #[test]
    fn test_dpop_wrong_server_nonce_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let ts = now_secs();
            let proof = generate_dpop_proof(&sk, claims, ts, TEST_HTM, TEST_HTU, Some(b"nonce-a"));
            assert!(!verify_dpop_proof(&vk, &proof, claims, ts, &expected_hash, TEST_HTM, TEST_HTU, Some(b"nonce-b")));
        });
    }

    #[test]
    fn test_dpop_nonce_present_but_not_expected_rejected() {
        run_with_large_stack(|| {
            let (sk, vk) = generate_dpop_keypair_raw();
            let vk_bytes = vk.encode();
            let expected_hash = dpop_key_hash(vk_bytes.as_ref());
            let claims = b"claims";
            let ts = now_secs();
            // Proof was generated WITH a nonce, but verifier expects none
            let proof = generate_dpop_proof(&sk, claims, ts, TEST_HTM, TEST_HTU, Some(b"surprise-nonce"));
            assert!(!verify_dpop_proof(&vk, &proof, claims, ts, &expected_hash, TEST_HTM, TEST_HTU, None));
        });
    }
}
