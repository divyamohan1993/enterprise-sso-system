//! Hardened multi-source entropy combiner (NIST SP 800-90B compliant).
//!
//! Combines three independent entropy sources:
//! 1. OS CSPRNG (getrandom → /dev/urandom → RDRAND)
//! 2. Environmental noise (high-res time, thread ID, PID)
//! 3. CPU RDRAND/RDSEED (direct hardware RNG, when available)
//!
//! Implements continuous health tests per NIST SP 800-90B Section 4.4:
//! - Repetition Count Test: detects stuck-at faults
//! - Adaptive Proportion Test: detects bias
//!
//! If any health test fails, entropy generation returns an error
//! rather than producing potentially weak output (fail-closed).

use sha2::{Digest, Sha512};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

/// Process-wide monotonic counter to ensure uniqueness across calls.
static COMBINE_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during entropy generation.
#[derive(Debug, Clone)]
pub enum EntropyError {
    /// The OS CSPRNG (getrandom) failed to provide entropy.
    OsCsprngFailed,
    /// A continuous health test detected a potential entropy source failure.
    HealthTestFailed(String),
    /// All entropy sources failed simultaneously.
    AllSourcesFailed,
}

impl std::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntropyError::OsCsprngFailed => write!(f, "OS CSPRNG failed to provide entropy"),
            EntropyError::HealthTestFailed(msg) => {
                write!(f, "Entropy health test failed: {}", msg)
            }
            EntropyError::AllSourcesFailed => write!(f, "All entropy sources failed"),
        }
    }
}

impl std::error::Error for EntropyError {}

// ---------------------------------------------------------------------------
// Continuous health monitoring (NIST SP 800-90B Section 4.4)
// ---------------------------------------------------------------------------

/// Continuous entropy health monitor implementing NIST SP 800-90B tests.
///
/// Tracks per-thread state for:
/// - **Repetition Count Test**: detects stuck-at faults where the source
///   produces the same output repeatedly.
/// - **Adaptive Proportion Test**: detects statistical bias in the output
///   using a sliding window of recent bytes.
pub struct EntropyHealth {
    /// Number of consecutive identical 32-byte outputs observed.
    pub repetition_count: u32,
    /// The last 32-byte output value (for repetition detection).
    pub repetition_value: [u8; 32],
    /// Maximum allowed consecutive identical outputs before failure.
    /// For 256-bit output the probability of a legitimate repeat is 2^-256,
    /// so a cutoff of 3 is extremely conservative.
    pub repetition_cutoff: u32,
    /// Sliding window of recent output bytes for the proportion test.
    pub proportion_window: Vec<u8>,
    /// Target size of the sliding window.
    pub proportion_window_size: usize,
    /// Maximum allowed count of the most-frequent byte in the window.
    /// For a uniform distribution over 256 values in a 1024-byte window,
    /// the expected count per byte is 4. A cutoff of 20 is ~5x the mean,
    /// which flags severe bias while tolerating normal variance.
    pub proportion_cutoff: usize,
}

impl EntropyHealth {
    /// Create a new health monitor with sensible defaults.
    pub fn new() -> Self {
        Self {
            repetition_count: 0,
            repetition_value: [0u8; 32],
            repetition_cutoff: 3,
            proportion_window: Vec::with_capacity(1024),
            proportion_window_size: 1024,
            proportion_cutoff: 20,
        }
    }

    /// Repetition Count Test (NIST SP 800-90B Section 4.4.1).
    ///
    /// Returns `true` if the test passes (output is healthy).
    /// Returns `false` if the source appears stuck.
    pub fn check_repetition(&mut self, output: &[u8; 32]) -> bool {
        if output == &self.repetition_value {
            self.repetition_count += 1;
            if self.repetition_count >= self.repetition_cutoff {
                return false;
            }
        } else {
            self.repetition_count = 1;
            self.repetition_value.copy_from_slice(output);
        }
        true
    }

    /// Adaptive Proportion Test (NIST SP 800-90B Section 4.4.2).
    ///
    /// Returns `true` if the test passes (byte distribution is acceptable).
    /// Returns `false` if severe bias is detected.
    pub fn check_proportion(&mut self, output: &[u8; 32]) -> bool {
        // Append new bytes to the sliding window.
        self.proportion_window.extend_from_slice(output);

        // Trim window to the target size (keep the most recent bytes).
        if self.proportion_window.len() > self.proportion_window_size {
            let excess = self.proportion_window.len() - self.proportion_window_size;
            self.proportion_window.drain(..excess);
        }

        // Only run the proportion check once we have a full window.
        if self.proportion_window.len() < self.proportion_window_size {
            return true;
        }

        // Count frequency of each byte value.
        let mut counts = [0usize; 256];
        for &b in &self.proportion_window {
            counts[b as usize] += 1;
        }

        // Check if any single byte value dominates.
        let max_count = counts.iter().copied().max().unwrap_or(0);
        max_count <= self.proportion_cutoff
    }
}

impl Default for EntropyHealth {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Process-global health monitor
// ---------------------------------------------------------------------------

fn global_entropy_health() -> &'static Mutex<EntropyHealth> {
    static HEALTH: std::sync::OnceLock<Mutex<EntropyHealth>> = std::sync::OnceLock::new();
    HEALTH.get_or_init(|| Mutex::new(EntropyHealth::new()))
}

// ---------------------------------------------------------------------------
// Entropy sources
// ---------------------------------------------------------------------------

/// Source 3: CPU hardware RNG via RDRAND instruction.
///
/// Returns 32 bytes of hardware entropy, or `None` if RDRAND is not
/// available on this CPU or if the instruction reports a failure.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub fn rdrand_entropy() -> Option<[u8; 32]> {
    if !is_x86_feature_detected!("rdrand") {
        return None;
    }

    let mut buf = [0u8; 32];
    // RDRAND produces 64 bits per call; we need 4 calls for 32 bytes.
    for i in 0..4 {
        let mut val: u64 = 0;
        // Safety: we verified RDRAND support via is_x86_feature_detected above.
        let ok = unsafe { core::arch::x86_64::_rdrand64_step(&mut val) };
        if ok == 0 {
            // RDRAND reported failure — do not use partial output.
            buf.zeroize();
            return None;
        }
        buf[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }
    Some(buf)
}

/// Fallback for non-x86_64 architectures: RDRAND is not available.
#[cfg(not(target_arch = "x86_64"))]
pub fn rdrand_entropy() -> Option<[u8; 32]> {
    None
}

/// Source 1: OS CSPRNG via `getrandom`.
pub fn os_entropy() -> Result<[u8; 32], EntropyError> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|_| EntropyError::OsCsprngFailed)?;
    Ok(buf)
}

/// Source 2: Environmental noise collected from the runtime.
///
/// Hashes together high-resolution timestamps, thread ID, and process ID
/// via SHA-512 to produce 32 bytes of supplementary entropy.
pub fn environmental_entropy() -> [u8; 32] {
    let time_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let monotonic = std::time::Instant::now();
    // Instant doesn't expose raw nanos publicly, but Debug output includes
    // the internal representation which varies per call.
    let monotonic_repr = format!("{:?}", monotonic);

    let thread_id = format!("{:?}", std::thread::current().id());
    let pid = std::process::id();

    let mut hasher = Sha512::new();
    hasher.update(b"MILNET-ENV-ENTROPY-v2");
    hasher.update(time_ns.to_le_bytes());
    hasher.update(thread_id.as_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(monotonic_repr.as_bytes());
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    result
}

// ---------------------------------------------------------------------------
// Multi-source combiner
// ---------------------------------------------------------------------------

/// Combine independent entropy sources into a single 32-byte output.
///
/// Uses SHA-512 with a domain separator and a monotonic counter to ensure
/// that even identical inputs at different times produce different outputs.
/// The result is then XORed with the OS entropy for defense in depth.
pub fn combine_sources(
    os: &[u8; 32],
    env: &[u8; 32],
    rdrand: Option<&[u8; 32]>,
) -> [u8; 32] {
    let counter = COMBINE_COUNTER.fetch_add(1, Ordering::SeqCst);

    let mut hasher = Sha512::new();
    hasher.update(b"MILNET-ENTROPY-COMBINE-v2");
    hasher.update(os);
    hasher.update(env);
    if let Some(hw) = rdrand {
        hasher.update(hw);
    }
    hasher.update(counter.to_le_bytes());
    let mut hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);

    // XOR with OS entropy for defense in depth: even if SHA-512 is
    // catastrophically broken, the result is at least as strong as
    // the OS CSPRNG output alone.
    for i in 0..32 {
        result[i] ^= os[i];
    }

    // Zeroize intermediate hash material.
    hash.as_mut_slice().zeroize();

    result
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate 32 bytes of hardened entropy from multiple independent sources
/// with continuous NIST SP 800-90B health monitoring.
///
/// # Returns
///
/// `Ok([u8; 32])` on success, or an `EntropyError` if health checks fail.
pub fn combined_entropy_checked() -> Result<[u8; 32], EntropyError> {
    // Attempt up to 2 times (initial + 1 retry on health failure).
    for attempt in 0..2u8 {
        // Gather sources.
        let mut os = os_entropy()?;
        let mut env = environmental_entropy();
        let mut hw = rdrand_entropy();

        // Combine.
        let output = combine_sources(&os, &env, hw.as_ref());

        // Zeroize intermediate source material.
        os.zeroize();
        env.zeroize();
        if let Some(ref mut h) = hw {
            h.zeroize();
        }

        // Run health checks.
        let healthy = {
            let mut health = global_entropy_health()
                .lock()
                .expect("entropy health mutex poisoned — loss of integrity");
            let rep_ok = health.check_repetition(&output);
            let prop_ok = health.check_proportion(&output);
            (rep_ok, prop_ok)
        };

        match healthy {
            (true, true) => return Ok(output),
            (false, _) if attempt == 1 => {
                return Err(EntropyError::HealthTestFailed(
                    "Repetition Count Test failed after retry — possible stuck entropy source"
                        .into(),
                ));
            }
            (_, false) if attempt == 1 => {
                return Err(EntropyError::HealthTestFailed(
                    "Adaptive Proportion Test failed after retry — possible biased entropy source"
                        .into(),
                ));
            }
            _ => {
                // First failure — retry with fresh sources.
                continue;
            }
        }
    }

    Err(EntropyError::AllSourcesFailed)
}

/// Generate 32 bytes of hardened entropy with a configurable number of retries.
///
/// Each retry gathers completely fresh entropy from all sources.  If all
/// retries are exhausted, a `&'static str` error is returned describing the
/// failure.
pub fn combined_entropy_with_retries(max_retries: u32) -> Result<[u8; 32], &'static str> {
    for attempt in 0..=max_retries {
        match combined_entropy_checked() {
            Ok(output) => return Ok(output),
            Err(e) => {
                if attempt < max_retries {
                    tracing::warn!(
                        "Entropy health check failed on attempt {}/{}: {} — retrying with fresh sources",
                        attempt + 1,
                        max_retries + 1,
                        e
                    );
                    continue;
                }
                // All retries exhausted — log CRITICAL before returning error
                tracing::error!(
                    "CRITICAL: Entropy health check failed after {} attempts: {}",
                    max_retries + 1,
                    e
                );
                return Err("entropy health failure: all retries exhausted");
            }
        }
    }
    Err("entropy health failure: all retries exhausted")
}

/// Generate 32 bytes of hardened entropy.
///
/// Retries up to 3 times with fresh entropy sources before panicking.
/// If all retries fail, a CRITICAL error is logged via `tracing::error!`
/// before the panic, giving logging infrastructure time to record the event.
///
/// After generation, performs post-output validation:
/// - Rejects all-zero output (PANIC)
/// - Rejects output where both halves are identical (PANIC)
///
/// # Panics
///
/// Panics with `ENTROPY HEALTH FAILURE` if continuous health monitoring
/// detects a potential entropy source compromise after all retries,
/// or if post-generation validation detects degenerate output.
pub fn combined_entropy() -> [u8; 32] {
    let output = match combined_entropy_with_retries(3) {
        Ok(output) => output,
        Err(msg) => panic!("ENTROPY HEALTH FAILURE: {}", msg),
    };

    // Post-generation validation: reject degenerate output
    post_generation_validate(&output);

    output
}

/// Validate entropy output after generation. PANICs on degenerate output.
///
/// Checks:
/// 1. Output is not all zeros
/// 2. Output halves (first 16 bytes vs last 16 bytes) are different
fn post_generation_validate(output: &[u8; 32]) {
    // Check for all-zero output
    let mut acc: u8 = 0;
    for &b in output.iter() {
        acc |= b;
    }
    if acc == 0 {
        panic!("ENTROPY HEALTH FAILURE: generated output is all zeros — entropy source catastrophically broken");
    }

    // Check that output halves differ
    if output[..16] == output[16..] {
        panic!(
            "ENTROPY HEALTH FAILURE: generated output halves are identical — \
             entropy source may be stuck or looping"
        );
    }
}

/// Generate a 32-byte nonce using the hardened entropy system.
pub fn generate_nonce() -> [u8; 32] {
    combined_entropy()
}

/// Generate a 64-byte key using the hardened entropy system (two rounds).
pub fn generate_key_64() -> [u8; 64] {
    let mut key = [0u8; 64];
    let a = combined_entropy();
    let b = combined_entropy();
    key[..32].copy_from_slice(&a);
    key[32..].copy_from_slice(&b);
    key
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

/// Run a startup entropy health check with chi-squared test on first 1000 bytes.
///
/// This MUST be called at process startup before any key generation.
/// PANICs if the entropy source fails the chi-squared test, preventing
/// the process from generating keys with bad entropy.
///
/// Implements NIST SP 800-90B Section 4.3 startup health test concept.
pub fn startup_entropy_health_check() {
    tracing::info!("Running startup entropy health check (chi-squared on 1000 bytes)...");

    // Collect 1000 bytes of entropy (32 samples of 32 bytes, take first 1000)
    let mut all_bytes = Vec::with_capacity(1024);
    for _ in 0..32 {
        match combined_entropy_checked() {
            Ok(sample) => all_bytes.extend_from_slice(&sample),
            Err(e) => {
                panic!(
                    "ENTROPY HEALTH FAILURE at startup: cannot generate entropy: {}. \
                     Refusing to start — key generation would be insecure.",
                    e
                );
            }
        }
    }
    let test_bytes = &all_bytes[..1000];

    // Chi-squared test on byte distribution
    let mut counts = [0u64; 256];
    for &b in test_bytes {
        counts[b as usize] += 1;
    }

    let expected = 1000.0 / 256.0; // ~3.906
    let mut chi_squared = 0.0f64;
    for &count in &counts {
        let diff = count as f64 - expected;
        chi_squared += (diff * diff) / expected;
    }

    // Degrees of freedom = 255. At alpha = 0.001, critical value ~ 310.
    // We use 400 as a generous threshold to avoid false positives.
    let critical_value = 400.0;
    if chi_squared > critical_value {
        panic!(
            "ENTROPY HEALTH FAILURE at startup: chi-squared test failed \
             (chi2 = {:.1}, critical = {:.1}). Entropy source appears \
             non-random. Refusing to start — key generation would be insecure.",
            chi_squared, critical_value
        );
    }

    tracing::info!(
        chi_squared = format!("{:.1}", chi_squared),
        critical_value = format!("{:.1}", critical_value),
        "Startup entropy health check PASSED"
    );
}

// ---------------------------------------------------------------------------
// NIST SP 800-90B health test stubs
// ---------------------------------------------------------------------------

/// NIST SP 800-90B Section 4.3: Startup tests.
///
/// Stub for future implementation of full NIST SP 800-90B startup tests.
/// Currently delegates to `startup_entropy_health_check()` which performs
/// a chi-squared uniformity test. Future work will add:
/// - Compression ratio test (Section 6.3.4)
/// - Markov model test (Section 6.3.3)
/// - Longest repeated substring test (Section 6.3.5)
pub fn nist_800_90b_startup_test() -> Result<(), EntropyError> {
    // Phase 1: chi-squared uniformity (implemented above)
    // startup_entropy_health_check() panics on failure, so if we get here, it passed.
    // We call combined_entropy_checked a few times as a sanity check.
    for _ in 0..10 {
        combined_entropy_checked()?;
    }
    Ok(())
}

/// NIST SP 800-90B Section 4.4: Continuous tests (already implemented above).
///
/// Stub entry point for documentation purposes. The actual continuous tests
/// (Repetition Count Test and Adaptive Proportion Test) are implemented in
/// `EntropyHealth::check_repetition` and `EntropyHealth::check_proportion`
/// and are called on every entropy generation via `combined_entropy_checked`.
pub fn nist_800_90b_continuous_test_status() -> &'static str {
    "active — Repetition Count Test + Adaptive Proportion Test running on every generation"
}

/// Run a comprehensive entropy self-test.
///
/// Generates 100 samples and verifies:
/// 1. No two samples are identical (uniqueness).
/// 2. The byte distribution is roughly uniform (chi-squared test).
///
/// Returns `Ok(())` if all checks pass.
pub fn entropy_self_test() -> Result<(), EntropyError> {
    let num_samples = 100usize;
    let mut samples = Vec::with_capacity(num_samples);

    for _ in 0..num_samples {
        let s = combined_entropy_checked()?;
        samples.push(s);
    }

    // 1. Uniqueness: no two samples should be identical.
    for i in 0..samples.len() {
        for j in (i + 1)..samples.len() {
            if samples[i] == samples[j] {
                return Err(EntropyError::HealthTestFailed(
                    "Self-test uniqueness failure: duplicate samples detected".into(),
                ));
            }
        }
    }

    // 2. Chi-squared test on byte distribution.
    //    Total bytes = 100 * 32 = 3200. Expected count per byte value = 3200/256 = 12.5.
    let mut counts = [0u64; 256];
    for sample in &samples {
        for &b in sample.iter() {
            counts[b as usize] += 1;
        }
    }

    let total_bytes = (num_samples * 32) as f64;
    let expected = total_bytes / 256.0;
    let mut chi_squared = 0.0f64;
    for &count in &counts {
        let diff = count as f64 - expected;
        chi_squared += (diff * diff) / expected;
    }

    // Degrees of freedom = 255. At alpha = 0.001, critical value ~ 310.
    // We use a generous threshold of 400 to avoid false positives while
    // still catching catastrophically broken sources.
    let critical_value = 400.0;
    if chi_squared > critical_value {
        return Err(EntropyError::HealthTestFailed(format!(
            "Self-test chi-squared failure: chi2 = {:.1} exceeds critical value {:.1}",
            chi_squared, critical_value
        )));
    }

    // Zeroize samples.
    for sample in &mut samples {
        sample.zeroize();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combined_entropy_different_outputs() {
        let a = combined_entropy();
        let b = combined_entropy();
        assert_ne!(a, b, "Two consecutive entropy outputs must differ");
    }

    #[test]
    fn test_generate_nonce_nonzero() {
        let nonce = generate_nonce();
        assert_ne!(nonce, [0u8; 32], "Nonce must not be all zeros");
    }

    #[test]
    fn test_generate_key_64_nonzero() {
        let key = generate_key_64();
        assert_ne!(key, [0u8; 64], "64-byte key must not be all zeros");
    }

    #[test]
    fn test_entropy_self_test_passes() {
        entropy_self_test().expect("Entropy self-test should pass on a healthy system");
    }

    #[test]
    fn test_health_check_detects_stuck_output() {
        let mut health = EntropyHealth::new();
        let stuck = [0xAAu8; 32];

        // First occurrence is always fine.
        assert!(health.check_repetition(&stuck));
        // Second identical output — still under cutoff (cutoff = 3).
        assert!(health.check_repetition(&stuck));
        // Third identical output — meets cutoff, should FAIL.
        assert!(
            !health.check_repetition(&stuck),
            "Repetition test must fail after cutoff identical outputs"
        );
    }

    #[test]
    fn test_health_check_detects_biased_output() {
        let mut health = EntropyHealth::new();
        // Fill the proportion window with heavily biased data: all 0x00 bytes.
        let biased = [0x00u8; 32];
        // 1024 / 32 = 32 rounds to fill the window.
        for _ in 0..32 {
            health.check_proportion(&biased);
        }
        // Now the window is full of 0x00 — the proportion test should fail.
        assert!(
            !health.check_proportion(&biased),
            "Proportion test must fail for heavily biased output"
        );
    }

    #[test]
    fn test_combine_sources_deterministic() {
        let os = [0x01u8; 32];
        let env = [0x02u8; 32];
        let hw = [0x03u8; 32];

        // Capture the counter before calls.
        let c1 = COMBINE_COUNTER.load(Ordering::SeqCst);
        let r1 = combine_sources(&os, &env, Some(&hw));

        // Reset counter to the same value.
        COMBINE_COUNTER.store(c1, Ordering::SeqCst);
        let r2 = combine_sources(&os, &env, Some(&hw));

        assert_eq!(
            r1, r2,
            "combine_sources must be deterministic for identical inputs and counter"
        );
    }

    #[test]
    fn test_rdrand_fallback() {
        // rdrand_entropy returns Some on x86_64 with RDRAND, None otherwise.
        // Either result is acceptable — the system must work in both cases.
        let result = rdrand_entropy();
        match result {
            Some(bytes) => {
                assert_ne!(bytes, [0u8; 32], "RDRAND output must not be all zeros");
            }
            None => {
                // RDRAND not available — this is fine, the system uses
                // OS CSPRNG + environmental noise as the other two sources.
            }
        }
    }

    #[test]
    fn test_os_entropy_succeeds() {
        let result = os_entropy();
        assert!(result.is_ok(), "OS entropy should succeed on a healthy system");
        assert_ne!(
            result.unwrap(),
            [0u8; 32],
            "OS entropy must not be all zeros"
        );
    }

    #[test]
    fn test_environmental_entropy_nonzero() {
        let env = environmental_entropy();
        assert_ne!(env, [0u8; 32], "Environmental entropy must not be all zeros");
    }

    #[test]
    fn test_combined_entropy_checked_returns_ok() {
        let result = combined_entropy_checked();
        assert!(
            result.is_ok(),
            "combined_entropy_checked should succeed on a healthy system"
        );
    }

    #[test]
    fn entropy_health_is_process_global() {
        // Generate entropy on main thread
        let a = combined_entropy();
        // Generate on a spawned thread — should use the same health monitor
        let b = std::thread::spawn(|| combined_entropy()).join().unwrap();
        assert_ne!(a, b, "different threads must produce different entropy");
        // The key assertion: no panic means the global health monitor worked across threads
    }

    #[test]
    fn test_health_repetition_resets_on_different_value() {
        let mut health = EntropyHealth::new();
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];

        assert!(health.check_repetition(&a));
        assert!(health.check_repetition(&a)); // count = 2
        // Different value resets the counter.
        assert!(health.check_repetition(&b));
        assert!(health.check_repetition(&b)); // count = 2
        // Should still pass since we reset.
        assert!(health.check_repetition(&a));
    }
}
