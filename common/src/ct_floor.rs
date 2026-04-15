//! SC-MARVIN: constant-time floor wrapper.
//!
//! Wraps any verification call (typically RSA / variable-time crypto) so
//! that the observable wall-clock duration is always at least `floor`,
//! regardless of whether the operation succeeded or failed early. This
//! eliminates the Marvin / Bleichenbacher-style timing oracle that lets an
//! attacker distinguish "fast reject" from "slow success".
//!
//! The verification result is captured before the floor sleep so that the
//! sleep itself cannot be skipped on the success path.

use std::time::{Duration, Instant};

/// Synchronous constant-time floor. Use for non-async call sites.
///
/// Returns whatever `op` returned, after blocking the thread until the total
/// elapsed time is at least `floor`.
pub fn constant_time_floor_sync<T, F>(floor: Duration, op: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = op();
    let elapsed = start.elapsed();
    if elapsed < floor {
        std::thread::sleep(floor - elapsed);
    }
    result
}

/// Async constant-time floor. Use inside `async fn` paths that already have
/// access to a tokio runtime — avoids blocking a worker thread.
pub async fn constant_time_floor<T, F>(floor: Duration, op: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = op();
    let elapsed = start.elapsed();
    if elapsed < floor {
        tokio::time::sleep(floor - elapsed).await;
    }
    result
}

/// Default floor for RSA / variable-time verifications. 50 ms matches the
/// existing google_oauth.rs pattern and is large enough to mask any
/// platform-level RSA verify variation observed on x86_64 + AES-NI.
pub const RSA_VERIFY_FLOOR: Duration = Duration::from_millis(50);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_enforces_minimum_duration() {
        let start = Instant::now();
        let v = constant_time_floor_sync(Duration::from_millis(20), || 42u32);
        assert_eq!(v, 42);
        assert!(start.elapsed() >= Duration::from_millis(20));
    }
}
