//! Synchronization primitives hardened for military-grade reliability.
//!
//! In a military-grade system, a poisoned mutex indicates that a thread
//! panicked while holding the lock, leaving the protected state in an
//! unknown (possibly corrupt) condition. Continuing with corrupt state
//! is unacceptable, so we log an audit-level error and panic.

use std::sync::{Mutex, MutexGuard};

/// Acquire a mutex lock with military-grade poisoning policy.
///
/// If the mutex is poisoned (a previous holder panicked), this function
/// logs a critical error and panics. In a military-grade system,
/// corrupt shared state is never acceptable -- the process must restart
/// to regain a known-good state.
///
/// # Panics
///
/// Panics if the mutex is poisoned.
pub fn lock_or_panic<'a, T>(mutex: &'a Mutex<T>, context: &str) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|e| {
        tracing::error!(
            "CRITICAL: mutex poisoned in {context} -- shared state may be corrupt, \
             process must restart: {e}"
        );
        panic!("mutex poisoned in {context}: shared state integrity lost");
    })
}

/// Acquire a mutex lock, recovering from poisoning with a warning.
///
/// Use this only for non-critical state where availability is more
/// important than integrity (e.g., metrics, caches). For security-critical
/// state (crypto keys, auth state), use [`lock_or_panic`] instead.
pub fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>, context: &str) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|e| {
        tracing::warn!(
            "mutex poisoned in {context} -- recovering with potentially stale state: {e}"
        );
        e.into_inner()
    })
}
