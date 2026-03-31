//! Synchronization primitives hardened for military-grade reliability.
//!
//! In a military-grade system, a poisoned mutex indicates that a thread
//! panicked while holding the lock, leaving the protected state in an
//! unknown (possibly corrupt) condition. Continuing with corrupt state
//! is unacceptable, so we log an audit-level error and panic.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

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
/// SECURITY: Mutex poisoning indicates a thread panicked while holding a lock.
/// In a military-grade system, this is treated as a compromise indicator.
/// Panic prevents use of potentially corrupted state.
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

// ── SIEM-reporting lock helpers ──────────────────────────────────────────────
//
// These helpers emit a SIEM event on lock poisoning, then recover by using the
// inner guard. Every poisoning incident is visible in the SIEM dashboard while
// the system remains available.

/// Acquire a mutex lock with SIEM-reported poisoning recovery.
pub fn siem_lock<'a, T>(mutex: &'a Mutex<T>, context: &str) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|e| {
        crate::siem::emit_runtime_error(
            crate::siem::category::RUNTIME_ERROR,
            context,
            &format!("mutex poisoned: {e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        tracing::error!("SIEM: mutex poisoned in {context}, recovering: {e}");
        e.into_inner()
    })
}

/// Acquire an RwLock read guard with SIEM-reported poisoning recovery.
pub fn siem_read<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockReadGuard<'a, T> {
    lock.read().unwrap_or_else(|e| {
        crate::siem::emit_runtime_error(
            crate::siem::category::RUNTIME_ERROR,
            context,
            &format!("rwlock read poisoned: {e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        tracing::error!("SIEM: rwlock read poisoned in {context}, recovering: {e}");
        e.into_inner()
    })
}

/// Acquire an RwLock write guard with SIEM-reported poisoning recovery.
pub fn siem_write<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockWriteGuard<'a, T> {
    lock.write().unwrap_or_else(|e| {
        crate::siem::emit_runtime_error(
            crate::siem::category::RUNTIME_ERROR,
            context,
            &format!("rwlock write poisoned: {e}"),
            file!(),
            line!(),
            column!(),
            module_path!(),
        );
        tracing::error!("SIEM: rwlock write poisoned in {context}, recovering: {e}");
        e.into_inner()
    })
}
