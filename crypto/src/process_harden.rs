//! Early process hardening — MUST be the first call in every service `main()`.
//!
//! # Why this module exists
//!
//! Individual services previously called `prctl(PR_SET_DUMPABLE, 0)`,
//! `mlockall`, `PR_SET_NO_NEW_PRIVS`, and `RLIMIT_CORE=0` at scattered points
//! during startup. Any allocation that touches a secret before
//! `PR_SET_DUMPABLE=0` runs can appear in a core dump if the process crashes
//! in the interval. A single chokepoint that runs BEFORE any heap allocation
//! that could hold a secret closes that window.
//!
//! # Module location
//!
//! The CAT-B spec called for `common::process_harden`, but the `crypto` crate
//! already depends on `common`, so the hardening helper lives here alongside
//! `crypto::memguard` (which owns the underlying primitives) to avoid a
//! circular dependency. All service binaries already depend on `crypto`, so
//! the import path is `crypto::process_harden::harden_early`.
//!
//! # Contract
//!
//! `harden_early()` MUST be the very first statement of every binary `main()`,
//! before any allocation, before any env var read, before tokio runtime
//! construction. It applies the union of:
//!   - `mlockall(MCL_CURRENT | MCL_FUTURE)` — no swap, ever.
//!   - `PR_SET_DUMPABLE = 0` — no core dumps.
//!   - `PR_SET_NO_NEW_PRIVS = 1` — suid/setcap bits ignored in exec.
//!   - `PR_SET_PTRACER = 0` — deny ptrace self-attach (Yama LSM).
//!   - `RLIMIT_CORE = 0` — belt-and-suspenders core dump block.
//!
//! The actual primitives live in `crate::memguard::harden_process()`; this
//! module is the single, documented entry point with military-mode semantics:
//! **any failure in military mode aborts the process**.
//!
//! # Idempotency
//!
//! Safe to call more than once; the underlying prctl/mlockall calls are
//! idempotent. A `OnceLock` guards the first-call log message so duplicated
//! calls remain quiet.

use std::sync::OnceLock;

static HARDENED: OnceLock<bool> = OnceLock::new();

/// Apply early process hardening. Call as the FIRST line of every service `main()`.
///
/// In military mode (`MILNET_MILITARY_DEPLOYMENT=1`), any failure aborts the
/// process with exit code 199. In non-military mode, failures degrade to a
/// loud SIEM warning but do not block startup.
///
/// Returns `true` if every hardening primitive succeeded.
pub fn harden_early() -> bool {
    if let Some(&cached) = HARDENED.get() {
        return cached;
    }

    let military_mode = std::env::var("MILNET_MILITARY_DEPLOYMENT").as_deref() == Ok("1");
    let ok = crate::memguard::harden_process();

    if !ok && military_mode {
        // Why: secrets can leak through any of swap, core dump, ptrace attach,
        // or /proc/pid/mem. If any primitive failed, the threat model the
        // military-mode deployment promised is void. Refuse to run rather than
        // silently degrade.
        eprintln!(
            "FATAL: process hardening failed in military mode. \
             One of mlockall/PR_SET_DUMPABLE/PR_SET_NO_NEW_PRIVS/RLIMIT_CORE \
             could not be applied. Refusing to start to avoid swap/coredump/ptrace \
             secret exfiltration. Check RLIMIT_MEMLOCK, CAP_IPC_LOCK, and kernel Yama LSM."
        );
        std::process::exit(199);
    }

    let _ = HARDENED.set(ok);

    if ok {
        // Why: emitted exactly once per process so SIEM can correlate the
        // moment hardening took effect with later events.
        tracing::info!(
            target: "siem",
            event = "process_harden_applied",
            military_mode,
            "process hardening complete (mlockall, PR_SET_DUMPABLE=0, PR_SET_NO_NEW_PRIVS=1, PR_SET_PTRACER=0, RLIMIT_CORE=0)"
        );
    } else {
        tracing::warn!(
            target: "siem",
            severity = "HIGH",
            event = "process_harden_degraded",
            "SIEM:HIGH process hardening partially failed. Secrets may be exposed to swap, core dumps, or ptrace."
        );
    }

    ok
}

/// Returns `true` if `harden_early()` has been called and succeeded.
pub fn is_hardened() -> bool {
    HARDENED.get().copied().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_early_is_idempotent() {
        // Why: harden_early must be safe to call multiple times because the
        // library-init path and the main()-first-line path both call it.
        let first = harden_early();
        let second = harden_early();
        assert_eq!(first, second);
        assert_eq!(is_hardened(), first);
    }
}
