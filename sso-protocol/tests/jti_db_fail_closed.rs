//! Regression test for **X-G** — `DatabaseJtiStore` panic + fail-open.
//!
//! Defects cited at:
//!   - `sso-protocol/src/tokens.rs:137-156` (legacy `mark_used` block_on)
//!   - `sso-protocol/src/tokens.rs:181-200` (legacy `is_used` block_on +
//!     `unwrap_or(0) > 0` fail-open)
//!
//! Original bugs:
//!   1. Both methods built a fresh `tokio::runtime::Builder::new_current_thread`
//!      and called `rt.block_on(...)` from inside an existing tokio runtime,
//!      which panics with "Cannot start a runtime from within a runtime"
//!      under any async server stack.
//!   2. `is_used` swallowed all DB errors via `unwrap_or(0) > 0`,
//!      reporting any replayed JTI as fresh when Postgres was briefly
//!      unavailable — fail-open against the system's last defence
//!      against stolen-token reuse.
//!
//! Fix under test:
//!   - The legacy sync `JtiReplayStore` impl on `DatabaseJtiStore` now
//!     fails CLOSED instead of panicking: `mark_used` returns
//!     `Ok(false)` ("not fresh" → verifier rejects), `is_used` returns
//!     `true` ("used" → verifier rejects). Both emit a SIEM CRITICAL
//!     `jti_store.db_failure` audit event via
//!     `common::audit_bridge::buffer_audit_entry`.
//!   - The new `AsyncJtiReplayStore` trait exposes the correct async
//!     path. Any `sqlx::Error` along that path also returns the
//!     fail-closed sentinel (`Ok(false)` / `true`) and emits the same
//!     audit event.
//!
//! This integration test induces a DB error by pointing the pool at a
//! non-existent server (lazy connect; the actual error fires on
//! query execution). It then asserts:
//!   1. The async `is_used` returns `true` (deny) — fail-closed.
//!   2. The async `mark_used` returns `Ok(false)` (deny) — fail-closed.
//!   3. A `SystemDegraded` audit entry was buffered with the
//!      X-G failure marker in `request_id`.
//!   4. The legacy sync `is_used` does NOT panic and also fails
//!      closed (`true`) — defence-in-depth for callers that have not
//!      yet migrated.

use common::audit_bridge::{buffer_audit_entry as _, drain_audit_buffer};
use common::types::AuditEventType;
use sqlx::postgres::PgPoolOptions;
use sso_protocol::tokens::{
    AsyncJtiReplayStore, DatabaseJtiStore, JtiReplayStore,
};

fn build_unreachable_pool() -> sqlx::PgPool {
    // Non-routable IP — `connect_lazy` succeeds (no I/O); the actual
    // sqlx::Error fires when a query tries to execute. RFC 5737
    // TEST-NET-1 (192.0.2.0/24) is the canonical un-routable space.
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(500))
        .connect_lazy("postgres://test:test@192.0.2.1:5432/jti_test_does_not_exist")
        .expect("connect_lazy must succeed for syntactically-valid URL")
}

#[tokio::test(flavor = "current_thread")]
async fn async_is_used_fails_closed_on_db_error() {
    let _ = drain_audit_buffer();

    let store = DatabaseJtiStore::new(build_unreachable_pool(), 1024);
    let jti = "jti-fail-closed-is-used";

    // The DB is unreachable; the L1 cache has not seen this JTI; the
    // pre-fix code returned `unwrap_or(0) > 0` = false (fail-OPEN). The
    // post-fix code must emit SIEM CRITICAL and return `true` (deny).
    let used = AsyncJtiReplayStore::is_used(&store, jti).await;
    assert!(
        used,
        "X-G regression: is_used must fail closed (return true / deny) \
         when the database is unreachable — pre-fix this returned false \
         (fail-OPEN), allowing replayed tokens through"
    );

    // SIEM CRITICAL audit must have been emitted.
    let drained = drain_audit_buffer();
    let found = drained.iter().any(|e| {
        matches!(e.event_type, AuditEventType::SystemDegraded)
            && e.request_id
                .as_deref()
                .is_some_and(|r| r.starts_with("jti_store.db_failure:"))
    });
    assert!(
        found,
        "X-G regression: SIEM CRITICAL `jti_store.db_failure` audit event \
         must be buffered on DB failure (got entries: {:?})",
        drained
            .iter()
            .map(|e| (&e.event_type, &e.request_id))
            .collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn async_mark_used_fails_closed_on_db_error() {
    let _ = drain_audit_buffer();

    let store = DatabaseJtiStore::new(build_unreachable_pool(), 1024);
    let jti = "jti-fail-closed-mark-used";

    // Pre-fix: the legacy block_on path either panicked (nested runtime)
    // or surfaced an `Err`. Post-fix: any sqlx error returns Ok(false)
    // (= "not fresh" = caller rejects with "JTI replay detected") and
    // emits a SIEM CRITICAL audit event.
    let res = AsyncJtiReplayStore::mark_used(&store, jti, 9_999_999_999_i64).await;
    match res {
        Ok(false) => {} // fail-closed sentinel
        Ok(true) => panic!(
            "X-G regression: mark_used must fail closed (Ok(false)) on DB \
             error; got Ok(true) = treating the JTI as a fresh insert \
             without DB confirmation"
        ),
        Err(e) => panic!(
            "X-G regression: mark_used must NOT propagate raw sqlx errors; \
             expected Ok(false) sentinel, got Err({e})"
        ),
    }

    // No panic from a nested-runtime block_on (this whole test is inside
    // a tokio runtime). Confirm SIEM emission occurred.
    let drained = drain_audit_buffer();
    let found = drained.iter().any(|e| {
        matches!(e.event_type, AuditEventType::SystemDegraded)
            && e.request_id
                .as_deref()
                .is_some_and(|r| r.starts_with("jti_store.db_failure:"))
    });
    assert!(found, "expected jti_store.db_failure audit on DB error");
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_sync_is_used_does_not_panic_and_fails_closed() {
    let _ = drain_audit_buffer();

    let store = DatabaseJtiStore::new(build_unreachable_pool(), 1024);
    // Pre-fix: this would build a nested runtime via `block_on` and
    // panic ("Cannot start a runtime from within a runtime"). Post-fix:
    // the sync path returns `true` (fail-closed, deny) without ever
    // touching the DB, and emits a SIEM CRITICAL audit event.
    let used = <DatabaseJtiStore as JtiReplayStore>::is_used(&store, "legacy-jti");
    assert!(
        used,
        "X-G regression: legacy sync is_used must fail closed (return \
         true / deny) when called against DatabaseJtiStore — pre-fix \
         this panicked or returned false (fail-OPEN)"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_sync_mark_used_does_not_panic_and_fails_closed() {
    let _ = drain_audit_buffer();

    let store = DatabaseJtiStore::new(build_unreachable_pool(), 1024);
    let res = <DatabaseJtiStore as JtiReplayStore>::mark_used(&store, "legacy-jti", 0);
    assert!(
        matches!(res, Ok(false)),
        "X-G regression: legacy sync mark_used must fail closed \
         (Ok(false) / treat as replay), got {res:?}"
    );
}
