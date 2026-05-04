//! Regression test for **X-H** — refresh tokens unredeemable after restart.
//!
//! Defect cited at:
//!   - `sso-protocol/src/tokens.rs:560-590` (legacy `load_from_db`)
//!
//! Original bug: `PersistentRefreshTokenStore::load_from_db` inserted
//! loaded refresh tokens into the in-memory `tokens` map keyed by the
//! `token_hash` column read from Postgres (SHA-512 hex). However
//! `RefreshTokenStore::redeem` (and `issue`/`get` paths) looked the
//! entry up by the raw token string. After ANY process restart, every
//! previously-issued refresh token became unredeemable: the verifier
//! returned "refresh token not found" even though the row existed in
//! Postgres. This silently broke the entire refresh-token rotation
//! flow on the first deployment that restarted a node.
//!
//! Fix under test: both `issue_in_family` and `redeem` now key the
//! in-memory map via `rt_lookup_key(raw) = hex(SHA-512(raw))` — the
//! same formula the persistent layer's `token_hash` column uses. This
//! integration test issues a refresh token, simulates a restart by
//! tearing down and re-creating the `PersistentRefreshTokenStore`, and
//! redeems the original raw token successfully.
//!
//! ## Running
//!
//! Requires a writable Postgres at `MILNET_TEST_PG_URL`. Skips
//! cleanly (PASS) when the env var is unset — the in-memory simulated-
//! restart variant in `sso-protocol/src/tokens.rs::tests` covers the
//! key-formula invariant without Postgres.
//!
//! Schema bootstrap is performed by the test itself (`CREATE TABLE IF
//! NOT EXISTS refresh_tokens (...)`); each run uses a per-test prefix
//! on `family_id` for isolation.

use sqlx::postgres::PgPoolOptions;
use sso_protocol::tokens::PersistentRefreshTokenStore;
use uuid::Uuid;

const SCHEMA_DDL: &str = "
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        token_hash  TEXT PRIMARY KEY,
        user_id     UUID NOT NULL,
        client_id   TEXT NOT NULL,
        scope       TEXT NOT NULL,
        expires_at  BIGINT NOT NULL,
        used        BOOLEAN NOT NULL,
        family_id   TEXT NOT NULL
    );
";

#[tokio::test(flavor = "current_thread")]
async fn refresh_token_survives_restart() {
    let url = match std::env::var("MILNET_TEST_PG_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!(
                "skipping rt_survives_restart: MILNET_TEST_PG_URL not set. \
                 The in-module test `rt_survives_simulated_restart` covers \
                 the X-H key-formula invariant without Postgres."
            );
            return;
        }
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("connect to MILNET_TEST_PG_URL");

    sqlx::query(SCHEMA_DDL)
        .execute(&pool)
        .await
        .expect("create refresh_tokens schema");

    // Phase 1: issue a refresh token through the persistent store.
    let mut store_v1 = PersistentRefreshTokenStore::new(pool.clone())
        .await
        .expect("create v1 store");
    let user = Uuid::new_v4();
    let client = format!("rt-survives-{}", Uuid::new_v4());
    let raw = store_v1
        .issue(user, &client, "openid offline_access")
        .await
        .expect("issue refresh token");
    drop(store_v1);

    // Phase 2: simulate restart by re-creating the store. The new
    // store's constructor calls `load_from_db`, which (pre-fix) keyed
    // the in-memory map by `token_hash` while `redeem` looked up by
    // the raw token — every restart-loaded token was unredeemable.
    let mut store_v2 = PersistentRefreshTokenStore::new(pool.clone())
        .await
        .expect("create v2 store after simulated restart");

    // Phase 3: redeem the original raw token. Post-fix this succeeds.
    let res = store_v2.redeem(&raw, &client).await;
    assert!(
        res.is_ok(),
        "X-H regression: previously-issued refresh token must remain \
         redeemable across a restart-rehydrate cycle, got {:?}",
        res.err()
    );

    // Cleanup: revoke this test's family so we don't leave rows behind.
    let (old_rt, _new_token) = res.unwrap();
    let _ = store_v2.revoke_family(&old_rt.family_id).await;
}
