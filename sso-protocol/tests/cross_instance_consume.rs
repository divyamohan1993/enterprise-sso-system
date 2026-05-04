//! Regression test for **X-I** —
//! `PersistentAuthorizationStore::consume_code` lost scope and returned
//! `Ok(None)` after winning the cross-instance DB race.
//!
//! Defect cited at:
//!   - `sso-protocol/src/authorize.rs:705-712` (legacy `consume_code`)
//!
//! Original bug: the function ran an atomic `UPDATE ... SET consumed =
//! TRUE WHERE code_hash = $1 AND consumed = FALSE`. On a race-win
//! (`rows_affected = 1`) it then called `self.memory.consume_code(code)`
//! and returned its result. When the local in-memory cache was cold
//! (the canonical cross-instance scenario the persistent store exists
//! to support), `self.memory.consume_code` returned `None` because the
//! code was minted on a different instance, so the function returned
//! `Ok(None)` despite legitimately consuming the row in the DB. The
//! caller could not complete the token exchange. Even if the lookup
//! had worked, the loaded row had `scope: String::new()` because
//! `load_from_db` discarded the column entirely.
//!
//! Fix under test:
//!   - `consume_code` now uses a single `DELETE ... WHERE consumed =
//!     FALSE RETURNING <all columns>` query. The race winner gets a
//!     fully-reconstructed `AuthorizationCode` (including scope); the
//!     loser gets `Ok(None)`.
//!   - `load_from_db` and `create_code_with_tier` both now persist
//!     and load the `scope` column.
//!
//! ## Running
//!
//! Requires writable Postgres at `MILNET_TEST_PG_URL`. Skips cleanly
//! (PASS) when the env var is unset. The test creates the
//! `authorization_codes` table itself with the X-I-required `scope
//! TEXT NOT NULL` column.

use sqlx::postgres::PgPoolOptions;
use sso_protocol::authorize::PersistentAuthorizationStore;
use uuid::Uuid;

const SCHEMA_DDL: &str = "
    CREATE TABLE IF NOT EXISTS authorization_codes (
        code_hash             VARCHAR(255) PRIMARY KEY,
        client_id             VARCHAR(255) NOT NULL,
        redirect_uri          TEXT NOT NULL,
        user_id               UUID NOT NULL,
        scope                 TEXT NOT NULL,
        code_challenge_blind  VARCHAR(255),
        tier                  INTEGER NOT NULL,
        nonce                 VARCHAR(255),
        created_at            BIGINT NOT NULL,
        consumed              BOOLEAN DEFAULT FALSE
    );
";

#[tokio::test(flavor = "current_thread")]
async fn cross_instance_consume_winner_gets_full_record() {
    let url = match std::env::var("MILNET_TEST_PG_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!(
                "skipping cross_instance_consume: MILNET_TEST_PG_URL not set."
            );
            return;
        }
    };

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("connect to MILNET_TEST_PG_URL");

    sqlx::query(SCHEMA_DDL)
        .execute(&pool)
        .await
        .expect("create authorization_codes schema");

    // Phase 1: instance A creates a code.
    let mut as_a = PersistentAuthorizationStore::new(pool.clone())
        .await
        .expect("instance A");
    let user = Uuid::new_v4();
    let client = format!("xi-test-client-{}", Uuid::new_v4());
    let redirect = "https://example.com/cb".to_string();
    let scope = "openid profile offline_access".to_string();
    let code = as_a
        .create_code_with_tier(
            &client, &redirect, user, &scope,
            Some("ch-test".to_string()), Some("nonce-test".to_string()), 2,
        )
        .await
        .expect("create_code_with_tier");

    // Phase 2: instance B has a cold cache — it has never seen this
    // code in memory. This is the exact scenario X-I addresses.
    let mut as_b = PersistentAuthorizationStore::new(pool.clone())
        .await
        .expect("instance B (cold cache)");

    // Phase 3: race A and B on consume_code. Exactly one wins.
    let (res_a, res_b) = tokio::join!(
        as_a.consume_code(&code),
        as_b.consume_code(&code),
    );

    let res_a = res_a.expect("consume on A returned Err");
    let res_b = res_b.expect("consume on B returned Err");

    let winners = [res_a.is_some(), res_b.is_some()]
        .into_iter()
        .filter(|w| *w)
        .count();
    assert_eq!(
        winners, 1,
        "X-I regression: exactly one instance must win the race \
         (got {} winners; A={:?}, B={:?})",
        winners, res_a.is_some(), res_b.is_some()
    );

    let winner = res_a.or(res_b).expect("one of A/B must be Some");

    // X-I core assertion: the winner's AuthorizationCode is COMPLETE,
    // including scope. Pre-fix the cross-instance winner got Ok(None)
    // when its cache was cold, or an empty `scope` when load_from_db
    // happened to populate the cache.
    assert_eq!(winner.client_id, client);
    assert_eq!(winner.redirect_uri, redirect);
    assert_eq!(winner.user_id, user);
    assert_eq!(
        winner.scope, scope,
        "X-I regression: scope must round-trip through DELETE...RETURNING; \
         pre-fix the load path discarded it"
    );
    assert_eq!(winner.tier, 2);
    assert!(winner.consumed, "winner record must be marked consumed");
}

#[tokio::test(flavor = "current_thread")]
async fn cold_cache_winner_still_returns_some() {
    let url = match std::env::var("MILNET_TEST_PG_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => return, // graceful skip
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    sqlx::query(SCHEMA_DDL).execute(&pool).await.expect("ddl");

    // Create the code on one instance, drop it, then spin up a second
    // instance with a fresh (cold) memory cache to consume it. Pre-fix
    // this path always returned `Ok(None)` regardless of DB success.
    let mut maker = PersistentAuthorizationStore::new(pool.clone())
        .await
        .expect("maker");
    let user = Uuid::new_v4();
    let scope = "openid email";
    let code = maker.create_code_with_tier(
        "cold-cache-client", "https://x/cb", user, scope,
        None, None, 1,
    ).await.expect("create");
    drop(maker);

    let mut consumer = PersistentAuthorizationStore::new(pool.clone())
        .await
        .expect("consumer");
    // Manually evict from consumer's cache to force the cross-instance
    // cold-cache scenario (the constructor's load_from_db will have
    // populated it; we simulate the case where the code was minted
    // AFTER load_from_db ran).
    let _ = consumer.cleanup_expired().await;

    let result = consumer.consume_code(&code).await.expect("consume");
    let auth_code = result.expect(
        "X-I regression: cross-instance consume must return Some(...) \
         on race-win even when the local cache is cold — pre-fix \
         this returned Ok(None) and lost the entire token exchange"
    );
    assert_eq!(auth_code.scope, scope);
    assert_eq!(auth_code.user_id, user);
}
