//! PostgreSQL persistence layer for the SSO system.
//! Uses sqlx with async PostgreSQL driver.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Initialize the PostgreSQL connection pool
pub async fn init_database(database_url: &str) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    // Run migrations
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            opaque_registration BYTEA,
            tier INTEGER NOT NULL DEFAULT 2,
            created_at BIGINT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true
        )
    "#).execute(&pool).await.expect("Failed to create users table");

    // Migration: add tier column to existing users tables that lack it
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS tier INTEGER NOT NULL DEFAULT 2")
        .execute(&pool)
        .await;

    // Migration: add duress_pin_hash column for duress PIN system
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS duress_pin_hash BYTEA")
        .execute(&pool)
        .await;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS devices (
            id UUID PRIMARY KEY,
            tier INTEGER NOT NULL,
            attestation_hash BYTEA,
            enrolled_by UUID,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create devices table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS portals (
            id UUID PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            callback_url TEXT NOT NULL,
            client_id VARCHAR(255) UNIQUE,
            client_secret VARCHAR(255),
            required_tier INTEGER NOT NULL DEFAULT 2,
            required_scope INTEGER NOT NULL DEFAULT 0,
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create portals table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS audit_log (
            id UUID PRIMARY KEY,
            event_type VARCHAR(100) NOT NULL,
            user_ids TEXT,
            timestamp BIGINT NOT NULL,
            prev_hash BYTEA,
            signature BYTEA,
            data TEXT
        )
    "#).execute(&pool).await.expect("Failed to create audit_log table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS sessions (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL,
            ratchet_epoch BIGINT NOT NULL DEFAULT 0,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true
        )
    "#).execute(&pool).await.expect("Failed to create sessions table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS oauth_codes (
            code VARCHAR(255) PRIMARY KEY,
            client_id VARCHAR(255) NOT NULL,
            user_id UUID NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            code_challenge TEXT,
            nonce TEXT,
            expires_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create oauth_codes table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS server_config (
            key VARCHAR(255) PRIMARY KEY,
            value BYTEA NOT NULL,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create server_config table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS fido_credentials (
            credential_id BYTEA PRIMARY KEY,
            user_id UUID NOT NULL,
            public_key BYTEA NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            authenticator_type VARCHAR(50) NOT NULL,
            created_at BIGINT NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create fido_credentials table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS key_material (
            key_name VARCHAR(255) PRIMARY KEY,
            key_bytes BYTEA NOT NULL,
            created_at BIGINT NOT NULL,
            rotated_at BIGINT
        )
    "#).execute(&pool).await.expect("Failed to create key_material table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS shard_sequences (
            module_pair VARCHAR(100) PRIMARY KEY,
            sequence BIGINT NOT NULL DEFAULT 0
        )
    "#).execute(&pool).await.expect("Failed to create shard_sequences table");

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS witness_checkpoints (
            sequence BIGINT PRIMARY KEY,
            audit_root BYTEA NOT NULL,
            kt_root BYTEA NOT NULL,
            timestamp BIGINT NOT NULL,
            signature BYTEA NOT NULL
        )
    "#).execute(&pool).await.expect("Failed to create witness_checkpoints table");

    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires running PostgreSQL — set DATABASE_URL"]
    async fn test_db_init_creates_tables() {
        let url = std::env::var("DATABASE_URL").unwrap();
        let pool = init_database(&url).await;
        // Verify tables exist by querying the information_schema
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('users', 'devices', 'portals', 'audit_log', 'sessions', 'oauth_codes', 'fido_credentials')"
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, 7);
    }

    #[tokio::test]
    #[ignore = "requires running PostgreSQL — set DATABASE_URL"]
    async fn test_db_insert_and_query_user() {
        let url = std::env::var("DATABASE_URL").unwrap();
        let pool = init_database(&url).await;
        let user_id = uuid::Uuid::new_v4();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query("INSERT INTO users (id, username, opaque_registration, created_at) VALUES ($1, $2, $3, $4)")
            .bind(user_id)
            .bind("alice")
            .bind(&[0u8; 32] as &[u8])
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();

        let row: (uuid::Uuid, String) = sqlx::query_as(
            "SELECT id, username FROM users WHERE username = $1"
        )
        .bind("alice")
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(row.0, user_id);
        assert_eq!(row.1, "alice");

        // Clean up
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
