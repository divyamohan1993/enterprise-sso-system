//! SQLite persistence layer for the SSO system.
//! Uses rusqlite with bundled SQLite for zero-dependency deployment.

use rusqlite::{Connection, params};

pub fn init_database(path: &str) -> Connection {
    let conn = Connection::open(path).expect("Failed to open database");
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            opaque_registration BLOB,
            created_at INTEGER NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            tier INTEGER NOT NULL,
            attestation_hash BLOB,
            enrolled_by TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS portals (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            callback_url TEXT NOT NULL,
            client_id TEXT UNIQUE,
            client_secret TEXT,
            required_tier INTEGER NOT NULL DEFAULT 2,
            required_scope INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            user_ids TEXT,
            timestamp INTEGER NOT NULL,
            prev_hash BLOB,
            signature BLOB,
            data TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            ratchet_epoch INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS oauth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            code_challenge TEXT,
            nonce TEXT,
            expires_at INTEGER NOT NULL
        );
    ").expect("Failed to initialize database schema");

    conn
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    #[test]
    fn test_db_init_creates_tables() {
        let conn = init_database(":memory:");
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(tables.contains(&"users".to_string()));
        assert!(tables.contains(&"devices".to_string()));
        assert!(tables.contains(&"portals".to_string()));
        assert!(tables.contains(&"audit_log".to_string()));
        assert!(tables.contains(&"sessions".to_string()));
        assert!(tables.contains(&"oauth_codes".to_string()));
    }

    #[test]
    fn test_db_insert_and_query_user() {
        let conn = init_database(":memory:");
        let user_id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "INSERT INTO users (id, username, opaque_registration, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![user_id, "alice", &[0u8; 32] as &[u8], now],
        )
        .unwrap();

        let (found_id, found_name): (String, String) = conn
            .query_row(
                "SELECT id, username FROM users WHERE username = ?1",
                params!["alice"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(found_id, user_id);
        assert_eq!(found_name, "alice");
    }

    #[test]
    fn test_db_survives_reconnect() {
        let dir = std::env::temp_dir().join(format!("sso_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");
        let db_path_str = db_path.to_str().unwrap();

        let user_id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Open, insert, close
        {
            let conn = init_database(db_path_str);
            conn.execute(
                "INSERT INTO users (id, username, created_at) VALUES (?1, ?2, ?3)",
                params![user_id, "bob", now],
            )
            .unwrap();
            // conn dropped here
        }

        // Reopen and verify data persists
        {
            let conn = init_database(db_path_str);
            let found: String = conn
                .query_row(
                    "SELECT username FROM users WHERE id = ?1",
                    params![user_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(found, "bob");
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
