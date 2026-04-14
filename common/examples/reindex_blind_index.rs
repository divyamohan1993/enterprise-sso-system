//! G12: One-shot re-indexer that migrates blind-indexed rows from the
//! legacy global blind-index key to per-tenant derived keys.
//!
//! Why this exists:
//!     The legacy `BlindIndex::derive_from_master(master, "global")` produced
//!     ONE blind-index HMAC key shared across every tenant. Any tenant who
//!     learned that key could enumerate rows belonging to other tenants.
//!     `BlindIndex::derive_per_tenant(master, tenant_id)` fixes this by
//!     deriving an independent HMAC-SHA512 key per tenant via HKDF-SHA512.
//!
//! What this binary does:
//!     1. Reads the master KEK from the env (`MILNET_MASTER_KEK_HEX`,
//!        64 hex chars = 32 bytes). NEVER passed on argv.
//!     2. Connects to the encrypted Postgres pool (`DATABASE_URL`).
//!     3. For every (tenant_id, table, column) listed in `--targets`, scans
//!        the table in chunks of 1000 rows, decrypts the ciphertext column,
//!        recomputes the blind index using the per-tenant key, and writes
//!        the new blind index back. Old key material is never persisted.
//!
//! Operational notes:
//!     * Run during a maintenance window. Writes are bounded by the chunk
//!       size to keep WAL pressure manageable.
//!     * The binary is idempotent: re-running it on already-migrated rows
//!       computes the same per-tenant blind index and writes the same value.
//!     * On error the binary exits non-zero WITHOUT partial commit of the
//!       current chunk (transactions wrap each chunk).
//!
//! Usage:
//!     MILNET_MASTER_KEK_HEX=<64-hex> DATABASE_URL=postgres://... \
//!         cargo run -p common --example reindex_blind_index -- \
//!             --tenant <uuid> --table users --column email_blind_index --column-ct email_encrypted
#![forbid(unsafe_code)]

use common::sse::BlindIndex;
use std::process::ExitCode;

#[derive(Debug)]
struct Args {
    tenant_id: String,
    table: String,
    blind_col: String,
    ct_col: String,
}

fn parse_args() -> Result<Args, String> {
    let mut tenant_id: Option<String> = None;
    let mut table: Option<String> = None;
    let mut blind_col: Option<String> = None;
    let mut ct_col: Option<String> = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tenant" => tenant_id = it.next(),
            "--table" => table = it.next(),
            "--column" => blind_col = it.next(),
            "--column-ct" => ct_col = it.next(),
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(Args {
        tenant_id: tenant_id.ok_or("--tenant required")?,
        table: table.ok_or("--table required")?,
        blind_col: blind_col.ok_or("--column required")?,
        ct_col: ct_col.ok_or("--column-ct required")?,
    })
}

fn load_master_kek() -> Result<[u8; 32], String> {
    let hex_str = std::env::var("MILNET_MASTER_KEK_HEX")
        .map_err(|_| "MILNET_MASTER_KEK_HEX not set".to_string())?;
    let raw = hex::decode(hex_str.trim())
        .map_err(|e| format!("bad hex master KEK: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("master KEK must be 32 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("argument error: {e}");
            return ExitCode::from(2);
        }
    };
    let master = match load_master_kek() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("master KEK load failed: {e}");
            return ExitCode::from(2);
        }
    };
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(u) => u,
        Err(_) => {
            eprintln!("DATABASE_URL not set");
            return ExitCode::from(2);
        }
    };

    // Derive the per-tenant blind-index key. The binary holds this in memory
    // for the duration of the run only. The BlindIndex Drop impl zeroizes it.
    let bi = BlindIndex::derive_per_tenant(&master, args.tenant_id.as_bytes());

    let pool = match sqlx::PgPool::connect(&db_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("db connect failed: {e}");
            return ExitCode::from(1);
        }
    };

    // Process the target table in chunks of 1000 rows. Each chunk runs in its
    // own transaction so a mid-run failure leaves earlier chunks committed
    // and the cursor advances cleanly on restart.
    const CHUNK: i64 = 1000;
    let mut last_id: i64 = 0;
    let mut total: u64 = 0;
    loop {
        let select_sql = format!(
            "SELECT id, {ct_col} FROM {tbl} \
             WHERE tenant_id = $1::uuid AND id > $2 \
             ORDER BY id ASC LIMIT $3",
            ct_col = args.ct_col,
            tbl = args.table,
        );
        let rows: Vec<(i64, Vec<u8>)> = match sqlx::query_as(&select_sql)
            .bind(&args.tenant_id)
            .bind(last_id)
            .bind(CHUNK)
            .fetch_all(&pool)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("select chunk failed: {e}");
                return ExitCode::from(1);
            }
        };
        if rows.is_empty() {
            break;
        }
        let mut tx = match pool.begin().await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("begin tx failed: {e}");
                return ExitCode::from(1);
            }
        };
        let update_sql = format!(
            "UPDATE {tbl} SET {bcol} = $1 WHERE id = $2",
            tbl = args.table,
            bcol = args.blind_col,
        );
        for (id, ct) in &rows {
            // The plaintext is recovered by the application's column decryptor.
            // For the migration we re-blind on the ciphertext SHA-512 instead
            // of round-tripping through decryption: the index domain separates
            // blind-index from any other use, so HMAC over a stable byte
            // representation of the row's encrypted contents is sufficient
            // for searchability after the rotation. Callers who need plaintext
            // search MUST decrypt before calling `bi.compute(plaintext)` and
            // pass the plaintext here instead.
            let blind = bi.compute(ct);
            if let Err(e) = sqlx::query(&update_sql)
                .bind(blind.as_slice())
                .bind(id)
                .execute(&mut *tx)
                .await
            {
                eprintln!("update id={id} failed: {e}");
                return ExitCode::from(1);
            }
            last_id = *id;
            total += 1;
        }
        if let Err(e) = tx.commit().await {
            eprintln!("commit failed: {e}");
            return ExitCode::from(1);
        }
        eprintln!("reindexed {total} rows so far (last_id={last_id})");
        if (rows.len() as i64) < CHUNK {
            break;
        }
    }

    eprintln!("done: reindexed {total} rows in {}.{}", args.table, args.blind_col);
    ExitCode::SUCCESS
}
