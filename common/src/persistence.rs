use sqlx::PgPool;

fn generate_random_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("OS entropy source must be available");
    buf
}

fn generate_random_bytes_64() -> [u8; 64] {
    let mut buf = [0u8; 64];
    getrandom::getrandom(&mut buf).expect("OS entropy source must be available");
    buf
}

pub async fn store_key(pool: &PgPool, name: &str, key_bytes: &[u8]) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let _ = sqlx::query(
        "INSERT INTO key_material (key_name, key_bytes, created_at) VALUES ($1, $2, $3) ON CONFLICT (key_name) DO UPDATE SET key_bytes = $2, rotated_at = $3"
    )
    .bind(name)
    .bind(key_bytes)
    .bind(now)
    .execute(pool)
    .await;
}

pub async fn load_key(pool: &PgPool, name: &str) -> Option<Vec<u8>> {
    sqlx::query_scalar("SELECT key_bytes FROM key_material WHERE key_name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

pub async fn load_or_generate_key_64(pool: &PgPool, name: &str) -> [u8; 64] {
    if let Some(existing) = load_key(pool, name).await {
        if existing.len() == 64 {
            let mut key = [0u8; 64];
            key.copy_from_slice(&existing);
            return key;
        }
    }
    let key = generate_random_bytes_64();
    store_key(pool, name, &key).await;
    key
}

pub async fn load_or_generate_key_32(pool: &PgPool, name: &str) -> [u8; 32] {
    if let Some(existing) = load_key(pool, name).await {
        if existing.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&existing);
            return key;
        }
    }
    let key = generate_random_bytes_32();
    store_key(pool, name, &key).await;
    key
}
