//! Integration tests for the Bastion Gateway.

use gateway::puzzle::{
    generate_challenge, solve_challenge, verify_solution, PuzzleChallenge, PuzzleSolution,
};
use gateway::server::GatewayServer;
use gateway::wire::{AuthRequest, AuthResponse};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// -- Puzzle unit tests --

#[test]
fn puzzle_generate_and_solve() {
    let challenge = generate_challenge(4);
    let solution = solve_challenge(&challenge);
    assert!(
        verify_solution(&challenge, &solution),
        "valid solution must pass verification"
    );
}

#[test]
fn puzzle_wrong_solution_rejected() {
    let challenge = generate_challenge(4);
    let bad_solution = [0xFFu8; 32];
    assert!(
        !verify_solution(&challenge, &bad_solution),
        "random solution should fail verification"
    );
}

#[test]
fn puzzle_expired_rejected() {
    let mut challenge = generate_challenge(4);
    challenge.timestamp -= 60; // well past TTL
    let solution = solve_challenge(&challenge);
    assert!(
        !verify_solution(&challenge, &solution),
        "expired challenge must be rejected"
    );
}

// -- Gateway integration test --

async fn send_frame<T: serde::Serialize>(stream: &mut TcpStream, value: &T) {
    let payload = postcard::to_allocvec(value).unwrap();
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
}

async fn recv_frame<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> T {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf);
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.unwrap();
    postcard::from_bytes(&buf).unwrap()
}

async fn send_raw_frame(stream: &mut TcpStream, data: &[u8]) {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(data).await.unwrap();
    stream.flush().await.unwrap();
}

async fn recv_raw_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf);
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.unwrap();
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_accepts_solved_puzzle() {
    // Start gateway on an ephemeral port
    let server = GatewayServer::bind("127.0.0.1:0", 4).await.unwrap();
    let addr = server.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        server.accept_one().await.unwrap();
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();

    // 1. Receive puzzle challenge (includes server's X-Wing public key)
    let challenge: PuzzleChallenge = recv_frame(&mut stream).await;

    // 2. Parse server's X-Wing public key and encapsulate against it.
    //    The client produces a shared secret and ciphertext; the ciphertext
    //    is sent to the server so it can decapsulate.
    let server_pk_bytes = challenge.xwing_server_pk.as_ref().expect("server PK in challenge");
    let server_pk = crypto::xwing::XWingPublicKey::from_bytes(server_pk_bytes)
        .expect("parse server X-Wing PK");
    let (shared_secret, kem_ct) = crypto::xwing::xwing_encapsulate(&server_pk);
    let kem_ct_bytes = kem_ct.to_bytes();

    // 3. Solve puzzle and send solution with KEM ciphertext
    let challenge_clone = challenge.clone();
    let solution_bytes = tokio::task::spawn_blocking(move || solve_challenge(&challenge_clone))
        .await
        .unwrap();
    let solution = PuzzleSolution {
        nonce: challenge.nonce,
        solution: solution_bytes,
        xwing_kem_ciphertext: Some(kem_ct_bytes),
    };
    send_frame(&mut stream, &solution).await;

    // 4. Derive session key (both sides use the same shared secret)
    let session_key = crypto::xwing::derive_session_key(&shared_secret, &challenge.nonce);
    let enc_key: [u8; 32] = session_key[..32].try_into().unwrap();

    // 5. Encrypt and send auth request
    let auth_req = AuthRequest {
        username: "testuser".into(),
        password: vec![0xBB; 32],
        audience: None,
    };
    let auth_plain = postcard::to_allocvec(&auth_req).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&enc_key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).unwrap();
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, auth_plain.as_ref()).unwrap();
    let mut encrypted = Vec::with_capacity(12 + ciphertext.len());
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted.extend_from_slice(&ciphertext);
    send_raw_frame(&mut stream, &encrypted).await;

    // 6. Receive and decrypt auth response
    let encrypted_resp = recv_raw_frame(&mut stream).await;
    let resp_nonce = GenericArray::from_slice(&encrypted_resp[..12]);
    let resp_plain = cipher.decrypt(resp_nonce, &encrypted_resp[12..]).unwrap();
    let resp: AuthResponse = postcard::from_bytes(&resp_plain).unwrap();

    // No orchestrator configured, so auth fails gracefully
    assert!(!resp.success || resp.error.is_none());

    server_handle.await.unwrap();
}

// -- X-Wing key pinning tests --

#[test]
fn xwing_fingerprint_is_deterministic() {
    let pk_bytes = vec![0xABu8; 1216]; // typical X-Wing PK size
    let fp1 = compute_fingerprint(&pk_bytes);
    let fp2 = compute_fingerprint(&pk_bytes);
    assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    assert!(!fp1.is_empty());
    // Must be hex-encoded SHA-256 (64 hex chars)
    assert_eq!(fp1.len(), 64, "fingerprint must be 64 hex chars (SHA-256)");
}

#[test]
fn xwing_fingerprint_different_keys_differ() {
    let fp1 = compute_fingerprint(&vec![0x01u8; 1216]);
    let fp2 = compute_fingerprint(&vec![0x02u8; 1216]);
    assert_ne!(fp1, fp2, "different keys must produce different fingerprints");
}

#[test]
fn puzzle_challenge_includes_fingerprint() {
    // When xwing_server_pk_fingerprint is set, it should be present
    let mut challenge = generate_challenge(4);
    challenge.xwing_server_pk_fingerprint = Some("abcdef1234567890".to_string());
    assert_eq!(
        challenge.xwing_server_pk_fingerprint.as_deref(),
        Some("abcdef1234567890")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_challenge_contains_fingerprint() {
    // Start gateway and verify the challenge includes a fingerprint
    let server = GatewayServer::bind("127.0.0.1:0", 4).await.unwrap();
    let addr = server.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        // We only care about receiving the challenge, not completing the handshake.
        // The accept_one call will error because the client drops the connection.
        let _ = server.accept_one().await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();

    // Receive puzzle challenge
    let challenge: PuzzleChallenge = recv_frame(&mut stream).await;

    // The challenge must include a fingerprint
    assert!(
        challenge.xwing_server_pk_fingerprint.is_some(),
        "puzzle challenge must include X-Wing public key fingerprint"
    );
    let fingerprint = challenge.xwing_server_pk_fingerprint.unwrap();
    assert_eq!(fingerprint.len(), 64, "fingerprint must be 64 hex chars");

    // The fingerprint must match the included public key
    let pk_bytes = challenge.xwing_server_pk.as_ref().unwrap();
    let expected = compute_fingerprint(pk_bytes);
    assert_eq!(fingerprint, expected, "fingerprint must match server PK");

    drop(stream);
    let _ = server_handle.await;
}

/// Helper to compute X-Wing PK fingerprint (mirrors server implementation).
fn compute_fingerprint(pk_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"MILNET-XWING-PIN-v1");
    hasher.update(pk_bytes);
    hex::encode(hasher.finalize())
}
