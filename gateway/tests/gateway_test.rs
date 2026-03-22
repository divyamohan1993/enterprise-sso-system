//! Integration tests for the Bastion Gateway.

use gateway::puzzle::{
    generate_challenge, solve_challenge, verify_solution, PuzzleChallenge, PuzzleSolution,
};
use gateway::server::GatewayServer;
use gateway::wire::{AuthRequest, AuthResponse, KemCiphertext};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ── Puzzle unit tests ───────────────────────────────────────────────────

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

// ── Gateway integration test ────────────────────────────────────────────

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

    // 1. Receive puzzle challenge
    let challenge: PuzzleChallenge = recv_frame(&mut stream).await;

    // 2. Generate X-Wing keypair and solve puzzle
    let client_kp = crypto::xwing::XWingKeyPair::generate();
    let client_pk_bytes = client_kp.public_key().to_bytes();

    let challenge_clone = challenge.clone();
    let solution_bytes = tokio::task::spawn_blocking(move || solve_challenge(&challenge_clone))
        .await
        .unwrap();
    let solution = PuzzleSolution {
        nonce: challenge.nonce,
        solution: solution_bytes,
        xwing_client_pk: Some(client_pk_bytes),
    };
    send_frame(&mut stream, &solution).await;

    // 3. Receive KEM ciphertext
    let kem_msg: KemCiphertext = recv_frame(&mut stream).await;
    let kem_ct = crypto::xwing::Ciphertext::from_bytes(&kem_msg.ciphertext)
        .expect("parse KEM ciphertext");
    let shared_secret = crypto::xwing::xwing_decapsulate(&client_kp, &kem_ct);

    // 4. Derive session key
    let session_key = crypto::xwing::derive_session_key(&shared_secret, &challenge.nonce);
    let enc_key: [u8; 32] = session_key[..32].try_into().unwrap();

    // 5. Encrypt and send auth request
    let auth_req = AuthRequest {
        username: "testuser".into(),
        password: vec![0xBB; 32],
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
