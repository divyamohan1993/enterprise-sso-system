//! Integration tests for the Bastion Gateway.

use milnet_gateway::puzzle::{
    generate_challenge, solve_challenge, verify_solution, PuzzleChallenge, PuzzleSolution,
};
use milnet_gateway::server::GatewayServer;
use milnet_gateway::wire::{AuthRequest, AuthResponse};

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
    // With difficulty=4, a solution of all 0xFF bytes is overwhelmingly
    // unlikely to have 4 leading zero bits.
    assert!(
        !verify_solution(&challenge, &bad_solution),
        "random solution should fail verification"
    );
}

#[test]
fn puzzle_expired_rejected() {
    // Create a challenge with an old timestamp (20 seconds ago).
    let mut challenge = generate_challenge(4);
    challenge.timestamp -= 20; // 20 seconds in the past, well past 10s TTL

    let solution = solve_challenge(&challenge);
    assert!(
        !verify_solution(&challenge, &solution),
        "expired challenge must be rejected"
    );
}

// ── Gateway integration test ────────────────────────────────────────────

/// Helper: send a length-prefixed postcard frame.
async fn send_frame<T: serde::Serialize>(stream: &mut TcpStream, value: &T) {
    let payload = postcard::to_allocvec(value).unwrap();
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
}

/// Helper: receive a length-prefixed postcard frame.
async fn recv_frame<T: serde::de::DeserializeOwned>(stream: &mut TcpStream) -> T {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf);
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.unwrap();
    postcard::from_bytes(&buf).unwrap()
}

#[tokio::test]
async fn gateway_accepts_solved_puzzle() {
    // Start gateway on an ephemeral port
    let server = GatewayServer::bind("127.0.0.1:0", 4).await.unwrap();
    let addr = server.local_addr().unwrap();

    // Run accept_one in background
    let server_handle = tokio::spawn(async move {
        server.accept_one().await.unwrap();
    });

    // Connect as client
    let mut stream = TcpStream::connect(addr).await.unwrap();

    // 1. Receive puzzle challenge
    let challenge: PuzzleChallenge = recv_frame(&mut stream).await;
    assert_eq!(challenge.difficulty, 4);

    // 2. Solve and send solution
    let solution_bytes = solve_challenge(&challenge);
    let solution = PuzzleSolution {
        nonce: challenge.nonce,
        solution: solution_bytes,
    };
    send_frame(&mut stream, &solution).await;

    // 3. Send auth request
    let auth_req = AuthRequest {
        username: "testuser".into(),
        password: vec![0xBB; 32],
    };
    send_frame(&mut stream, &auth_req).await;

    // 4. Receive auth response
    let resp: AuthResponse = recv_frame(&mut stream).await;
    assert!(resp.success, "auth should succeed");
    assert!(resp.token.is_some(), "should receive a token");
    assert!(resp.error.is_none(), "should have no error");

    server_handle.await.unwrap();
}
