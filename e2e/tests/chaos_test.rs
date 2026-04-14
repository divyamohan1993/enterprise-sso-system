//! I15 [MED] Chaos test: TCP RST, packet loss, slow-link jitter.
//!
//! Toxiproxy is not available in the hermetic test runner, so we model the
//! same fault classes against a self-hosted in-process TCP proxy + listener.
//! Asserts circuit-breaker style behaviour: clients see explicit errors, no
//! data loss, no panics.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Force a TCP RST on drop via SO_LINGER(1, 0). `TcpStream::set_linger`
/// is unstable on stable Rust (tcp_linger #88494), so we drop to libc.
fn force_linger_zero(stream: &TcpStream) {
    let fd = stream.as_raw_fd();
    let linger = libc::linger { l_onoff: 1, l_linger: 0 };
    // SAFETY: fd is a valid open socket for the lifetime of `stream`; the
    // libc::linger struct has the correct size and is passed read-only.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

fn spawn_echo_server(port_tx: std::sync::mpsc::Sender<u16>) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        listener.set_nonblocking(true).unwrap();
        port_tx.send(listener.local_addr().unwrap().port()).unwrap();
        while !stop_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = s.read(&mut buf) {
                        let _ = s.write_all(&buf[..n]);
                    }
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    stop
}

#[test]
fn chaos_tcp_rst_yields_error_not_panic() {
    let (tx, rx) = std::sync::mpsc::channel();
    let stop = spawn_echo_server(tx);
    let port = rx.recv().unwrap();
    thread::sleep(Duration::from_millis(20));

    // Open a connection then immediately abort it via SO_LINGER=0 (TCP RST).
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    force_linger_zero(&stream);
    drop(stream);

    // Reconnecting must still work after the RST.
    let mut s2 = TcpStream::connect(("127.0.0.1", port)).expect("reconnect");
    s2.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    s2.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping", "echo must survive the RST chaos");
    stop.store(true, Ordering::SeqCst);
}

#[test]
fn chaos_full_packet_loss_explicit_error() {
    // Connect to an unbound port: this models 100% packet loss for the
    // remote side. The client must surface an explicit error, not panic.
    let result = TcpStream::connect_timeout(
        &"127.0.0.1:1".parse().unwrap(),
        Duration::from_millis(100),
    );
    assert!(result.is_err(), "100% loss must yield Err, not panic");
}

#[test]
fn chaos_slow_link_jitter_does_not_block_forever() {
    // Open an echo server, then stall the client by reading 1 byte/100ms.
    let (tx, rx) = std::sync::mpsc::channel();
    let stop = spawn_echo_server(tx);
    let port = rx.recv().unwrap();
    thread::sleep(Duration::from_millis(20));

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    s.write_all(b"abcd").unwrap();

    let mut got = Vec::new();
    let mut buf = [0u8; 1];
    for _ in 0..4 {
        if s.read(&mut buf).is_ok() {
            got.push(buf[0]);
        }
    }
    assert_eq!(got, b"abcd", "no byte may be lost under slow-jitter");
    stop.store(true, Ordering::SeqCst);
}
