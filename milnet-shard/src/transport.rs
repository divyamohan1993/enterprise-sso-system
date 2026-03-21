//! Async TCP transport for SHARD messages with length-prefixed framing.
//!
//! Provides [`ShardTransport`] for sending/receiving authenticated SHARD
//! messages over TCP, and [`ShardListener`] for accepting inbound connections.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

use milnet_common::error::MilnetError;
use milnet_common::types::ModuleId;

use crate::protocol::ShardProtocol;

/// Maximum SHARD frame payload size (16 MiB). Prevents allocation bombs.
const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// A TCP transport that sends and receives SHARD-authenticated messages
/// using 4-byte big-endian length-prefixed framing.
pub struct ShardTransport {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    /// The underlying SHARD protocol instance (public for advanced use cases
    /// such as offline verification of captured frames).
    pub protocol: ShardProtocol,
}

impl ShardTransport {
    /// Wrap an already-connected TCP stream with a [`ShardProtocol`] instance.
    pub fn new(stream: TcpStream, protocol: ShardProtocol) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader,
            writer,
            protocol,
        }
    }

    /// Create an authenticated SHARD message from `payload`, frame it with a
    /// 4-byte big-endian length prefix, and write it to the TCP stream.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MilnetError> {
        let msg = self.protocol.create_message(payload)?;
        let len = msg.len() as u32;
        self.writer
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| MilnetError::Shard(format!("write length: {e}")))?;
        self.writer
            .write_all(&msg)
            .await
            .map_err(|e| MilnetError::Shard(format!("write payload: {e}")))?;
        self.writer
            .flush()
            .await
            .map_err(|e| MilnetError::Shard(format!("flush: {e}")))?;
        Ok(())
    }

    /// Read a length-prefixed frame from the TCP stream, verify the SHARD
    /// authentication, and return `(sender_module, payload)`.
    pub async fn recv(&mut self) -> Result<(ModuleId, Vec<u8>), MilnetError> {
        let mut len_buf = [0u8; 4];
        self.reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| MilnetError::Shard(format!("read length: {e}")))?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_LEN {
            return Err(MilnetError::Shard(format!(
                "frame too large: {len} bytes (max {MAX_FRAME_LEN})"
            )));
        }
        let mut buf = vec![0u8; len as usize];
        self.reader
            .read_exact(&mut buf)
            .await
            .map_err(|e| MilnetError::Shard(format!("read payload: {e}")))?;
        self.protocol.verify_message(&buf)
    }

    /// Read raw framed bytes from the TCP stream without verification.
    /// Useful for testing replay scenarios.
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, MilnetError> {
        let mut len_buf = [0u8; 4];
        self.reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| MilnetError::Shard(format!("read length: {e}")))?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_LEN {
            return Err(MilnetError::Shard(format!(
                "frame too large: {len} bytes (max {MAX_FRAME_LEN})"
            )));
        }
        let mut buf = vec![0u8; len as usize];
        self.reader
            .read_exact(&mut buf)
            .await
            .map_err(|e| MilnetError::Shard(format!("read payload: {e}")))?;
        Ok(buf)
    }

    /// Write raw pre-framed bytes to the TCP stream (length prefix + payload).
    /// Useful for testing replay scenarios.
    pub async fn send_raw(&mut self, raw: &[u8]) -> Result<(), MilnetError> {
        let len = raw.len() as u32;
        self.writer
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| MilnetError::Shard(format!("write length: {e}")))?;
        self.writer
            .write_all(raw)
            .await
            .map_err(|e| MilnetError::Shard(format!("write payload: {e}")))?;
        self.writer
            .flush()
            .await
            .map_err(|e| MilnetError::Shard(format!("flush: {e}")))?;
        Ok(())
    }
}

/// Accepts incoming TCP connections and wraps them in [`ShardTransport`].
pub struct ShardListener {
    listener: TcpListener,
    module_id: ModuleId,
    hmac_key: [u8; 64],
}

impl ShardListener {
    /// Bind to the given address and prepare to accept SHARD connections.
    pub async fn bind(
        addr: &str,
        module_id: ModuleId,
        hmac_key: [u8; 64],
    ) -> Result<Self, MilnetError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| MilnetError::Shard(format!("bind {addr}: {e}")))?;
        Ok(Self {
            listener,
            module_id,
            hmac_key,
        })
    }

    /// Return the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, MilnetError> {
        self.listener
            .local_addr()
            .map_err(|e| MilnetError::Shard(format!("local_addr: {e}")))
    }

    /// Accept a single inbound connection and return a [`ShardTransport`].
    pub async fn accept(&self) -> Result<ShardTransport, MilnetError> {
        let (stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| MilnetError::Shard(format!("accept: {e}")))?;
        let protocol = ShardProtocol::new(self.module_id, self.hmac_key);
        Ok(ShardTransport::new(stream, protocol))
    }
}

/// Connect to a remote SHARD peer and return a [`ShardTransport`].
pub async fn connect(
    addr: &str,
    module_id: ModuleId,
    hmac_key: [u8; 64],
) -> Result<ShardTransport, MilnetError> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| MilnetError::Shard(format!("connect {addr}: {e}")))?;
    let protocol = ShardProtocol::new(module_id, hmac_key);
    Ok(ShardTransport::new(stream, protocol))
}
