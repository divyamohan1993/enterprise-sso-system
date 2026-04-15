//! Length-prefixed I/O helpers with mandatory size clamps.
//!
//! All untrusted length-prefixed reads MUST go through these helpers to prevent
//! unbounded allocation / OOM from a malicious or corrupted source.

use std::io::Read;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    Big,
    Little,
}

#[derive(Debug)]
pub enum IoError {
    TooLarge { got: usize, max: usize },
    Truncated,
    Io(std::io::Error),
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoError::TooLarge { got, max } => {
                write!(f, "length-prefixed payload {got} exceeds max {max}")
            }
            IoError::Truncated => write!(f, "length-prefixed payload truncated"),
            IoError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for IoError {}

impl From<std::io::Error> for IoError {
    fn from(e: std::io::Error) -> Self {
        IoError::Io(e)
    }
}

fn decode_u32(bytes: [u8; 4], endian: Endian) -> u32 {
    match endian {
        Endian::Big => u32::from_be_bytes(bytes),
        Endian::Little => u32::from_le_bytes(bytes),
    }
}

/// Read a 4-byte length prefix followed by `len` bytes from a stream.
///
/// Rejects payloads larger than `max` BEFORE allocating, preventing OOM.
pub fn read_length_prefixed<R: Read>(
    reader: &mut R,
    max: usize,
    endian: Endian,
) -> Result<Vec<u8>, IoError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = decode_u32(len_buf, endian) as usize;
    if len > max {
        return Err(IoError::TooLarge { got: len, max });
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    Ok(body)
}

/// Parse a 4-byte length prefix + body out of a pre-loaded buffer.
///
/// Returns `(body, rest)` where `body` is the `len` bytes following the prefix
/// and `rest` is everything after `body`. Rejects `len > max` before slicing.
pub fn parse_length_prefixed(
    buf: &[u8],
    max: usize,
    endian: Endian,
) -> Result<(&[u8], &[u8]), IoError> {
    if buf.len() < 4 {
        return Err(IoError::Truncated);
    }
    let len_bytes: [u8; 4] = buf[..4].try_into().map_err(|_| IoError::Truncated)?;
    let len = decode_u32(len_bytes, endian) as usize;
    if len > max {
        return Err(IoError::TooLarge { got: len, max });
    }
    let end = 4usize.checked_add(len).ok_or(IoError::Truncated)?;
    if end > buf.len() {
        return Err(IoError::Truncated);
    }
    Ok((&buf[4..end], &buf[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_le_ok() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3]);
        buf.extend_from_slice(&[9, 9]);
        let (body, rest) = parse_length_prefixed(&buf, 1024, Endian::Little).unwrap();
        assert_eq!(body, &[1, 2, 3]);
        assert_eq!(rest, &[9, 9]);
    }

    #[test]
    fn parse_too_large_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1_000_000u32.to_le_bytes());
        let err = parse_length_prefixed(&buf, 1024, Endian::Little).unwrap_err();
        assert!(matches!(err, IoError::TooLarge { got: 1_000_000, max: 1024 }));
    }

    #[test]
    fn parse_truncated_body() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&[1, 2]);
        let err = parse_length_prefixed(&buf, 1024, Endian::Little).unwrap_err();
        assert!(matches!(err, IoError::Truncated));
    }

    #[test]
    fn read_be_ok() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(&[7, 8, 9]);
        let mut cursor = std::io::Cursor::new(buf);
        let body = read_length_prefixed(&mut cursor, 1024, Endian::Big).unwrap();
        assert_eq!(body, &[7, 8, 9]);
    }

    #[test]
    fn read_too_large_no_alloc() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(u32::MAX).to_be_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_length_prefixed(&mut cursor, 1024, Endian::Big).unwrap_err();
        assert!(matches!(err, IoError::TooLarge { .. }));
    }
}
