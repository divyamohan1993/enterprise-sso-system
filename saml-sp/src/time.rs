//! Strict ISO 8601 / XSD `dateTime` parser for SAML timestamps.
//!
//! Accepts `YYYY-MM-DDTHH:MM:SS[.fff]Z` and `+HH:MM` / `-HH:MM` offsets only.
//! Rejects anything else with `SamlError::TimestampParse`. No `unwrap`, no
//! month/day overflow, no leap-second tolerance (SAML forbids it).

use crate::SamlError;

/// Returns POSIX seconds since 1970-01-01T00:00:00Z. Strict.
pub fn parse_iso8601(s: &str) -> Result<i64, SamlError> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return Err(SamlError::TimestampParse);
    }
    let year: i32 = parse_n(&b[0..4])?;
    if b[4] != b'-' {
        return Err(SamlError::TimestampParse);
    }
    let month: u32 = parse_n(&b[5..7])?;
    if b[7] != b'-' {
        return Err(SamlError::TimestampParse);
    }
    let day: u32 = parse_n(&b[8..10])?;
    if b[10] != b'T' {
        return Err(SamlError::TimestampParse);
    }
    let hour: u32 = parse_n(&b[11..13])?;
    if b[13] != b':' {
        return Err(SamlError::TimestampParse);
    }
    let min: u32 = parse_n(&b[14..16])?;
    if b[16] != b':' {
        return Err(SamlError::TimestampParse);
    }
    let sec: u32 = parse_n(&b[17..19])?;

    let mut i = 19usize;
    // Optional fractional seconds — ignored (we report whole seconds).
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err(SamlError::TimestampParse);
        }
    }

    let offset_secs: i64 = if i >= b.len() {
        return Err(SamlError::TimestampParse);
    } else if b[i] == b'Z' {
        if i + 1 != b.len() {
            return Err(SamlError::TimestampParse);
        }
        0
    } else if b[i] == b'+' || b[i] == b'-' {
        if i + 6 != b.len() || b[i + 3] != b':' {
            return Err(SamlError::TimestampParse);
        }
        let oh: i64 = parse_n::<i64>(&b[i + 1..i + 3])?;
        let om: i64 = parse_n::<i64>(&b[i + 4..i + 6])?;
        if oh > 14 || om > 59 {
            return Err(SamlError::TimestampParse);
        }
        let total = oh * 3600 + om * 60;
        if b[i] == b'-' {
            -total
        } else {
            total
        }
    } else {
        return Err(SamlError::TimestampParse);
    };

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)?
        || hour > 23
        || min > 59
        || sec > 59
    {
        return Err(SamlError::TimestampParse);
    }

    let days = days_from_civil(year, month as i32, day as i32);
    let secs = days * 86_400
        + (hour as i64) * 3600
        + (min as i64) * 60
        + (sec as i64);
    Ok(secs - offset_secs)
}

fn parse_n<T: std::str::FromStr>(b: &[u8]) -> Result<T, SamlError> {
    let s = std::str::from_utf8(b).map_err(|_| SamlError::TimestampParse)?;
    if !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(SamlError::TimestampParse);
    }
    s.parse::<T>().map_err(|_| SamlError::TimestampParse)
}

fn days_in_month(y: i32, m: u32) -> Result<u32, SamlError> {
    Ok(match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => return Err(SamlError::TimestampParse),
    })
}

/// Howard Hinnant's `days_from_civil` — exact, branch-free for the proleptic
/// Gregorian calendar. Returns days since 1970-01-01.
fn days_from_civil(y: i32, m: i32, d: i32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era as i64) * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zulu() {
        assert_eq!(parse_iso8601("2099-01-01T00:00:00Z").unwrap(), 4_070_908_800);
    }
    #[test]
    fn parses_offset() {
        assert_eq!(
            parse_iso8601("2024-01-01T05:30:00+05:30").unwrap(),
            parse_iso8601("2024-01-01T00:00:00Z").unwrap()
        );
    }
    #[test]
    fn parses_fractional() {
        assert!(parse_iso8601("2024-01-01T00:00:00.123Z").is_ok());
    }
    #[test]
    fn rejects_garbage() {
        assert!(parse_iso8601("not a date").is_err());
        assert!(parse_iso8601("2024-13-01T00:00:00Z").is_err());
        assert!(parse_iso8601("2024-02-30T00:00:00Z").is_err());
        assert!(parse_iso8601("2024-01-01T25:00:00Z").is_err());
        assert!(parse_iso8601("").is_err());
    }
}
