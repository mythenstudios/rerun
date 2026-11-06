//! Wire helpers for the durable JSON formats (journal records, ADR 0019; plans, ADR 0020).
//!
//! - [`hex32`] and [`hex128`]: `#[serde(with = …)]` modules for a SHA-256 and a 128-bit file
//!   ID as lower-case hex strings of exactly 64 and 32 digits (no JSON number above 2^53,
//!   ADR 0020). Parsing accepts exactly what is written.
//! - [`TmpName`] serialises as its name and parses back only through [`TmpName::parse`].

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::sys::fs::TmpName;

/// Exactly `n` lower-case hex digits.
fn parse_hex(s: &str, n: usize) -> Option<u128> {
    let hex = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
    (s.len() == n && s.chars().all(hex)).then(|| u128::from_str_radix(s, 16).ok())?
}

/// A SHA-256 as 64 lower-case hex digits.
pub(crate) mod hex32 {
    use serde::de::Error as _;

    use super::{Deserialize, Deserializer, Serializer};

    /// Serialises `v` as 64 lower-case hex digits.
    pub(crate) fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&to_string(v))
    }

    /// Parses exactly 64 lower-case hex digits.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        from_str(&s).ok_or_else(|| D::Error::custom("expected 64 lower-case hex digits"))
    }

    /// 64 lower-case hex digits.
    pub(crate) fn to_string(v: &[u8; 32]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parses exactly 64 lower-case hex digits.
    pub(crate) fn from_str(s: &str) -> Option<[u8; 32]> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            let pair = s.get(i * 2..i * 2 + 2)?;
            *b = u8::try_from(super::parse_hex(pair, 2)?).ok()?;
        }
        Some(out)
    }
}

/// A 128-bit file ID as 32 lower-case hex digits.
pub(crate) mod hex128 {
    use serde::de::Error as _;

    use super::{Deserialize, Deserializer, Serializer};

    /// Serialises `v` as 32 lower-case hex digits.
    pub(crate) fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{v:032x}"))
    }

    /// Parses exactly 32 lower-case hex digits.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        super::parse_hex(&s, 32)
            .ok_or_else(|| D::Error::custom("expected 32 lower-case hex digits"))
    }
}

impl Serialize for TmpName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TmpName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).ok_or_else(|| D::Error::custom("not a temp name of Rerun"))
    }
}

#[cfg(test)]
mod tests {
    use super::{hex32, parse_hex};

    #[test]
    fn hex_parses_exactly_what_is_written() {
        let v: [u8; 32] = std::array::from_fn(|i| u8::try_from(i * 7).unwrap());
        let s = hex32::to_string(&v);
        assert_eq!(s.len(), 64);
        assert_eq!(hex32::from_str(&s), Some(v));
        for bad in [
            s.to_uppercase(),
            s[1..].to_owned(),
            format!("{s}0"),
            format!("+{}", &s[1..]),
            format!("{}g", &s[..63]),
        ] {
            assert_eq!(hex32::from_str(&bad), None, "{bad}");
        }
        assert_eq!(parse_hex("00ff", 4), Some(0xff));
        for bad in ["0FF", "+ff", "-0f", " ff", "ff "] {
            assert_eq!(parse_hex(bad, bad.len()), None, "{bad}");
        }
        assert_eq!(parse_hex(&"f".repeat(32), 32), Some(u128::MAX));
    }
}
