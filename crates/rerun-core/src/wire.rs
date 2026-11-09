//! Wire helpers for the durable JSON formats (journal records, ADR 0019; plans, ADR 0020).
//!
//! - [`hex32`] and [`hex128_opt`]: `#[serde(with = …)]` modules for a SHA-256 and an optional
//!   128-bit file ID as lower-case hex strings of exactly 64 and 32 digits (or `null`; no JSON
//!   number above 2^53, ADR 0020); [`hex128`] the same for a file ID that is always there (a
//!   `Rebind`'s directory proofs, P2-14); [`hex_bytes`] a byte string as lower-case hex, two digits
//!   per byte. Parsing accepts exactly what is written.
//! - [`TmpName`] serialises as its name and parses back only through [`TmpName::parse`].
//! - [`RelPath`] and [`RootPath`] serialise as their backslash-separated string and parse back
//!   through [`RelPath::parse`] and [`RootPath::new`] (every lexical rule again); a plan's
//!   one-form check (re-encoding gives the same bytes) refuses a non-normalised spelling.
//! - [`RootId`] serialises as its `Display` form `<16 hex>-<32 hex>`, [`Attrs`] as
//!   `{"readonly":…,"hidden":…,"system":…}`.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::path::{RelPath, RootPath};
use crate::policy::root::RootId;
use crate::sys::fs::{Attrs, TmpName};

/// Exactly `n` lower-case hex digits.
pub(crate) fn parse_hex(s: &str, n: usize) -> Option<u128> {
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

/// An optional 128-bit file ID: `null` or exactly 32 lower-case hex digits.
pub(crate) mod hex128_opt {
    use serde::de::Error as _;

    use super::{Deserialize, Deserializer, Serializer};

    /// Serialises `None` as `null`, `Some(v)` as 32 lower-case hex digits.
    pub(crate) fn serialize<S: Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_str(&format!("{v:032x}")),
            None => s.serialize_none(),
        }
    }

    /// Parses `null` or exactly 32 lower-case hex digits.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u128>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| {
                super::parse_hex(&s, 32)
                    .ok_or_else(|| D::Error::custom("expected 32 lower-case hex digits"))
            })
            .transpose()
    }
}

/// A 128-bit file ID: exactly 32 lower-case hex digits.
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

/// A byte string as lower-case hex, two digits per byte (ADR 0020: no JSON arrays of numbers
/// for bytes). The caller bounds the input (a record is read with a limit).
pub(crate) mod hex_bytes {
    use serde::de::Error as _;

    use super::{Deserialize, Deserializer, Serializer};

    /// Serialises `v` as lower-case hex.
    pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }

    /// Parses an even number of lower-case hex digits.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        from_str(&s).ok_or_else(|| D::Error::custom("expected lower-case hex bytes"))
    }

    /// Parses an even number of lower-case hex digits.
    pub(crate) fn from_str(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len() / 2)
            .map(|i| {
                let pair = s.get(i * 2..i * 2 + 2)?;
                u8::try_from(super::parse_hex(pair, 2)?).ok()
            })
            .collect()
    }
}

/// An optional byte string: `null` or [`hex_bytes`].
pub(crate) mod hex_bytes_opt {
    use super::{Deserialize, Deserializer, Serializer};

    /// Serialises `None` as `null`, `Some(v)` as lower-case hex.
    pub(crate) fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => super::hex_bytes::serialize(v, s),
            None => s.serialize_none(),
        }
    }

    /// Parses `null` or an even number of lower-case hex digits.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        use serde::de::Error as _;
        Option::<String>::deserialize(d)?
            .map(|s| {
                super::hex_bytes::from_str(&s)
                    .ok_or_else(|| D::Error::custom("expected lower-case hex bytes"))
            })
            .transpose()
    }
}

/// A `u64` as a decimal string without sign or leading zero (`"0"` is zero): no JSON number
/// above 2^53 (ADR 0020).
pub(crate) mod dec_u64 {
    use serde::de::Error as _;

    use super::{Deserialize, Deserializer, Serializer};

    /// Serialises `v` as its decimal digits.
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "the signature serde's `with` expects"
    )]
    pub(crate) fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    /// Parses exactly what [`serialize`] writes.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        from_str(&s).ok_or_else(|| D::Error::custom("expected a decimal u64 without leading zero"))
    }

    /// Decimal digits, no sign, no leading zero, at most `u64::MAX`.
    pub(crate) fn from_str(s: &str) -> Option<u64> {
        let canonical = !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'));
        canonical.then(|| s.parse().ok())?
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

impl Serialize for RelPath {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RelPath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(D::Error::custom)
    }
}

impl Serialize for RootPath {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.path().to_str() {
            Some(p) => s.serialize_str(p),
            None => Err(serde::ser::Error::custom("a root path is valid Unicode")),
        }
    }
}

impl<'de> Deserialize<'de> for RootPath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::new(&s).map_err(D::Error::custom)
    }
}

impl Serialize for RootId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RootId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bad = || D::Error::custom("expected <16 hex digits>-<32 hex digits>");
        let (serial, id) = s.split_once('-').ok_or_else(bad)?;
        let volume_serial =
            u64::try_from(parse_hex(serial, 16).ok_or_else(bad)?).map_err(|_| bad())?;
        let file_id = parse_hex(id, 32).ok_or_else(bad)?;
        Ok(Self {
            volume_serial,
            file_id,
        })
    }
}

/// [`Attrs`] on the wire.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttrsWire {
    readonly: bool,
    hidden: bool,
    system: bool,
}

impl Serialize for Attrs {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        AttrsWire {
            readonly: self.readonly,
            hidden: self.hidden,
            system: self.system,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Attrs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = AttrsWire::deserialize(d)?;
        Ok(Self {
            readonly: w.readonly,
            hidden: w.hidden,
            system: w.system,
        })
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
        // Byte strings (P2-10a): even, lower-case, exactly.
        assert_eq!(super::hex_bytes::from_str(""), Some(Vec::new()));
        assert_eq!(
            super::hex_bytes::from_str("00ff10"),
            Some(vec![0, 0xff, 0x10])
        );
        for bad in ["0", "0F", "+f", " f", "0g", "fff"] {
            assert_eq!(super::hex_bytes::from_str(bad), None, "{bad}");
        }
        // Decimal u64 (P2-10b, `qword`): canonical digits only.
        assert_eq!(super::dec_u64::from_str("0"), Some(0));
        assert_eq!(
            super::dec_u64::from_str("18446744073709551615"),
            Some(u64::MAX)
        );
        for bad in [
            "",
            "00",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1e3",
            "0x1",
            "18446744073709551616",
        ] {
            assert_eq!(super::dec_u64::from_str(bad), None, "{bad}");
        }
    }

    #[test]
    fn root_ids_paths_and_attrs_parse_exactly_what_is_written() {
        use crate::path::{RelPath, RootPath};
        use crate::policy::root::RootId;
        use crate::sys::fs::Attrs;
        let id = RootId {
            volume_serial: 0x1234,
            file_id: u128::MAX - 1,
        };
        let s = serde_json::to_string(&id).unwrap();
        assert_eq!(s, format!("\"{:016x}-{:032x}\"", 0x1234, u128::MAX - 1));
        assert_eq!(serde_json::from_str::<RootId>(&s).unwrap(), id);
        for bad in [
            "\"1234-00\"",
            "\"0000000000001234\"",
            &s.to_uppercase(),
            &s.replace('-', "+"),
        ] {
            assert!(serde_json::from_str::<RootId>(bad).is_err(), "{bad}");
        }
        let p: RelPath = serde_json::from_str(r#""a/B\\c.dll""#).unwrap();
        assert_eq!(serde_json::to_string(&p).unwrap(), r#""a\\B\\c.dll""#);
        for bad in [r#""..\\x""#, r#""C:\\x""#, r#""""#, r#""a\\CON""#] {
            assert!(serde_json::from_str::<RelPath>(bad).is_err(), "{bad}");
        }
        let r: RootPath = serde_json::from_str(r#""d:\\Games\\G""#).unwrap();
        assert_eq!(serde_json::to_string(&r).unwrap(), r#""D:\\Games\\G""#);
        assert!(serde_json::from_str::<RootPath>(r#""D:\\""#).is_err());
        let a = Attrs {
            readonly: true,
            hidden: false,
            system: true,
        };
        let s = serde_json::to_string(&a).unwrap();
        assert_eq!(s, r#"{"readonly":true,"hidden":false,"system":true}"#);
        assert_eq!(serde_json::from_str::<Attrs>(&s).unwrap(), a);
        assert!(serde_json::from_str::<Attrs>(r#"{"readonly":true,"hidden":false}"#).is_err());
        assert!(
            serde_json::from_str::<Attrs>(
                r#"{"readonly":true,"hidden":false,"system":true,"archive":true}"#
            )
            .is_err()
        );
    }
}
