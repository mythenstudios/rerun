//! Registry trait.

use std::fmt;

use super::{SysError, SysErrorKind, SysResult};

/// Registry hive. Further hives only when a primitive needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hive {
    /// `HKEY_CURRENT_USER`
    CurrentUser,
    /// `HKEY_LOCAL_MACHINE`
    LocalMachine,
}

impl fmt::Display for Hive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CurrentUser => "HKCU",
            Self::LocalMachine => "HKLM",
        })
    }
}

/// Registry view (WOW64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegView {
    /// Native 64-bit view.
    Native,
    /// 32-bit view (`KEY_WOW64_32KEY`).
    Wow32,
}

impl fmt::Display for RegView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::Wow32 => "wow32",
        })
    }
}

/// A registry key. `path` without leading or trailing `\`; empty = hive root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegKey {
    /// Hive.
    pub hive: Hive,
    /// View.
    pub view: RegView,
    /// Path below the hive, separated by `\`.
    pub path: String,
}

impl RegKey {
    /// New key; leading and trailing `\` are removed.
    pub fn new(hive: Hive, view: RegView, path: impl AsRef<str>) -> Self {
        Self {
            hive,
            view,
            path: path.as_ref().trim_matches('\\').to_owned(),
        }
    }

    /// Subkey.
    #[must_use]
    pub fn join(&self, sub: &str) -> Self {
        let sub = sub.trim_matches('\\');
        let path = if self.path.is_empty() {
            sub.to_owned()
        } else {
            format!("{}\\{sub}", self.path)
        };
        Self {
            hive: self.hive,
            view: self.view,
            path,
        }
    }

    /// Parent key; `None` for the hive root.
    pub fn parent(&self) -> Option<Self> {
        if self.path.is_empty() {
            return None;
        }
        let path = self
            .path
            .rsplit_once('\\')
            .map_or("", |(p, _)| p)
            .to_owned();
        Some(Self {
            hive: self.hive,
            view: self.view,
            path,
        })
    }
}

impl fmt::Display for RegKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]\\{}", self.hive, self.view, self.path)
    }
}

/// Registry value types (`REG_*`), as stored on disk and returned by `RegQueryValueExW`.
pub mod reg_type {
    /// `REG_NONE`
    pub const REG_NONE: u32 = 0;
    /// `REG_SZ`
    pub const REG_SZ: u32 = 1;
    /// `REG_EXPAND_SZ`
    pub const REG_EXPAND_SZ: u32 = 2;
    /// `REG_BINARY`
    pub const REG_BINARY: u32 = 3;
    /// `REG_DWORD` (little endian)
    pub const REG_DWORD: u32 = 4;
    /// `REG_DWORD_BIG_ENDIAN`
    pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
    /// `REG_LINK`
    pub const REG_LINK: u32 = 6;
    /// `REG_MULTI_SZ`
    pub const REG_MULTI_SZ: u32 = 7;
    /// `REG_RESOURCE_LIST`
    pub const REG_RESOURCE_LIST: u32 = 8;
    /// `REG_FULL_RESOURCE_DESCRIPTOR`
    pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
    /// `REG_RESOURCE_REQUIREMENTS_LIST`
    pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
    /// `REG_QWORD` (little endian)
    pub const REG_QWORD: u32 = 11;
}

/// Longest key segment (one key name) in UTF-16 units.
pub const MAX_SEGMENT_UTF16: usize = 255;
/// Longest key path in UTF-16 units.
pub const MAX_PATH_UTF16: usize = 32_767;
/// Longest value name in UTF-16 units.
pub const MAX_VALUE_NAME_UTF16: usize = 16_383;

/// Largest value a read returns, in bytes. Registry data is untrusted: anything larger is
/// `Unsupported`, never truncated.
pub const MAX_VALUE_BYTES: usize = 1 << 20;
/// Most values `values` returns for one key.
pub const MAX_VALUES: usize = 16_384;
/// Most bytes `values` returns for one key in total: the names (UTF-16, without NUL) plus
/// the data of every value.
pub const MAX_VALUES_TOTAL_BYTES: usize = 16 << 20;
/// Most subkey names `subkeys` returns for one key.
pub const MAX_SUBKEYS: usize = 65_536;

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Shortened text for error targets, so a hostile 32 K path does not flood a message.
fn shown(s: &str) -> String {
    let mut out: String = s.chars().take(80).collect();
    if out.len() < s.len() {
        out.push('…');
    }
    out
}

/// Input rules for a key path, shared by every [`Registry`] implementation: no NUL, no empty
/// segment (leading, trailing or doubled `\`), a segment at most [`MAX_SEGMENT_UTF16`] and the
/// whole path at most [`MAX_PATH_UTF16`] UTF-16 units. Otherwise `InvalidPath`. The hive root
/// (empty path) is valid.
pub fn check_key(k: &RegKey) -> SysResult<()> {
    let bad = |why: &str| {
        Err(SysError::new(
            SysErrorKind::InvalidPath,
            format!("{}[{}]\\{}: {why}", k.hive, k.view, shown(&k.path)),
        ))
    };
    if k.path.is_empty() {
        return Ok(());
    }
    // NUL would truncate the path in the Win32 call.
    if k.path.contains('\0') {
        return bad("NUL in key path");
    }
    if utf16_len(&k.path) > MAX_PATH_UTF16 {
        return bad("key path too long");
    }
    for seg in k.path.split('\\') {
        if seg.is_empty() {
            return bad("empty key segment");
        }
        if utf16_len(seg) > MAX_SEGMENT_UTF16 {
            return bad("key segment too long");
        }
    }
    Ok(())
}

/// Input rules for a value name (`""` = default value): no NUL, at most
/// [`MAX_VALUE_NAME_UTF16`] UTF-16 units. Otherwise `InvalidPath`.
pub fn check_value_name(k: &RegKey, name: &str) -> SysResult<()> {
    let why = if name.contains('\0') {
        "NUL in value name"
    } else if utf16_len(name) > MAX_VALUE_NAME_UTF16 {
        "value name too long"
    } else {
        return Ok(());
    };
    Err(SysError::new(
        SysErrorKind::InvalidPath,
        format!("{k} @ {:?}: {why}", shown(name)),
    ))
}

/// A registry value whose type or bytes have no canonical typed form (see
/// [`RegValue::decode`]): kept exactly as stored. Only [`RegValue::decode`] makes one, so a
/// `RawValue` never holds bytes that a typed variant would encode to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawValue {
    kind: u32,
    data: Vec<u8>,
}

impl RawValue {
    /// The registry type number as stored (`REG_*`, possibly unknown).
    pub fn kind(&self) -> u32 {
        self.kind
    }

    /// The bytes as stored.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A registry value. `Dword(1)` and `String("1")` are different.
///
/// The typed variants hold exactly the values that have a canonical encoding;
/// everything else read from a registry is [`RegValue::Raw`]. So
/// `RegValue::decode(kind, data).encode() == Some((kind, data))` for every input: a snapshot
/// and the revert that follows see the exact bytes, and two different byte strings never decode
/// to the same value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    /// `REG_SZ`: no NUL inside.
    String(String),
    /// `REG_EXPAND_SZ`: no NUL inside. Never expanded.
    ExpandString(String),
    /// `REG_MULTI_SZ`: no element is empty or contains a NUL.
    MultiString(Vec<String>),
    /// `REG_DWORD`
    Dword(u32),
    /// `REG_QWORD`
    Qword(u64),
    /// `REG_BINARY`
    Binary(Vec<u8>),
    /// Any other type number, or bytes that are not the canonical encoding of their type.
    Raw(RawValue),
}

fn utf16_units(data: &[u8]) -> Option<Vec<u16>> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    Some(
        data.as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect(),
    )
}

/// `REG_SZ` bytes: valid UTF-16LE, exactly one NUL, at the end.
fn decode_sz(data: &[u8]) -> Option<String> {
    let units = utf16_units(data)?;
    let (last, body) = units.split_last()?;
    if *last != 0 || body.contains(&0) {
        return None;
    }
    String::from_utf16(body).ok()
}

/// `REG_MULTI_SZ` bytes: every string NUL-terminated, then one final NUL.
fn decode_multi(data: &[u8]) -> Option<Vec<String>> {
    let units = utf16_units(data)?;
    let (last, body) = units.split_last()?;
    if *last != 0 {
        return None;
    }
    if body.is_empty() {
        return Some(Vec::new());
    }
    let (terminator, body) = body.split_last()?;
    if *terminator != 0 {
        return None;
    }
    body.split(|u| *u == 0)
        .map(|s| {
            if s.is_empty() {
                None
            } else {
                String::from_utf16(s).ok()
            }
        })
        .collect()
}

fn encode_sz(s: &str) -> Option<Vec<u8>> {
    if s.contains('\0') {
        return None;
    }
    Some(
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect(),
    )
}

impl RegValue {
    /// Decodes stored `kind` and `data`: a typed variant only if its canonical encoding is
    /// exactly `data`, otherwise [`RegValue::Raw`].
    ///
    /// - `REG_SZ`, `REG_EXPAND_SZ`: valid UTF-16LE, no NUL inside, exactly one terminating
    ///   NUL. Zero length, odd length, missing or extra NULs and lone surrogates are `Raw`.
    /// - `REG_MULTI_SZ`: each string NUL-terminated, then one final NUL; the empty list is a
    ///   single NUL. An empty element or a missing final NUL is `Raw`.
    /// - `REG_DWORD` exactly 4 bytes, `REG_QWORD` exactly 8, little endian; other lengths are
    ///   `Raw`. `REG_BINARY` takes any bytes.
    /// - `REG_NONE`, `REG_DWORD_BIG_ENDIAN`, `REG_LINK`, the resource-list types and unknown
    ///   numbers are always `Raw`.
    #[must_use]
    pub fn decode(kind: u32, data: &[u8]) -> Self {
        let typed = match kind {
            reg_type::REG_SZ => decode_sz(data).map(Self::String),
            reg_type::REG_EXPAND_SZ => decode_sz(data).map(Self::ExpandString),
            reg_type::REG_MULTI_SZ => decode_multi(data).map(Self::MultiString),
            reg_type::REG_DWORD => <[u8; 4]>::try_from(data)
                .ok()
                .map(|b| Self::Dword(u32::from_le_bytes(b))),
            reg_type::REG_QWORD => <[u8; 8]>::try_from(data)
                .ok()
                .map(|b| Self::Qword(u64::from_le_bytes(b))),
            reg_type::REG_BINARY => Some(Self::Binary(data.to_vec())),
            _ => None,
        };
        // Belt and braces: the invariant holds by construction, but never trust it for data
        // that came from outside.
        match typed {
            Some(v)
                if v.encode()
                    .is_some_and(|(k, d)| k == kind && d.as_slice() == data) =>
            {
                v
            }
            _ => Self::Raw(RawValue {
                kind,
                data: data.to_vec(),
            }),
        }
    }

    /// The registry type number and bytes to store. `None` for a typed value without a
    /// canonical encoding (a string with a NUL, a multi-string with an empty element or a NUL):
    /// it cannot be written.
    pub fn encode(&self) -> Option<(u32, Vec<u8>)> {
        match self {
            Self::String(s) => Some((reg_type::REG_SZ, encode_sz(s)?)),
            Self::ExpandString(s) => Some((reg_type::REG_EXPAND_SZ, encode_sz(s)?)),
            Self::MultiString(list) => {
                let mut data = Vec::new();
                for s in list {
                    if s.is_empty() {
                        return None;
                    }
                    data.extend(encode_sz(s)?);
                }
                data.extend([0, 0]);
                Some((reg_type::REG_MULTI_SZ, data))
            }
            Self::Dword(v) => Some((reg_type::REG_DWORD, v.to_le_bytes().to_vec())),
            Self::Qword(v) => Some((reg_type::REG_QWORD, v.to_le_bytes().to_vec())),
            Self::Binary(b) => Some((reg_type::REG_BINARY, b.clone())),
            Self::Raw(r) => Some((r.kind, r.data.clone())),
        }
    }
}

impl fmt::Display for RegValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "REG_SZ {s:?}"),
            Self::ExpandString(s) => write!(f, "REG_EXPAND_SZ {s:?}"),
            Self::MultiString(v) => write!(f, "REG_MULTI_SZ {v:?}"),
            Self::Dword(v) => write!(f, "REG_DWORD {v:#010x}"),
            Self::Qword(v) => write!(f, "REG_QWORD {v:#018x}"),
            Self::Binary(b) => write!(f, "REG_BINARY {} bytes", b.len()),
            Self::Raw(r) => write!(f, "raw type {} {} bytes", r.kind, r.data.len()),
        }
    }
}

/// Registry. Key and value names are case-insensitive, the original case is preserved.
///
/// An existing empty key is different from a missing one: the revert must restore
/// this difference.
///
/// Every method applies [`check_key`] and, where a value name is given, [`check_value_name`]
/// first (`InvalidPath`). Registry data is untrusted: reads return values through
/// [`RegValue::decode`] (so [`RegValue::Raw`] keeps whatever is stored) and refuse, with
/// `Unsupported` and never a partial result, a value above [`MAX_VALUE_BYTES`], more than
/// [`MAX_VALUES`] values or [`MAX_VALUES_TOTAL_BYTES`] bytes in `values`, and more than
/// [`MAX_SUBKEYS`] names in `subkeys`. A value that [`RegValue::encode`] cannot encode is
/// refused by `set` with `Unsupported`.
pub trait Registry: Send + Sync {
    /// Does the key exist?
    fn key_exists(&self, k: &RegKey) -> SysResult<bool>;

    /// Reads a value; `""` = default value. Key missing → `NotFound`, value missing → `None`.
    fn get(&self, k: &RegKey, name: &str) -> SysResult<Option<RegValue>>;

    /// All values of a key (name in its original case).
    fn values(&self, k: &RegKey) -> SysResult<Vec<(String, RegValue)>>;

    /// Names of the direct subkeys.
    fn subkeys(&self, k: &RegKey) -> SysResult<Vec<String>>;

    /// Creates exactly one key; the parent key must exist (`NotFound` otherwise).
    /// `true` = newly created, `false` = already existed (important for the journal).
    fn create_key(&self, k: &RegKey) -> SysResult<bool>;

    /// Sets a value. Key missing → `NotFound`.
    fn set(&self, k: &RegKey, name: &str, v: &RegValue) -> SysResult<()>;

    /// Deletes a value. Missing → `NotFound`.
    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()>;

    /// Deletes a key without subkeys (`NotEmpty` otherwise).
    fn delete_key(&self, k: &RegKey) -> SysResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_and_parent() {
        let root = RegKey::new(Hive::CurrentUser, RegView::Native, "\\Software\\");
        assert_eq!(root.path, "Software");
        let k = root.join("Rerun");
        assert_eq!(k.path, "Software\\Rerun");
        assert_eq!(k.parent(), Some(root.clone()));
        assert_eq!(root.parent().map(|p| p.path), Some(String::new()));
        assert_eq!(
            RegKey::new(Hive::CurrentUser, RegView::Native, "").parent(),
            None
        );
    }

    use super::reg_type::*;

    fn utf16(s: &[u16]) -> Vec<u8> {
        s.iter().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn is_raw(v: &RegValue, kind: u32, data: &[u8]) -> bool {
        matches!(v, RegValue::Raw(r) if r.kind() == kind && r.data() == data)
    }

    /// Decoding keeps the exact bytes, whatever they are.
    fn assert_exact(kind: u32, data: &[u8]) -> RegValue {
        let v = RegValue::decode(kind, data);
        assert_eq!(
            v.encode(),
            Some((kind, data.to_vec())),
            "{kind} {data:02x?}"
        );
        v
    }

    #[test]
    fn canonical_strings_are_typed() {
        let mut data = utf16(&w("Steam"));
        data.extend([0, 0]);
        assert_eq!(
            assert_exact(REG_SZ, &data),
            RegValue::String("Steam".into())
        );
        assert_eq!(
            assert_exact(REG_EXPAND_SZ, &data),
            RegValue::ExpandString("Steam".into())
        );
        // The empty string is one NUL.
        assert_eq!(
            assert_exact(REG_SZ, &[0, 0]),
            RegValue::String(String::new())
        );
        // Non-BMP characters survive as surrogate pairs.
        let mut emoji = utf16(&w("a\u{1F3AE}"));
        emoji.extend([0, 0]);
        assert_eq!(
            assert_exact(REG_SZ, &emoji),
            RegValue::String("a\u{1F3AE}".into())
        );
    }

    #[test]
    fn malformed_strings_are_raw() {
        let cases: [(&str, Vec<u8>); 7] = [
            ("zero length", vec![]),
            ("odd length", vec![b'a', 0, 0]),
            ("no terminator", utf16(&w("abc"))),
            ("two terminators", utf16(&[0x61, 0, 0])),
            ("NUL inside", utf16(&[0x61, 0, 0x62, 0])),
            ("lone high surrogate", utf16(&[0xD800, 0])),
            ("lone low surrogate", utf16(&[0xDC00, 0x61, 0])),
        ];
        for (what, data) in cases {
            for kind in [REG_SZ, REG_EXPAND_SZ] {
                let v = assert_exact(kind, &data);
                assert!(is_raw(&v, kind, &data), "{what} (type {kind}): {v:?}");
            }
        }
    }

    #[test]
    fn multi_strings() {
        let enc = |parts: &[&str]| {
            let mut u: Vec<u16> = Vec::new();
            for p in parts {
                u.extend(w(p));
                u.push(0);
            }
            u.push(0);
            utf16(&u)
        };
        assert_eq!(
            assert_exact(REG_MULTI_SZ, &enc(&["a", "bc"])),
            RegValue::MultiString(vec!["a".into(), "bc".into()])
        );
        // The empty list is a single NUL.
        assert_eq!(
            assert_exact(REG_MULTI_SZ, &[0, 0]),
            RegValue::MultiString(vec![])
        );
        let raw_cases: [(&str, Vec<u8>); 6] = [
            ("zero length", vec![]),
            ("empty list with two NULs", vec![0, 0, 0, 0]),
            ("empty element", utf16(&[0x61, 0, 0, 0x62, 0, 0])),
            ("no final NUL", utf16(&[0x61, 0])),
            ("odd length", vec![0x61, 0, 0, 0, 0]),
            ("lone surrogate", utf16(&[0xD800, 0, 0])),
        ];
        for (what, data) in raw_cases {
            let v = assert_exact(REG_MULTI_SZ, &data);
            assert!(is_raw(&v, REG_MULTI_SZ, &data), "{what}: {v:?}");
        }
    }

    #[test]
    fn numbers_and_binary() {
        assert_eq!(assert_exact(REG_DWORD, &[1, 0, 0, 0]), RegValue::Dword(1));
        assert_eq!(
            assert_exact(REG_DWORD, &0xA1B2_C3D4_u32.to_le_bytes()),
            RegValue::Dword(0xA1B2_C3D4)
        );
        assert_eq!(
            assert_exact(REG_QWORD, &u64::MAX.to_le_bytes()),
            RegValue::Qword(u64::MAX)
        );
        for len in [0, 1, 3, 5, 8] {
            let data = vec![7; len];
            let v = assert_exact(REG_DWORD, &data);
            assert!(is_raw(&v, REG_DWORD, &data), "dword of {len} bytes");
        }
        for len in [0, 4, 7, 9] {
            let data = vec![7; len];
            let v = assert_exact(REG_QWORD, &data);
            assert!(is_raw(&v, REG_QWORD, &data), "qword of {len} bytes");
        }
        assert_eq!(assert_exact(REG_BINARY, &[]), RegValue::Binary(vec![]));
        assert_eq!(
            assert_exact(REG_BINARY, &[1, 2, 3]),
            RegValue::Binary(vec![1, 2, 3])
        );
    }

    #[test]
    fn other_types_are_always_raw() {
        for kind in [
            REG_NONE,
            REG_DWORD_BIG_ENDIAN,
            REG_LINK,
            REG_RESOURCE_LIST,
            REG_FULL_RESOURCE_DESCRIPTOR,
            REG_RESOURCE_REQUIREMENTS_LIST,
            12,
            0x8000_0001,
            u32::MAX,
        ] {
            for data in [&[][..], &[0, 0], &[1, 0, 0, 0], &[1, 2, 3]] {
                let v = assert_exact(kind, data);
                assert!(is_raw(&v, kind, data), "type {kind}");
            }
        }
    }

    #[test]
    fn typed_values_without_a_canonical_encoding_cannot_be_encoded() {
        for v in [
            RegValue::String("a\0b".into()),
            RegValue::ExpandString("\0".into()),
            RegValue::MultiString(vec!["a".into(), String::new()]),
            RegValue::MultiString(vec!["a\0b".into()]),
        ] {
            assert_eq!(v.encode(), None, "{v:?}");
        }
        // Everything else encodes and decodes to itself.
        for v in [
            RegValue::String(String::new()),
            RegValue::String("x".into()),
            RegValue::MultiString(vec![]),
            RegValue::MultiString(vec!["a".into(), "b".into()]),
            RegValue::Dword(0),
            RegValue::Qword(1 << 40),
            RegValue::Binary(vec![0, 0]),
        ] {
            let (k, d) = v.encode().unwrap();
            assert_eq!(RegValue::decode(k, &d), v);
        }
    }

    #[test]
    fn display_shows_raw_values() {
        let v = RegValue::decode(REG_NONE, &[1, 2, 3]);
        assert_eq!(v.to_string(), "raw type 0 3 bytes");
    }

    /// xorshift64*, so the loop is the same on every machine.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[test]
    fn random_values_round_trip_exactly() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut typed = 0_u32;
        let mut raw = 0_u32;
        for _ in 0..20_000 {
            let kind = match rng.below(4) {
                0 => u32::try_from(rng.below(14)).unwrap_or(0),
                1 => [REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ]
                    [usize::try_from(rng.below(3)).unwrap_or(0)],
                2 => [REG_DWORD, REG_QWORD, REG_BINARY][usize::try_from(rng.below(3)).unwrap_or(0)],
                _ => u32::try_from(rng.next() >> 32).unwrap_or(0),
            };
            // Biased towards structure: few distinct units, many NULs, some surrogates.
            let units = usize::try_from(rng.below(9)).unwrap_or(0);
            let mut data = Vec::new();
            match rng.below(3) {
                0 => {
                    for _ in 0..units {
                        let u: u16 = match rng.below(6) {
                            0..=1 => 0,
                            2 => 0xD800 + u16::try_from(rng.below(0x800)).unwrap_or(0),
                            _ => 0x61 + u16::try_from(rng.below(3)).unwrap_or(0),
                        };
                        data.extend(u.to_le_bytes());
                    }
                }
                1 => {
                    for _ in 0..rng.below(13) {
                        data.push(u8::try_from(rng.below(256)).unwrap_or(0));
                    }
                }
                _ => {
                    for _ in 0..units {
                        data.extend(u16::to_le_bytes(if rng.below(3) == 0 { 0 } else { 0x62 }));
                    }
                    if rng.below(2) == 0 {
                        data.push(0);
                    }
                }
            }
            let v = RegValue::decode(kind, &data);
            assert_eq!(v.encode(), Some((kind, data.clone())), "{kind} {data:02x?}");
            if matches!(v, RegValue::Raw(_)) {
                raw += 1;
            } else {
                typed += 1;
                // The typed form is canonical: no other bytes decode to it.
                assert_eq!(RegValue::decode(kind, &data), v);
            }
        }
        assert!(typed > 1000 && raw > 1000, "typed {typed}, raw {raw}");
    }

    #[test]
    fn input_rules() {
        let k = |p: &str| RegKey {
            hive: Hive::LocalMachine,
            view: RegView::Native,
            path: p.into(),
        };
        let long = |n: usize| "a".repeat(n);
        for ok in [
            String::new(),
            "Software".into(),
            r"Software\Valve\Steam".into(),
            long(255),
            // Many long segments, below the path limit.
            vec![long(255); 127].join(r"\"),
        ] {
            assert!(check_key(&k(&ok)).is_ok(), "{}", ok.len());
        }
        let nul = "a\0b".to_owned();
        let leading = r"\a".to_owned();
        let trailing = "a\\".to_owned();
        let double = r"a\\b".to_owned();
        let long_seg = long(256);
        // 128 segments of 255 + 127 separators = 32,767: one more unit is over the limit.
        let at_limit = vec![long(255); 128].join(r"\");
        assert_eq!(at_limit.len(), 32_767);
        let over = format!("{at_limit}a");
        // The limit counts UTF-16 units: 128 astral characters are 256 units.
        let astral = "\u{1F3AE}".repeat(128);
        for bad in [nul, leading, trailing, double, long_seg, over, astral] {
            let e = check_key(&k(&bad)).unwrap_err();
            assert_eq!(e.kind, SysErrorKind::InvalidPath, "{}", bad.len());
            assert!(e.target.chars().count() < 200, "error text is shortened");
        }
        assert!(check_key(&k(&at_limit)).is_ok());

        let key = k("x");
        assert!(check_value_name(&key, "").is_ok());
        assert!(check_value_name(&key, &long(16_383)).is_ok());
        for bad in ["a\0b".to_owned(), long(16_384), "\u{1F3AE}".repeat(8_192)] {
            let e = check_value_name(&key, &bad).unwrap_err();
            assert_eq!(e.kind, SysErrorKind::InvalidPath);
            assert!(e.target.chars().count() < 200);
        }
    }
}
