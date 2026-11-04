//! Names at the NT boundary. Pure, no I/O.
//!
//! - [`Seg16`]: a single path segment as UTF-16, re-checked here even though `RelPath` already
//!   validated it (ADR 0007: `sys::win` re-asserts single segments at the boundary).
//! - [`long_name_matches`]: the L1 check (8.3 short names must not reach another entry).
//! - [`volume_path`]: `RootInfo::volume_path` from `FileNormalizedNameInformation`.
//! - [`parse_abs`] and [`nt_path`]: input rules of `Fs::open_dir`, same as the fake.
//! - [`parse_name_info`] and [`parse_dir_names`]: decoding of NT information buffers.

use crate::fold::fold;

const BACKSLASH: u16 = b'\\' as u16;
const SLASH: u16 = b'/' as u16;
const COLON: u16 = b':' as u16;
const DOT: u16 = b'.' as u16;

/// Maximum length of one name in UTF-16 code units (NTFS, ReFS, FAT LFN).
pub(super) const MAX_SEGMENT: usize = 255;

/// A single path segment in UTF-16: not empty, not `.` or `..`, no `\`, `/`, `:` or NUL, at
/// most [`MAX_SEGMENT`] code units. May contain unpaired surrogates (raw names from disk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Seg16(Vec<u16>);

impl Seg16 {
    /// Checks and converts a segment given as a string.
    pub(super) fn new(s: &str) -> Option<Self> {
        Self::from_units(s.encode_utf16().collect())
    }

    /// Checks a raw segment (e.g. a name from a directory listing).
    pub(super) fn from_units(units: Vec<u16>) -> Option<Self> {
        let ok = !units.is_empty()
            && units.len() <= MAX_SEGMENT
            && units != [DOT]
            && units != [DOT, DOT]
            && !units
                .iter()
                .any(|&u| u == 0 || u == BACKSLASH || u == SLASH || u == COLON);
        ok.then_some(Self(units))
    }

    /// The code units.
    pub(super) fn units(&self) -> &[u16] {
        &self.0
    }
}

/// Last segment of an NT name (`\a\b` → `b`).
fn last_segment(name: &[u16]) -> &[u16] {
    match name.iter().rposition(|&u| u == BACKSLASH) {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// L1 check (ADR 0007): the last segment of the name the file system reports for the opened
/// object (`FileNormalizedNameInformation`, long names) equals the requested segment, exactly
/// or case-insensitively via [`fold`]. Fails for an 8.3 short name of another entry. A folding
/// difference to the NTFS upcase table can only make this fail (fail closed), never pass.
pub(super) fn long_name_matches(reported: &[u16], requested: &[u16]) -> bool {
    let last = last_segment(reported);
    last == requested
        || fold(&String::from_utf16_lossy(last)) == fold(&String::from_utf16_lossy(requested))
}

/// `RootInfo::volume_path` from the `FileNormalizedNameInformation` of a directory: exactly one
/// leading `\` stripped, lossy UTF-16. `\` (volume root) yields `""`. Anything that is not
/// `\` followed by non-empty segments yields `None` (fail closed).
pub(super) fn volume_path(normalized: &[u16]) -> Option<String> {
    let rest = normalized.strip_prefix(&[BACKSLASH])?;
    if rest.is_empty() {
        return Some(String::new());
    }
    if rest.split(|&u| u == BACKSLASH).any(<[u16]>::is_empty) {
        return None;
    }
    Some(String::from_utf16_lossy(rest))
}

/// Parses the input of `Fs::open_dir`: `X:\a\b` or `\\?\X:\a\b`, `/` treated as `\`, empty
/// segments ignored. `None` for anything else (relative, UNC, volume GUID, `\\.\`), for `.`
/// and `..` and for segments with control characters or `<>:"|?*`. Same rules as the fake.
pub(super) fn parse_abs(s: &str) -> Option<(char, Vec<String>)> {
    let s = s.replace('/', "\\");
    let t = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let b = t.as_bytes();
    if !(b.len() >= 2
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b.len() == 2 || b[2] == b'\\'))
    {
        return None;
    }
    let drive = char::from(b[0]).to_ascii_uppercase();
    let mut segs = Vec::new();
    for seg in t[2..].split('\\') {
        match seg {
            "" => {}
            "." | ".." => return None,
            _ if seg.chars().any(|c| {
                c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
            }) =>
            {
                return None;
            }
            _ => segs.push(seg.to_owned()),
        }
    }
    Some((drive, segs))
}

/// NT path `\??\X:\a\b` for [`parse_abs`] output (`\??\X:\` for a drive root).
pub(super) fn nt_path(drive: char, segs: &[String]) -> Vec<u16> {
    let mut s = format!(r"\??\{drive}:\");
    s.push_str(&segs.join("\\"));
    s.encode_utf16().collect()
}

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn units_at(buf: &[u8], off: usize, len_bytes: usize) -> Option<Vec<u16>> {
    if !len_bytes.is_multiple_of(2) {
        return None;
    }
    let b = buf.get(off..off.checked_add(len_bytes)?)?;
    Some(
        b.as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect(),
    )
}

/// Decodes `FILE_NAME_INFORMATION` (`FileNameInformation`, `FileNormalizedNameInformation`):
/// `ULONG FileNameLength` (bytes) followed by the name. `None` if truncated.
pub(super) fn parse_name_info(buf: &[u8]) -> Option<Vec<u16>> {
    let len = usize::try_from(u32_at(buf, 0)?).ok()?;
    units_at(buf, 4, len)
}

/// Offset of `FileNameLength` in `FILE_FULL_DIR_INFORMATION` (ntifs.h).
const FULL_DIR_NAME_LEN: usize = 60;
/// Offset of `FileName` in `FILE_FULL_DIR_INFORMATION` (ntifs.h).
const FULL_DIR_NAME: usize = 68;

/// Decodes a buffer of `FILE_FULL_DIR_INFORMATION` entries (`NtQueryDirectoryFile`,
/// `FileFullDirectoryInformation`) into raw names, `.` and `..` included. `None` if an entry
/// is truncated or the next offset points out of the buffer.
pub(super) fn parse_dir_names(buf: &[u8]) -> Option<Vec<Vec<u16>>> {
    let mut names = Vec::new();
    let mut off = 0usize;
    loop {
        let next = usize::try_from(u32_at(buf, off)?).ok()?;
        let len = usize::try_from(u32_at(buf, off.checked_add(FULL_DIR_NAME_LEN)?)?).ok()?;
        names.push(units_at(buf, off.checked_add(FULL_DIR_NAME)?, len)?);
        if next == 0 {
            return Some(names);
        }
        off = off.checked_add(next)?;
        if off >= buf.len() {
            return None;
        }
    }
}

/// `.` or `..` in a directory listing.
pub(super) fn is_dot_entry(name: &[u16]) -> bool {
    name == [DOT] || name == [DOT, DOT]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn seg16_rejects_non_segments() {
        for bad in ["", ".", "..", r"a\b", "a/b", "a:b", "a\0b"] {
            assert!(Seg16::new(bad).is_none(), "{bad:?}");
        }
        assert!(Seg16::new(&"x".repeat(256)).is_none());
        assert!(Seg16::new(&"x".repeat(255)).is_some());
        // 255 UTF-16 units, not 255 chars: 128 surrogate pairs are 256 units.
        assert!(Seg16::new(&"😀".repeat(128)).is_none());
        for ok in ["a", "...", "d3d9.dll.", "CON", "Straße"] {
            assert_eq!(Seg16::new(ok).map(|s| s.units().to_vec()), Some(w(ok)));
        }
        // Raw names may contain unpaired surrogates.
        assert!(Seg16::from_units(vec![0xD800, u16::from(b'a')]).is_some());
    }

    #[test]
    fn long_name_check() {
        assert!(long_name_matches(&w(r"\Games\Data"), &w("Data")));
        assert!(long_name_matches(&w(r"\Games\Data"), &w("DATA")));
        assert!(long_name_matches(&w(r"\Straße"), &w("STRAßE")));
        // 8.3 short name of another spelling, ß vs SS: never equal.
        assert!(!long_name_matches(&w(r"\Program Files"), &w("PROGRA~1")));
        assert!(!long_name_matches(&w(r"\Straße"), &w("STRASSE")));
        assert!(!long_name_matches(&w(r"\a\bc"), &w("c")));
        // Raw names compare exactly first.
        let raw = vec![0xD800, u16::from(b'x')];
        let mut reported = w(r"\d\");
        reported.extend_from_slice(&raw);
        assert!(long_name_matches(&reported, &raw));
    }

    #[test]
    fn volume_path_strips_exactly_one_backslash() {
        assert_eq!(volume_path(&w(r"\")), Some(String::new()));
        assert_eq!(volume_path(&w(r"\Games")), Some("Games".to_owned()));
        assert_eq!(
            volume_path(&w(r"\Mounts\Data\Steam")),
            Some(r"Mounts\Data\Steam".to_owned())
        );
        for bad in ["", "Games", r"\\Games", r"\Games\", r"\a\\b"] {
            assert_eq!(volume_path(&w(bad)), None, "{bad:?}");
        }
        assert_eq!(
            volume_path(&[BACKSLASH, 0xD800]),
            Some("\u{FFFD}".to_owned())
        );
    }

    #[test]
    fn abs_parsing_matches_fake_rules() {
        assert_eq!(parse_abs(r"c:\"), Some(('C', vec![])));
        assert_eq!(parse_abs("C:"), Some(('C', vec![])));
        assert_eq!(
            parse_abs(r"\\?\D:\Steam\\steamapps/common"),
            Some((
                'D',
                vec!["Steam".into(), "steamapps".into(), "common".into()]
            ))
        );
        for bad in [
            r"Steam",
            r"\Steam",
            r"C:Steam",
            r"\\server\share",
            r"\\?\UNC\server\share",
            r"\\?\Volume{0000}\x",
            r"\\.\C:\x",
            r"C:\a\..\b",
            r"C:\.\b",
            r"C:\a*",
            "C:\\a\u{1}",
            r"C:\a:b",
        ] {
            assert_eq!(parse_abs(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn nt_path_shape() {
        assert_eq!(nt_path('C', &[]), w(r"\??\C:\"));
        assert_eq!(nt_path('D', &["a".into(), "b".into()]), w(r"\??\D:\a\b"));
    }

    fn name_info(name: &str) -> Vec<u8> {
        let u = w(name);
        let mut b = u32::try_from(u.len() * 2).unwrap().to_le_bytes().to_vec();
        b.extend(u.iter().flat_map(|c| c.to_le_bytes()));
        b
    }

    #[test]
    fn name_info_decoding() {
        assert_eq!(parse_name_info(&name_info(r"\a\b")), Some(w(r"\a\b")));
        let mut b = name_info(r"\abc");
        b.pop();
        assert_eq!(parse_name_info(&b), None);
        assert_eq!(parse_name_info(&[1, 0, 0, 0, 0]), None, "odd length");
        assert_eq!(parse_name_info(&[0, 0]), None);
    }

    fn dir_entry(name: &str, last: bool) -> Vec<u8> {
        let u = w(name);
        let len = FULL_DIR_NAME + u.len() * 2;
        let padded = len.div_ceil(8) * 8;
        let mut b = vec![0u8; padded];
        let next = if last { 0 } else { padded };
        b[0..4].copy_from_slice(&u32::try_from(next).unwrap().to_le_bytes());
        b[FULL_DIR_NAME_LEN..FULL_DIR_NAME_LEN + 4]
            .copy_from_slice(&u32::try_from(u.len() * 2).unwrap().to_le_bytes());
        for (i, c) in u.iter().enumerate() {
            b[FULL_DIR_NAME + 2 * i..FULL_DIR_NAME + 2 * i + 2].copy_from_slice(&c.to_le_bytes());
        }
        b
    }

    #[test]
    fn dir_buffer_decoding() {
        let mut buf = dir_entry(".", false);
        buf.extend(dir_entry("..", false));
        buf.extend(dir_entry("d3d9.dll", true));
        let names = parse_dir_names(&buf).unwrap();
        assert_eq!(names, vec![w("."), w(".."), w("d3d9.dll")]);
        assert!(is_dot_entry(&names[0]) && is_dot_entry(&names[1]));
        assert!(!is_dot_entry(&names[2]));

        // Truncated name.
        let mut t = dir_entry("abcdef", true);
        t.truncate(FULL_DIR_NAME + 4);
        assert_eq!(parse_dir_names(&t), None);
        // Next offset out of the buffer.
        let mut o = dir_entry("a", true);
        o[0..4].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(parse_dir_names(&o), None);
        assert_eq!(parse_dir_names(&[]), None);
    }
}
