//! Names at the NT boundary. Pure, no I/O.
//!
//! - [`Seg16`]: a single path segment as UTF-16, re-checked here even though `RelPath` already
//!   validated it (ADR 0007: `sys::win` re-asserts single segments at the boundary).
//! - [`long_name_matches`]: the L1 check (8.3 short names must not reach another entry).
//! - [`volume_path`]: `RootInfo::volume_path` from `FileNormalizedNameInformation`.
//! - [`parse_abs`] and [`nt_path`]: input rules of `Fs::open_dir`, same as the fake.
//! - [`parse_name_info`] and [`parse_dir_entries`]: decoding of NT information buffers.

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

/// Layout of a directory listing buffer (`NtQueryDirectoryFile`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DirLayout {
    /// `FILE_ID_EXTD_DIR_INFORMATION` (`FileIdExtdDirectoryInformation`): explicit reparse
    /// tag and 128-bit file ID. NTFS and ReFS.
    IdExtd,
    /// `FILE_FULL_DIR_INFORMATION` (`FileFullDirectoryInformation`): no file ID; the reparse
    /// tag is in `EaSize` when `FILE_ATTRIBUTE_REPARSE_POINT` is set. Fallback for file
    /// systems without the ID class (FAT).
    Full,
}

/// Offsets shared by both layouts (ntifs.h): `EndOfFile`, `FileAttributes`, `FileNameLength`
/// and `EaSize`.
const DIR_END_OF_FILE: usize = 40;
const DIR_ATTRIBUTES: usize = 56;
const DIR_NAME_LEN: usize = 60;
const DIR_EA_SIZE: usize = 64;
/// `FILE_FULL_DIR_INFORMATION::FileName`.
const FULL_DIR_NAME: usize = 68;
/// `FILE_ID_EXTD_DIR_INFORMATION::{ReparsePointTag, FileId, FileName}`.
const EXTD_DIR_TAG: usize = 68;
const EXTD_DIR_ID: usize = 72;
const EXTD_DIR_NAME: usize = 88;

/// winnt.h `FILE_ATTRIBUTE_REPARSE_POINT`.
const ATTR_REPARSE_POINT: u32 = 0x0000_0400;

/// One entry of a directory listing, as the file system reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Listed {
    /// Raw name (long name; never the 8.3 short name).
    pub name: Vec<u16>,
    /// `FileAttributes`.
    pub attrs: u32,
    /// `EndOfFile`.
    pub len: u64,
    /// Reparse tag, only if `FILE_ATTRIBUTE_REPARSE_POINT` is set.
    pub tag: Option<u32>,
    /// 128-bit file ID ([`DirLayout::IdExtd`] only).
    pub file_id: Option<u128>,
}

fn u64_at(buf: &[u8], off: usize) -> Option<u64> {
    let b = buf.get(off..off.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Some(u64::from_le_bytes(a))
}

fn u128_at(buf: &[u8], off: usize) -> Option<u128> {
    let b = buf.get(off..off.checked_add(16)?)?;
    let mut a = [0u8; 16];
    a.copy_from_slice(b);
    Some(u128::from_le_bytes(a))
}

/// Decodes one listing buffer in `layout` into entries, `.` and `..` included. `None` if an
/// entry is truncated or the next offset points out of the buffer.
pub(super) fn parse_dir_entries(buf: &[u8], layout: DirLayout) -> Option<Vec<Listed>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        let at = |rel: usize| off.checked_add(rel);
        let next = usize::try_from(u32_at(buf, off)?).ok()?;
        let len = usize::try_from(u32_at(buf, at(DIR_NAME_LEN)?)?).ok()?;
        let attrs = u32_at(buf, at(DIR_ATTRIBUTES)?)?;
        let end_of_file = u64_at(buf, at(DIR_END_OF_FILE)?)?;
        let reparse = attrs & ATTR_REPARSE_POINT != 0;
        let (name_off, raw_tag, file_id) = match layout {
            DirLayout::IdExtd => (
                EXTD_DIR_NAME,
                u32_at(buf, at(EXTD_DIR_TAG)?)?,
                Some(u128_at(buf, at(EXTD_DIR_ID)?)?),
            ),
            DirLayout::Full => (FULL_DIR_NAME, u32_at(buf, at(DIR_EA_SIZE)?)?, None),
        };
        out.push(Listed {
            name: units_at(buf, at(name_off)?, len)?,
            attrs,
            len: end_of_file,
            tag: reparse.then_some(raw_tag),
            file_id,
        });
        if next == 0 {
            return Some(out);
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

    struct Raw<'a> {
        name: &'a str,
        attrs: u32,
        len: u64,
        tag: u32,
        id: u128,
    }

    fn raw(name: &str) -> Raw<'_> {
        Raw {
            name,
            attrs: 0x20,
            len: 0,
            tag: 0,
            id: 0,
        }
    }

    fn dir_entry(layout: DirLayout, e: &Raw<'_>, last: bool) -> Vec<u8> {
        let u = w(e.name);
        let name_off = match layout {
            DirLayout::IdExtd => EXTD_DIR_NAME,
            DirLayout::Full => FULL_DIR_NAME,
        };
        let padded = (name_off + u.len() * 2).div_ceil(8) * 8;
        let mut b = vec![0u8; padded];
        let next = if last { 0 } else { padded };
        let mut put = |off: usize, bytes: &[u8]| b[off..off + bytes.len()].copy_from_slice(bytes);
        put(0, &u32::try_from(next).unwrap().to_le_bytes());
        put(DIR_END_OF_FILE, &e.len.to_le_bytes());
        put(DIR_ATTRIBUTES, &e.attrs.to_le_bytes());
        put(
            DIR_NAME_LEN,
            &u32::try_from(u.len() * 2).unwrap().to_le_bytes(),
        );
        match layout {
            DirLayout::IdExtd => {
                put(DIR_EA_SIZE, &0u32.to_le_bytes());
                put(EXTD_DIR_TAG, &e.tag.to_le_bytes());
                put(EXTD_DIR_ID, &e.id.to_le_bytes());
            }
            DirLayout::Full => put(DIR_EA_SIZE, &e.tag.to_le_bytes()),
        }
        for (i, c) in u.iter().enumerate() {
            put(name_off + 2 * i, &c.to_le_bytes());
        }
        b
    }

    #[test]
    fn dir_buffer_decoding() {
        for layout in [DirLayout::IdExtd, DirLayout::Full] {
            let mut buf = dir_entry(layout, &raw("."), false);
            buf.extend(dir_entry(layout, &raw(".."), false));
            buf.extend(dir_entry(layout, &raw("d3d9.dll"), true));
            let entries = parse_dir_entries(&buf, layout).unwrap();
            let names: Vec<Vec<u16>> = entries.iter().map(|e| e.name.clone()).collect();
            assert_eq!(names, vec![w("."), w(".."), w("d3d9.dll")]);
            assert!(is_dot_entry(&names[0]) && is_dot_entry(&names[1]));
            assert!(!is_dot_entry(&names[2]));

            // Truncated name.
            let mut t = dir_entry(layout, &raw("abcdef"), true);
            t.truncate(FULL_DIR_NAME + 4);
            assert_eq!(parse_dir_entries(&t, layout), None);
            // Next offset out of the buffer.
            let mut o = dir_entry(layout, &raw("a"), true);
            o[0..4].copy_from_slice(&4096u32.to_le_bytes());
            assert_eq!(parse_dir_entries(&o, layout), None);
            assert_eq!(parse_dir_entries(&[], layout), None);
        }
    }

    #[test]
    fn dir_entry_fields() {
        let junction = Raw {
            name: "link",
            attrs: 0x10 | ATTR_REPARSE_POINT,
            len: 0,
            tag: 0xA000_0003,
            id: 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF,
        };
        let file = Raw {
            name: "secret.bin",
            attrs: 0x20 | 0x1,
            len: 6,
            // Without FILE_ATTRIBUTE_REPARSE_POINT the tag field is ignored (EaSize).
            tag: 0x1234,
            id: 7,
        };
        let mut buf = dir_entry(DirLayout::IdExtd, &junction, false);
        buf.extend(dir_entry(DirLayout::IdExtd, &file, true));
        let e = parse_dir_entries(&buf, DirLayout::IdExtd).unwrap();
        assert_eq!(
            e[0],
            Listed {
                name: w("link"),
                attrs: junction.attrs,
                len: 0,
                tag: Some(0xA000_0003),
                file_id: Some(junction.id),
            }
        );
        assert_eq!(
            e[1],
            Listed {
                name: w("secret.bin"),
                attrs: file.attrs,
                len: 6,
                tag: None,
                file_id: Some(7),
            }
        );
        // The FULL layout has no file ID and keeps the tag in EaSize.
        let mut buf = dir_entry(DirLayout::Full, &junction, false);
        buf.extend(dir_entry(DirLayout::Full, &file, true));
        let e = parse_dir_entries(&buf, DirLayout::Full).unwrap();
        assert_eq!((e[0].tag, e[0].file_id), (Some(0xA000_0003), None));
        assert_eq!((e[1].tag, e[1].len, e[1].file_id), (None, 6, None));
    }
}
