//! Parser for `REPARSE_DATA_BUFFER` (`FSCTL_GET_REPARSE_POINT` output). Pure, no I/O.
//!
//! Layout (ntifs.h): `ULONG ReparseTag; USHORT ReparseDataLength; USHORT Reserved;` then the
//! tag-specific data:
//! - mount point (junction): `USHORT SubstituteNameOffset, SubstituteNameLength,
//!   PrintNameOffset, PrintNameLength; WCHAR PathBuffer[]`, offsets relative to `PathBuffer`;
//! - symbolic link: the same four `USHORT`s, then `ULONG Flags`, then `PathBuffer`;
//! - WSL symbolic link: `ULONG Version` (2), then the target as UTF-8 (not NUL-terminated).
//!
//! The reported target is the print name; if a junction has an empty print name (some tools
//! write none), the substitute name is reported instead, so a link never shows as "no target".

use crate::sys::fs::tag;

/// Why a buffer could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParseError {
    /// Shorter than its header or than `ReparseDataLength` claims, or a name outside the data.
    Truncated,
    /// Odd name length, unknown WSL version or invalid UTF-8.
    Malformed,
}

/// Tag and link target of a reparse buffer. The target is `Some` for mount points, symbolic
/// links and WSL symbolic links; `None` for every other tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Parsed {
    /// Reparse tag.
    pub tag: u32,
    /// Link target (print name).
    pub target: Option<String>,
}

const HEADER: usize = 8;

fn u16_at(b: &[u8], off: usize) -> Result<u16, ParseError> {
    let s = b.get(off..off + 2).ok_or(ParseError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, ParseError> {
    let s = b.get(off..off + 4).ok_or(ParseError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// A UTF-16 name at `offset`/`len` (bytes) inside `path_buffer`.
fn name(path_buffer: &[u8], offset: u16, len: u16) -> Result<String, ParseError> {
    let (off, len) = (usize::from(offset), usize::from(len));
    if !off.is_multiple_of(2) || !len.is_multiple_of(2) {
        return Err(ParseError::Malformed);
    }
    let b = path_buffer
        .get(off..off + len)
        .ok_or(ParseError::Truncated)?;
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Print name of a mount point or symbolic link. `data` starts at the
/// `SubstituteNameOffset` field, `path_start` is the offset of `PathBuffer` within `data`.
fn link_target(data: &[u8], path_start: usize) -> Result<String, ParseError> {
    let sub_off = u16_at(data, 0)?;
    let sub_len = u16_at(data, 2)?;
    let print_off = u16_at(data, 4)?;
    let print_len = u16_at(data, 6)?;
    let path_buffer = data.get(path_start..).ok_or(ParseError::Truncated)?;
    let print = name(path_buffer, print_off, print_len)?;
    // Always validate the substitute name too: a buffer with a bad one is malformed.
    let sub = name(path_buffer, sub_off, sub_len)?;
    Ok(if print.is_empty() { sub } else { print })
}

/// Parses a `REPARSE_DATA_BUFFER`. Only the first `8 + ReparseDataLength` bytes are used.
pub(super) fn parse(buf: &[u8]) -> Result<Parsed, ParseError> {
    let tag = u32_at(buf, 0)?;
    let data_len = usize::from(u16_at(buf, 4)?);
    let data = buf
        .get(HEADER..HEADER + data_len)
        .ok_or(ParseError::Truncated)?;
    let target = match tag {
        tag::MOUNT_POINT => Some(link_target(data, 8)?),
        tag::SYMLINK => {
            u32_at(data, 8)?; // Flags
            Some(link_target(data, 12)?)
        }
        tag::LX_SYMLINK => {
            if u32_at(data, 0)? != 2 {
                return Err(ParseError::Malformed);
            }
            let s = std::str::from_utf8(&data[4..]).map_err(|_| ParseError::Malformed)?;
            Some(s.to_owned())
        }
        _ => None,
    };
    Ok(Parsed { tag, target })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn header(tag: u32, data: &[u8]) -> Vec<u8> {
        let mut b = tag.to_le_bytes().to_vec();
        b.extend(u16::try_from(data.len()).unwrap().to_le_bytes());
        b.extend([0, 0]);
        b.extend_from_slice(data);
        b
    }

    /// Mount point or symlink data with the substitute name first, then the print name.
    fn link(sub: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
        let (s, p) = (utf16(sub), utf16(print));
        let mut d = Vec::new();
        for v in [0, s.len(), s.len(), p.len()] {
            d.extend(u16::try_from(v).unwrap().to_le_bytes());
        }
        if let Some(f) = flags {
            d.extend(f.to_le_bytes());
        }
        d.extend(s);
        d.extend(p);
        d
    }

    #[test]
    fn mount_point_print_name() {
        let b = header(
            tag::MOUNT_POINT,
            &link(r"\??\D:\SteamLibrary", r"D:\SteamLibrary", None),
        );
        assert_eq!(
            parse(&b),
            Ok(Parsed {
                tag: tag::MOUNT_POINT,
                target: Some(r"D:\SteamLibrary".into())
            })
        );
        // Empty print name: the substitute name is reported.
        let b = header(tag::MOUNT_POINT, &link(r"\??\D:\x", "", None));
        assert_eq!(parse(&b).unwrap().target.as_deref(), Some(r"\??\D:\x"));
    }

    #[test]
    fn symlink_print_name_after_flags() {
        let b = header(tag::SYMLINK, &link(r"..\x", r"..\x", Some(1)));
        assert_eq!(parse(&b).unwrap().target.as_deref(), Some(r"..\x"));
    }

    #[test]
    fn lx_symlink_utf8() {
        let mut d = 2u32.to_le_bytes().to_vec();
        d.extend(b"/mnt/c/x");
        assert_eq!(
            parse(&header(tag::LX_SYMLINK, &d))
                .unwrap()
                .target
                .as_deref(),
            Some("/mnt/c/x")
        );
        let mut d = 1u32.to_le_bytes().to_vec();
        d.extend(b"x");
        assert_eq!(
            parse(&header(tag::LX_SYMLINK, &d)),
            Err(ParseError::Malformed)
        );
        let mut d = 2u32.to_le_bytes().to_vec();
        d.push(0xFF);
        assert_eq!(
            parse(&header(tag::LX_SYMLINK, &d)),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn other_tags_have_no_target() {
        assert_eq!(
            parse(&header(tag::WOF, &[1, 2, 3, 4])),
            Ok(Parsed {
                tag: tag::WOF,
                target: None
            })
        );
        assert_eq!(parse(&header(tag::APPEXECLINK, &[])).unwrap().target, None);
    }

    #[test]
    fn truncated_buffers_are_errors() {
        assert_eq!(parse(&[0x03, 0, 0, 0xA0]), Err(ParseError::Truncated));
        let full = header(tag::MOUNT_POINT, &link(r"\??\D:\x", r"D:\x", None));
        for cut in [HEADER, HEADER + 4, full.len() - 1] {
            assert_eq!(parse(&full[..cut]), Err(ParseError::Truncated), "cut {cut}");
        }
        // ReparseDataLength larger than the buffer.
        let mut b = full.clone();
        b[4] = 0xFF;
        assert_eq!(parse(&b), Err(ParseError::Truncated));
        // Name offset beyond the data.
        let mut d = link(r"\??\D:\x", r"D:\x", None);
        d[4] = 0xF0;
        assert_eq!(
            parse(&header(tag::MOUNT_POINT, &d)),
            Err(ParseError::Truncated)
        );
        // Odd name length.
        let mut d = link(r"\??\D:\x", r"D:\x", None);
        d[6] = 3;
        assert_eq!(
            parse(&header(tag::MOUNT_POINT, &d)),
            Err(ParseError::Malformed)
        );
        // Trailing bytes after ReparseDataLength are ignored.
        let mut b = full;
        b.extend([0xAA; 7]);
        assert_eq!(parse(&b).unwrap().target.as_deref(), Some(r"D:\x"));
    }
}
