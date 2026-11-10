//! The zip reader (APPNOTE 6.3): the end record, the central directory, every local header and
//! data descriptor checked before any content is read (ADR 0025 part 2).
//!
//! - **End record:** the one closest to the end whose comment ends exactly at the end of the
//!   file, searched in the last 22 + 65,535 bytes. The central directory lies directly before
//!   it (`offset + size` = the record's position) and holds exactly the stated number of
//!   entries, back to back.
//! - **Refused:** zip64 (a field at its maximum, a zip64 locator, a zip64 extra field: no
//!   package archive comes near 4 GiB, and the download limit is 64 MiB), more than one disk,
//!   encryption, any method but stored (0) and deflate (8), the Info-ZIP Unicode path field
//!   (`0x7075`: other tools would extract under a name Rerun never checked), a malformed extra
//!   field, a name that is not UTF-8 (flag 11) or not ASCII (without it), a Unix link or
//!   special file mode, a Windows reparse point attribute.
//! - **Local headers** agree with the central directory: signature, the flags that matter
//!   (encryption, data descriptor, UTF-8), method, name byte for byte, CRC-32 and sizes (with a
//!   data descriptor each is 0 or the same). A data descriptor (with or without its signature)
//!   must repeat the central directory's CRC-32 and sizes.
//! - **No overlap:** every entry's local header, data and descriptor lie before the central
//!   directory, and no two entries share a byte (the overlapping zip bomb).
//! - **Sizes:** each entry within `max_entry_bytes` and the ratio rule, all entries together
//!   within `max_total_bytes`; a stored entry's two sizes are equal; a folder has no content.

use super::{ArchiveError, Limits, Loc, RawEntry};

const EOCD_SIG: u32 = 0x0605_4B50;
const CD_SIG: u32 = 0x0201_4B50;
const LOCAL_SIG: u32 = 0x0403_4B50;
const DD_SIG: u32 = 0x0807_4B50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4B50;

const EOCD_LEN: usize = 22;
const CD_LEN: usize = 46;
const LOCAL_LEN: usize = 30;
const MAX_COMMENT: usize = 0xFFFF;

/// Encryption (bit 0), strong encryption (bit 6), masked local header (bit 13).
const FLAGS_ENCRYPTED: u16 = 0x0001 | 0x0040 | 0x2000;
/// A data descriptor follows the data (bit 3).
const FLAG_DESCRIPTOR: u16 = 0x0008;
/// The name is UTF-8 (bit 11).
const FLAG_UTF8: u16 = 0x0800;
/// The flags a local header must share with its central directory entry.
const FLAGS_SHARED: u16 = FLAGS_ENCRYPTED | FLAG_DESCRIPTOR | FLAG_UTF8;

const STORED: u16 = 0;
const DEFLATED: u16 = 8;

/// Extra field IDs.
const EXTRA_ZIP64: u16 = 0x0001;
const EXTRA_UNICODE_PATH: u16 = 0x7075;

/// Host systems of "version made by" whose external attributes carry a Unix mode.
const HOST_UNIX: u16 = 3;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
/// `FILE_ATTRIBUTE_REPARSE_POINT` in the low word of the external attributes.
const ATTR_REPARSE: u32 = 0x0400;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([*s.first()?, *s.get(1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        *s.first()?,
        *s.get(1)?,
        *s.get(2)?,
        *s.get(3)?,
    ]))
}

fn usize_of(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// The end record's position.
fn find_eocd(b: &[u8]) -> Option<usize> {
    let last = b.len().checked_sub(EOCD_LEN)?;
    let lowest = last.saturating_sub(MAX_COMMENT);
    let mut p = last;
    loop {
        if u32_at(b, p) == Some(EOCD_SIG)
            && u16_at(b, p + 20).map(usize::from) == Some(b.len() - p - EOCD_LEN)
        {
            return Some(p);
        }
        if p == lowest {
            return None;
        }
        p -= 1;
    }
}

/// Walks an extra field: well-formed blocks that exactly fill it, none of the refused IDs.
fn check_extra(x: &[u8]) -> Result<(), ArchiveError> {
    let mut at = 0usize;
    while at < x.len() {
        let (Some(id), Some(len)) = (u16_at(x, at), u16_at(x, at + 2)) else {
            return Err(ArchiveError::Corrupt("an extra field"));
        };
        match id {
            EXTRA_ZIP64 => return Err(ArchiveError::Unsupported("zip64")),
            EXTRA_UNICODE_PATH => {
                return Err(ArchiveError::Unsupported(
                    "a second (Unicode) name for an entry",
                ));
            }
            _ => {}
        }
        at = at
            .checked_add(4 + usize::from(len))
            .filter(|e| *e <= x.len())
            .ok_or(ArchiveError::Corrupt("an extra field"))?;
    }
    Ok(())
}

/// The name as text: UTF-8 with flag 11, else ASCII only.
fn decode_name(raw: &[u8], flags: u16) -> Result<String, ArchiveError> {
    let bad = |why| ArchiveError::BadName {
        name: String::from_utf8_lossy(raw).into_owned(),
        why,
    };
    if flags & FLAG_UTF8 != 0 {
        std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| bad("not UTF-8"))
    } else if raw.is_ascii() {
        Ok(String::from_utf8_lossy(raw).into_owned())
    } else {
        Err(bad("not ASCII and not marked as UTF-8"))
    }
}

/// One central directory entry, parsed.
struct Central<'a> {
    made_by: u16,
    flags: u16,
    method: u16,
    crc: u32,
    csize: u32,
    usize: u32,
    attrs: u32,
    local: usize,
    name: &'a [u8],
}

/// The span `[start, end)` of an entry's local header, data and descriptor, and where its
/// data starts.
struct Span {
    start: usize,
    data: usize,
    end: usize,
}

/// Checks the local header of `c` and returns its span (module docs).
fn local(b: &[u8], c: &Central<'_>, cd_off: usize) -> Result<Span, ArchiveError> {
    let lo = c.local;
    let fixed = lo
        .checked_add(LOCAL_LEN)
        .filter(|e| *e <= cd_off)
        .ok_or(ArchiveError::Corrupt("a local header outside the entries"))?;
    let differs = ArchiveError::Corrupt("a local header that differs from the central directory");
    let field16 = |at| u16_at(b, lo + at).ok_or(ArchiveError::Truncated("a local header"));
    let field32 = |at| u32_at(b, lo + at).ok_or(ArchiveError::Truncated("a local header"));
    if field32(0)? != LOCAL_SIG {
        return Err(ArchiveError::Corrupt("a local header signature"));
    }
    let flags = field16(6)?;
    if flags & FLAGS_SHARED != c.flags & FLAGS_SHARED || field16(8)? != c.method {
        return Err(differs);
    }
    let (crc, csize, usize) = (field32(14)?, field32(18)?, field32(22)?);
    let same = |local: u32, central: u32| local == central;
    let zero_or_same = |local: u32, central: u32| local == 0 || local == central;
    let ok = if c.flags & FLAG_DESCRIPTOR == 0 {
        same(crc, c.crc) && same(csize, c.csize) && same(usize, c.usize)
    } else {
        zero_or_same(crc, c.crc) && zero_or_same(csize, c.csize) && zero_or_same(usize, c.usize)
    };
    if !ok {
        return Err(differs);
    }
    let nlen = usize::from(field16(26)?);
    let xlen = usize::from(field16(28)?);
    let name_end = fixed + nlen;
    let data = name_end + xlen;
    if data > cd_off {
        return Err(ArchiveError::Corrupt("a local header outside the entries"));
    }
    if b.get(fixed..name_end) != Some(c.name) {
        return Err(differs);
    }
    check_extra(b.get(name_end..data).ok_or(ArchiveError::Internal)?)?;
    let data_end = data
        .checked_add(usize_of(c.csize))
        .filter(|e| *e <= cd_off)
        .ok_or(ArchiveError::Corrupt(
            "an entry that runs into the central directory",
        ))?;
    let mut end = data_end;
    if c.flags & FLAG_DESCRIPTOR != 0 {
        let at = |i: usize| u32_at(b, data_end + i);
        let with_sig = at(0) == Some(DD_SIG)
            && at(4) == Some(c.crc)
            && at(8) == Some(c.csize)
            && at(12) == Some(c.usize);
        let without = at(0) == Some(c.crc) && at(4) == Some(c.csize) && at(8) == Some(c.usize);
        end += if with_sig {
            16
        } else if without {
            12
        } else {
            return Err(ArchiveError::Corrupt(
                "a data descriptor that differs from the central directory",
            ));
        };
        if end > cd_off {
            return Err(ArchiveError::Corrupt(
                "an entry that runs into the central directory",
            ));
        }
    }
    Ok(Span {
        start: lo,
        data,
        end,
    })
}

/// Checks the whole zip `b` (module docs) and lists its entries in central directory order.
pub(super) fn scan(b: &[u8], lim: &Limits) -> Result<Vec<RawEntry>, ArchiveError> {
    let p = find_eocd(b).ok_or(ArchiveError::NotFormat("zip"))?;
    let f16 = |at| u16_at(b, p + at).ok_or(ArchiveError::Internal);
    let f32 = |at| u32_at(b, p + at).ok_or(ArchiveError::Internal);
    let (disk, cd_disk, n_disk, n) = (f16(4)?, f16(6)?, f16(8)?, f16(10)?);
    let (cd_size, cd_off) = (f32(12)?, f32(16)?);
    let zip64_locator = p >= 20 && u32_at(b, p - 20) == Some(ZIP64_LOCATOR_SIG);
    if n == 0xFFFF || n_disk == 0xFFFF || cd_size == u32::MAX || cd_off == u32::MAX || zip64_locator
    {
        return Err(ArchiveError::Unsupported("zip64"));
    }
    if disk != 0 || cd_disk != 0 || n_disk != n {
        return Err(ArchiveError::Unsupported("an archive over several disks"));
    }
    if usize::from(n) > lim.max_entries {
        return Err(ArchiveError::TooLarge("the number of entries"));
    }
    let cd_off = usize_of(cd_off);
    if cd_off.checked_add(usize_of(cd_size)) != Some(p) {
        return Err(ArchiveError::Corrupt(
            "the position of the central directory",
        ));
    }
    let mut out = Vec::with_capacity(usize::from(n));
    let mut spans = Vec::with_capacity(usize::from(n));
    let mut total = 0u64;
    let mut pos = cd_off;
    for _ in 0..n {
        let h = |at| u16_at(b, pos + at).ok_or(ArchiveError::Truncated("the central directory"));
        let w = |at| u32_at(b, pos + at).ok_or(ArchiveError::Truncated("the central directory"));
        if pos + CD_LEN > p {
            return Err(ArchiveError::Truncated("the central directory"));
        }
        if w(0)? != CD_SIG {
            return Err(ArchiveError::Corrupt("a central directory entry"));
        }
        let (nlen, xlen, clen) = (
            usize::from(h(28)?),
            usize::from(h(30)?),
            usize::from(h(32)?),
        );
        if nlen > lim.max_name_bytes {
            return Err(ArchiveError::TooLarge("an entry name"));
        }
        let name_at = pos + CD_LEN;
        let next = name_at + nlen + xlen + clen;
        if next > p {
            return Err(ArchiveError::Truncated("the central directory"));
        }
        let c = Central {
            made_by: h(4)?,
            flags: h(8)?,
            method: h(10)?,
            crc: w(16)?,
            csize: w(20)?,
            usize: w(24)?,
            attrs: w(38)?,
            local: usize_of(w(42)?),
            name: b
                .get(name_at..name_at + nlen)
                .ok_or(ArchiveError::Internal)?,
        };
        if h(34)? != 0 {
            return Err(ArchiveError::Unsupported("an archive over several disks"));
        }
        if c.csize == u32::MAX || c.usize == u32::MAX || w(42)? == u32::MAX {
            return Err(ArchiveError::Unsupported("zip64"));
        }
        check_extra(
            b.get(name_at + nlen..name_at + nlen + xlen)
                .ok_or(ArchiveError::Internal)?,
        )?;
        if c.flags & FLAGS_ENCRYPTED != 0 {
            return Err(ArchiveError::Unsupported("encryption"));
        }
        let name = decode_name(c.name, c.flags)?;
        let dir = name.ends_with('/');
        if c.method != STORED && c.method != DEFLATED {
            return Err(ArchiveError::Unsupported(
                "a compression method other than stored or deflate",
            ));
        }
        if (c.made_by >> 8) == HOST_UNIX {
            let kind = (c.attrs >> 16) & S_IFMT;
            if kind == S_IFLNK {
                return Err(ArchiveError::Special {
                    name,
                    kind: "a link",
                });
            }
            if kind != 0 && kind != S_IFREG && kind != S_IFDIR {
                return Err(ArchiveError::Special {
                    name,
                    kind: "a special file",
                });
            }
        } else if c.attrs & ATTR_REPARSE != 0 {
            return Err(ArchiveError::Special {
                name,
                kind: "a reparse point",
            });
        }
        let size = u64::from(c.usize);
        if dir && size != 0 {
            return Err(ArchiveError::Corrupt("a folder entry with content"));
        }
        if c.method == STORED && c.csize != c.usize {
            return Err(ArchiveError::Corrupt(
                "a stored entry whose two sizes differ",
            ));
        }
        if size > lim.max_entry_bytes {
            return Err(ArchiveError::TooLarge("the size of an entry"));
        }
        if !lim.ratio_ok(size, u64::from(c.csize)) {
            return Err(ArchiveError::TooLarge("the compression ratio of an entry"));
        }
        total = total.saturating_add(size);
        if total > lim.max_total_bytes {
            return Err(ArchiveError::TooLarge("the total size of the entries"));
        }
        let span = local(b, &c, cd_off)?;
        out.push(RawEntry {
            name,
            dir,
            size,
            loc: Loc::Zip {
                start: span.data,
                len: usize_of(c.csize),
                deflated: c.method == DEFLATED,
                crc: c.crc,
            },
        });
        spans.push((span.start, span.end));
        pos = next;
    }
    if pos != p {
        return Err(ArchiveError::Corrupt("the size of the central directory"));
    }
    spans.sort_unstable();
    for pair in spans.windows(2) {
        if let [(_, end), (start, _)] = pair
            && start < end
        {
            return Err(ArchiveError::Overlap);
        }
    }
    Ok(out)
}
