//! The tar.gz reader: one gzip member ([`Gunzip`]) holding a ustar (POSIX) or GNU tar, read to
//! its end before anything is extracted (ADR 0025 part 2).
//!
//! - **Headers:** the checksum (unsigned sum, the field as spaces) must match; the magic is
//!   `ustar\0` + `00` (POSIX: a `prefix` joins the name) or `ustar  \0` (GNU: no prefix); a
//!   version 7 header without magic is refused. Sizes are octal (base-256 is refused).
//! - **Types:** `0` (and NUL) files and `5` folders only. Hard links (`1`), symbolic links
//!   (`2`), devices, pipes, contiguous files, GNU long names (`L`, `K`), pax headers (`x`, `g`:
//!   they could rename the next entry for other tools), sparse files and every other type
//!   refuse the archive.
//! - **The end:** a zero block, then only zero bytes up to the end of the stream (the second
//!   zero block and the record padding), then the gzip trailer (CRC-32 and length) and nothing
//!   after it.
//! - **Sizes:** each entry within `max_entry_bytes`, the decompressed stream within
//!   `max_total_bytes` and the ratio rule against the archive's size.

use super::inflate::{Gunzip, Pull, fill, skip};
use super::{ArchiveError, Limits, Loc, RawEntry};

const BLOCK: usize = 512;

/// The bytes of a NUL-terminated field up to its NUL.
fn cstr(f: &[u8]) -> &[u8] {
    let end = f.iter().position(|b| *b == 0).unwrap_or(f.len());
    f.get(..end).unwrap_or_default()
}

/// An octal number field: optional leading spaces, octal digits, then only NULs or spaces.
fn octal(f: &[u8], what: &'static str) -> Result<u64, ArchiveError> {
    if f.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(ArchiveError::Unsupported("a tar number in base-256"));
    }
    let bad = ArchiveError::Corrupt(what);
    let mut i = 0;
    while f.get(i) == Some(&b' ') {
        i += 1;
    }
    let mut v: u64 = 0;
    let mut digits = 0;
    while let Some(&c) = f.get(i) {
        if !(b'0'..=b'7').contains(&c) {
            break;
        }
        v = v
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
            .ok_or(bad.clone())?;
        digits += 1;
        i += 1;
    }
    let rest_ok = f
        .get(i..)
        .unwrap_or_default()
        .iter()
        .all(|b| *b == 0 || *b == b' ');
    if digits == 0 || !rest_ok {
        return Err(bad);
    }
    Ok(v)
}

/// One header: its name, whether it is a folder, its size.
fn header(h: &[u8; BLOCK], lim: &Limits) -> Result<(String, bool, u64), ArchiveError> {
    let field = |a: usize, b: usize| h.get(a..b).unwrap_or_default();
    let stored = octal(field(148, 156), "a tar header checksum")?;
    let sum: u64 = h
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                u64::from(b' ')
            } else {
                u64::from(*b)
            }
        })
        .sum();
    if sum != stored {
        return Err(ArchiveError::Corrupt("a tar header checksum"));
    }
    let posix = field(257, 265) == b"ustar\x0000";
    let gnu = field(257, 265) == b"ustar  \x00";
    if !posix && !gnu {
        return Err(ArchiveError::Unsupported(
            "a tar format other than ustar or GNU",
        ));
    }
    let mut raw = cstr(field(0, 100)).to_vec();
    if posix {
        let prefix = cstr(field(345, 500));
        if !prefix.is_empty() {
            let mut joined = prefix.to_vec();
            joined.push(b'/');
            joined.extend_from_slice(&raw);
            raw = joined;
        }
    }
    if raw.len() > lim.max_name_bytes {
        return Err(ArchiveError::TooLarge("an entry name"));
    }
    let name = String::from_utf8(raw).map_err(|e| ArchiveError::BadName {
        name: String::from_utf8_lossy(e.as_bytes()).into_owned(),
        why: "not UTF-8",
    })?;
    let special = |kind| ArchiveError::Special {
        name: name.clone(),
        kind,
    };
    let dir = match h.get(156).copied().unwrap_or(0) {
        b'0' | 0 => false,
        b'5' => true,
        b'1' => return Err(special("a hard link")),
        b'2' => return Err(special("a link")),
        b'3' | b'4' => return Err(special("a device")),
        b'6' => return Err(special("a pipe")),
        b'L' | b'K' => return Err(ArchiveError::Unsupported("GNU long names")),
        b'x' | b'g' => return Err(ArchiveError::Unsupported("pax headers")),
        b'S' => return Err(ArchiveError::Unsupported("sparse files")),
        _ => return Err(special("an entry of another type")),
    };
    let size = octal(field(124, 136), "a tar entry size")?;
    if dir && size != 0 {
        return Err(ArchiveError::Corrupt("a folder entry with content"));
    }
    if size > lim.max_entry_bytes {
        return Err(ArchiveError::TooLarge("the size of an entry"));
    }
    Ok((name, dir, size))
}

/// Checks the whole tar.gz `b` (module docs) and lists its entries in archive order.
pub(super) fn scan(b: &[u8], lim: &Limits) -> Result<Vec<RawEntry>, ArchiveError> {
    let mut gz = Gunzip::new(b, lim.max_total_bytes)?;
    let mut out = Vec::new();
    let mut block = [0u8; BLOCK];
    loop {
        if !fill(&mut gz, &mut block, "a tar header")? {
            return Err(ArchiveError::Truncated("the end of the tar archive"));
        }
        if block.iter().all(|x| *x == 0) {
            break;
        }
        if out.len() >= lim.max_entries {
            return Err(ArchiveError::TooLarge("the number of entries"));
        }
        let (name, dir, size) = header(&block, lim)?;
        let offset = gz.produced();
        let padded = size.div_ceil(512).saturating_mul(512);
        skip(&mut gz, padded, "a tar entry")?;
        out.push(RawEntry {
            name,
            dir,
            size,
            loc: Loc::Tar { offset },
        });
    }
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = gz.pull(&mut buf)?;
        if n == 0 {
            break;
        }
        if buf.get(..n).unwrap_or_default().iter().any(|x| *x != 0) {
            return Err(ArchiveError::Trailing);
        }
    }
    if !lim.ratio_ok(gz.produced(), u64::try_from(b.len()).unwrap_or(u64::MAX)) {
        return Err(ArchiveError::TooLarge(
            "the compression ratio of the archive",
        ));
    }
    Ok(out)
}
