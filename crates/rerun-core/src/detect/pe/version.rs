//! `VS_VERSIONINFO` (ADR 0013, "VS_VERSIONINFO"): a pure parser over the at most
//! [`Limits::max_version_bytes`] read from the version resource.
//!
//! Blocks are `wLength`, `wValueLength`, `wType`, a NUL-terminated UTF-16 key, padding to 4
//! bytes (relative to the root block), the value, then children. An explicit loop over at most
//! four levels (root, `StringFileInfo`/`VarFileInfo`, string table, string), no recursion.
//! Tolerant of old toolchains (Borland, Delphi): `wValueLength` of string blocks is ignored, a
//! string runs to its first NUL or the end of its block, trailing padding may be missing, a
//! broken fixed part is `None`.

use super::Limits;
use super::error::PeErrorKind;
use super::layout as l;
use super::reader::{u16_at, u32_at};
use crate::detect::text::RawText;

/// `VS_FIXEDFILEINFO`, the binary part of the version resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedFileInfo {
    /// `dwFileVersionMS`/`LS` as four parts (major, minor, build, revision).
    pub file_version: [u16; 4],
    /// `dwProductVersionMS`/`LS` as four parts.
    pub product_version: [u16; 4],
    /// `dwFileFlagsMask`.
    pub file_flags_mask: u32,
    /// `dwFileFlags`.
    pub file_flags: u32,
    /// `dwFileOS`.
    pub file_os: u32,
    /// `dwFileType`.
    pub file_type: u32,
    /// `dwFileSubtype`.
    pub file_subtype: u32,
}

/// The language and code page of a string table (its key, 8 hex digits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StringTableId {
    /// Language ID (first four hex digits).
    pub language: u16,
    /// Code page (last four hex digits).
    pub codepage: u16,
}

/// The kept strings of the chosen string table, raw (output layers sanitize them). `Debug`
/// shows only their lengths.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct VersionStrings {
    /// `CompanyName`.
    pub company_name: Option<RawText>,
    /// `FileDescription`.
    pub file_description: Option<RawText>,
    /// `FileVersion`.
    pub file_version: Option<RawText>,
    /// `OriginalFilename`.
    pub original_filename: Option<RawText>,
    /// `ProductName`.
    pub product_name: Option<RawText>,
    /// `ProductVersion`.
    pub product_version: Option<RawText>,
}

/// The version resource.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct VersionInfo {
    /// The fixed part, if it is exactly a `VS_FIXEDFILEINFO` with its signature.
    pub fixed: Option<FixedFileInfo>,
    /// The chosen string table: the one matching the first `Translation` pair, else the first
    /// with language `0x0409`, else the first.
    pub table: Option<StringTableId>,
    /// The kept strings of the chosen table.
    pub strings: VersionStrings,
}

/// Kept keys, in the order of the fields of [`VersionStrings`].
const KEPT: [&str; 6] = [
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "OriginalFilename",
    "ProductName",
    "ProductVersion",
];

/// A block: where it is and where its parts are (byte positions in the data).
#[derive(Debug, Clone, Copy)]
struct Block {
    start: usize,
    /// `start + wLength`, clamped to the parent.
    end: usize,
    value_len: usize,
    /// The key's UTF-16 units, without the NUL.
    key: (usize, usize),
    /// Start of the value: the end of the key, aligned to 4 (at most `end`).
    value: usize,
}

fn align4(v: usize) -> usize {
    v.saturating_add(3) & !3
}

/// The block at `pos` within `[pos, parent_end)`.
fn block(data: &[u8], pos: usize, parent_end: usize) -> Result<Block, (PeErrorKind, usize)> {
    let bad = (PeErrorKind::BadVersionBlock, pos);
    let length = usize::from(u16_at(data, pos).ok_or(bad)?);
    let value_len = usize::from(u16_at(data, pos + 2).ok_or(bad)?);
    if length < 6 {
        return Err(bad);
    }
    let end = pos + length.min(parent_end.saturating_sub(pos));
    let key_start = pos + 6;
    let mut k = key_start;
    loop {
        if k + 2 > end {
            return Err(bad);
        }
        if u16_at(data, k) == Some(0) {
            break;
        }
        k += 2;
    }
    Ok(Block {
        start: pos,
        end,
        value_len,
        key: (key_start, k),
        value: align4(k + 2).min(end),
    })
}

/// The children of a block: blocks from `from` (aligned) to `end`. Trailing bytes too short
/// for a block header are padding.
struct Children {
    pos: usize,
    end: usize,
}

impl Children {
    fn new(from: usize, end: usize) -> Self {
        Self {
            pos: align4(from),
            end,
        }
    }

    fn next(&mut self, data: &[u8]) -> Option<Result<Block, (PeErrorKind, usize)>> {
        if self.pos.saturating_add(6) > self.end {
            return None;
        }
        Some(block(data, self.pos, self.end).inspect(|b| {
            // Every block is at least 6 bytes and the next starts aligned: at least 8 bytes
            // of progress, so the loop ends.
            self.pos = align4(b.end);
        }))
    }
}

/// The key of `b` equals `s`, ASCII case-insensitively.
fn key_is(data: &[u8], b: &Block, s: &str) -> bool {
    let (start, end) = b.key;
    if (end - start) / 2 != s.len() {
        return false;
    }
    s.bytes().enumerate().all(|(i, c)| {
        u16_at(data, start + 2 * i)
            .and_then(|u| u8::try_from(u).ok())
            .is_some_and(|u| u.eq_ignore_ascii_case(&c))
    })
}

/// A string table key: 8 hex digits.
fn table_id(data: &[u8], b: &Block) -> Option<StringTableId> {
    let (start, end) = b.key;
    if end - start != 16 {
        return None;
    }
    let mut v: u32 = 0;
    for i in 0..8 {
        let unit = u16_at(data, start + 2 * i)?;
        let digit = char::from_u32(u32::from(unit))?.to_digit(16)?;
        v = v << 4 | digit;
    }
    Some(StringTableId {
        language: u16::try_from(v >> 16).ok()?,
        codepage: u16::try_from(v & 0xFFFF).ok()?,
    })
}

fn fixed_info(data: &[u8], root: &Block) -> Option<FixedFileInfo> {
    if root.value_len != l::FIXED_FILE_INFO_SIZE || root.value + l::FIXED_FILE_INFO_SIZE > root.end
    {
        return None;
    }
    let f = |at: usize| u32_at(data, root.value + at);
    if f(l::FIXED_SIGNATURE)? != l::FIXED_SIGNATURE_VALUE {
        return None;
    }
    let parts = |ms: u32, ls: u32| {
        let [a, b] = [ms >> 16, ms & 0xFFFF].map(|v| u16::try_from(v).unwrap_or(0));
        let [c, d] = [ls >> 16, ls & 0xFFFF].map(|v| u16::try_from(v).unwrap_or(0));
        [a, b, c, d]
    };
    Some(FixedFileInfo {
        file_version: parts(f(l::FIXED_FILE_VERSION_MS)?, f(l::FIXED_FILE_VERSION_LS)?),
        product_version: parts(
            f(l::FIXED_PRODUCT_VERSION_MS)?,
            f(l::FIXED_PRODUCT_VERSION_LS)?,
        ),
        file_flags_mask: f(l::FIXED_FILE_FLAGS_MASK)?,
        file_flags: f(l::FIXED_FILE_FLAGS)?,
        file_os: f(l::FIXED_FILE_OS)?,
        file_type: f(l::FIXED_FILE_TYPE)?,
        file_subtype: f(l::FIXED_FILE_SUBTYPE)?,
    })
}

/// A string table seen while walking: its ID and where its kept values are (block start,
/// value start, value end).
struct Table {
    id: StringTableId,
    values: [Option<(usize, usize, usize)>; 6],
}

/// Value of a string block: from the aligned end of its key to the first NUL or the end of
/// the block (`wValueLength` is ignored).
fn string_value(data: &[u8], s: &Block) -> (usize, usize) {
    let mut end = s.value;
    while end + 2 <= s.end && u16_at(data, end) != Some(0) {
        end += 2;
    }
    (s.value, end)
}

/// Parses the version resource `data`. Errors carry their position in `data`.
pub(super) fn parse(data: &[u8], limits: &Limits) -> Result<VersionInfo, (PeErrorKind, usize)> {
    let root = block(data, 0, data.len())?;
    if !key_is(data, &root, "VS_VERSION_INFO") {
        return Err((PeErrorKind::BadVersionBlock, 0));
    }
    let fixed = fixed_info(data, &root);
    let mut translation: Option<StringTableId> = None;
    let mut tables: Vec<Table> = Vec::new();
    let mut seen_tables = 0usize;

    let first_child = root.value.saturating_add(root.value_len).min(root.end);
    let mut level2 = Children::new(first_child, root.end);
    while let Some(info) = level2.next(data) {
        let info = info?;
        let string_file_info = key_is(data, &info, "StringFileInfo");
        if !string_file_info && !key_is(data, &info, "VarFileInfo") {
            continue;
        }
        let mut level3 = Children::new(info.value, info.end);
        while let Some(child) = level3.next(data) {
            let child = child?;
            if !string_file_info {
                if translation.is_none()
                    && key_is(data, &child, "Translation")
                    && child.value + 4 <= child.end
                {
                    translation = u16_at(data, child.value)
                        .zip(u16_at(data, child.value + 2))
                        .map(|(language, codepage)| StringTableId { language, codepage });
                }
                continue;
            }
            seen_tables += 1;
            if seen_tables > limits.max_string_tables {
                return Err((PeErrorKind::TooManyStringTables, child.start));
            }
            let Some(id) = table_id(data, &child) else {
                continue;
            };
            let mut table = Table {
                id,
                values: [None; 6],
            };
            let mut level4 = Children::new(child.value, child.end);
            while let Some(s) = level4.next(data) {
                let s = s?;
                let Some(i) = KEPT.iter().position(|k| key_is(data, &s, k)) else {
                    continue;
                };
                if let Some(slot) = table.values.get_mut(i).filter(|v| v.is_none()) {
                    let (from, to) = string_value(data, &s);
                    *slot = Some((s.start, from, to));
                }
            }
            tables.push(table);
        }
    }

    let chosen = translation
        .and_then(|t| tables.iter().find(|x| x.id == t))
        .or_else(|| tables.iter().find(|x| x.id.language == l::LANG_EN_US))
        .or_else(|| tables.first());
    let mut strings = VersionStrings::default();
    if let Some(t) = chosen {
        let slots = [
            &mut strings.company_name,
            &mut strings.file_description,
            &mut strings.file_version,
            &mut strings.original_filename,
            &mut strings.product_name,
            &mut strings.product_version,
        ];
        for (slot, value) in slots.into_iter().zip(t.values) {
            let Some((at, from, to)) = value else {
                continue;
            };
            let units = (to - from) / 2;
            if units > limits.max_version_string {
                return Err((PeErrorKind::StringTooLong, at));
            }
            let text: String =
                char::decode_utf16((0..units).filter_map(|i| u16_at(data, from + 2 * i)))
                    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect();
            *slot = Some(RawText::new(text));
        }
    }
    Ok(VersionInfo {
        fixed,
        table: chosen.map(|t| t.id),
        strings,
    })
}

#[cfg(test)]
mod tests;
