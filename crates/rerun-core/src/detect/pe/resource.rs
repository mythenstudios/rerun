//! The `RT_VERSION` branch of the resource directory (ADR 0013, "Version resource"): fixed
//! depth, no tree walk.
//!
//! Root table: the ID entry `RT_VERSION` (16). Its table: the ID entry `1`, else the lowest ID.
//! That table: the language `0x0000`, else `0x0409`, else the lowest ID. Levels 1 and 2 must be
//! directories, level 3 a data entry. Named entries are skipped. Table offsets are relative to
//! the resource directory RVA; the data entry's `OffsetToData` is an RVA. Each table read is
//! `16 + 8 × entries` bytes with at most `max_resource_entries` entries.

use std::io::{Read, Seek};

use super::Pe;
use super::error::{PeError, PeErrorKind};
use super::layout as l;
use super::reader::{off, u16_at, u32_at};
use super::version::{self, VersionInfo};

/// An ID entry of a resource directory table.
#[derive(Debug, Clone, Copy)]
struct Entry {
    id: u16,
    /// `OffsetToData`, raw (high bit: subdirectory).
    target: u32,
    /// File offset of the entry.
    at: u64,
}

impl Entry {
    /// The subdirectory offset, or `BadResourceTree` for a data entry.
    fn directory(self) -> Result<u32, PeError> {
        if self.target & l::RESOURCE_DATA_IS_DIRECTORY == 0 {
            return Err(PeError::at(PeErrorKind::BadResourceTree, self.at));
        }
        Ok(self.target & !l::RESOURCE_DATA_IS_DIRECTORY)
    }

    /// The data entry offset, or `BadResourceTree` for a subdirectory.
    fn data(self) -> Result<u32, PeError> {
        if self.target & l::RESOURCE_DATA_IS_DIRECTORY != 0 {
            return Err(PeError::at(PeErrorKind::BadResourceTree, self.at));
        }
        Ok(self.target)
    }
}

/// The first entry with `id`, else the lowest ID (first of equal ones).
fn pick(entries: &[Entry], preferred: &[u16]) -> Option<Entry> {
    preferred
        .iter()
        .find_map(|p| entries.iter().find(|e| e.id == *p))
        .or_else(|| entries.iter().min_by_key(|e| e.id))
        .copied()
}

impl<R: Read + Seek> Pe<R> {
    /// The version resource; `Ok(None)` without a resource directory, without `RT_VERSION` or
    /// without a matching entry.
    pub fn version_info(&mut self) -> Result<Option<VersionInfo>, PeError> {
        let Some(dir) = self.layout.dir(l::DIR_RESOURCE) else {
            return Ok(None);
        };
        let base = dir.rva;
        let root = self.table(base, 0, dir.entry)?;
        let Some(types) = root.iter().find(|e| e.id == l::RT_VERSION).copied() else {
            return Ok(None);
        };
        let names = self.table(base, types.directory()?, types.at)?;
        let Some(name) = pick(&names, &[l::VS_VERSION_INFO]) else {
            return Ok(None);
        };
        let langs = self.table(base, name.directory()?, name.at)?;
        let Some(lang) = pick(&langs, &[l::LANG_NEUTRAL, l::LANG_EN_US]) else {
            return Ok(None);
        };
        let entry_rva = Self::below(base, lang.data()?, lang.at)?;
        let entry = self.read_rva_exact(entry_rva, l::RESOURCE_DATA_ENTRY_SIZE, lang.at)?;
        let entry_at = entry.1;
        let field = |at| u32_at(&entry.0, at).ok_or(PeError::at(PeErrorKind::Truncated, entry_at));
        let data_rva = field(l::RESOURCE_DATA_OFFSET_TO_DATA)?;
        let size = usize::try_from(field(l::RESOURCE_DATA_SIZE)?).unwrap_or(usize::MAX);
        let m = self
            .layout
            .map(data_rva)
            .map_err(|k| PeError::at(k, entry_at))?;
        // Tolerant: a size beyond the backed data or the file is clamped; the parser clamps
        // every block to what is there.
        let len = m.clamp(size.min(self.limits.max_version_bytes));
        let data = self.source.read_at(m.offset, len)?;
        version::parse(&data, &self.limits)
            .map(Some)
            .map_err(|(kind, pos)| PeError::at(kind, m.offset + off(pos)))
    }

    /// `base + offset` as an RVA; an overflow is `RvaNotMapped` at `at`.
    fn below(base: u32, offset: u32, at: u64) -> Result<u32, PeError> {
        base.checked_add(offset)
            .ok_or(PeError::at(PeErrorKind::RvaNotMapped, at))
    }

    /// Exactly `len` bytes at `rva` (mapping errors at `at`); bytes past the backed data or
    /// the file are `Truncated`. Returns the bytes and their file offset.
    fn read_rva_exact(&mut self, rva: u32, len: usize, at: u64) -> Result<(Vec<u8>, u64), PeError> {
        let m = self.layout.map(rva).map_err(|k| PeError::at(k, at))?;
        let truncated = PeError::at(PeErrorKind::Truncated, m.offset);
        if m.clamp(len) < len {
            return Err(truncated);
        }
        let buf = self.source.read_at(m.offset, len)?;
        if buf.len() < len {
            return Err(truncated);
        }
        Ok((buf, m.offset))
    }

    /// The ID entries of the table at `offset` below the resource directory; `at` is the
    /// field that leads to it.
    fn table(&mut self, base: u32, offset: u32, at: u64) -> Result<Vec<Entry>, PeError> {
        let rva = Self::below(base, offset, at)?;
        let (header, table_at) = self.read_rva_exact(rva, l::RESOURCE_DIRECTORY_SIZE, at)?;
        let count = |field| {
            u16_at(&header, field)
                .map(usize::from)
                .ok_or(PeError::at(PeErrorKind::Truncated, table_at))
        };
        let total =
            count(l::RESOURCE_NUMBER_OF_NAMED_ENTRIES)? + count(l::RESOURCE_NUMBER_OF_ID_ENTRIES)?;
        if total > self.limits.max_resource_entries {
            return Err(PeError::at(PeErrorKind::TooManyResourceEntries, table_at));
        }
        if total == 0 {
            return Ok(Vec::new());
        }
        let header_len = u32::try_from(l::RESOURCE_DIRECTORY_SIZE).unwrap_or(u32::MAX);
        let entries_rva = Self::below(rva, header_len, at)?;
        let (raw, entries_at) =
            self.read_rva_exact(entries_rva, total * l::RESOURCE_ENTRY_SIZE, at)?;
        Ok(raw
            .as_chunks::<{ l::RESOURCE_ENTRY_SIZE }>()
            .0
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                let e = e.as_slice();
                let name = u32_at(e, l::RESOURCE_ENTRY_NAME)?;
                if name & l::RESOURCE_NAME_IS_STRING != 0 {
                    return None;
                }
                Some(Entry {
                    id: u16::try_from(name).ok()?,
                    target: u32_at(e, l::RESOURCE_ENTRY_OFFSET_TO_DATA)?,
                    at: entries_at + off(i * l::RESOURCE_ENTRY_SIZE),
                })
            })
            .collect())
    }
}
