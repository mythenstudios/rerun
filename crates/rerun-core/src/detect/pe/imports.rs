//! Import and delay-import DLL names, `DependentLoadFlags` (ADR 0013, "Imports", "DLL names",
//! "Load config").
//!
//! Descriptors are read in one range of at most `(max_import_dlls + 1) × stride` bytes, clamped
//! to the file-backed part of their section, and walked in table order until an all-zero
//! descriptor. Each name is one read of at most `max_name_bytes + 1` bytes, clamped the same
//! way. No thunks, no function names, no ordinals, no bound imports.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek};

use super::error::{PeError, PeErrorKind};
use super::layout as l;
use super::reader::{off, u16_at, u32_at};
use super::{Pe, PeFormat};

/// An imported DLL name: 1 to 255 bytes of printable ASCII (`0x20` to `0x7E`). Keeps its
/// spelling; compares and hashes ASCII case-insensitively. Safe to print: no control, bidi or
/// non-ASCII character can pass.
#[derive(Clone)]
pub struct DllName(String);

impl DllName {
    /// Checks raw name bytes (without the NUL).
    fn new(bytes: &[u8], max: usize) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > max || !bytes.iter().all(|b| (0x20..=0x7E).contains(b))
        {
            return None;
        }
        // Printable ASCII is UTF-8.
        std::str::from_utf8(bytes).ok().map(|s| Self(s.to_owned()))
    }

    /// A name for the tests of other modules (`detect::exe`), checked by the same rules.
    #[cfg(test)]
    pub(crate) fn for_test(name: &str) -> Self {
        Self::new(name.as_bytes(), 255).unwrap_or_else(|| panic!("invalid DLL name {name:?}"))
    }

    /// The name as spelled in the file.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// ASCII case-insensitive comparison with `other`.
    pub fn eq_ignore_ascii_case(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

impl PartialEq for DllName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for DllName {}

impl Hash for DllName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.0.bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
        state.write_u8(0);
    }
}

impl fmt::Display for DllName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DllName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DllName({:?})", self.0)
    }
}

/// The two descriptor tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Table {
    Import,
    Delay,
}

impl Table {
    fn dir(self) -> usize {
        match self {
            Self::Import => l::DIR_IMPORT,
            Self::Delay => l::DIR_DELAY_IMPORT,
        }
    }

    fn stride(self) -> usize {
        match self {
            Self::Import => l::IMPORT_DESCRIPTOR_SIZE,
            Self::Delay => l::DELAYLOAD_DESCRIPTOR_SIZE,
        }
    }

    fn name_at(self) -> usize {
        match self {
            Self::Import => l::IMPORT_NAME,
            Self::Delay => l::DELAYLOAD_DLL_NAME_RVA,
        }
    }
}

impl<R: Read + Seek> Pe<R> {
    /// DLL names of the import directory, in table order. No directory: empty.
    pub fn imports(&mut self) -> Result<Vec<DllName>, PeError> {
        self.names(Table::Import)
    }

    /// DLL names of the delay-import directory, in table order. No directory: empty.
    /// VC6-style descriptors (`Attributes` bit 0 clear) hold virtual addresses; `ImageBase`
    /// is subtracted.
    pub fn delay_imports(&mut self) -> Result<Vec<DllName>, PeError> {
        self.names(Table::Delay)
    }

    /// `DependentLoadFlags` of the load config directory (offset `0x4E` in PE32+, `0x36` in
    /// PE32); `None` without a load config or if its `Size` field does not reach the field.
    pub fn dependent_load_flags(&mut self) -> Result<Option<u16>, PeError> {
        let Some(dir) = self.layout.dir(l::DIR_LOAD_CONFIG) else {
            return Ok(None);
        };
        let field = match self.layout.headers.format {
            PeFormat::Pe32 => l::LOAD_CONFIG32_DEPENDENT_LOAD_FLAGS,
            PeFormat::Pe32Plus => l::LOAD_CONFIG64_DEPENDENT_LOAD_FLAGS,
        };
        let m = self
            .layout
            .map(dir.rva)
            .map_err(|k| PeError::at(k, dir.entry))?;
        let want = field + 2;
        let buf = self.source.read_at(m.offset, m.clamp(want))?;
        let truncated = PeError::at(PeErrorKind::Truncated, m.offset);
        let size = u32_at(&buf, l::LOAD_CONFIG_SIZE).ok_or(truncated)?;
        if usize::try_from(size).unwrap_or(usize::MAX) < want {
            return Ok(None);
        }
        u16_at(&buf, field).map(Some).ok_or(truncated)
    }

    fn names(&mut self, table: Table) -> Result<Vec<DllName>, PeError> {
        let Some(dir) = self.layout.dir(table.dir()) else {
            return Ok(Vec::new());
        };
        let m = self
            .layout
            .map(dir.rva)
            .map_err(|k| PeError::at(k, dir.entry))?;
        let max = self.limits.max_import_dlls;
        let stride = table.stride();
        let cap = max.saturating_add(1).saturating_mul(stride);
        let len = m.clamp(cap);
        let descriptors = self.source.read_at(m.offset, len)?;
        let mut names = Vec::new();
        for (i, d) in descriptors.chunks_exact(stride).enumerate() {
            let at = m.offset + off(i * stride);
            if d.iter().all(|&b| b == 0) {
                return Ok(names);
            }
            if i >= max {
                return Err(PeError::at(PeErrorKind::TooManyImports, m.offset));
            }
            let raw = u32_at(d, table.name_at()).ok_or(PeError::at(PeErrorKind::Truncated, at))?;
            let rva = match table {
                Table::Delay
                    if u32_at(d, l::DELAYLOAD_ATTRIBUTES)
                        .is_some_and(|a| a & l::DELAYLOAD_RVA_BASED == 0) =>
                {
                    u64::from(raw)
                        .checked_sub(self.layout.headers.image_base)
                        .and_then(|r| u32::try_from(r).ok())
                        .ok_or(PeError::at(PeErrorKind::RvaNotMapped, at))?
                }
                _ => raw,
            };
            names.push(self.name(rva, at)?);
        }
        let kind = if descriptors.len() < len {
            PeErrorKind::Truncated
        } else if len < cap {
            PeErrorKind::ImportsNotTerminated
        } else {
            PeErrorKind::TooManyImports
        };
        Err(PeError::at(kind, m.offset))
    }

    /// The NUL-terminated DLL name at `rva`; `at` is the descriptor holding it.
    fn name(&mut self, rva: u32, at: u64) -> Result<DllName, PeError> {
        let m = self.layout.map(rva).map_err(|k| PeError::at(k, at))?;
        let max = self.limits.max_name_bytes;
        let buf = self
            .source
            .read_at(m.offset, m.clamp(max.saturating_add(1)))?;
        buf.iter()
            .position(|&b| b == 0)
            .and_then(|end| DllName::new(buf.get(..end)?, max))
            .ok_or(PeError::at(PeErrorKind::BadDllName, m.offset))
    }
}

#[cfg(test)]
mod tests;
