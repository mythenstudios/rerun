//! DOS and NT headers, data directories, section table and RVA mapping (ADR 0013, "What is
//! parsed"). Everything here works on the header region, read once.

use super::error::{LegacyFormat, PeError, PeErrorKind};
use super::layout as l;
use super::reader::{off, u16_at, u32_at, u64_at};
use super::{Headers, Limits, Machine, PeFormat};

/// One data directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DataDir {
    /// `VirtualAddress`.
    pub rva: u32,
    /// `Size`.
    pub size: u32,
    /// File offset of the entry in the optional header (for error offsets).
    pub entry: u64,
}

/// One section, reduced to what the mapping and the section names need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Section {
    /// `Name`, the 8 bytes as stored.
    name: [u8; l::SECTION_NAME_SIZE],
    va: u64,
    /// `VirtualSize`, or `SizeOfRawData` when `VirtualSize` is 0.
    extent: u64,
    raw_ptr: u64,
    /// File-backed part: `min(extent, SizeOfRawData)`.
    backed: u64,
}

/// Where an RVA lies in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Mapped {
    /// File offset.
    pub offset: u64,
    /// File-backed bytes from `offset` to the end of the section's file data (or the headers).
    pub available: u64,
}

impl Mapped {
    /// `len` clamped to the file-backed bytes.
    pub(super) fn clamp(&self, len: usize) -> usize {
        usize::try_from(self.available).map_or(len, |a| a.min(len))
    }
}

/// The parsed header region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Layout {
    pub headers: Headers,
    /// The first `min(NumberOfRvaAndSizes, 16)` data directories.
    pub dirs: Vec<DataDir>,
    sections: Vec<Section>,
    /// File offset of the COFF file header.
    pub coff: u64,
    /// File offset of the optional header.
    pub opt: u64,
    /// `CheckSum` of the optional header.
    pub checksum: u32,
    /// [`VLV_SIGNATURE`] at [`VLV_AT`], in the DOS stub (before the NT headers).
    pub vlv: bool,
}

/// Where a Valve header starts: right after the 64-byte DOS header, in the DOS stub (P4-13).
pub(super) const VLV_AT: usize = l::DOS_HEADER_SIZE;
/// Its signature (P4-13): `"VLV"` and a NUL.
pub(super) const VLV_SIGNATURE: &[u8; 4] = b"VLV\0";

/// Outcome of `need`: the header buffer does not reach `end`.
fn short(eof: bool, at: usize) -> PeError {
    let kind = if eof {
        PeErrorKind::Truncated
    } else {
        PeErrorKind::HeadersOutOfRange
    };
    PeError::at(kind, off(at))
}

/// Parses the header region `buf`; `eof` is true when the file ended within the region (so a
/// structure past `buf` is truncated rather than out of range).
pub(super) fn parse(buf: &[u8], eof: bool, limits: &Limits) -> Result<Layout, PeError> {
    if buf.get(..2) != Some(l::DOS_SIGNATURE.as_slice()) {
        return Err(PeError::at(PeErrorKind::NotExecutable, 0));
    }
    let dos = || PeError::at(PeErrorKind::Legacy(LegacyFormat::Dos), off(l::DOS_E_LFANEW));
    let e = u32_at(buf, l::DOS_E_LFANEW)
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(dos)?;
    match buf.get(e..e.saturating_add(4)) {
        Some(sig) if sig == l::NT_SIGNATURE => {}
        _ => {
            return Err(match buf.get(e..e.saturating_add(2)) {
                Some(s) if s == l::NE_SIGNATURE => {
                    PeError::at(PeErrorKind::Legacy(LegacyFormat::Ne), off(e))
                }
                Some(s) if s == l::LE_SIGNATURE || s == l::LX_SIGNATURE => {
                    PeError::at(PeErrorKind::Legacy(LegacyFormat::Le), off(e))
                }
                _ => dos(),
            });
        }
    }

    // P4-13: a Valve header in the DOS stub, only where the stub reaches past it (the NT
    // headers start at `e`); the slice is bounded by `buf`, a short file has none.
    let vlv = VLV_AT
        .checked_add(VLV_SIGNATURE.len())
        .is_some_and(|end| end <= e && buf.get(VLV_AT..end) == Some(VLV_SIGNATURE.as_slice()));

    let coff = e + 4;
    let need = |end: usize, at: usize| {
        if end <= buf.len() {
            Ok(())
        } else {
            Err(short(eof, at))
        }
    };
    need(coff + l::FILE_HEADER_SIZE, coff)?;
    let field16 = |at: usize| u16_at(buf, at).ok_or_else(|| short(eof, at));
    let field32 = |at: usize| u32_at(buf, at).ok_or_else(|| short(eof, at));
    let machine_raw = field16(coff + l::FILE_MACHINE)?;
    let section_count = field16(coff + l::FILE_NUMBER_OF_SECTIONS)?;
    let opt_size = usize::from(field16(coff + l::FILE_SIZE_OF_OPTIONAL_HEADER)?);
    let characteristics = field16(coff + l::FILE_CHARACTERISTICS)?;
    if usize::from(section_count) > limits.max_sections {
        return Err(PeError::at(
            PeErrorKind::TooManySections,
            off(coff + l::FILE_NUMBER_OF_SECTIONS),
        ));
    }

    let opt = coff + l::FILE_HEADER_SIZE;
    let bad_size = || {
        PeError::at(
            PeErrorKind::BadOptionalHeaderSize,
            off(coff + l::FILE_SIZE_OF_OPTIONAL_HEADER),
        )
    };
    if opt_size < 2 {
        return Err(bad_size());
    }
    need(opt + 2, opt)?;
    let (format, fixed, count_at) = match field16(opt + l::OPT_MAGIC)? {
        l::OPTIONAL_MAGIC_PE32 => (
            PeFormat::Pe32,
            l::OPT32_DATA_DIRECTORY,
            l::OPT32_NUMBER_OF_RVA_AND_SIZES,
        ),
        l::OPTIONAL_MAGIC_PE32_PLUS => (
            PeFormat::Pe32Plus,
            l::OPT64_DATA_DIRECTORY,
            l::OPT64_NUMBER_OF_RVA_AND_SIZES,
        ),
        _ => return Err(PeError::at(PeErrorKind::UnknownOptionalMagic, off(opt))),
    };
    if opt_size < fixed {
        return Err(bad_size());
    }
    need(opt + opt_size, opt)?;
    let dir_count = usize::try_from(field32(opt + count_at)?)
        .unwrap_or(usize::MAX)
        .min(l::NUMBER_OF_DIRECTORY_ENTRIES);
    if fixed + dir_count * l::DATA_DIRECTORY_SIZE > opt_size {
        return Err(bad_size());
    }

    let machine = match machine_raw {
        l::MACHINE_I386 => Machine::X86,
        l::MACHINE_AMD64 => Machine::X64,
        l::MACHINE_ARM64 => Machine::Arm64,
        other => Machine::Other(other),
    };
    let expected = match machine {
        Machine::X86 => Some(PeFormat::Pe32),
        Machine::X64 | Machine::Arm64 => Some(PeFormat::Pe32Plus),
        Machine::Other(_) => None,
    };
    if expected.is_some_and(|f| f != format) {
        return Err(PeError::at(
            PeErrorKind::MachineMismatch,
            off(coff + l::FILE_MACHINE),
        ));
    }

    let image_base = match format {
        PeFormat::Pe32 => u64::from(field32(opt + l::OPT32_IMAGE_BASE)?),
        PeFormat::Pe32Plus => u64_at(buf, opt + l::OPT64_IMAGE_BASE)
            .ok_or_else(|| short(eof, opt + l::OPT64_IMAGE_BASE))?,
    };
    let size_of_headers = field32(opt + l::OPT_SIZE_OF_HEADERS)?;
    let subsystem = field16(opt + l::OPT_SUBSYSTEM)?;
    let checksum = field32(opt + l::OPT_CHECKSUM)?;
    let dll_characteristics = field16(opt + l::OPT_DLL_CHARACTERISTICS)?;
    let dirs = (0..dir_count)
        .map(|i| {
            let at = opt + fixed + i * l::DATA_DIRECTORY_SIZE;
            Ok(DataDir {
                rva: field32(at)?,
                size: field32(at + 4)?,
                entry: off(at),
            })
        })
        .collect::<Result<Vec<_>, PeError>>()?;

    let table = opt + opt_size;
    let count = usize::from(section_count);
    need(table + count * l::SECTION_HEADER_SIZE, table)?;
    let sections = (0..count)
        .map(|i| {
            let s = table + i * l::SECTION_HEADER_SIZE;
            let virtual_size = u64::from(field32(s + l::SECTION_VIRTUAL_SIZE)?);
            let raw_size = u64::from(field32(s + l::SECTION_SIZE_OF_RAW_DATA)?);
            let extent = if virtual_size == 0 {
                raw_size
            } else {
                virtual_size
            };
            let mut name = [0u8; l::SECTION_NAME_SIZE];
            name.copy_from_slice(
                buf.get(s + l::SECTION_NAME..s + l::SECTION_NAME + l::SECTION_NAME_SIZE)
                    .ok_or_else(|| short(eof, s))?,
            );
            Ok(Section {
                name,
                va: u64::from(field32(s + l::SECTION_VIRTUAL_ADDRESS)?),
                extent,
                raw_ptr: u64::from(field32(s + l::SECTION_POINTER_TO_RAW_DATA)?),
                backed: extent.min(raw_size),
            })
        })
        .collect::<Result<Vec<_>, PeError>>()?;

    let managed = dirs
        .get(l::DIR_COM_DESCRIPTOR)
        .is_some_and(|d| d.rva != 0 && d.size != 0);
    Ok(Layout {
        headers: Headers {
            machine,
            format,
            characteristics,
            subsystem,
            dll_characteristics,
            image_base,
            size_of_headers,
            section_count,
            managed,
        },
        dirs,
        sections,
        coff: off(coff),
        opt: off(opt),
        checksum,
        vlv,
    })
}

impl Layout {
    /// The names of the sections in table order.
    pub(super) fn section_names(&self) -> Vec<[u8; l::SECTION_NAME_SIZE]> {
        self.sections.iter().map(|s| s.name).collect()
    }

    /// The data directory `index` if it is present (`VirtualAddress` not 0).
    pub(super) fn dir(&self, index: usize) -> Option<DataDir> {
        self.dirs.get(index).copied().filter(|d| d.rva != 0)
    }

    /// Maps an RVA to the file: the first section in table order that covers it, else the
    /// headers below `SizeOfHeaders`.
    pub(super) fn map(&self, rva: u32) -> Result<Mapped, PeErrorKind> {
        let rva = u64::from(rva);
        for s in &self.sections {
            let Some(delta) = rva.checked_sub(s.va).filter(|&d| d < s.extent) else {
                continue;
            };
            if delta >= s.backed {
                return Err(PeErrorKind::RvaNotBacked);
            }
            return Ok(Mapped {
                offset: s.raw_ptr + delta,
                available: s.backed - delta,
            });
        }
        let headers = u64::from(self.headers.size_of_headers);
        if rva < headers {
            return Ok(Mapped {
                offset: rva,
                available: headers - rva,
            });
        }
        Err(PeErrorKind::RvaNotMapped)
    }
}
