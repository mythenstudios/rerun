//! Bounded PE parser for executables in game folders (ADR 0013).
//!
//! Executables in game folders are untrusted: any process of the user can replace or plant
//! them. [`Pe::parse`] reads the header region once (at most [`Limits::max_header_bytes`]);
//! everything else is read on demand, by range. Every read is one `seek` plus one read into a
//! buffer whose size comes from a limit, never from a header field alone, and every read is
//! charged to a total budget ([`Limits::max_read_bytes`]) before it happens. No memory
//! mapping, no whole-file read, no recursion, no `unsafe`, no system call: the parser works on
//! any `Read + Seek` (tests use `std::io::Cursor`).
//!
//! - DOS, NE and LE/LX executables are recognised ([`PeErrorKind::Legacy`]).
//! - [`Headers`]: machine, PE32/PE32+, characteristics (Large Address Aware, DLL),
//!   subsystem, DLL characteristics, image base, CLR header present.
//! - [`Pe::imports`], [`Pe::delay_imports`]: the imported DLL names ([`DllName`]), in table
//!   order; no function names, ordinals, exports or forwarders (phase 6 may add them).
//! - [`Pe::dependent_load_flags`]: `DependentLoadFlags` of the load config.
//! - [`Pe::version_info`]: the version resource ([`VersionInfo`]: the fixed part and six
//!   strings of one string table, as [`RawText`](crate::detect::text::RawText)), tolerant of
//!   the quirks of old toolchains.
//! - [`Pe::info`]: all of it at once ([`PeInfo`]); a broken version resource does not hide
//!   the headers and imports, a broken import table fails the file.
//! - Errors ([`PeError`]) carry a kind and a file offset, never file content.
//! - [`open_game_exe`]: the only reader for product code, relative to a
//!   [`GameDir`](crate::policy::root::GameDir) handle (ADR 0007); [`PeReadError`] adds the file.
//!
//! Facts read here are hints for display, matching and suggestions, never authorization
//! (ADR 0013, Consequences).

mod error;
mod headers;
mod imports;
pub mod layout;
mod open;
mod reader;
mod resource;
mod version;

#[cfg(test)]
pub(crate) mod testfx;
#[cfg(test)]
mod tests;

use std::io::{Read, Seek};

pub use error::{LegacyFormat, PeError, PeErrorKind};
pub use imports::DllName;
pub use open::{GameExe, PeReadError, open_game_exe};
pub use version::{FixedFileInfo, StringTableId, VersionInfo, VersionStrings};

use headers::Layout;
use reader::Source;

/// Bounds for one [`Pe`]. A value of exactly the limit is accepted, one more is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    /// The header region: DOS header, NT headers and section table must lie in these first
    /// bytes of the file.
    pub max_header_bytes: usize,
    /// Sections in the section table.
    pub max_sections: usize,
    /// DLLs per import table (static and delay-load each).
    pub max_import_dlls: usize,
    /// Bytes of a DLL name, without its NUL.
    pub max_name_bytes: usize,
    /// Entries of one resource directory table.
    pub max_resource_entries: usize,
    /// Bytes of the version resource that are read.
    pub max_version_bytes: usize,
    /// UTF-16 units of a kept version string.
    pub max_version_string: usize,
    /// String tables in the version resource.
    pub max_string_tables: usize,
    /// Total bytes read per [`Pe`], every read counted with its requested length.
    pub max_read_bytes: u64,
}

impl Limits {
    /// The shipped limits (ADR 0013, "Limits").
    pub const DEFAULT: Self = Self {
        max_header_bytes: 64 << 10,
        max_sections: 96,
        max_import_dlls: 1024,
        max_name_bytes: 255,
        max_resource_entries: 1024,
        max_version_bytes: 64 << 10,
        max_version_string: 1024,
        max_string_tables: 64,
        max_read_bytes: 1 << 20,
    };
}

/// The machine of an image (`IMAGE_FILE_HEADER::Machine`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Machine {
    /// `IMAGE_FILE_MACHINE_I386`, always PE32.
    X86,
    /// `IMAGE_FILE_MACHINE_AMD64`, always PE32+ (ARM64EC images report this too).
    X64,
    /// `IMAGE_FILE_MACHINE_ARM64`, always PE32+ (ARM64X images report this too).
    Arm64,
    /// Any other machine, raw.
    Other(u16),
}

/// The optional header format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeFormat {
    /// PE32 (magic `0x10B`).
    Pe32,
    /// PE32+ (magic `0x20B`).
    Pe32Plus,
}

/// Facts from the headers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Headers {
    /// Machine.
    pub machine: Machine,
    /// PE32 or PE32+.
    pub format: PeFormat,
    /// `IMAGE_FILE_HEADER::Characteristics`, raw.
    pub characteristics: u16,
    /// `Subsystem`, raw (see [`layout::SUBSYSTEM_WINDOWS_GUI`] and its neighbours).
    pub subsystem: u16,
    /// `DllCharacteristics`, raw.
    pub dll_characteristics: u16,
    /// `ImageBase`.
    pub image_base: u64,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
    /// `NumberOfSections`.
    pub section_count: u16,
    /// The CLR runtime header directory is present (a .NET image); the header is not read.
    pub managed: bool,
}

impl Headers {
    /// `IMAGE_FILE_LARGE_ADDRESS_AWARE`, reported for every machine (it matters for x86 only;
    /// that is decided above `detect::pe`).
    pub fn large_address_aware(&self) -> bool {
        self.characteristics & layout::FILE_LARGE_ADDRESS_AWARE != 0
    }

    /// `IMAGE_FILE_DLL`.
    pub fn is_dll(&self) -> bool {
        self.characteristics & layout::FILE_DLL != 0
    }
}

/// Everything [`Pe::info`] reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInfo {
    /// Facts from the headers.
    pub headers: Headers,
    /// DLL names of the import directory.
    pub imports: Vec<DllName>,
    /// DLL names of the delay-import directory.
    pub delay_imports: Vec<DllName>,
    /// The version resource, or why it is malformed: a malformed version resource does not
    /// hide the rest (user decision 3, ADR 0013). Only format errors land here; an I/O error
    /// or the exhausted read budget fails [`Pe::info`] as a whole.
    pub version: Result<Option<VersionInfo>, PeError>,
}

/// A parsed executable over its reader. Further facts are read on demand within the same
/// budget.
///
/// To keep the reader after a failed parse, pass `&mut reader` (`Read` and `Seek` are
/// implemented for `&mut R`).
#[derive(Debug)]
pub struct Pe<R> {
    source: Source<R>,
    limits: Limits,
    layout: Layout,
}

impl<R: Read + Seek> Pe<R> {
    /// Reads the header region (at most [`Limits::max_header_bytes`], shorter only at the end
    /// of the file) and parses the DOS header, the NT headers, the data directories and the
    /// section table.
    pub fn parse(reader: R, limits: &Limits) -> Result<Self, PeError> {
        let mut source = Source::new(reader, limits.max_read_bytes);
        let region = source.read_at(0, limits.max_header_bytes)?;
        let eof = region.len() < limits.max_header_bytes;
        let layout = headers::parse(&region, eof, limits)?;
        Ok(Self {
            source,
            limits: *limits,
            layout,
        })
    }

    /// Facts from the headers.
    pub fn headers(&self) -> &Headers {
        &self.layout.headers
    }

    /// Bytes charged to the budget so far.
    pub fn bytes_read(&self) -> u64 {
        self.source.used()
    }

    /// Headers, imports, delay imports and the version resource. A malformed import table
    /// fails the whole call (the loader would refuse such an image); a malformed version
    /// resource is kept as [`PeInfo::version`]. Reading errors ([`PeErrorKind::Io`],
    /// [`PeErrorKind::ReadBudget`]) are no property of the file and fail the call, also in the
    /// version part.
    pub fn info(&mut self) -> Result<PeInfo, PeError> {
        let imports = self.imports()?;
        let delay_imports = self.delay_imports()?;
        let version = match self.version_info() {
            Err(e) if matches!(e.kind, PeErrorKind::Io(_) | PeErrorKind::ReadBudget) => {
                return Err(e);
            }
            other => other,
        };
        Ok(PeInfo {
            headers: self.layout.headers.clone(),
            imports,
            delay_imports,
            version,
        })
    }

    /// Hands the reader back (e.g. to hash the very handle that was parsed).
    pub fn into_inner(self) -> R {
        self.source.into_inner()
    }
}
