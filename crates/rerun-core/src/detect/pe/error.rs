//! Errors of the PE parser (ADR 0013). They never carry file content: no names, no strings, no
//! header values, only a kind and the file offset of the offending structure.

use std::fmt;

/// Format of an executable that is not PE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyFormat {
    /// A plain DOS `MZ` executable (or an `MZ` file whose `e_lfanew` leads nowhere).
    Dos,
    /// A 16-bit Windows (`NE`) executable.
    Ne,
    /// A linear executable (`LE`/`LX`: VxD, OS/2, DOS extenders).
    Le,
}

impl fmt::Display for LegacyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Dos => "DOS",
            Self::Ne => "16-bit Windows (NE)",
            Self::Le => "linear (LE/LX)",
        })
    }
}

/// Kind of a PE error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum PeErrorKind {
    /// Reading failed (only the kind of the I/O error is kept, not its message).
    #[error("read failed ({0})")]
    Io(std::io::ErrorKind),
    /// No `MZ` signature: not an executable.
    #[error("not an executable (no MZ signature)")]
    NotExecutable,
    /// An executable, but not PE.
    #[error("{0} executable, not PE")]
    Legacy(LegacyFormat),
    /// The file ends inside a structure that must be complete.
    #[error("file ends inside a structure")]
    Truncated,
    /// The NT headers or the section table do not lie within the header region.
    #[error("headers outside the header region")]
    HeadersOutOfRange,
    /// The optional header magic is neither PE32 nor PE32+.
    #[error("unknown optional header magic")]
    UnknownOptionalMagic,
    /// `SizeOfOptionalHeader` does not cover the fixed part and the data directories.
    #[error("optional header too small for its fields")]
    BadOptionalHeaderSize,
    /// The machine does not match the optional header format (x86 needs PE32, x64 and ARM64
    /// need PE32+).
    #[error("machine does not match the optional header format")]
    MachineMismatch,
    /// More sections than [`super::Limits::max_sections`].
    #[error("too many sections")]
    TooManySections,
    /// An RVA (or a VC6 delay-load address) that no section and not the headers cover.
    #[error("address in no section")]
    RvaNotMapped,
    /// An RVA past the file-backed part of its section.
    #[error("address beyond the file data of its section")]
    RvaNotBacked,
    /// No terminating descriptor within [`super::Limits::max_import_dlls`] descriptors.
    #[error("too many import descriptors")]
    TooManyImports,
    /// The file-backed data ends before the terminating descriptor.
    #[error("import descriptors not terminated")]
    ImportsNotTerminated,
    /// A DLL name that is empty, too long, unterminated or not printable ASCII.
    #[error("invalid DLL name")]
    BadDllName,
    /// The `RT_VERSION` branch of the resource directory has the wrong shape.
    #[error("malformed resource directory")]
    BadResourceTree,
    /// A resource directory table with more than [`super::Limits::max_resource_entries`]
    /// entries.
    #[error("too many resource directory entries")]
    TooManyResourceEntries,
    /// A malformed `VS_VERSIONINFO` block.
    #[error("malformed version resource block")]
    BadVersionBlock,
    /// A kept version string longer than [`super::Limits::max_version_string`].
    #[error("version string too long")]
    StringTooLong,
    /// More string tables than [`super::Limits::max_string_tables`].
    #[error("too many version string tables")]
    TooManyStringTables,
    /// The total read budget [`super::Limits::max_read_bytes`] is exhausted.
    #[error("read budget exhausted")]
    ReadBudget,
}

/// A PE error: its kind and the file offset of the offending structure, if known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeError {
    /// What went wrong.
    pub kind: PeErrorKind,
    /// File offset of the offending structure (or of the field that leads to it).
    pub offset: Option<u64>,
}

impl PeError {
    /// An error at a file offset.
    pub(super) fn at(kind: PeErrorKind, offset: u64) -> Self {
        Self {
            kind,
            offset: Some(offset),
        }
    }
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(at) => write!(f, "{} at offset {at:#x}", self.kind),
            None => write!(f, "{}", self.kind),
        }
    }
}

impl std::error::Error for PeError {}
