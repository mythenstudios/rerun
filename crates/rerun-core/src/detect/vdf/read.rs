//! The only reader for VDF files on disk (ADR 0011).
//!
//! [`read_store_file`] reads the file relative to an open [`StoreDir`] handle (ADR 0007: never
//! by absolute path, never through a reparse point below the store) with
//! [`Dir::read_limited`] and `max_bytes` as the bound: a longer file is refused with
//! `TooLarge` before the parser sees a byte, never truncated. The file length from metadata
//! is never asked for: a file can grow between a size check and the read, and a device or a
//! filter can report any length. The unbounded [`Dir::read`] is never used.

use super::{Document, Limits, LineCol, VdfError, parse};
use crate::path::RelPath;
use crate::policy::root::StoreDir;
use crate::sys::{Dir, SysError};

/// Error while reading a VDF file from a store. Names the file, never its content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VdfReadError {
    /// Reading failed: missing (`NotFound`), a directory or restricted (`AccessDenied`), a
    /// reparse point on the way (`ReparsePoint`), an I/O error (its code kept, its message
    /// not), or longer than `max_bytes` (`TooLarge`).
    #[error("{file}: {source}")]
    Read {
        /// The file, relative to the store.
        file: RelPath,
        /// Error of the system layer.
        source: SysError,
    },
    /// The content was refused by the parser.
    #[error("{file}: {error} ({at})")]
    Parse {
        /// The file, relative to the store.
        file: RelPath,
        /// The parse error.
        error: VdfError,
        /// Line and column of the error.
        at: LineCol,
    },
}

/// Reads and parses `file` (relative to the store root) within `limits`.
pub fn read_store_file(
    store: &StoreDir<'_>,
    file: &RelPath,
    limits: &Limits,
) -> Result<Document, VdfReadError> {
    read_bounded(store.dir(), file, limits)
}

/// [`read_store_file`] on a bare handle; separate so the bound can be tested with a reader
/// that never ends.
fn read_bounded(dir: &dyn Dir, file: &RelPath, limits: &Limits) -> Result<Document, VdfReadError> {
    let max = u64::try_from(limits.max_bytes).unwrap_or(u64::MAX);
    let buf = dir
        .read_limited(file, max)
        .map_err(|source| VdfReadError::Read {
            file: file.clone(),
            source,
        })?;
    parse(&buf, limits).map_err(|error| VdfReadError::Parse {
        file: file.clone(),
        at: error.line_col(&buf),
        error,
    })
}

#[cfg(test)]
mod tests;
