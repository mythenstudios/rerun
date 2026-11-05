//! The only reader for VDF files on disk (ADR 0011).
//!
//! [`read_store_file`] opens the file relative to an open [`StoreDir`] handle (ADR 0007: never
//! by absolute path, never through a reparse point below the store) and reads at most
//! `max_bytes + 1` bytes through [`Read::take`], so the parser can tell "exactly at the limit"
//! from "over it". The file length from metadata is never asked for: a file can grow between
//! a size check and the read, and a device or a filter can report any length. The unbounded
//! [`Dir::read`] is never used.
//!
//! Phase 2 follow-up: a general `Dir::read_limited` in `sys` with a contract test; this module
//! then uses it.

use std::io::Read;

use super::{Document, Limits, LineCol, VdfError, parse};
use crate::path::RelPath;
use crate::policy::root::StoreDir;
use crate::sys::{Dir, SysError};

/// Error while reading a VDF file from a store. Names the file, never its content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VdfReadError {
    /// Opening failed: missing, a directory, a reparse point on the way, restricted, …
    #[error("{file}: {source}")]
    Open {
        /// The file, relative to the store.
        file: RelPath,
        /// Error of the system layer.
        source: SysError,
    },
    /// Reading failed after the file was opened.
    #[error("{file}: read failed ({kind})")]
    Read {
        /// The file, relative to the store.
        file: RelPath,
        /// Kind of the I/O error (its message is not kept).
        kind: std::io::ErrorKind,
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
    let reader = dir.open_read(file).map_err(|source| VdfReadError::Open {
        file: file.clone(),
        source,
    })?;
    // One byte over the limit is enough for `parse` to report `TooLarge`.
    let cap = u64::try_from(limits.max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut buf = Vec::new();
    reader
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| VdfReadError::Read {
            file: file.clone(),
            kind: e.kind(),
        })?;
    parse(&buf, limits).map_err(|error| VdfReadError::Parse {
        file: file.clone(),
        at: error.line_col(&buf),
        error,
    })
}

#[cfg(test)]
mod tests;
