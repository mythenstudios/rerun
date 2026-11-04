//! File system trait.

use std::io::Read;
use std::path::Path;

use super::{SysError, SysErrorKind, SysResult};

/// Kind of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Reparse point (symlink, junction …). Never followed.
    Reparse,
}

/// Metadata of an entry. Timestamps are deliberately absent (see `snapshot`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    /// Kind of the entry.
    pub kind: EntryKind,
    /// Size in bytes (0 for directories and reparse points).
    pub len: u64,
    /// Read-only attribute.
    pub readonly: bool,
}

/// Entry of a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Name in its original case.
    pub name: String,
    /// Metadata.
    pub meta: Metadata,
}

/// File system. All paths are absolute; relative paths yield `InvalidPath`.
///
/// Semantics (identical for `win` and `fake`, checked in `sys::contract`):
/// - Names are case-insensitive, the original case is preserved.
/// - Reparse points are never followed: `metadata` reports them as [`EntryKind::Reparse`],
///   other operations through a reparse point return `ReparsePoint`.
/// - If the parent directory is missing, writing operations return `NotFound`.
pub trait Fs: Send + Sync {
    /// Metadata without following reparse points. `Ok(None)` = does not exist.
    fn metadata(&self, p: &Path) -> SysResult<Option<Metadata>>;

    /// Opens a file for reading (streaming, e.g. for large exe files).
    fn open_read<'a>(&'a self, p: &Path) -> SysResult<Box<dyn Read + Send + 'a>>;

    /// Reads a whole file.
    fn read(&self, p: &Path) -> SysResult<Vec<u8>> {
        let mut reader = self.open_read(p)?;
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|_| SysError::path(SysErrorKind::Other, p))?;
        Ok(buf)
    }

    /// Lists a directory. The order is unspecified.
    fn read_dir(&self, p: &Path) -> SysResult<Vec<DirEntry>>;

    /// Writes a file; replaces an existing one atomically (temp file + rename).
    /// Read-only files yield `AccessDenied`.
    fn write(&self, p: &Path, data: &[u8]) -> SysResult<()>;

    /// Creates exactly one directory. Deliberately no `create_dir_all`: every created
    /// directory must be journaled individually.
    fn create_dir(&self, p: &Path) -> SysResult<()>;

    /// Deletes a file (or a reparse point itself, never its target).
    fn remove_file(&self, p: &Path) -> SysResult<()>;

    /// Deletes an empty directory. Not empty yields `NotEmpty`.
    fn remove_dir(&self, p: &Path) -> SysResult<()>;

    /// Renames or moves. Never overwrites (`AlreadyExists`); a case-only change
    /// is allowed.
    fn rename(&self, from: &Path, to: &Path) -> SysResult<()>;

    /// Sets or clears the read-only attribute.
    fn set_readonly(&self, p: &Path, readonly: bool) -> SysResult<()>;
}
