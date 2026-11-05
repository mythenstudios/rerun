//! The write sequences of ADR 0017, written once (amendment A1, user decision D-4).
//!
//! `create_new`, `create_dir`, `remove_dir`, `flush` and `lock` (and, with the guard, replace,
//! delete and `rename_to`) are generic over two small primitive traits: [`PrimDir`] (a
//! directory handle) and [`PrimFile`] (a held file or directory handle). `sys::fake` and, from
//! P2-4, `sys::win` implement only the primitives; the order of the steps, the cleanup of
//! `<tmp>` and every check between the steps live here, so the failure paths that ship are the
//! ones the fake's fault, crash and power-loss tests exercise.
//!
//! Rules that belong to a single call stay inside the primitives: the single-segment
//! re-assertion of a rename target, the status mapping (a rename collision is `Busy`, a
//! create collision `AlreadyExists`), `IGNORE_READONLY_ATTRIBUTE` on a delete, never following
//! a reparse point on an open.

use std::fmt;
use std::io::{self, Read};

use sha2::{Digest, Sha256};

use super::fs::{Attrs, EntryKind, FileLock, Metadata, NewFile, RootInfo, Written};
use super::{SysError, SysErrorKind, SysResult};
use crate::path::RelPath;

/// Bytes streamed per write call.
const CHUNK: usize = 64 * 1024;

/// What a held handle reports about its object (`FileAttributeTagInformation`,
/// `FileStandardInformation`, `FileIdInformation` on the handle itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldState {
    /// Plain file (also with an allowlisted data tag), directory, or anything else.
    pub(crate) kind: EntryKind,
    /// Hard links of the object.
    pub(crate) links: u32,
    /// Read-only, hidden, system.
    pub(crate) attrs: Attrs,
    /// Length in bytes (0 for a directory).
    pub(crate) len: u64,
    /// 128-bit file ID.
    pub(crate) file_id: u128,
    /// Reparse tag, if any (an allowlisted data tag on a plain file).
    pub(crate) reparse_tag: Option<u32>,
}

/// A directory handle, the parent of every name a primitive takes. Every `name` is a single
/// segment; a primitive re-asserts that (`InvalidPath`) and never follows a reparse point.
pub(crate) trait PrimDir: Send + Sync {
    /// The held handle type of this implementation.
    type File: PrimFile;

    /// Identity and properties of this directory.
    fn info(&self) -> SysResult<RootInfo>;

    /// Attribute-only metadata of the child `name` (`Ok(None)`: missing).
    fn lookup(&self, name: &str) -> SysResult<Option<Metadata>>;

    /// Creates `name` (`FILE_CREATE`, write, delete, share 0); an existing name is
    /// `AlreadyExists`.
    fn create_tmp(&self, name: &str) -> SysResult<Self::File>;

    /// Opens or creates the plain file `name` (`FILE_OPEN_IF`, `FILE_READ_DATA`, share 0,
    /// never following a reparse point); held until the handle drops.
    fn open_lock(&self, name: &str) -> SysResult<Self::File>;

    /// Creates the directory `name` (`FILE_CREATE`) and returns its file ID.
    fn create_dir(&self, name: &str) -> SysResult<u128>;

    /// Opens the directory `name` itself for deleting (`DELETE`, shares read and write);
    /// a file is `InvalidPath`.
    fn open_dir_delete(&self, name: &str) -> SysResult<Self::File>;

    /// Renames the held `f` to `name` in this directory (`RootDirectory` = this handle, no
    /// replace). A collision is `Busy`.
    fn rename(&self, f: &Self::File, name: &str) -> SysResult<()>;

    /// Flushes this directory (`NtFlushBuffersFileEx` on a re-open for `FILE_ADD_FILE`).
    fn flush(&self) -> SysResult<()>;
}

/// A held file or directory handle. Dropping it closes the handle; a POSIX delete set on it
/// removes the name then.
pub(crate) trait PrimFile: Send + fmt::Debug {
    /// What the handle reports about its object.
    fn state(&self) -> SysResult<HeldState>;

    /// Appends `buf` (a file created by [`PrimDir::create_tmp`]).
    fn write(&mut self, buf: &[u8]) -> SysResult<()>;

    /// Sets read-only, hidden and system (`FileBasicInformation`); other attributes stay.
    fn set_attrs(&self, attrs: Attrs) -> SysResult<()>;

    /// Flushes the file's data and metadata.
    fn flush(&self) -> SysResult<()>;

    /// POSIX delete on the handle (`FileDispositionInformationEx`: delete, POSIX semantics,
    /// ignore read-only). The name goes when the handle closes. A non-empty directory is
    /// `NotEmpty`; an image section (`STATUS_CANNOT_DELETE`) is `Busy`.
    fn posix_delete(&self) -> SysResult<()>;
}

/// The single segment of a write's `name` (`InvalidPath` otherwise).
fn segment(name: &RelPath) -> SysResult<&str> {
    let mut segs = name.segments();
    match (segs.next(), segs.next()) {
        (Some(s), None) => Ok(s),
        _ => Err(SysError::new(SysErrorKind::InvalidPath, name.as_str())),
    }
}

/// Writes are refused in a case-sensitive directory and on a volume without POSIX delete and
/// rename semantics (ADR 0017).
fn writable<D: PrimDir>(d: &D, target: &str) -> SysResult<()> {
    let info = d.info()?;
    if info.case_sensitive {
        return Err(SysError::new(
            SysErrorKind::Unsupported,
            format!("{target}: write in a case-sensitive directory"),
        ));
    }
    if !info.supports_posix_rename {
        return Err(SysError::new(
            SysErrorKind::Unsupported,
            format!("{target}: volume without POSIX delete and rename (FAT, exFAT)"),
        ));
    }
    Ok(())
}

/// Deletes a `<tmp>` that will not be renamed (POSIX delete on the held handle, never a
/// re-open, so nobody can swap it) and returns the error that ended the sequence. A failing
/// cleanup is not reported over the cause: the journal names `<tmp>` and recovery deletes it.
fn discard<F: PrimFile>(tmp: F, e: SysError) -> SysError {
    let _ = tmp.posix_delete();
    drop(tmp);
    e
}

/// Steps 3 to 5: streams `src` into `tmp`, hashing, at most `new.max_len` bytes; checks the
/// hash; sets the attributes after the last write; flushes.
fn fill<F: PrimFile>(
    tmp: &mut F,
    src: &mut dyn Read,
    new: &NewFile,
    target: &str,
) -> SysResult<Written> {
    let mut hash = Sha256::new();
    let mut len = 0u64;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(SysError::io(&e, target)),
        };
        len = len.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if len > new.max_len {
            return Err(SysError::too_large(target, new.max_len));
        }
        let chunk = buf.get(..n).unwrap_or_default();
        hash.update(chunk);
        tmp.write(chunk)?;
    }
    let sha256: [u8; 32] = hash.finalize().into();
    if sha256 != new.sha256 {
        return Err(SysError::new(
            SysErrorKind::Mismatch,
            format!("{target}: the source does not have the expected hash"),
        ));
    }
    tmp.set_attrs(new.attrs)?;
    tmp.flush()?;
    let file_id = tmp.state()?.file_id;
    Ok(Written {
        sha256,
        len,
        file_id,
    })
}

/// [`DirWrite::create_new`](super::fs::DirWrite::create_new): an existing name is
/// `AlreadyExists`; `<tmp>` (`FILE_CREATE`, share 0), write, attributes, flush, rename onto the
/// name without replace (a collision only there is `Busy`). Any failure deletes `<tmp>` on its
/// handle.
pub(crate) fn create_new<D: PrimDir>(
    d: &D,
    name: &RelPath,
    src: &mut dyn Read,
    new: &NewFile,
) -> SysResult<Written> {
    let n = segment(name)?;
    writable(d, n)?;
    if d.lookup(n)?.is_some() {
        return Err(SysError::new(SysErrorKind::AlreadyExists, n));
    }
    let mut tmp = d.create_tmp(new.tmp.as_str())?;
    let written = match fill(&mut tmp, src, new, n) {
        Ok(w) => w,
        Err(e) => return Err(discard(tmp, e)),
    };
    if let Err(e) = d.rename(&tmp, n) {
        return Err(discard(tmp, e));
    }
    Ok(written)
}

/// [`DirWrite::create_dir`](super::fs::DirWrite::create_dir).
pub(crate) fn create_dir<D: PrimDir>(d: &D, name: &RelPath) -> SysResult<u128> {
    let n = segment(name)?;
    writable(d, n)?;
    d.create_dir(n)
}

/// [`DirWrite::remove_dir`](super::fs::DirWrite::remove_dir): opens the directory itself
/// for deleting, compares its file ID on that handle (`Mismatch`), POSIX-deletes it there
/// (`NotEmpty` if it has entries).
pub(crate) fn remove_dir<D: PrimDir>(d: &D, name: &RelPath, expected_id: u128) -> SysResult<()> {
    let n = segment(name)?;
    writable(d, n)?;
    let f = d.open_dir_delete(n)?;
    let st = f.state()?;
    match st.kind {
        EntryKind::Dir => {}
        EntryKind::Reparse => return Err(SysError::new(SysErrorKind::ReparsePoint, n)),
        EntryKind::File => return Err(SysError::new(SysErrorKind::InvalidPath, n)),
    }
    if st.file_id != expected_id {
        return Err(SysError::new(
            SysErrorKind::Mismatch,
            format!("{n}: not the expected directory"),
        ));
    }
    f.posix_delete()
}

/// [`DirWrite::flush`](super::fs::DirWrite::flush).
pub(crate) fn flush<D: PrimDir>(d: &D) -> SysResult<()> {
    writable(d, ".")?;
    d.flush()
}

/// A held lock file (ADR 0017, A7); released when it drops.
#[derive(Debug)]
pub(crate) struct Lock<F: PrimFile> {
    _file: F,
}

impl<F: PrimFile> FileLock for Lock<F> {}

/// [`DirWrite::lock`](super::fs::DirWrite::lock): opens or creates the plain file `name`
/// with share 0 and keeps it open. A directory is `AccessDenied`, a reparse point
/// `ReparsePoint`, a link count other than 1 `Linked`.
pub(crate) fn lock<D: PrimDir>(d: &D, name: &RelPath) -> SysResult<Lock<D::File>> {
    let n = segment(name)?;
    writable(d, n)?;
    let f = d.open_lock(n)?;
    let st = f.state()?;
    match st.kind {
        EntryKind::File => {}
        EntryKind::Dir => return Err(SysError::new(SysErrorKind::AccessDenied, n)),
        EntryKind::Reparse => return Err(SysError::new(SysErrorKind::ReparsePoint, n)),
    }
    if st.links != 1 {
        return Err(SysError::new(SysErrorKind::Linked, n));
    }
    Ok(Lock { _file: f })
}
