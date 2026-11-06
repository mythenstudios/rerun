//! The write sequences of ADR 0017, written once (amendment A1, user decision D-4).
//!
//! `create_new`, `create_dir`, `remove_dir`, `flush` and `lock` (and, with the guard, replace,
//! delete and `rename_to`) are generic over two small primitive traits: [`PrimDir`] (a
//! directory handle) and [`PrimFile`] (a held file or directory handle). `sys::fake` and
//! `sys::win` implement only the primitives; the order of the steps, the cleanup of
//! `<tmp>` and every check between the steps live here, so the failure paths that ship are the
//! ones the fake's fault, crash and power-loss tests exercise.
//!
//! Rules that belong to a single call stay inside the primitives: the single-segment
//! re-assertion of a rename target, the status mapping (a rename collision is `Busy`, a
//! create collision `AlreadyExists`), `IGNORE_READONLY_ATTRIBUTE` on a delete, never following
//! a reparse point on an open.
//!
//! [`Guard`] is the one implementation of [`FileGuard`]: the replace sequence (steps 1 to 8),
//! the undo of a failed step 7 on the same handle and the success with pending cleanup of a
//! failed step 8 (A2), and the re-checks of name, link count and R/H/S on the guard before
//! step 6, before the undo rename, before step 8 and before a delete or `rename_to` (A4).

use std::fmt;
use std::io::{self, Read};

use sha2::{Digest, Sha256};

use super::fs::{
    Attrs, EntryKind, FileGuard, FileLock, Metadata, NewFile, ReparseInfo, Replaced, Written, tag,
};
use super::{SysError, SysErrorKind, SysResult};
use crate::fold::fold;
use crate::path::RelPath;

#[cfg_attr(
    not(any(test, feature = "fake")),
    expect(
        dead_code,
        reason = "sys::win uses the registry sequences from P2-9 C5 on"
    )
)]
pub(crate) mod reg;

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

/// A validated single segment: a [`RelPath`] of exactly one segment, so it has passed the
/// segment rules of `crate::path` (no `:`, no `.` or `..`, no reserved device name, no
/// trailing dot or space, no control or confusable character). It is the only name type of
/// the primitives, so `sys::fake` and `sys::win` share one check: an alternate data stream
/// (`x:s`) or a stream rename (`:x`) can never reach a primitive.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Seg<'a>(&'a RelPath);

impl<'a> Seg<'a> {
    /// `p` if it is exactly one segment (`InvalidPath` otherwise).
    pub(crate) fn new(p: &'a RelPath) -> SysResult<Self> {
        let mut segs = p.segments();
        match (segs.next(), segs.next()) {
            (Some(_), None) => Ok(Self(p)),
            _ => Err(SysError::new(SysErrorKind::InvalidPath, p.as_str())),
        }
    }

    /// The segment.
    pub(crate) fn as_str(self) -> &'a str {
        self.0.as_str()
    }

    /// The segment as a [`RelPath`] (for the read-side lookup of `sys::win`).
    pub(crate) fn rel(self) -> &'a RelPath {
        self.0
    }
}

/// What a write needs to know about its directory before it starts (ADR 0017): a
/// case-sensitive directory and a volume without POSIX delete and rename are `Unsupported`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Support {
    /// `FILE_CASE_SENSITIVE_DIR` on the directory.
    pub(crate) case_sensitive: bool,
    /// `FILE_SUPPORTS_POSIX_UNLINK_RENAME` of its volume.
    pub(crate) posix: bool,
}

/// A directory handle, the parent of every name a primitive takes. Every name is a [`Seg`];
/// a primitive never follows a reparse point.
pub(crate) trait PrimDir: Send + Sync {
    /// The held handle type of this implementation.
    type File: PrimFile;

    /// Case sensitivity of this directory and POSIX support of its volume, queried on the
    /// handle (a narrow query, not the full `Dir::info`).
    fn support(&self) -> SysResult<Support>;

    /// This directory's path on its volume as `FileNameInformation` reports it: `\`-separated
    /// with a leading `\` (`\` alone for a volume root). The guard's name checks compare
    /// [`PrimFile::name`] with it plus the expected name.
    fn volume_name(&self) -> SysResult<String>;

    /// Attribute-only metadata of the child `name` (`Ok(None)`: missing).
    fn lookup(&self, name: Seg<'_>) -> SysResult<Option<Metadata>>;

    /// Opens the entry `name` itself for a guard (`DELETE | FILE_READ_DATA |
    /// FILE_READ_ATTRIBUTES | SYNCHRONIZE`, share read only, never following a reparse
    /// point); the sequence classifies it on the handle.
    fn open_guard(&self, name: Seg<'_>) -> SysResult<Self::File>;

    /// Creates `name` (`FILE_CREATE`, write, delete, share 0); an existing name is
    /// `AlreadyExists`.
    fn create_tmp(&self, name: Seg<'_>) -> SysResult<Self::File>;

    /// Opens or creates the plain file `name` (`FILE_OPEN_IF`, `FILE_READ_DATA`, share 0,
    /// never following a reparse point); held until the handle drops.
    fn open_lock(&self, name: Seg<'_>) -> SysResult<Self::File>;

    /// Creates the directory `name` (`FILE_CREATE`) and returns its file ID.
    fn create_dir(&self, name: Seg<'_>) -> SysResult<u128>;

    /// Opens the directory `name` itself for deleting (`DELETE`, shares read and write);
    /// a file is `InvalidPath`.
    fn open_dir_delete(&self, name: Seg<'_>) -> SysResult<Self::File>;

    /// Renames the held `f` (opened with `DELETE`) to `name` in this directory
    /// (`RootDirectory` = this handle, no replace). A collision is `Busy`.
    fn rename(&self, f: &Self::File, name: Seg<'_>) -> SysResult<()>;

    /// Flushes this directory (`NtFlushBuffersFileEx` on a re-open for `FILE_ADD_FILE`).
    fn flush(&self) -> SysResult<()>;
}

/// A held file or directory handle. Dropping it closes the handle; a POSIX delete set on it
/// removes the name then.
pub(crate) trait PrimFile: Send + fmt::Debug {
    /// What the handle reports about its object.
    fn state(&self) -> SysResult<HeldState>;

    /// The object's current path on its volume (`FileNameInformation`, see
    /// [`PrimDir::volume_name`]); it follows renames at once.
    fn name(&self) -> SysResult<String>;

    /// Reads at `off` into `buf` (a guard); 0 at the end.
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> SysResult<usize>;

    /// Process IDs using the object, queried on this handle (which itself is not counted).
    fn users(&self) -> SysResult<Vec<u32>>;

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

/// Writes are refused in a case-sensitive directory and on a volume without POSIX delete and
/// rename semantics (ADR 0017). Checked at the start of every write, also on a guard.
fn writable<D: PrimDir>(d: &D, target: &str) -> SysResult<()> {
    let s = d.support()?;
    if s.case_sensitive {
        return Err(SysError::new(
            SysErrorKind::Unsupported,
            format!("{target}: write in a case-sensitive directory"),
        ));
    }
    if !s.posix {
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
/// A hard link someone added to `<tmp>` keeps its own name; only ours goes.
fn discard<F: PrimFile>(tmp: F, e: SysError) -> SysError {
    let _ = tmp.posix_delete();
    drop(tmp);
    e
}

/// `<tmp>` still has exactly one link: share 0 does not stop another program from adding a
/// hard link (observed for a guard, A4), and a linked `<tmp>` must never become the target.
fn single_link<F: PrimFile>(tmp: &F, target: &str) -> SysResult<()> {
    if tmp.state()?.links != 1 {
        return Err(SysError::new(
            SysErrorKind::Linked,
            format!("{target}: a hard link was added to the temp file"),
        ));
    }
    Ok(())
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
/// `AlreadyExists`; `<tmp>` (`FILE_CREATE`, share 0), write, attributes, flush, a link check
/// of `<tmp>` (`Linked`), rename onto the name without replace (a collision only there is
/// `Busy`). Any failure deletes `<tmp>` on its handle.
pub(crate) fn create_new<D: PrimDir>(
    d: &D,
    name: &RelPath,
    src: &mut dyn Read,
    new: &NewFile,
) -> SysResult<Written> {
    let n = Seg::new(name)?;
    writable(d, n.as_str())?;
    if d.lookup(n)?.is_some() {
        return Err(SysError::new(SysErrorKind::AlreadyExists, n.as_str()));
    }
    let tmp_name = new.tmp.to_rel();
    let mut tmp = d.create_tmp(Seg::new(&tmp_name)?)?;
    let written = match fill(&mut tmp, src, new, n.as_str()) {
        Ok(w) => w,
        Err(e) => return Err(discard(tmp, e)),
    };
    if let Err(e) = single_link(&tmp, n.as_str()).and_then(|()| d.rename(&tmp, n)) {
        return Err(discard(tmp, e));
    }
    Ok(written)
}

/// [`DirWrite::create_dir`](super::fs::DirWrite::create_dir).
pub(crate) fn create_dir<D: PrimDir>(d: &D, name: &RelPath) -> SysResult<u128> {
    let n = Seg::new(name)?;
    writable(d, n.as_str())?;
    d.create_dir(n)
}

/// [`DirWrite::remove_dir`](super::fs::DirWrite::remove_dir): opens the directory itself
/// for deleting, compares its file ID on that handle (`Mismatch`), POSIX-deletes it there
/// (`NotEmpty` if it has entries).
pub(crate) fn remove_dir<D: PrimDir>(d: &D, name: &RelPath, expected_id: u128) -> SysResult<()> {
    let n = Seg::new(name)?;
    let t = n.as_str();
    writable(d, t)?;
    let f = d.open_dir_delete(n)?;
    let st = f.state()?;
    match st.kind {
        EntryKind::Dir => {}
        EntryKind::Reparse => return Err(SysError::new(SysErrorKind::ReparsePoint, t)),
        EntryKind::File => return Err(SysError::new(SysErrorKind::InvalidPath, t)),
    }
    if st.file_id != expected_id {
        return Err(SysError::new(
            SysErrorKind::Mismatch,
            format!("{t}: not the expected directory"),
        ));
    }
    f.posix_delete()
}

/// [`DirWrite::flush`](super::fs::DirWrite::flush).
pub(crate) fn flush<D: PrimDir>(d: &D) -> SysResult<()> {
    writable(d, ".")?;
    d.flush()
}

/// `\a\b` of a directory's volume name plus `name`, for comparing with
/// [`PrimFile::name`].
fn full_name<D: PrimDir>(d: &D, name: &str) -> SysResult<String> {
    Ok(format!(
        "{}\\{name}",
        d.volume_name()?.trim_end_matches('\\')
    ))
}

/// [`DirWrite::guard`](super::fs::DirWrite::guard): one handle on the existing plain file
/// `name` that shares read only. Refuses a directory (`AccessDenied`), a reparse point
/// (`ReparsePoint`), a link count other than 1 (`Linked`), a file that is no longer at
/// `name` in this directory once opened (`Busy`, full volume path compared); keeps the
/// stored spelling of the name and the R/H/S it saw (A4).
pub(crate) fn guard<'a, D: PrimDir>(d: &'a D, name: &RelPath) -> SysResult<Guard<'a, D>> {
    let n = Seg::new(name)?;
    let t = n.as_str();
    writable(d, t)?;
    let file = d.open_guard(n)?;
    let st = file.state()?;
    match st.kind {
        EntryKind::File => {}
        EntryKind::Dir => return Err(SysError::new(SysErrorKind::AccessDenied, t)),
        EntryKind::Reparse => return Err(SysError::new(SysErrorKind::ReparsePoint, t)),
    }
    if st.links != 1 {
        return Err(SysError::new(SysErrorKind::Linked, t));
    }
    let want = full_name(d, t)?;
    let found = file.name()?;
    let moved = || {
        SysError::new(
            SysErrorKind::Busy,
            format!("{t}: renamed while it was opened"),
        )
    };
    if fold(&found) != fold(&want) {
        return Err(moved());
    }
    let stored = RelPath::from_segment(found.rsplit('\\').next().unwrap_or_default())
        .map_err(|_| moved())?;
    Ok(Guard {
        d,
        file,
        stored,
        attrs: st.attrs,
        hash: None,
    })
}

/// The one [`FileGuard`] (ADR 0017): a held handle on a plain file of `d`.
pub(crate) struct Guard<'a, D: PrimDir> {
    d: &'a D,
    file: D::File,
    /// The stored spelling of the name it was opened by (one segment).
    stored: RelPath,
    /// Read-only, hidden and system when it was opened (A4).
    attrs: Attrs,
    /// SHA-256 of the content, once streamed.
    hash: Option<[u8; 32]>,
}

impl<D: PrimDir> fmt::Debug for Guard<'_, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guard")
            .field("name", &self.stored.as_str())
            .field("file", &self.file)
            .finish_non_exhaustive()
    }
}

impl<D: PrimDir> Guard<'_, D> {
    /// The stored name as a primitive's name.
    fn stored(&self) -> SysResult<Seg<'_>> {
        Seg::new(&self.stored)
    }

    /// A4: the guard is still at `expected` in its directory (`Busy`), still has one link
    /// (`Linked`) and the R/H/S it was opened with (`Mismatch`).
    fn recheck(&self, expected: Seg<'_>) -> SysResult<()> {
        let e = expected.as_str();
        let want = full_name(self.d, e)?;
        if fold(&self.file.name()?) != fold(&want) {
            return Err(SysError::new(
                SysErrorKind::Busy,
                format!("{e}: renamed while it was held"),
            ));
        }
        let st = self.file.state()?;
        if st.links != 1 {
            return Err(SysError::new(SysErrorKind::Linked, e));
        }
        if st.attrs != self.attrs {
            return Err(SysError::new(
                SysErrorKind::Mismatch,
                format!("{e}: attributes changed while it was held"),
            ));
        }
        Ok(())
    }

    /// The hash compared with `expected` before an act (`Mismatch`, nothing touched).
    fn expect(&mut self, expected: &[u8; 32]) -> SysResult<()> {
        if self.sha256()? != *expected {
            return Err(SysError::new(
                SysErrorKind::Mismatch,
                format!("{}: not the expected content", self.stored.as_str()),
            ));
        }
        Ok(())
    }
}

/// Reads a guard from offset 0.
struct GuardReader<'g, F> {
    file: &'g mut F,
    off: u64,
}

impl<F: PrimFile> Read for GuardReader<'_, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read_at(self.off, buf).map_err(io::Error::other)?;
        self.off = self
            .off
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }
}

impl<D: PrimDir> FileGuard for Guard<'_, D> {
    fn name(&self) -> &RelPath {
        &self.stored
    }

    fn metadata(&self) -> SysResult<Metadata> {
        let st = self.file.state()?;
        Ok(Metadata {
            kind: st.kind,
            len: st.len,
            attrs: st.attrs,
            links: Some(st.links),
            file_id: st.file_id,
            reparse: st.reparse_tag.map(|t| ReparseInfo {
                tag: t,
                surrogate: tag::is_surrogate(t),
                target: None,
            }),
            restricted: false,
        })
    }

    fn sha256(&mut self) -> SysResult<[u8; 32]> {
        if let Some(h) = self.hash {
            return Ok(h);
        }
        let mut hash = Sha256::new();
        let mut off = 0u64;
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = self.file.read_at(off, &mut buf)?;
            if n == 0 {
                break;
            }
            hash.update(buf.get(..n).unwrap_or_default());
            off = off.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        }
        let h: [u8; 32] = hash.finalize().into();
        self.hash = Some(h);
        Ok(h)
    }

    fn reader(&mut self) -> SysResult<Box<dyn Read + '_>> {
        Ok(Box::new(GuardReader {
            file: &mut self.file,
            off: 0,
        }))
    }

    fn users(&self) -> SysResult<Vec<u32>> {
        self.file.users()
    }

    /// Steps 1 to 8 of ADR 0017 with the failure handling of A2 and the re-checks of A4.
    fn replace(
        mut self: Box<Self>,
        expected: &[u8; 32],
        src: &mut dyn Read,
        new: &NewFile,
    ) -> SysResult<Replaced> {
        let t = self.stored.as_str().to_owned();
        if new.sha256 == *expected {
            return Err(SysError::new(
                SysErrorKind::Unsupported,
                format!("{t}: content unchanged"),
            ));
        }
        writable(self.d, &t)?;
        self.expect(expected)?;
        let (tmp_name, old_name) = (new.tmp.to_rel(), new.tmp.old());
        let (tmp_seg, old) = (Seg::new(&tmp_name)?, Seg::new(&old_name)?);
        let stored = self.stored()?;
        // Steps 2 to 5.
        let mut tmp = self.d.create_tmp(tmp_seg)?;
        let written = match fill(&mut tmp, src, new, &t) {
            Ok(w) => w,
            Err(e) => return Err(discard(tmp, e)),
        };
        // Step 6: the guard becomes `<tmp>.old`.
        if let Err(e) = self
            .recheck(stored)
            .and_then(|()| self.d.rename(&self.file, old))
        {
            return Err(discard(tmp, e));
        }
        // Step 7: `<tmp>` (still single-linked) onto the stored spelling; on failure the
        // guard goes back (A2).
        if let Err(e) = single_link(&tmp, &t).and_then(|()| self.d.rename(&tmp, stored)) {
            let _undo = self
                .recheck(old)
                .and_then(|()| self.d.rename(&self.file, stored));
            return Err(discard(tmp, e));
        }
        drop(tmp);
        // Step 8: any failure is success with pending cleanup (A2).
        let old_left = match self.recheck(old).and_then(|()| self.file.posix_delete()) {
            Ok(()) => None,
            Err(_) => Some(new.tmp.clone()),
        };
        Ok(Replaced {
            new: written,
            old_left,
        })
    }

    fn delete(mut self: Box<Self>, expected: &[u8; 32]) -> SysResult<()> {
        writable(self.d, self.stored.as_str())?;
        self.expect(expected)?;
        self.recheck(self.stored()?)?;
        self.file.posix_delete()
    }

    fn rename_to(self: Box<Self>, name: &RelPath) -> SysResult<()> {
        let n = Seg::new(name)?;
        writable(self.d, n.as_str())?;
        self.recheck(self.stored()?)?;
        self.d.rename(&self.file, n)
    }
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
    let n = Seg::new(name)?;
    let t = n.as_str();
    writable(d, t)?;
    let f = d.open_lock(n)?;
    let st = f.state()?;
    match st.kind {
        EntryKind::File => {}
        EntryKind::Dir => return Err(SysError::new(SysErrorKind::AccessDenied, t)),
        EntryKind::Reparse => return Err(SysError::new(SysErrorKind::ReparsePoint, t)),
    }
    if st.links != 1 {
        return Err(SysError::new(SysErrorKind::Linked, t));
    }
    Ok(Lock { _file: f })
}
