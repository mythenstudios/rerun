//! [`WinFs`] and [`WinDir`]: the real file system (ADR 0007), read side so far: of the write
//! side (ADR 0017) only `DirWrite::open_dir_write` exists, every writing method returns
//! `Unsupported`. No `unsafe` here; every system call goes through [`super::nt`] or
//! [`super::token`].
//!
//! Walk: each segment is opened relative to its parent handle ([`nt::open_relative`],
//! `OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT`), checked against the requested name (L1,
//! [`name::long_name_matches`]) and classified on the same handle
//! (`FileAttributeTagInformation`): surrogates and unknown tags stop the walk with
//! `ReparsePoint`, a file where a directory is needed with `InvalidPath`.
//!
//! Restricted entries: when the attribute-only reopen of a listed entry is denied (its own
//! DACL denies the user even `FILE_READ_ATTRIBUTES`/`SYNCHRONIZE`), the entry is described
//! from the listing (`FileIdExtdDirectoryInformation`) with `Metadata::restricted`. `metadata`
//! of such an entry scans the listing of its parent for the same description, so both agree.

use std::ffi::OsString;
use std::io::Read;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_INFORMATION_CLASS, FileAttributeTagInformation, FileCaseSensitiveInformation,
    FileIdInformation, FileNameInformation, FileNormalizedNameInformation,
    FileProcessIdsUsingFileInformation, FileStandardInformation,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM,
};

use super::name::{self, DirLayout, Listed, Seg16};
use super::nt::{self, Access, RelOpen};
use super::reparse;
use super::status::{
    NtStatus, STATUS_DELETE_PENDING, STATUS_UNSUCCESSFUL, is_unsupported_class, nt_error,
    win32_error, win32_info_error,
};
use super::token;
use crate::fold::fold;
use crate::path::RelPath;
use crate::sys::fs::{
    Attrs, Dir, DirEntry, DirWrite, EntryKind, FileGuard, FileLock, Fs, FsKind, Metadata, NewFile,
    ReadSeek, ReparseInfo, RootInfo, WriteCap, Written, tag,
};
use crate::sys::{SysError, SysErrorKind, SysResult};

/// Message of every writing method until the write side exists (ADR 0017).
const NO_WRITE: &str = "sys::win: the write side is not implemented yet";
/// Target shown for errors about the handle itself.
const HANDLE_TARGET: &str = "<dir handle>";

/// winnt.h `FILE_SUPPORTS_POSIX_UNLINK_RENAME`.
const FILE_SUPPORTS_POSIX_UNLINK_RENAME: u32 = 0x0000_0400;
/// ntifs.h `FILE_CS_FLAG_CASE_SENSITIVE_DIR`.
const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 0x0000_0001;

fn err(kind: SysErrorKind, target: &str) -> SysError {
    SysError::new(kind, target)
}

/// Error target for a listed entry of the directory `dir` (a validated path or the handle
/// placeholder): the raw name from disk, always escaped.
fn entry_target(dir: &str, raw_name: &str) -> String {
    format!("{dir}: entry {raw_name:?}")
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// A fixed-size information class; a short reply is an error (`Other`).
fn query(
    h: BorrowedHandle<'_>,
    class: FILE_INFORMATION_CLASS,
    size: usize,
    target: &str,
) -> SysResult<Vec<u8>> {
    let b = nt::query_info(h, class, size).map_err(|s| nt_error(s, target))?;
    if b.len() < size {
        return Err(err(SysErrorKind::Other, target));
    }
    Ok(b)
}

/// `FILE_ATTRIBUTE_TAG_INFORMATION`.
#[derive(Debug, Clone, Copy)]
struct TagInfo {
    attrs: u32,
    /// Reparse tag, only if `FILE_ATTRIBUTE_REPARSE_POINT` is set.
    tag: Option<u32>,
}

impl TagInfo {
    fn is_dir(self) -> bool {
        self.attrs & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// Kind of the entry: surrogates and tags off the allowlist are `Reparse`.
    fn kind(self) -> EntryKind {
        match self.tag {
            Some(t) if !tag::is_allowed_data_tag(t) => EntryKind::Reparse,
            _ if self.is_dir() => EntryKind::Dir,
            _ => EntryKind::File,
        }
    }

    /// A placeholder whose data would be recalled (downloaded) on access.
    fn needs_recall(self) -> bool {
        self.attrs
            & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
                | FILE_ATTRIBUTE_RECALL_ON_OPEN
                | FILE_ATTRIBUTE_OFFLINE)
            != 0
    }
}

fn tag_info(h: BorrowedHandle<'_>, target: &str) -> SysResult<TagInfo> {
    let b = query(h, FileAttributeTagInformation, 8, target)?;
    let attrs = u32_at(&b, 0).ok_or_else(|| err(SysErrorKind::Other, target))?;
    let raw_tag = u32_at(&b, 4).ok_or_else(|| err(SysErrorKind::Other, target))?;
    Ok(TagInfo {
        attrs,
        tag: (attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0).then_some(raw_tag),
    })
}

/// `FILE_STANDARD_INFORMATION`: end of file, link count, delete pending.
struct Standard {
    len: u64,
    links: u32,
    delete_pending: bool,
}

fn standard(h: BorrowedHandle<'_>, target: &str) -> SysResult<Standard> {
    let b = query(h, FileStandardInformation, 24, target)?;
    let bad = || err(SysErrorKind::Other, target);
    Ok(Standard {
        len: u64_at(&b, 8).ok_or_else(bad)?,
        links: u32_at(&b, 16).ok_or_else(bad)?,
        delete_pending: b.get(20).ok_or_else(bad)? != &0,
    })
}

/// `FILE_ID_INFORMATION`: volume serial and 128-bit file ID (little-endian bytes).
fn file_id(h: BorrowedHandle<'_>, target: &str) -> SysResult<(u64, u128)> {
    let b = query(h, FileIdInformation, 24, target)?;
    let serial = u64_at(&b, 0).ok_or_else(|| err(SysErrorKind::Other, target))?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&b[8..24]);
    Ok((serial, u128::from_le_bytes(id)))
}

/// A name information class (`FILE_NAME_INFORMATION`); raw `NTSTATUS` on failure.
fn name_info(h: BorrowedHandle<'_>, class: FILE_INFORMATION_CLASS) -> Result<Vec<u16>, NtStatus> {
    let b = nt::query_info(h, class, 4 + 2 * 260)?;
    name::parse_name_info(&b).ok_or(STATUS_UNSUCCESSFUL)
}

/// L1 check (ADR 0007, D5) on a freshly opened handle. `FileNormalizedNameInformation`; only
/// if that class is unsupported **and** the volume is FAT or exFAT (which have no
/// normalized-name support), `FileNameInformation`. On any other file system an unsupported
/// class is an error (fail closed): a filter driver failing the query on NTFS must not turn
/// the check into one that lets `PROGRA~1` through. A mismatch is `NotFound`: the requested
/// name is not the long name of the entry.
fn check_long_name(h: BorrowedHandle<'_>, seg: &Seg16, target: &str) -> SysResult<()> {
    let reported = match name_info(h, FileNormalizedNameInformation) {
        Ok(n) => n,
        Err(s) if is_unsupported_class(s) && on_fat(h) => {
            name_info(h, FileNameInformation).map_err(|s| nt_error(s, target))?
        }
        Err(s) => return Err(nt_error(s, target)),
    };
    if name::long_name_matches(&reported, seg.units()) {
        Ok(())
    } else {
        Err(err(SysErrorKind::NotFound, target))
    }
}

/// The volume of `h` is FAT or exFAT (`GetVolumeInformationByHandleW`); `false` if unknown.
fn on_fat(h: BorrowedHandle<'_>) -> bool {
    nt::volume_info(h).is_ok_and(|(name, _)| {
        matches!(
            fs_kind(&String::from_utf16_lossy(&name)),
            FsKind::Fat | FsKind::ExFat
        )
    })
}

/// Link target of a name surrogate (print name), read on its `FILE_OPEN_REPARSE_POINT` handle.
fn link_target(h: BorrowedHandle<'_>, target: &str) -> SysResult<Option<String>> {
    let buf = nt::reparse_data(h).map_err(|c| win32_error(c, target))?;
    reparse::parse(&buf)
        .map(|p| p.target)
        .map_err(|_| err(SysErrorKind::Other, target))
}

/// `FILE_PROCESS_IDS_USING_FILE_INFORMATION`: a `ULONG` count, then `ULONG_PTR` process IDs
/// (aligned to a `ULONG_PTR`). Sorted, without duplicates. `None` if the reply is shorter
/// than its count or an ID does not fit a `u32` (PIDs always do).
fn parse_process_ids(b: &[u8]) -> Option<Vec<u32>> {
    const PTR: usize = size_of::<usize>();
    let count = usize::try_from(u32_at(b, 0)?).ok()?;
    let mut out = Vec::with_capacity(count.min(b.len() / PTR));
    for i in 0..count {
        let at = PTR.checked_add(i.checked_mul(PTR)?)?;
        let id = match PTR {
            8 => u64_at(b, at)?,
            _ => u64::from(u32_at(b, at)?),
        };
        out.push(u32::try_from(id).ok()?);
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// Process IDs using the file of `h` (`FileProcessIdsUsingFileInformation`); the buffer
/// grows like every name query (up to about 8,000 IDs, more is an error).
fn process_ids(h: BorrowedHandle<'_>, target: &str) -> SysResult<Vec<u32>> {
    let b = nt::query_info(h, FileProcessIdsUsingFileInformation, 4096)
        .map_err(|s| nt_error(s, target))?;
    parse_process_ids(&b).ok_or_else(|| err(SysErrorKind::Other, target))
}

/// Metadata of an entry from its handle (shared by `metadata` and `read_dir`).
fn meta_of(h: BorrowedHandle<'_>, t: TagInfo, target: &str) -> SysResult<Metadata> {
    let kind = t.kind();
    let std_info = standard(h, target)?;
    let (_, id) = file_id(h, target)?;
    let reparse = match t.tag {
        None => None,
        Some(rt) => Some(ReparseInfo {
            tag: rt,
            surrogate: tag::is_surrogate(rt),
            target: if tag::is_surrogate(rt) {
                link_target(h, target)?
            } else {
                None
            },
        }),
    };
    let file = kind == EntryKind::File;
    Ok(Metadata {
        kind,
        len: if file { std_info.len } else { 0 },
        attrs: Attrs {
            readonly: t.attrs & FILE_ATTRIBUTE_READONLY != 0,
            hidden: t.attrs & FILE_ATTRIBUTE_HIDDEN != 0,
            system: t.attrs & FILE_ATTRIBUTE_SYSTEM != 0,
        },
        links: Some(if file { std_info.links } else { 1 }),
        file_id: id,
        reparse,
        restricted: false,
    })
}

/// Metadata of a restricted entry from its listing data alone: kind from the attributes and
/// the tag (a surrogate or unknown tag is `Reparse`), link count and link target unknown.
/// `None` without a file ID ([`DirLayout::Full`], FAT): the caller then keeps the
/// `AccessDenied` error (fail closed).
fn restricted_meta(l: &Listed) -> Option<Metadata> {
    let t = TagInfo {
        attrs: l.attrs,
        tag: l.tag,
    };
    let kind = t.kind();
    Some(Metadata {
        kind,
        len: if kind == EntryKind::File { l.len } else { 0 },
        attrs: Attrs {
            readonly: l.attrs & FILE_ATTRIBUTE_READONLY != 0,
            hidden: l.attrs & FILE_ATTRIBUTE_HIDDEN != 0,
            system: l.attrs & FILE_ATTRIBUTE_SYSTEM != 0,
        },
        links: None,
        file_id: l.file_id?,
        reparse: l.tag.map(|rt| ReparseInfo {
            tag: rt,
            surrogate: tag::is_surrogate(rt),
            target: None,
        }),
        restricted: true,
    })
}

/// The listed entry `seg` names: an exact match, else the only case-insensitive one (L1: the
/// listing has long names only, so an 8.3 short name never matches). `None` otherwise.
fn find_listed(listed: Vec<Listed>, seg: &Seg16) -> Option<Listed> {
    if let Some(i) = listed.iter().position(|l| l.name == seg.units()) {
        return listed.into_iter().nth(i);
    }
    let mut folded = listed
        .into_iter()
        .filter(|l| name::long_name_matches(&l.name, seg.units()));
    match (folded.next(), folded.next()) {
        (Some(l), None) => Some(l),
        _ => None,
    }
}

/// Why a listing stopped early.
#[derive(Debug, Clone, Copy)]
enum ListStop {
    /// `NtQueryDirectoryFile` failed.
    Status(NtStatus),
    /// A buffer that does not parse.
    Malformed,
    /// More names than the caller's bound.
    TooMany,
}

/// A freshly opened entry: L1-checked, classified on its own handle.
struct Opened {
    handle: OwnedHandle,
    tag: TagInfo,
}

/// Opens one segment relative to `parent` (D4): `RelOpen::Entry`, then L1, then the tag.
fn open_entry(
    parent: BorrowedHandle<'_>,
    seg: &Seg16,
    access: Access,
    target: &str,
) -> SysResult<Opened> {
    let handle =
        nt::open_relative(parent, seg, RelOpen::Entry(access)).map_err(|s| nt_error(s, target))?;
    check_long_name(handle.as_handle(), seg, target)?;
    let tag = tag_info(handle.as_handle(), target)?;
    Ok(Opened { handle, tag })
}

fn seg16(seg: &str, target: &str) -> SysResult<Seg16> {
    Seg16::new(seg).ok_or_else(|| err(SysErrorKind::InvalidPath, target))
}

/// `Dir` handle: a directory opened with [`Access::Dir`].
fn dir_handle(o: Opened, target: &str) -> SysResult<OwnedHandle> {
    match o.tag.kind() {
        EntryKind::Dir => Ok(o.handle),
        EntryKind::Reparse => Err(err(SysErrorKind::ReparsePoint, target)),
        EntryKind::File => Err(err(SysErrorKind::InvalidPath, target)),
    }
}

/// The real file system (`Fs`). Read side so far; the writing `DirWrite` methods return
/// `Unsupported` (ADR 0017).
#[derive(Debug, Default, Clone, Copy)]
pub struct WinFs;

impl WinFs {
    /// The real file system.
    pub fn new() -> Self {
        Self
    }
}

impl Fs for WinFs {
    /// D3: drive-absolute paths only (`X:\…`, `\\?\X:\…`, `/` as `\`); `.`, `..`, UNC, volume
    /// GUID paths and segments with control characters or `<>:"|?*` yield `InvalidPath`.
    /// Opened as `\??\X:\…` with `NtCreateFile`, following reparse points (they are above the
    /// root). A non-allowlisted tag on the opened directory yields `ReparsePoint`.
    fn open_dir(&self, abs: &Path) -> SysResult<Box<dyn Dir + '_>> {
        Ok(Box::new(Self::open_abs(abs)?))
    }

    /// Same open as [`Fs::open_dir`]; the handle type is the same, the capability is in the
    /// returned trait object.
    fn open_dir_write(&self, abs: &Path, _: &WriteCap) -> SysResult<Box<dyn DirWrite + '_>> {
        Ok(Box::new(Self::open_abs(abs)?))
    }
}

impl WinFs {
    /// The absolute open behind both [`Fs`] methods.
    fn open_abs(abs: &Path) -> SysResult<WinDir> {
        let shown = abs.display().to_string();
        let (drive, segs) = abs
            .to_str()
            .and_then(name::parse_abs)
            .ok_or_else(|| err(SysErrorKind::InvalidPath, &shown))?;
        let handle =
            nt::open_absolute_dir(&name::nt_path(drive, &segs)).map_err(|s| nt_error(s, &shown))?;
        let t = tag_info(handle.as_handle(), &shown)?;
        if t.tag.is_some_and(|rt| !tag::is_allowed_data_tag(rt)) {
            return Err(err(SysErrorKind::ReparsePoint, &shown));
        }
        if !t.is_dir() {
            return Err(err(SysErrorKind::InvalidPath, &shown));
        }
        Ok(WinDir::new(handle))
    }
}

/// An open directory of the real file system. One handle type for reading and writing (it
/// shares read, write and delete); the capability split is in the types (ADR 0017). Every
/// writing method returns `Unsupported` so far.
pub struct WinDir {
    handle: OwnedHandle,
    /// Serializes `read_dir(None)`: the enumeration position belongs to the handle.
    listing: Mutex<()>,
}

impl std::fmt::Debug for WinDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinDir")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl WinDir {
    fn new(handle: OwnedHandle) -> Self {
        Self {
            handle,
            listing: Mutex::new(()),
        }
    }

    fn h(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }

    /// `NotFound` if this directory was deleted (like the fake's dead handle).
    fn ensure_live(&self) -> SysResult<()> {
        if standard(self.h(), HANDLE_TARGET)?.delete_pending {
            return Err(err(SysErrorKind::NotFound, HANDLE_TARGET));
        }
        Ok(())
    }

    /// Walks `segs` as directories from this handle; `None` = this handle itself. Callers
    /// check [`Self::ensure_live`] first.
    fn walk(&self, segs: &[&str], target: &str) -> SysResult<Option<OwnedHandle>> {
        let mut cur: Option<OwnedHandle> = None;
        for seg in segs {
            let s = seg16(seg, target)?;
            let parent = cur.as_ref().map_or(self.h(), AsHandle::as_handle);
            let o = open_entry(parent, &s, Access::Attributes, target)?;
            cur = Some(dir_handle(o, target)?);
        }
        Ok(cur)
    }

    /// Parent handle of `p` and the last segment.
    fn split<'p>(&self, p: &'p RelPath) -> SysResult<(Option<OwnedHandle>, &'p str)> {
        let segs: Vec<&str> = p.segments().collect();
        let Some((last, parents)) = segs.split_last() else {
            return Err(err(SysErrorKind::InvalidPath, p.as_str()));
        };
        Ok((self.walk(parents, p.as_str())?, last))
    }

    /// Opens `p` as a directory with [`Access::Dir`].
    fn open_dir_handle(&self, p: &RelPath) -> SysResult<OwnedHandle> {
        let t = p.as_str();
        let (parent, last) = self.split(p)?;
        let parent = parent.as_ref().map_or(self.h(), AsHandle::as_handle);
        let s = seg16(last, t)?;
        match open_entry(parent, &s, Access::Dir, t) {
            Ok(o) => dir_handle(o, t),
            // Directory access can be denied on a file (FILE_EXECUTE) or a link: classify
            // with an attribute-only open for the error kind. Its handle is never returned.
            Err(e) if e.kind == SysErrorKind::AccessDenied => {
                match open_entry(parent, &s, Access::Attributes, t) {
                    Ok(o) if o.tag.kind() != EntryKind::Dir => dir_handle(o, t),
                    _ => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Lists `dir` (raw UTF-16 names, without `.` and `..`), at most `max` names (else
    /// `TooLarge`). `FileIdExtdDirectoryInformation`; only if the file system does not support
    /// that class (FAT) on the first call, `FileFullDirectoryInformation` (no file IDs).
    fn list(dir: BorrowedHandle<'_>, max: usize, target: &str) -> SysResult<Vec<Listed>> {
        let stop = |s: ListStop| match s {
            ListStop::Status(s) => nt_error(s, target),
            ListStop::Malformed => err(SysErrorKind::Other, target),
            ListStop::TooMany => {
                SysError::too_large(target, u64::try_from(max).unwrap_or(u64::MAX))
            }
        };
        match Self::list_as(dir, DirLayout::IdExtd, max) {
            Err(ListStop::Status(s)) if is_unsupported_class(s) => {}
            Err(s) => return Err(stop(s)),
            Ok(l) => return Ok(l),
        }
        Self::list_as(dir, DirLayout::Full, max).map_err(stop)
    }

    /// One complete listing in `layout`. Stops with [`ListStop::TooMany`] at the first batch
    /// that brings the count over `max`, so at most `max` names plus one batch are held.
    fn list_as(
        dir: BorrowedHandle<'_>,
        layout: DirLayout,
        max: usize,
    ) -> Result<Vec<Listed>, ListStop> {
        let mut out = Vec::new();
        let mut restart = true;
        while let Some(buf) = nt::query_dir(dir, restart, layout).map_err(ListStop::Status)? {
            restart = false;
            let batch = name::parse_dir_entries(&buf, layout).ok_or(ListStop::Malformed)?;
            out.extend(batch.into_iter().filter(|l| !name::is_dot_entry(&l.name)));
            if out.len() > max {
                return Err(ListStop::TooMany);
            }
        }
        Ok(out)
    }

    /// D8: metadata of every listed entry, reopened by its raw name relative to `dir`. An
    /// entry whose reopen is denied is described from the listing (restricted).
    fn entries(
        dir: BorrowedHandle<'_>,
        listed: Vec<Listed>,
        target: &str,
    ) -> SysResult<Vec<DirEntry>> {
        let mut out = Vec::with_capacity(listed.len());
        for l in listed {
            let shown = String::from_utf16_lossy(&l.name);
            // Raw from disk: in an error only escaped (module docs of `sys::fs`).
            let t = entry_target(target, &shown);
            // A name from disk that is not a single segment cannot be reopened safely.
            let seg = Seg16::from_units(l.name.clone())
                .ok_or_else(|| err(SysErrorKind::Other, target))?;
            let meta = match open_entry(dir, &seg, Access::Attributes, &t) {
                Ok(o) => meta_of(o.handle.as_handle(), o.tag, &t)?,
                // Vanished between listing and reopen (or renamed: L1 mismatch), or in legacy
                // delete-pending state: it is being removed (ADR 0017, A6).
                Err(e) if e.kind == SysErrorKind::NotFound => continue,
                Err(e) if e.ntstatus == Some(STATUS_DELETE_PENDING) => continue,
                Err(e) if e.kind == SysErrorKind::AccessDenied => match restricted_meta(&l) {
                    Some(m) => m,
                    None => return Err(e),
                },
                Err(e) => return Err(e),
            };
            out.push(DirEntry { name: shown, meta });
        }
        Ok(out)
    }

    /// `metadata` of an entry whose attribute open was denied: the description of the same
    /// name in the listing of its parent (`parents` below this handle, `walked` the parent
    /// handle of the walk that was denied), as `read_dir` reports it. `Ok(None)` if the
    /// listing has no such long name (e.g. it was an 8.3 short name); `denied` if the listing
    /// has no file ID (fail closed). The parent is reopened for listing by a second walk; it
    /// must be the same object as `walked` (volume serial and file ID), else `Busy`.
    fn restricted_lookup(
        &self,
        parents: &[&str],
        walked: BorrowedHandle<'_>,
        seg: &Seg16,
        denied: SysError,
    ) -> SysResult<Option<Metadata>> {
        let t = denied.target.clone();
        let listed = if parents.is_empty() {
            let _guard = self.listing.lock().unwrap_or_else(PoisonError::into_inner);
            Self::list(self.h(), usize::MAX, &t)?
        } else {
            let rel = RelPath::parse(&parents.join("\\"))
                .map_err(|_| err(SysErrorKind::InvalidPath, &t))?;
            let parent = self.open_dir_handle(&rel)?;
            if file_id(parent.as_handle(), &t)? != file_id(walked, &t)? {
                return Err(err(SysErrorKind::Busy, &t));
            }
            Self::list(parent.as_handle(), usize::MAX, &t)?
        };
        match find_listed(listed, seg) {
            None => Ok(None),
            Some(l) => restricted_meta(&l).map(Some).ok_or(denied),
        }
    }
}

impl Dir for WinDir {
    fn info(&self) -> SysResult<RootInfo> {
        let t = HANDLE_TARGET;
        let h = self.h();
        if standard(h, t)?.delete_pending {
            return Err(err(SysErrorKind::NotFound, t));
        }
        // Name-based queries resolve the current path component by component; a concurrent
        // rename of an ancestor makes them fail transiently (found by the race contract), and
        // two queries can see two different moments. Both are taken in one attempt that must
        // agree; otherwise retried, finally `NotFound`.
        let (final_path, volume_path) =
            settle(|| names_of(h), |e| e.kind == SysErrorKind::NotFound)?;
        let (volume_serial, file_id) = file_id(h, t)?;
        let user_writable = token::user_writable(h).map_err(|c| win32_error(c, t))?;
        let case_sensitive = match nt::query_info(h, FileCaseSensitiveInformation, 4) {
            Ok(b) => u32_at(&b, 0).is_some_and(|f| f & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0),
            Err(s) if is_unsupported_class(s) => false,
            Err(s) => return Err(nt_error(s, t)),
        };
        let (fs_name, flags) = nt::volume_info(h).map_err(|c| win32_info_error(c, t))?;
        Ok(RootInfo {
            final_path,
            volume_serial,
            file_id,
            user_writable,
            case_sensitive,
            volume_path,
            fs_kind: fs_kind(&String::from_utf16_lossy(&fs_name)),
            supports_posix_rename: flags & FILE_SUPPORTS_POSIX_UNLINK_RENAME != 0,
        })
    }

    fn open_dir(&self, p: &RelPath) -> SysResult<Box<dyn Dir + '_>> {
        self.ensure_live()?;
        Ok(Box::new(WinDir::new(self.open_dir_handle(p)?)))
    }

    fn metadata(&self, p: &RelPath) -> SysResult<Option<Metadata>> {
        let t = p.as_str();
        // A deleted handle is an error, not a missing entry.
        self.ensure_live()?;
        let absent =
            |e: &SysError| matches!(e.kind, SysErrorKind::NotFound | SysErrorKind::InvalidPath);
        let (parent, last) = match self.split(p) {
            Ok(x) => x,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let parent = parent.as_ref().map_or(self.h(), AsHandle::as_handle);
        let s = seg16(last, t)?;
        match open_entry(parent, &s, Access::Attributes, t) {
            Ok(o) => meta_of(o.handle.as_handle(), o.tag, t).map(Some),
            Err(e) if absent(&e) => Ok(None),
            Err(e) if e.kind == SysErrorKind::AccessDenied => {
                let segs: Vec<&str> = p.segments().collect();
                let parents = segs.split_last().map_or(&[][..], |(_, rest)| rest);
                self.restricted_lookup(parents, parent, &s, e)
            }
            Err(e) => Err(e),
        }
    }

    fn open_read(&self, p: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>> {
        let t = p.as_str();
        self.ensure_live()?;
        let (parent, last) = self.split(p)?;
        let parent = parent.as_ref().map_or(self.h(), AsHandle::as_handle);
        let s = seg16(last, t)?;
        let first = open_entry(parent, &s, Access::Read, t)?;
        match first.tag.kind() {
            EntryKind::Dir => return Err(err(SysErrorKind::AccessDenied, t)),
            EntryKind::Reparse => return Err(err(SysErrorKind::ReparsePoint, t)),
            EntryKind::File => {}
        }
        // Never hydrate a placeholder (ADR 0007, M4).
        if first.tag.needs_recall() {
            return Err(err(SysErrorKind::Unsupported, t));
        }
        let handle = if first.tag.tag.is_some() {
            // Allowlisted data tag: the data is only visible without FILE_OPEN_REPARSE_POINT.
            // Reopen relative to the same parent and require the same object.
            let data =
                nt::open_relative(parent, &s, RelOpen::Data).map_err(|st| nt_error(st, t))?;
            if file_id(data.as_handle(), t)? != file_id(first.handle.as_handle(), t)? {
                return Err(err(SysErrorKind::Busy, t));
            }
            // The attributes seen through the data handle may differ (a cloud placeholder in
            // compatibility mode, a recall flag set in between): check them again.
            if tag_info(data.as_handle(), t)?.needs_recall() {
                return Err(err(SysErrorKind::Unsupported, t));
            }
            data
        } else {
            first.handle
        };
        Ok(Box::new(std::fs::File::from(handle)))
    }

    fn read_dir_limited(
        &self,
        p: Option<&RelPath>,
        max_entries: usize,
    ) -> SysResult<Vec<DirEntry>> {
        self.ensure_live()?;
        match p {
            None => {
                let names = {
                    let _guard = self.listing.lock().unwrap_or_else(PoisonError::into_inner);
                    Self::list(self.h(), max_entries, HANDLE_TARGET)?
                };
                Self::entries(self.h(), names, HANDLE_TARGET)
            }
            Some(p) => {
                let dir = self.open_dir_handle(p)?;
                let names = Self::list(dir.as_handle(), max_entries, p.as_str())?;
                Self::entries(dir.as_handle(), names, p.as_str())
            }
        }
    }

    fn users(&self, p: &RelPath) -> SysResult<Vec<u32>> {
        let t = p.as_str();
        self.ensure_live()?;
        let (parent, last) = self.split(p)?;
        let parent = parent.as_ref().map_or(self.h(), AsHandle::as_handle);
        let s = seg16(last, t)?;
        // Attribute-only, relative, never through or at a reparse point: no share mode blocks
        // it, and it never opens the data.
        let o = open_entry(parent, &s, Access::Attributes, t)?;
        match o.tag.kind() {
            EntryKind::File => process_ids(o.handle.as_handle(), t),
            EntryKind::Dir => Err(err(SysErrorKind::AccessDenied, t)),
            EntryKind::Reparse => Err(err(SysErrorKind::ReparsePoint, t)),
        }
    }
}

impl DirWrite for WinDir {
    fn open_dir_write(&self, p: &RelPath) -> SysResult<Box<dyn DirWrite + '_>> {
        self.ensure_live()?;
        Ok(Box::new(WinDir::new(self.open_dir_handle(p)?)))
    }

    fn guard(&self, _: &RelPath) -> SysResult<Box<dyn FileGuard + '_>> {
        Err(err(SysErrorKind::Unsupported, NO_WRITE))
    }

    fn create_new(&self, _: &RelPath, _: &mut dyn Read, _: &NewFile) -> SysResult<Written> {
        Err(err(SysErrorKind::Unsupported, NO_WRITE))
    }

    fn create_dir(&self, _: &RelPath) -> SysResult<u128> {
        Err(err(SysErrorKind::Unsupported, NO_WRITE))
    }

    fn remove_dir(&self, _: &RelPath, _: u128) -> SysResult<()> {
        Err(err(SysErrorKind::Unsupported, NO_WRITE))
    }

    fn flush(&self) -> SysResult<()> {
        Err(err(SysErrorKind::Unsupported, NO_WRITE))
    }

    fn lock(&self, _: &RelPath) -> SysResult<Box<dyn FileLock + '_>> {
        Err(err(SysErrorKind::Unsupported, NO_WRITE))
    }
}

/// `final_path` and `volume_path` of `h`, taken together. D6: `volume_path` only from
/// `FileNormalizedNameInformation`, no fallback. The final path must end component-wise with
/// the volume path (case-insensitively via the crate's fold); if it does not, the two queries
/// saw different moments of a concurrent rename: `NotFound`, which `info` retries.
fn names_of(h: BorrowedHandle<'_>) -> SysResult<(PathBuf, String)> {
    let t = HANDLE_TARGET;
    let raw = nt::final_path(h).map_err(|c| win32_error(c, t))?;
    let final_path = PathBuf::from(OsString::from_wide(&raw));
    if !is_drive_final_path(&final_path) {
        return Err(err(SysErrorKind::Other, &final_path.display().to_string()));
    }
    let normalized = name_info(h, FileNormalizedNameInformation).map_err(|s| nt_error(s, t))?;
    let volume_path = name::volume_path(&normalized).ok_or_else(|| err(SysErrorKind::Other, t))?;
    if !ends_with_components(&final_path.to_string_lossy(), &volume_path) {
        return Err(err(SysErrorKind::NotFound, t));
    }
    Ok((final_path, volume_path))
}

/// `full` (`\\?\X:\a\b\c`) ends with the components of `tail` (`b\c`; `""` always matches).
fn ends_with_components(full: &str, tail: &str) -> bool {
    let tail: Vec<&str> = tail.split('\\').filter(|s| !s.is_empty()).collect();
    let full: Vec<&str> = full.split('\\').filter(|s| !s.is_empty()).collect();
    full.len() >= tail.len()
        && full[full.len() - tail.len()..]
            .iter()
            .zip(&tail)
            .all(|(a, b)| a == b || fold(a) == fold(b))
}

/// Attempts of [`settle`].
const SETTLE_ATTEMPTS: u32 = 32;

/// Retries a name-based query of a live handle while it fails with a `transient` error (an
/// ancestor is being renamed at that moment), at most [`SETTLE_ATTEMPTS`] times, yielding in
/// between. The last error is returned; a deleted handle is caught before by `info`.
fn settle<T, E>(
    mut f: impl FnMut() -> Result<T, E>,
    transient: impl Fn(&E) -> bool,
) -> Result<T, E> {
    let mut attempt = 1;
    loop {
        match f() {
            Err(e) if transient(&e) && attempt < SETTLE_ATTEMPTS => {
                attempt += 1;
                std::thread::yield_now();
            }
            r => return r,
        }
    }
}

/// `\\?\X:\…` (the shape `RootInfo::final_path` promises).
fn is_drive_final_path(p: &Path) -> bool {
    p.to_str()
        .and_then(|s| s.strip_prefix(r"\\?\"))
        .is_some_and(|s| {
            let b = s.as_bytes();
            b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
        })
}

/// File system name from `GetVolumeInformationByHandleW`.
fn fs_kind(name: &str) -> FsKind {
    match name {
        "NTFS" => FsKind::Ntfs,
        "ReFS" => FsKind::Refs,
        "FAT" | "FAT32" => FsKind::Fat,
        "exFAT" => FsKind::ExFat,
        _ => FsKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::{SysErrorKind, ends_with_components, entry_target, err, parse_process_ids};

    /// `FILE_PROCESS_IDS_USING_FILE_INFORMATION` as the kernel writes it on this target.
    fn reply(count: u32, ids: &[u64]) -> Vec<u8> {
        const PTR: usize = size_of::<usize>();
        let mut b = vec![0u8; PTR];
        b[..4].copy_from_slice(&count.to_le_bytes());
        for id in ids {
            b.extend_from_slice(&id.to_le_bytes()[..PTR]);
        }
        b
    }

    #[test]
    fn process_id_replies_are_parsed_strictly() {
        assert_eq!(parse_process_ids(&reply(0, &[])), Some(vec![]));
        assert_eq!(
            parse_process_ids(&reply(3, &[1200, 4, 1200])),
            Some(vec![4, 1200])
        );
        // Shorter than its count, or no count at all.
        assert_eq!(parse_process_ids(&reply(2, &[4])), None);
        assert_eq!(parse_process_ids(&[1, 0]), None);
        // A huge count never allocates up front.
        assert_eq!(parse_process_ids(&reply(u32::MAX, &[4])), None);
        if size_of::<usize>() == 8 {
            assert_eq!(parse_process_ids(&reply(1, &[1 << 32])), None);
        }
    }

    /// A raw name from a listing (LX symlink with a bidi override, a newline, an escape
    /// sequence) never reaches an error message unescaped, also on the error paths of the
    /// attribute reopen in `entries`.
    #[test]
    fn listed_names_are_escaped_in_error_targets() {
        for raw in ["evil\u{202E}gpj.exe", "a\nb", "\u{1b}[31m", "plain.acf"] {
            let t = entry_target(r"steamapps", raw);
            assert_eq!(t, format!("steamapps: entry {raw:?}"));
            let shown = err(SysErrorKind::Other, &t).to_string();
            for c in ['\u{202E}', '\n', '\u{1b}'] {
                assert!(!shown.contains(c), "{shown:?}");
            }
        }
        assert_eq!(
            entry_target("steamapps", "evil\u{202E}gpj.exe"),
            r#"steamapps: entry "evil\u{202e}gpj.exe""#
        );
    }

    #[test]
    fn final_path_must_end_with_the_volume_path() {
        let full = r"\\?\D:\Mounts\Data\Steam";
        for ok in [
            "",
            "Steam",
            r"Data\Steam",
            r"data\STEAM",
            r"Mounts\Data\Steam",
        ] {
            assert!(ends_with_components(full, ok), "{ok}");
        }
        for bad in [
            "Stea",
            "team",
            r"Other\Steam",
            r"X\Mounts\Data\Steam\Steam",
            "Data",
        ] {
            assert!(!ends_with_components(full, bad), "{bad}");
        }
    }
}
