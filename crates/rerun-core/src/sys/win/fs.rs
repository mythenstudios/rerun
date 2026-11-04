//! [`WinFs`] and [`WinDir`]: the real, read-only file system (ADR 0007). No `unsafe` here;
//! every system call goes through [`super::nt`] or [`super::token`].
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
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_INFORMATION_CLASS, FileAttributeTagInformation, FileCaseSensitiveInformation,
    FileIdInformation, FileNameInformation, FileNormalizedNameInformation, FileStandardInformation,
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
    NtStatus, STATUS_UNSUCCESSFUL, is_unsupported_class, nt_error, win32_error, win32_info_error,
};
use super::token;
use crate::path::RelPath;
use crate::sys::fs::{
    Attrs, Dir, DirEntry, EntryKind, Fs, FsKind, Metadata, ReadSeek, ReparseInfo, RootInfo, tag,
};
use crate::sys::{SysError, SysErrorKind, SysResult};

/// Message of every write method in phase 1.
const READ_ONLY: &str = "sys::win is read-only in phase 1";
/// Target shown for errors about the handle itself.
const HANDLE_TARGET: &str = "<dir handle>";

/// winnt.h `FILE_SUPPORTS_POSIX_UNLINK_RENAME`.
const FILE_SUPPORTS_POSIX_UNLINK_RENAME: u32 = 0x0000_0400;
/// ntifs.h `FILE_CS_FLAG_CASE_SENSITIVE_DIR`.
const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 0x0000_0001;

fn err(kind: SysErrorKind, target: &str) -> SysError {
    SysError::new(kind, target)
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
/// if the file system does not support that class (FAT), `FileNameInformation`. A mismatch
/// is `NotFound`: the requested name is not the long name of the entry.
fn check_long_name(h: BorrowedHandle<'_>, seg: &Seg16, target: &str) -> SysResult<()> {
    let reported = match name_info(h, FileNormalizedNameInformation) {
        Ok(n) => n,
        Err(s) if is_unsupported_class(s) => {
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

/// Link target of a name surrogate (print name), read on its `FILE_OPEN_REPARSE_POINT` handle.
fn link_target(h: BorrowedHandle<'_>, target: &str) -> SysResult<Option<String>> {
    let buf = nt::reparse_data(h).map_err(|c| win32_error(c, target))?;
    reparse::parse(&buf)
        .map(|p| p.target)
        .map_err(|_| err(SysErrorKind::Other, target))
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

/// The real file system (`Fs`). Read-only in phase 1.
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
        Ok(Box::new(WinDir::new(handle)))
    }
}

/// An open directory of the real file system. Read-only in phase 1: every write method
/// returns `Unsupported`.
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

    /// Lists `dir` (raw UTF-16 names, without `.` and `..`). `FileIdExtdDirectoryInformation`;
    /// only if the file system does not support that class (FAT) on the first call,
    /// `FileFullDirectoryInformation` (no file IDs).
    fn list(dir: BorrowedHandle<'_>, target: &str) -> SysResult<Vec<Listed>> {
        match Self::list_as(dir, DirLayout::IdExtd) {
            Err(Some(s)) if is_unsupported_class(s) => {}
            Err(Some(s)) => return Err(nt_error(s, target)),
            Err(None) => return Err(err(SysErrorKind::Other, target)),
            Ok(l) => return Ok(l),
        }
        Self::list_as(dir, DirLayout::Full).map_err(|s| match s {
            Some(s) => nt_error(s, target),
            None => err(SysErrorKind::Other, target),
        })
    }

    /// One complete listing in `layout`; `Err(None)` for a malformed buffer.
    fn list_as(
        dir: BorrowedHandle<'_>,
        layout: DirLayout,
    ) -> Result<Vec<Listed>, Option<NtStatus>> {
        let mut out = Vec::new();
        let mut restart = true;
        while let Some(buf) = nt::query_dir(dir, restart, layout).map_err(Some)? {
            restart = false;
            let batch = name::parse_dir_entries(&buf, layout).ok_or(None)?;
            out.extend(batch.into_iter().filter(|l| !name::is_dot_entry(&l.name)));
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
            // A name from disk that is not a single segment cannot be reopened safely.
            let seg = Seg16::from_units(l.name.clone())
                .ok_or_else(|| err(SysErrorKind::Other, target))?;
            let meta = match open_entry(dir, &seg, Access::Attributes, &shown) {
                Ok(o) => meta_of(o.handle.as_handle(), o.tag, &shown)?,
                // Vanished between listing and reopen (or renamed: L1 mismatch).
                Err(e) if e.kind == SysErrorKind::NotFound => continue,
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
    /// name in the listing of its parent (`parents` below this handle), as `read_dir` reports
    /// it. `Ok(None)` if the listing has no such long name (e.g. it was an 8.3 short name);
    /// `denied` if the listing has no file ID (fail closed).
    fn restricted_lookup(
        &self,
        parents: &[&str],
        seg: &Seg16,
        denied: SysError,
    ) -> SysResult<Option<Metadata>> {
        let t = denied.target.clone();
        let listed = if parents.is_empty() {
            let _guard = self.listing.lock().unwrap_or_else(PoisonError::into_inner);
            Self::list(self.h(), &t)?
        } else {
            let rel = RelPath::parse(&parents.join("\\"))
                .map_err(|_| err(SysErrorKind::InvalidPath, &t))?;
            let parent = self.open_dir_handle(&rel)?;
            Self::list(parent.as_handle(), &t)?
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
        let final_path = nt::final_path(h).map_err(|c| win32_error(c, t))?;
        let final_path = PathBuf::from(OsString::from_wide(&final_path));
        if !is_drive_final_path(&final_path) {
            return Err(err(SysErrorKind::Other, &final_path.display().to_string()));
        }
        let (volume_serial, file_id) = file_id(h, t)?;
        let user_writable = token::user_writable(h).map_err(|c| win32_error(c, t))?;
        let case_sensitive = match nt::query_info(h, FileCaseSensitiveInformation, 4) {
            Ok(b) => u32_at(&b, 0).is_some_and(|f| f & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0),
            Err(s) if is_unsupported_class(s) => false,
            Err(s) => return Err(nt_error(s, t)),
        };
        // D6: only FileNormalizedNameInformation, no fallback.
        let normalized = name_info(h, FileNormalizedNameInformation).map_err(|s| nt_error(s, t))?;
        let volume_path =
            name::volume_path(&normalized).ok_or_else(|| err(SysErrorKind::Other, t))?;
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
                self.restricted_lookup(parents, &s, e)
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
            data
        } else {
            first.handle
        };
        Ok(Box::new(std::fs::File::from(handle)))
    }

    fn read_dir(&self, p: Option<&RelPath>) -> SysResult<Vec<DirEntry>> {
        self.ensure_live()?;
        match p {
            None => {
                let names = {
                    let _guard = self.listing.lock().unwrap_or_else(PoisonError::into_inner);
                    Self::list(self.h(), HANDLE_TARGET)?
                };
                Self::entries(self.h(), names, HANDLE_TARGET)
            }
            Some(p) => {
                let dir = self.open_dir_handle(p)?;
                let names = Self::list(dir.as_handle(), p.as_str())?;
                Self::entries(dir.as_handle(), names, p.as_str())
            }
        }
    }

    fn create_new(&self, _: &RelPath, _: &[u8]) -> SysResult<()> {
        Err(err(SysErrorKind::Unsupported, READ_ONLY))
    }

    fn replace(&self, _: &RelPath, _: &[u8], _: &str) -> SysResult<()> {
        Err(err(SysErrorKind::Unsupported, READ_ONLY))
    }

    fn create_dir(&self, _: &RelPath) -> SysResult<()> {
        Err(err(SysErrorKind::Unsupported, READ_ONLY))
    }

    fn remove_file(&self, _: &RelPath) -> SysResult<()> {
        Err(err(SysErrorKind::Unsupported, READ_ONLY))
    }

    fn remove_dir(&self, _: &RelPath) -> SysResult<()> {
        Err(err(SysErrorKind::Unsupported, READ_ONLY))
    }

    fn rename(&self, _: &RelPath, _: &RelPath) -> SysResult<()> {
        Err(err(SysErrorKind::Unsupported, READ_ONLY))
    }

    fn set_readonly(&self, _: &RelPath, _: bool) -> SysResult<()> {
        Err(err(SysErrorKind::Unsupported, READ_ONLY))
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
