//! The write primitives of `sys::win` ([`PrimDir`] for [`WinDir`], [`PrimFile`] for
//! [`WinFile`], ADR 0017 A1); the sequences themselves live in `sys::seq`. No `unsafe`: every
//! system call goes through [`super::nt`].
//!
//! The rules that belong to one call stay here (A1): every name is re-asserted as one segment
//! (`Seg16`: no `\`, `/`, `:` or NUL) before it reaches the kernel; every open is relative to
//! the directory handle with `OBJ_DONT_REPARSE` and opens the entry itself
//! (`FILE_OPEN_REPARSE_POINT`; the only exception is the guard's data reopen of an
//! allowlisted data tag, compared by file ID); a rename collision is `Busy`, a create
//! collision `AlreadyExists`; a delete is always POSIX with `IGNORE_READONLY_ATTRIBUTE`.
//! [`HeldState`] and the name come only from the held handle itself, the name and the
//! directory's volume name both from `FileNameInformation`.

use std::fs::File;
use std::io::Write;
use std::os::windows::fs::FileExt;
use std::os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle};

use windows_sys::Wdk::Storage::FileSystem::FileNameInformation;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
};

use super::super::name::Seg16;
use super::super::nt::{self, Access, RelOpen, SetInfo};
use super::super::status::{nt_error, rename_error, win32_info_error};
use super::{
    FILE_SUPPORTS_POSIX_UNLINK_RENAME, WinDir, case_sensitive, check_long_name, err, file_id,
    name_info, process_ids, seg16, standard, tag_info,
};
use crate::sys::fs::{Attrs, Dir, EntryKind, Metadata, tag};
use crate::sys::seq::{HeldState, PrimDir, PrimFile, Seg, Support};
use crate::sys::{SysError, SysErrorKind, SysResult};

/// Target shown for errors about a held handle.
const HELD: &str = "<held>";

/// ntifs.h `FILE_ATTRIBUTE_VALID_SET_FLAGS`: what `FileBasicInformation` may set.
const VALID_SET_FLAGS: u32 = 0x0000_31a7;

/// A held file or directory handle of the write side (a guard, `<tmp>`, a lock, a directory
/// opened for deleting). Closed on drop; a POSIX delete set on it removes the name at once.
#[derive(Debug)]
pub(crate) struct WinFile {
    file: File,
}

impl WinFile {
    fn new(h: OwnedHandle) -> Self {
        Self {
            file: File::from(h),
        }
    }

    fn h(&self) -> BorrowedHandle<'_> {
        self.file.as_handle()
    }
}

/// `FileNameInformation` of `h` as a string: the path below the volume root with a leading
/// `\` (`\` alone for the root). A name that is not valid UTF-16 is `Other` (fail closed: it
/// can never equal a name built from a `RelPath`).
fn volume_name_of(h: BorrowedHandle<'_>, target: &str) -> SysResult<String> {
    let units = name_info(h, FileNameInformation).map_err(|s| nt_error(s, target))?;
    String::from_utf16(&units).map_err(|_| err(SysErrorKind::Other, target))
}

/// The attribute-only classification of `name` after an open was denied: a link at the name
/// is `ReparsePoint` (it is never followed or created through), anything else keeps `denied`.
fn classify_denied(dir: BorrowedHandle<'_>, s: &Seg16, t: &str, denied: SysError) -> SysError {
    match nt::open_relative(dir, s, RelOpen::Entry(Access::Attributes)) {
        Ok(h) => match tag_info(h.as_handle(), t) {
            Ok(ti) if ti.kind() == EntryKind::Reparse => {
                let e = err(SysErrorKind::ReparsePoint, t);
                match denied.ntstatus {
                    Some(st) => e.with_ntstatus(st),
                    None => e,
                }
            }
            _ => denied,
        },
        Err(_) => denied,
    }
}

impl PrimDir for WinDir {
    type File = WinFile;

    fn support(&self) -> SysResult<Support> {
        let t = super::HANDLE_TARGET;
        let case_sensitive = case_sensitive(self.h(), t)?;
        let (_, flags) = nt::volume_info(self.h()).map_err(|c| win32_info_error(c, t))?;
        Ok(Support {
            case_sensitive,
            posix: flags & FILE_SUPPORTS_POSIX_UNLINK_RENAME != 0,
        })
    }

    fn volume_name(&self) -> SysResult<String> {
        volume_name_of(self.h(), super::HANDLE_TARGET)
    }

    fn lookup(&self, name: Seg<'_>) -> SysResult<Option<Metadata>> {
        Dir::metadata(self, name.rel())
    }

    /// Opens the entry itself for a guard and checks its long name (L1). A file with an
    /// allowlisted data tag (WOF, dedup) is reopened without `FILE_OPEN_REPARSE_POINT`, so the
    /// guard reads, hashes and backs up its real data; the reopen must be the same file (file
    /// ID, else `Busy`). A placeholder whose data would be recalled is `Unsupported`, like
    /// `open_read` (ADR 0007, M4).
    fn open_guard(&self, name: Seg<'_>) -> SysResult<WinFile> {
        let t = name.as_str();
        let s = seg16(t, t)?;
        let first =
            nt::open_relative(self.h(), &s, RelOpen::Guard).map_err(|st| nt_error(st, t))?;
        check_long_name(first.as_handle(), &s, t)?;
        let ti = tag_info(first.as_handle(), t)?;
        if ti.kind() != EntryKind::File {
            // The sequence refuses it on the handle (directory, link).
            return Ok(WinFile::new(first));
        }
        if ti.needs_recall() {
            return Err(err(SysErrorKind::Unsupported, t));
        }
        if !ti.tag.is_some_and(tag::is_allowed_data_tag) {
            return Ok(WinFile::new(first));
        }
        // The guard shares read only, so the data reopen (also with DELETE) needs the first
        // handle closed; the file ID ties the two together.
        let id = file_id(first.as_handle(), t)?;
        drop(first);
        let data =
            nt::open_relative(self.h(), &s, RelOpen::GuardData).map_err(|st| nt_error(st, t))?;
        check_long_name(data.as_handle(), &s, t)?;
        if file_id(data.as_handle(), t)? != id {
            return Err(err(SysErrorKind::Busy, t));
        }
        if tag_info(data.as_handle(), t)?.needs_recall() {
            return Err(err(SysErrorKind::Unsupported, t));
        }
        Ok(WinFile::new(data))
    }

    fn create_tmp(&self, name: Seg<'_>) -> SysResult<WinFile> {
        let t = name.as_str();
        let s = seg16(t, t)?;
        let h =
            nt::open_relative(self.h(), &s, RelOpen::CreateTmp).map_err(|st| nt_error(st, t))?;
        Ok(WinFile::new(h))
    }

    /// `FILE_OPEN_IF` as the plain file `name`: a directory or a link to one is refused by the
    /// open (`FILE_IS_A_DIRECTORY`) and classified: a link is `ReparsePoint`, a directory
    /// `AccessDenied`; a file link is opened as itself and refused by the sequence.
    fn open_lock(&self, name: Seg<'_>) -> SysResult<WinFile> {
        let t = name.as_str();
        let s = seg16(t, t)?;
        let h = match nt::open_relative(self.h(), &s, RelOpen::Lock) {
            Ok(h) => h,
            Err(st) => {
                let e = nt_error(st, t);
                return Err(if e.kind == SysErrorKind::AccessDenied {
                    classify_denied(self.h(), &s, t, e)
                } else {
                    e
                });
            }
        };
        check_long_name(h.as_handle(), &s, t)?;
        Ok(WinFile::new(h))
    }

    fn create_dir(&self, name: Seg<'_>) -> SysResult<u128> {
        let t = name.as_str();
        let s = seg16(t, t)?;
        let h =
            nt::open_relative(self.h(), &s, RelOpen::CreateDir).map_err(|st| nt_error(st, t))?;
        Ok(file_id(h.as_handle(), t)?.1)
    }

    fn open_dir_delete(&self, name: Seg<'_>) -> SysResult<WinFile> {
        let t = name.as_str();
        let s = seg16(t, t)?;
        let h =
            nt::open_relative(self.h(), &s, RelOpen::DirDelete).map_err(|st| nt_error(st, t))?;
        check_long_name(h.as_handle(), &s, t)?;
        Ok(WinFile::new(h))
    }

    /// `FileRenameInformationEx` on `f` with `RootDirectory` = this handle, flags 0. An error
    /// means nothing was renamed (the class acts completely or not at all).
    fn rename(&self, f: &WinFile, name: Seg<'_>) -> SysResult<()> {
        let t = name.as_str();
        let s = seg16(t, t)?;
        nt::set_info(
            f.h(),
            SetInfo::Rename {
                root: self.h(),
                name: &s,
            },
        )
        .map_err(|st| rename_error(st, t))
    }

    fn flush(&self) -> SysResult<()> {
        let t = super::HANDLE_TARGET;
        let h = nt::open_self_for_flush(self.h()).map_err(|st| nt_error(st, t))?;
        nt::flush(h.as_handle()).map_err(|st| nt_error(st, t))
    }
}

impl PrimFile for WinFile {
    fn state(&self) -> SysResult<HeldState> {
        let h = self.h();
        let ti = tag_info(h, HELD)?;
        let std_info = standard(h, HELD)?;
        let (_, id) = file_id(h, HELD)?;
        let kind = ti.kind();
        Ok(HeldState {
            kind,
            links: if ti.is_dir() { 1 } else { std_info.links },
            attrs: attrs_of(ti.attrs),
            len: if kind == EntryKind::File {
                std_info.len
            } else {
                0
            },
            file_id: id,
            reparse_tag: ti.tag,
        })
    }

    fn name(&self) -> SysResult<String> {
        volume_name_of(self.h(), HELD)
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> SysResult<usize> {
        loop {
            match self.file.seek_read(buf, off) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                // ERROR_HANDLE_EOF: reading at or past the end.
                Err(e) if e.raw_os_error() == Some(38) => return Ok(0),
                Err(e) => return Err(SysError::io(&e, HELD)),
            }
        }
    }

    fn users(&self) -> SysResult<Vec<u32>> {
        process_ids(self.h(), HELD)
    }

    fn write(&mut self, buf: &[u8]) -> SysResult<()> {
        self.file.write_all(buf).map_err(|e| SysError::io(&e, HELD))
    }

    /// R/H/S as requested, every other attribute as it is (only the flags
    /// `FileBasicInformation` may set); `FILE_ATTRIBUTE_NORMAL` when none remains, because 0
    /// means "no change".
    fn set_attrs(&self, attrs: Attrs) -> SysResult<()> {
        const RHS: u32 = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
        let current = tag_info(self.h(), HELD)?.attrs;
        let mut bits = current & VALID_SET_FLAGS & !RHS & !FILE_ATTRIBUTE_NORMAL;
        for (on, bit) in [
            (attrs.readonly, FILE_ATTRIBUTE_READONLY),
            (attrs.hidden, FILE_ATTRIBUTE_HIDDEN),
            (attrs.system, FILE_ATTRIBUTE_SYSTEM),
        ] {
            if on {
                bits |= bit;
            }
        }
        if bits == 0 {
            bits = FILE_ATTRIBUTE_NORMAL;
        }
        nt::set_info(self.h(), SetInfo::Attributes(bits)).map_err(|st| nt_error(st, HELD))
    }

    fn flush(&self) -> SysResult<()> {
        nt::flush(self.h()).map_err(|st| nt_error(st, HELD))
    }

    /// POSIX delete with `IGNORE_READONLY_ATTRIBUTE`; an image section is
    /// `STATUS_CANNOT_DELETE` (`Busy`), a non-empty directory `NotEmpty`.
    fn posix_delete(&self) -> SysResult<()> {
        nt::set_info(self.h(), SetInfo::PosixDelete).map_err(|st| nt_error(st, HELD))
    }
}

/// Read-only, hidden and system of a raw attribute word.
fn attrs_of(a: u32) -> Attrs {
    Attrs {
        readonly: a & FILE_ATTRIBUTE_READONLY != 0,
        hidden: a & FILE_ATTRIBUTE_HIDDEN != 0,
        system: a & FILE_ATTRIBUTE_SYSTEM != 0,
    }
}
