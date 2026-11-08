//! The result file writer (ADR 0022 amendment P3-2, D5, B13): the one wrapper module of the
//! shim's file writes. `CreateFileW`, `CreateDirectoryW` and `SetFileInformationByHandle` are
//! banned (ADR 0007, ADR 0017) and called here and nowhere else in `rerun-launch`.
//!
//! `<base>\Rerun\launch\<id>.result`, `<base>` being `LocalAppData` from the known folder:
//! 1. `Rerun` is opened as itself (`FILE_FLAG_OPEN_REPARSE_POINT`) and refused unless it is a
//!    directory without a reparse point; it is never created (no Rerun folder, no result).
//! 2. `launch` likewise; created with `CreateDirectoryW` if missing, then opened and checked.
//!    Both handles are kept without `FILE_SHARE_DELETE` until the end: neither folder, nor any
//!    folder above them, can be **renamed** while they are open. That does not stop a change of
//!    the folder itself: an empty `launch` can still be made a mount point
//!    (`FSCTL_SET_REPARSE_POINT` needs only `FILE_WRITE_ATTRIBUTES`, which no share mode
//!    protects; measured on build 26300). Step 3 catches that before the first byte.
//! 3. A temp file `<id>.<pid>-<nanos>.tmp` is created new (`CREATE_NEW`, so never an existing
//!    entry or link, share mode 0), and its final path must be the `launch` handle's final path
//!    plus its name (else [`OsError::Escaped`]; the temp file, wherever it landed, is then
//!    deleted by handle). Only then are the bytes written through its handle.
//! 4. An existing `<id>.result` that is a reparse point or not a file refuses the write.
//! 5. The temp file is renamed by its handle (`FileRenameInfoEx`, replace if exists, POSIX
//!    semantics) to the full path `<launch>\<id>.result`: `SetFileInformationByHandle` refuses
//!    a `RootDirectory` with 87 (measured on build 26300), and a bare name would be resolved
//!    against the current directory. A reader that holds the old file shared for delete does
//!    not block the replace; `rerun status` (core's `sys::win`) opens it shared for read only,
//!    so a replace during a concurrent `rerun status` fails with a sharing violation: harmless,
//!    the start is recorded as `Written::Failed` and the old result stays. The renamed file's
//!    final path is checked like the temp file's. Any failure after step 3 and before the
//!    rename marks the temp file for deletion by handle.
//!
//! No flush: the file is a status record, its loss on a power cut is harmless. Never called
//! when elevated (B13, `WinOs::write_result` checks again).

use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use rerun_proto::launch::MAX_RESULT_BYTES;
use rerun_proto::profile::ProfileId;
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_DATA,
    FileAttributeTagInfo, FileDispositionInfo, FileRenameInfoEx, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, OPEN_EXISTING, SYNCHRONIZE, SetFileInformationByHandle,
};

use super::{compare_ordinal_ignore_case, last_error};
use crate::os::OsError;

/// winbase.h `FILE_RENAME_FLAG_REPLACE_IF_EXISTS`.
const RENAME_REPLACE_IF_EXISTS: u32 = 0x1;
/// winbase.h `FILE_RENAME_FLAG_POSIX_SEMANTICS`.
const RENAME_POSIX_SEMANTICS: u32 = 0x2;
/// Longest final path read back, in UTF-16 units.
const MAX_FINAL_PATH: usize = 32_768;

fn wide(s: &[u16]) -> Vec<u16> {
    let mut v = s.to_vec();
    v.push(0);
    v
}

fn join(dir: &[u16], name: &str) -> Vec<u16> {
    let mut v = dir.to_vec();
    v.push(u16::from(b'\\'));
    v.extend(name.encode_utf16());
    v
}

/// `CreateFileW` with the flags of this module; the handle or the Win32 error.
fn create(
    path: &[u16],
    access: u32,
    share: u32,
    disposition: u32,
    flags: u32,
) -> Result<OwnedHandle, u32> {
    let p = wide(path);
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's result file writer (ADR 0022 amendment P3-2): every open is \
                  FILE_FLAG_OPEN_REPARSE_POINT below folders held without FILE_SHARE_DELETE"
    )]
    // SAFETY: `p` is a NUL-terminated UTF-16 path owned by this function and alive for the
    // call; null security attributes (default, not inheritable) and a null template are
    // documented inputs.
    let raw = unsafe {
        CreateFileW(
            p.as_ptr(),
            access,
            share,
            ptr::null(),
            disposition,
            flags,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(last_error());
    }
    // SAFETY: `raw` was just returned by a successful CreateFileW; this function owns it and
    // nothing else closes it.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// The attributes of an open handle (`FileAttributeTagInfo`).
fn attributes(h: &OwnedHandle) -> Result<u32, u32> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    let len = u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap_or(0);
    // SAFETY: `h` is a live file or directory handle with FILE_READ_ATTRIBUTES, kept alive by
    // the borrow; `info` is a writable FILE_ATTRIBUTE_TAG_INFO of `len` bytes.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h.as_raw_handle(),
            FileAttributeTagInfo,
            ptr::from_mut(&mut info).cast::<c_void>(),
            len,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(info.FileAttributes)
}

/// Opens the folder at `path` as itself and refuses a reparse point or a file. The handle is
/// shared for read and write, never for delete: the folder cannot be renamed while it is open.
fn open_dir(path: &[u16]) -> Result<OwnedHandle, OsError> {
    let h = create(
        path,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_EXISTING,
        // BACKUP_SEMANTICS only to open a directory: a non-elevated shim holds no backup
        // privilege to enable (M1).
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(OsError::Win32)?;
    let attrs = attributes(&h).map_err(OsError::Win32)?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(OsError::ReparsePoint);
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(OsError::NotAFile);
    }
    Ok(h)
}

/// The final path of a handle (`FILE_NAME_NORMALIZED`, DOS volume name), at most
/// [`MAX_FINAL_PATH`] units.
fn final_path(h: &impl AsRawHandle) -> Result<Vec<u16>, u32> {
    let mut buf = vec![0u16; MAX_FINAL_PATH];
    let cap = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `h` is a live handle kept alive by the borrow; `buf` is a writable buffer of
    // `cap` units.
    let n = unsafe {
        GetFinalPathNameByHandleW(
            h.as_raw_handle(),
            buf.as_mut_ptr(),
            cap,
            FILE_NAME_NORMALIZED,
        )
    };
    let n = usize::try_from(n).unwrap_or(usize::MAX);
    if n == 0 {
        return Err(last_error());
    }
    if n >= buf.len() {
        return Err(ERROR_FILENAME_EXCED_RANGE);
    }
    buf.truncate(n);
    Ok(buf)
}

/// winerror.h `ERROR_FILENAME_EXCED_RANGE`.
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
/// winerror.h `ERROR_INVALID_PARAMETER`.
const ERROR_INVALID_PARAMETER: u32 = 87;

/// The temp file: marked for deletion by handle on drop unless it was renamed.
struct Temp {
    file: File,
    renamed: bool,
}

impl Drop for Temp {
    fn drop(&mut self) {
        if !self.renamed {
            let info = FILE_DISPOSITION_INFO { DeleteFile: true };
            let len = u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(0);
            #[expect(
                clippy::disallowed_methods,
                reason = "rerun-launch's result writer deletes its own temp file by handle \
                          (ADR 0022 amendment P3-2)"
            )]
            // SAFETY: `self.file` holds the temp file's live handle, opened with DELETE;
            // `info` is a valid FILE_DISPOSITION_INFO of `len` bytes. Best effort: a failure
            // leaves a `.tmp` that `rerun status` ignores.
            unsafe {
                SetFileInformationByHandle(
                    self.file.as_raw_handle(),
                    FileDispositionInfo,
                    ptr::from_ref(&info).cast::<c_void>(),
                    len,
                )
            };
        }
    }
}

/// Renames the temp file by its handle to the full path `target`, replacing a file there.
/// `SetFileInformationByHandle` refuses a `RootDirectory` (87, measured), and a bare name
/// would be resolved against the current directory, so the target is the full path below the
/// folders held open.
fn rename(temp: &Temp, target: &[u16]) -> Result<(), u32> {
    let name_bytes = size_of_val(target);
    let name_at = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let len_at = std::mem::offset_of!(FILE_RENAME_INFO, FileNameLength);
    // The structure with the name and a NUL; `RootDirectory` stays null (zero).
    let total = name_at + name_bytes + size_of::<u16>();
    let len = u32::try_from(total).map_err(|_| ERROR_INVALID_PARAMETER)?;
    let name_len = u32::try_from(name_bytes).map_err(|_| ERROR_INVALID_PARAMETER)?;
    // `u64` storage for the structure's 8-byte alignment.
    let mut buf = vec![0u64; total.div_ceil(8)];
    {
        // SAFETY: `buf` owns `buf.len() * 8` initialized bytes; any byte pattern is a valid
        // `u8`, and the byte view is the only access to `buf` while it lives.
        let bytes: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len() * 8) };
        // `Flags` is the union at offset 0 (checked in the tests).
        let flags = RENAME_REPLACE_IF_EXISTS | RENAME_POSIX_SEMANTICS;
        bytes[..4].copy_from_slice(&flags.to_ne_bytes());
        bytes[len_at..len_at + 4].copy_from_slice(&name_len.to_ne_bytes());
        for (i, unit) in target.iter().enumerate() {
            let at = name_at + 2 * i;
            bytes[at..at + 2].copy_from_slice(&unit.to_ne_bytes());
        }
    }
    let info = buf.as_ptr().cast::<FILE_RENAME_INFO>();
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's result writer renames its own temp file by handle to the full \
                  path below the held launch folder, final path checked after (ADR 0022 \
                  amendment P3-2)"
    )]
    // SAFETY: the temp file's handle is live and opened with DELETE; `info` points to `len`
    // initialized bytes of a FILE_RENAME_INFO as built above, alive for the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            temp.file.as_raw_handle(),
            FileRenameInfoEx,
            info.cast::<c_void>(),
            len,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Creates `launch` below `rerun` if it is missing.
fn create_dir(path: &[u16]) -> Result<(), u32> {
    let p = wide(path);
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch creates its launch folder below the checked Rerun folder, which \
                  it holds open (ADR 0022 amendment P3-2)"
    )]
    // SAFETY: `p` is a NUL-terminated UTF-16 path alive for the call; null security attributes
    // (inherit the parent's ACL) are documented.
    let ok = unsafe { CreateDirectoryW(p.as_ptr(), ptr::null()) };
    if ok == 0 {
        let code = last_error();
        if code != ERROR_ALREADY_EXISTS {
            return Err(code);
        }
    }
    Ok(())
}

/// Writes `bytes` to `<base>\Rerun\launch\<id>.result` (module docs). `base` is the
/// `LocalAppData` path without a NUL.
pub(crate) fn write(base: &[u16], id: &ProfileId, bytes: &[u8]) -> Result<(), OsError> {
    write_with(base, id, bytes, &mut |_| {})
}

/// [`write`] with a hook called with the `launch` path right after its handle is checked
/// (tests: change the folder in the window between the check and the create).
fn write_with(
    base: &[u16],
    id: &ProfileId,
    bytes: &[u8],
    after_launch: &mut dyn FnMut(&[u16]),
) -> Result<(), OsError> {
    if bytes.len() > MAX_RESULT_BYTES {
        return Err(OsError::Encode);
    }
    let rerun_path = join(base, "Rerun");
    let _rerun = open_dir(&rerun_path)?;
    let launch_path = join(&rerun_path, "launch");
    let launch = match open_dir(&launch_path) {
        Ok(h) => h,
        Err(OsError::Win32(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)) => {
            create_dir(&launch_path).map_err(OsError::Win32)?;
            open_dir(&launch_path)?
        }
        Err(e) => return Err(e),
    };
    after_launch(&launch_path);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let temp_name = format!("{id}.{}-{nanos}.tmp", std::process::id());
    let handle = create(
        &join(&launch_path, &temp_name),
        FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
        0,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(OsError::Win32)?;
    let mut temp = Temp {
        file: File::from(handle),
        renamed: false,
    };
    // The temp file is where the checked folder is (step 3).
    let dir = final_path(&launch).map_err(OsError::Win32)?;
    let here = final_path(&temp.file).map_err(OsError::Win32)?;
    if !compare_ordinal_ignore_case(&here, &join(&dir, &temp_name)) {
        return Err(OsError::Escaped);
    }
    temp.file
        .write_all(bytes)
        .map_err(|e| OsError::Win32(e.raw_os_error().map_or(0, i32::cast_unsigned)))?;
    // Step 4: an existing result file must be a plain file.
    let final_name = format!("{id}.result");
    match create(
        &join(&launch_path, &final_name),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    ) {
        Ok(existing) => {
            let attrs = attributes(&existing).map_err(OsError::Win32)?;
            if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(OsError::ReparsePoint);
            }
            if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                return Err(OsError::NotAFile);
            }
        }
        Err(ERROR_FILE_NOT_FOUND) => {}
        Err(code) => return Err(OsError::Win32(code)),
    }
    rename(&temp, &join(&launch_path, &final_name)).map_err(OsError::Win32)?;
    temp.renamed = true;
    // The renamed file is where the checked folder is (the folders were held open throughout,
    // so this only fails if that assumption does).
    let there = final_path(&temp.file).map_err(OsError::Win32)?;
    if !compare_ordinal_ignore_case(&there, &join(&dir, &final_name)) {
        return Err(OsError::Escaped);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
