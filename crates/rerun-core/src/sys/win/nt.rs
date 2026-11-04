//! The only calls to `NtCreateFile`, `NtQueryInformationFile`, `NtQueryDirectoryFile`,
//! `GetFinalPathNameByHandleW`, `GetVolumeInformationByHandleW` and `DeviceIoControl`.
//!
//! - Handles come back as [`OwnedHandle`] and are closed on drop, also in every error path.
//! - `NtCreateFile` is reachable only through [`open_absolute_dir`] and [`open_relative`]
//!   (`clippy.toml` bans it everywhere else). The flags are fixed here; callers choose from
//!   [`Access`] and [`RelOpen`], so `FILE_OPEN_FOR_BACKUP_INTENT`, another disposition or a
//!   relative open without `OBJ_DONT_REPARSE` cannot be expressed.
//! - Buffers for the kernel are `Vec<u64>` (8-byte aligned, as `FILE_*_INFORMATION` with
//!   `LARGE_INTEGER` members needs) and are copied out as little-endian bytes, so no
//!   structure is read through a raw pointer.

#![allow(
    unsafe_code,
    reason = "FFI to ntdll/kernel32 file APIs (ADR 0008); every block has a SAFETY comment"
)]

use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_INFORMATION_CLASS, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileFullDirectoryInformation,
    FileIdExtdDirectoryInformation, NtCreateFile, NtQueryDirectoryFile, NtQueryInformationFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, OBJECT_ATTRIBUTE_FLAGS, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_READ, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, READ_CONTROL, SYNCHRONIZE,
    VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

use super::name::DirLayout;
use super::status::{
    NtStatus, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_PARAMETER, STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};

/// Upper bound for growing name buffers: a 32767-character NT name plus the length field.
const MAX_NAME_BUF: usize = 4 + 2 * 32_768;
/// Buffer for one `NtQueryDirectoryFile` call (ADR 0007, D8).
pub(super) const DIR_BUF: usize = 64 * 1024;

/// Access of a handle. Every variant includes `SYNCHRONIZE` (needed by
/// `FILE_SYNCHRONOUS_IO_NONALERT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Access {
    /// `FILE_READ_ATTRIBUTES`: classify an entry, metadata, walk through a directory.
    /// Shares read, write and delete (never blocks anyone).
    Attributes,
    /// List, traverse, read attributes, `READ_CONTROL` (for `AccessCheck`): a [`Dir`]
    /// handle. Shares read, write and delete.
    ///
    /// [`Dir`]: crate::sys::Dir
    Dir,
    /// `FILE_GENERIC_READ`: data reads. Shares read only, so a concurrent writer yields a
    /// sharing violation (`Busy`) instead of torn content.
    Read,
}

impl Access {
    fn mask(self) -> u32 {
        match self {
            Self::Attributes => FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            Self::Dir => {
                FILE_LIST_DIRECTORY
                    | FILE_TRAVERSE
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE
            }
            Self::Read => FILE_GENERIC_READ,
        }
    }

    fn share(self) -> u32 {
        match self {
            Self::Attributes | Self::Dir => FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Self::Read => FILE_SHARE_READ,
        }
    }
}

/// Kind of a relative open. Both use `FILE_OPEN`, `OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE`
/// and `FILE_SYNCHRONOUS_IO_NONALERT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RelOpen {
    /// `FILE_OPEN_REPARSE_POINT`, neither `FILE_DIRECTORY_FILE` nor `FILE_NON_DIRECTORY_FILE`:
    /// opens the entry itself, whatever it is; the caller classifies it on the handle.
    Entry(Access),
    /// Data reopen of a file with an allowlisted data tag (WOF, dedup, cloud files):
    /// `FILE_NON_DIRECTORY_FILE` without `FILE_OPEN_REPARSE_POINT`, [`Access::Read`]. The
    /// caller compares volume serial and file ID with the first open.
    Data,
}

/// `UNICODE_STRING` over `name`; `None` if it is longer than `u16::MAX` bytes.
fn unicode(name: &[u16]) -> Option<UNICODE_STRING> {
    let len = u16::try_from(name.len().checked_mul(2)?).ok()?;
    Some(UNICODE_STRING {
        Length: len,
        MaximumLength: len,
        // The kernel only reads the buffer (ObjectName is an input).
        Buffer: name.as_ptr().cast_mut(),
    })
}

/// `OBJECT_ATTRIBUTES::Length` (48 bytes on x64, 24 on x86).
const OA_LEN: u32 = {
    let n = size_of::<OBJECT_ATTRIBUTES>();
    assert!(n <= 0xFFFF);
    #[expect(clippy::cast_possible_truncation, reason = "asserted above")]
    let n32 = n as u32;
    n32
};

fn object_attributes(
    root: HANDLE,
    name: &UNICODE_STRING,
    flags: OBJECT_ATTRIBUTE_FLAGS,
) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: OA_LEN,
        RootDirectory: root,
        ObjectName: name,
        Attributes: flags,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    }
}

/// Wraps the result of `NtCreateFile`. A returned handle is owned first, so it is closed
/// even if the status is a success code other than `STATUS_SUCCESS` (e.g. `STATUS_REPARSE`).
fn finish(status: NtStatus, raw: HANDLE) -> Result<OwnedHandle, NtStatus> {
    let owned = (status >= 0 && !raw.is_null()).then(|| {
        // SAFETY: NtCreateFile succeeded and wrote a new handle into `raw`; nothing else owns
        // it, so OwnedHandle takes sole ownership and closes it exactly once.
        unsafe { OwnedHandle::from_raw_handle(raw) }
    });
    match (status, owned) {
        (STATUS_SUCCESS, Some(h)) => Ok(h),
        (STATUS_SUCCESS, None) => Err(STATUS_UNSUCCESSFUL),
        (other, _) => Err(other),
    }
}

/// Opens a directory by NT path (`\??\X:\…`) for `Fs::open_dir`: `RootDirectory` NULL,
/// `OBJ_CASE_INSENSITIVE` only (reparse points above the root are followed),
/// `FILE_DIRECTORY_FILE`, `FILE_OPEN`, [`Access::Dir`].
#[expect(
    clippy::disallowed_methods,
    reason = "one of the two NtCreateFile wrappers (ADR 0007)"
)]
pub(super) fn open_absolute_dir(nt_path: &[u16]) -> Result<OwnedHandle, NtStatus> {
    let name = unicode(nt_path).ok_or(STATUS_INVALID_PARAMETER)?;
    let oa = object_attributes(ptr::null_mut(), &name, OBJ_CASE_INSENSITIVE);
    let mut iosb = IO_STATUS_BLOCK::default();
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: `raw` and `iosb` are valid for writes for the duration of the call; `oa` points
    // to `name`, whose buffer `nt_path` outlives the call; no allocation size, no EA buffer
    // (null with length 0). The call is synchronous (FILE_SYNCHRONOUS_IO_NONALERT).
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            Access::Dir.mask(),
            &oa,
            &mut iosb,
            ptr::null(),
            0,
            Access::Dir.share(),
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    finish(status, raw)
}

/// Opens `name` (one segment, checked by `name::Seg16`) relative to `parent`:
/// `RootDirectory` = `parent`, `OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE`, `FILE_OPEN`,
/// options from [`RelOpen`]. Never `FILE_OPEN_FOR_BACKUP_INTENT`.
#[expect(
    clippy::disallowed_methods,
    reason = "one of the two NtCreateFile wrappers (ADR 0007)"
)]
pub(super) fn open_relative(
    parent: BorrowedHandle<'_>,
    name: &super::name::Seg16,
    how: RelOpen,
) -> Result<OwnedHandle, NtStatus> {
    let (access, options) = match how {
        RelOpen::Entry(a) => (a, FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT),
        RelOpen::Data => (
            Access::Read,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        ),
    };
    let name = unicode(name.units()).ok_or(STATUS_INVALID_PARAMETER)?;
    let oa = object_attributes(
        parent.as_raw_handle(),
        &name,
        OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE,
    );
    let mut iosb = IO_STATUS_BLOCK::default();
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: `parent` is a live handle borrowed for the call; `raw` and `iosb` are valid for
    // writes; `oa` points to `name`, whose buffer (the Seg16) outlives the call; no
    // allocation size, no EA buffer. Synchronous call (FILE_SYNCHRONOUS_IO_NONALERT).
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            access.mask(),
            &oa,
            &mut iosb,
            ptr::null(),
            0,
            access.share(),
            FILE_OPEN,
            options,
            ptr::null(),
            0,
        )
    };
    finish(status, raw)
}

/// Copies the first `len` bytes of an aligned buffer out as little-endian bytes.
fn bytes_of(buf: &[u64], len: usize) -> Vec<u8> {
    buf.iter().flat_map(|w| w.to_le_bytes()).take(len).collect()
}

/// `NtQueryInformationFile` into a buffer of `size` bytes, growing (doubling, up to
/// [`MAX_NAME_BUF`]) on `STATUS_BUFFER_OVERFLOW` and friends. Returns the bytes written.
pub(super) fn query_info(
    h: BorrowedHandle<'_>,
    class: FILE_INFORMATION_CLASS,
    size: usize,
) -> Result<Vec<u8>, NtStatus> {
    let mut size = size.max(8);
    loop {
        let mut buf = vec![0u64; size.div_ceil(8)];
        let len = u32::try_from(buf.len() * 8).map_err(|_| STATUS_BUFFER_TOO_SMALL)?;
        let mut iosb = IO_STATUS_BLOCK::default();
        // SAFETY: `h` is a live handle; `buf` is valid for writes of `len` bytes and 8-byte
        // aligned; `iosb` is valid for writes. Synchronous handle, so the call has completed
        // when it returns and nothing writes to `buf` afterwards.
        let status = unsafe {
            NtQueryInformationFile(
                h.as_raw_handle(),
                &mut iosb,
                buf.as_mut_ptr().cast(),
                len,
                class,
            )
        };
        match status {
            STATUS_SUCCESS => return Ok(bytes_of(&buf, iosb.Information.min(buf.len() * 8))),
            STATUS_BUFFER_OVERFLOW | STATUS_BUFFER_TOO_SMALL | STATUS_INFO_LENGTH_MISMATCH
                if size < MAX_NAME_BUF =>
            {
                size = (size * 2).min(MAX_NAME_BUF);
            }
            other => return Err(other),
        }
    }
}

/// One `NtQueryDirectoryFile` call in `layout` (`FileIdExtdDirectoryInformation` or
/// `FileFullDirectoryInformation`), [`DIR_BUF`] bytes, all entries that fit, no filter.
/// `Ok(None)` at the end of the listing.
pub(super) fn query_dir(
    h: BorrowedHandle<'_>,
    restart: bool,
    layout: DirLayout,
) -> Result<Option<Vec<u8>>, NtStatus> {
    let class = match layout {
        DirLayout::IdExtd => FileIdExtdDirectoryInformation,
        DirLayout::Full => FileFullDirectoryInformation,
    };
    let mut buf = vec![0u64; DIR_BUF / 8];
    let len = u32::try_from(DIR_BUF).map_err(|_| STATUS_BUFFER_TOO_SMALL)?;
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: `h` is a live directory handle; `buf` is valid for writes of `len` bytes and
    // 8-byte aligned; `iosb` is valid for writes; no event, no APC, no file name filter
    // (null). Synchronous handle, so the call has completed when it returns.
    let status = unsafe {
        NtQueryDirectoryFile(
            h.as_raw_handle(),
            ptr::null_mut(),
            None,
            ptr::null(),
            &mut iosb,
            buf.as_mut_ptr().cast(),
            len,
            class,
            false,
            ptr::null(),
            restart,
        )
    };
    match status {
        STATUS_SUCCESS if iosb.Information == 0 => Ok(None),
        STATUS_SUCCESS => Ok(Some(bytes_of(&buf, iosb.Information.min(DIR_BUF)))),
        STATUS_NO_MORE_FILES => Ok(None),
        STATUS_NO_SUCH_FILE if restart => Ok(None),
        other => Err(other),
    }
}

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

/// `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)`, growing the buffer.
pub(super) fn final_path(h: BorrowedHandle<'_>) -> Result<Vec<u16>, u32> {
    let mut cap: u32 = 512;
    loop {
        let mut buf = vec![0u16; cap as usize];
        // SAFETY: `h` is a live handle; `buf` is valid for writes of `cap` UTF-16 units.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                h.as_raw_handle(),
                buf.as_mut_ptr(),
                cap,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if n == 0 {
            return Err(last_error());
        }
        if n < cap {
            // Success: `n` units without the terminating NUL.
            buf.truncate(n as usize);
            return Ok(buf);
        }
        // Too small: `n` is the required size including the NUL. Guard against a loop.
        if n <= cap || n > 32_768 + 16 {
            return Err(122); // ERROR_INSUFFICIENT_BUFFER
        }
        cap = n;
    }
}

/// File system name and flags of the volume of `h` (`GetVolumeInformationByHandleW`).
pub(super) fn volume_info(h: BorrowedHandle<'_>) -> Result<(Vec<u16>, u32), u32> {
    // MAX_PATH + 1, the documented maximum for the file system name.
    let mut fs_name = vec![0u16; 261];
    let mut flags: u32 = 0;
    let cap = u32::try_from(fs_name.len()).map_err(|_| 122u32)?;
    // SAFETY: `h` is a live handle; `fs_name` is valid for writes of `cap` units; `flags` is
    // valid for a write; the volume name, serial and component length outputs are null
    // (optional) with size 0.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            h.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            fs_name.as_mut_ptr(),
            cap,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    let end = fs_name
        .iter()
        .position(|&u| u == 0)
        .unwrap_or(fs_name.len());
    fs_name.truncate(end);
    Ok((fs_name, flags))
}

/// Raw `REPARSE_DATA_BUFFER` of the entry `h` was opened on (`FSCTL_GET_REPARSE_POINT`; the
/// handle must have been opened with `FILE_OPEN_REPARSE_POINT`).
pub(super) fn reparse_data(h: BorrowedHandle<'_>) -> Result<Vec<u8>, u32> {
    let size = MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize;
    let mut buf = vec![0u64; size / 8];
    let mut returned: u32 = 0;
    // SAFETY: `h` is a live handle opened for synchronous I/O, so a null OVERLAPPED is
    // allowed; no input buffer (null, 0); `buf` is valid for writes of
    // MAXIMUM_REPARSE_DATA_BUFFER_SIZE bytes and 8-byte aligned; `returned` is valid for a
    // write.
    let ok = unsafe {
        DeviceIoControl(
            h.as_raw_handle(),
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            buf.as_mut_ptr().cast(),
            MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(bytes_of(&buf, (returned as usize).min(size)))
}
