//! The only calls to `NtCreateFile`, `NtQueryInformationFile`, `NtQueryDirectoryFile`,
//! `NtSetInformationFile`, `NtFlushBuffersFileEx`, `GetFinalPathNameByHandleW`,
//! `GetVolumeInformationByHandleW` and `DeviceIoControl`.
//!
//! - Handles come back as [`OwnedHandle`] and are closed on drop, also in every error path.
//! - `NtCreateFile` is reachable only through [`open_absolute_dir`], [`open_relative`] and
//!   [`open_self_for_flush`] (`clippy.toml` bans it everywhere else; the two relative ones
//!   share one private call). The flags are fixed here; callers choose from
//!   [`Access`] and [`RelOpen`], so `FILE_OPEN_FOR_BACKUP_INTENT`, `FILE_OVERWRITE*`,
//!   `FILE_SUPERSEDE`, another disposition or a relative open without `OBJ_DONT_REPARSE`
//!   cannot be expressed.
//! - `NtSetInformationFile` is reachable only through [`set_info`] with exactly three classes
//!   ([`SetInfo`], ADR 0017): `FileRenameInformationEx` with flags 0 (never
//!   `REPLACE_IF_EXISTS`) and `RootDirectory` = the parent handle,
//!   `FileDispositionInformationEx` with `DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE`
//!   (never the legacy class), and `FileBasicInformation` with unchanged times.
//!   `NtFlushBuffersFileEx` only in [`flush`].
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
    FILE_BASIC_INFORMATION, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_DELETE,
    FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_INFORMATION_EX,
    FILE_DISPOSITION_POSIX_SEMANTICS, FILE_INFORMATION_CLASS, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_BY_FILE_ID, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
    FILE_SYNCHRONOUS_IO_NONALERT, FileBasicInformation, FileDispositionInformationEx,
    FileFullDirectoryInformation, FileIdExtdDirectoryInformation, FileRenameInformationEx,
    NTCREATEFILE_CREATE_DISPOSITION, NtCreateFile, NtFlushBuffersFileEx, NtQueryDirectoryFile,
    NtQueryInformationFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, OBJECT_ATTRIBUTE_FLAGS, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_LIST_DIRECTORY,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
    READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_DOS, VOLUME_NAME_GUID, VOLUME_NAME_NT,
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
    /// `READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE`: the security descriptor of an
    /// entry (`sd_facts`, ADR 0023 §2). Shares read, write and delete.
    Security,
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
            Self::Security => READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            Self::Read => FILE_GENERIC_READ,
        }
    }

    fn share(self) -> u32 {
        match self {
            Self::Attributes | Self::Dir | Self::Security => {
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            }
            Self::Read => FILE_SHARE_READ,
        }
    }
}

/// Kind of a relative open. Every kind uses `OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE` and
/// `FILE_SYNCHRONOUS_IO_NONALERT`; all but [`RelOpen::Data`] and [`RelOpen::GuardData`] also
/// `FILE_OPEN_REPARSE_POINT`, so the entry itself is opened, never what a link points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RelOpen {
    /// `FILE_OPEN`, neither `FILE_DIRECTORY_FILE` nor `FILE_NON_DIRECTORY_FILE`: opens the
    /// entry itself, whatever it is; the caller classifies it on the handle.
    Entry(Access),
    /// Data reopen of a file with an allowlisted data tag (WOF, dedup, cloud files):
    /// `FILE_NON_DIRECTORY_FILE` without `FILE_OPEN_REPARSE_POINT`, [`Access::Read`]. The
    /// caller compares volume serial and file ID with the first open.
    Data,
    /// A guard (ADR 0017): `FILE_OPEN`, `DELETE | FILE_READ_DATA | FILE_READ_ATTRIBUTES |
    /// SYNCHRONIZE`, share read only; the entry itself, classified by the caller.
    Guard,
    /// The guard's data reopen of a file with an allowlisted data tag: like
    /// [`RelOpen::Guard`], with `FILE_NON_DIRECTORY_FILE` instead of
    /// `FILE_OPEN_REPARSE_POINT` (the data of a WOF or dedup file is only visible so). The
    /// caller compares the file ID with the first open.
    GuardData,
    /// `<tmp>` (ADR 0017, step 2): `FILE_CREATE | FILE_NON_DIRECTORY_FILE`, `FILE_WRITE_DATA |
    /// FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE`, share 0,
    /// `FILE_ATTRIBUTE_NORMAL`. An existing name is `STATUS_OBJECT_NAME_COLLISION`.
    CreateTmp,
    /// A lock file (A7): `FILE_OPEN_IF | FILE_NON_DIRECTORY_FILE`, `FILE_READ_DATA |
    /// FILE_READ_ATTRIBUTES | SYNCHRONIZE`, share 0. A directory (also a junction, opened as
    /// itself) is `STATUS_FILE_IS_A_DIRECTORY`.
    Lock,
    /// A new directory: `FILE_CREATE | FILE_DIRECTORY_FILE`, `FILE_READ_ATTRIBUTES |
    /// SYNCHRONIZE`, share 0.
    CreateDir,
    /// A directory opened for deleting: `FILE_OPEN | FILE_DIRECTORY_FILE`, `DELETE |
    /// FILE_READ_ATTRIBUTES | SYNCHRONIZE`, shares read and write. A file is
    /// `STATUS_NOT_A_DIRECTORY`.
    DirDelete,
}

/// Everything `NtCreateFile` gets for a [`RelOpen`].
struct Spec {
    access: u32,
    share: u32,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    options: u32,
    attributes: u32,
}

impl RelOpen {
    fn spec(self) -> Spec {
        const SYNC: u32 = FILE_SYNCHRONOUS_IO_NONALERT;
        const ITSELF: u32 = FILE_OPEN_REPARSE_POINT | SYNC;
        const GUARD: u32 = DELETE | FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        let plain = |access: u32, share: u32, disposition, options: u32| Spec {
            access,
            share,
            disposition,
            options,
            attributes: 0,
        };
        match self {
            Self::Entry(a) => plain(a.mask(), a.share(), FILE_OPEN, ITSELF),
            Self::Data => plain(
                Access::Read.mask(),
                Access::Read.share(),
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | SYNC,
            ),
            Self::Guard => plain(GUARD, FILE_SHARE_READ, FILE_OPEN, ITSELF),
            Self::GuardData => plain(
                GUARD,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | SYNC,
            ),
            Self::CreateTmp => Spec {
                access: FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | DELETE
                    | SYNCHRONIZE,
                share: 0,
                disposition: FILE_CREATE,
                options: FILE_NON_DIRECTORY_FILE | ITSELF,
                attributes: FILE_ATTRIBUTE_NORMAL,
            },
            Self::Lock => plain(
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                0,
                FILE_OPEN_IF,
                FILE_NON_DIRECTORY_FILE | ITSELF,
            ),
            Self::CreateDir => plain(
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                0,
                FILE_CREATE,
                FILE_DIRECTORY_FILE | ITSELF,
            ),
            Self::DirDelete => plain(
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | ITSELF,
            ),
        }
    }
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

/// Opens or creates `name` (one segment, checked by `name::Seg16`) relative to `parent`:
/// `RootDirectory` = `parent`, `OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE`; disposition,
/// access, share, options and attributes from [`RelOpen`]. Never
/// `FILE_OPEN_FOR_BACKUP_INTENT`, never `FILE_OVERWRITE*` or `FILE_SUPERSEDE`.
pub(super) fn open_relative(
    parent: BorrowedHandle<'_>,
    name: &super::name::Seg16,
    how: RelOpen,
) -> Result<OwnedHandle, NtStatus> {
    create_relative(parent, name.units(), &how.spec())
}

/// Reopens the directory `dir` itself (the empty name relative to it) for a flush:
/// `FILE_OPEN | FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT`, `FILE_ADD_FILE | SYNCHRONIZE`
/// (read access is denied for a flush, ADR 0017), shares read, write and delete.
pub(super) fn open_self_for_flush(dir: BorrowedHandle<'_>) -> Result<OwnedHandle, NtStatus> {
    let spec = Spec {
        access: FILE_ADD_FILE | SYNCHRONIZE,
        share: FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        disposition: FILE_OPEN,
        options: FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        attributes: 0,
    };
    create_relative(dir, &[], &spec)
}

/// The one `NtCreateFile` call of the relative opens: `units` (one checked segment, or empty
/// for the parent itself) relative to `parent` with `OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE`.
#[expect(
    clippy::disallowed_methods,
    reason = "the relative NtCreateFile call behind open_relative and open_self_for_flush (ADR 0007)"
)]
fn create_relative(
    parent: BorrowedHandle<'_>,
    units: &[u16],
    spec: &Spec,
) -> Result<OwnedHandle, NtStatus> {
    let name = unicode(units).ok_or(STATUS_INVALID_PARAMETER)?;
    let oa = object_attributes(
        parent.as_raw_handle(),
        &name,
        OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE,
    );
    let mut iosb = IO_STATUS_BLOCK::default();
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: `parent` is a live handle borrowed for the call; `raw` and `iosb` are valid for
    // writes; `oa` points to `name`, whose buffer (`units`, borrowed by the caller) outlives
    // the call; no allocation size, no EA buffer. Synchronous call: every spec has
    // FILE_SYNCHRONOUS_IO_NONALERT.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            spec.access,
            &oa,
            &mut iosb,
            ptr::null(),
            spec.attributes,
            spec.share,
            spec.disposition,
            spec.options,
            ptr::null(),
            0,
        )
    };
    finish(status, raw)
}

/// The `ObjectName` bytes of an open by file ID (ADR 0023 §4, A4 N2): the 8-byte `FILE_ID`
/// (little-endian) when the upper half of `id` is 0, as NTFS expects, else the 16-byte
/// `FILE_ID_128` (ReFS, Dev Drive). As UTF-16 units, because `UNICODE_STRING` points to
/// `u16`s; the bytes are the same.
pub(super) fn file_id_name(id: u128) -> Vec<u16> {
    let bytes = id.to_le_bytes();
    let len = if id >> 64 == 0 { 8 } else { 16 };
    bytes[..len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect()
}

/// Opens the directory with file ID `id` on the volume whose root directory `volume` is
/// (ADR 0023 §4, §5 step 4; ADR 0007 "Elevation", R4): `RootDirectory` = `volume`, the name
/// = [`file_id_name`], `FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT | FILE_DIRECTORY_FILE`
/// (the object itself, never what a link points to; a file is `STATUS_NOT_A_DIRECTORY`),
/// [`Access::Dir`], `FILE_OPEN`. Never `OpenFileById`. The caller checks the handle's file ID
/// and kind.
#[expect(
    clippy::disallowed_methods,
    reason = "the third NtCreateFile call site: open by file ID (ADR 0023, A4 S1/N2)"
)]
pub(super) fn open_by_file_id(
    volume: BorrowedHandle<'_>,
    id: u128,
) -> Result<OwnedHandle, NtStatus> {
    let units = file_id_name(id);
    let name = unicode(&units).ok_or(STATUS_INVALID_PARAMETER)?;
    let oa = object_attributes(volume.as_raw_handle(), &name, 0);
    let mut iosb = IO_STATUS_BLOCK::default();
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: `volume` is a live handle borrowed for the call; `raw` and `iosb` are valid for
    // writes; `oa` points to `name`, whose buffer (`units`, 8 or 16 bytes) outlives the call; no
    // allocation size, no EA buffer. Synchronous call (FILE_SYNCHRONOUS_IO_NONALERT).
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
            FILE_OPEN_BY_FILE_ID
                | FILE_OPEN_REPARSE_POINT
                | FILE_DIRECTORY_FILE
                | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    finish(status, raw)
}

/// A change made on a held handle: the three classes of ADR 0017.
#[derive(Debug, Clone, Copy)]
pub(super) enum SetInfo<'a> {
    /// `FileRenameInformationEx` with flags 0 (no `REPLACE_IF_EXISTS`, so an existing name is
    /// `STATUS_OBJECT_NAME_COLLISION`): the handle's object becomes `name` in the directory
    /// `root`. The renamed handle needs `DELETE`.
    Rename {
        /// The parent directory (`RootDirectory`).
        root: BorrowedHandle<'a>,
        /// One segment, checked by `name::Seg16`: no `\`, so the kernel never resolves a path
        /// (which would follow junctions, ADR 0017 "Renames").
        name: &'a super::name::Seg16,
    },
    /// `FileDispositionInformationEx` with `DELETE | POSIX_SEMANTICS |
    /// IGNORE_READONLY_ATTRIBUTE`: the name goes at once (POSIX), the object when the last
    /// handle closes. The handle needs `DELETE`.
    PosixDelete,
    /// `FileBasicInformation`: the four times 0 (unchanged) and these attributes. Never 0,
    /// which would also mean "unchanged": `FILE_ATTRIBUTE_NORMAL` clears every flag.
    Attributes(u32),
}

/// `FILE_RENAME_INFORMATION` (`FileRenameInformationEx` uses the same layout, with `Flags` in
/// the union) for `name` with flags 0, as 8-byte aligned words, and its length in bytes.
fn rename_buffer(root: HANDLE, name: &[u16]) -> Option<(Vec<u64>, u32)> {
    let root_at = std::mem::offset_of!(FILE_RENAME_INFORMATION, RootDirectory);
    let len_at = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileNameLength);
    let name_at = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let name_bytes = name.len().checked_mul(2)?;
    let total = name_at
        .checked_add(name_bytes)?
        .max(size_of::<FILE_RENAME_INFORMATION>());
    // All zero: the flags (offset 0) stay 0.
    let mut bytes = vec![0u8; total];
    // The handle value, as the kernel reads the pointer-sized field.
    let root_value = root as usize;
    bytes
        .get_mut(root_at..root_at + size_of::<usize>())?
        .copy_from_slice(&root_value.to_le_bytes());
    bytes
        .get_mut(len_at..len_at + 4)?
        .copy_from_slice(&u32::try_from(name_bytes).ok()?.to_le_bytes());
    for (i, u) in name.iter().enumerate() {
        let at = name_at + 2 * i;
        bytes.get_mut(at..at + 2)?.copy_from_slice(&u.to_le_bytes());
    }
    let mut words = vec![0u64; total.div_ceil(8)];
    for (w, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
        let mut a = [0u8; 8];
        a[..chunk.len()].copy_from_slice(chunk);
        *w = u64::from_le_bytes(a);
    }
    Some((words, u32::try_from(total).ok()?))
}

/// The only `NtSetInformationFile` call: one change of [`SetInfo`] on `h`. Each class acts
/// completely or not at all, so an error means nothing was changed (for a rename: nothing was
/// renamed).
#[expect(
    clippy::disallowed_methods,
    reason = "the one NtSetInformationFile wrapper (ADR 0017)"
)]
pub(super) fn set_info(h: BorrowedHandle<'_>, info: SetInfo<'_>) -> Result<(), NtStatus> {
    let disposition = FILE_DISPOSITION_INFORMATION_EX {
        Flags: FILE_DISPOSITION_DELETE
            | FILE_DISPOSITION_POSIX_SEMANTICS
            | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    };
    let basic;
    let rename;
    let size_of_u32 = |n: usize| u32::try_from(n).map_err(|_| STATUS_INVALID_PARAMETER);
    let (buf, len, class): (*const std::ffi::c_void, u32, FILE_INFORMATION_CLASS) = match info {
        SetInfo::Rename { root, name } => {
            rename = rename_buffer(root.as_raw_handle(), name.units())
                .ok_or(STATUS_INVALID_PARAMETER)?;
            (rename.0.as_ptr().cast(), rename.1, FileRenameInformationEx)
        }
        SetInfo::PosixDelete => (
            ptr::from_ref(&disposition).cast(),
            size_of_u32(size_of::<FILE_DISPOSITION_INFORMATION_EX>())?,
            FileDispositionInformationEx,
        ),
        SetInfo::Attributes(attrs) => {
            if attrs == 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            basic = FILE_BASIC_INFORMATION {
                FileAttributes: attrs,
                ..FILE_BASIC_INFORMATION::default()
            };
            (
                ptr::from_ref(&basic).cast(),
                size_of_u32(size_of::<FILE_BASIC_INFORMATION>())?,
                FileBasicInformation,
            )
        }
    };
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: `h` is a live handle borrowed for the call (for a rename `root` too, whose raw
    // value is in the buffer and which outlives the call); `buf` points to `len` readable
    // bytes that live until the end of this function (`disposition`, `basic` or `rename.0`,
    // at least 4-byte aligned, laid out as the class expects: pinned by
    // `set_info_layouts_match_the_documented_offsets`); `iosb` is valid for writes. The
    // handle is synchronous, so the call has completed when it returns.
    let status = unsafe { NtSetInformationFile(h.as_raw_handle(), &mut iosb, buf, len, class) };
    if status >= 0 { Ok(()) } else { Err(status) }
}

/// The only `NtFlushBuffersFileEx` call, flags 0: data and metadata of a file, or the
/// entries of a directory opened with [`open_self_for_flush`].
#[expect(
    clippy::disallowed_methods,
    reason = "the one flush wrapper (ADR 0017, ADR 0019)"
)]
pub(super) fn flush(h: BorrowedHandle<'_>) -> Result<(), NtStatus> {
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: `h` is a live handle borrowed for the call; no parameters (null, 0); `iosb` is
    // valid for writes. Synchronous handle, so the call has completed when it returns.
    let status = unsafe { NtFlushBuffersFileEx(h.as_raw_handle(), 0, ptr::null(), 0, &mut iosb) };
    if status >= 0 { Ok(()) } else { Err(status) }
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
    final_path_as(h, VOLUME_NAME_DOS)
}

/// `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_GUID)`: `\\?\Volume{…}\…`, the
/// volume GUID of `RootInfo::volume_guid` (ADR 0023 §4).
pub(super) fn final_path_guid(h: BorrowedHandle<'_>) -> Result<Vec<u16>, u32> {
    final_path_as(h, VOLUME_NAME_GUID)
}

/// `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_NT)`: the NT name of `SdFacts::nt_name`.
pub(super) fn final_path_nt(h: BorrowedHandle<'_>) -> Result<Vec<u16>, u32> {
    final_path_as(h, VOLUME_NAME_NT)
}

fn final_path_as(h: BorrowedHandle<'_>, volume: u32) -> Result<Vec<u16>, u32> {
    let mut cap: u32 = 512;
    loop {
        let mut buf = vec![0u16; cap as usize];
        // SAFETY: `h` is a live handle; `buf` is valid for writes of `cap` UTF-16 units.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                h.as_raw_handle(),
                buf.as_mut_ptr(),
                cap,
                FILE_NAME_NORMALIZED | volume,
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
#[expect(
    clippy::disallowed_methods,
    reason = "the one DeviceIoControl call, FSCTL_GET_REPARSE_POINT (ADR 0007)"
)]
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

#[cfg(test)]
mod tests {
    use std::mem::offset_of;

    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_BASIC_INFORMATION, FILE_DISPOSITION_INFORMATION_EX, FILE_RENAME_INFORMATION,
    };

    use super::rename_buffer;

    /// The documented x64 layouts (ntifs.h, wdm.h): `FILE_RENAME_INFORMATION` has `Flags` at
    /// 0, `RootDirectory` at 8, `FileNameLength` at 16, `FileName` at 20 (24 bytes);
    /// `FILE_DISPOSITION_INFORMATION_EX` is one `ULONG`; `FILE_BASIC_INFORMATION` has four
    /// `LARGE_INTEGER` times, then `FileAttributes` at 32 (40 bytes).
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn set_info_layouts_match_the_documented_offsets() {
        assert_eq!(offset_of!(FILE_RENAME_INFORMATION, Anonymous), 0);
        assert_eq!(offset_of!(FILE_RENAME_INFORMATION, RootDirectory), 8);
        assert_eq!(offset_of!(FILE_RENAME_INFORMATION, FileNameLength), 16);
        assert_eq!(offset_of!(FILE_RENAME_INFORMATION, FileName), 20);
        assert_eq!(size_of::<FILE_RENAME_INFORMATION>(), 24);
        assert_eq!(size_of::<FILE_DISPOSITION_INFORMATION_EX>(), 4);
        assert_eq!(offset_of!(FILE_BASIC_INFORMATION, FileAttributes), 32);
        assert_eq!(size_of::<FILE_BASIC_INFORMATION>(), 40);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn rename_buffer_is_flags_zero_root_length_name() {
        let name: Vec<u16> = "ab.txt".encode_utf16().collect();
        let (words, len) = rename_buffer(0x1234 as _, &name).unwrap();
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(len, 20 + 12);
        assert_eq!(bytes[0..8], [0; 8], "flags 0: never REPLACE_IF_EXISTS");
        assert_eq!(bytes[8..16], 0x1234u64.to_le_bytes());
        assert_eq!(bytes[16..20], 12u32.to_le_bytes());
        let back: Vec<u16> = bytes[20..32]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(back, name);
        // A one-character name still passes the full fixed size.
        assert_eq!(rename_buffer(0x1 as _, &[0x61]).unwrap().1, 24);
    }
}

#[cfg(test)]
mod id_tests {
    use super::file_id_name;

    /// A4 N2: 8 bytes when the upper half is 0 (NTFS `FILE_ID`), else 16 (ReFS `FILE_ID_128`),
    /// little-endian either way.
    #[test]
    fn open_by_id_names_are_8_or_16_bytes() {
        let ntfs = file_id_name(0x0001_0000_0000_002A);
        assert_eq!(ntfs, [0x002A, 0, 0, 0x0001]);
        let refs = file_id_name(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10);
        assert_eq!(refs.len(), 8);
        assert_eq!(refs[0], 0x0F10);
        assert_eq!(refs[7], 0x0102);
        assert_eq!(file_id_name(1u128 << 64).len(), 8);
        assert_eq!(file_id_name(0).len(), 4);
    }
}
