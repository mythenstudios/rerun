//! Mapping of `NTSTATUS` and Win32 error codes (file and registry calls) to [`SysErrorKind`].
//! Pure, no I/O.
//!
//! Every error carries its original code (`SysError::ntstatus` or `SysError::win32`), so the
//! kind is a classification for callers, never a loss of information.

use crate::sys::{SysError, SysErrorKind};

/// `NTSTATUS` as returned by the NT APIs.
pub(super) type NtStatus = i32;

/// Builds an `NTSTATUS` constant from its documented hex value (ntstatus.h).
const fn st(v: u32) -> NtStatus {
    v as NtStatus
}

pub(super) const STATUS_SUCCESS: NtStatus = 0;
pub(super) const STATUS_BUFFER_OVERFLOW: NtStatus = st(0x8000_0005);
pub(super) const STATUS_NO_MORE_FILES: NtStatus = st(0x8000_0006);
pub(super) const STATUS_NO_MORE_ENTRIES: NtStatus = st(0x8000_001A);
pub(super) const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = st(0xC000_0034);
pub(super) const STATUS_UNSUCCESSFUL: NtStatus = st(0xC000_0001);
pub(super) const STATUS_INFO_LENGTH_MISMATCH: NtStatus = st(0xC000_0004);
pub(super) const STATUS_INVALID_PARAMETER: NtStatus = st(0xC000_000D);
pub(super) const STATUS_NO_SUCH_FILE: NtStatus = st(0xC000_000F);
pub(super) const STATUS_BUFFER_TOO_SMALL: NtStatus = st(0xC000_0023);
pub(super) const STATUS_OBJECT_NAME_COLLISION: NtStatus = st(0xC000_0035);
pub(super) const STATUS_DELETE_PENDING: NtStatus = st(0xC000_0056);

/// `ERROR_INVALID_PARAMETER`: only "unsupported" for an information class.
const ERROR_INVALID_PARAMETER: u32 = 87;

/// Classifies an `NTSTATUS` (ntstatus.h names in the comments).
pub(super) fn kind_of_ntstatus(status: NtStatus) -> SysErrorKind {
    // Compare as u32 so the table reads like ntstatus.h.
    match status.cast_unsigned() {
        // OBJECT_NAME_NOT_FOUND, OBJECT_PATH_NOT_FOUND, NO_SUCH_FILE, FILE_DELETED
        0xC000_0034 | 0xC000_003A | 0xC000_000F | 0xC000_0123 => SysErrorKind::NotFound,
        // ACCESS_DENIED, FILE_IS_A_DIRECTORY, MEDIA_WRITE_PROTECTED
        0xC000_0022 | 0xC000_00BA | 0xC000_00A2 => SysErrorKind::AccessDenied,
        // NOT_A_DIRECTORY, OBJECT_NAME_INVALID, OBJECT_PATH_INVALID, OBJECT_PATH_SYNTAX_BAD,
        // NAME_TOO_LONG, OBJECT_TYPE_MISMATCH
        0xC000_0103 | 0xC000_0033 | 0xC000_0039 | 0xC000_003B | 0xC000_0106 | 0xC000_0024 => {
            SysErrorKind::InvalidPath
        }
        // REPARSE_POINT_ENCOUNTERED (OBJ_DONT_REPARSE), STOPPED_ON_SYMLINK,
        // IO_REPARSE_TAG_NOT_HANDLED, REPARSE_POINT_NOT_RESOLVED, REPARSE (defensive)
        0xC000_050B | 0x8000_002D | 0xC000_0279 | 0xC000_0280 | 0x0000_0104 => {
            SysErrorKind::ReparsePoint
        }
        // SHARING_VIOLATION, FILE_LOCK_CONFLICT, LOCK_NOT_GRANTED; DELETE_PENDING (a name in
        // legacy delete-pending state, ADR 0017 A6) and CANNOT_DELETE (with
        // IGNORE_READONLY_ATTRIBUTE the remaining cause is an image section: in use). "Busy"
        // is "transient or concurrent, a retry may succeed" (ADR 0017, "Error kinds").
        0xC000_0043 | 0xC000_0054 | 0xC000_0055 | 0xC000_0056 | 0xC000_0121 => SysErrorKind::Busy,
        // OBJECT_NAME_COLLISION
        0xC000_0035 => SysErrorKind::AlreadyExists,
        // DIRECTORY_NOT_EMPTY
        0xC000_0101 => SysErrorKind::NotEmpty,
        // NOT_SUPPORTED, INVALID_DEVICE_REQUEST, INVALID_INFO_CLASS, NOT_IMPLEMENTED
        0xC000_00BB | 0xC000_0010 | 0xC000_0003 | 0xC000_0002 => SysErrorKind::Unsupported,
        _ => SysErrorKind::Other,
    }
}

/// Classifies a Win32 error code (winerror.h). Lives in `sys::error`, which also maps the
/// codes inside `std::io::Error`s of reads on a handle ([`SysError::io`](crate::sys::SysError::io)).
pub(super) use crate::sys::error::kind_of_win32;

/// Like [`kind_of_win32`], for a query of an information class: `ERROR_INVALID_PARAMETER`
/// there means the class is not supported by the file system.
pub(super) fn kind_of_win32_info(code: u32) -> SysErrorKind {
    if code == ERROR_INVALID_PARAMETER {
        SysErrorKind::Unsupported
    } else {
        kind_of_win32(code)
    }
}

/// The file system does not support an information class (FAT and others):
/// `STATUS_INVALID_PARAMETER` counts in this context only.
pub(super) fn is_unsupported_class(status: NtStatus) -> bool {
    status == STATUS_INVALID_PARAMETER || kind_of_ntstatus(status) == SysErrorKind::Unsupported
}

/// `SysError` from an `NTSTATUS`, with the status attached.
pub(super) fn nt_error(status: NtStatus, target: &str) -> SysError {
    SysError::new(kind_of_ntstatus(status), target).with_ntstatus(status)
}

/// `SysError` from the `NTSTATUS` of a rename by handle (ADR 0017): a collision with an
/// existing name is `Busy` there (someone holds the name, "retry"), not `AlreadyExists` as on
/// a create. The status is attached.
pub(super) fn rename_error(status: NtStatus, target: &str) -> SysError {
    let kind = if status == STATUS_OBJECT_NAME_COLLISION {
        SysErrorKind::Busy
    } else {
        kind_of_ntstatus(status)
    };
    SysError::new(kind, target).with_ntstatus(status)
}

/// `SysError` from a Win32 error code, with the code attached.
pub(super) fn win32_error(code: u32, target: &str) -> SysError {
    SysError::new(kind_of_win32(code), target).with_win32(code)
}

/// Classifies a Win32 error code of a registry call (ADR 0009). Narrower than
/// [`kind_of_win32`]: the input rules run first, so `ERROR_INVALID_PARAMETER` is an invalid
/// path, and everything not listed is `Other` (with the code attached).
pub(super) fn kind_of_reg(code: u32) -> SysErrorKind {
    match code {
        // FILE_NOT_FOUND, PATH_NOT_FOUND, KEY_DELETED
        2 | 3 | 1018 => SysErrorKind::NotFound,
        // ACCESS_DENIED
        5 => SysErrorKind::AccessDenied,
        // FILENAME_EXCED_RANGE, INVALID_PARAMETER
        206 | 87 => SysErrorKind::InvalidPath,
        _ => SysErrorKind::Other,
    }
}

/// Classifies an `NTSTATUS` of a registry value call (ADR 0009), like [`kind_of_reg`].
pub(super) fn kind_of_reg_ntstatus(status: NtStatus) -> SysErrorKind {
    match status.cast_unsigned() {
        // OBJECT_NAME_NOT_FOUND, OBJECT_PATH_NOT_FOUND, KEY_DELETED
        0xC000_0034 | 0xC000_003A | 0xC000_017C => SysErrorKind::NotFound,
        // ACCESS_DENIED
        0xC000_0022 => SysErrorKind::AccessDenied,
        // INVALID_PARAMETER, OBJECT_NAME_INVALID
        0xC000_000D | 0xC000_0033 => SysErrorKind::InvalidPath,
        _ => SysErrorKind::Other,
    }
}

/// `SysError` from the `NTSTATUS` of a registry value call, with the status attached.
pub(super) fn reg_nt_error(status: NtStatus, target: &str) -> SysError {
    SysError::new(kind_of_reg_ntstatus(status), target).with_ntstatus(status)
}

/// `SysError` from the Win32 error code of a registry call, with the code attached.
pub(super) fn reg_error(code: u32, target: &str) -> SysError {
    SysError::new(kind_of_reg(code), target).with_win32(code)
}

/// `SysError` from a Win32 error code of an information-class query.
pub(super) fn win32_info_error(code: u32, target: &str) -> SysError {
    SysError::new(kind_of_win32_info(code), target).with_win32(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntstatus_table() {
        let cases: &[(u32, SysErrorKind)] = &[
            (0xC000_0034, SysErrorKind::NotFound),
            (0xC000_003A, SysErrorKind::NotFound),
            (0xC000_000F, SysErrorKind::NotFound),
            (0xC000_0123, SysErrorKind::NotFound),
            (0xC000_0022, SysErrorKind::AccessDenied),
            (0xC000_00BA, SysErrorKind::AccessDenied),
            (0xC000_00A2, SysErrorKind::AccessDenied),
            (0xC000_0103, SysErrorKind::InvalidPath),
            (0xC000_0033, SysErrorKind::InvalidPath),
            (0xC000_0039, SysErrorKind::InvalidPath),
            (0xC000_003B, SysErrorKind::InvalidPath),
            (0xC000_0106, SysErrorKind::InvalidPath),
            (0xC000_0024, SysErrorKind::InvalidPath),
            (0xC000_050B, SysErrorKind::ReparsePoint),
            (0x8000_002D, SysErrorKind::ReparsePoint),
            (0xC000_0279, SysErrorKind::ReparsePoint),
            (0xC000_0280, SysErrorKind::ReparsePoint),
            (0x0000_0104, SysErrorKind::ReparsePoint),
            (0xC000_0043, SysErrorKind::Busy),
            (0xC000_0054, SysErrorKind::Busy),
            (0xC000_0055, SysErrorKind::Busy),
            (0xC000_0056, SysErrorKind::Busy),
            (0xC000_0121, SysErrorKind::Busy),
            (0xC000_0035, SysErrorKind::AlreadyExists),
            (0xC000_0101, SysErrorKind::NotEmpty),
            (0xC000_00BB, SysErrorKind::Unsupported),
            (0xC000_0010, SysErrorKind::Unsupported),
            (0xC000_0003, SysErrorKind::Unsupported),
            (0xC000_0002, SysErrorKind::Unsupported),
            (0xC000_000D, SysErrorKind::Other),
            (0xC000_0001, SysErrorKind::Other),
        ];
        for &(code, kind) in cases {
            assert_eq!(kind_of_ntstatus(st(code)), kind, "{code:#010x}");
        }
    }

    #[test]
    fn win32_table() {
        let cases: &[(u32, SysErrorKind)] = &[
            (2, SysErrorKind::NotFound),
            (3, SysErrorKind::NotFound),
            (5, SysErrorKind::AccessDenied),
            (19, SysErrorKind::AccessDenied),
            (123, SysErrorKind::InvalidPath),
            (161, SysErrorKind::InvalidPath),
            (206, SysErrorKind::InvalidPath),
            (267, SysErrorKind::InvalidPath),
            (1920, SysErrorKind::ReparsePoint),
            (1921, SysErrorKind::ReparsePoint),
            (32, SysErrorKind::Busy),
            (33, SysErrorKind::Busy),
            (80, SysErrorKind::AlreadyExists),
            (183, SysErrorKind::AlreadyExists),
            (145, SysErrorKind::NotEmpty),
            (1, SysErrorKind::Unsupported),
            (50, SysErrorKind::Unsupported),
            (87, SysErrorKind::Other),
            (6, SysErrorKind::Other),
        ];
        for &(code, kind) in cases {
            assert_eq!(kind_of_win32(code), kind, "{code}");
        }
        assert_eq!(kind_of_win32_info(87), SysErrorKind::Unsupported);
        assert_eq!(kind_of_win32_info(5), SysErrorKind::AccessDenied);
    }

    #[test]
    fn registry_table() {
        let cases: &[(u32, SysErrorKind)] = &[
            (2, SysErrorKind::NotFound),
            (3, SysErrorKind::NotFound),
            (1018, SysErrorKind::NotFound),
            (5, SysErrorKind::AccessDenied),
            (206, SysErrorKind::InvalidPath),
            (87, SysErrorKind::InvalidPath),
            // Not mapped for the registry, unlike files: Other with the code.
            (32, SysErrorKind::Other),
            (123, SysErrorKind::Other),
            (234, SysErrorKind::Other),
            (1, SysErrorKind::Other),
            (6, SysErrorKind::Other),
        ];
        for &(code, kind) in cases {
            assert_eq!(kind_of_reg(code), kind, "{code}");
        }
        let e = reg_error(1018, "k");
        assert_eq!((e.kind, e.win32), (SysErrorKind::NotFound, Some(1018)));
        let nt: &[(u32, SysErrorKind)] = &[
            (0xC000_0034, SysErrorKind::NotFound),
            (0xC000_003A, SysErrorKind::NotFound),
            (0xC000_017C, SysErrorKind::NotFound),
            (0xC000_0022, SysErrorKind::AccessDenied),
            (0xC000_000D, SysErrorKind::InvalidPath),
            (0xC000_0033, SysErrorKind::InvalidPath),
            (0xC000_0004, SysErrorKind::Other),
            (0xC000_0043, SysErrorKind::Other),
        ];
        for &(code, kind) in nt {
            assert_eq!(kind_of_reg_ntstatus(st(code)), kind, "{code:#010x}");
        }
        let e = reg_nt_error(st(0xC000_017C), "k");
        assert_eq!(
            (e.kind, e.ntstatus, e.win32),
            (SysErrorKind::NotFound, Some(st(0xC000_017C)), None)
        );
    }

    #[test]
    fn unsupported_class_includes_invalid_parameter_only_here() {
        assert!(is_unsupported_class(STATUS_INVALID_PARAMETER));
        assert!(is_unsupported_class(st(0xC000_0003)));
        assert!(!is_unsupported_class(st(0xC000_0022)));
        assert_eq!(
            kind_of_ntstatus(STATUS_INVALID_PARAMETER),
            SysErrorKind::Other
        );
    }

    #[test]
    fn errors_carry_their_code() {
        let e = nt_error(st(0xC000_0034), "a");
        assert_eq!(e.kind, SysErrorKind::NotFound);
        assert_eq!(e.ntstatus, Some(st(0xC000_0034)));
        assert_eq!(e.win32, None);
        let e = win32_error(32, "b");
        assert_eq!(
            (e.kind, e.win32, e.ntstatus),
            (SysErrorKind::Busy, Some(32), None)
        );
        // A rename collision is Busy, a create collision AlreadyExists; both keep the status.
        let e = rename_error(STATUS_OBJECT_NAME_COLLISION, "r");
        assert_eq!(
            (e.kind, e.ntstatus),
            (SysErrorKind::Busy, Some(STATUS_OBJECT_NAME_COLLISION))
        );
        let e = nt_error(STATUS_OBJECT_NAME_COLLISION, "c");
        assert_eq!(e.kind, SysErrorKind::AlreadyExists);
        assert_eq!(
            rename_error(st(0xC000_0022), "r").kind,
            SysErrorKind::AccessDenied
        );
        // Win32 code 5 is ambiguous (ACCESS_DENIED and CANNOT_DELETE), the status is not.
        let e = nt_error(st(0xC000_0121), "d");
        assert_eq!(
            (e.kind, e.ntstatus),
            (SysErrorKind::Busy, Some(st(0xC000_0121)))
        );
        let e = win32_info_error(87, "c");
        assert_eq!((e.kind, e.win32), (SysErrorKind::Unsupported, Some(87)));
    }
}
