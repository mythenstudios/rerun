//! The only registry FFI of `sys::win` (ADR 0009, ADR 0018): `RegOpenCurrentUser`,
//! `RegOpenKeyExW`, `RegEnumKeyExW`, `RegQueryInfoKeyW`, `RegCloseKey`, for values
//! `NtQueryValueKey` and `NtEnumerateValueKey`, `NtQueryKey` for the kernel name and the flags of
//! a key; for the write side (P2-9) `RegCreateKeyExW` and `RegOpenKeyExW` of one segment with
//! `REG_OPTION_OPEN_LINK`, `NtSetValueKey`, `NtDeleteValueKey`, `NtDeleteKey` and
//! `RegFlushKey`. `WinRegistry::new`
//! refuses an impersonating thread (`OpenThreadToken`) and a current-user key that is not a
//! user hive (the `.DEFAULT` fallback of `RegOpenCurrentUser`).
//!
//! - Values are read with the NT calls, not `RegQueryValueExW`/`RegEnumValueW`: for a
//!   string-typed value stored without a terminating NUL those write a NUL into the caller's
//!   buffer behind the data, and for an odd-length one over its last byte (the reported size
//!   stays 3, the third byte comes back 0), so they do not return the stored bytes (found on
//!   Windows 11, 2026-11-04). The NT calls return type and bytes of one
//!   value from one call, exactly as stored. Key handles from `RegOpenKeyExW` are kernel
//!   handles and serve both.
//! - Key handles come back as [`OwnedKey`] and are closed on drop, also in every error path.
//!   `HKEY_LOCAL_MACHINE` is a predefined key and is never closed ([`Root::LocalMachine`]).
//! - Read opens take a [`ReadAccess`], so a write right cannot be expressed there; the write side
//!   opens with a [`WriteAccess`], always in the native view. The view flag is
//!   added on every open (`KEY_WOW64_32KEY` for the 32-bit view, `KEY_WOW64_64KEY` for the
//!   native one, so the native view is the 64-bit one even in a 32-bit build).
//!   Reads follow symbolic-link keys; only `open_link` (for `Registry::link`) opens the last
//!   segment itself with `REG_OPTION_OPEN_LINK`, and `key_flags` reads its link flag.
//! - Every call passes the size of the buffer it hands to the API and reads back at most that
//!   many units; kernel output is parsed from `Vec<u64>` buffers (8-byte aligned) by bounds-
//!   checked byte copies, never through a raw structure pointer. The callers in `registry` own
//!   the retry and limit logic.
//!
//! Every function here is a `clippy.toml` ban everywhere else.

#![allow(
    unsafe_code,
    reason = "FFI to the advapi32/ntdll registry read APIs (ADR 0009); every block has a \
              SAFETY comment"
)]

use std::ptr;

use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows_sys::Wdk::System::Registry::{
    KeyFlagsInformation, KeyNameInformation, KeyValueFullInformation, KeyValuePartialInformation,
    NtDeleteKey, NtDeleteValueKey, NtEnumerateValueKey, NtQueryKey, NtQueryValueKey, NtSetValueKey,
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::{FILETIME, UNICODE_STRING};
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Storage::FileSystem::{DELETE, READ_CONTROL};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER,
    HKEY_CURRENT_USER_LOCAL_SETTINGS, HKEY_DYN_DATA, HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA,
    HKEY_PERFORMANCE_NLSTEXT, HKEY_PERFORMANCE_TEXT, HKEY_USERS, KEY_CREATE_SUB_KEY,
    KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_32KEY,
    KEY_WOW64_64KEY, REG_CREATED_NEW_KEY, REG_OPTION_OPEN_LINK, RegCloseKey, RegCreateKeyExW,
    RegEnumKeyExW, RegFlushKey, RegOpenCurrentUser, RegOpenKeyExW, RegQueryInfoKeyW,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use super::status::{
    NtStatus, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_PARAMETER, STATUS_NO_MORE_ENTRIES, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};

/// winerror.h `ERROR_SUCCESS`.
const ERROR_SUCCESS: u32 = 0;
/// winerror.h `ERROR_FILE_NOT_FOUND`.
const ERROR_FILE_NOT_FOUND: u32 = 2;
/// winerror.h `ERROR_MORE_DATA`.
const ERROR_MORE_DATA: u32 = 234;
/// winerror.h `ERROR_NO_MORE_ITEMS`.
const ERROR_NO_MORE_ITEMS: u32 = 259;
/// winerror.h `ERROR_INVALID_HANDLE`.
const ERROR_INVALID_HANDLE: u32 = 6;

/// An open registry key, closed with `RegCloseKey` on drop. Never a predefined key (`open`
/// refuses one).
#[derive(Debug)]
pub(super) struct OwnedKey(HKEY);

// SAFETY: an HKEY returned by RegOpenKeyExW/RegOpenCurrentUser (or RegLoadAppKeyW in tests) is
// a kernel object handle; the registry APIs may use it from any thread, and `OwnedKey` only
// hands it to those APIs (read-only through `&self`) and closes it once in `drop`.
unsafe impl Send for OwnedKey {}
// SAFETY: see `Send`; concurrent registry calls on one handle are serialized by the kernel.
unsafe impl Sync for OwnedKey {}

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: `self.0` is an open, non-predefined key handle that this wrapper owns and
        // closes exactly once; nothing uses it afterwards.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

impl OwnedKey {
    /// Takes ownership of an open key handle (test fixtures: `RegLoadAppKeyW`,
    /// `RegCreateKeyExW`).
    ///
    /// # Safety
    ///
    /// `raw` must be an open registry key handle that is not a predefined key, that nothing
    /// else closes, and that is not used after the returned `OwnedKey` is dropped.
    #[cfg(test)]
    pub(super) unsafe fn from_raw(raw: HKEY) -> Self {
        Self(raw)
    }

    /// The raw handle, borrowed for a call while `self` lives (tests; and `hkeyClass` of the
    /// helper start, `elevation`).
    pub(super) fn raw(&self) -> HKEY {
        self.0
    }
}

/// The key a path is opened from.
#[derive(Debug)]
pub(super) enum Root {
    /// The predefined `HKEY_LOCAL_MACHINE` (never closed).
    LocalMachine,
    /// An open key (`RegOpenCurrentUser`, or a test hive).
    Key(OwnedKey),
}

impl Root {
    fn hkey(&self) -> HKEY {
        match self {
            Self::LocalMachine => HKEY_LOCAL_MACHINE,
            Self::Key(k) => k.0,
        }
    }
}

/// The rights a read opens a key with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadAccess {
    /// `KEY_QUERY_VALUE`: `key_exists`, `get`, `values` (and `RegQueryInfoKeyW`).
    Query,
    /// `KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE`: `subkeys`.
    Enumerate,
}

/// The WOW64 view an open uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum View {
    /// `KEY_WOW64_64KEY`.
    Native,
    /// `KEY_WOW64_32KEY`.
    Wow32,
}

/// The `samDesired` of an open (pure).
pub(super) fn sam(access: ReadAccess, view: View) -> u32 {
    let rights = match access {
        ReadAccess::Query => KEY_QUERY_VALUE,
        ReadAccess::Enumerate => KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
    };
    rights
        | match view {
            View::Native => KEY_WOW64_64KEY,
            View::Wow32 => KEY_WOW64_32KEY,
        }
}

/// Why [`open_current_user`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum UserHiveError {
    /// A Win32 error of `OpenThreadToken` or `RegOpenCurrentUser`.
    Win32(u32),
    /// The calling thread has an impersonation token: `RegOpenCurrentUser` would open the
    /// impersonated user's hive, not this process's.
    Impersonating,
    /// The returned key is not a user hive `\REGISTRY\USER\S-1-…` (the fallback to
    /// `HKEY_USERS\.DEFAULT` when the user's hive cannot be opened, or something else): its
    /// kernel name, or the `NTSTATUS` if the name could not be read.
    NotAUserHive(String),
}

/// winerror.h `ERROR_NO_TOKEN`: the thread does not impersonate.
const ERROR_NO_TOKEN: u32 = 1008;
/// winerror.h `ERROR_ACCESS_DENIED`.
const ERROR_ACCESS_DENIED: u32 = 5;

/// Does the calling thread impersonate? `OpenThreadToken` must fail with `ERROR_NO_TOKEN`.
fn thread_impersonates() -> Result<bool, u32> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentThread returns a pseudo handle that needs no closing and is valid for
    // the calling thread.
    let thread = unsafe { GetCurrentThread() };
    // SAFETY: `thread` is the current-thread pseudo handle; `raw` is valid for a write and on
    // success receives a token handle that `OwnedHandle` takes over below.
    let ok = unsafe { OpenThreadToken(thread, TOKEN_QUERY, 1, &mut raw) };
    if ok != 0 && !raw.is_null() {
        // SAFETY: `raw` was just returned by a successful OpenThreadToken; nothing else owns
        // or closes it.
        drop(unsafe { OwnedHandle::from_raw_handle(raw) });
        return Ok(true);
    }
    match last_error() {
        ERROR_NO_TOKEN => Ok(false),
        // A thread token exists but cannot be opened for query: still impersonating.
        ERROR_ACCESS_DENIED => Ok(true),
        code => Err(code),
    }
}

/// `RegOpenCurrentUser(KEY_READ)`: the hive of the user this process runs as (not the
/// per-process cached `HKEY_CURRENT_USER`). `RegOpenCurrentUser` follows the **thread**
/// token, so it is refused while the thread impersonates; and it falls back to
/// `HKEY_USERS\.DEFAULT` when it cannot open the user's hive, so the result must be a user
/// hive `\REGISTRY\USER\S-1-…` by its kernel name.
pub(super) fn open_current_user() -> Result<OwnedKey, UserHiveError> {
    if thread_impersonates().map_err(UserHiveError::Win32)? {
        return Err(UserHiveError::Impersonating);
    }
    let mut raw: HKEY = ptr::null_mut();
    #[expect(
        clippy::disallowed_methods,
        reason = "the one RegOpenCurrentUser call site (ADR 0009)"
    )]
    // SAFETY: `raw` is valid for a write; on success it receives a new key handle that is owned
    // by the returned `OwnedKey`.
    let rc = unsafe { RegOpenCurrentUser(KEY_READ, &mut raw) };
    let key = owned(rc, raw).map_err(UserHiveError::Win32)?;
    let name = key_name(&key).map_err(|st| UserHiveError::NotAUserHive(format!("{st:#010x}")))?;
    if is_user_hive(&name) {
        Ok(key)
    } else {
        Err(UserHiveError::NotAUserHive(name))
    }
}

/// `\REGISTRY\USER\S-1-…` with exactly one segment after `USER`, not a `_Classes` hive
/// (pure).
pub(super) fn is_user_hive(name: &str) -> bool {
    const PREFIX: &str = r"\REGISTRY\USER\";
    let (Some(head), Some(sid)) = (name.get(..PREFIX.len()), name.get(PREFIX.len()..)) else {
        return false;
    };
    head.eq_ignore_ascii_case(PREFIX)
        && sid.len() > 4
        && sid.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("S-1-"))
        && !sid.contains('\\')
        && !sid.to_ascii_uppercase().ends_with("_CLASSES")
}

/// `KEY_NAME_INFORMATION` buffer in `u64`s: the longest key path plus a hive prefix.
const KEY_NAME_BUFFER_U64: usize = 9_000;

/// Kernel name of an open key (`\REGISTRY\…`), via `NtQueryKey(KeyNameInformation)`.
pub(super) fn key_name(key: &OwnedKey) -> Result<String, NtStatus> {
    let mut buf = vec![0u64; KEY_NAME_BUFFER_U64];
    let cap = len_u32(buf.len() * 8);
    let mut got: u32 = 0;
    #[expect(
        clippy::disallowed_methods,
        reason = "the one NtQueryKey call site (ADR 0009)"
    )]
    // SAFETY: `key` is an open key handle kept alive by the borrow; `buf` is writable for `cap`
    // bytes, 8-byte aligned as KEY_NAME_INFORMATION needs, and outlives the call; `got` is valid
    // for a write.
    let status = unsafe {
        NtQueryKey(
            key.0,
            KeyNameInformation,
            buf.as_mut_ptr().cast(),
            cap,
            &mut got,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    let len = len_usize(u32_at(&buf, 0).ok_or(STATUS_INFO_LENGTH_MISMATCH)?);
    if len.saturating_add(4) > len_usize(got) || !len.is_multiple_of(2) {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let bytes = bytes_at(&buf, 4, len).ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

/// `RegOpenKeyExW(root, path, 0, sam(access, view))`. `path` is a checked key path (no NUL,
/// `\`-separated, empty = a new handle to `root` itself).
pub(super) fn open(
    root: &Root,
    path: &str,
    access: ReadAccess,
    view: View,
) -> Result<OwnedKey, u32> {
    let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let mut raw: HKEY = ptr::null_mut();
    #[expect(
        clippy::disallowed_methods,
        reason = "the one RegOpenKeyExW call site (ADR 0009)"
    )]
    // SAFETY: `root` is HKEY_LOCAL_MACHINE or an open key that `root` keeps alive for the call;
    // `wide` is NUL-terminated and outlives the call; `raw` is valid for a write and on success
    // receives a new key handle owned by the returned `OwnedKey`. Options 0: no
    // REG_OPTION_OPEN_LINK, links are followed.
    let rc = unsafe { RegOpenKeyExW(root.hkey(), wide.as_ptr(), 0, sam(access, view), &mut raw) };
    owned(rc, raw)
}

/// `RegOpenKeyExW(root, path, REG_OPTION_OPEN_LINK, KEY_QUERY_VALUE | view)`: every segment
/// but the last is followed like on every read, the last one is opened itself, so a
/// symbolic-link key comes back as the link (`Registry::link`, ADR 0009 amendment P2-9).
pub(super) fn open_link(root: &Root, path: &str, view: View) -> Result<OwnedKey, u32> {
    let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let mut raw: HKEY = ptr::null_mut();
    #[expect(
        clippy::disallowed_methods,
        reason = "the RegOpenKeyExW call site of Registry::link (ADR 0009 amendment P2-9)"
    )]
    // SAFETY: `root` is HKEY_LOCAL_MACHINE or an open key that `root` keeps alive for the call;
    // `wide` is NUL-terminated and outlives the call; `raw` is valid for a write and on success
    // receives a new key handle owned by the returned `OwnedKey`.
    let rc = unsafe {
        RegOpenKeyExW(
            root.hkey(),
            wide.as_ptr(),
            REG_OPTION_OPEN_LINK,
            sam(ReadAccess::Query, view),
            &mut raw,
        )
    };
    owned(rc, raw)
}

/// `KEY_FLAGS_INFORMATION.KeyFlags` bit of a symbolic-link key.
pub(super) const REG_FLAG_LINK: u32 = 0x2;

/// `NtQueryKey(KeyFlagsInformation)`: the `KeyFlags` of an open key (needs `KEY_QUERY_VALUE`;
/// [`REG_FLAG_LINK`]). `KEY_FLAGS_INFORMATION` is `Wow64Flags`,
/// `KeyFlags`, `ControlFlags`, three `ULONG`s.
pub(super) fn key_flags(key: &OwnedKey) -> Result<u32, NtStatus> {
    let mut buf = [0u64; 2];
    let cap = len_u32(buf.len() * 8);
    let mut got: u32 = 0;
    #[expect(
        clippy::disallowed_methods,
        reason = "the NtQueryKey(KeyFlagsInformation) call site (ADR 0018)"
    )]
    // SAFETY: `key` is an open key handle kept alive by the borrow; `buf` is writable for `cap`
    // bytes (16, more than the 12 of KEY_FLAGS_INFORMATION), 8-byte aligned, and outlives the
    // call; `got` is valid for a write.
    let status = unsafe {
        NtQueryKey(
            key.0,
            KeyFlagsInformation,
            buf.as_mut_ptr().cast(),
            cap,
            &mut got,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    if len_usize(got) < 12 {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    u32_at(&buf, 4).ok_or(STATUS_INFO_LENGTH_MISMATCH)
}

fn owned(rc: u32, raw: HKEY) -> Result<OwnedKey, u32> {
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    if raw.is_null() {
        // Success without a handle: a failure (nothing to close).
        return Err(ERROR_INVALID_HANDLE);
    }
    if is_predefined(raw) {
        // The registry documents that an empty path below a predefined key may hand back that
        // same predefined key. Closing it would close the process-wide cached key, and the NT
        // value calls cannot use it: refuse, without closing. (Windows 11 returns a new handle;
        // `the_hive_root_is_a_new_handle` pins that.)
        return Err(ERROR_INVALID_HANDLE);
    }
    Ok(OwnedKey(raw))
}

/// One of the predefined `HKEY_*` values (pure).
fn is_predefined(raw: HKEY) -> bool {
    [
        HKEY_CLASSES_ROOT,
        HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE,
        HKEY_USERS,
        HKEY_PERFORMANCE_DATA,
        HKEY_CURRENT_CONFIG,
        HKEY_DYN_DATA,
        HKEY_CURRENT_USER_LOCAL_SETTINGS,
        HKEY_PERFORMANCE_TEXT,
        HKEY_PERFORMANCE_NLSTEXT,
    ]
    .contains(&raw)
}

fn len_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn len_usize(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// The little-endian `u32` at byte `at` of `words` (the kernel's output buffer), if inside.
fn u32_at(words: &[u64], at: usize) -> Option<u32> {
    let mut b = [0u8; 4];
    for (i, out) in b.iter_mut().enumerate() {
        *out = byte_at(words, at.checked_add(i)?)?;
    }
    Some(u32::from_le_bytes(b))
}

fn byte_at(words: &[u64], at: usize) -> Option<u8> {
    let w = words.get(at / 8)?;
    w.to_le_bytes().get(at % 8).copied()
}

/// Bytes `range` of `words`, copied out; `None` if outside.
fn bytes_at(words: &[u64], start: usize, len: usize) -> Option<Vec<u8>> {
    let end = start.checked_add(len)?;
    if end > words.len().checked_mul(8)? {
        return None;
    }
    let first = start / 8;
    let last = end.div_ceil(8);
    let raw: Vec<u8> = words[first..last]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let off = start - first * 8;
    Some(raw[off..off + len].to_vec())
}

/// `words` with room for at least `bytes` bytes.
fn ensure_bytes(words: &mut Vec<u64>, bytes: usize) {
    let need = bytes.div_ceil(8).max(1);
    if words.len() < need {
        words.resize(need, 0);
    }
}

/// `KEY_VALUE_PARTIAL_INFORMATION`: `TitleIndex`, `Type`, `DataLength`, then the data.
const PARTIAL_HEADER: usize = 12;
/// `KEY_VALUE_FULL_INFORMATION`: `TitleIndex`, `Type`, `DataOffset`, `DataLength`,
/// `NameLength`, then the name.
const FULL_HEADER: usize = 20;

/// A value as stored: type number and bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RawData {
    pub kind: u32,
    pub data: Vec<u8>,
}

/// The outcome of one value read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Read {
    /// The value, exactly as stored.
    Value(RawData),
    /// The value does not exist (the key does).
    Missing,
    /// The buffer is too small; the data needs `needed` bytes.
    MoreData { needed: usize },
}

/// `NtQueryValueKey(key, name, KeyValuePartialInformation)` with room for `cap` data bytes in
/// `scratch`. Not `RegQueryValueExW`, which fixes up string-typed values (module docs).
pub(super) fn query_value(
    key: &OwnedKey,
    name: &str,
    cap: usize,
    scratch: &mut Vec<u64>,
) -> Result<Read, NtStatus> {
    let units: Vec<u16> = name.encode_utf16().collect();
    // A value name has at most 16,383 units (checked by the caller), so it fits a u16 length.
    let bytes = u16::try_from(units.len() * 2).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let us = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: units.as_ptr().cast_mut(),
    };
    ensure_bytes(scratch, PARTIAL_HEADER.saturating_add(cap));
    let size = len_u32(scratch.len().saturating_mul(8));
    let mut got: u32 = 0;
    #[expect(
        clippy::disallowed_methods,
        reason = "the one NtQueryValueKey call site (ADR 0009)"
    )]
    // SAFETY: `key` is an open key handle kept alive by the borrow; `us` describes `units`
    // (exactly `bytes` bytes, alive until after the call; the kernel only reads it); `scratch`
    // is writable for `size` bytes (its length in bytes, capped at u32::MAX), 8-byte aligned,
    // and outlives the call; `got` is valid for a write.
    let status = unsafe {
        NtQueryValueKey(
            key.0,
            &us,
            KeyValuePartialInformation,
            scratch.as_mut_ptr().cast(),
            size,
            &mut got,
        )
    };
    match status {
        STATUS_SUCCESS => {
            let kind = u32_at(scratch, 4).ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
            let len = len_usize(u32_at(scratch, 8).ok_or(STATUS_INFO_LENGTH_MISMATCH)?);
            if PARTIAL_HEADER.saturating_add(len) > len_usize(got) {
                return Err(STATUS_INFO_LENGTH_MISMATCH);
            }
            let data = bytes_at(scratch, PARTIAL_HEADER, len).ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
            Ok(Read::Value(RawData { kind, data }))
        }
        STATUS_BUFFER_OVERFLOW | STATUS_BUFFER_TOO_SMALL => Ok(Read::MoreData {
            needed: len_usize(got).saturating_sub(PARTIAL_HEADER),
        }),
        STATUS_OBJECT_NAME_NOT_FOUND => Ok(Read::Missing),
        other => Err(other),
    }
}

/// One entry of [`enum_value`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EnumValue {
    /// A value: its name (UTF-16) and the value exactly as stored.
    Entry { name: Vec<u16>, value: RawData },
    /// The buffer is too small; the whole entry needs `needed` bytes (header, name, data).
    MoreData { needed: usize },
    /// No value at this index.
    End,
}

/// Bytes of the fixed part and the longest name of a `KEY_VALUE_FULL_INFORMATION`, plus
/// alignment of the data.
pub(super) const FULL_OVERHEAD: usize = FULL_HEADER + 2 * 16_383 + 8;

/// `NtEnumerateValueKey(key, index, KeyValueFullInformation)` with room for `cap` bytes in
/// `scratch` (the whole entry). Not `RegEnumValueW`, which fixes up strings like
/// `RegQueryValueExW` (see [`query_value`]).
pub(super) fn enum_value(
    key: &OwnedKey,
    index: u32,
    cap: usize,
    scratch: &mut Vec<u64>,
) -> Result<EnumValue, NtStatus> {
    ensure_bytes(scratch, cap);
    let size = len_u32(scratch.len().saturating_mul(8));
    let mut got: u32 = 0;
    #[expect(
        clippy::disallowed_methods,
        reason = "the one NtEnumerateValueKey call site (ADR 0009)"
    )]
    // SAFETY: `key` is an open key handle kept alive by the borrow; `scratch` is writable for
    // `size` bytes (its length in bytes, capped at u32::MAX), 8-byte aligned, and outlives the
    // call; `got` is valid for a write.
    let status = unsafe {
        NtEnumerateValueKey(
            key.0,
            index,
            KeyValueFullInformation,
            scratch.as_mut_ptr().cast(),
            size,
            &mut got,
        )
    };
    match status {
        STATUS_SUCCESS => {
            let bad = STATUS_INFO_LENGTH_MISMATCH;
            let got = len_usize(got);
            let kind = u32_at(scratch, 4).ok_or(bad)?;
            let data_off = len_usize(u32_at(scratch, 8).ok_or(bad)?);
            let data_len = len_usize(u32_at(scratch, 12).ok_or(bad)?);
            let name_len = len_usize(u32_at(scratch, 16).ok_or(bad)?);
            if FULL_HEADER.saturating_add(name_len) > got
                || !name_len.is_multiple_of(2)
                || (data_len > 0 && data_off.saturating_add(data_len) > got)
            {
                return Err(bad);
            }
            let name_bytes = bytes_at(scratch, FULL_HEADER, name_len).ok_or(bad)?;
            let name = name_bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            let data = if data_len == 0 {
                Vec::new()
            } else {
                bytes_at(scratch, data_off, data_len).ok_or(bad)?
            };
            Ok(EnumValue::Entry {
                name,
                value: RawData { kind, data },
            })
        }
        STATUS_BUFFER_OVERFLOW | STATUS_BUFFER_TOO_SMALL => Ok(EnumValue::MoreData {
            needed: len_usize(got),
        }),
        STATUS_NO_MORE_ENTRIES => Ok(EnumValue::End),
        other => Err(other),
    }
}

/// `RegEnumKeyExW(key, index, name, …)`: the length of the name in `name`, or `None` at the
/// end. A name that does not fit is `ERROR_MORE_DATA` (key names have at most 255 units, so a
/// buffer of 256 always fits).
pub(super) fn enum_key(key: &OwnedKey, index: u32, name: &mut [u16]) -> Result<Option<usize>, u32> {
    let cap = len_u32(name.len());
    let mut len = cap;
    #[expect(
        clippy::disallowed_methods,
        reason = "the one RegEnumKeyExW call site (ADR 0009)"
    )]
    // SAFETY: `key` is an open key kept alive by the borrow; `name` is writable for `len`
    // UTF-16 units (its length, capped at u32::MAX) and outlives the call; `len` is valid for a
    // write; class and time pointers are null (not requested).
    let rc = unsafe {
        RegEnumKeyExW(
            key.0,
            index,
            name.as_mut_ptr(),
            &mut len,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    match rc {
        ERROR_SUCCESS if len < cap => Ok(Some(len_usize(len))),
        ERROR_SUCCESS => Err(ERROR_MORE_DATA),
        ERROR_NO_MORE_ITEMS => Ok(None),
        code => Err(code),
    }
}

/// What `RegQueryInfoKeyW` reports about a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KeyInfo {
    /// Number of subkeys.
    pub subkeys: usize,
    /// Number of values.
    pub values: usize,
    /// Longest value data in bytes (an upper bound; Windows does not lower it on delete).
    pub max_value_len: usize,
    /// Last write time (`FILETIME` as one number).
    pub last_write: u64,
}

/// `RegQueryInfoKeyW(key)`: counts, the largest value size and the last write time.
pub(super) fn info(key: &OwnedKey) -> Result<KeyInfo, u32> {
    let mut subkeys: u32 = 0;
    let mut values: u32 = 0;
    let mut max_value_len: u32 = 0;
    let mut time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "the one RegQueryInfoKeyW call site (ADR 0009)"
    )]
    // SAFETY: `key` is an open key kept alive by the borrow; `subkeys`, `values`,
    // `max_value_len` and `time` are valid for writes; every other out pointer is null (not
    // requested), which the API allows.
    let rc = unsafe {
        RegQueryInfoKeyW(
            key.0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            &mut subkeys,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut values,
            ptr::null_mut(),
            &mut max_value_len,
            ptr::null_mut(),
            &mut time,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    Ok(KeyInfo {
        subkeys: len_usize(subkeys),
        values: len_usize(values),
        max_value_len: len_usize(max_value_len),
        last_write: (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime),
    })
}

// ---------- Write side (ADR 0018, amendment P2-9) ----------

/// `KEY_FLAGS_INFORMATION.KeyFlags` bit of a volatile key.
pub(super) const REG_FLAG_VOLATILE: u32 = 0x1;

/// The rights a write-side open asks for (`sys::seq::reg::KeyAccess`); each includes
/// `KEY_QUERY_VALUE` (flags, values, counts) and `READ_CONTROL` (the kernel name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteAccess {
    /// Query only.
    Query,
    /// And `KEY_CREATE_SUB_KEY`.
    CreateSub,
    /// And `KEY_SET_VALUE`.
    SetValue,
    /// And `DELETE`.
    Delete,
}

/// The `samDesired` of a write-side open (pure): always the native view.
pub(super) fn write_sam(a: WriteAccess) -> u32 {
    let extra = match a {
        WriteAccess::Query => 0,
        WriteAccess::CreateSub => KEY_CREATE_SUB_KEY,
        WriteAccess::SetValue => KEY_SET_VALUE,
        WriteAccess::Delete => DELETE,
    };
    KEY_QUERY_VALUE | READ_CONTROL | KEY_WOW64_64KEY | extra
}

/// A new handle to `root` itself (`RegOpenKeyExW(root, "", 0, sam)`), the start of a walk.
pub(super) fn reopen(root: &Root, a: WriteAccess) -> Result<OwnedKey, u32> {
    let empty = [0u16];
    let mut raw: HKEY = ptr::null_mut();
    #[expect(
        clippy::disallowed_methods,
        reason = "the write-side RegOpenKeyExW of the hive root (ADR 0018)"
    )]
    // SAFETY: `root` is HKEY_LOCAL_MACHINE or an open key that `root` keeps alive for the call;
    // `empty` is a NUL-terminated empty string that outlives the call; `raw` is valid for a
    // write and on success receives a new key handle owned by the returned `OwnedKey`.
    let rc = unsafe { RegOpenKeyExW(root.hkey(), empty.as_ptr(), 0, write_sam(a), &mut raw) };
    owned(rc, raw)
}

/// `RegOpenKeyExW(parent, seg, REG_OPTION_OPEN_LINK, sam)`: the one segment `seg` itself, a
/// link opened and never followed. `Ok(None)`: missing.
pub(super) fn open_segment(
    parent: &OwnedKey,
    seg: &str,
    a: WriteAccess,
) -> Result<Option<OwnedKey>, u32> {
    let wide: Vec<u16> = seg.encode_utf16().chain([0]).collect();
    let mut raw: HKEY = ptr::null_mut();
    #[expect(
        clippy::disallowed_methods,
        reason = "the write-side RegOpenKeyExW of one segment (ADR 0018)"
    )]
    // SAFETY: `parent` is an open key kept alive by the borrow; `wide` is NUL-terminated and
    // outlives the call; `raw` is valid for a write and on success receives a new key handle
    // owned by the returned `OwnedKey`.
    let rc = unsafe {
        RegOpenKeyExW(
            parent.0,
            wide.as_ptr(),
            REG_OPTION_OPEN_LINK,
            write_sam(a),
            &mut raw,
        )
    };
    match rc {
        ERROR_FILE_NOT_FOUND => Ok(None),
        _ => owned(rc, raw).map(Some),
    }
}

/// `RegCreateKeyExW(parent, seg, REG_OPTION_OPEN_LINK, sam)`: opens or creates the one
/// segment `seg` itself (non-volatile); `true` if this call created it (the disposition).
pub(super) fn create_segment(
    parent: &OwnedKey,
    seg: &str,
    a: WriteAccess,
) -> Result<(OwnedKey, bool), u32> {
    let wide: Vec<u16> = seg.encode_utf16().chain([0]).collect();
    let mut raw: HKEY = ptr::null_mut();
    let mut disposition: u32 = 0;
    #[expect(
        clippy::disallowed_methods,
        reason = "the one RegCreateKeyExW call site (ADR 0018)"
    )]
    // SAFETY: `parent` is an open key kept alive by the borrow; `wide` is NUL-terminated and
    // outlives the call; class and security attributes are null; `raw` and `disposition` are
    // valid for writes, and on success `raw` is a new key handle owned by the returned
    // `OwnedKey`.
    let rc = unsafe {
        RegCreateKeyExW(
            parent.0,
            wide.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_OPEN_LINK,
            write_sam(a),
            ptr::null(),
            &mut raw,
            &mut disposition,
        )
    };
    let key = owned(rc, raw)?;
    Ok((key, disposition == REG_CREATED_NEW_KEY))
}

/// A value name as a counted `UNICODE_STRING` over `units` (at most 16,383 units, checked by
/// the caller, so the byte length fits a `u16`).
fn name_string(units: &[u16]) -> Result<UNICODE_STRING, NtStatus> {
    let bytes = u16::try_from(units.len() * 2).map_err(|_| STATUS_INVALID_PARAMETER)?;
    Ok(UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: units.as_ptr().cast_mut(),
    })
}

/// `NtSetValueKey(key, name, kind, data)`: stores exactly these bytes (not `RegSetValueExW`,
/// which may extend a string-typed value by a NUL behind the caller's buffer, ADR 0009).
pub(super) fn set_value(
    key: &OwnedKey,
    name: &str,
    kind: u32,
    data: &[u8],
) -> Result<(), NtStatus> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let us = name_string(&units)?;
    let len = u32::try_from(data.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    #[expect(
        clippy::disallowed_methods,
        reason = "the one NtSetValueKey call site (ADR 0018)"
    )]
    // SAFETY: `key` is an open key (KEY_SET_VALUE) kept alive by the borrow; `us` describes
    // `units` (exactly its byte length, read only) and `data` is readable for `len` bytes;
    // both outlive the call.
    let status = unsafe { NtSetValueKey(key.0, &us, 0, kind, data.as_ptr().cast(), len) };
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

/// `NtDeleteValueKey(key, name)`.
pub(super) fn delete_value(key: &OwnedKey, name: &str) -> Result<(), NtStatus> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let us = name_string(&units)?;
    #[expect(
        clippy::disallowed_methods,
        reason = "the one NtDeleteValueKey call site (ADR 0018)"
    )]
    // SAFETY: `key` is an open key (KEY_SET_VALUE) kept alive by the borrow; `us` describes
    // `units` (exactly its byte length, read only), which outlives the call.
    let status = unsafe { NtDeleteValueKey(key.0, &us) };
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

/// `NtDeleteKey(key)`: deletes the key the handle refers to (opened with `DELETE`); the
/// handle stays valid and is closed by `OwnedKey`.
pub(super) fn delete_key(key: &OwnedKey) -> Result<(), NtStatus> {
    #[expect(
        clippy::disallowed_methods,
        reason = "the one NtDeleteKey call site (ADR 0018)"
    )]
    // SAFETY: `key` is an open key with DELETE access, kept alive by the borrow until after
    // the call.
    let status = unsafe { NtDeleteKey(key.0) };
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

/// `RegFlushKey(key)`: writes the key's hive to disk (any access right suffices, observed).
pub(super) fn flush(key: &OwnedKey) -> Result<(), u32> {
    #[expect(
        clippy::disallowed_methods,
        reason = "the one RegFlushKey call site (ADR 0018)"
    )]
    // SAFETY: `key` is an open key kept alive by the borrow until after the call.
    let rc = unsafe { RegFlushKey(key.0) };
    if rc == ERROR_SUCCESS { Ok(()) } else { Err(rc) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_hive_names() {
        for ok in [
            r"\REGISTRY\USER\S-1-5-21-1-2-3-1001",
            r"\Registry\User\s-1-5-18",
        ] {
            assert!(is_user_hive(ok), "{ok}");
        }
        for bad in [
            r"\REGISTRY\USER\.DEFAULT",
            r"\REGISTRY\USER\S-1-5-21-1-2-3-1001_Classes",
            r"\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software",
            r"\REGISTRY\USER\S-1-",
            r"\REGISTRY\MACHINE",
            r"\REGISTRY\A\{x}",
            "",
        ] {
            assert!(!is_user_hive(bad), "{bad}");
        }
    }

    #[test]
    fn predefined_keys_are_recognised() {
        assert!(is_predefined(HKEY_LOCAL_MACHINE));
        assert!(is_predefined(HKEY_CURRENT_USER));
        assert!(!is_predefined(ptr::null_mut()));
    }

    /// `RegOpenKeyExW(HKEY_LOCAL_MACHINE, "")` gives a new kernel handle (not the predefined
    /// key), so dropping it leaves `HKEY_LOCAL_MACHINE` usable and the NT value calls work.
    #[test]
    fn the_hive_root_is_a_new_handle() {
        for _ in 0..3 {
            let root = open(&Root::LocalMachine, "", ReadAccess::Query, View::Native).unwrap();
            assert!(!is_predefined(root.0));
            let mut scratch = Vec::new();
            assert!(query_value(&root, "rerun-no-such-value", 64, &mut scratch).is_ok());
            assert!(
                key_name(&root)
                    .unwrap()
                    .eq_ignore_ascii_case(r"\REGISTRY\MACHINE")
            );
        }
        let k = open(
            &Root::LocalMachine,
            r"SYSTEM\CurrentControlSet\Control",
            ReadAccess::Query,
            View::Native,
        )
        .unwrap();
        assert!(info(&k).is_ok());
    }

    #[test]
    fn the_current_user_hive_is_the_users_own() {
        assert!(!thread_impersonates().unwrap());
        let k = open_current_user().unwrap();
        assert!(is_user_hive(&key_name(&k).unwrap()));
    }

    #[test]
    fn every_open_carries_its_view_and_no_write_right() {
        for access in [ReadAccess::Query, ReadAccess::Enumerate] {
            let native = sam(access, View::Native);
            let wow = sam(access, View::Wow32);
            assert_eq!(native & KEY_WOW64_64KEY, KEY_WOW64_64KEY);
            assert_eq!(native & KEY_WOW64_32KEY, 0);
            assert_eq!(wow & KEY_WOW64_32KEY, KEY_WOW64_32KEY);
            assert_eq!(wow & KEY_WOW64_64KEY, 0);
            // KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_CREATE_LINK, DELETE, WRITE_DAC, WRITE_OWNER.
            let writes = 0x2 | 0x4 | 0x20 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000;
            assert_eq!(native & writes, 0);
            assert_eq!(wow & writes, 0);
        }
        assert_eq!(sam(ReadAccess::Query, View::Native) & 0xFF, KEY_QUERY_VALUE);
        assert_eq!(
            sam(ReadAccess::Enumerate, View::Native) & 0xFF,
            KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS
        );
    }
}
