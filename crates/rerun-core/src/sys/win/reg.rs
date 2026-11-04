//! The only registry FFI of `sys::win` (ADR 0009): `RegOpenCurrentUser`, `RegOpenKeyExW`,
//! `RegEnumKeyExW`, `RegQueryInfoKeyW`, `RegCloseKey`, and for values `NtQueryValueKey` and
//! `NtEnumerateValueKey`.
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
//! - Opens take a [`ReadAccess`], so a write right cannot be expressed here. The view flag is
//!   added on every open (`KEY_WOW64_32KEY` for the 32-bit view, `KEY_WOW64_64KEY` for the
//!   native one, so the native view is the 64-bit one even in a 32-bit build).
//!   `REG_OPTION_OPEN_LINK` is never used: symbolic-link keys are followed on reads.
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

use windows_sys::Wdk::System::Registry::{
    KeyValueFullInformation, KeyValuePartialInformation, NtEnumerateValueKey, NtQueryValueKey,
};
use windows_sys::Win32::Foundation::{FILETIME, UNICODE_STRING};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_READ, KEY_WOW64_32KEY,
    KEY_WOW64_64KEY, RegCloseKey, RegEnumKeyExW, RegOpenCurrentUser, RegOpenKeyExW,
    RegQueryInfoKeyW,
};

use super::status::{
    NtStatus, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_PARAMETER, STATUS_NO_MORE_ENTRIES, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};

/// winerror.h `ERROR_SUCCESS`.
const ERROR_SUCCESS: u32 = 0;
/// winerror.h `ERROR_MORE_DATA`.
const ERROR_MORE_DATA: u32 = 234;
/// winerror.h `ERROR_NO_MORE_ITEMS`.
const ERROR_NO_MORE_ITEMS: u32 = 259;
/// winerror.h `ERROR_INVALID_HANDLE`.
const ERROR_INVALID_HANDLE: u32 = 6;

/// An open registry key, closed with `RegCloseKey` on drop. Never a predefined key.
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

    /// The raw handle, borrowed for a call while `self` lives.
    #[cfg(test)]
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

/// `RegOpenCurrentUser(KEY_READ)`: the hive of the user this process runs as (not the
/// per-process cached `HKEY_CURRENT_USER`).
pub(super) fn open_current_user() -> Result<OwnedKey, u32> {
    let mut raw: HKEY = ptr::null_mut();
    #[expect(
        clippy::disallowed_methods,
        reason = "the one RegOpenCurrentUser call site (ADR 0009)"
    )]
    // SAFETY: `raw` is valid for a write; on success it receives a new key handle that is owned
    // by the returned `OwnedKey`.
    let rc = unsafe { RegOpenCurrentUser(KEY_READ, &mut raw) };
    owned(rc, raw)
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

fn owned(rc: u32, raw: HKEY) -> Result<OwnedKey, u32> {
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    if raw.is_null() {
        // Success without a handle: a failure (nothing to close).
        return Err(ERROR_INVALID_HANDLE);
    }
    Ok(OwnedKey(raw))
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

#[cfg(test)]
mod tests {
    use super::*;

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
