//! [`WinRegistry`]: the real [`Registry`] (ADR 0009) and [`RegistryWrite`] (ADR 0018). No
//! `unsafe`; the FFI is in `reg`.
//!
//! - `Hive::CurrentUser` is the handle from `RegOpenCurrentUser(KEY_READ)`, taken once in
//!   [`WinRegistry::new`] (the predefined `HKEY_CURRENT_USER` is cached per process and wrong
//!   under impersonation); `Hive::LocalMachine` is `HKEY_LOCAL_MACHINE`.
//! - Every method applies [`check_key`] and [`check_value_name`] first, then opens the full
//!   path from the hive root in one `RegOpenKeyExW`, with the view flag (`KEY_WOW64_32KEY` for
//!   [`RegView::Wow32`]). Links are followed; `link` opens the last segment itself
//!   (`REG_OPTION_OPEN_LINK`) and reads its `KeyFlags` and `SymbolicLinkValue`. `key_exists`,
//!   `get`, `values` and `link` open with `KEY_QUERY_VALUE`, `subkeys` with
//!   `KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE`; a denied open is `AccessDenied`, also for
//!   `key_exists`.
//! - Values come back through [`RegValue::decode`], so a malformed or unknown value is
//!   [`RegValue::Raw`] with its exact bytes.
//! - Limits for untrusted data ([`MAX_VALUE_BYTES`], [`MAX_VALUES`], [`MAX_VALUES_TOTAL_BYTES`],
//!   [`MAX_SUBKEYS`]): beyond one, `TooLarge` with that limit, never a partial result.
//! - Races: a too-small buffer (`STATUS_BUFFER_OVERFLOW`) grows to the reported size (capped by
//!   the limit) and the read retries, at most [`MORE_DATA_RETRIES`] times, then `Busy`; type
//!   and data always come from one successful call. `values` and `subkeys` compare the key's
//!   last-write time before and
//!   after the enumeration and restart on a change or a duplicate name, at most
//!   [`ENUM_ATTEMPTS`] times, then `Busy`.
//! - Enumerated names are converted lossily (U+FFFD), like `read_dir`.
//! - Write side (P2-9): the sequences of `sys::seq::reg` over [`WinKey`] (one `OwnedKey`): each
//!   segment opened or created by itself relative to its parent with `REG_OPTION_OPEN_LINK` and
//!   `KEY_QUERY_VALUE | READ_CONTROL` plus the one right it needs, in the native view; the walk
//!   starts from a new handle to the hive root (a `RegOpenKeyExW(root, "")`), the kernel names
//!   are compared with the root's, taken once in [`WinRegistry::new`]. An elevated process
//!   (`TokenElevation`, or a token that cannot be asked) changes nothing. `STATUS_KEY_DELETED`
//!   is `Busy`, `NtDeleteKey` on a key with subkeys `NotEmpty`.

use std::collections::HashSet;
use std::fmt;

use super::reg::{
    self, EnumValue, OwnedKey, Read, ReadAccess, Root, UserHiveError, View, WriteAccess,
};
use super::status::{reg_error, reg_nt_error};
use super::token;
use crate::sys::registry::{
    Hive, KeyState, MAX_SUBKEYS, MAX_VALUE_BYTES, MAX_VALUES, MAX_VALUES_TOTAL_BYTES, RegKey,
    RegLink, RegValue, RegView, Registry, RegistryWrite, check_key, check_value_name,
};
use crate::sys::seq::reg::{self as reg_seq, KeyAccess, KeyFlags, KeySeg, PrimHive, PrimKey};
use crate::sys::{SysError, SysErrorKind, SysResult};

/// Attempts of one read after "buffer too small" (`STATUS_BUFFER_OVERFLOW`).
pub(super) const MORE_DATA_RETRIES: usize = 16;
/// Attempts of one enumeration (restart on a change or a duplicate name).
pub(super) const ENUM_ATTEMPTS: usize = 8;
/// First buffer of a value read; grown to the reported size.
const FIRST_BUFFER: usize = 512;
/// A key name has at most 255 UTF-16 units, plus the NUL.
const KEY_NAME_BUFFER: usize = 256;

/// The real registry. Read-only in phase 1.
pub struct WinRegistry {
    current_user: Root,
    local_machine: Root,
    /// Kernel name of the `current_user` root (`\REGISTRY\USER\<SID>`; a test: the app hive
    /// key), the start of every kernel-name check of the write side.
    user_name: String,
    /// The process token is elevated (or that could not be told): the write side refuses
    /// every change (S2).
    elevated: bool,
}

impl fmt::Debug for WinRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinRegistry").finish_non_exhaustive()
    }
}

impl WinRegistry {
    /// The registry of the user this process runs as (`RegOpenCurrentUser`) and
    /// `HKEY_LOCAL_MACHINE`.
    ///
    /// # Errors
    ///
    /// `RegOpenCurrentUser` fails (`Other` with its Win32 code); the calling thread
    /// impersonates (`Unsupported`: `RegOpenCurrentUser` follows the thread token and would
    /// open the impersonated user's hive); or the key it returns is not a user hive
    /// (`Unsupported`, e.g. the fallback to `HKEY_USERS\.DEFAULT` when the user's hive cannot
    /// be opened).
    pub fn new() -> SysResult<Self> {
        const WHAT: &str = "RegOpenCurrentUser";
        let current_user = reg::open_current_user().map_err(|e| match e {
            UserHiveError::Win32(code) => reg_error(code, WHAT),
            UserHiveError::Impersonating => SysError::new(
                SysErrorKind::Unsupported,
                format!(
                    "{WHAT}: the calling thread impersonates; the registry is opened only for \
                     the process's own user"
                ),
            ),
            UserHiveError::NotAUserHive(name) => SysError::new(
                SysErrorKind::Unsupported,
                format!("{WHAT}: returned {name:?}, not the user's own hive (profile not loaded?)"),
            ),
        })?;
        let user_name = reg::key_name(&current_user).map_err(|st| reg_nt_error(st, WHAT))?;
        Ok(Self {
            current_user: Root::Key(current_user),
            local_machine: Root::LocalMachine,
            user_name,
            // Fail closed: a token that cannot be asked counts as elevated.
            elevated: token::process_elevated().unwrap_or(true),
        })
    }

    /// Test only: both hives mapped to keys of a private app hive (ADR 0009).
    #[cfg(test)]
    pub(super) fn with_roots(current_user: OwnedKey, local_machine: OwnedKey) -> Self {
        let user_name = reg::key_name(&current_user).unwrap_or_default();
        Self {
            current_user: Root::Key(current_user),
            local_machine: Root::Key(local_machine),
            user_name,
            elevated: false,
        }
    }

    /// Test only: the write side treats the process as elevated (S2).
    #[cfg(test)]
    pub(super) fn set_elevated(&mut self, on: bool) {
        self.elevated = on;
    }

    fn root(&self, hive: Hive) -> &Root {
        match hive {
            Hive::CurrentUser => &self.current_user,
            Hive::LocalMachine => &self.local_machine,
        }
    }

    /// Opens `k` (already checked) with `access` in its view.
    fn open(&self, k: &RegKey, access: ReadAccess) -> SysResult<OwnedKey> {
        reg::open(self.root(k.hive), &k.path, access, view_of(k.view))
            .map_err(|code| reg_error(code, &k.to_string()))
    }

    fn info(key: &OwnedKey, k: &RegKey) -> SysResult<reg::KeyInfo> {
        reg::info(key).map_err(|code| reg_error(code, &k.to_string()))
    }
}

/// The `reg` view of a [`RegView`].
fn view_of(v: RegView) -> View {
    match v {
        RegView::Native => View::Native,
        RegView::Wow32 => View::Wow32,
    }
}

/// A read over one of the limits for untrusted data: `TooLarge` with that limit.
fn too_large(target: &str, why: &str, limit: usize) -> SysError {
    SysError::too_large(
        format!("{target}: {why}"),
        u64::try_from(limit).unwrap_or(u64::MAX),
    )
}

fn busy(target: &str, why: &str) -> SysError {
    SysError::new(SysErrorKind::Busy, format!("{target}: {why}"))
}

/// A refused value size (pure): above [`MAX_VALUE_BYTES`].
fn check_size(needed: usize, target: &str) -> SysResult<()> {
    if needed > MAX_VALUE_BYTES {
        Err(too_large(
            target,
            &format!("value of {needed} bytes is over the limit of {MAX_VALUE_BYTES}"),
            MAX_VALUE_BYTES,
        ))
    } else {
        Ok(())
    }
}

/// The next buffer size after a too-small buffer (pure): the reported size, at least one byte
/// more than the current buffer (a reported size that does not grow would loop).
fn grown(current: usize, needed: usize) -> usize {
    needed.max(current.saturating_add(1)).min(MAX_VALUE_BYTES)
}

/// Bookkeeping of one enumeration attempt (pure): `Err` for a limit, `Ok(false)` for a
/// duplicate name (restart).
struct Tally {
    /// Raw UTF-16 names: two names that differ only in unpaired surrogates are different.
    seen: HashSet<Vec<u16>>,
    count: usize,
    bytes: usize,
}

impl Tally {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            count: 0,
            bytes: 0,
        }
    }

    fn add(
        &mut self,
        name: &[u16],
        bytes: usize,
        max_count: usize,
        max_bytes: usize,
        target: &str,
    ) -> SysResult<bool> {
        self.count += 1;
        if self.count > max_count {
            return Err(too_large(
                target,
                &format!("more than {max_count} entries"),
                max_count,
            ));
        }
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > max_bytes {
            return Err(too_large(
                target,
                &format!("more than {max_bytes} bytes of names and values"),
                max_bytes,
            ));
        }
        Ok(self.seen.insert(name.to_vec()))
    }
}

/// One value of an open key, exactly as stored (`None`: missing), within [`MAX_VALUE_BYTES`];
/// a value that keeps growing is `Busy`.
pub(super) fn query(key: &OwnedKey, name: &str, target: &str) -> SysResult<Option<RegValue>> {
    let mut scratch = Vec::new();
    let mut cap = FIRST_BUFFER;
    for _ in 0..MORE_DATA_RETRIES {
        match reg::query_value(key, name, cap, &mut scratch) {
            Ok(Read::Value(raw)) => {
                check_size(raw.data.len(), target)?;
                return Ok(Some(RegValue::decode(raw.kind, &raw.data)));
            }
            Ok(Read::MoreData { needed }) => {
                check_size(needed, target)?;
                cap = grown(cap, needed);
            }
            // The value is missing (the key was opened, so it exists).
            Ok(Read::Missing) => return Ok(None),
            Err(status) => return Err(reg_nt_error(status, target)),
        }
    }
    Err(busy(target, "value kept growing"))
}

/// One `values` attempt. `Ok(None)`: restart (duplicate name). `cap` is the entry size the
/// scratch buffer is asked for first (grown on `MoreData`).
fn values_once(
    key: &OwnedKey,
    cap: &mut usize,
    scratch: &mut Vec<u64>,
    target: &str,
) -> SysResult<Option<Vec<(String, RegValue)>>> {
    let mut out = Vec::new();
    let mut tally = Tally::new();
    let mut index: u32 = 0;
    loop {
        let mut attempts = 0;
        let (name, raw) = loop {
            attempts += 1;
            match reg::enum_value(key, index, *cap, scratch) {
                Ok(EnumValue::End) => return Ok(Some(out)),
                Ok(EnumValue::Entry { name, value }) => break (name, value),
                Ok(EnumValue::MoreData { needed }) => {
                    // Header and name are below FULL_OVERHEAD, so anything beyond it plus the
                    // limit is certainly a value over the limit.
                    check_size(needed.saturating_sub(reg::FULL_OVERHEAD), target)?;
                    if attempts >= MORE_DATA_RETRIES {
                        return Err(busy(target, "value kept growing during the enumeration"));
                    }
                    *cap = needed.max(cap.saturating_add(1));
                }
                Err(status) => return Err(reg_nt_error(status, target)),
            }
        };
        check_size(raw.data.len(), target)?;
        // The total counts the name (UTF-16 bytes) and the data.
        if !tally.add(
            &name,
            raw.data.len().saturating_add(name.len().saturating_mul(2)),
            MAX_VALUES,
            MAX_VALUES_TOTAL_BYTES,
            target,
        )? {
            return Ok(None);
        }
        out.push((
            String::from_utf16_lossy(&name),
            RegValue::decode(raw.kind, &raw.data),
        ));
        index = index.saturating_add(1);
    }
}

/// One `subkeys` attempt. `Ok(None)`: restart (duplicate name).
fn subkeys_once(key: &OwnedKey, target: &str) -> SysResult<Option<Vec<String>>> {
    let mut name = [0u16; KEY_NAME_BUFFER];
    let mut out = Vec::new();
    let mut tally = Tally::new();
    let mut index: u32 = 0;
    loop {
        match reg::enum_key(key, index, &mut name) {
            Ok(None) => return Ok(Some(out)),
            Ok(Some(len)) => {
                let raw = &name[..len.min(name.len())];
                if !tally.add(raw, 0, MAX_SUBKEYS, usize::MAX, target)? {
                    return Ok(None);
                }
                out.push(String::from_utf16_lossy(raw));
            }
            Err(code) => return Err(reg_error(code, target)),
        }
        index = index.saturating_add(1);
    }
}

impl Registry for WinRegistry {
    fn key_exists(&self, k: &RegKey) -> SysResult<bool> {
        check_key(k)?;
        match self.open(k, ReadAccess::Query) {
            Ok(_) => Ok(true),
            Err(e) if e.kind == SysErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn get(&self, k: &RegKey, name: &str) -> SysResult<Option<RegValue>> {
        check_key(k)?;
        check_value_name(k, name)?;
        let key = self.open(k, ReadAccess::Query)?;
        query(&key, name, &format!("{k} @ {name:?}"))
    }

    fn values(&self, k: &RegKey) -> SysResult<Vec<(String, RegValue)>> {
        check_key(k)?;
        let key = self.open(k, ReadAccess::Query)?;
        let target = k.to_string();
        let mut scratch = Vec::new();
        let mut cap = 0;
        for _ in 0..ENUM_ATTEMPTS {
            let before = Self::info(&key, k)?;
            if before.values > MAX_VALUES {
                return Err(too_large(
                    &target,
                    &format!("{} values, over the limit of {MAX_VALUES}", before.values),
                    MAX_VALUES,
                ));
            }
            // The largest value size is only a hint: Windows does not lower it on delete.
            let first = before
                .max_value_len
                .clamp(FIRST_BUFFER, MAX_VALUE_BYTES)
                .saturating_add(reg::FULL_OVERHEAD);
            cap = cap.max(first);
            let got = values_once(&key, &mut cap, &mut scratch, &target)?;
            let after = Self::info(&key, k)?;
            if let Some(list) = got
                && after.last_write == before.last_write
            {
                return Ok(list);
            }
        }
        Err(busy(
            &target,
            "the key kept changing during the enumeration",
        ))
    }

    fn subkeys(&self, k: &RegKey) -> SysResult<Vec<String>> {
        check_key(k)?;
        let key = self.open(k, ReadAccess::Enumerate)?;
        let target = k.to_string();
        for _ in 0..ENUM_ATTEMPTS {
            let before = Self::info(&key, k)?;
            if before.subkeys > MAX_SUBKEYS {
                return Err(too_large(
                    &target,
                    &format!(
                        "{} subkeys, over the limit of {MAX_SUBKEYS}",
                        before.subkeys
                    ),
                    MAX_SUBKEYS,
                ));
            }
            let got = subkeys_once(&key, &target)?;
            let after = Self::info(&key, k)?;
            if let Some(list) = got
                && after.last_write == before.last_write
            {
                return Ok(list);
            }
        }
        Err(busy(
            &target,
            "the key kept changing during the enumeration",
        ))
    }

    fn link(&self, k: &RegKey) -> SysResult<Option<RegLink>> {
        check_key(k)?;
        if k.path.is_empty() {
            return Ok(None);
        }
        let target = k.to_string();
        let key = reg::open_link(self.root(k.hive), &k.path, view_of(k.view))
            .map_err(|code| reg_error(code, &target))?;
        let flags = reg::key_flags(&key).map_err(|st| reg_nt_error(st, &target))?;
        if flags & reg::REG_FLAG_LINK == 0 {
            return Ok(None);
        }
        // Missing, another type, empty or an odd trailing byte: unreadable, shown as such.
        let target = query(&key, "SymbolicLinkValue", &target)?
            .and_then(|v| v.encode())
            .filter(|(kind, data)| {
                *kind == crate::sys::registry::reg_type::REG_LINK
                    && !data.is_empty()
                    && data.len().is_multiple_of(2)
            })
            .map(|(_, data)| {
                data.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect()
            });
        Ok(Some(RegLink { target }))
    }
}

// ---------- Write side: the primitives of `sys::seq::reg` (ADR 0018 amendment P2-9) ----------

/// ntstatus.h `STATUS_CANNOT_DELETE`: `NtDeleteKey` on a key that still has subkeys.
const STATUS_CANNOT_DELETE: i32 = 0xC000_0121_u32.cast_signed();

/// An open key of the write side, with the path it was walked by (for messages only).
#[derive(Debug)]
pub(crate) struct WinKey {
    key: OwnedKey,
    shown: String,
}

fn access(a: KeyAccess) -> WriteAccess {
    match a {
        KeyAccess::Query => WriteAccess::Query,
        KeyAccess::CreateSub => WriteAccess::CreateSub,
        KeyAccess::SetValue => WriteAccess::SetValue,
        KeyAccess::Delete => WriteAccess::Delete,
    }
}

impl WinKey {
    fn child(&self, seg: KeySeg<'_>) -> String {
        format!("{}\\{}", self.shown, seg.as_str())
    }

    fn at(&self, name: &str) -> String {
        format!("{} @ {name:?}", self.shown)
    }
}

impl PrimKey for WinKey {
    fn open(&self, seg: KeySeg<'_>, a: KeyAccess) -> SysResult<Option<Self>> {
        let shown = self.child(seg);
        let key = reg::open_segment(&self.key, seg.as_str(), access(a))
            .map_err(|code| reg_error(code, &shown))?;
        Ok(key.map(|key| Self { key, shown }))
    }

    fn create(&self, seg: KeySeg<'_>, a: KeyAccess) -> SysResult<(Self, bool)> {
        let shown = self.child(seg);
        let (key, created) = reg::create_segment(&self.key, seg.as_str(), access(a))
            .map_err(|code| reg_error(code, &shown))?;
        Ok((Self { key, shown }, created))
    }

    fn flags(&self) -> SysResult<KeyFlags> {
        let f = reg::key_flags(&self.key).map_err(|st| reg_nt_error(st, &self.shown))?;
        Ok(KeyFlags {
            link: f & reg::REG_FLAG_LINK != 0,
            volatile: f & reg::REG_FLAG_VOLATILE != 0,
        })
    }

    fn kernel_name(&self) -> SysResult<String> {
        reg::key_name(&self.key).map_err(|st| reg_nt_error(st, &self.shown))
    }

    fn query(&self, name: &str) -> SysResult<Option<RegValue>> {
        query(&self.key, name, &self.at(name))
    }

    fn counts(&self) -> SysResult<(u32, u32)> {
        let i = reg::info(&self.key).map_err(|code| reg_error(code, &self.shown))?;
        Ok((
            u32::try_from(i.values).unwrap_or(u32::MAX),
            u32::try_from(i.subkeys).unwrap_or(u32::MAX),
        ))
    }

    fn set_value(&self, name: &str, v: &RegValue) -> SysResult<()> {
        let target = self.at(name);
        let (kind, data) = v.encode().ok_or_else(|| {
            SysError::new(
                SysErrorKind::Unsupported,
                format!("{target}: no canonical encoding"),
            )
        })?;
        reg::set_value(&self.key, name, kind, &data).map_err(|st| reg_nt_error(st, &target))
    }

    fn delete_value(&self, name: &str) -> SysResult<()> {
        let target = self.at(name);
        reg::delete_value(&self.key, name).map_err(|st| reg_nt_error(st, &target))
    }

    fn delete(self) -> SysResult<()> {
        reg::delete_key(&self.key).map_err(|st| {
            if st == STATUS_CANNOT_DELETE {
                SysError::new(
                    SysErrorKind::NotEmpty,
                    format!("{}: has subkeys", self.shown),
                )
                .with_ntstatus(st)
            } else {
                reg_nt_error(st, &self.shown)
            }
        })
    }

    fn flush(&self) -> SysResult<()> {
        reg::flush(&self.key).map_err(|code| reg_error(code, &self.shown))
    }
}

impl PrimHive for WinRegistry {
    type Key = WinKey;

    fn open_root(&self, h: Hive, a: KeyAccess) -> SysResult<WinKey> {
        let shown = h.to_string();
        let key = reg::reopen(self.root(h), access(a)).map_err(|code| reg_error(code, &shown))?;
        Ok(WinKey { key, shown })
    }

    fn root_name(&self, h: Hive) -> SysResult<String> {
        match h {
            Hive::CurrentUser => Ok(self.user_name.clone()),
            Hive::LocalMachine => Err(SysError::new(
                SysErrorKind::Unsupported,
                "HKLM has no write side (ADR 0018)",
            )),
        }
    }

    fn elevated(&self) -> bool {
        self.elevated
    }
}

impl RegistryWrite for WinRegistry {
    fn key_state(&self, k: &RegKey) -> SysResult<KeyState> {
        reg_seq::key_state(self, k)
    }

    fn read(&self, k: &RegKey, name: &str) -> SysResult<Option<RegValue>> {
        reg_seq::read(self, k, name)
    }

    fn create_key(&self, k: &RegKey) -> SysResult<bool> {
        reg_seq::create_key(self, k)
    }

    fn set(
        &self,
        k: &RegKey,
        name: &str,
        expected: Option<&RegValue>,
        new: &RegValue,
    ) -> SysResult<()> {
        reg_seq::set(self, k, name, expected, new)
    }

    fn delete_value(&self, k: &RegKey, name: &str, expected: &RegValue) -> SysResult<()> {
        reg_seq::delete_value(self, k, name, expected)
    }

    fn delete_empty_key(&self, k: &RegKey) -> SysResult<()> {
        reg_seq::delete_empty_key(self, k)
    }

    fn flush(&self, hive: Hive) -> SysResult<()> {
        reg_seq::flush(self, hive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffers_grow_to_the_reported_size_and_never_past_the_limit() {
        assert_eq!(grown(512, 4096), 4096);
        // A reported size that does not grow still grows by one byte.
        assert_eq!(grown(512, 100), 513);
        assert_eq!(grown(512, 512), 513);
        assert_eq!(grown(MAX_VALUE_BYTES, MAX_VALUE_BYTES), MAX_VALUE_BYTES);
        assert!(check_size(MAX_VALUE_BYTES, "t").is_ok());
        let e = check_size(MAX_VALUE_BYTES + 1, "t").unwrap_err();
        assert_eq!((e.kind, e.limit), (SysErrorKind::TooLarge, Some(1 << 20)));
    }

    #[test]
    fn the_tally_refuses_limits_and_reports_duplicates() {
        const A: [u16; 1] = [0x61];
        const B: [u16; 1] = [0x62];
        let mut t = Tally::new();
        assert!(t.add(&A, 1, 2, 10, "t").unwrap());
        assert!(!t.add(&A, 1, 3, 10, "t").unwrap(), "duplicate → restart");
        // Names that differ only in an unpaired surrogate are different (raw UTF-16), even
        // though both convert to U+FFFD.
        let mut t = Tally::new();
        assert!(t.add(&[0xD800], 0, 5, 10, "t").unwrap());
        assert!(t.add(&[0xD801], 0, 5, 10, "t").unwrap());
        assert_eq!(
            String::from_utf16_lossy(&[0xD800]),
            String::from_utf16_lossy(&[0xD801])
        );
        let mut t = Tally::new();
        assert!(t.add(&A, 1, 1, 10, "t").unwrap());
        let e = t.add(&B, 1, 1, 10, "t").unwrap_err();
        assert_eq!((e.kind, e.limit), (SysErrorKind::TooLarge, Some(1)));
        let mut t = Tally::new();
        assert!(t.add(&A, 10, 5, 10, "t").unwrap());
        let e = t.add(&B, 1, 5, 10, "t").unwrap_err();
        assert_eq!((e.kind, e.limit), (SysErrorKind::TooLarge, Some(10)));
    }
}
