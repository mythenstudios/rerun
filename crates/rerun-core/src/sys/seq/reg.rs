//! The registry write sequences of ADR 0018 (amendment P2-9), written once like the file
//! sequences of `sys::seq` (ADR 0017 A1, D-4).
//!
//! `sys::fake` and `sys::win` implement only [`PrimHive`] (a hive root) and [`PrimKey`] (an
//! open key handle); the walk, the link, volatile and kernel-name checks, the expected-value
//! check and the read-back live here, so the fake's fault, crash and power-loss tests exercise
//! the failure paths that ship.
//!
//! The walk opens a key from its hive root **one segment at a time**, each segment relative to
//! the handle of the previous one and opened itself (`REG_OPTION_OPEN_LINK` on Windows, which
//! only ever affects the last segment of a path, so every segment is its own last segment),
//! and asks every handle for its flags: a link is `ReparsePoint`, a volatile key
//! `Unsupported`. Before a change the walked handle's kernel name must still be the root's
//! name plus the key's path (folded), otherwise `Busy`: checking and acting then run on one
//! handle, so another program that renames or replaces a key between the walk and the act is
//! noticed instead of written through. A rename in the microseconds between that check and the
//! write is not prevented (the registry has no compare-and-swap; accepted, ADR 0018 amendment
//! P2-9): the write follows the handle into the moved key, and a second check after it reports
//! `Busy`, so the caller observes.

use super::super::registry::{
    Hive, KeyState, RegKey, RegValue, RegView, check_key, check_value_name,
};
use super::super::{SysError, SysErrorKind, SysResult};
use crate::fold::fold;

/// What a key handle reports about its key (`NtQueryKey(KeyFlagsInformation)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct KeyFlags {
    /// A symbolic-link key (`REG_FLAG_LINK`).
    pub(crate) link: bool,
    /// A volatile key (`REG_FLAG_VOLATILE`): its changes never reach the hive file.
    pub(crate) volatile: bool,
}

/// The rights a primitive opens a key with; each includes `KEY_QUERY_VALUE` (for
/// [`PrimKey::flags`]) and `READ_CONTROL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyAccess {
    /// Flags, kernel name, values, counts.
    Query,
    /// And `KEY_CREATE_SUB_KEY` (the parent of a `create_key`).
    CreateSub,
    /// And `KEY_SET_VALUE` (`set`, `delete_value`).
    SetValue,
    /// And `DELETE` (`delete_empty_key`).
    Delete,
}

/// One validated key segment: a segment of a path that passed [`check_key`] (not empty, no
/// `\`, no NUL, at most 255 UTF-16 units).
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeySeg<'a>(&'a str);

impl<'a> KeySeg<'a> {
    /// The segment as given.
    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }
}

/// A hive root of the write side.
pub(crate) trait PrimHive: Send + Sync {
    /// The handle type of this implementation.
    type Key: PrimKey;

    /// A new handle to the root of `h` with `a`.
    fn open_root(&self, h: Hive, a: KeyAccess) -> SysResult<Self::Key>;

    /// The kernel name of the root of `h` (`\REGISTRY\USER\<SID>`; a test: the app hive key).
    fn root_name(&self, h: Hive) -> SysResult<String>;

    /// The process runs elevated (or that cannot be told): writes are refused (S2).
    fn elevated(&self) -> bool;
}

/// An open key handle (closed on drop). Every name is opened itself, never followed.
pub(crate) trait PrimKey: Send + Sized {
    /// Opens the subkey `seg` itself (`REG_OPTION_OPEN_LINK`) with `a`; `None` if missing.
    fn open(&self, seg: KeySeg<'_>, a: KeyAccess) -> SysResult<Option<Self>>;

    /// Opens or creates the subkey `seg` itself (`REG_OPTION_OPEN_LINK`) with `a`; `true` if
    /// this call created it (the disposition).
    fn create(&self, seg: KeySeg<'_>, a: KeyAccess) -> SysResult<(Self, bool)>;

    /// The key's flags.
    fn flags(&self) -> SysResult<KeyFlags>;

    /// The key's current kernel name (`KeyNameInformation`); it follows a rename at once.
    fn kernel_name(&self) -> SysResult<String>;

    /// The value `name` exactly as stored (`None`: missing), within the read limits.
    fn query(&self, name: &str) -> SysResult<Option<RegValue>>;

    /// Number of values and of direct subkeys.
    fn counts(&self) -> SysResult<(u32, u32)>;

    /// Stores `v` as `name` (`NtSetValueKey`); an existing name keeps its spelling.
    fn set_value(&self, name: &str, v: &RegValue) -> SysResult<()>;

    /// Deletes the value `name` (`NotFound` if missing).
    fn delete_value(&self, name: &str) -> SysResult<()>;

    /// Deletes the key by this handle (`NtDeleteKey`); with a subkey `NotEmpty`.
    fn delete(self) -> SysResult<()>;

    /// Flushes the key's hive (`RegFlushKey`).
    fn flush(&self) -> SysResult<()>;
}

/// Test hooks of this thread (contract RW9): a deferred action that runs once between the walk
/// and the act of the next registry write sequence.
#[cfg(any(test, feature = "fake"))]
pub(crate) mod hook {
    use std::cell::RefCell;

    use crate::sys::registry::RegKey;

    type AfterWalk = Box<dyn FnOnce(&RegKey)>;

    thread_local! {
        static AFTER_WALK: RefCell<Option<AfterWalk>> = const { RefCell::new(None) };
    }

    /// Runs `f` once, after the walk of the next sequence on this thread that changes
    /// something (another program acting in between).
    pub(crate) fn after_walk_once(f: impl FnOnce(&RegKey) + 'static) {
        AFTER_WALK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    /// Removes a hook that has not fired.
    pub(crate) fn clear() {
        AFTER_WALK.with(|h| *h.borrow_mut() = None);
    }

    pub(super) fn fire(k: &RegKey) {
        let f = AFTER_WALK.with(|h| h.borrow_mut().take());
        if let Some(f) = f {
            f(k);
        }
    }
}

fn link_flag_off() -> bool {
    #[cfg(test)]
    return knob::link_flag_off();
    #[cfg(not(test))]
    false
}

fn kernel_name_off() -> bool {
    #[cfg(test)]
    return knob::kernel_name_off();
    #[cfg(not(test))]
    false
}

fn expected_off() -> bool {
    #[cfg(test)]
    return knob::expected_off();
    #[cfg(not(test))]
    false
}

fn after_walk(
    #[cfg_attr(
        not(any(test, feature = "fake")),
        expect(unused_variables, reason = "test hook")
    )]
    k: &RegKey,
) {
    #[cfg(any(test, feature = "fake"))]
    hook::fire(k);
}

fn err(kind: SysErrorKind, k: &RegKey, why: &str) -> SysError {
    SysError::new(kind, format!("{k}: {why}"))
}

/// The rules every method checks before it opens anything; `changes`: the method changes
/// something (S2 applies).
fn preflight<H: PrimHive>(h: &H, k: &RegKey, changes: bool) -> SysResult<()> {
    check_key(k)?;
    if k.hive == Hive::LocalMachine {
        return Err(err(
            SysErrorKind::Unsupported,
            k,
            "HKLM is written only by the elevated helper (ADR 0018)",
        ));
    }
    if k.view == RegView::Wow32 {
        return Err(err(
            SysErrorKind::Unsupported,
            k,
            "the write side uses the native view only (ADR 0018, S1)",
        ));
    }
    if changes && h.elevated() {
        return Err(err(
            SysErrorKind::Unsupported,
            k,
            "an elevated process never writes the registry (ADR 0018, S2)",
        ));
    }
    Ok(())
}

/// The segments of `k` (none for the hive root).
fn segments(k: &RegKey) -> Vec<KeySeg<'_>> {
    if k.path.is_empty() {
        Vec::new()
    } else {
        k.path.split('\\').map(KeySeg).collect()
    }
}

/// A walked handle must not be a link (`ReparsePoint`) or volatile (`Unsupported`).
fn check_flags<K: PrimKey>(key: &K, k: &RegKey, at: &str) -> SysResult<()> {
    let f = key.flags()?;
    if f.link && !link_flag_off() {
        return Err(SysError::new(
            SysErrorKind::ReparsePoint,
            format!("{k}: {at} is a symbolic-link key"),
        ));
    }
    if f.volatile {
        return Err(SysError::new(
            SysErrorKind::Unsupported,
            format!("{k}: {at} is a volatile key (its changes are never durable)"),
        ));
    }
    Ok(())
}

/// Opens the first `n` segments of `k` one at a time (the last with `last`, every other one
/// with [`KeyAccess::Query`]), checking every handle's flags. `None`: a segment is missing.
fn walk<H: PrimHive>(h: &H, k: &RegKey, n: usize, last: KeyAccess) -> SysResult<Option<H::Key>> {
    let segs = segments(k);
    let segs = segs.get(..n).unwrap_or(&segs);
    let root_access = if segs.is_empty() {
        last
    } else {
        KeyAccess::Query
    };
    let mut cur = h.open_root(k.hive, root_access)?;
    for (i, seg) in segs.iter().enumerate() {
        let a = if i + 1 == segs.len() {
            last
        } else {
            KeyAccess::Query
        };
        let Some(next) = cur.open(*seg, a)? else {
            return Ok(None);
        };
        check_flags(&next, k, seg.as_str())?;
        cur = next;
    }
    Ok(Some(cur))
}

/// The walk of the whole key; a missing segment is `NotFound`.
fn walk_all<H: PrimHive>(h: &H, k: &RegKey, a: KeyAccess) -> SysResult<H::Key> {
    walk(h, k, segments(k).len(), a)?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, k.to_string()))
}

/// The handle is still at `at` (its kernel name, folded), else `Busy` (condition S5).
fn still_at<H: PrimHive>(h: &H, key: &H::Key, at: &RegKey) -> SysResult<()> {
    if kernel_name_off() {
        return Ok(());
    }
    let root = h.root_name(at.hive)?;
    let want = if at.path.is_empty() {
        root
    } else {
        format!("{}\\{}", root.trim_end_matches('\\'), at.path)
    };
    if fold(&key.kernel_name()?) != fold(&want) {
        return Err(err(
            SysErrorKind::Busy,
            at,
            "the key was renamed or replaced while it was opened",
        ));
    }
    Ok(())
}

/// [`RegistryWrite::key_state`](super::super::RegistryWrite::key_state).
pub(crate) fn key_state<H: PrimHive>(h: &H, k: &RegKey) -> SysResult<KeyState> {
    preflight(h, k, false)?;
    let Some(key) = walk(h, k, segments(k).len(), KeyAccess::Query)? else {
        return Ok(KeyState::Missing);
    };
    let (values, subkeys) = key.counts()?;
    Ok(KeyState::Present { values, subkeys })
}

/// [`RegistryWrite::read`](super::super::RegistryWrite::read).
pub(crate) fn read<H: PrimHive>(h: &H, k: &RegKey, name: &str) -> SysResult<Option<RegValue>> {
    preflight(h, k, false)?;
    check_value_name(k, name)?;
    walk_all(h, k, KeyAccess::Query)?.query(name)
}

/// [`RegistryWrite::create_key`](super::super::RegistryWrite::create_key): walks to the parent
/// (`KEY_CREATE_SUB_KEY`), checks the parent's kernel name, creates the last segment itself;
/// an existing link there is `ReparsePoint`.
pub(crate) fn create_key<H: PrimHive>(h: &H, k: &RegKey) -> SysResult<bool> {
    preflight(h, k, true)?;
    let segs = segments(k);
    let (Some(last), Some(parent)) = (segs.last().copied(), k.parent()) else {
        return Err(err(SysErrorKind::InvalidPath, k, "the hive root"));
    };
    let p = walk(h, k, segs.len() - 1, KeyAccess::CreateSub)?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, parent.to_string()))?;
    after_walk(k);
    still_at(h, &p, &parent)?;
    let (child, created) = p.create(last, KeyAccess::Query)?;
    // A failure from here on may leave a key this call created: the caller observes it.
    check_flags(&child, k, last.as_str())?;
    Ok(created)
}

/// [`RegistryWrite::set`](super::super::RegistryWrite::set).
pub(crate) fn set<H: PrimHive>(
    h: &H,
    k: &RegKey,
    name: &str,
    expected: Option<&RegValue>,
    new: &RegValue,
) -> SysResult<()> {
    preflight(h, k, true)?;
    check_value_name(k, name)?;
    if new.encode().is_none() {
        return Err(err(
            SysErrorKind::Unsupported,
            k,
            "the value has no canonical encoding",
        ));
    }
    let key = walk_all(h, k, KeyAccess::SetValue)?;
    after_walk(k);
    still_at(h, &key, k)?;
    if key.query(name)?.as_ref() != expected && !expected_off() {
        return Err(SysError::new(
            SysErrorKind::Mismatch,
            format!("{k} @ {name:?}: not the expected value"),
        ));
    }
    key.set_value(name, new)?;
    // The key may have been renamed between the check and the write (accepted window, ADR
    // 0018 amendment P2-9): then the write landed in the moved key; say so.
    still_at(h, &key, k)?;
    if key.query(name)?.as_ref() != Some(new) {
        return Err(SysError::new(
            SysErrorKind::Busy,
            format!("{k} @ {name:?}: changed right after the write"),
        ));
    }
    Ok(())
}

/// [`RegistryWrite::delete_value`](super::super::RegistryWrite::delete_value).
pub(crate) fn delete_value<H: PrimHive>(
    h: &H,
    k: &RegKey,
    name: &str,
    expected: &RegValue,
) -> SysResult<()> {
    preflight(h, k, true)?;
    check_value_name(k, name)?;
    let key = walk_all(h, k, KeyAccess::SetValue)?;
    after_walk(k);
    still_at(h, &key, k)?;
    match key.query(name)? {
        None => {
            return Err(SysError::new(
                SysErrorKind::NotFound,
                format!("{k} @ {name:?}"),
            ));
        }
        Some(v) if v != *expected && !expected_off() => {
            return Err(SysError::new(
                SysErrorKind::Mismatch,
                format!("{k} @ {name:?}: not the expected value"),
            ));
        }
        Some(_) => {}
    }
    key.delete_value(name)?;
    still_at(h, &key, k)?;
    if key.query(name)?.is_some() {
        return Err(SysError::new(
            SysErrorKind::Busy,
            format!("{k} @ {name:?}: written again right after the delete"),
        ));
    }
    Ok(())
}

/// [`RegistryWrite::delete_empty_key`](super::super::RegistryWrite::delete_empty_key).
pub(crate) fn delete_empty_key<H: PrimHive>(h: &H, k: &RegKey) -> SysResult<()> {
    preflight(h, k, true)?;
    if k.path.is_empty() {
        return Err(err(SysErrorKind::InvalidPath, k, "the hive root"));
    }
    let key = walk_all(h, k, KeyAccess::Delete)?;
    after_walk(k);
    still_at(h, &key, k)?;
    if key.counts()? != (0, 0) {
        return Err(err(SysErrorKind::NotEmpty, k, "has values or subkeys"));
    }
    key.delete()
}

/// [`RegistryWrite::writable`](super::super::RegistryWrite::writable): the S2 rule of
/// [`preflight`] on its own.
pub(crate) fn writable<H: PrimHive>(h: &H) -> SysResult<()> {
    if h.elevated() {
        return Err(SysError::new(
            SysErrorKind::Unsupported,
            "an elevated process never writes the registry (ADR 0018, S2)",
        ));
    }
    Ok(())
}

/// [`RegistryWrite::flush`](super::super::RegistryWrite::flush).
pub(crate) fn flush<H: PrimHive>(h: &H, hive: Hive) -> SysResult<()> {
    preflight(h, &RegKey::new(hive, RegView::Native, ""), false)?;
    h.open_root(hive, KeyAccess::Query)?.flush()
}

/// Test knobs of this thread: the controls K-R1 to K-R3 switch a check off, and the contract
/// that must notice fails.
#[cfg(test)]
pub(crate) mod knob {
    use std::cell::Cell;

    thread_local! {
        static NO_LINK_FLAG: Cell<bool> = const { Cell::new(false) };
        static NO_KERNEL_NAME: Cell<bool> = const { Cell::new(false) };
        static NO_EXPECTED: Cell<bool> = const { Cell::new(false) };
    }

    /// K-R1: the walk ignores the link flag.
    pub(crate) fn no_link_flag(on: bool) {
        NO_LINK_FLAG.with(|c| c.set(on));
    }
    /// K-R2: no kernel-name comparison before a change.
    pub(crate) fn no_kernel_name(on: bool) {
        NO_KERNEL_NAME.with(|c| c.set(on));
    }
    /// K-R3: `set` and `delete_value` ignore `expected`.
    pub(crate) fn no_expected(on: bool) {
        NO_EXPECTED.with(|c| c.set(on));
    }
    pub(super) fn link_flag_off() -> bool {
        NO_LINK_FLAG.with(Cell::get)
    }
    pub(super) fn kernel_name_off() -> bool {
        NO_KERNEL_NAME.with(Cell::get)
    }
    pub(super) fn expected_off() -> bool {
        NO_EXPECTED.with(Cell::get)
    }
}
