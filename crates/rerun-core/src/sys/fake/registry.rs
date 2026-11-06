//! In-memory registry with Win32 semantics (case-insensitive, WOW64 redirection, link keys).
//!
//! # Model
//!
//! Every key is a node with an ID that stays with the key when another program renames it
//! (S3); a deleted and re-created key gets a new ID. Hive roots always exist and cannot be
//! deleted. A **symbolic-link key** ([`RegFixture::link`]) holds the path of its target; reads
//! follow it in every segment (like the real `HKCU`, ADR 0009), at most [`MAX_LINK_HOPS`]
//! times per lookup. [`Registry::link`] opens the last segment itself.
//!
//! The write side ([`RegistryWrite`]) is the one sequence of `sys::seq::reg` over the
//! primitives at the end of this file: a [`FakeKey`] holds a key's ID, opens and creates one
//! segment at a time without following a link, and reports a kernel-style name
//! (`\REGISTRY\FAKE\HKCU\…`, the stored spelling) that follows a rename
//! ([`FakeRegistry::rename_key`]). Volatile keys ([`FakeRegistry::put_volatile_key`]) and an
//! elevated process ([`FakeRegistry::set_elevated`]) are flags.
//!
//! Faults and power loss (ADR 0019 amendment P2-9): every primitive is a unit of the fault hub
//! the registry shares with the file system of its `FakeSystem` ([`Prim::Reg`]); after a crash
//! every call of Rerun fails, reads included, and a restart makes every handle stale.
//! [`FakeRegistry::on_step`] runs before each primitive (another program). Each hive keeps an
//! ordered log of Rerun's changes; `PrimKey::flush` makes the hive durable, a fixture change
//! counts as another program that flushed, and `FakeSystem::power_loss` keeps the durable part
//! plus any prefix of the rest.
//!
//! # WOW64 model
//!
//! A key is stored once, in its native location. [`RegView::Wow32`] only changes where a key of
//! `HKLM\SOFTWARE` lives: `HKLM\SOFTWARE\X` in the 32-bit view is `HKLM\SOFTWARE\WOW6432Node\X`
//! in the native view. Everything else is shared between the views: `HKLM\SOFTWARE` itself, all
//! other `HKLM` keys, every `HKCU` key. An explicit `SOFTWARE\WOW6432Node\...` is not redirected
//! a second time in the 32-bit view, so it names the same key in both views (ADR 0009 leaves it
//! to the contract on real Windows whether `sys::win` agrees).
//!
//! # Deviations from Windows (deliberate)
//!
//! - Only the redirection above is modelled. The shared and the reflected subkeys inside
//!   `HKLM\SOFTWARE` (a handful of `Microsoft\...` keys), `HKLM\SOFTWARE\Classes` and the
//!   redirection of `HKCU\Software\Classes` do not exist: they behave like any key.
//! - Enumerating `HKLM\SOFTWARE` in the 32-bit view lists the native children (including
//!   `WOW6432Node`), not the 32-bit view's.
//! - `WOW6432Node` exists below `HKLM\SOFTWARE` only once a 32-bit key is created (the real one
//!   always exists); creating a 32-bit key below `SOFTWARE` creates it.
//! - Link keys are followed on reads in every hive; in a private app hive Windows refuses to
//!   follow one (`AccessDenied`), so `sys::win` pins link following only in Windows Sandbox.
//!   Too many link levels are `Other`.
//! - Access is all-or-nothing per key: a denied key and everything below it return
//!   `AccessDenied` for every method; there are no security descriptors.
//! - Key and value names fold with `fold`, a close but not exact copy of the registry's upcase
//!   table.
//! - Enumeration returns names sorted by folded name; the registry's order is unspecified.
//! - Reads are consistent snapshots: the races of `sys::win` (`ERROR_MORE_DATA`, a key that
//!   changes during an enumeration) cannot happen.
//! - The fixture ([`RegFixture`]) and the setup helpers follow links on every segment but the
//!   last one they create or delete.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::fold::fold;
use crate::sys::contract::{DeferredRename, RegFixture};
use crate::sys::registry::{
    Hive, KeyState, MAX_SUBKEYS, MAX_VALUE_BYTES, MAX_VALUES, MAX_VALUES_TOTAL_BYTES, RegKey,
    RegLink, RegValue, RegView, Registry, RegistryWrite, check_key, check_value_name,
};
use crate::sys::seq::reg::{self as reg_seq, KeyAccess, KeyFlags, KeySeg, PrimHive, PrimKey};

use super::faults::{Fault, FaultHub, Prim, RegPrim, crashed_err, set_in_hook};
use crate::sys::{SysError, SysErrorKind, SysResult};

/// Most symbolic-link keys one lookup follows.
pub const MAX_LINK_HOPS: u32 = 16;

/// The target of a symbolic-link key.
#[derive(Debug, Clone)]
struct LinkTo {
    /// Folded native path of the target in the same hive.
    path: String,
    /// The target as given (for [`RegLink::target`]).
    shown: String,
}

#[derive(Debug, Clone)]
struct KeyNode {
    /// Identity; stays with the key across a rename.
    id: u64,
    name: String,
    /// Folded value name → (original name, value).
    values: BTreeMap<String, (String, RegValue)>,
    /// `Some` for a symbolic-link key.
    link: Option<LinkTo>,
    /// A volatile key (`REG_OPTION_VOLATILE`).
    volatile: bool,
}

/// Hive and folded path of the native location.
type MapKey = (Hive, String);
type Keys = BTreeMap<MapKey, KeyNode>;

#[derive(Debug)]
struct State {
    keys: Keys,
    /// Keys (with everything below them) that refuse every method.
    denied: Vec<MapKey>,
    next_id: u64,
    /// The process counts as elevated ([`FakeRegistry::set_elevated`]).
    elevated: bool,
    /// The fault hub, shared with the file system of a `FakeSystem`.
    hub: Arc<FaultHub>,
    /// Per-hive logs of Rerun's changes (power-loss model).
    logs: BTreeMap<Hive, HiveLog>,
    /// Control K-R4: a flush makes nothing durable.
    flush_broken: bool,
}

impl Default for State {
    fn default() -> Self {
        let mut keys = Keys::new();
        for (id, hive) in [(1, Hive::CurrentUser), (2, Hive::LocalMachine)] {
            keys.insert(
                (hive, String::new()),
                KeyNode {
                    id,
                    name: String::new(),
                    values: BTreeMap::new(),
                    link: None,
                    volatile: false,
                },
            );
        }
        Self {
            keys,
            denied: Vec::new(),
            next_id: 16,
            elevated: false,
            hub: Arc::default(),
            logs: BTreeMap::new(),
            flush_broken: false,
        }
    }
}

/// The shared state of a [`FakeRegistry`] and its handles.
#[derive(Default)]
struct Inner {
    state: Mutex<State>,
    hook: Mutex<Option<RegHook>>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// In-memory registry. Hive roots always exist and cannot be deleted.
#[derive(Default)]
pub struct FakeRegistry {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for FakeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeRegistry")
            .field("keys", &self.lock().keys.len())
            .finish_non_exhaustive()
    }
}

/// Folded name of `WOW6432Node`.
const WOW_NODE: &str = "WOW6432NODE";

/// Native location of `k`: the WOW64 redirection of `HKLM\SOFTWARE\X` in the 32-bit view.
fn map_key(k: &RegKey) -> SysResult<MapKey> {
    check_key(k)?;
    let folded = fold(&k.path);
    if k.hive == Hive::LocalMachine && k.view == RegView::Wow32 {
        let mut parts = folded.splitn(3, '\\');
        if let (Some("SOFTWARE"), Some(second), rest) = (parts.next(), parts.next(), parts.next())
            && second != WOW_NODE
        {
            let mut path = format!("SOFTWARE\\{WOW_NODE}\\{second}");
            if let Some(rest) = rest {
                path.push('\\');
                path.push_str(rest);
            }
            return Ok((k.hive, path));
        }
    }
    Ok((k.hive, folded))
}

fn join(parent: &str, seg: &str) -> String {
    if parent.is_empty() {
        seg.to_owned()
    } else {
        format!("{parent}\\{seg}")
    }
}

/// `(parent, last segment)` of a folded path; `None` for the hive root.
fn split_last(path: &str) -> Option<(&str, &str)> {
    if path.is_empty() {
        return None;
    }
    Some(path.rsplit_once('\\').unwrap_or(("", path)))
}

fn unsupported(k: &RegKey, why: &str) -> SysError {
    SysError::new(SysErrorKind::Unsupported, format!("{k}: {why}"))
}

/// A read over one of the limits for untrusted data: `TooLarge` with that limit.
fn too_large(k: &RegKey, why: &str, limit: usize) -> SysError {
    SysError::too_large(
        format!("{k}: {why}"),
        u64::try_from(limit).unwrap_or(u64::MAX),
    )
}

/// Size of a value as stored; a typed value without a canonical encoding has none.
fn data_len(v: &RegValue) -> usize {
    v.encode().map_or(0, |(_, d)| d.len())
}

fn not_found(k: &RegKey) -> SysError {
    SysError::new(SysErrorKind::NotFound, k.to_string())
}

/// The kernel-style name the fake reports for a key (`\REGISTRY\FAKE\HKCU\…`).
fn kernel_name(hive: Hive, shown: &str) -> String {
    if shown.is_empty() {
        format!(r"\REGISTRY\FAKE\{hive}")
    } else {
        format!(r"\REGISTRY\FAKE\{hive}\{shown}")
    }
}

impl State {
    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// The folded native path `path` with every link key on it followed.
    fn resolve(&self, hive: Hive, path: &str, hops: &mut u32) -> SysResult<String> {
        let mut cur = String::new();
        if path.is_empty() {
            return Ok(cur);
        }
        for seg in path.split('\\') {
            cur = join(&cur, seg);
            if let Some(to) = self
                .keys
                .get(&(hive, cur.clone()))
                .and_then(|n| n.link.clone())
            {
                *hops += 1;
                if *hops > MAX_LINK_HOPS {
                    return Err(SysError::new(
                        SysErrorKind::Other,
                        format!("fake: more than {MAX_LINK_HOPS} symbolic-link levels"),
                    ));
                }
                cur = self.resolve(hive, &to.path, hops)?;
            }
        }
        Ok(cur)
    }

    /// `mk` with every link followed.
    fn follow(&self, mk: &MapKey) -> SysResult<MapKey> {
        Ok((mk.0, self.resolve(mk.0, &mk.1, &mut 0)?))
    }

    /// `mk` with every link but the last segment followed (the key itself).
    fn follow_parent(&self, mk: &MapKey) -> SysResult<MapKey> {
        match split_last(&mk.1) {
            None => Ok(mk.clone()),
            Some((parent, last)) => {
                let p = self.resolve(mk.0, parent, &mut 0)?;
                Ok((mk.0, join(&p, last)))
            }
        }
    }

    /// `AccessDenied` if `mk` is a denied key or lies below one.
    fn check_access(&self, k: &RegKey, mk: &MapKey) -> SysResult<()> {
        let hit = self.denied.iter().any(|(h, p)| {
            *h == mk.0
                && (mk.1 == *p
                    || mk
                        .1
                        .strip_prefix(p.as_str())
                        .is_some_and(|rest| rest.starts_with('\\')))
        });
        if hit {
            return Err(SysError::new(SysErrorKind::AccessDenied, k.to_string()));
        }
        Ok(())
    }

    fn child_keys<'a>(&'a self, mk: &'a MapKey) -> impl Iterator<Item = &'a KeyNode> + 'a {
        let prefix = if mk.1.is_empty() {
            String::new()
        } else {
            format!("{}\\", mk.1)
        };
        let skip = prefix.len();
        self.keys
            .range((mk.0, prefix.clone())..)
            .take_while(move |((h, p), _)| *h == mk.0 && p.starts_with(&prefix))
            .filter(move |((_, p), _)| !p.is_empty() && !p[skip..].contains('\\'))
            .map(|(_, node)| node)
    }

    /// Creates the key `mk` (its parent resolved, the last segment itself), named `name`.
    /// `Ok(false)` if it exists. The real `WOW6432Node` always exists; here the first 32-bit
    /// key creates it.
    fn create(&mut self, k: &RegKey, mk: &MapKey, name: &str) -> SysResult<bool> {
        if self.keys.contains_key(mk) {
            return Ok(false);
        }
        let Some((parent, _)) = split_last(&mk.1) else {
            return Ok(false);
        };
        if !self.keys.contains_key(&(mk.0, parent.to_owned())) {
            let parent_key = k.parent().unwrap_or_else(|| k.clone());
            if parent != format!("SOFTWARE\\{WOW_NODE}") {
                return Err(not_found(&parent_key));
            }
            let id = self.new_id();
            self.keys.insert(
                (mk.0, parent.to_owned()),
                KeyNode {
                    id,
                    name: "WOW6432Node".to_owned(),
                    values: BTreeMap::new(),
                    link: None,
                    volatile: false,
                },
            );
        }
        let id = self.new_id();
        self.keys.insert(
            mk.clone(),
            KeyNode {
                id,
                name: name.to_owned(),
                values: BTreeMap::new(),
                link: None,
                volatile: false,
            },
        );
        Ok(true)
    }
}

/// The last segment of `k` as given.
fn last_name(k: &RegKey) -> String {
    k.path.rsplit('\\').next().unwrap_or_default().to_owned()
}

impl FakeRegistry {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.lock()
    }

    /// The state for a fixture or setup change: another program that flushed, so every hive
    /// log is durable up to now.
    fn fixture(&self) -> MutexGuard<'_, State> {
        let mut st = self.inner.lock();
        st.fixture_flushed();
        st
    }

    /// Builder only: `k` and everything below it refuse every method with `AccessDenied`
    /// (like `HKLM\SECURITY` for a user). Create the key and its children first.
    pub(super) fn deny(&self, k: &RegKey) -> SysResult<()> {
        let mk = map_key(k)?;
        self.lock().denied.push(mk);
        Ok(())
    }

    /// The folded map name of the raw UTF-16 name `units`: a valid name folds as usual; a name
    /// with unpaired surrogates (listed with U+FFFD, as `sys::win` does) gets the units as a
    /// suffix after a NUL, which no name holds, so two such names stay apart and a lookup by
    /// the converted name finds neither (on Windows it names other units).
    fn utf16_map_name(units: &[u16]) -> (String, String) {
        let shown = String::from_utf16_lossy(units);
        let mut folded = fold(&shown);
        if String::from_utf16(units).is_err() {
            folded.push('\0');
            for u in units {
                folded.push_str(&format!("{u:04x}"));
            }
        }
        (shown, folded)
    }

    /// Setup: creates exactly the key `k` (its parent must exist, links on the way are
    /// followed); `true` if it is new.
    pub fn put_key(&self, k: &RegKey) -> SysResult<bool> {
        let mk = map_key(k)?;
        let mut st = self.fixture();
        let mk = st.follow_parent(&mk)?;
        st.check_access(k, &mk)?;
        st.create(k, &mk, &last_name(k))
    }

    /// Setup: creates a key including missing parents.
    pub fn put_key_all(&self, k: &RegKey) -> SysResult<()> {
        let mut chain = Vec::new();
        let mut cur = Some(k.clone());
        while let Some(key) = cur {
            cur = key.parent();
            chain.push(key);
        }
        for key in chain.iter().rev() {
            self.put_key(key)?;
        }
        Ok(())
    }

    /// Setup: sets the value `name` of the existing key `k` (links followed), keeping the
    /// stored spelling of an existing name. A value without a canonical encoding is
    /// `Unsupported`.
    pub fn put_value(&self, k: &RegKey, name: &str, v: &RegValue) -> SysResult<()> {
        let mk = map_key(k)?;
        check_value_name(k, name)?;
        if v.encode().is_none() {
            return Err(unsupported(k, "value has no canonical encoding"));
        }
        let mut st = self.fixture();
        let mk = st.follow(&mk)?;
        st.check_access(k, &mk)?;
        let node = st.keys.get_mut(&mk).ok_or_else(|| not_found(k))?;
        let folded = fold(name);
        let original = node
            .values
            .get(&folded)
            .map_or_else(|| name.to_owned(), |(n, _)| n.clone());
        node.values.insert(folded, (original, v.clone()));
        Ok(())
    }

    /// Setup: deletes the value `name` of the existing key `k` (`NotFound` if missing).
    pub fn remove_value(&self, k: &RegKey, name: &str) -> SysResult<()> {
        let mk = map_key(k)?;
        check_value_name(k, name)?;
        let mut st = self.fixture();
        let mk = st.follow(&mk)?;
        st.check_access(k, &mk)?;
        let node = st.keys.get_mut(&mk).ok_or_else(|| not_found(k))?;
        match node.values.remove(&fold(name)) {
            Some(_) => Ok(()),
            None => Err(SysError::new(
                SysErrorKind::NotFound,
                format!("{k} @ {name:?}"),
            )),
        }
    }

    /// Setup: deletes the key `k` itself (a link key is deleted, not followed) if it has no
    /// subkeys (`NotEmpty`); the hive root is `InvalidPath`.
    pub fn remove_key(&self, k: &RegKey) -> SysResult<()> {
        let mk = map_key(k)?;
        if k.path.is_empty() {
            return Err(SysError::new(SysErrorKind::InvalidPath, k.to_string()));
        }
        let mut st = self.fixture();
        let mk = st.follow_parent(&mk)?;
        st.check_access(k, &mk)?;
        if !st.keys.contains_key(&mk) {
            return Err(not_found(k));
        }
        if st.child_keys(&mk).next().is_some() {
            return Err(SysError::new(SysErrorKind::NotEmpty, k.to_string()));
        }
        st.keys.remove(&mk);
        Ok(())
    }
}

impl Registry for FakeRegistry {
    fn key_exists(&self, k: &RegKey) -> SysResult<bool> {
        let mk = map_key(k)?;
        let st = self.lock();
        st.alive()?;
        let mk = st.follow(&mk)?;
        st.check_access(k, &mk)?;
        Ok(st.keys.contains_key(&mk))
    }

    fn get(&self, k: &RegKey, name: &str) -> SysResult<Option<RegValue>> {
        let mk = map_key(k)?;
        check_value_name(k, name)?;
        let st = self.lock();
        st.alive()?;
        let mk = st.follow(&mk)?;
        st.check_access(k, &mk)?;
        let node = st.keys.get(&mk).ok_or_else(|| not_found(k))?;
        let value = node.values.get(&fold(name)).map(|(_, v)| v.clone());
        if value
            .as_ref()
            .is_some_and(|v| data_len(v) > MAX_VALUE_BYTES)
        {
            return Err(too_large(k, "value larger than 1 MiB", MAX_VALUE_BYTES));
        }
        Ok(value)
    }

    fn values(&self, k: &RegKey) -> SysResult<Vec<(String, RegValue)>> {
        let mk = map_key(k)?;
        let st = self.lock();
        st.alive()?;
        let mk = st.follow(&mk)?;
        st.check_access(k, &mk)?;
        let node = st.keys.get(&mk).ok_or_else(|| not_found(k))?;
        let values: Vec<(String, RegValue)> = node.values.values().cloned().collect();
        if values.len() > MAX_VALUES {
            return Err(too_large(k, "too many values", MAX_VALUES));
        }
        let mut total = 0_usize;
        for (name, v) in &values {
            let len = data_len(v);
            if len > MAX_VALUE_BYTES {
                return Err(too_large(k, "value larger than 1 MiB", MAX_VALUE_BYTES));
            }
            // Names count too (UTF-16 bytes), as in `sys::win`.
            total += len + 2 * name.encode_utf16().count();
        }
        if total > MAX_VALUES_TOTAL_BYTES {
            return Err(too_large(
                k,
                "names and values larger than 16 MiB in total",
                MAX_VALUES_TOTAL_BYTES,
            ));
        }
        Ok(values)
    }

    fn subkeys(&self, k: &RegKey) -> SysResult<Vec<String>> {
        let mk = map_key(k)?;
        let st = self.lock();
        st.alive()?;
        let mk = st.follow(&mk)?;
        st.check_access(k, &mk)?;
        if !st.keys.contains_key(&mk) {
            return Err(not_found(k));
        }
        let names: Vec<String> = st.child_keys(&mk).map(|n| n.name.clone()).collect();
        if names.len() > MAX_SUBKEYS {
            return Err(too_large(k, "too many subkeys", MAX_SUBKEYS));
        }
        Ok(names)
    }

    fn link(&self, k: &RegKey) -> SysResult<Option<RegLink>> {
        let mk = map_key(k)?;
        let st = self.lock();
        st.alive()?;
        let mk = st.follow_parent(&mk)?;
        st.check_access(k, &mk)?;
        let node = st.keys.get(&mk).ok_or_else(|| not_found(k))?;
        Ok(node.link.as_ref().map(|to| RegLink {
            target: kernel_name(k.hive, &to.shown).encode_utf16().collect(),
        }))
    }
}

impl RegFixture for FakeRegistry {
    fn key(&self, k: &RegKey) -> SysResult<()> {
        self.put_key_all(k)
    }

    fn raw(&self, k: &RegKey, name: &str, kind: u32, data: &[u8]) -> SysResult<()> {
        self.put_value(k, name, &RegValue::decode(kind, data))
    }

    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()> {
        self.remove_value(k, name)
    }

    fn delete_key(&self, k: &RegKey) -> SysResult<()> {
        self.remove_key(k)
    }

    fn utf16_key(&self, parent: &RegKey, units: &[u16]) -> SysResult<bool> {
        let (shown, folded) = Self::utf16_map_name(units);
        if units.is_empty() || shown.contains(['\0', '\\']) {
            return Err(SysError::new(
                SysErrorKind::InvalidPath,
                format!("{parent} \\ {shown:?}"),
            ));
        }
        let pmk = map_key(parent)?;
        let mut st = self.fixture();
        let pmk = st.follow(&pmk)?;
        if !st.keys.contains_key(&pmk) {
            return Err(not_found(parent));
        }
        let path = join(&pmk.1, &folded);
        if !st.keys.contains_key(&(pmk.0, path.clone())) {
            let id = st.new_id();
            st.keys.insert(
                (pmk.0, path),
                KeyNode {
                    id,
                    name: shown,
                    values: BTreeMap::new(),
                    link: None,
                    volatile: false,
                },
            );
        }
        Ok(true)
    }

    fn utf16_value(&self, k: &RegKey, units: &[u16], kind: u32, data: &[u8]) -> SysResult<bool> {
        let (shown, folded) = Self::utf16_map_name(units);
        if shown.contains('\0') {
            return Err(SysError::new(
                SysErrorKind::InvalidPath,
                format!("{k} @ {shown:?}"),
            ));
        }
        let mk = map_key(k)?;
        let mut st = self.fixture();
        let mk = st.follow(&mk)?;
        let node = st.keys.get_mut(&mk).ok_or_else(|| not_found(k))?;
        let original = node.values.get(&folded).map_or(shown, |(n, _)| n.clone());
        node.values
            .insert(folded, (original, RegValue::decode(kind, data)));
        Ok(true)
    }

    fn link(&self, link: &RegKey, target: &RegKey) -> SysResult<bool> {
        let mk = map_key(link)?;
        let to = map_key(target)?;
        if link.path.is_empty() || to.0 != mk.0 {
            return Err(SysError::new(
                SysErrorKind::InvalidPath,
                format!("{link} -> {target}"),
            ));
        }
        let mut st = self.fixture();
        let mk = st.follow_parent(&mk)?;
        if !st.create(link, &mk, &last_name(link))? {
            return Err(SysError::new(
                SysErrorKind::AlreadyExists,
                format!("{link}: a link must be a new key"),
            ));
        }
        if let Some(node) = st.keys.get_mut(&mk) {
            node.link = Some(LinkTo {
                path: to.1,
                shown: target.path.clone(),
            });
        }
        Ok(true)
    }

    fn links_followed(&self) -> bool {
        true
    }

    fn rename_later(&self, k: &RegKey, new_name: &str) -> SysResult<Option<DeferredRename>> {
        let other = Self {
            inner: self.inner.clone(),
        };
        let (k, new_name) = (k.clone(), new_name.to_owned());
        Ok(Some(Box::new(move || other.rename_key(&k, &new_name))))
    }

    fn volatile_key(&self, k: &RegKey) -> SysResult<bool> {
        self.put_volatile_key(k)?;
        Ok(true)
    }

    fn large(&self, k: &RegKey, name: &str, len: usize) -> SysResult<bool> {
        self.put_value(k, name, &RegValue::Binary(vec![7; len]))?;
        Ok(true)
    }
}

// ---------- Write side: the primitives of `sys::seq::reg` (ADR 0018 amendment P2-9) ----------

/// How to undo one logged change of Rerun (power-loss model, see the module docs).
#[derive(Debug)]
enum Undo {
    /// A key was created: remove it again (it must exist and be empty by then).
    KeyCreated { id: u64 },
    /// A key was deleted: put it back where it was.
    KeyDeleted { mk: MapKey, node: KeyNode },
    /// A value was set or deleted: its old state (`None`: it was missing).
    Value {
        id: u64,
        folded: String,
        old: Option<(String, RegValue)>,
    },
}

/// The ordered log of one hive.
#[derive(Debug, Default)]
struct HiveLog {
    entries: Vec<Undo>,
    /// Entries `..durable` are durable.
    durable: usize,
}

impl State {
    /// The map key of the node `id` (a key renamed by another program keeps its ID).
    fn path_of_id(&self, hive: Hive, id: u64) -> Option<MapKey> {
        self.keys
            .iter()
            .find(|((h, _), n)| *h == hive && n.id == id)
            .map(|(mk, _)| mk.clone())
    }

    /// The stored spelling of the path `mk` (every segment's own name).
    fn shown_path(&self, mk: &MapKey) -> String {
        if mk.1.is_empty() {
            return String::new();
        }
        let mut cur = String::new();
        let mut shown = Vec::new();
        for seg in mk.1.split('\\') {
            cur = join(&cur, seg);
            shown.push(
                self.keys
                    .get(&(mk.0, cur.clone()))
                    .map_or_else(|| seg.to_owned(), |n| n.name.clone()),
            );
        }
        shown.join("\\")
    }

    /// Appends a change of Rerun to the log of `hive`.
    fn log(&mut self, hive: Hive, undo: Undo) {
        self.logs.entry(hive).or_default().entries.push(undo);
    }

    /// A fixture change: another program that flushed, so every hive log is durable up to now
    /// (the ordered log stays consistent with changes nobody logs).
    fn fixture_flushed(&mut self) {
        for log in self.logs.values_mut() {
            log.durable = log.entries.len();
        }
    }

    /// `AccessDenied`-free check that the process is alive (reads of Rerun after a crash).
    fn alive(&self) -> SysResult<()> {
        if self.hub.crashed() {
            Err(crashed_err())
        } else {
            Ok(())
        }
    }

    fn undo(&mut self, hive: Hive, u: Undo) {
        match u {
            Undo::KeyCreated { id } => {
                let Some(mk) = self.path_of_id(hive, id) else {
                    panic!("fake power loss: created key {id} is gone before its undo");
                };
                assert!(
                    self.child_keys(&mk).next().is_none(),
                    "fake power loss: created key {id} has subkeys at its undo"
                );
                self.keys.remove(&mk);
            }
            Undo::KeyDeleted { mk, node } => {
                let parent = split_last(&mk.1).map(|(p, _)| p.to_owned());
                assert!(
                    !self.keys.contains_key(&mk)
                        && parent.is_some_and(|p| self.keys.contains_key(&(mk.0, p))),
                    "fake power loss: undo of the delete of {} collides",
                    mk.1
                );
                self.keys.insert(mk, node);
            }
            Undo::Value { id, folded, old } => {
                let Some(mk) = self.path_of_id(hive, id) else {
                    panic!("fake power loss: key {id} is gone before the undo of its value");
                };
                if let Some(node) = self.keys.get_mut(&mk) {
                    match old {
                        Some(v) => {
                            node.values.insert(folded, v);
                        }
                        None => {
                            node.values.remove(&folded);
                        }
                    }
                }
            }
        }
    }
}

/// A key handle of the fake's write side: the key's identity, so it follows a rename, and a
/// key deleted under it is `Busy` (`STATUS_KEY_DELETED`, S3); a restart makes it stale.
pub(crate) struct FakeKey {
    reg: Arc<Inner>,
    hive: Hive,
    id: u64,
    epoch: u64,
}

impl std::fmt::Debug for FakeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeKey")
            .field("hive", &self.hive)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

fn deleted() -> SysError {
    SysError::new(
        SysErrorKind::Busy,
        "fake: the key was deleted under the handle (STATUS_KEY_DELETED)",
    )
}

/// Runs one registry primitive of Rerun: fires the hook (without the state lock), then,
/// under it, checks the handle's epoch, enters the call at the hub (crash, armed fault) and
/// runs `f`. A [`Fault::CrashAfter`] lets `f` act and then crashes.
fn prim<T>(
    reg: &Arc<Inner>,
    call: RegPrim,
    epoch: Option<u64>,
    f: impl FnOnce(&mut State) -> SysResult<T>,
) -> SysResult<T> {
    let crashed = reg.lock().hub.crashed();
    if !crashed {
        fire(reg, call);
    }
    let mut st = reg.lock();
    let hub = st.hub.clone();
    let crash = hub.enter(Prim::Reg(call))?;
    if epoch.is_some_and(|e| e != hub.epoch()) {
        return Err(SysError::new(
            SysErrorKind::Other,
            "fake: registry handle closed by a restart",
        ));
    }
    let r = f(&mut st);
    if crash {
        hub.crash();
        return Err(crashed_err());
    }
    r
}

/// Runs the registry hook (another program) before `call`, without the state lock.
fn fire(reg: &Arc<Inner>, call: RegPrim) {
    let hook = reg
        .hook
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(mut hook) = hook {
        set_in_hook(true);
        hook(&FakeRegistry { inner: reg.clone() }, call);
        set_in_hook(false);
        let mut slot = reg.hook.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(hook);
        }
    }
}

impl FakeKey {
    fn prim<T>(
        &self,
        call: RegPrim,
        f: impl FnOnce(&mut State, MapKey) -> SysResult<T>,
    ) -> SysResult<T> {
        let (hive, id) = (self.hive, self.id);
        prim(&self.reg, call, Some(self.epoch), |st| {
            let mk = st.path_of_id(hive, id).ok_or_else(deleted)?;
            f(st, mk)
        })
    }

    fn handle(&self, id: u64) -> Self {
        Self {
            reg: self.reg.clone(),
            hive: self.hive,
            id,
            epoch: self.epoch,
        }
    }

    /// The child `seg` of the key `mk`: its map key and its ID if it exists.
    fn child(st: &State, mk: &MapKey, seg: KeySeg<'_>) -> SysResult<(MapKey, Option<u64>)> {
        let child = (mk.0, join(&mk.1, &fold(seg.as_str())));
        let shown = RegKey::new(mk.0, RegView::Native, st.shown_path(&child));
        st.check_access(&shown, &child)?;
        let id = st.keys.get(&child).map(|n| n.id);
        Ok((child, id))
    }
}

impl PrimKey for FakeKey {
    fn open(&self, seg: KeySeg<'_>, _a: KeyAccess) -> SysResult<Option<Self>> {
        let id = self.prim(RegPrim::Open, |st, mk| Ok(Self::child(st, &mk, seg)?.1))?;
        Ok(id.map(|id| self.handle(id)))
    }

    fn create(&self, seg: KeySeg<'_>, _a: KeyAccess) -> SysResult<(Self, bool)> {
        let hive = self.hive;
        let (id, created) = self.prim(RegPrim::Create, |st, mk| {
            let (child, id) = Self::child(st, &mk, seg)?;
            if let Some(id) = id {
                return Ok((id, false));
            }
            let id = st.new_id();
            st.keys.insert(
                child,
                KeyNode {
                    id,
                    name: seg.as_str().to_owned(),
                    values: BTreeMap::new(),
                    link: None,
                    volatile: false,
                },
            );
            st.log(hive, Undo::KeyCreated { id });
            Ok((id, true))
        })?;
        Ok((self.handle(id), created))
    }

    fn flags(&self) -> SysResult<KeyFlags> {
        self.prim(RegPrim::Flags, |st, mk| {
            let n = st.keys.get(&mk).ok_or_else(deleted)?;
            Ok(KeyFlags {
                link: n.link.is_some(),
                volatile: n.volatile,
            })
        })
    }

    fn kernel_name(&self) -> SysResult<String> {
        self.prim(RegPrim::KernelName, |st, mk| {
            Ok(kernel_name(mk.0, &st.shown_path(&mk)))
        })
    }

    fn query(&self, name: &str) -> SysResult<Option<RegValue>> {
        self.prim(RegPrim::Query, |st, mk| {
            let n = st.keys.get(&mk).ok_or_else(deleted)?;
            let v = n.values.get(&fold(name)).map(|(_, v)| v.clone());
            if v.as_ref().is_some_and(|v| data_len(v) > MAX_VALUE_BYTES) {
                return Err(SysError::too_large(
                    format!("{name:?}: value larger than 1 MiB"),
                    u64::try_from(MAX_VALUE_BYTES).unwrap_or(u64::MAX),
                ));
            }
            Ok(v)
        })
    }

    fn counts(&self) -> SysResult<(u32, u32)> {
        self.prim(RegPrim::Counts, |st, mk| {
            let n = st.keys.get(&mk).ok_or_else(deleted)?;
            let subkeys = st.child_keys(&mk).count();
            Ok((
                u32::try_from(n.values.len()).unwrap_or(u32::MAX),
                u32::try_from(subkeys).unwrap_or(u32::MAX),
            ))
        })
    }

    fn set_value(&self, name: &str, v: &RegValue) -> SysResult<()> {
        let (hive, id) = (self.hive, self.id);
        self.prim(RegPrim::SetValue, |st, mk| {
            if v.encode().is_none() {
                return Err(SysError::new(
                    SysErrorKind::Unsupported,
                    format!("{name:?}: no canonical encoding"),
                ));
            }
            let n = st.keys.get_mut(&mk).ok_or_else(deleted)?;
            let folded = fold(name);
            let old = n.values.get(&folded).cloned();
            let original = old
                .as_ref()
                .map_or_else(|| name.to_owned(), |(o, _)| o.clone());
            n.values.insert(folded.clone(), (original, v.clone()));
            st.log(hive, Undo::Value { id, folded, old });
            Ok(())
        })
    }

    fn delete_value(&self, name: &str) -> SysResult<()> {
        let (hive, id) = (self.hive, self.id);
        self.prim(RegPrim::DeleteValue, |st, mk| {
            let n = st.keys.get_mut(&mk).ok_or_else(deleted)?;
            let folded = fold(name);
            let Some(old) = n.values.remove(&folded) else {
                return Err(SysError::new(SysErrorKind::NotFound, format!("{name:?}")));
            };
            st.log(
                hive,
                Undo::Value {
                    id,
                    folded,
                    old: Some(old),
                },
            );
            Ok(())
        })
    }

    fn delete(self) -> SysResult<()> {
        let hive = self.hive;
        self.prim(RegPrim::Delete, |st, mk| {
            if mk.1.is_empty() {
                return Err(SysError::new(
                    SysErrorKind::AccessDenied,
                    "fake: a hive root cannot be deleted",
                ));
            }
            if st.child_keys(&mk).next().is_some() {
                return Err(SysError::new(SysErrorKind::NotEmpty, st.shown_path(&mk)));
            }
            if let Some(node) = st.keys.remove(&mk) {
                st.log(hive, Undo::KeyDeleted { mk, node });
            }
            Ok(())
        })
    }

    fn flush(&self) -> SysResult<()> {
        let hive = self.hive;
        self.prim(RegPrim::Flush, |st, _| {
            if !st.flush_broken
                && let Some(log) = st.logs.get_mut(&hive)
            {
                log.durable = log.entries.len();
            }
            Ok(())
        })
    }
}

impl PrimHive for FakeRegistry {
    type Key = FakeKey;

    fn open_root(&self, h: Hive, _a: KeyAccess) -> SysResult<FakeKey> {
        let (id, epoch) = prim(&self.inner, RegPrim::Root, None, |st| {
            let id = st
                .keys
                .get(&(h, String::new()))
                .map(|n| n.id)
                .ok_or_else(|| SysError::new(SysErrorKind::NotFound, h.to_string()))?;
            Ok((id, st.hub.epoch()))
        })?;
        Ok(FakeKey {
            reg: self.inner.clone(),
            hive: h,
            id,
            epoch,
        })
    }

    fn root_name(&self, h: Hive) -> SysResult<String> {
        Ok(kernel_name(h, ""))
    }

    fn elevated(&self) -> bool {
        self.lock().elevated
    }
}

impl RegistryWrite for FakeRegistry {
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

/// Test hook, see [`FakeRegistry::on_step`].
pub type RegHook = Box<dyn FnMut(&FakeRegistry, RegPrim) + Send>;

impl FakeRegistry {
    /// Shares `hub` with the file system of the same `FakeSystem`.
    pub(super) fn set_hub(&self, hub: Arc<FaultHub>) {
        self.lock().hub = hub;
    }

    /// Installs a hook that runs before each registry primitive of Rerun (another program:
    /// rename a key, plant a link), without the state lock; calls it makes are not counted.
    /// Replaces an earlier hook.
    pub fn on_step(&self, hook: impl FnMut(&FakeRegistry, RegPrim) + Send + 'static) {
        *self
            .inner
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Removes the hook (not from inside the hook itself).
    pub fn clear_on_step(&self) {
        *self
            .inner
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Arms `fault` for the `nth` (1-based) call of `call` (shared hub, see
    /// [`FakeFs::fault`](super::FakeFs::fault)).
    pub fn fault(&self, call: RegPrim, nth: usize, fault: Fault) {
        self.lock().hub.arm(Prim::Reg(call), nth, fault);
    }

    /// `fault(call, nth, Fault::Fail(kind))`.
    pub fn fail_at(&self, call: RegPrim, nth: usize, kind: SysErrorKind) {
        self.fault(call, nth, Fault::Fail(kind));
    }

    /// Makes every change so far durable in every hive, like a clean shutdown.
    pub fn sync_all(&self) {
        let mut st = self.lock();
        for log in st.logs.values_mut() {
            log.durable = log.entries.len();
        }
    }

    /// Changes of `hive` a power loss could drop (logged, not durable).
    pub fn pending(&self, hive: Hive) -> usize {
        self.lock()
            .logs
            .get(&hive)
            .map_or(0, |l| l.entries.len() - l.durable)
    }

    /// The registry part of a power loss (`FakeSystem::power_loss`): per hive the durable
    /// changes plus `keep[hive]` (default 0) more survive, the rest is undone newest first.
    pub(super) fn cut(&self, keep: &BTreeMap<Hive, usize>) {
        let mut st = self.lock();
        let logs = std::mem::take(&mut st.logs);
        for (hive, mut log) in logs {
            let kept = (log.durable + keep.get(&hive).copied().unwrap_or(0)).min(log.entries.len());
            while log.entries.len() > kept {
                if let Some(u) = log.entries.pop() {
                    st.undo(hive, u);
                }
            }
        }
    }

    /// Control K-R4: `PrimKey::flush` makes nothing durable.
    #[cfg(test)]
    pub(crate) fn break_flush(&self, on: bool) {
        self.lock().flush_broken = on;
    }

    /// Test: the process counts as elevated, so every changing write method is `Unsupported`
    /// (S2).
    pub fn set_elevated(&self, on: bool) {
        self.lock().elevated = on;
    }

    /// Attacker or other program: renames the existing key `k` (with everything below it) to
    /// `new_name` under the same parent, like `RegRenameKey`; the keys keep their identity, so
    /// an open handle follows. The new name must be free.
    pub fn rename_key(&self, k: &RegKey, new_name: &str) -> SysResult<()> {
        let mk = map_key(k)?;
        let mut st = self.fixture();
        let mk = st.follow_parent(&mk)?;
        let Some((parent, _)) = split_last(&mk.1) else {
            return Err(SysError::new(SysErrorKind::InvalidPath, k.to_string()));
        };
        let to = (mk.0, join(parent, &fold(new_name)));
        if !st.keys.contains_key(&mk) {
            return Err(not_found(k));
        }
        if st.keys.contains_key(&to) {
            return Err(SysError::new(
                SysErrorKind::AlreadyExists,
                new_name.to_owned(),
            ));
        }
        let prefix = format!("{}\\", mk.1);
        let moved: Vec<MapKey> = st
            .keys
            .keys()
            .filter(|(h, p)| *h == mk.0 && (*p == mk.1 || p.starts_with(&prefix)))
            .cloned()
            .collect();
        for old in moved {
            if let Some(mut node) = st.keys.remove(&old) {
                let rest = old.1.get(mk.1.len()..).unwrap_or_default().to_owned();
                if old == mk {
                    new_name.clone_into(&mut node.name);
                }
                st.keys.insert((old.0, format!("{}{rest}", to.1)), node);
            }
        }
        Ok(())
    }

    /// Setup: creates the key `k` (its parent must exist) as a volatile key (S4).
    pub fn put_volatile_key(&self, k: &RegKey) -> SysResult<()> {
        let mk = map_key(k)?;
        let mut st = self.fixture();
        let mk = st.follow_parent(&mk)?;
        st.create(k, &mk, &last_name(k))?;
        if let Some(n) = st.keys.get_mut(&mk) {
            n.volatile = true;
        }
        Ok(())
    }
}
