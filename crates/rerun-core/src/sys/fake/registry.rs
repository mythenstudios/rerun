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
use crate::sys::contract::RegFixture;
use crate::sys::registry::{
    Hive, MAX_SUBKEYS, MAX_VALUE_BYTES, MAX_VALUES, MAX_VALUES_TOTAL_BYTES, RegKey, RegLink,
    RegValue, RegView, Registry, check_key, check_value_name,
};
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
    #[expect(
        dead_code,
        reason = "the key identity of the write primitives, read from P2-9 C3 on"
    )]
    id: u64,
    name: String,
    /// Folded value name → (original name, value).
    values: BTreeMap<String, (String, RegValue)>,
    /// `Some` for a symbolic-link key.
    link: Option<LinkTo>,
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
                },
            );
        }
        Self {
            keys,
            denied: Vec::new(),
            next_id: 16,
        }
    }
}

/// In-memory registry. Hive roots always exist and cannot be deleted.
#[derive(Debug, Default)]
pub struct FakeRegistry {
    inner: Arc<Mutex<State>>,
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
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
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
        let mut st = self.lock();
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
        let mut st = self.lock();
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
        let mut st = self.lock();
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
        let mut st = self.lock();
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
        let mk = st.follow(&mk)?;
        st.check_access(k, &mk)?;
        Ok(st.keys.contains_key(&mk))
    }

    fn get(&self, k: &RegKey, name: &str) -> SysResult<Option<RegValue>> {
        let mk = map_key(k)?;
        check_value_name(k, name)?;
        let st = self.lock();
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
        let mk = st.follow_parent(&mk)?;
        st.check_access(k, &mk)?;
        let node = st.keys.get(&mk).ok_or_else(|| not_found(k))?;
        Ok(node.link.as_ref().map(|to| RegLink {
            target: kernel_name(k.hive, &to.shown).encode_utf16().collect(),
        }))
    }

    fn create_key(&self, k: &RegKey) -> SysResult<bool> {
        self.put_key(k)
    }

    fn set(&self, k: &RegKey, name: &str, v: &RegValue) -> SysResult<()> {
        self.put_value(k, name, v)
    }

    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()> {
        self.remove_value(k, name)
    }

    fn delete_key(&self, k: &RegKey) -> SysResult<()> {
        if k.path.is_empty() {
            map_key(k)?;
            return Err(SysError::new(SysErrorKind::AccessDenied, k.to_string()));
        }
        self.remove_key(k)
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
        let mut st = self.lock();
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
        let mut st = self.lock();
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
        let mut st = self.lock();
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

    fn large(&self, k: &RegKey, name: &str, len: usize) -> SysResult<bool> {
        self.put_value(k, name, &RegValue::Binary(vec![7; len]))?;
        Ok(true)
    }
}
