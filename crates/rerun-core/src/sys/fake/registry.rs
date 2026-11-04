//! In-memory registry with Win32 semantics (case-insensitive, WOW64 redirection).
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
//! - No symbolic-link keys (`HKLM\SYSTEM\CurrentControlSet` is a plain key if a test seeds it;
//!   `RegFixture::link` reports "not available").
//! - Access is all-or-nothing per key: a denied key and everything below it return
//!   `AccessDenied` for every method; there are no security descriptors.
//! - Key and value names fold with `fold`, a close but not exact copy of the registry's upcase
//!   table.
//! - Enumeration returns names sorted by folded name; the registry's order is unspecified.
//! - Reads are consistent snapshots: the races of `sys::win` (`ERROR_MORE_DATA`, a key that
//!   changes during an enumeration) cannot happen.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::fold::fold;
use crate::sys::contract::RegFixture;
use crate::sys::registry::{
    Hive, MAX_SUBKEYS, MAX_VALUE_BYTES, MAX_VALUES, MAX_VALUES_TOTAL_BYTES, RegKey, RegValue,
    RegView, Registry, check_key, check_value_name,
};
use crate::sys::{SysError, SysErrorKind, SysResult};

#[derive(Debug, Clone, Default)]
struct KeyNode {
    name: String,
    /// Folded value name → (original name, value).
    values: BTreeMap<String, (String, RegValue)>,
}

/// Hive and folded path of the native location.
type MapKey = (Hive, String);
type Keys = BTreeMap<MapKey, KeyNode>;

/// In-memory registry. Hive roots always exist and cannot be deleted.
#[derive(Debug, Default)]
pub struct FakeRegistry {
    keys: Mutex<Keys>,
    /// Keys (with everything below them) that refuse every method.
    denied: Mutex<Vec<MapKey>>,
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

fn check_name(k: &RegKey, name: &str) -> SysResult<()> {
    check_value_name(k, name)
}

fn unsupported(k: &RegKey, why: &str) -> SysError {
    SysError::new(SysErrorKind::Unsupported, format!("{k}: {why}"))
}

/// Size of a value as stored; a typed value without a canonical encoding has none.
fn data_len(v: &RegValue) -> usize {
    v.encode().map_or(0, |(_, d)| d.len())
}

fn not_found(k: &RegKey) -> SysError {
    SysError::new(SysErrorKind::NotFound, k.to_string())
}

impl FakeRegistry {
    fn lock(&self) -> MutexGuard<'_, Keys> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn exists(keys: &Keys, k: &RegKey, mk: &MapKey) -> bool {
        k.path.is_empty() || keys.contains_key(mk)
    }

    /// `AccessDenied` if `mk` is a denied key or lies below one.
    fn check_access(&self, k: &RegKey, mk: &MapKey) -> SysResult<()> {
        let denied = self.denied.lock().unwrap_or_else(PoisonError::into_inner);
        let hit = denied.iter().any(|(h, p)| {
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

    /// Builder only: `k` and everything below it refuse every method with `AccessDenied`
    /// (like `HKLM\SECURITY` for a user). Create the key and its children first.
    pub(super) fn deny(&self, k: &RegKey) -> SysResult<()> {
        let mk = map_key(k)?;
        self.denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(mk);
        Ok(())
    }

    fn child_keys<'a>(keys: &'a Keys, mk: &'a MapKey) -> impl Iterator<Item = &'a KeyNode> + 'a {
        let prefix = if mk.1.is_empty() {
            String::new()
        } else {
            format!("{}\\", mk.1)
        };
        let skip = prefix.len();
        keys.range((mk.0, prefix.clone())..)
            .take_while(move |((h, p), _)| *h == mk.0 && p.starts_with(&prefix))
            .filter(move |((_, p), _)| !p.is_empty() && !p[skip..].contains('\\'))
            .map(|(_, node)| node)
    }

    /// Builder only: creates a key including missing parents.
    pub(super) fn create_key_all(&self, k: &RegKey) -> SysResult<()> {
        let mut chain = Vec::new();
        let mut cur = Some(k.clone());
        while let Some(key) = cur {
            cur = key.parent();
            chain.push(key);
        }
        for key in chain.iter().rev() {
            self.create_key(key)?;
        }
        Ok(())
    }
}

impl Registry for FakeRegistry {
    fn key_exists(&self, k: &RegKey) -> SysResult<bool> {
        let mk = map_key(k)?;
        self.check_access(k, &mk)?;
        Ok(Self::exists(&self.lock(), k, &mk))
    }

    fn get(&self, k: &RegKey, name: &str) -> SysResult<Option<RegValue>> {
        let mk = map_key(k)?;
        self.check_access(k, &mk)?;
        check_name(k, name)?;
        let keys = self.lock();
        if !Self::exists(&keys, k, &mk) {
            return Err(not_found(k));
        }
        let value = keys
            .get(&mk)
            .and_then(|n| n.values.get(&fold(name)))
            .map(|(_, v)| v.clone());
        if value
            .as_ref()
            .is_some_and(|v| data_len(v) > MAX_VALUE_BYTES)
        {
            return Err(unsupported(k, "value larger than 1 MiB"));
        }
        Ok(value)
    }

    fn values(&self, k: &RegKey) -> SysResult<Vec<(String, RegValue)>> {
        let mk = map_key(k)?;
        self.check_access(k, &mk)?;
        let keys = self.lock();
        if !Self::exists(&keys, k, &mk) {
            return Err(not_found(k));
        }
        let values: Vec<(String, RegValue)> = keys
            .get(&mk)
            .map(|n| n.values.values().cloned().collect())
            .unwrap_or_default();
        if values.len() > MAX_VALUES {
            return Err(unsupported(k, "too many values"));
        }
        let mut total = 0_usize;
        for (_, v) in &values {
            let len = data_len(v);
            if len > MAX_VALUE_BYTES {
                return Err(unsupported(k, "value larger than 1 MiB"));
            }
            total += len;
        }
        if total > MAX_VALUES_TOTAL_BYTES {
            return Err(unsupported(k, "values larger than 16 MiB in total"));
        }
        Ok(values)
    }

    fn subkeys(&self, k: &RegKey) -> SysResult<Vec<String>> {
        let mk = map_key(k)?;
        self.check_access(k, &mk)?;
        let keys = self.lock();
        if !Self::exists(&keys, k, &mk) {
            return Err(not_found(k));
        }
        let names: Vec<String> = Self::child_keys(&keys, &mk)
            .map(|n| n.name.clone())
            .collect();
        if names.len() > MAX_SUBKEYS {
            return Err(unsupported(k, "too many subkeys"));
        }
        Ok(names)
    }

    fn create_key(&self, k: &RegKey) -> SysResult<bool> {
        let mk = map_key(k)?;
        self.check_access(k, &mk)?;
        let mut keys = self.lock();
        if Self::exists(&keys, k, &mk) {
            return Ok(false);
        }
        let Some(parent) = k.parent() else {
            return Ok(false);
        };
        let pmk = map_key(&parent)?;
        if !Self::exists(&keys, &parent, &pmk) {
            return Err(not_found(&parent));
        }
        // The real `WOW6432Node` always exists; here the first 32-bit key creates it.
        if let Some((parent_path, _)) = mk.1.rsplit_once('\\')
            && parent_path == format!("SOFTWARE\\{WOW_NODE}")
        {
            keys.entry((mk.0, parent_path.to_owned()))
                .or_insert_with(|| KeyNode {
                    name: "WOW6432Node".to_owned(),
                    values: BTreeMap::new(),
                });
        }
        let name = k.path.rsplit('\\').next().unwrap_or_default().to_owned();
        keys.insert(
            mk,
            KeyNode {
                name,
                values: BTreeMap::new(),
            },
        );
        Ok(true)
    }

    fn set(&self, k: &RegKey, name: &str, v: &RegValue) -> SysResult<()> {
        let mk = map_key(k)?;
        self.check_access(k, &mk)?;
        check_name(k, name)?;
        if v.encode().is_none() {
            return Err(unsupported(k, "value has no canonical encoding"));
        }
        let mut keys = self.lock();
        if !Self::exists(&keys, k, &mk) {
            return Err(not_found(k));
        }
        // The hive root has no entry in the map; values there are allowed nonetheless.
        let node = keys.entry(mk).or_default();
        let folded = fold(name);
        let original = node
            .values
            .get(&folded)
            .map_or_else(|| name.to_owned(), |(n, _)| n.clone());
        node.values.insert(folded, (original, v.clone()));
        Ok(())
    }

    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()> {
        let mk = map_key(k)?;
        self.check_access(k, &mk)?;
        check_name(k, name)?;
        let mut keys = self.lock();
        if !Self::exists(&keys, k, &mk) {
            return Err(not_found(k));
        }
        match keys.get_mut(&mk).and_then(|n| n.values.remove(&fold(name))) {
            Some(_) => Ok(()),
            None => Err(SysError::new(
                SysErrorKind::NotFound,
                format!("{k} @ {name:?}"),
            )),
        }
    }

    fn delete_key(&self, k: &RegKey) -> SysResult<()> {
        let mk = map_key(k)?;
        self.check_access(k, &mk)?;
        if k.path.is_empty() {
            return Err(SysError::new(SysErrorKind::AccessDenied, k.to_string()));
        }
        let mut keys = self.lock();
        if !keys.contains_key(&mk) {
            return Err(not_found(k));
        }
        if Self::child_keys(&keys, &mk).next().is_some() {
            return Err(SysError::new(SysErrorKind::NotEmpty, k.to_string()));
        }
        keys.remove(&mk);
        Ok(())
    }
}

impl RegFixture for FakeRegistry {
    fn key(&self, k: &RegKey) -> SysResult<()> {
        self.create_key_all(k)
    }

    fn raw(&self, k: &RegKey, name: &str, kind: u32, data: &[u8]) -> SysResult<()> {
        self.set(k, name, &RegValue::decode(kind, data))
    }

    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()> {
        Registry::delete_value(self, k, name)
    }

    fn link(&self, _link: &RegKey, _target: &RegKey) -> SysResult<bool> {
        Ok(false)
    }

    fn large(&self, k: &RegKey, name: &str, len: usize) -> SysResult<bool> {
        self.set(k, name, &RegValue::Binary(vec![7; len]))?;
        Ok(true)
    }
}
