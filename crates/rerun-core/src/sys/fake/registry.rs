//! In-memory registry with Win32 semantics (case-insensitive, separate views).

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::sys::fold::fold;
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, Registry};
use crate::sys::{SysError, SysErrorKind, SysResult};

#[derive(Debug, Clone, Default)]
struct KeyNode {
    name: String,
    /// Folded value name → (original name, value).
    values: BTreeMap<String, (String, RegValue)>,
}

type MapKey = (Hive, RegView, String);
type Keys = BTreeMap<MapKey, KeyNode>;

/// In-memory registry. Hive roots always exist and cannot be deleted.
#[derive(Debug, Default)]
pub struct FakeRegistry {
    keys: Mutex<Keys>,
}

fn map_key(k: &RegKey) -> SysResult<MapKey> {
    // NUL would truncate the path in Win32 calls; empty segments are invalid.
    if k.path.contains('\0') || (!k.path.is_empty() && k.path.split('\\').any(str::is_empty)) {
        return Err(SysError::new(SysErrorKind::InvalidPath, k.to_string()));
    }
    Ok((k.hive, k.view, fold(&k.path)))
}

fn check_name(k: &RegKey, name: &str) -> SysResult<()> {
    if name.contains('\0') {
        return Err(SysError::new(
            SysErrorKind::InvalidPath,
            format!("{k} @ {name:?}"),
        ));
    }
    Ok(())
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

    fn child_keys<'a>(keys: &'a Keys, mk: &'a MapKey) -> impl Iterator<Item = &'a KeyNode> + 'a {
        let prefix = if mk.2.is_empty() {
            String::new()
        } else {
            format!("{}\\", mk.2)
        };
        let skip = prefix.len();
        keys.range((mk.0, mk.1, prefix.clone())..)
            .take_while(move |((h, v, p), _)| *h == mk.0 && *v == mk.1 && p.starts_with(&prefix))
            .filter(move |((_, _, p), _)| !p.is_empty() && !p[skip..].contains('\\'))
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
        Ok(Self::exists(&self.lock(), k, &mk))
    }

    fn get(&self, k: &RegKey, name: &str) -> SysResult<Option<RegValue>> {
        let mk = map_key(k)?;
        check_name(k, name)?;
        let keys = self.lock();
        if !Self::exists(&keys, k, &mk) {
            return Err(not_found(k));
        }
        Ok(keys
            .get(&mk)
            .and_then(|n| n.values.get(&fold(name)))
            .map(|(_, v)| v.clone()))
    }

    fn values(&self, k: &RegKey) -> SysResult<Vec<(String, RegValue)>> {
        let mk = map_key(k)?;
        let keys = self.lock();
        if !Self::exists(&keys, k, &mk) {
            return Err(not_found(k));
        }
        Ok(keys
            .get(&mk)
            .map(|n| n.values.values().cloned().collect())
            .unwrap_or_default())
    }

    fn subkeys(&self, k: &RegKey) -> SysResult<Vec<String>> {
        let mk = map_key(k)?;
        let keys = self.lock();
        if !Self::exists(&keys, k, &mk) {
            return Err(not_found(k));
        }
        Ok(Self::child_keys(&keys, &mk)
            .map(|n| n.name.clone())
            .collect())
    }

    fn create_key(&self, k: &RegKey) -> SysResult<bool> {
        let mk = map_key(k)?;
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
        check_name(k, name)?;
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
