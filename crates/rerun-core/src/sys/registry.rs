//! Registry trait.

use std::fmt;

use super::SysResult;

/// Registry hive. Further hives only when a primitive needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hive {
    /// `HKEY_CURRENT_USER`
    CurrentUser,
    /// `HKEY_LOCAL_MACHINE`
    LocalMachine,
}

impl fmt::Display for Hive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CurrentUser => "HKCU",
            Self::LocalMachine => "HKLM",
        })
    }
}

/// Registry view (WOW64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegView {
    /// Native 64-bit view.
    Native,
    /// 32-bit view (`KEY_WOW64_32KEY`).
    Wow32,
}

impl fmt::Display for RegView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::Wow32 => "wow32",
        })
    }
}

/// A registry key. `path` without leading or trailing `\`; empty = hive root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegKey {
    /// Hive.
    pub hive: Hive,
    /// View.
    pub view: RegView,
    /// Path below the hive, separated by `\`.
    pub path: String,
}

impl RegKey {
    /// New key; leading and trailing `\` are removed.
    pub fn new(hive: Hive, view: RegView, path: impl AsRef<str>) -> Self {
        Self {
            hive,
            view,
            path: path.as_ref().trim_matches('\\').to_owned(),
        }
    }

    /// Subkey.
    #[must_use]
    pub fn join(&self, sub: &str) -> Self {
        let sub = sub.trim_matches('\\');
        let path = if self.path.is_empty() {
            sub.to_owned()
        } else {
            format!("{}\\{sub}", self.path)
        };
        Self {
            hive: self.hive,
            view: self.view,
            path,
        }
    }

    /// Parent key; `None` for the hive root.
    pub fn parent(&self) -> Option<Self> {
        if self.path.is_empty() {
            return None;
        }
        let path = self
            .path
            .rsplit_once('\\')
            .map_or("", |(p, _)| p)
            .to_owned();
        Some(Self {
            hive: self.hive,
            view: self.view,
            path,
        })
    }
}

impl fmt::Display for RegKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]\\{}", self.hive, self.view, self.path)
    }
}

/// A typed registry value. `Dword(1)` and `String("1")` are different.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    /// `REG_SZ`
    String(String),
    /// `REG_EXPAND_SZ`
    ExpandString(String),
    /// `REG_MULTI_SZ`
    MultiString(Vec<String>),
    /// `REG_DWORD`
    Dword(u32),
    /// `REG_QWORD`
    Qword(u64),
    /// `REG_BINARY`
    Binary(Vec<u8>),
}

impl fmt::Display for RegValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "REG_SZ {s:?}"),
            Self::ExpandString(s) => write!(f, "REG_EXPAND_SZ {s:?}"),
            Self::MultiString(v) => write!(f, "REG_MULTI_SZ {v:?}"),
            Self::Dword(v) => write!(f, "REG_DWORD {v:#010x}"),
            Self::Qword(v) => write!(f, "REG_QWORD {v:#018x}"),
            Self::Binary(b) => write!(f, "REG_BINARY {} bytes", b.len()),
        }
    }
}

/// Registry. Key and value names are case-insensitive, the original case is preserved.
///
/// An existing empty key is different from a missing one: the revert must restore
/// this difference.
pub trait Registry: Send + Sync {
    /// Does the key exist?
    fn key_exists(&self, k: &RegKey) -> SysResult<bool>;

    /// Reads a value; `""` = default value. Key missing → `NotFound`, value missing → `None`.
    fn get(&self, k: &RegKey, name: &str) -> SysResult<Option<RegValue>>;

    /// All values of a key (name in its original case).
    fn values(&self, k: &RegKey) -> SysResult<Vec<(String, RegValue)>>;

    /// Names of the direct subkeys.
    fn subkeys(&self, k: &RegKey) -> SysResult<Vec<String>>;

    /// Creates exactly one key; the parent key must exist (`NotFound` otherwise).
    /// `true` = newly created, `false` = already existed (important for the journal).
    fn create_key(&self, k: &RegKey) -> SysResult<bool>;

    /// Sets a value. Key missing → `NotFound`.
    fn set(&self, k: &RegKey, name: &str, v: &RegValue) -> SysResult<()>;

    /// Deletes a value. Missing → `NotFound`.
    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()>;

    /// Deletes a key without subkeys (`NotEmpty` otherwise).
    fn delete_key(&self, k: &RegKey) -> SysResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_and_parent() {
        let root = RegKey::new(Hive::CurrentUser, RegView::Native, "\\Software\\");
        assert_eq!(root.path, "Software");
        let k = root.join("Rerun");
        assert_eq!(k.path, "Software\\Rerun");
        assert_eq!(k.parent(), Some(root.clone()));
        assert_eq!(root.parent().map(|p| p.path), Some(String::new()));
        assert_eq!(
            RegKey::new(Hive::CurrentUser, RegView::Native, "").parent(),
            None
        );
    }
}
