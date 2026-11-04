//! Snapshot of directories and registry keys for the round-trip contract
//! `apply → verify → revert → snapshot identical` (see `docs/09-testing.md`).
//!
//! Generic over `&dyn System`: runs against `sys::fake` in tests, in Windows Sandbox and
//! later for the folder comparison after a revert.
//!
//! "Identical" means: existence, kind, case, content (SHA-256), length, read-only
//! attribute; for the registry: keys, value names, value type and value.
//! **Timestamps are deliberately ignored**: restored backups have a new mtime.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::fs::{EntryKind, Fs};
use super::registry::{RegKey, RegValue, Registry};
use super::{SysError, SysErrorKind, SysResult, System};
use crate::fold::fold;

/// What a snapshot captures. Directories and keys, each recursively.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Absolute directories (or files).
    pub dirs: Vec<PathBuf>,
    /// Registry keys.
    pub keys: Vec<RegKey>,
}

/// Location of an entry (folded, i.e. unique case-insensitively).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Loc {
    Fs(String),
    Key(String),
    Value(String, String),
}

impl fmt::Display for Loc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fs(p) => write!(f, "{p}"),
            Self::Key(k) => write!(f, "{k}"),
            Self::Value(k, v) => write!(f, "{k} @ {v:?}"),
        }
    }
}

/// A captured entry. Names in their original case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapEntry {
    /// Root of the scope does not exist.
    Missing,
    /// Directory.
    Dir {
        /// Name.
        name: String,
        /// Read-only.
        readonly: bool,
    },
    /// File.
    File {
        /// Name.
        name: String,
        /// Length in bytes.
        len: u64,
        /// SHA-256 of the content.
        sha256: [u8; 32],
        /// Read-only.
        readonly: bool,
    },
    /// Reparse point (not followed).
    Reparse {
        /// Name.
        name: String,
    },
    /// Registry key.
    Key {
        /// Name.
        name: String,
    },
    /// Registry value.
    Value {
        /// Name (`""` = default value).
        name: String,
        /// Typed value.
        value: RegValue,
    },
}

impl fmt::Display for SnapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ro = |r: &bool| if *r { " [readonly]" } else { "" };
        match self {
            Self::Missing => f.write_str("<missing>"),
            Self::Dir { name, readonly } => write!(f, "dir {name:?}{}", ro(readonly)),
            Self::File {
                name,
                len,
                sha256,
                readonly,
            } => {
                write!(f, "file {name:?} {len} bytes sha256 ")?;
                for b in &sha256[..6] {
                    write!(f, "{b:02x}")?;
                }
                write!(f, "…{}", ro(readonly))
            }
            Self::Reparse { name } => write!(f, "reparse {name:?}"),
            Self::Key { name } => write!(f, "key {name:?}"),
            Self::Value { name, value } => write!(f, "value {name:?} = {value}"),
        }
    }
}

/// State of a [`Scope`] at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    entries: BTreeMap<Loc, SnapEntry>,
}

impl Snapshot {
    /// Number of captured entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if nothing was captured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Human-readable differences from `self` (before) to `other` (after).
    /// `-` = gone, `+` = new, `~` = changed. Empty = identical.
    pub fn diff(&self, other: &Self) -> Vec<String> {
        let mut out = Vec::new();
        for (loc, before) in &self.entries {
            match other.entries.get(loc) {
                None => out.push(format!("- {loc}: {before}")),
                Some(after) if after != before => out.push(format!("~ {loc}: {before} → {after}")),
                Some(_) => {}
            }
        }
        for (loc, after) in &other.entries {
            if !self.entries.contains_key(loc) {
                out.push(format!("+ {loc}: {after}"));
            }
        }
        out
    }
}

/// Captures the state of `scope`.
pub fn snapshot(sys: &dyn System, scope: &Scope) -> SysResult<Snapshot> {
    let mut snap = Snapshot::default();
    for dir in &scope.dirs {
        let name = dir.display().to_string();
        walk_fs(sys.fs(), dir, name, &mut snap.entries)?;
    }
    for key in &scope.keys {
        walk_key(sys.registry(), key, key.path.clone(), &mut snap.entries)?;
    }
    Ok(snap)
}

fn fs_loc(p: &Path) -> Loc {
    Loc::Fs(fold(&p.display().to_string().replace('/', "\\")))
}

fn walk_fs(
    fs: &dyn Fs,
    path: &Path,
    name: String,
    out: &mut BTreeMap<Loc, SnapEntry>,
) -> SysResult<()> {
    let Some(meta) = fs.metadata(path)? else {
        out.insert(fs_loc(path), SnapEntry::Missing);
        return Ok(());
    };
    match meta.kind {
        EntryKind::File => {
            let sha256 = hash_file(fs, path)?;
            out.insert(
                fs_loc(path),
                SnapEntry::File {
                    name,
                    len: meta.len,
                    sha256,
                    readonly: meta.readonly,
                },
            );
        }
        EntryKind::Reparse => {
            out.insert(fs_loc(path), SnapEntry::Reparse { name });
        }
        EntryKind::Dir => {
            out.insert(
                fs_loc(path),
                SnapEntry::Dir {
                    name,
                    readonly: meta.readonly,
                },
            );
            for entry in fs.read_dir(path)? {
                let child = path.join(&entry.name);
                walk_fs(fs, &child, entry.name, out)?;
            }
        }
    }
    Ok(())
}

fn hash_file(fs: &dyn Fs, path: &Path) -> SysResult<[u8; 32]> {
    let mut reader = fs.open_read(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| SysError::path(SysErrorKind::Other, path))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

fn key_loc(k: &RegKey) -> String {
    format!("{}[{}]\\{}", k.hive, k.view, fold(&k.path))
}

fn walk_key(
    reg: &dyn Registry,
    key: &RegKey,
    name: String,
    out: &mut BTreeMap<Loc, SnapEntry>,
) -> SysResult<()> {
    let loc = key_loc(key);
    if !reg.key_exists(key)? {
        out.insert(Loc::Key(loc), SnapEntry::Missing);
        return Ok(());
    }
    out.insert(Loc::Key(loc.clone()), SnapEntry::Key { name });
    for (value_name, value) in reg.values(key)? {
        out.insert(
            Loc::Value(loc.clone(), fold(&value_name)),
            SnapEntry::Value {
                name: value_name,
                value,
            },
        );
    }
    for sub in reg.subkeys(key)? {
        walk_key(reg, &key.join(&sub), sub, out)?;
    }
    Ok(())
}
