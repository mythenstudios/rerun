//! Snapshot of directories and registry keys for the round-trip contract
//! `apply → verify → revert → snapshot identical` (see `docs/09-testing.md`).
//!
//! Generic over `&dyn System`: runs against `sys::fake` in tests, against `sys::win` in the
//! contract runs and later for the folder comparison after a revert.
//!
//! Each scope directory is opened by absolute path (one of the two allowed callers of
//! [`Fs::open_dir`], ADR 0007) and then walked through [`Dir`] handles, never following
//! reparse points.
//!
//! "Identical" means: existence, kind, case, content (SHA-256), length, attributes
//! (read-only, hidden, system), link count, reparse tag and link target; for the registry:
//! keys, value names, value type and value. Names that fail `policy::path::classify` (and
//! all entries of case-sensitive directories, and entries whose names fold to the same key)
//! are captured as [`SnapEntry::Anomaly`] with metadata only: never hashed, never opened,
//! never descended into.
//!
//! Not captured: timestamps and file IDs (restored backups have a new mtime and a new ID),
//! the attributes of a scope root itself (that would need a second absolute open of its
//! parent), and the content of cloud placeholders (allowlisted `0x9000_x01A` tags): hashing
//! them could trigger a download (ADR 0007), so they are recorded with metadata only.
//! Directories nested deeper than [`MAX_DEPTH`] below a scope root are an error.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use super::fs::{Attrs, Dir, EntryKind};
use super::registry::{RegKey, RegValue, Registry};
use super::{SysError, SysErrorKind, SysResult, System};
use crate::fold::fold;
use crate::path::{RelPath, classify};

/// Maximum directory depth below a scope root.
pub const MAX_DEPTH: usize = 64;

/// What a snapshot captures. Directories and keys, each recursively.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Absolute directories.
    pub dirs: Vec<PathBuf>,
    /// Registry keys.
    pub keys: Vec<RegKey>,
}

/// Location of an entry (folded, i.e. unique case-insensitively; exact in case-sensitive
/// directories).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Loc {
    Fs(String),
    Key(String),
    Value(String, String),
}

impl fmt::Display for Loc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fs(p) => write!(f, "{}", p.replace('\0', "<raw>")),
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
        /// Attributes.
        attrs: Attrs,
    },
    /// File.
    File {
        /// Name.
        name: String,
        /// Length in bytes.
        len: u64,
        /// SHA-256 of the content; `None` for cloud placeholders (not hashed).
        sha256: Option<[u8; 32]>,
        /// Allowlisted data tag (WOF, dedup, cloud), if any.
        tag: Option<u32>,
        /// Attributes.
        attrs: Attrs,
        /// Number of hard links.
        links: u32,
    },
    /// Reparse point (not followed).
    Reparse {
        /// Name.
        name: String,
        /// Reparse tag.
        tag: u32,
        /// Link target, if any.
        target: Option<String>,
    },
    /// Entry whose raw name is not a valid segment, or an entry of a case-sensitive
    /// directory. Metadata only.
    Anomaly {
        /// Raw name.
        name: String,
        /// Kind.
        kind: EntryKind,
        /// Length in bytes.
        len: u64,
        /// Attributes.
        attrs: Attrs,
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

struct ShowAttrs<'a>(&'a Attrs);

impl fmt::Display for ShowAttrs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self.0;
        for (on, label) in [
            (a.readonly, " [readonly]"),
            (a.hidden, " [hidden]"),
            (a.system, " [system]"),
        ] {
            if on {
                f.write_str(label)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for SnapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("<missing>"),
            Self::Dir { name, attrs } => write!(f, "dir {name:?}{}", ShowAttrs(attrs)),
            Self::File {
                name,
                len,
                sha256,
                tag,
                attrs,
                links,
            } => {
                write!(f, "file {name:?} {len} bytes")?;
                match sha256 {
                    Some(h) => {
                        f.write_str(" sha256 ")?;
                        for b in &h[..6] {
                            write!(f, "{b:02x}")?;
                        }
                        f.write_str("…")?;
                    }
                    None => f.write_str(" (not hashed)")?,
                }
                if let Some(t) = tag {
                    write!(f, " tag {t:#010x}")?;
                }
                write!(f, "{}", ShowAttrs(attrs))?;
                if *links > 1 {
                    write!(f, " [{links} links]")?;
                }
                Ok(())
            }
            Self::Reparse { name, tag, target } => {
                write!(f, "reparse {name:?} tag {tag:#010x}")?;
                if let Some(t) = target {
                    write!(f, " → {t:?}")?;
                }
                Ok(())
            }
            Self::Anomaly {
                name,
                kind,
                len,
                attrs,
            } => write!(
                f,
                "anomaly {name:?} {kind:?} {len} bytes{}",
                ShowAttrs(attrs)
            ),
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
        let loc = fold(name.replace('/', "\\").trim_end_matches('\\'));
        let handle = match sys.fs().open_dir(dir) {
            Ok(h) => h,
            Err(e) if e.kind == SysErrorKind::NotFound => {
                snap.entries.insert(Loc::Fs(loc), SnapEntry::Missing);
                continue;
            }
            Err(e) => return Err(e),
        };
        let attrs = Attrs::default();
        snap.entries
            .insert(Loc::Fs(loc.clone()), SnapEntry::Dir { name, attrs });
        walk_dir(&*handle, &loc, 0, &mut snap.entries)?;
    }
    for key in &scope.keys {
        walk_key(sys.registry(), key, key.path.clone(), &mut snap.entries)?;
    }
    Ok(snap)
}

/// `true` for the cloud files family (placeholders that may hydrate when read).
fn is_cloud(tag: u32) -> bool {
    tag & 0xFFFF_0FFF == super::fs::tag::CLOUD
}

fn walk_dir(
    dir: &dyn Dir,
    prefix: &str,
    depth: usize,
    out: &mut BTreeMap<Loc, SnapEntry>,
) -> SysResult<()> {
    if depth > MAX_DEPTH {
        return Err(SysError::new(
            SysErrorKind::Other,
            format!("{prefix}: deeper than {MAX_DEPTH} directories"),
        ));
    }
    let case_sensitive = dir.info()?.case_sensitive;
    let entries = dir.read_dir(None)?;
    let key_of = |name: &str| {
        if case_sensitive {
            name.to_owned()
        } else {
            fold(name)
        }
    };
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for e in &entries {
        *seen.entry(key_of(&e.name)).or_default() += 1;
    }
    for entry in entries {
        let key = key_of(&entry.name);
        let collides = seen.get(&key).is_some_and(|&n| n > 1);
        let meta = entry.meta;
        let seg = if collides {
            None
        } else {
            classify(&entry.name, case_sensitive).ok()
        };
        let Some(seg) = seg else {
            // NUL cannot occur in a name on disk: raw keys never clash with folded ones.
            let loc = if collides || case_sensitive {
                format!("{prefix}\\\0{}", entry.name)
            } else {
                format!("{prefix}\\{key}")
            };
            out.insert(
                Loc::Fs(loc),
                SnapEntry::Anomaly {
                    name: entry.name,
                    kind: meta.kind,
                    len: meta.len,
                    attrs: meta.attrs,
                },
            );
            continue;
        };
        let loc = format!("{prefix}\\{key}");
        match meta.kind {
            EntryKind::File => {
                let tag = meta.reparse.map(|r| r.tag);
                let sha256 = if tag.is_some_and(is_cloud) {
                    None
                } else {
                    Some(hash_file(dir, &seg)?)
                };
                out.insert(
                    Loc::Fs(loc),
                    SnapEntry::File {
                        name: entry.name,
                        len: meta.len,
                        sha256,
                        tag,
                        attrs: meta.attrs,
                        links: meta.links,
                    },
                );
            }
            EntryKind::Reparse => {
                let (tag, target) = meta.reparse.map_or((0, None), |r| (r.tag, r.target));
                out.insert(
                    Loc::Fs(loc),
                    SnapEntry::Reparse {
                        name: entry.name,
                        tag,
                        target,
                    },
                );
            }
            EntryKind::Dir => {
                out.insert(
                    Loc::Fs(loc.clone()),
                    SnapEntry::Dir {
                        name: entry.name,
                        attrs: meta.attrs,
                    },
                );
                let sub = dir.open_dir(&seg)?;
                walk_dir(&*sub, &loc, depth + 1, out)?;
            }
        }
    }
    Ok(())
}

fn hash_file(dir: &dyn Dir, p: &RelPath) -> SysResult<[u8; 32]> {
    let mut reader = dir.open_read(p)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| SysError::new(SysErrorKind::Other, p.as_str()))?;
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Loc, SnapEntry, walk_dir};
    use crate::path::RelPath;
    use crate::sys::fs::{Attrs, Dir, DirEntry, EntryKind, Metadata, ReadSeek, RootInfo};
    use crate::sys::{SysError, SysErrorKind, SysResult};

    /// A directory whose listing contains two names that fold to the same key (possible on
    /// real NTFS when its upcase table differs from ours). Every other call fails.
    #[derive(Debug)]
    struct Colliding;

    fn no<T>() -> SysResult<T> {
        Err(SysError::new(SysErrorKind::Unsupported, "stub"))
    }

    impl Dir for Colliding {
        fn info(&self) -> SysResult<RootInfo> {
            Ok(RootInfo {
                final_path: PathBuf::from(r"\\?\C:\G"),
                volume_serial: 1,
                file_id: 1,
                user_writable: true,
                case_sensitive: false,
                volume_root: false,
                fs_kind: crate::sys::fs::FsKind::Ntfs,
                supports_posix_rename: true,
            })
        }
        fn open_dir(&self, _: &RelPath) -> SysResult<Box<dyn Dir + '_>> {
            no()
        }
        fn metadata(&self, _: &RelPath) -> SysResult<Option<Metadata>> {
            no()
        }
        fn open_read(&self, p: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>> {
            assert_eq!(p.as_str(), "other.bin", "colliding name opened");
            Ok(Box::new(std::io::Cursor::new(vec![1u8])))
        }
        fn read_dir(&self, _: Option<&RelPath>) -> SysResult<Vec<DirEntry>> {
            let meta = Metadata {
                kind: EntryKind::File,
                len: 1,
                attrs: Attrs::default(),
                links: 1,
                file_id: 2,
                reparse: None,
            };
            Ok(["data.bin", "DATA.BIN", "other.bin"]
                .into_iter()
                .map(|n| DirEntry {
                    name: n.to_owned(),
                    meta: meta.clone(),
                })
                .collect())
        }
        fn create_new(&self, _: &RelPath, _: &[u8]) -> SysResult<()> {
            no()
        }
        fn replace(&self, _: &RelPath, _: &[u8], _: &str) -> SysResult<()> {
            no()
        }
        fn create_dir(&self, _: &RelPath) -> SysResult<()> {
            no()
        }
        fn remove_file(&self, _: &RelPath) -> SysResult<()> {
            no()
        }
        fn remove_dir(&self, _: &RelPath) -> SysResult<()> {
            no()
        }
        fn rename(&self, _: &RelPath, _: &RelPath) -> SysResult<()> {
            no()
        }
        fn set_readonly(&self, _: &RelPath, _: bool) -> SysResult<()> {
            no()
        }
    }

    #[test]
    fn colliding_names_become_anomalies_and_are_never_opened() {
        let mut out = std::collections::BTreeMap::new();
        walk_dir(&Colliding, r"c:\g", 0, &mut out).unwrap();
        assert_eq!(out.len(), 3, "{out:#?}");
        assert!(
            out.values()
                .any(|e| matches!(e, SnapEntry::File { name, .. } if name == "other.bin"))
        );
        let anomalies: Vec<&SnapEntry> = out
            .iter()
            .filter(|(loc, _)| matches!(loc, Loc::Fs(p) if p.contains('\0')))
            .map(|(_, e)| e)
            .collect();
        assert_eq!(anomalies.len(), 2, "{out:#?}");
        assert!(
            anomalies
                .iter()
                .all(|e| matches!(e, SnapEntry::Anomaly { .. }))
        );
    }
}
