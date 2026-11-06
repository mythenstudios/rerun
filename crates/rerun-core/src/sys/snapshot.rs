//! Snapshot of directories and registry keys for the round-trip contract
//! `apply → verify → revert → snapshot identical` (see `docs/09-testing.md`). Test code only
//! (`cfg(any(test, feature = "fake"))`, like `contract` and `fake`; ADR 0004).
//!
//! A scope names its directories as **root handles** ([`SnapRoot`]): the [`Dir`] of a root
//! that `policy::root` opened (a `GameDir`, later an `AppDir`), never an absolute path. The
//! snapshot walks each one through [`Dir`] handles and never follows a reparse point. It reads
//! the registry through `&dyn Registry`, so it runs against `sys::fake` and `sys::win`
//! (`sys::contract::snapshot_contract`).
//!
//! Each root is recorded with its identity (volume serial and file ID of the opened directory)
//! and, for [`SnapRoot::below`], the subtree: two snapshots of different roots are never
//! identical, whatever their content. The root's label is for display only.
//!
//! "Identical" means: existence, kind, case, content (SHA-256), length, attributes
//! (read-only, hidden, system), link count, reparse tag and link target; for the registry:
//! keys, value names, value type and value. Names that fail `policy::path::classify` (and
//! all entries of case-sensitive directories, and entries whose names fold to the same key)
//! are captured as [`SnapEntry::Anomaly`] with metadata only: never hashed, never opened,
//! never descended into. Restricted entries (their DACL denies the current user every open,
//! [`Metadata::restricted`](super::fs::Metadata::restricted)) are captured as
//! [`SnapEntry::Restricted`] from the listing: kind, length, attributes and reparse tag count,
//! the link count does not (unknown); they are never opened, hashed or descended into.
//!
//! Not captured: timestamps and file IDs of entries (restored backups have a new mtime and a
//! new ID), the attributes and the name of a root itself (only its identity), and the content
//! of cloud placeholders (allowlisted `0x9000_x01A` tags): hashing them could trigger a
//! download (ADR 0007), so they are recorded with metadata only. Directories nested deeper
//! than [`MAX_DEPTH`] below a root are an error.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

use sha2::{Digest, Sha256};

use super::fs::{Attrs, Dir, DirEntry, EntryKind};
use super::registry::{RegKey, RegValue, Registry};
use super::{SysError, SysErrorKind, SysResult};
use crate::fold::fold;
use crate::path::{RelPath, classify};

/// Maximum directory depth below a root.
pub const MAX_DEPTH: usize = 64;

/// One directory of a [`Scope`]: the handle of a root and what of it to capture.
#[derive(Debug, Clone)]
pub struct SnapRoot<'a> {
    dir: &'a dyn Dir,
    label: String,
    sub: Option<RelPath>,
}

impl<'a> SnapRoot<'a> {
    /// The whole tree below the root `dir`. `dir` is the read handle of a root that
    /// `policy::root` handed out (`GameDir::dir`, later `AppDir`); test code of this crate
    /// may pass any [`Dir`]. `label` is shown in a diff (e.g. the root's canonical path) and
    /// never compared.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "built by the tests of this crate only")
    )]
    pub(crate) fn new(dir: &'a dyn Dir, label: impl Into<String>) -> Self {
        Self {
            dir,
            label: label.into(),
            sub: None,
        }
    }

    /// Only the entry `sub` below the root and, if it is a directory, the tree below it (a
    /// second call replaces the first). The entry is captured like any entry of its parent's
    /// listing: a file is hashed, a reparse point is recorded and not followed, a restricted
    /// entry is recorded from the listing. A missing `sub` (or a parent of it that is missing
    /// or a file) is [`SnapEntry::Missing`]; a reparse point or a restricted entry among its
    /// parents is an error (`ReparsePoint`, `AccessDenied`), never followed.
    #[must_use]
    pub fn below(mut self, sub: RelPath) -> Self {
        self.sub = Some(sub);
        self
    }
}

/// What a snapshot captures: root handles and registry keys, each recursively.
#[derive(Debug, Clone, Default)]
pub struct Scope<'a> {
    /// Directories, as root handles.
    pub dirs: Vec<SnapRoot<'a>>,
    /// Registry keys.
    pub keys: Vec<RegKey>,
}

/// Identity of a captured root: the opened directory and the subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RootIdent {
    volume_serial: u64,
    file_id: u128,
    /// Folded [`SnapRoot::below`] path.
    sub: Option<String>,
}

impl fmt::Display for RootIdent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}-{:032x}", self.volume_serial, self.file_id)?;
        if let Some(s) = &self.sub {
            write!(f, " below {s:?}")?;
        }
        Ok(())
    }
}

/// Location of an entry (folded, i.e. unique case-insensitively; exact in case-sensitive
/// directories).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Loc {
    /// Path below root number `root` of [`Scope::dirs`], `\`-separated; a segment that
    /// starts with NUL is a raw name (an anomaly).
    Fs {
        root: usize,
        path: String,
    },
    Key(String),
    Value(String, String),
}

/// A captured entry. Names in their original case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapEntry {
    /// The entry does not exist (a registry key of the scope, or the `sub` of
    /// [`SnapRoot::below`]).
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
        /// Number of hard links (`None` = unknown; only for entries `sys` could not open).
        links: Option<u32>,
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
        /// The entry is also restricted (cannot be opened).
        restricted: bool,
    },
    /// Entry that the current user cannot open at all (its DACL denies even reading its
    /// attributes). Metadata from the directory listing only; never opened, hashed or
    /// descended into.
    Restricted {
        /// Name.
        name: String,
        /// Kind.
        kind: EntryKind,
        /// Length in bytes (0 for directories and reparse points).
        len: u64,
        /// Attributes.
        attrs: Attrs,
        /// Reparse tag, if any (the link target is unknown).
        tag: Option<u32>,
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
                match links {
                    Some(1) => {}
                    Some(n) => write!(f, " [{n} links]")?,
                    None => f.write_str(" [links unknown]")?,
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
                restricted,
            } => write!(
                f,
                "anomaly {name:?} {kind:?} {len} bytes{}{}",
                ShowAttrs(attrs),
                if *restricted { " [restricted]" } else { "" }
            ),
            Self::Restricted {
                name,
                kind,
                len,
                attrs,
                tag,
            } => {
                write!(f, "restricted {name:?} {kind:?} {len} bytes")?;
                if let Some(t) = tag {
                    write!(f, " tag {t:#010x}")?;
                }
                write!(f, "{}", ShowAttrs(attrs))
            }
            Self::Key { name } => write!(f, "key {name:?}"),
            Self::Value { name, value } => write!(f, "value {name:?} = {value}"),
        }
    }
}

/// State of a [`Scope`] at a point in time. Two snapshots are equal if they captured the same
/// roots (identity and subtree, in the same order) and the same entries; the labels of the
/// roots are not compared.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    roots: Vec<RootIdent>,
    labels: Vec<String>,
    entries: BTreeMap<Loc, SnapEntry>,
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        self.roots == other.roots && self.entries == other.entries
    }
}

impl Eq for Snapshot {}

impl Snapshot {
    /// Number of captured entries (the roots themselves not counted).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no entry was captured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn label(&self, root: usize) -> &str {
        self.labels.get(root).map_or("<root>", String::as_str)
    }

    fn show(&self, loc: &Loc) -> String {
        match loc {
            Loc::Fs { root, path } if path.is_empty() => self.label(*root).to_owned(),
            Loc::Fs { root, path } => {
                format!("{}\\{}", self.label(*root), path.replace('\0', "<raw>"))
            }
            Loc::Key(k) => k.clone(),
            Loc::Value(k, v) => format!("{k} @ {v:?}"),
        }
    }

    /// Human-readable differences from `self` (before) to `other` (after).
    /// `-` = gone, `+` = new, `~` = changed. Empty = identical. A different root (another
    /// directory, another subtree, or another number of roots) is a difference of its own.
    pub fn diff(&self, other: &Self) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0..self.roots.len().max(other.roots.len()) {
            match (self.roots.get(i), other.roots.get(i)) {
                (Some(a), Some(b)) if a != b => {
                    out.push(format!("~ root {i} ({}): {a} → {b}", self.label(i)))
                }
                (Some(a), None) => out.push(format!("- root {i} ({}): {a}", self.label(i))),
                (None, Some(b)) => out.push(format!("+ root {i} ({}): {b}", other.label(i))),
                _ => {}
            }
        }
        for (loc, before) in &self.entries {
            match other.entries.get(loc) {
                None => out.push(format!("- {}: {before}", self.show(loc))),
                Some(after) if after != before => {
                    out.push(format!("~ {}: {before} → {after}", self.show(loc)));
                }
                Some(_) => {}
            }
        }
        for (loc, after) in &other.entries {
            if !self.entries.contains_key(loc) {
                out.push(format!("+ {}: {after}", other.show(loc)));
            }
        }
        out
    }
}

/// Captures the state of `scope`. Directories through their root handles, keys through `reg`.
pub fn snapshot(reg: &dyn Registry, scope: &Scope<'_>) -> SysResult<Snapshot> {
    let mut snap = Snapshot::default();
    for (i, root) in scope.dirs.iter().enumerate() {
        let info = root.dir.info()?;
        snap.roots.push(RootIdent {
            volume_serial: info.volume_serial,
            file_id: info.file_id,
            sub: root.sub.as_ref().map(|s| fold(s.as_str())),
        });
        snap.labels.push(root.label.clone());
        let mut walk = Walk {
            root: i,
            out: &mut snap.entries,
        };
        match &root.sub {
            None => walk.dir(root.dir, "", 0)?,
            Some(sub) => walk.sub(root.dir, sub)?,
        }
    }
    for key in &scope.keys {
        walk_key(reg, key, key.path.clone(), &mut snap.entries)?;
    }
    Ok(snap)
}

/// `true` for the cloud files family (placeholders that may hydrate when read).
fn is_cloud(tag: u32) -> bool {
    tag & 0xFFFF_0FFF == super::fs::tag::CLOUD
}

/// The walk of one root.
struct Walk<'o> {
    root: usize,
    out: &'o mut BTreeMap<Loc, SnapEntry>,
}

impl Walk<'_> {
    fn insert(&mut self, path: String, entry: SnapEntry) {
        self.out.insert(
            Loc::Fs {
                root: self.root,
                path,
            },
            entry,
        );
    }

    /// The entry `sub` of [`SnapRoot::below`] and the tree below it.
    fn sub(&mut self, root: &dyn Dir, sub: &RelPath) -> SysResult<()> {
        let folded = fold(sub.as_str());
        let parent = sub.parent();
        let opened;
        let dir: &dyn Dir = match &parent {
            None => root,
            Some(p) => match root.metadata(p)? {
                Some(m) if m.kind == EntryKind::Dir && !m.restricted => {
                    opened = root.open_dir(p)?;
                    &*opened
                }
                // A file on the way: nothing below it exists.
                Some(m) if m.kind == EntryKind::File && !m.restricted => {
                    self.insert(folded, SnapEntry::Missing);
                    return Ok(());
                }
                // A reparse point or a restricted entry: never followed or opened.
                Some(m) => {
                    let kind = if m.restricted {
                        SysErrorKind::AccessDenied
                    } else {
                        SysErrorKind::ReparsePoint
                    };
                    return Err(SysError::new(kind, p.as_str()));
                }
                None => {
                    self.insert(folded, SnapEntry::Missing);
                    return Ok(());
                }
            },
        };
        let case_sensitive = dir.info()?.case_sensitive;
        let name = sub.file_name();
        let wanted = key_of(name, case_sensitive);
        let entries: Vec<DirEntry> = dir
            .read_dir(None)?
            .into_iter()
            .filter(|e| key_of(&e.name, case_sensitive) == wanted)
            .collect();
        if entries.is_empty() {
            self.insert(folded, SnapEntry::Missing);
            return Ok(());
        }
        let prefix = parent.map(|p| fold(p.as_str())).unwrap_or_default();
        self.entries(dir, &prefix, entries, case_sensitive, 0)
    }

    /// Lists `dir` (at `depth` below the root) and captures its entries.
    fn dir(&mut self, dir: &dyn Dir, prefix: &str, depth: usize) -> SysResult<()> {
        if depth > MAX_DEPTH {
            return Err(SysError::new(
                SysErrorKind::Other,
                format!("{prefix}: deeper than {MAX_DEPTH} directories"),
            ));
        }
        let case_sensitive = dir.info()?.case_sensitive;
        let entries = dir.read_dir(None)?;
        self.entries(dir, prefix, entries, case_sensitive, depth)
    }

    /// Captures `entries` of `dir`, whose path below the root is `prefix`.
    fn entries(
        &mut self,
        dir: &dyn Dir,
        prefix: &str,
        entries: Vec<DirEntry>,
        case_sensitive: bool,
        depth: usize,
    ) -> SysResult<()> {
        let join = |name: &str| {
            if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}\\{name}")
            }
        };
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for e in &entries {
            *seen.entry(key_of(&e.name, case_sensitive)).or_default() += 1;
        }
        for entry in entries {
            let key = key_of(&entry.name, case_sensitive);
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
                    join(&format!("\0{}", entry.name))
                } else {
                    join(&key)
                };
                self.insert(
                    loc,
                    SnapEntry::Anomaly {
                        name: entry.name,
                        kind: meta.kind,
                        len: meta.len,
                        attrs: meta.attrs,
                        restricted: meta.restricted,
                    },
                );
                continue;
            };
            let loc = join(&key);
            if meta.restricted {
                // Cannot be opened: metadata only, never hashed or descended into.
                self.insert(
                    loc,
                    SnapEntry::Restricted {
                        name: entry.name,
                        kind: meta.kind,
                        len: meta.len,
                        attrs: meta.attrs,
                        tag: meta.reparse.map(|r| r.tag),
                    },
                );
                continue;
            }
            match meta.kind {
                EntryKind::File => {
                    let tag = meta.reparse.map(|r| r.tag);
                    let sha256 = if tag.is_some_and(is_cloud) {
                        None
                    } else {
                        Some(hash_file(dir, &seg)?)
                    };
                    self.insert(
                        loc,
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
                    self.insert(
                        loc,
                        SnapEntry::Reparse {
                            name: entry.name,
                            tag,
                            target,
                        },
                    );
                }
                EntryKind::Dir => {
                    self.insert(
                        loc.clone(),
                        SnapEntry::Dir {
                            name: entry.name,
                            attrs: meta.attrs,
                        },
                    );
                    let sub = dir.open_dir(&seg)?;
                    self.dir(&*sub, &loc, depth + 1)?;
                }
            }
        }
        Ok(())
    }
}

/// The key of a name in its directory: folded, exact in a case-sensitive directory.
fn key_of(name: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        name.to_owned()
    } else {
        fold(name)
    }
}

fn hash_file(dir: &dyn Dir, p: &RelPath) -> SysResult<[u8; 32]> {
    let mut reader = dir.open_read(p)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| SysError::io(&e, p.as_str()))?;
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
    use std::io::{self, Read, Seek, SeekFrom};
    use std::path::PathBuf;

    use super::{Loc, SnapEntry, Walk, hash_file};
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
                volume_path: "G".to_owned(),
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
        fn read_dir_limited(&self, _: Option<&RelPath>, _: usize) -> SysResult<Vec<DirEntry>> {
            let meta = Metadata {
                kind: EntryKind::File,
                len: 1,
                attrs: Attrs::default(),
                links: Some(1),
                file_id: 2,
                reparse: None,
                restricted: false,
            };
            Ok(["data.bin", "DATA.BIN", "other.bin"]
                .into_iter()
                .map(|n| DirEntry {
                    name: n.to_owned(),
                    meta: meta.clone(),
                })
                .collect())
        }
        fn users(&self, _: &RelPath) -> SysResult<Vec<u32>> {
            no()
        }
    }

    #[test]
    fn colliding_names_become_anomalies_and_are_never_opened() {
        let mut out = std::collections::BTreeMap::new();
        Walk {
            root: 0,
            out: &mut out,
        }
        .dir(&Colliding, "", 0)
        .unwrap();
        assert_eq!(out.len(), 3, "{out:#?}");
        assert!(
            out.values()
                .any(|e| matches!(e, SnapEntry::File { name, .. } if name == "other.bin"))
        );
        let anomalies: Vec<&SnapEntry> = out
            .iter()
            .filter(|(loc, _)| matches!(loc, Loc::Fs { path, .. } if path.contains('\0')))
            .map(|(_, e)| e)
            .collect();
        assert_eq!(anomalies.len(), 2, "{out:#?}");
        assert!(
            anomalies
                .iter()
                .all(|e| matches!(e, SnapEntry::Anomaly { .. }))
        );
    }

    /// A directory whose only file fails to read like `ReadFile` on a locked range
    /// (`ERROR_LOCK_VIOLATION`, 33). Every other call fails.
    #[derive(Debug)]
    struct Locked;

    struct LockedReader;

    impl Read for LockedReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(33))
        }
    }

    impl Seek for LockedReader {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }

    impl Dir for Locked {
        fn info(&self) -> SysResult<RootInfo> {
            no()
        }
        fn open_dir(&self, _: &RelPath) -> SysResult<Box<dyn Dir + '_>> {
            no()
        }
        fn metadata(&self, _: &RelPath) -> SysResult<Option<Metadata>> {
            no()
        }
        fn open_read(&self, _: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>> {
            Ok(Box::new(LockedReader))
        }
        fn read_dir_limited(&self, _: Option<&RelPath>, _: usize) -> SysResult<Vec<DirEntry>> {
            no()
        }
        fn users(&self, _: &RelPath) -> SysResult<Vec<u32>> {
            no()
        }
    }

    #[test]
    fn a_failed_read_keeps_its_win32_code() {
        let p = RelPath::parse(r"Data\a.forge").unwrap();
        for e in [
            hash_file(&Locked, &p).unwrap_err(),
            Locked.read(&p).unwrap_err(),
        ] {
            assert_eq!(
                (e.kind, e.win32, e.target.as_str()),
                (SysErrorKind::Busy, Some(33), r"Data\a.forge")
            );
        }
    }
}
