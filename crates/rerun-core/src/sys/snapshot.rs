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
//! "Identical" means (ADR 0017, "What exact means"; ADR 0018 for the registry):
//! - a file: name and its case, length, content (SHA-256), read-only, hidden and system,
//!   link count; a directory: name and its case, read-only, hidden and system; a reparse
//!   point (never followed): name and its case, tag, link target, read-only, hidden and
//!   system;
//! - a restricted entry (its DACL denies the current user every open,
//!   [`Metadata::restricted`](super::fs::Metadata::restricted)), [`SnapEntry::Restricted`]:
//!   kind, length, read-only, hidden and system, reparse tag, from the listing (the link count
//!   is unknown and does not count); never opened, hashed or descended into;
//! - an anomaly, [`SnapEntry::Anomaly`]: a name that fails `policy::path::classify` (also
//!   U+FFFD for invalid UTF-16), every entry of a case-sensitive directory, and entries whose
//!   names fold to the same key: the raw name, kind, length, read-only, hidden and system and
//!   the restricted flag; never hashed, opened or descended into. Anomalies with the same raw
//!   name under one directory (two names that differ only in unpaired surrogates list alike)
//!   are kept as a multiset, none overwrites another;
//! - for the registry: keys (existing, empty or missing), key and value names and their case,
//!   value type and the exact bytes. A key or value name with U+FFFD (an unpaired surrogate
//!   converted by `sys`, user decision E1: the same rule as `classify` for file names) and
//!   names that fold to the same key are a [`SnapEntry::RegAnomaly`]: a key anomaly is never
//!   opened or descended into, a value anomaly keeps the value `values` returned (it is never
//!   addressed by its name). Anomalies with the same name under one key are a multiset. The
//!   walk is bounded: [`MAX_KEY_DEPTH`] levels of subkeys and [`MAX_KEYS_WALKED`] keys in
//!   all, beyond either `TooLarge` (the depth stops a cycle, the budget a fan-out). A name
//!   that cannot be a key path segment or value name at all (NUL; for a subkey also `\` or
//!   empty) is a `RegAnomaly` too and never opened, so one hostile name does not abort the
//!   snapshot. The name of a key of the scope itself comes from the caller, not from the
//!   registry: a change of its case is not seen (like the name of a root on the file side).
//!   A symbolic-link key (a key of the scope or a subkey, [`Registry::link`]) is a
//!   [`SnapEntry::RegLink`] with its raw target and is never entered, so a cycle ends there and
//!   a link replaced by a key with the same content is a difference (P2-9); the segments above
//!   a key of the scope are followed like every read.
//!
//! Shown in a diff but **not compared** (user decision E3): the allowlisted data tag of a
//! file (WOF, dedup, cloud, [`Shown`]). `wof.sys` hides the WOF tag anyway (ADR 0007), so it
//! cannot be pinned, and compressing or deduplicating a folder changes no content. A cloud
//! placeholder stays distinguishable: its content is not hashed (`sha256: None`), since
//! reading it could trigger a download (ADR 0007). The tag of a reparse point (a name
//! surrogate or an unknown tag) and of a restricted entry is compared.
//!
//! Not captured: timestamps and file IDs of entries (restored backups have a new mtime and a
//! new ID), DACL and owner, alternate data streams, 8.3 names, extended attributes,
//! compression and EFS state, `ARCHIVE` and every other attribute, and the attributes and the
//! name of a root itself (only its identity). **Delete-pending entries** (user decision E2)
//! are skipped like every listing of `sys` skips them (ADR 0017, A6): a name that another
//! program deleted while a handle of it is still open is on its way out and cannot be
//! opened, so a snapshot taken meanwhile is identical to one taken after it is gone.
//! Directories nested deeper than [`MAX_DEPTH`] below a root are `TooLarge`.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

use sha2::{Digest, Sha256};

use super::fs::{Attrs, Dir, DirEntry, EntryKind};
use super::registry::{RegKey, RegValue, Registry};
use super::{SysError, SysErrorKind, SysResult};
use crate::fold::fold;
use crate::path::{RelPath, classify};

/// Maximum directory depth below a root: a directory 64 levels below it (a direct child is
/// level 1) is walked, one at level 65 is `TooLarge` with this limit. The depth bounds a walk
/// that a cycle could make endless.
pub const MAX_DEPTH: usize = 64;

/// Maximum depth of subkeys below a key of the scope: a key 64 levels below it (a direct
/// subkey is level 1) is walked, one at level 65 is `TooLarge` with this limit.
pub const MAX_KEY_DEPTH: usize = 64;

/// Most registry keys one snapshot walks (the keys of the scope included); one more is
/// `TooLarge` with this limit. Symbolic-link keys are followed on reads (ADR 0009, ADR 0018
/// open point), so a cycle through one ends at [`MAX_KEY_DEPTH`] and a wide tree here.
pub const MAX_KEYS_WALKED: usize = 100_000;

/// A value that a diff shows and a comparison ignores: two `Shown` are always equal (user
/// decision E3, the data tag of a file).
#[derive(Debug, Clone, Copy, Default)]
pub struct Shown<T>(pub T);

impl<T> PartialEq for Shown<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<T> Eq for Shown<T> {}

/// One directory of a [`Scope`]: the handle of a root and what of it to capture.
#[derive(Debug, Clone)]
pub struct SnapRoot<'a> {
    dir: &'a dyn Dir,
    label: String,
    sub: Option<RelPath>,
}

impl<'a> SnapRoot<'a> {
    /// The whole tree below the root `dir`. `dir` is the read handle of a root that
    /// `policy::root` handed out (`GameDir::dir`, later `AppDir`); test code may pass any
    /// [`Dir`]. `label` is shown in a diff (e.g. the root's canonical path) and never
    /// compared. Public because the whole module is test code (`feature = "fake"`): a crate
    /// that enables it (CLI end-to-end tests, the sandbox runner) snapshots its roots too.
    pub fn new(dir: &'a dyn Dir, label: impl Into<String>) -> Self {
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
        /// Allowlisted data tag (WOF, dedup, cloud), if `sys` reports one. Shown, not
        /// compared ([`Shown`]).
        tag: Shown<Option<u32>>,
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
        /// Attributes.
        attrs: Attrs,
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
    /// Symbolic-link key (P2-9): recorded with its raw target, never entered.
    RegLink {
        /// Name.
        name: String,
        /// `SymbolicLinkValue` as stored (UTF-16).
        target: Vec<u16>,
    },
    /// Registry key or value whose name cannot be used to address it (see [`RegWhy`]).
    RegAnomaly {
        /// Key or value.
        kind: RegKind,
        /// The name as `sys` returned it.
        name: String,
        /// Why it is an anomaly.
        why: RegWhy,
        /// The value as `values` returned it (`None` for a key).
        value: Option<RegValue>,
    },
}

/// What a [`SnapEntry::RegAnomaly`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegKind {
    /// A subkey (never opened, never descended into).
    Key,
    /// A value.
    Value,
}

/// Why a registry name is a [`SnapEntry::RegAnomaly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegWhy {
    /// The name holds U+FFFD: `sys` converted an unpaired surrogate, so the name does not
    /// address the key or value on disk (user decision E1).
    Lossy,
    /// The name folds to the same key as another name of the same key.
    Collides,
    /// The name cannot address anything at all: it holds NUL (a subkey also `\`, or it is
    /// empty), which no key path or value name may hold.
    Invalid,
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
                if let Some(t) = tag.0 {
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
            Self::Reparse {
                name,
                tag,
                target,
                attrs,
            } => {
                write!(f, "reparse {name:?} tag {tag:#010x}")?;
                if let Some(t) = target {
                    write!(f, " → {t:?}")?;
                }
                write!(f, "{}", ShowAttrs(attrs))
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
            Self::RegLink { name, target } => write!(
                f,
                "link key {name:?} -> {:?}",
                String::from_utf16_lossy(target)
            ),
            Self::Value { name, value } => write!(f, "value {name:?} = {value}"),
            Self::RegAnomaly {
                kind,
                name,
                why,
                value,
            } => {
                let kind = match kind {
                    RegKind::Key => "key",
                    RegKind::Value => "value",
                };
                let why = match why {
                    RegWhy::Lossy => "lossy name",
                    RegWhy::Collides => "colliding name",
                    RegWhy::Invalid => "invalid name",
                };
                write!(f, "anomaly {kind} {name:?} ({why})")?;
                if let Some(v) = value {
                    write!(f, " = {v}")?;
                }
                Ok(())
            }
        }
    }
}

/// Entries per location: one, or a multiset of anomalies with the same raw name, sorted by
/// [`order_key`] so that equal multisets compare equal.
type Entries = BTreeMap<Loc, Vec<SnapEntry>>;

/// State of a [`Scope`] at a point in time. Two snapshots are equal if they captured the same
/// roots (identity and subtree, in the same order) and the same entries; the labels of the
/// roots are not compared.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    roots: Vec<RootIdent>,
    labels: Vec<String>,
    entries: Entries,
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
        self.entries.values().map(Vec::len).sum()
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
            Loc::Key(k) => k.replace('\0', "<raw>"),
            Loc::Value(k, v) => format!("{k} @ {:?}", v.replace('\0', "<raw>")),
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
        let none = Vec::new();
        let locs: std::collections::BTreeSet<&Loc> =
            self.entries.keys().chain(other.entries.keys()).collect();
        for loc in locs {
            let before = self.entries.get(loc).unwrap_or(&none);
            let after = other.entries.get(loc).unwrap_or(&none);
            if before == after {
                continue;
            }
            // Multiset differences: what only `before` has, what only `after` has.
            let gone = minus(before, after);
            let new = minus(after, before);
            let shown = if before.is_empty() {
                other.show(loc)
            } else {
                self.show(loc)
            };
            if let ([b], [a]) = (gone.as_slice(), new.as_slice()) {
                out.push(format!("~ {shown}: {b} → {a}"));
                continue;
            }
            out.extend(gone.iter().map(|b| format!("- {shown}: {b}")));
            out.extend(new.iter().map(|a| format!("+ {shown}: {a}")));
        }
        out
    }
}

/// The elements of the multiset `a` that `b` does not have (as often as `a` has them more).
fn minus<'e>(a: &'e [SnapEntry], b: &[SnapEntry]) -> Vec<&'e SnapEntry> {
    let mut left: Vec<&SnapEntry> = b.iter().collect();
    let mut out = Vec::new();
    for e in a {
        match left.iter().position(|x| *x == e) {
            Some(i) => {
                left.swap_remove(i);
            }
            None => out.push(e),
        }
    }
    out
}

/// Sort key of an entry inside the multiset of one location: every compared field. Only
/// anomalies share a location; other entries are ordered by their display text.
fn order_key(e: &SnapEntry) -> (String, Vec<u8>) {
    match e {
        SnapEntry::Anomaly {
            name,
            kind,
            len,
            attrs,
            restricted,
        } => {
            let mut k = vec![
                match kind {
                    EntryKind::File => 0,
                    EntryKind::Dir => 1,
                    EntryKind::Reparse => 2,
                },
                u8::from(attrs.readonly),
                u8::from(attrs.hidden),
                u8::from(attrs.system),
                u8::from(*restricted),
            ];
            k.extend(len.to_be_bytes());
            (name.clone(), k)
        }
        SnapEntry::RegAnomaly {
            kind,
            name,
            why,
            value,
        } => {
            let why = match why {
                RegWhy::Lossy => 0,
                RegWhy::Collides => 1,
                RegWhy::Invalid => 2,
            };
            let mut k = vec![u8::from(*kind == RegKind::Key), why];
            // `RegValue` has no order; its exact type and bytes do.
            if let Some((t, d)) = value.as_ref().and_then(RegValue::encode) {
                k.push(1);
                k.extend(t.to_be_bytes());
                k.extend(d);
            }
            (name.clone(), k)
        }
        other => (other.to_string(), Vec::new()),
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
    let mut walked = 0;
    for key in &scope.keys {
        let mut walk = KeyWalk {
            reg,
            walked: &mut walked,
            out: &mut snap.entries,
        };
        walk.key(key, key.path.clone(), 0)?;
    }
    for list in snap.entries.values_mut() {
        list.sort_by_cached_key(order_key);
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
    out: &'o mut Entries,
}

impl Walk<'_> {
    fn insert(&mut self, path: String, entry: SnapEntry) {
        let loc = Loc::Fs {
            root: self.root,
            path,
        };
        self.out.entry(loc).or_default().push(entry);
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
        // The listed directory lies one level above `sub`: depths count from the root, so
        // `below` keeps the limit of 64 levels below the root.
        let depth = sub.segments().count() - 1;
        self.entries(dir, &prefix, entries, case_sensitive, depth)
    }

    /// Lists `dir` (at `depth` below the root) and captures its entries.
    fn dir(&mut self, dir: &dyn Dir, prefix: &str, depth: usize) -> SysResult<()> {
        if depth > MAX_DEPTH {
            return Err(SysError::too_large(
                format!("{prefix}: directories nested deeper than the limit"),
                MAX_DEPTH as u64,
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
                // Always under the raw name after NUL, which no name on disk holds: raw keys
                // never clash with folded ones.
                let loc = join(&format!("\0{}", entry.name));
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
                            tag: Shown(tag),
                            attrs: meta.attrs,
                            links: meta.links,
                        },
                    );
                }
                EntryKind::Reparse => {
                    // `sys` always reports the tag of a reparse point it could open; without
                    // it the entry would be recorded as tag 0 and a changed tag go unseen.
                    let Some(reparse) = meta.reparse else {
                        return Err(SysError::new(
                            SysErrorKind::Other,
                            format!("{loc}: reparse point without reparse data"),
                        ));
                    };
                    self.insert(
                        loc,
                        SnapEntry::Reparse {
                            name: entry.name,
                            tag: reparse.tag,
                            target: reparse.target,
                            attrs: meta.attrs,
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

/// The registry walk of one snapshot, with its key budget.
struct KeyWalk<'w> {
    reg: &'w dyn Registry,
    walked: &'w mut usize,
    out: &'w mut Entries,
}

/// The folded names of one enumeration, to tell which names cannot address what they name.
struct NameCounts(BTreeMap<String, usize>);

impl NameCounts {
    fn of<'n>(names: impl Iterator<Item = &'n str>) -> Self {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for n in names {
            *seen.entry(fold(n)).or_default() += 1;
        }
        Self(seen)
    }

    /// A name no key path or value name may hold first (NUL; for a subkey, `subkey`, also `\`
    /// or empty), then U+FFFD (lossy), then a name that folds to the same key as another one.
    /// `Some(why)` for an anomaly.
    fn why(&self, n: &str, subkey: bool) -> Option<RegWhy> {
        if n.contains('\0') || (subkey && (n.is_empty() || n.contains('\\'))) {
            Some(RegWhy::Invalid)
        } else if n.contains('\u{FFFD}') {
            Some(RegWhy::Lossy)
        } else if self.0.get(&fold(n)).is_some_and(|&c| c > 1) {
            Some(RegWhy::Collides)
        } else {
            None
        }
    }
}

impl KeyWalk<'_> {
    fn push(&mut self, loc: Loc, entry: SnapEntry) {
        self.out.entry(loc).or_default().push(entry);
    }

    /// The key `key` (named `name`, `depth` levels below a key of the scope) and everything
    /// below it.
    fn key(&mut self, key: &RegKey, name: String, depth: usize) -> SysResult<()> {
        if depth > MAX_KEY_DEPTH {
            return Err(SysError::too_large(
                format!("{key}: subkeys nested deeper than the limit"),
                MAX_KEY_DEPTH as u64,
            ));
        }
        let loc = key_loc(key);
        // The key itself is opened without following a link: a link is an entry of its own
        // and never entered, so a cycle ends here and a link replaced by a key with the same
        // content is a difference (P2-9).
        match self.reg.link(key) {
            Err(e) if e.kind == SysErrorKind::NotFound => {
                self.push(Loc::Key(loc), SnapEntry::Missing);
                return Ok(());
            }
            Err(e) => return Err(e),
            Ok(Some(link)) => {
                self.push(
                    Loc::Key(loc),
                    SnapEntry::RegLink {
                        name,
                        target: link.target,
                    },
                );
                return Ok(());
            }
            Ok(None) => {}
        }
        *self.walked += 1;
        if *self.walked > MAX_KEYS_WALKED {
            return Err(SysError::too_large(
                format!("{key}: more registry keys than the limit"),
                MAX_KEYS_WALKED as u64,
            ));
        }
        self.push(Loc::Key(loc.clone()), SnapEntry::Key { name });
        let values = self.reg.values(key)?;
        let counts = NameCounts::of(values.iter().map(|(n, _)| n.as_str()));
        for (value_name, value) in values {
            match counts.why(&value_name, false) {
                Some(why) => self.push(
                    Loc::Value(loc.clone(), format!("\0{value_name}")),
                    SnapEntry::RegAnomaly {
                        kind: RegKind::Value,
                        name: value_name,
                        why,
                        value: Some(value),
                    },
                ),
                None => self.push(
                    Loc::Value(loc.clone(), fold(&value_name)),
                    SnapEntry::Value {
                        name: value_name,
                        value,
                    },
                ),
            }
        }
        let subkeys = self.reg.subkeys(key)?;
        let counts = NameCounts::of(subkeys.iter().map(String::as_str));
        for sub in subkeys {
            match counts.why(&sub, true) {
                // Never opened: the name would address another key, or none.
                Some(why) => self.push(
                    Loc::Key(format!("{loc}\\\0{sub}")),
                    SnapEntry::RegAnomaly {
                        kind: RegKind::Key,
                        name: sub,
                        why,
                        value: None,
                    },
                ),
                None => self.key(&key.join(&sub), sub, depth + 1)?,
            }
        }
        Ok(())
    }
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
                .flatten()
                .any(|e| matches!(e, SnapEntry::File { name, .. } if name == "other.bin"))
        );
        let anomalies: Vec<&SnapEntry> = out
            .iter()
            .filter(|(loc, _)| matches!(loc, Loc::Fs { path, .. } if path.contains('\0')))
            .flat_map(|(_, e)| e)
            .collect();
        assert_eq!(anomalies.len(), 2, "{out:#?}");
        assert!(
            anomalies
                .iter()
                .all(|e| matches!(e, SnapEntry::Anomaly { .. }))
        );
    }

    /// A directory that lists a reparse point without its reparse data (a broken `sys`).
    #[derive(Debug)]
    struct NoTag;

    impl Dir for NoTag {
        fn info(&self) -> SysResult<RootInfo> {
            Colliding.info()
        }
        fn open_dir(&self, _: &RelPath) -> SysResult<Box<dyn Dir + '_>> {
            no()
        }
        fn metadata(&self, _: &RelPath) -> SysResult<Option<Metadata>> {
            no()
        }
        fn open_read(&self, _: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>> {
            no()
        }
        fn read_dir_limited(&self, _: Option<&RelPath>, _: usize) -> SysResult<Vec<DirEntry>> {
            Ok(vec![DirEntry {
                name: "Saves".to_owned(),
                meta: Metadata {
                    kind: EntryKind::Reparse,
                    len: 0,
                    attrs: Attrs::default(),
                    links: Some(1),
                    file_id: 3,
                    reparse: None,
                    restricted: false,
                },
            }])
        }
        fn users(&self, _: &RelPath) -> SysResult<Vec<u32>> {
            no()
        }
    }

    /// Never a silent tag 0: a changed tag would go unseen.
    #[test]
    fn a_reparse_point_without_reparse_data_is_an_error() {
        let mut out = std::collections::BTreeMap::new();
        let e = Walk {
            root: 0,
            out: &mut out,
        }
        .dir(&NoTag, "", 0)
        .unwrap_err();
        assert_eq!(e.kind, SysErrorKind::Other, "{e}");
        assert!(e.target.contains("SAVES"), "{e}");
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
