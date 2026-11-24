//! Rerun's package store, read and remove (P5-8b, ADR 0025 amendment P5-8b): the version
//! folders `<AppDir>\packages\<id>\<version>` and the archives `<AppDir>\cache\<sha256>`.
//!
//! This module knows no journal: whether a package is still used by a transaction is the rule of
//! `exec::remove_packages`, which holds `journal\lock` before it calls [`remove`].
//!
//! - **[`list`] reads only** (no lock, nothing created): a missing `AppDir` sub folder lists
//!   nothing. Every folder is listed with a bound ([`MAX_ENTRIES`] names, as the sweeps of the
//!   download and the extraction), iteratively and at most [`MAX_DEPTH`] levels below a version
//!   folder, and the whole store with one budget ([`MAX_VERSIONS`] version folders,
//!   [`MAX_STORE_ENTRIES`] names read; the rest is foreign, `TooMany`); a walk stops at the first
//!   reason to keep its package whole. Nothing is hashed, only metadata is read.
//! - **What is Rerun's** (user decision E1 a): every plain file and plain folder below a valid
//!   `<id>\<version>` (an ID of the index's form, a version of its form). A version folder that
//!   holds a reparse point (also a link itself), a file with more than one link, an entry with the
//!   read-only, hidden or system attribute or one the user cannot open, a name that is not a valid
//!   path segment, or too many entries stays whole, with the reason ([`StoreKeep`]). Entries of
//!   `packages` and `cache` that are not of Rerun's form (another name, a link, a folder in the
//!   cache) are listed as foreign and never touched; so are `packages\.lock`, `cache\lock` and the
//!   two folders themselves.
//! - **[`remove`] removes exactly what was shown.** Under `packages\.lock` and `cache\lock`
//!   (taken here, in this order, never waiting: `Busy`) it lists again from the very handles it
//!   deletes through and compares with what was shown before the first deletion: an entry with
//!   another file ID or length, a new entry in a shown folder, a shown package that now stays, or
//!   an entry that is there but no longer of Rerun's form is [`StoreError::Changed`] and nothing is
//!   deleted. What is gone already counts as done. Then each entry is deleted by the file ID of
//!   that listing (`DirWrite::remove_file`, `DirWrite::remove_dir`), never by a hash, so no
//!   large file is read: files deepest first, then folders deepest first, the version folder, its
//!   `<id>` folder if it is empty then, then the archives and leftovers. A deletion that fails (a
//!   file a scanner holds: `Busy`; a swapped entry: `Changed` or `Reparse`) stops only that
//!   package, and its archives stay with it; the rest goes on (best effort). The two folders are
//!   flushed at the end (best effort). The only thing a removal may create is a missing lock file
//!   (`lock` creates it), also when it ends with `Changed`.
//!
//! Nothing here is journaled (ADR 0025 part 2): the planner and `exec` hash every package file
//! again before they use it, so a package removed half way is only incomplete (the planner refuses
//! it and names `package fetch`, which completes it), never used.

use crate::catalog::check::version as version_form;
use crate::catalog::model::Id;
use crate::path::RelPath;
use crate::policy::root::{AppDir, AppSub, Create, RootError};
use crate::sys::fs::{EntryKind, Metadata, TmpName};
use crate::sys::{Dir, DirWrite, SysError, SysErrorKind, System};

/// Most names listed in one folder of the store, and most entries of one version folder.
pub const MAX_ENTRIES: usize = 4096;
/// Most folder levels below a version folder.
pub const MAX_DEPTH: usize = 16;
/// Most version folders of the whole store; the rest is listed as one foreign entry
/// ([`StoreKeep::TooMany`]).
pub const MAX_VERSIONS: usize = 4096;
/// Most names one listing of the store reads in all (every folder of `packages` and `cache`
/// together); past it the rest is one foreign entry ([`StoreKeep::TooMany`]), so a store
/// planted full of names costs a bounded amount of work.
pub const MAX_STORE_ENTRIES: usize = 65_536;

/// The lock file of `packages` (`pkg::extract`).
const PACKAGES_LOCK: &str = super::extract::LOCK;
/// The lock file of `cache` (`pkg::download`).
const CACHE_LOCK: &str = super::download::LOCK;

/// Why an entry of the store stays (it is never deleted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreKeep {
    /// A reparse point (a junction, a symbolic link or another tag): neither the link nor its
    /// target is touched.
    Reparse,
    /// A file with more than one hard link (or an unknown link count).
    Linked,
    /// The read-only, hidden or system attribute, or an entry the user cannot open.
    Attributes,
    /// More than [`MAX_ENTRIES`] entries, deeper than [`MAX_DEPTH`], or past the bounds of the
    /// whole store ([`MAX_VERSIONS`], [`MAX_STORE_ENTRIES`]).
    TooMany,
    /// A name that is not of Rerun's form there.
    BadName,
    /// In use (another program holds it without share-delete); try again later.
    Busy,
    /// It changed while it was removed (another file ID, a new entry): show the store again.
    Changed,
    /// The file system does not allow the removal (a volume without POSIX delete, FAT/exFAT).
    Unsupported,
}

/// A sub folder of `AppDir` that holds the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreSub {
    /// `packages`.
    Packages,
    /// `cache`.
    Cache,
}

/// A file or folder below a version folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Item {
    /// Its path below the version folder.
    pub(crate) rel: RelPath,
    /// Its file ID.
    pub(crate) file_id: u128,
    /// Its length (0 for a folder).
    pub(crate) len: u64,
    /// A folder.
    pub(crate) dir: bool,
}

/// One version folder `packages\<id>\<version>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionDir {
    /// The package ID (the folder's name as listed).
    pub(crate) id: String,
    /// The version (the folder's name as listed).
    pub(crate) version: String,
    /// The file ID of `<id>`.
    pub(crate) id_dir: u128,
    /// The file ID of `<version>`.
    pub(crate) dir: u128,
    /// Every plain entry below it (an entry that makes it stay is not followed or listed; the
    /// walk stops at too many).
    pub(crate) items: Vec<Item>,
    /// Why it stays whole (`None`: it is Rerun's and may be removed).
    pub(crate) keep: Option<StoreKeep>,
}

impl VersionDir {
    /// Its files (not counting folders).
    pub(crate) fn files(&self) -> u32 {
        u32::try_from(self.items.iter().filter(|i| !i.dir).count()).unwrap_or(u32::MAX)
    }

    /// The length of its files.
    pub(crate) fn bytes(&self) -> u64 {
        self.items
            .iter()
            .map(|i| i.len)
            .fold(0, u64::saturating_add)
    }

    /// Whether it holds the file `rel` (a path below the version folder; names only).
    pub(crate) fn has_file(&self, rel: &RelPath) -> bool {
        self.items.iter().any(|i| !i.dir && i.rel == *rel)
    }
}

/// One entry of `cache`: an archive by its SHA-256, or a temp file a download left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CacheEntry {
    /// Its name: 64 hex digits, or a Rerun temp name.
    pub(crate) name: String,
    /// Its file ID.
    pub(crate) file_id: u128,
    /// Its length.
    pub(crate) len: u64,
    /// A Rerun temp name (a download that did not finish).
    pub(crate) temp: bool,
}

/// An `<id>` folder without any entry (a removal stopped between its version folder and it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmptyId {
    /// The ID.
    pub(crate) id: String,
    /// Its file ID.
    pub(crate) file_id: u128,
}

/// An entry of the store that is not Rerun's, or cannot be read: never touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Foreign {
    /// Which folder.
    pub(crate) sub: StoreSub,
    /// Its path below that folder (`""`: the folder itself), escaped for display.
    pub(crate) name: String,
    /// Why it stays.
    pub(crate) keep: StoreKeep,
}

/// What the store holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Listing {
    /// The version folders.
    pub(crate) packages: Vec<VersionDir>,
    /// The archives and temp files of `cache`.
    pub(crate) cache: Vec<CacheEntry>,
    /// Empty `<id>` folders.
    pub(crate) empty_ids: Vec<EmptyId>,
    /// Everything else.
    pub(crate) foreign: Vec<Foreign>,
}

/// One entry a preview showed for removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Shown {
    /// A version folder with everything below it.
    Package(VersionDir),
    /// An archive or a temp file of `cache`, with the packages (ID, version) it belongs to
    /// (empty for an archive without a package and a temp file): `exec::remove_packages` checks
    /// them against the users like a version folder, and it stays when one of them stopped.
    Archive {
        /// The entry.
        entry: CacheEntry,
        /// The packages it belongs to.
        owners: Vec<(String, String)>,
    },
    /// An empty `<id>` folder.
    EmptyId(EmptyId),
}

/// What [`remove`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Removed {
    /// The packages removed (ID, version): a version folder removed, or a package that was only
    /// its archive. A front end takes the counts of what goes from the preview.
    pub packages: Vec<(String, String)>,
    /// The archives removed.
    pub archives: usize,
    /// Leftovers removed: temp files of the cache, empty `<id>` folders.
    pub leftovers: usize,
    /// The bytes freed.
    pub bytes: u64,
    /// Shown entries that were gone already (done).
    pub gone: usize,
    /// Shown entries that stopped, with the reason (`<id>@<version>` or the cache name); they
    /// show again in the next listing.
    pub stopped: Vec<(String, StoreKeep)>,
}

/// Why the store could not be listed or nothing was removed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The process is elevated (or its elevation is unknown).
    #[error(
        "packages are removed only as a standard user (Rerun runs as administrator, or that \
         cannot be determined)"
    )]
    Elevated,
    /// The store is not what was shown; nothing was removed.
    #[error("Rerun's packages folder changed since it was shown; nothing was removed")]
    Changed,
    /// A lock of the store is held: another Rerun downloads or unpacks a package.
    #[error("another Rerun is downloading or unpacking a package; try again when it has finished")]
    Busy,
    /// Rerun's folder, `packages` or `cache`.
    #[error(transparent)]
    Root(Box<RootError>),
    /// The file system.
    #[error(transparent)]
    Sys(SysError),
}

impl From<RootError> for StoreError {
    fn from(e: RootError) -> Self {
        Self::Root(Box::new(e))
    }
}

/// A fixed valid segment.
fn seg(s: &str) -> RelPath {
    match RelPath::from_segment(s) {
        Ok(p) => p,
        Err(e) => unreachable!("{s} is a fixed valid segment: {e}"),
    }
}

/// Why an entry as listed is not a plain entry of Rerun's (`None`: it is).
fn entry_keep(m: &Metadata) -> Option<StoreKeep> {
    if m.kind == EntryKind::Reparse {
        return Some(StoreKeep::Reparse);
    }
    if m.restricted || m.attrs.readonly || m.attrs.hidden || m.attrs.system {
        return Some(StoreKeep::Attributes);
    }
    if m.kind == EntryKind::File && !m.is_single_link() {
        return Some(StoreKeep::Linked);
    }
    None
}

/// The reason of a failed listing or deletion.
fn keep_of(e: &SysError) -> StoreKeep {
    match e.kind {
        SysErrorKind::ReparsePoint => StoreKeep::Reparse,
        SysErrorKind::Linked => StoreKeep::Linked,
        SysErrorKind::AccessDenied => StoreKeep::Attributes,
        SysErrorKind::InvalidPath => StoreKeep::BadName,
        SysErrorKind::TooLarge => StoreKeep::TooMany,
        // Another file ID, or a new entry in a folder: it is not what was listed.
        SysErrorKind::Mismatch | SysErrorKind::NotEmpty => StoreKeep::Changed,
        // Permanent: the volume cannot do it (FAT, exFAT, a case-sensitive folder).
        SysErrorKind::Unsupported => StoreKeep::Unsupported,
        _ => StoreKeep::Busy,
    }
}

/// 64 hex digits: the name of an archive (`download::cache_name`; any case, as the file system
/// folds it).
fn is_archive_name(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn foreign(out: &mut Listing, sub: StoreSub, name: &str, keep: StoreKeep) {
    out.foreign.push(Foreign {
        sub,
        name: crate::escape::path(name).to_string(),
        keep,
    });
}

/// What one listing of the store may still read (security review S1): names in all, version
/// folders in all.
struct Budget {
    entries: usize,
    versions: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            entries: MAX_STORE_ENTRIES,
            versions: MAX_VERSIONS,
        }
    }

    /// Takes `n` names; `false` (and nothing taken) when they do not fit any more.
    fn take(&mut self, n: usize) -> bool {
        match self.entries.checked_sub(n) {
            Some(rest) => {
                self.entries = rest;
                true
            }
            None => {
                self.entries = 0;
                false
            }
        }
    }
}

/// The entries below the version folder `vrel` of `packages`, iteratively. Stops at the first
/// reason to keep it whole (the package stays; nothing below is needed) and when the budget of
/// the store is spent.
fn walk(packages: &dyn Dir, vrel: &RelPath, v: &mut VersionDir, budget: &mut Budget) {
    let mut stack: Vec<(Option<RelPath>, usize)> = vec![(None, 0)];
    while let Some((sub, depth)) = stack.pop() {
        let at = match &sub {
            None => Ok(vrel.clone()),
            Some(s) => RelPath::parse(&format!("{}\\{}", vrel.as_str(), s.as_str())),
        };
        let Ok(at) = at else {
            v.keep = Some(StoreKeep::BadName);
            return;
        };
        let entries = match packages.read_dir_limited(Some(&at), MAX_ENTRIES) {
            Ok(e) => e,
            // Gone since its parent was listed: nothing to keep or remove.
            Err(e) if e.kind == SysErrorKind::NotFound => continue,
            Err(e) => {
                v.keep = Some(keep_of(&e));
                return;
            }
        };
        if !budget.take(entries.len()) {
            v.keep = Some(StoreKeep::TooMany);
            return;
        }
        for e in entries {
            let rel = match &sub {
                None => RelPath::from_segment(&e.name),
                Some(s) => s.child(&e.name),
            };
            let Ok(rel) = rel else {
                v.keep = Some(StoreKeep::BadName);
                return;
            };
            if let Some(k) = entry_keep(&e.meta) {
                v.keep = Some(k);
                return;
            }
            let dir = e.meta.kind == EntryKind::Dir;
            v.items.push(Item {
                rel: rel.clone(),
                file_id: e.meta.file_id,
                len: if dir { 0 } else { e.meta.len },
                dir,
            });
            if v.items.len() > MAX_ENTRIES {
                v.keep = Some(StoreKeep::TooMany);
                return;
            }
            if dir {
                if depth + 1 > MAX_DEPTH {
                    v.keep = Some(StoreKeep::TooMany);
                    return;
                }
                stack.push((Some(rel), depth + 1));
            }
        }
    }
}

/// The `<id>\<version>` folders of `packages`.
fn list_packages(packages: &dyn Dir, out: &mut Listing, budget: &mut Budget) {
    let sub = StoreSub::Packages;
    let entries = match packages.read_dir_limited(None, MAX_ENTRIES) {
        Ok(e) => e,
        Err(e) => return foreign(out, sub, "", keep_of(&e)),
    };
    if !budget.take(entries.len()) {
        return foreign(out, sub, "", StoreKeep::TooMany);
    }
    for e in entries {
        if e.name.eq_ignore_ascii_case(PACKAGES_LOCK) {
            continue;
        }
        let id_rel = match (Id::parse(&e.name), RelPath::from_segment(&e.name)) {
            (Some(_), Ok(r)) => r,
            _ => {
                foreign(out, sub, &e.name, StoreKeep::BadName);
                continue;
            }
        };
        if let Some(k) = entry_keep(&e.meta) {
            foreign(out, sub, &e.name, k);
            continue;
        }
        if e.meta.kind != EntryKind::Dir {
            foreign(out, sub, &e.name, StoreKeep::BadName);
            continue;
        }
        if budget.versions == 0 {
            foreign(out, sub, &e.name, StoreKeep::TooMany);
            continue;
        }
        let versions = match packages.read_dir_limited(Some(&id_rel), MAX_ENTRIES) {
            Ok(v) => v,
            Err(x) if x.kind == SysErrorKind::NotFound => continue,
            Err(x) => {
                foreign(out, sub, &e.name, keep_of(&x));
                continue;
            }
        };
        if !budget.take(versions.len()) {
            foreign(out, sub, &e.name, StoreKeep::TooMany);
            continue;
        }
        if versions.is_empty() {
            out.empty_ids.push(EmptyId {
                id: e.name.clone(),
                file_id: e.meta.file_id,
            });
            continue;
        }
        for v in versions {
            let shown = format!("{}\\{}", e.name, v.name);
            let vrel = match id_rel.child(&v.name) {
                Ok(r) if version_form(&v.name) => r,
                _ => {
                    foreign(out, sub, &shown, StoreKeep::BadName);
                    continue;
                }
            };
            if let Some(k) = entry_keep(&v.meta) {
                foreign(out, sub, &shown, k);
                continue;
            }
            if v.meta.kind != EntryKind::Dir {
                foreign(out, sub, &shown, StoreKeep::BadName);
                continue;
            }
            if budget.versions == 0 {
                foreign(out, sub, &shown, StoreKeep::TooMany);
                continue;
            }
            budget.versions -= 1;
            let mut dir = VersionDir {
                id: e.name.clone(),
                version: v.name.clone(),
                id_dir: e.meta.file_id,
                dir: v.meta.file_id,
                items: Vec::new(),
                keep: None,
            };
            walk(packages, &vrel, &mut dir, budget);
            out.packages.push(dir);
        }
    }
}

/// The archives and temp files of `cache`.
fn list_cache(cache: &dyn Dir, out: &mut Listing, budget: &mut Budget) {
    let sub = StoreSub::Cache;
    let entries = match cache.read_dir_limited(None, MAX_ENTRIES) {
        Ok(e) => e,
        Err(e) => return foreign(out, sub, "", keep_of(&e)),
    };
    if !budget.take(entries.len()) {
        return foreign(out, sub, "", StoreKeep::TooMany);
    }
    for e in entries {
        if e.name.eq_ignore_ascii_case(CACHE_LOCK) {
            continue;
        }
        let temp = TmpName::parse(&e.name).is_some();
        if !temp && !is_archive_name(&e.name) {
            foreign(out, sub, &e.name, StoreKeep::BadName);
            continue;
        }
        if let Some(k) = entry_keep(&e.meta) {
            foreign(out, sub, &e.name, k);
            continue;
        }
        if e.meta.kind != EntryKind::File {
            foreign(out, sub, &e.name, StoreKeep::BadName);
            continue;
        }
        out.cache.push(CacheEntry {
            name: e.name,
            file_id: e.meta.file_id,
            len: e.meta.len,
            temp,
        });
    }
}

/// The listing of the two folders as these handles see them, within one [`Budget`].
fn listing(packages: Option<&dyn Dir>, cache: Option<&dyn Dir>) -> Listing {
    let mut out = Listing::default();
    let mut budget = Budget::new();
    // The cache first: a full `packages` never hides an archive or a leftover.
    if let Some(c) = cache {
        list_cache(c, &mut out, &mut budget);
    }
    if let Some(p) = packages {
        list_packages(p, &mut out, &mut budget);
    }
    out
}

/// The folder `s` read side; a reparse point there is listed as foreign.
fn read_side<'a>(
    app: &'a AppDir<'_>,
    s: AppSub,
    sub: StoreSub,
    out: &mut Listing,
) -> Result<Option<Box<dyn Dir + 'a>>, StoreError> {
    match app.sub(s) {
        Ok(d) => Ok(d),
        Err(RootError::Reparse { .. }) => {
            foreign(out, sub, "", StoreKeep::Reparse);
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Lists the store (module docs). Reads only, takes no lock and creates nothing: no `AppDir` sub
/// folder lists nothing; a link as `packages` or `cache` is foreign (never followed).
///
/// # Errors
/// A folder that cannot be opened (other than a link).
pub(crate) fn list(app: &AppDir<'_>) -> Result<Listing, StoreError> {
    let mut links = Listing::default();
    let packages = read_side(app, AppSub::Packages, StoreSub::Packages, &mut links)?;
    let cache = read_side(app, AppSub::Cache, StoreSub::Cache, &mut links)?;
    let mut out = listing(packages.as_deref(), cache.as_deref());
    out.foreign.extend(links.foreign);
    Ok(out)
}

/// The folder `s` with the write capability, never created; a link there is `Changed` (the
/// preview listed it as foreign, so nothing shown can be below it).
fn write_side<'a>(
    app: &'a AppDir<'_>,
    s: AppSub,
) -> Result<Option<Box<dyn DirWrite + 'a>>, StoreError> {
    match app.sub_write(s, Create::Never) {
        Ok(d) => Ok(d),
        Err(RootError::Reparse { .. }) => Err(StoreError::Changed),
        Err(e) => Err(e.into()),
    }
}

fn lock_error(e: SysError) -> StoreError {
    if e.kind == SysErrorKind::Busy {
        StoreError::Busy
    } else {
        StoreError::Sys(e)
    }
}

/// Whether `rel` exists in `dir` (a doubt counts as there).
fn present(dir: Option<&dyn Dir>, rel: &str) -> bool {
    let (Some(dir), Ok(rel)) = (dir, RelPath::parse(rel)) else {
        return false;
    };
    !matches!(dir.metadata(&rel), Ok(None))
}

/// The version folder of `now` that is `v`.
fn find<'l>(now: &'l Listing, id: &str, version: &str) -> Option<&'l VersionDir> {
    now.packages
        .iter()
        .find(|n| n.id.eq_ignore_ascii_case(id) && n.version.eq_ignore_ascii_case(version))
}

/// Compares what was shown with `now` (module docs): `Ok(gone)` with the number of shown
/// entries that are gone, `Err(Changed)` if anything else differs.
fn compare(
    shown: &[Shown],
    now: &Listing,
    packages: Option<&dyn Dir>,
    cache: Option<&dyn Dir>,
) -> Result<usize, StoreError> {
    let mut gone = 0;
    for s in shown {
        let same = match s {
            Shown::Package(v) => match find(now, &v.id, &v.version) {
                None if present(packages, &format!("{}\\{}", v.id, v.version)) => false,
                None => {
                    gone += 1;
                    true
                }
                Some(n) => {
                    n.keep.is_none()
                        && n.id_dir == v.id_dir
                        && n.dir == v.dir
                        && n.items.iter().all(|i| v.items.contains(i))
                }
            },
            Shown::Archive { entry: c, .. } => match now
                .cache
                .iter()
                .find(|n| n.name.eq_ignore_ascii_case(&c.name))
            {
                None if present(cache, &c.name) => false,
                None => {
                    gone += 1;
                    true
                }
                Some(n) => n == c,
            },
            Shown::EmptyId(e) => match now
                .empty_ids
                .iter()
                .find(|n| n.id.eq_ignore_ascii_case(&e.id))
            {
                None if present(packages, &e.id) => false,
                None => {
                    gone += 1;
                    true
                }
                Some(n) => n.file_id == e.file_id,
            },
        };
        if !same {
            return Err(StoreError::Changed);
        }
    }
    Ok(gone)
}

/// The handle of the folder that holds `rel` below `base` (`None`: `base` itself) and the
/// name of `rel` in it.
fn parent_of<'d>(
    base: &'d dyn DirWrite,
    rel: &RelPath,
) -> Result<(Option<Box<dyn DirWrite + 'd>>, RelPath), SysError> {
    let name = RelPath::from_segment(rel.file_name())
        .map_err(|_| SysError::new(SysErrorKind::InvalidPath, rel.as_str()))?;
    let parent = rel.parent().map(|p| base.open_dir_write(&p)).transpose()?;
    Ok((parent, name))
}

/// `Ok` also for an entry that is gone already.
fn gone_ok(r: Result<(), SysError>) -> Result<(), SysError> {
    match r {
        Err(e) if e.kind == SysErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// Deletes the version folder `v` (as listed now) by file IDs, in the fixed order; the `<id>`
/// folder too if it is empty then. Adds the length of every file it deleted to `bytes`.
fn delete_package(
    packages: &dyn DirWrite,
    v: &VersionDir,
    bytes: &mut u64,
) -> Result<(), SysError> {
    let id = RelPath::from_segment(&v.id)
        .map_err(|_| SysError::new(SysErrorKind::InvalidPath, "package ID"))?;
    let vrel = id
        .child(&v.version)
        .map_err(|_| SysError::new(SysErrorKind::InvalidPath, "package version"))?;
    let depth = |i: &&Item| i.rel.segments().count();
    let mut files: Vec<&Item> = v.items.iter().filter(|i| !i.dir).collect();
    files.sort_by_key(|i| std::cmp::Reverse(depth(i)));
    let mut dirs: Vec<&Item> = v.items.iter().filter(|i| i.dir).collect();
    dirs.sort_by_key(|i| std::cmp::Reverse(depth(i)));
    {
        let version = packages.open_dir_write(&vrel)?;
        for f in files {
            let (parent, name) = parent_of(&*version, &f.rel)?;
            let dir: &dyn DirWrite = parent.as_deref().unwrap_or(&*version);
            match dir.remove_file(&name, f.file_id) {
                Ok(()) => *bytes = bytes.saturating_add(f.len),
                Err(e) if e.kind == SysErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        for d in dirs {
            let (parent, name) = parent_of(&*version, &d.rel)?;
            let dir: &dyn DirWrite = parent.as_deref().unwrap_or(&*version);
            gone_ok(dir.remove_dir(&name, d.file_id))?;
        }
    }
    {
        let id_dir = packages.open_dir_write(&id)?;
        gone_ok(id_dir.remove_dir(&seg_of(&v.version)?, v.dir))?;
        // Another version (or anything else) is left: the `<id>` folder stays.
        if !id_dir.read_dir_limited(None, 1).is_ok_and(|e| e.is_empty()) {
            return Ok(());
        }
    }
    match packages.remove_dir(&id, v.id_dir) {
        // Another version or something new came meanwhile: the folder stays.
        Err(e) if matches!(e.kind, SysErrorKind::NotEmpty | SysErrorKind::NotFound) => Ok(()),
        r => r,
    }
}

fn seg_of(s: &str) -> Result<RelPath, SysError> {
    RelPath::from_segment(s).map_err(|_| SysError::new(SysErrorKind::InvalidPath, "a store name"))
}

/// Removes exactly what `shown` holds (module docs). Standard user only; takes
/// `packages\.lock`, then `cache\lock` (each only where its folder exists), lists again and
/// compares before the first deletion. The caller holds `journal\lock` and has checked that no
/// shown package is used (`exec::remove_packages`).
///
/// # Errors
/// [`StoreError`]: nothing was deleted (a failure of one deletion is in
/// [`Removed::stopped`]).
pub(crate) fn remove(
    sys: &dyn System,
    app: &AppDir<'_>,
    shown: &[Shown],
) -> Result<Removed, StoreError> {
    crate::exec::standard_user(sys).map_err(|_| StoreError::Elevated)?;
    let packages = write_side(app, AppSub::Packages)?;
    let cache = write_side(app, AppSub::Cache)?;
    let _plock = packages
        .as_deref()
        .map(|d| d.lock(&seg(PACKAGES_LOCK)))
        .transpose()
        .map_err(lock_error)?;
    let _clock = cache
        .as_deref()
        .map(|d| d.lock(&seg(CACHE_LOCK)))
        .transpose()
        .map_err(lock_error)?;
    let p_read: Option<&dyn Dir> = packages.as_deref().map(|d| d as &dyn Dir);
    let c_read: Option<&dyn Dir> = cache.as_deref().map(|d| d as &dyn Dir);
    let now = listing(p_read, c_read);
    let mut out = Removed {
        gone: compare(shown, &now, p_read, c_read)?,
        ..Removed::default()
    };
    for s in shown {
        let Shown::Package(v) = s else { continue };
        let (Some(p), Some(n)) = (packages.as_deref(), find(&now, &v.id, &v.version)) else {
            continue;
        };
        let mut bytes = 0;
        let r = delete_package(p, n, &mut bytes);
        out.bytes = out.bytes.saturating_add(bytes);
        match r {
            Ok(()) => out.packages.push((n.id.clone(), n.version.clone())),
            Err(e) => out
                .stopped
                .push((format!("{}@{}", n.id, n.version), keep_of(&e))),
        }
    }
    for s in shown {
        let r = match s {
            Shown::Archive { entry: c, owners } => {
                let Some(dir) = cache.as_deref() else {
                    continue;
                };
                if !now.cache.iter().any(|n| n == c) {
                    continue;
                }
                // One unit (E2 a, security review S3): an archive stays with its package when that
                // stopped; the package's line in `stopped` covers both.
                let owner_stopped = owners.iter().any(|(id, version)| {
                    let name = format!("{id}@{version}");
                    out.stopped
                        .iter()
                        .any(|(s, _)| s.eq_ignore_ascii_case(&name))
                });
                if owner_stopped {
                    continue;
                }
                let r = seg_of(&c.name).and_then(|n| gone_ok(dir.remove_file(&n, c.file_id)));
                if r.is_ok() {
                    out.bytes = out.bytes.saturating_add(c.len);
                    if c.temp {
                        out.leftovers += 1;
                    } else {
                        out.archives += 1;
                    }
                    // A package that was only its archive is removed now too.
                    for o in owners {
                        let known = out.packages.iter().any(|(i, v)| {
                            i.eq_ignore_ascii_case(&o.0) && v.eq_ignore_ascii_case(&o.1)
                        });
                        if !known {
                            out.packages.push(o.clone());
                        }
                    }
                }
                r.map_err(|e| (c.name.clone(), e))
            }
            Shown::EmptyId(e) => {
                let Some(dir) = packages.as_deref() else {
                    continue;
                };
                if !now.empty_ids.iter().any(|n| n == e) {
                    continue;
                }
                let r = seg_of(&e.id).and_then(|n| gone_ok(dir.remove_dir(&n, e.file_id)));
                if r.is_ok() {
                    out.leftovers += 1;
                }
                r.map_err(|x| (e.id.clone(), x))
            }
            Shown::Package(_) => continue,
        };
        if let Err((name, e)) = r {
            out.stopped.push((name, keep_of(&e)));
        }
    }
    // Best effort: the deletions are POSIX deletes, complete when they return.
    if let Some(p) = packages.as_deref() {
        let _ = p.flush();
    }
    if let Some(c) = cache.as_deref() {
        let _ = c.flush();
    }
    Ok(out)
}

#[cfg(test)]
#[path = "store_tests.rs"]
pub(crate) mod tests;
