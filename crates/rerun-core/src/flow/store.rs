//! Rerun's package store for a front end (P5-8b, ADR 0027 amendment P5-8b): what it holds, who
//! uses what, and the removal of unused packages after a list preview.
//!
//! `flow` only selects; the rules are enforced below it: `exec::remove_packages` (a package a
//! transaction uses stays, an unreadable transaction keeps every package, the journal lock) and
//! `pkg::store::remove` (only Rerun's plain entries, exactly what was shown, by file ID).
//!
//! - [`package_store`] reads only: every version folder with its name from the current signed
//!   index (if it is there), its state, size, archives and users; archives no package of the
//!   index names; leftovers of interrupted runs; foreign entries.
//! - **One unit** (user decision E2 a): a package goes with its archives in the cache. An archive
//!   two packages name goes only when both go. Archives without a package and leftovers go only
//!   with "remove all unused" ([`Pick::Unused`]).
//! - [`remove_preview`] lists what goes and what stays with the reason (rule 5: the list, not a
//!   count); [`remove`] removes exactly that ([`RemoveShown`]) and is [`ActError::Changed`] with
//!   nothing removed when the store or the use of a shown package changed since.
//! - Nothing here needs a package for a recovery: a revert reads only the journal (P5-8b
//!   finding 1). A package that is no longer in the index cannot be downloaded again: the
//!   preview says so per package ([`StoredPackage::in_index`]).

use crate::exec::{self, ExecError, Refusal, TxnLine};
use crate::journal::{JournalError, TxnId};
use crate::pkg::download::{cache_name, downloads};
use crate::pkg::extract::layout;
use crate::pkg::store::{self, CacheEntry, Removed, Shown, StoreError, StoreKeep, StoreSub};
use crate::policy::root::AppDir;

use super::history::{app_of, ctx};
use super::revert::ActError;
use super::{Guarded, IndexState, index_state};

/// Whether a package's files are there (names only, nothing hashed: the planner hashes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredState {
    /// Its version folder holds every file the index names (or, for a package no longer in
    /// the index, any file).
    Unpacked,
    /// Its version folder lacks a file the index names (an interrupted download or removal):
    /// the planner refuses it, `package fetch` completes it.
    Incomplete,
    /// Only its archive is in the cache.
    ArchiveOnly,
}

/// A transaction that uses a package.
#[derive(Debug, Clone)]
pub struct UsedBy {
    /// The transaction (its number is `txn.seq()`).
    pub txn: TxnId,
    /// The Steam app of its head, if it names one.
    pub app: Option<u32>,
    /// Its state.
    pub line: TxnLine,
}

/// Why a package stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageKeep {
    /// A transaction that is not settled uses it ([`StoredPackage::used_by`]).
    InUse,
    /// These transactions cannot be read, so any package may be used (fail closed, user
    /// decision E3 a); forgetting or reverting them frees the packages.
    UnknownUse(Vec<TxnId>),
    /// Its folder holds something Rerun does not remove.
    Store(StoreKeep),
    /// It is only its archive, and a package that stays names that archive too: nothing of it
    /// would go.
    SharedArchive,
}

/// One package of the store.
#[derive(Debug, Clone)]
pub struct StoredPackage {
    /// The package ID.
    pub id: String,
    /// The version.
    pub version: String,
    /// Its name in the current index (`None`: not in it).
    pub name: Option<String>,
    /// The current index has this package at this version: it can be downloaded again.
    pub in_index: bool,
    /// Whether its files are there.
    pub state: StoredState,
    /// Its files in the version folder.
    pub files: u32,
    /// The paths of those files below the version folder, escaped, sorted (rule 5: what goes is
    /// listed, not counted; empty for a package that stays because of what its folder holds).
    pub paths: Vec<String>,
    /// Its files and archives, in bytes.
    pub bytes: u64,
    /// Its archives in the cache (their names, the SHA-256).
    pub archives: Vec<String>,
    /// The transactions that use it, oldest first.
    pub used_by: Vec<UsedBy>,
    /// Why it stays (`None`: it can be removed).
    pub keep: Option<PackageKeep>,
}

/// What the store holds.
#[derive(Debug, Clone)]
pub struct StoreView {
    /// The packages, by ID and version.
    pub packages: Vec<StoredPackage>,
    /// Archives no package of the index names (an older version), with their length.
    pub loose_archives: Vec<(String, u64)>,
    /// Leftovers of interrupted runs (temp files of the cache, empty package folders): count and
    /// bytes.
    pub leftovers: (usize, u64),
    /// Entries Rerun never touches (`packages\…` or `cache\…`, escaped), with the reason.
    pub foreign: Vec<(String, StoreKeep)>,
}

/// Why the store cannot be shown.
#[derive(Debug)]
pub enum StoreGate {
    /// Rerun's folder does not exist: there is no store.
    NoAppDir,
    /// The journal cannot be read (who uses what is unknown).
    Journal(JournalError),
    /// The store cannot be read.
    Store(StoreError),
    /// The package asked for is not in the store.
    NotFound,
}

/// Which packages a removal is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    /// One package (ID and version as listed).
    Package {
        /// The package ID.
        id: String,
        /// The version.
        version: String,
    },
    /// Every package no transaction uses, archives without a package, leftovers.
    Unused,
}

/// What a removal would do (rule 5: the list).
#[derive(Debug, Clone)]
pub struct RemovePreview {
    /// The packages that go (with the archives that go with them).
    pub remove: Vec<StoredPackage>,
    /// Archives without a package that go.
    pub loose_archives: Vec<(String, u64)>,
    /// Leftovers that go: count and bytes.
    pub leftovers: (usize, u64),
    /// Packages asked for that stay, with [`StoredPackage::keep`].
    pub stays: Vec<StoredPackage>,
    /// Bytes freed.
    pub bytes: u64,
}

/// Exactly what a preview showed for removal. Only [`remove_preview`] builds one.
#[derive(Debug)]
pub struct RemoveShown {
    items: Vec<Shown>,
}

impl RemoveShown {
    /// Nothing would be removed.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// The view with what each part is on disk.
struct Built {
    view: StoreView,
    /// Per package of the view: its version folder, if there is one.
    dirs: Vec<Option<store::VersionDir>>,
    /// Per package of the view: its archives as listed.
    archives: Vec<Vec<CacheEntry>>,
    loose: Vec<CacheEntry>,
    leftovers: Vec<Shown>,
}

/// The display path of a foreign entry.
fn foreign_name(f: &store::Foreign) -> String {
    let sub = match f.sub {
        StoreSub::Packages => "packages",
        StoreSub::Cache => "cache",
    };
    if f.name.is_empty() {
        sub.to_owned()
    } else {
        format!("{sub}\\{}", f.name)
    }
}

fn build(app: &AppDir<'_>) -> Result<Built, StoreGate> {
    let listing = store::list(app).map_err(StoreGate::Store)?;
    // One reading of the journal: the users and their lines agree.
    let (users, status) = exec::package_users_with_status(app).map_err(StoreGate::Journal)?;
    let catalog = match index_state(Some(app)) {
        IndexState::Current(c) => Some(c),
        IndexState::None | IndexState::Refused(_) => None,
    };
    let archive = |name: &str| {
        listing
            .cache
            .iter()
            .find(|c| !c.temp && c.name.eq_ignore_ascii_case(name))
    };
    let in_index = |id: &str, version: &str| {
        catalog
            .as_ref()
            .and_then(|c| c.package(id))
            .filter(|p| p.version.eq_ignore_ascii_case(version))
    };
    let archives_of = |p: &crate::catalog::model::Package| -> Vec<CacheEntry> {
        downloads(p)
            .map(|ds| {
                ds.iter()
                    .filter_map(|d| archive(&cache_name(d.sha256())).cloned())
                    .collect()
            })
            .unwrap_or_default()
    };
    let used = |id: &str, version: &str| -> Vec<UsedBy> {
        users
            .of(id, version)
            .into_iter()
            .filter_map(|t| {
                let st = status.txns.iter().find(|s| s.id == t)?;
                Some(UsedBy {
                    txn: t,
                    app: app_of(st),
                    line: st.state.clone(),
                })
            })
            .collect()
    };
    let keep = |id: &str, version: &str, store: Option<StoreKeep>| {
        if !users.of(id, version).is_empty() {
            Some(PackageKeep::InUse)
        } else if let Some(k) = store {
            Some(PackageKeep::Store(k))
        } else if !users.unreadable.is_empty() {
            Some(PackageKeep::UnknownUse(users.unreadable.clone()))
        } else {
            None
        }
    };
    let mut b = Built {
        view: StoreView {
            packages: Vec::new(),
            loose_archives: Vec::new(),
            leftovers: (0, 0),
            foreign: listing
                .foreign
                .iter()
                .map(|f| (foreign_name(f), f.keep))
                .collect(),
        },
        dirs: Vec::new(),
        archives: Vec::new(),
        loose: Vec::new(),
        leftovers: Vec::new(),
    };
    for v in &listing.packages {
        let p = in_index(&v.id, &v.version);
        let archives = p.map(archives_of).unwrap_or_default();
        let state = match p.map(layout) {
            Some(Ok(placed)) if placed.iter().all(|x| v.has_file(&x.dest)) => StoredState::Unpacked,
            Some(_) => StoredState::Incomplete,
            None if v.files() > 0 => StoredState::Unpacked,
            None => StoredState::Incomplete,
        };
        b.view.packages.push(StoredPackage {
            id: v.id.clone(),
            version: v.version.clone(),
            name: p.map(|p| p.name.clone()),
            in_index: p.is_some(),
            state,
            files: v.files(),
            paths: {
                let mut v: Vec<String> = v
                    .items
                    .iter()
                    .filter(|i| !i.dir)
                    .map(|i| crate::escape::path(i.rel.as_str()).to_string())
                    .collect();
                v.sort();
                v
            },
            bytes: archives
                .iter()
                .map(|a| a.len)
                .fold(v.bytes(), u64::saturating_add),
            archives: archives.iter().map(|a| a.name.clone()).collect(),
            used_by: used(&v.id, &v.version),
            keep: keep(&v.id, &v.version, v.keep),
        });
        b.dirs.push(Some(v.clone()));
        b.archives.push(archives);
    }
    // Packages of the index with an archive in the cache and no version folder.
    for p in catalog.iter().flat_map(|c| c.packages()) {
        let id = p.id.as_str();
        if b.view
            .packages
            .iter()
            .any(|s| s.id.eq_ignore_ascii_case(id) && s.version.eq_ignore_ascii_case(&p.version))
        {
            continue;
        }
        let archives = archives_of(p);
        if archives.is_empty() {
            continue;
        }
        b.view.packages.push(StoredPackage {
            id: id.to_owned(),
            version: p.version.clone(),
            name: Some(p.name.clone()),
            in_index: true,
            state: StoredState::ArchiveOnly,
            files: 0,
            paths: Vec::new(),
            bytes: archives.iter().map(|a| a.len).fold(0, u64::saturating_add),
            archives: archives.iter().map(|a| a.name.clone()).collect(),
            used_by: used(id, &p.version),
            keep: keep(id, &p.version, None),
        });
        b.dirs.push(None);
        b.archives.push(archives);
    }
    for c in &listing.cache {
        if c.temp {
            b.view.leftovers.0 += 1;
            b.view.leftovers.1 = b.view.leftovers.1.saturating_add(c.len);
            b.leftovers.push(Shown::Archive {
                entry: c.clone(),
                owners: Vec::new(),
            });
        } else if !b.archives.iter().flatten().any(|a| a == c) {
            b.view.loose_archives.push((c.name.clone(), c.len));
            b.loose.push(c.clone());
        }
    }
    for e in &listing.empty_ids {
        b.view.leftovers.0 += 1;
        b.leftovers.push(Shown::EmptyId(e.clone()));
    }
    Ok(b)
}

/// The store (module docs). Reads only; takes no lock, creates nothing.
///
/// # Errors
/// [`StoreGate`].
pub fn package_store(g: &Guarded<'_>) -> Result<StoreView, StoreGate> {
    let app = g.app().ok_or(StoreGate::NoAppDir)?;
    Ok(build(app)?.view)
}

/// The preview of a removal (module docs). Reads only. A package asked for that stays is in
/// [`RemovePreview::stays`] and nothing of it is in the [`RemoveShown`].
///
/// # Errors
/// [`StoreGate`]; [`StoreGate::NotFound`] for a [`Pick::Package`] the store does not hold.
pub fn remove_preview(
    g: &Guarded<'_>,
    pick: &Pick,
) -> Result<(RemovePreview, RemoveShown), StoreGate> {
    let app = g.app().ok_or(StoreGate::NoAppDir)?;
    let b = build(app)?;
    let asked: Vec<usize> = match pick {
        Pick::Package { id, version } => {
            let i = b
                .view
                .packages
                .iter()
                .position(|p| {
                    p.id.eq_ignore_ascii_case(id) && p.version.eq_ignore_ascii_case(version)
                })
                .ok_or(StoreGate::NotFound)?;
            vec![i]
        }
        Pick::Unused => (0..b.view.packages.len()).collect(),
    };
    // Going: no reason to stay, and something of it goes (D2: a package that is only an archive
    // another package that stays names would remove nothing). Dropping one can leave another
    // with nothing, so this runs until it settles.
    let mut going: Vec<usize> = asked
        .iter()
        .copied()
        .filter(|i| b.view.packages[*i].keep.is_none())
        .collect();
    let goes = |a: &CacheEntry, going: &[usize]| {
        b.archives
            .iter()
            .enumerate()
            .all(|(k, of)| !of.contains(a) || going.contains(&k))
    };
    let mut shared = Vec::new();
    loop {
        let empty = going
            .iter()
            .copied()
            .find(|i| b.dirs[*i].is_none() && !b.archives[*i].iter().any(|a| goes(a, &going)));
        let Some(i) = empty else { break };
        going.retain(|k| *k != i);
        shared.push(i);
    }
    let mut preview = RemovePreview {
        remove: Vec::new(),
        loose_archives: Vec::new(),
        leftovers: (0, 0),
        stays: asked
            .iter()
            .filter(|i| !going.contains(i))
            .map(|i| {
                let mut p = b.view.packages[*i].clone();
                if shared.contains(i) {
                    p.keep = Some(PackageKeep::SharedArchive);
                }
                p
            })
            .collect(),
        bytes: 0,
    };
    let owners = |a: &CacheEntry| -> Vec<(String, String)> {
        b.archives
            .iter()
            .enumerate()
            .filter(|(_, of)| of.contains(a))
            .map(|(k, _)| {
                let p = &b.view.packages[k];
                (p.id.clone(), p.version.clone())
            })
            .collect()
    };
    let mut items = Vec::new();
    let mut taken: Vec<CacheEntry> = Vec::new();
    for i in &going {
        let mut p = b.view.packages[*i].clone();
        let dir = b.dirs[*i].clone();
        // An archive another package names goes only when that one goes too.
        let archives: Vec<CacheEntry> = b.archives[*i]
            .iter()
            .filter(|a| goes(a, &going))
            .cloned()
            .collect();
        p.bytes = dir.as_ref().map_or(0, store::VersionDir::bytes);
        preview.bytes = preview.bytes.saturating_add(p.bytes);
        if let Some(d) = dir {
            items.push(Shown::Package(d));
        }
        for a in &archives {
            if !taken.contains(a) {
                preview.bytes = preview.bytes.saturating_add(a.len);
                items.push(Shown::Archive {
                    entry: a.clone(),
                    owners: owners(a),
                });
                taken.push(a.clone());
            }
            p.bytes = p.bytes.saturating_add(a.len);
        }
        p.archives = archives.iter().map(|a| a.name.clone()).collect();
        preview.remove.push(p);
    }
    if *pick == Pick::Unused {
        for a in &b.loose {
            preview.loose_archives.push((a.name.clone(), a.len));
            preview.bytes = preview.bytes.saturating_add(a.len);
            items.push(Shown::Archive {
                entry: a.clone(),
                owners: Vec::new(),
            });
        }
        preview.leftovers = b.view.leftovers;
        preview.bytes = preview.bytes.saturating_add(b.view.leftovers.1);
        items.extend(b.leftovers);
    }
    Ok((preview, RemoveShown { items }))
}

/// Removes exactly what the preview `s` showed (module docs). Nothing shown: nothing is opened or
/// created (only the standard-user check).
///
/// # Errors
/// [`ActError::Changed`] (the store, or the use of a shown package, changed: show the preview
/// again; nothing was removed), or `exec`'s error (another Rerun holds a lock: try again).
pub fn remove(g: &Guarded<'_>, s: RemoveShown) -> Result<Removed, ActError> {
    let app = g.app().ok_or(ActError::Changed)?;
    if s.items.is_empty() {
        exec::standard_user(g.env().sys).map_err(|r| ActError::Exec(r.into()))?;
        return Ok(Removed::default());
    }
    match exec::remove_packages(&ctx(g, app), &s.items) {
        Ok(r) => Ok(r),
        Err(ExecError::Refused(
            Refusal::StoreChanged | Refusal::PackageInUse { .. } | Refusal::Blocked { .. },
        )) => Err(ActError::Changed),
        Err(e) => Err(e.into()),
    }
}

// The index needs the published test key (feature `test-key`), as `flow::packages`' tests.
#[cfg(test)]
#[cfg(feature = "test-key")]
#[path = "store_tests.rs"]
mod tests;
