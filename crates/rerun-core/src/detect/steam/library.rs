//! Libraries and app manifests (ADR 0012).
//!
//! - The library list comes from `steamapps\libraryfolders.vdf` of the Steam root, or from
//!   `config\libraryfolders.vdf` only if the first is `NotFound`; never merged, no fallback
//!   after any other failure. Library 0 is always the root; listed paths go through
//!   [`StoreDir::open`] and are de-duplicated by [`RootId`],
//!   first occurrence wins, silently. At most [`MAX_LIBRARIES`] listed.
//! - Each library's `steamapps` is opened relative to the library handle and listed once;
//!   entries named `appmanifest_<id>.acf` (ASCII case-insensitive) are the manifests, at most
//!   [`MAX_MANIFESTS`], each a plain file read with `read_store_file` and checked (`appid`
//!   equals `<id>`, `installdir` a valid single segment).

use std::path::Path;

use super::files::{AppManifest, Library, LibraryFolders, decimal_u32};
use super::issue::{Issue, IssueKind, Location};
use super::state::{AppState, StateFlags};
use super::text::RawText;
use crate::detect::vdf::{Limits, VdfReadError, read_store_file};
use crate::path::{RelPath, RootPath, classify};
use crate::policy::root::{ForbiddenRoots, GameDir, RootError, RootId, StoreDir};
use crate::sys::fs::{DirEntry, EntryKind};
use crate::sys::{SysError, SysErrorKind, System};

/// Most libraries a library file may list (the root not counted); more refuses the file.
pub const MAX_LIBRARIES: usize = 256;
/// Most `appmanifest_*.acf` entries per library; more and the library has no apps.
pub const MAX_MANIFESTS: usize = 16_384;

const PRIMARY: &str = r"steamapps\libraryfolders.vdf";
const FALLBACK: &str = r"config\libraryfolders.vdf";
const STEAMAPPS: &str = "steamapps";
const PREFIX: &str = "appmanifest_";
const SUFFIX: &str = ".acf";

/// One installed (or partly installed) app of a library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteamApp {
    /// `appid`, equal to the `<id>` of the manifest's file name.
    pub app_id: u32,
    /// `name` as written; output layers sanitize it.
    pub name: RawText,
    /// `installdir`, a valid single segment (`policy::path::classify`). The game folder is
    /// `steamapps\common\<install_dir>`, opened only through `SteamLibrary::open_game`.
    pub install_dir: RelPath,
    /// `StateFlags`, raw.
    pub state_flags: StateFlags,
    /// The manifest, relative to the library (`steamapps\appmanifest_<id>.acf`).
    pub manifest: RelPath,
}

impl SteamApp {
    /// The state derived from [`Self::state_flags`].
    pub fn state(&self) -> AppState {
        self.state_flags.state()
    }
}

/// A Steam library: an opened store folder, its label and its apps sorted by app ID.
#[derive(Debug)]
pub struct SteamLibrary<'s> {
    store: StoreDir<'s>,
    label: Option<RawText>,
    apps: Vec<SteamApp>,
}

impl<'s> SteamLibrary<'s> {
    /// The store folder.
    pub fn store(&self) -> &StoreDir<'s> {
        &self.store
    }

    /// Canonical path as of opening.
    pub fn path(&self) -> &RootPath {
        self.store.path()
    }

    /// Identity.
    pub fn id(&self) -> RootId {
        self.store.id()
    }

    /// Label as written in the library file (`None` for the Steam root).
    pub fn label(&self) -> Option<&RawText> {
        self.label.as_ref()
    }

    /// Apps sorted by app ID.
    pub fn apps(&self) -> &[SteamApp] {
        &self.apps
    }

    /// The app with this ID in this library.
    pub fn app(&self, app_id: u32) -> Option<&SteamApp> {
        self.apps.iter().find(|a| a.app_id == app_id)
    }

    /// Opens the game folder `steamapps\common\<installdir>` of the app `app_id` of this
    /// library, relative to the library handle ([`StoreDir::game`]: no reparse point followed,
    /// canonical path and forbidden list checked). The app is looked up in this library's own
    /// list; an unknown ID, like a missing folder (soundtracks, tools), is `NotFound`.
    pub fn open_game(&self, fr: &ForbiddenRoots, app_id: u32) -> Result<GameDir<'_>, RootError> {
        let app = self.app(app_id).ok_or_else(|| {
            RootError::Sys(SysError::new(
                SysErrorKind::NotFound,
                format!("app {app_id} in library {}", self.path()),
            ))
        })?;
        self.store.game(fr, app.install_dir.as_str())
    }
}

/// A fixed relative path of this module.
fn fixed(s: &'static str) -> Result<RelPath, IssueKind> {
    RelPath::parse(s).map_err(|e| IssueKind::Root(Box::new(RootError::InvalidPath(e))))
}

fn read_library_file(root: &StoreDir<'_>, file: &RelPath) -> Result<LibraryFolders, IssueKind> {
    let doc = read_store_file(root, file, &Limits::LIBRARY_FOLDERS).map_err(IssueKind::VdfRead)?;
    LibraryFolders::from_vdf(&doc).map_err(IssueKind::View)
}

/// Opening the file found nothing (the file or `steamapps`/`config` is missing).
fn is_not_found(kind: &IssueKind) -> bool {
    matches!(
        kind,
        IssueKind::VdfRead(VdfReadError::Open { source, .. })
            if source.kind == SysErrorKind::NotFound
    )
}

/// The libraries listed by the root's library file, with the file they came from.
fn listed(root: &StoreDir<'_>, issues: &mut Vec<Issue>) -> Option<(RelPath, Vec<Library>)> {
    let at_file = |file: &RelPath| Location::LibraryFile {
        root: root.path().clone(),
        file: file.clone(),
    };
    let (primary, fallback) = match (fixed(PRIMARY), fixed(FALLBACK)) {
        (Ok(p), Ok(f)) => (p, f),
        (Err(kind), _) | (_, Err(kind)) => {
            issues.push(Issue {
                at: Location::Library(root.path().clone()),
                kind,
            });
            return None;
        }
    };
    let (file, result) = match read_library_file(root, &primary) {
        Err(first) if is_not_found(&first) => match read_library_file(root, &fallback) {
            // Neither file: report the canonical one.
            Err(second) if is_not_found(&second) => (primary, Err(first)),
            other => (fallback, other),
        },
        other => (primary, other),
    };
    match result {
        Err(kind) => {
            issues.push(Issue {
                at: at_file(&file),
                kind,
            });
            None
        }
        Ok(lf) if lf.libraries.len() > MAX_LIBRARIES => {
            issues.push(Issue {
                at: at_file(&file),
                kind: IssueKind::TooManyLibraries {
                    count: lf.libraries.len(),
                    max: MAX_LIBRARIES,
                },
            });
            None
        }
        Ok(lf) => Some((file, lf.libraries)),
    }
}

/// The libraries of the Steam `root`: library 0 is the root, then the listed ones in file
/// order, de-duplicated by identity; each with its apps. Problems go to `issues`.
pub fn libraries<'s>(
    sys: &'s dyn System,
    fr: &ForbiddenRoots,
    root: StoreDir<'s>,
    issues: &mut Vec<Issue>,
) -> Vec<SteamLibrary<'s>> {
    let mut stores: Vec<(StoreDir<'s>, Option<RawText>)> = Vec::new();
    let listed = listed(&root, issues);
    let root_path = root.path().clone();
    stores.push((root, None));
    if let Some((file, listed)) = listed {
        for (index, lib) in listed.into_iter().enumerate() {
            match StoreDir::open(sys, fr, Path::new(lib.path.as_raw_str())) {
                Err(e) => issues.push(Issue {
                    at: Location::LibraryEntry {
                        root: root_path.clone(),
                        file: file.clone(),
                        index,
                    },
                    kind: IssueKind::Root(Box::new(e)),
                }),
                Ok(store) => {
                    if !stores.iter().any(|(s, _)| s.id() == store.id()) {
                        stores.push((store, lib.label));
                    }
                }
            }
        }
    }
    stores
        .into_iter()
        .map(|(store, label)| {
            let apps = apps(&store, MAX_MANIFESTS, issues);
            SteamLibrary { store, label, apps }
        })
        .collect()
}

/// `<id>` of a name `appmanifest_<id>.acf` (prefix and suffix ASCII case-insensitive), not
/// yet checked; `None` for every other name.
fn manifest_id(name: &str) -> Option<&str> {
    let rest = name.get(PREFIX.len()..)?;
    let id_len = rest.len().checked_sub(SUFFIX.len())?;
    let (head, id, tail) = (
        name.get(..PREFIX.len())?,
        rest.get(..id_len)?,
        rest.get(id_len..)?,
    );
    (head.eq_ignore_ascii_case(PREFIX) && tail.eq_ignore_ascii_case(SUFFIX)).then_some(id)
}

/// The apps of one library, sorted by app ID. `max` is [`MAX_MANIFESTS`] (smaller in tests).
pub(super) fn apps(store: &StoreDir<'_>, max: usize, issues: &mut Vec<Issue>) -> Vec<SteamApp> {
    let mut report = |kind| {
        issues.push(Issue {
            at: Location::Library(store.path().clone()),
            kind,
        });
    };
    let steamapps = match fixed(STEAMAPPS) {
        Ok(p) => p,
        Err(kind) => {
            report(kind);
            return Vec::new();
        }
    };
    // Relative to the library handle: a junction or symlink at `steamapps` is
    // `ReparsePoint`, never followed; restricted is `AccessDenied`.
    let dir = match store.dir().open_dir(&steamapps) {
        Ok(dir) => dir,
        Err(e) => {
            report(IssueKind::Sys(e));
            return Vec::new();
        }
    };
    match dir.info() {
        Err(e) => {
            report(IssueKind::Sys(e));
            return Vec::new();
        }
        Ok(info) if info.case_sensitive => {
            report(IssueKind::CaseSensitiveSteamapps);
            return Vec::new();
        }
        Ok(_) => {}
    }
    let entries = match dir.read_dir(None) {
        Ok(entries) => entries,
        Err(e) => {
            report(IssueKind::Sys(e));
            return Vec::new();
        }
    };
    let candidates: Vec<(&DirEntry, &str)> = entries
        .iter()
        .filter_map(|e| manifest_id(&e.name).map(|id| (e, id)))
        .collect();
    // Counted before anything is opened or reported, so the issue list stays bounded too.
    if candidates.len() > max {
        report(IssueKind::TooManyManifests {
            count: candidates.len(),
            max,
        });
        return Vec::new();
    }
    let mut apps = Vec::with_capacity(candidates.len());
    for (entry, id) in candidates {
        match read_app(store, &steamapps, entry, id) {
            Ok(app) => apps.push(app),
            Err(kind) => issues.push(Issue {
                at: Location::Manifest {
                    library: store.path().clone(),
                    name: entry.name.clone(),
                },
                kind,
            }),
        }
    }
    apps.sort_by_key(|a| a.app_id);
    apps
}

/// One manifest entry: checked before it is opened, checked again after it is parsed.
fn read_app(
    store: &StoreDir<'_>,
    steamapps: &RelPath,
    entry: &DirEntry,
    id: &str,
) -> Result<SteamApp, IssueKind> {
    let file_id = decimal_u32(id, false).ok_or(IssueKind::ManifestName)?;
    // A file with an allowlisted data tag (WOF, cloud files) is `File` too.
    if entry.meta.kind != EntryKind::File || entry.meta.restricted {
        return Err(IssueKind::ManifestEntry {
            kind: entry.meta.kind,
            restricted: entry.meta.restricted,
        });
    }
    let seg = classify(&entry.name, false).map_err(IssueKind::Anomaly)?;
    let manifest = steamapps
        .child(seg.as_str())
        .map_err(|e| IssueKind::Root(Box::new(RootError::InvalidPath(e))))?;
    let doc =
        read_store_file(store, &manifest, &Limits::APP_MANIFEST).map_err(IssueKind::VdfRead)?;
    let m = AppManifest::from_vdf(&doc).map_err(IssueKind::View)?;
    if m.app_id != file_id {
        return Err(IssueKind::AppIdMismatch {
            file: file_id,
            manifest: m.app_id,
        });
    }
    let install_dir = classify(m.install_dir.as_raw_str(), false).map_err(IssueKind::Anomaly)?;
    Ok(SteamApp {
        app_id: m.app_id,
        name: m.name,
        install_dir,
        state_flags: StateFlags::new(m.state_flags),
        manifest,
    })
}

#[cfg(test)]
mod tests;
