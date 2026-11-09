//! Roots: the only way to open a store or game folder (ADR 0007 and its amendment).
//!
//! - [`StoreDir`]: a store folder (Steam and its libraries), opened by absolute path. It
//!   may be reached through a junction (moved library); the canonical path is checked.
//! - [`GameDir`]: a game folder. From a store it is opened **handle-relative**
//!   (`steamapps\common\<installdir>`), so a junction at the game level is reported as
//!   [`RootError::Reparse`] and never becomes a root. A manually added folder is opened by
//!   absolute path like a store ([`GameOrigin::Manual`]).
//! - [`AppDir`]: Rerun's own folder `<LocalAppData>\Rerun` (ADR 0019): `LocalAppData` by
//!   absolute path, `Rerun` and its sub folders handle-relative (a reparse point there is
//!   [`RootError::Reparse`]), created one level at a time on request ([`Create`]). Not
//!   checked against the forbidden list.
//! - [`ForbiddenRoots`]: the forbidden-root list, resolved from known folders. Every root is
//!   checked lexically before it is opened and canonically after; the canonical check is the
//!   one that counts.
//! - [`read_input`]: a file the user names (the step file of `rerun plan`, P2-13): its folder
//!   opened read side by absolute path, the file one plain segment below it, bounded.
//! - [`shadows`]: the UAC VirtualStore lookup (P3-7): a copy of a managed file below
//!   `<LocalAppData>\VirtualStore`, read only, never a root.
//! - [`RootId`]: volume serial and file ID. Plans store it; apply and revert reopen the root
//!   and abort on a mismatch ([`StoreDir::ensure_id`], [`GameDir::ensure_id`]).
//!
//! `open_abs` in this module is the only caller of [`crate::sys::Fs::open_dir`] outside
//! `sys`, `open_abs_write` the only caller of [`crate::sys::Fs::open_dir_write`] and the only
//! place that creates a [`WriteCap`] (enforced by `clippy.toml`).
//!
//! Capabilities (ADR 0017): [`StoreDir::dir`] and [`GameDir::dir`] hand out the read side
//! only ([`Dir`]). A store is never written. The write handle of a game folder
//! ([`DirWrite`]) is crate-internal (`GameDir::dir_write`), for the executor and the journal
//! only (ADR 0020), and refused on a volume without POSIX delete and rename semantics; the
//! same holds for `AppDir::dir_write` (journal and plan storage).

mod app;
mod forbidden;
mod input;
mod vstore;

use std::fmt;
use std::path::Path;

pub(crate) use app::AppSub;
pub use app::{AppDir, Create, ProfilesDir};
pub use forbidden::{Forbidden, ForbiddenRoots, Protected};
pub use input::{file_present, read_input};
pub use vstore::{Shadow, VIRTUAL_STORE, check_root, preview_with_shadows, shadows};

use crate::path::{Anomaly, PathError, RelPath, RootPath, classify};
use crate::sys::fs::RootInfo;
use crate::sys::{Dir, DirWrite, SysError, SysErrorKind, SysResult, System, WriteCap};

/// Identity of a root: volume serial and file ID of the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootId {
    /// Volume serial number.
    pub volume_serial: u64,
    /// 128-bit file ID.
    pub file_id: u128,
}

impl RootId {
    /// Identity of an opened directory.
    pub fn of(info: &RootInfo) -> Self {
        Self {
            volume_serial: info.volume_serial,
            file_id: info.file_id,
        }
    }
}

impl fmt::Display for RootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}-{:032x}", self.volume_serial, self.file_id)
    }
}

/// Error while opening or re-checking a root.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RootError {
    /// The path is not a plain drive-letter folder (lexically, or its canonical path is on a
    /// network share or a volume without a drive letter).
    #[error(transparent)]
    InvalidPath(#[from] PathError),
    /// The root is on the forbidden list.
    #[error("{path} is forbidden: {reason}")]
    Forbidden {
        /// Path that was checked (lexical before, canonical after opening).
        path: RootPath,
        /// Reason.
        reason: Forbidden,
    },
    /// A reparse point (junction, symlink, unknown tag) between store and game folder. An
    /// anomaly to report, never a root.
    #[error("{at} below {store} is or goes through a reparse point")]
    Reparse {
        /// The store.
        store: RootPath,
        /// Relative path that was opened.
        at: RelPath,
    },
    /// The install folder name is not a valid single segment, or `steamapps\common` is
    /// case-sensitive. An anomaly to report.
    #[error(transparent)]
    Anomaly(#[from] Anomaly),
    /// The reopened root is a different directory than the one in the plan.
    #[error("{path}: expected root {expected}, found {found}")]
    IdentityMismatch {
        /// The root.
        path: RootPath,
        /// Identity from the plan.
        expected: RootId,
        /// Identity now.
        found: RootId,
    },
    /// The store folder was renamed or moved after it was opened. Reopen it.
    #[error("store {was} moved to {now} after it was opened")]
    StoreMoved {
        /// Canonical path at open.
        was: RootPath,
        /// Canonical path now.
        now: RootPath,
    },
    /// The game folder is not where it must be below its store: a broken `sys`
    /// implementation, or the store was moved during the call. Fails closed.
    #[error("{child} is not below {store}\\steamapps\\common")]
    Escaped {
        /// The store.
        store: RootPath,
        /// Canonical path of the game folder.
        child: RootPath,
    },
    /// The forbidden list could not be resolved completely; no root is handed out.
    #[error("forbidden list incomplete ({what}): {reason}")]
    ForbiddenListIncomplete {
        /// Folder that failed.
        what: String,
        /// Reason.
        reason: String,
    },
    /// Error of the system layer.
    #[error(transparent)]
    Sys(#[from] SysError),
}

/// The one absolute open outside `sys` (ADR 0007).
#[expect(
    clippy::disallowed_methods,
    reason = "ADR 0007: policy::root is the only place that opens roots by absolute path"
)]
fn open_abs<'s>(sys: &'s dyn System, abs: &Path) -> SysResult<Box<dyn Dir + 's>> {
    sys.fs().open_dir(abs)
}

/// The one absolute open with the write capability (ADR 0017): the only place that creates a
/// [`WriteCap`]. Roots opened here hand the capability out only as
/// [`GameDir::dir_write`]; a [`StoreDir`] keeps it to open its game folders and never hands
/// it out.
#[expect(
    clippy::disallowed_methods,
    reason = "ADR 0017: policy::root is the only place that opens roots with the write capability"
)]
fn open_abs_write<'s>(sys: &'s dyn System, abs: &Path) -> SysResult<Box<dyn DirWrite + 's>> {
    sys.fs().open_dir_write(abs, &WriteCap::new())
}

/// Opens a root by absolute path: lexical check, open, canonical check.
/// A `NotFound` after the open itself succeeded (`Dir::info` of a handle whose folder was
/// deleted or renamed meanwhile, a folder that changed while it was opened) is a race, not a
/// missing path: `Busy`, like the other swap races. Only the open of the path itself reports
/// a missing folder as `NotFound` (P2-10a review: `exec` takes only that as "gone").
fn raced(e: SysError) -> SysError {
    // The codes of the original error stay; its target is already shown-safe.
    if e.kind == SysErrorKind::NotFound {
        SysError {
            kind: SysErrorKind::Busy,
            ..e
        }
    } else {
        e
    }
}

/// A root opened by absolute path: the handle, its canonical path, its properties and the path
/// it was opened by.
type Opened<'s> = (Box<dyn DirWrite + 's>, RootPath, RootInfo, RootPath);

fn open_checked<'s>(
    sys: &'s dyn System,
    fr: &ForbiddenRoots,
    abs: &Path,
) -> Result<Opened<'s>, RootError> {
    let lexical = RootPath::new(abs)?;
    fr.check(&lexical).map_err(|reason| RootError::Forbidden {
        path: lexical.clone(),
        reason,
    })?;
    let dir = open_abs_write(sys, lexical.path())?;
    let info = dir.info().map_err(raced)?;
    let path = RootPath::from_final_path(&info.final_path)?;
    check_canonical(fr, &path, &info)?;
    Ok((dir, path, info, lexical))
}

fn check_canonical(fr: &ForbiddenRoots, path: &RootPath, info: &RootInfo) -> Result<(), RootError> {
    // The per-volume rule runs on the volume-relative path as well, so it also applies to a
    // volume mounted in a folder (`D:\Mounts\Data\$Recycle.Bin`), ADR 0007 amendment.
    let verdict = match info.volume_first_segment() {
        None => Err(Forbidden::VolumeRoot),
        Some(first) => forbidden::volume_folder(first).and_then(|()| fr.check(path)),
    };
    verdict.map_err(|reason| RootError::Forbidden {
        path: path.clone(),
        reason,
    })
}

fn ensure(path: &RootPath, info: &RootInfo, expected: RootId) -> Result<(), RootError> {
    let found = RootId::of(info);
    if found == expected {
        Ok(())
    } else {
        Err(RootError::IdentityMismatch {
            path: path.clone(),
            expected,
            found,
        })
    }
}

/// A store folder (Steam folder or library). Read-only: it hands out no write handle.
#[derive(Debug)]
pub struct StoreDir<'s> {
    /// Write-capable only so that [`Self::game`] can open a game folder with the write
    /// capability; never handed out as such.
    dir: Box<dyn DirWrite + 's>,
    path: RootPath,
    info: RootInfo,
    /// The path it was opened by (from the registry or `libraryfolders.vdf`), normalised.
    opened_as: RootPath,
}

impl<'s> StoreDir<'s> {
    /// Opens a store folder by absolute path (from the registry or `libraryfolders.vdf`).
    /// Follows junctions above and at the store folder; checks the canonical path.
    pub fn open(sys: &'s dyn System, fr: &ForbiddenRoots, abs: &Path) -> Result<Self, RootError> {
        let (dir, path, info, opened_as) = open_checked(sys, fr, abs)?;
        Ok(Self {
            dir,
            path,
            info,
            opened_as,
        })
    }

    /// Opens the game folder `steamapps\common\<installdir>` relative to this store.
    /// `installdir` must be a single valid segment. No reparse point is followed.
    pub fn game(&self, fr: &ForbiddenRoots, installdir: &str) -> Result<GameDir<'_>, RootError> {
        let seg = classify(installdir, false)?;
        let common = RelPath::parse(r"steamapps\common")?;
        let reparse = |at: &RelPath| {
            let store = self.path.clone();
            let at = at.clone();
            move |e: SysError| {
                if e.kind == SysErrorKind::ReparsePoint {
                    RootError::Reparse { store, at }
                } else {
                    RootError::Sys(e)
                }
            }
        };
        // The store handle stays valid when the store is renamed; then the expected path
        // below would be stale. Report that as its own error, not as `Escaped`.
        let store_now = RootPath::from_final_path(&self.dir.info().map_err(raced)?.final_path)?;
        if store_now != self.path {
            return Err(RootError::StoreMoved {
                was: self.path.clone(),
                now: store_now,
            });
        }

        let rel = common.child(seg.as_str())?;
        let dir = self.dir.open_dir_write(&rel).map_err(reparse(&rel))?;
        let info = dir.info().map_err(raced)?;

        // Case-sensitive `common` is an anomaly. Checked after the game is open, on the
        // `common` that holds this very game folder (same file ID under the same name), so
        // swapping `common` between check and open cannot slip through.
        let common_dir = self
            .dir
            .open_dir(&common)
            .map_err(|e| reparse(&common)(raced(e)))?;
        if common_dir.info().map_err(raced)?.case_sensitive {
            classify(installdir, true)?;
        }
        let entry = common_dir
            .metadata(&RelPath::from_segment(seg.as_str())?)
            .map_err(|e| reparse(&rel)(raced(e)))?;
        if entry.is_none_or(|m| m.file_id != info.file_id) {
            return Err(RootError::Sys(SysError::new(
                SysErrorKind::Busy,
                format!("{rel} changed while opening"),
            )));
        }

        let path = RootPath::from_final_path(&info.final_path)?;
        let expected = self
            .path
            .child("steamapps")?
            .child("common")?
            .child(seg.as_str())?;
        // Forbidden first: it names the more specific reason (a volume mounted at the game
        // folder has its own serial and would otherwise only report `Escaped`).
        check_canonical(fr, &path, &info)?;
        if path != expected || info.volume_serial != self.info.volume_serial {
            return Err(RootError::Escaped {
                store: self.path.clone(),
                child: path,
            });
        }
        // Review S-a: the launch path is only a name for `compat_layer`; one that is no
        // `RootPath` (longer than the canonical path allows) never fails the opening.
        let opened_as = self
            .opened_as
            .child("steamapps")
            .and_then(|p| p.child("common"))
            .and_then(|p| p.child(seg.as_str()))
            .ok();
        Ok(GameDir {
            dir,
            path,
            info,
            opened_as,
            origin: GameOrigin::Store {
                store: self.path.clone(),
                store_id: self.id(),
                installdir: seg,
            },
        })
    }

    /// Aborts unless this is the directory recorded in a plan.
    pub fn ensure_id(&self, expected: RootId) -> Result<(), RootError> {
        ensure(&self.path, &self.info, expected)
    }

    /// Canonical path as of opening.
    pub fn path(&self) -> &RootPath {
        &self.path
    }

    /// Identity.
    pub fn id(&self) -> RootId {
        RootId::of(&self.info)
    }

    /// Properties as of opening.
    pub fn info(&self) -> &RootInfo {
        &self.info
    }

    /// The handle, read side only.
    pub fn dir(&self) -> &dyn Dir {
        &*self.dir
    }
}

/// Where a game folder came from; decides how it is reopened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GameOrigin {
    /// `steamapps\common\<installdir>` below a store.
    Store {
        /// Canonical path of the store.
        store: RootPath,
        /// Identity of the store.
        store_id: RootId,
        /// Install folder name.
        installdir: RelPath,
    },
    /// Added manually by the user, opened by absolute path.
    Manual,
}

/// A game folder. Detection and primitives take this type, never a bare [`Dir`].
#[derive(Debug)]
pub struct GameDir<'a> {
    dir: Box<dyn DirWrite + 'a>,
    path: RootPath,
    info: RootInfo,
    /// `None`: the launch path is no `RootPath` (too long).
    opened_as: Option<RootPath>,
    origin: GameOrigin,
}

impl<'a> GameDir<'a> {
    /// Opens a manually added game folder by absolute path, like a store root.
    pub fn open_manual(
        sys: &'a dyn System,
        fr: &ForbiddenRoots,
        abs: &Path,
    ) -> Result<Self, RootError> {
        let (dir, path, info, opened_as) = open_checked(sys, fr, abs)?;
        Ok(Self {
            dir,
            path,
            info,
            opened_as: Some(opened_as),
            origin: GameOrigin::Manual,
        })
    }

    /// Aborts unless this is the directory recorded in a plan.
    pub fn ensure_id(&self, expected: RootId) -> Result<(), RootError> {
        ensure(&self.path, &self.info, expected)
    }

    /// Where the folder came from.
    pub fn origin(&self) -> &GameOrigin {
        &self.origin
    }

    /// The path the folder was reached by, normalised (`RootPath::new`): the chosen path of a
    /// manual folder, `<library>\steamapps\common\<installdir>` with the library's path as
    /// Steam names it. Other than [`Self::path`] (compared folded) when a link, a junctioned
    /// library or an 8.3 name lies on the way (P2-11: `compat_layer` refuses such a folder
    /// until the Sandbox shows which name Windows matches, user decision E3). `None` if that
    /// path is no `RootPath` (a library path that makes it longer than allowed, review S-a).
    /// Read only; never used to reach a file.
    pub fn launch_path(&self) -> Option<&RootPath> {
        self.opened_as.as_ref()
    }

    /// Canonical path as of opening.
    pub fn path(&self) -> &RootPath {
        &self.path
    }

    /// Identity.
    pub fn id(&self) -> RootId {
        RootId::of(&self.info)
    }

    /// Properties as of opening.
    pub fn info(&self) -> &RootInfo {
        &self.info
    }

    /// The handle, read side only.
    pub fn dir(&self) -> &dyn Dir {
        &*self.dir
    }

    /// The handle with the write capability, for the executor and the journal only
    /// (ADR 0020). `Unsupported` on a volume without POSIX delete and rename semantics (FAT,
    /// exFAT; ADR 0017), as of opening; `sys` checks again per operation.
    pub(crate) fn dir_write(&self) -> SysResult<&dyn DirWrite> {
        if !self.info.supports_posix_rename {
            return Err(SysError::new(
                SysErrorKind::Unsupported,
                format!(
                    "{}: volume without POSIX delete and rename (FAT, exFAT)",
                    self.path
                ),
            ));
        }
        Ok(&*self.dir)
    }
}

#[cfg(test)]
mod tests;
