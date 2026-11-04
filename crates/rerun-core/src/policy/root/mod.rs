//! Roots: the only way to open a store or game folder (ADR 0007 and its amendment).
//!
//! - [`StoreDir`]: a store folder (Steam and its libraries), opened by absolute path. It
//!   may be reached through a junction (moved library); the canonical path is checked.
//! - [`GameDir`]: a game folder. From a store it is opened **handle-relative**
//!   (`steamapps\common\<installdir>`), so a junction at the game level is reported as
//!   [`RootError::Reparse`] and never becomes a root. A manually added folder is opened by
//!   absolute path like a store ([`GameOrigin::Manual`]).
//! - [`ForbiddenRoots`]: the forbidden-root list, resolved from known folders. Every root is
//!   checked lexically before it is opened and canonically after; the canonical check is the
//!   one that counts.
//! - [`RootId`]: volume serial and file ID. Plans store it; apply and revert reopen the root
//!   and abort on a mismatch ([`StoreDir::ensure_id`], [`GameDir::ensure_id`]).
//!
//! `open_abs` in this module is the only caller of [`crate::sys::Fs::open_dir`] outside
//! `sys` (enforced by `clippy.toml`).

mod forbidden;

use std::fmt;
use std::path::Path;

pub use forbidden::{Forbidden, ForbiddenRoots, Protected};

use crate::path::{Anomaly, PathError, RelPath, RootPath, classify};
use crate::sys::fs::RootInfo;
use crate::sys::{Dir, SysError, SysErrorKind, SysResult, System};

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
fn open_abs<'s>(sys: &'s dyn System, abs: &Path) -> SysResult<Box<dyn Dir + 's>> {
    sys.fs().open_dir(abs)
}

/// Opens a root by absolute path: lexical check, open, canonical check.
fn open_checked<'s>(
    sys: &'s dyn System,
    fr: &ForbiddenRoots,
    abs: &Path,
) -> Result<(Box<dyn Dir + 's>, RootPath, RootInfo), RootError> {
    let lexical = RootPath::new(abs)?;
    fr.check(&lexical).map_err(|reason| RootError::Forbidden {
        path: lexical.clone(),
        reason,
    })?;
    let dir = open_abs(sys, lexical.path())?;
    let info = dir.info()?;
    let path = RootPath::from_final_path(&info.final_path)?;
    check_canonical(fr, &path, &info)?;
    Ok((dir, path, info))
}

fn check_canonical(fr: &ForbiddenRoots, path: &RootPath, info: &RootInfo) -> Result<(), RootError> {
    let verdict = if info.volume_root {
        Err(Forbidden::VolumeRoot)
    } else {
        fr.check(path)
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

/// A store folder (Steam folder or library).
#[derive(Debug)]
pub struct StoreDir<'s> {
    dir: Box<dyn Dir + 's>,
    path: RootPath,
    info: RootInfo,
}

impl<'s> StoreDir<'s> {
    /// Opens a store folder by absolute path (from the registry or `libraryfolders.vdf`).
    /// Follows junctions above and at the store folder; checks the canonical path.
    pub fn open(sys: &'s dyn System, fr: &ForbiddenRoots, abs: &Path) -> Result<Self, RootError> {
        let (dir, path, info) = open_checked(sys, fr, abs)?;
        Ok(Self { dir, path, info })
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
        let store_now = RootPath::from_final_path(&self.dir.info()?.final_path)?;
        if store_now != self.path {
            return Err(RootError::StoreMoved {
                was: self.path.clone(),
                now: store_now,
            });
        }

        let rel = common.child(seg.as_str())?;
        let dir = self.dir.open_dir(&rel).map_err(reparse(&rel))?;
        let info = dir.info()?;

        // Case-sensitive `common` is an anomaly. Checked after the game is open, on the
        // `common` that holds this very game folder (same file ID under the same name), so
        // swapping `common` between check and open cannot slip through.
        let common_dir = self.dir.open_dir(&common).map_err(reparse(&common))?;
        if common_dir.info()?.case_sensitive {
            classify(installdir, true)?;
        }
        let entry = common_dir
            .metadata(&RelPath::from_segment(seg.as_str())?)
            .map_err(reparse(&rel))?;
        if entry.is_none_or(|m| m.file_id != info.file_id) {
            return Err(RootError::Sys(SysError::new(
                SysErrorKind::NotFound,
                format!("{rel} changed while opening"),
            )));
        }

        let path = RootPath::from_final_path(&info.final_path)?;
        let expected = self
            .path
            .child("steamapps")?
            .child("common")?
            .child(seg.as_str())?;
        if path != expected || info.volume_serial != self.info.volume_serial {
            return Err(RootError::Escaped {
                store: self.path.clone(),
                child: path,
            });
        }
        check_canonical(fr, &path, &info)?;
        Ok(GameDir {
            dir,
            path,
            info,
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

    /// The handle.
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
    dir: Box<dyn Dir + 'a>,
    path: RootPath,
    info: RootInfo,
    origin: GameOrigin,
}

impl<'a> GameDir<'a> {
    /// Opens a manually added game folder by absolute path, like a store root.
    pub fn open_manual(
        sys: &'a dyn System,
        fr: &ForbiddenRoots,
        abs: &Path,
    ) -> Result<Self, RootError> {
        let (dir, path, info) = open_checked(sys, fr, abs)?;
        Ok(Self {
            dir,
            path,
            info,
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

    /// The handle.
    pub fn dir(&self) -> &dyn Dir {
        &*self.dir
    }
}

#[cfg(test)]
mod tests;
