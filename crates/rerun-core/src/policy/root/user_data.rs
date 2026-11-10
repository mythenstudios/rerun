//! [`UserDataDir`]: a game's own folder below the user's `Documents` (P4-12, ADR 0007 amendment
//! P4-12, user decision D6), the fourth root kind. The base comes from a known folder
//! ([`UserBase`]; v1 only `Documents`), the folder below it from a signed Topo or a step file
//! (`My Games\Fallout3`): never the known folder itself, never created by Rerun (the game
//! creates it on its first start, like the INI file inside it).
//!
//! Rules, in this order (each one fails closed):
//! 1. **The folder below the base** passes [`user_dir_ok`] (pure; also the plan fence and the
//!    Topo loader): 1 to [`MAX_USER_DIR_SEGS`] plain segments ([`classify`]), not the shared
//!    container `My Games` alone, not below `WindowsPowerShell` or `PowerShell` (profile
//!    scripts are code).
//! 2. **The base** comes from [`KnownFolders`](crate::sys::KnownFolders) (process token, never
//!    the environment, never `User Shell Folders` raw), passes [`RootPath::new`] lexically
//!    (a share, an 8.3 name, a drive root are `InvalidPath`) and the forbidden list, and is
//!    opened by absolute path like a store (a junction at or above it is followed: Documents
//!    moved to `D:\Docs`). Its canonical path must be a drive-letter path (a mapped drive ends
//!    as `\\?\UNC\…`: refused), no volume root, and pass the forbidden list again: `Documents`
//!    that is the profile itself, lies in another user's or the `Public` profile, in
//!    `$Recycle.Bin`, … is refused. **In addition** to the allowlist of rule 1, not instead
//!    of it (ADR 0007 amendment P4-12).
//! 3. **The folder** is opened **relative** to the base's handle, one segment at a time,
//!    never following a reparse point ([`RootError::Reparse`]: a junction at `My Games` or at
//!    the folder itself, the legacy junctions `My Music` and friends); every folder on the
//!    way and the folder itself must not be case-sensitive. The handle kept is opened by its
//!    canonical absolute path and must be the same directory as the relative open (volume
//!    serial and file ID, else `Busy`), at exactly `<canonical base>\<sub>` on the same volume
//!    (else [`RootError::Escaped`]), and pass the forbidden list. It must be writable by the
//!    current user: the elevated helper never writes a user folder.
//! 4. **No cloud sync** (D6): two independent signals, either refuses
//!    ([`RootError::CloudSynced`]): (a) the base, a folder on the way or the folder itself is
//!    part of a cloud files sync root (`RootInfo::cloud`: a cloud files tag or a recall, offline
//!    or pin attribute of its handle); (b) a registered sync root
//!    (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\*\UserSyncRoots`,
//!    every SID, `REG_SZ` only, at most [`MAX_SYNC_PROVIDERS`] keys of
//!    [`MAX_SYNC_ROOTS_PER_KEY`] values) contains the base (lexical or canonical) or the
//!    folder. A missing `SyncRootManager` is "none"; one that cannot be read refuses. No path
//!    name heuristic, never `%OneDrive%`. The INI file below the folder is refused as a cloud
//!    placeholder by `ini_set` and `exec` already.
//!
//! The plan names the folder by its canonical path and identity (`PlanOrigin::UserFolder`);
//! apply and revert open it again through [`UserDataDir::open`] and compare both (`exec`): a
//! base that resolves elsewhere now is refused, never rebound (ADR 0020 amendment P4-12).

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{ForbiddenRoots, RootError, RootId, check_canonical, ensure, open_abs_write, raced};
use crate::fold::fold;
use crate::path::{RelPath, RootPath, classify};
use crate::sys::fs::RootInfo;
use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
use crate::sys::{Dir, DirWrite, KnownFolder, SysError, SysErrorKind, SysResult, System};

/// Most segments of the folder below the base.
pub const MAX_USER_DIR_SEGS: usize = 4;

/// Most provider keys below `SyncRootManager` read (more: refused, fail closed).
pub const MAX_SYNC_PROVIDERS: usize = 256;

/// Most values of one `UserSyncRoots` key read (more: refused, fail closed).
pub const MAX_SYNC_ROOTS_PER_KEY: usize = 64;

/// The key of the registered cloud sync roots (Cloud Files API; written by the providers'
/// installers, `HKLM`).
pub const SYNC_ROOT_MANAGER: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager";

/// The known folder a user data folder lies in. v1: only `Documents` (user decision U2 a);
/// another base is one more variant with its own checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserBase {
    /// `FOLDERID_Documents`.
    Documents,
}

impl UserBase {
    /// The known folder.
    pub fn known_folder(self) -> KnownFolder {
        match self {
            Self::Documents => KnownFolder::Documents,
        }
    }

    /// The name on the wire (`documents`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Documents => "documents",
        }
    }
}

impl fmt::Display for UserBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Documents => "your Documents folder",
        })
    }
}

/// Why a folder below a base is not allowed ([`user_dir_ok`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UserDirError {
    /// More than [`MAX_USER_DIR_SEGS`] segments.
    #[error("at most {MAX_USER_DIR_SEGS} folders below the base")]
    TooDeep,
    /// Only a container several games share (`My Games`): name the game's own folder below it.
    #[error("a folder several games share; name the game's own folder below it")]
    SharedContainer,
    /// A folder that is not a game's.
    #[error("{0}")]
    Denied(&'static str),
}

/// Folder names never allowed as the first segment (folded): profile scripts are code.
const DENIED_FIRST: [&str; 2] = ["WINDOWSPOWERSHELL", "POWERSHELL"];

/// Containers shared by many games (folded): allowed only with a folder below them.
const SHARED: [&str; 1] = ["MY GAMES"];

/// The allowlist of a folder below `base` (module docs, rule 1). Pure.
pub fn user_dir_ok(base: UserBase, sub: &RelPath) -> Result<(), UserDirError> {
    match base {
        UserBase::Documents => {}
    }
    let segs: Vec<&str> = sub.segments().collect();
    if segs.len() > MAX_USER_DIR_SEGS {
        return Err(UserDirError::TooDeep);
    }
    for s in &segs {
        if classify(s, false).is_err() {
            return Err(UserDirError::Denied("a folder name that is no plain name"));
        }
    }
    let first = segs.first().map(|s| fold(s)).unwrap_or_default();
    if DENIED_FIRST.contains(&first.as_str()) {
        return Err(UserDirError::Denied(
            "PowerShell's folder holds profile scripts, not game data",
        ));
    }
    if segs.len() == 1 && SHARED.contains(&first.as_str()) {
        return Err(UserDirError::SharedContainer);
    }
    Ok(())
}

/// Why a folder counts as cloud-synchronised ([`RootError::CloudSynced`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloudWhy {
    /// The folder (the base, one on the way, or the user data folder) is part of a cloud files
    /// sync root: a cloud files tag or a recall, offline or pin attribute of its handle.
    Folder(RootPath),
    /// A registered sync root (`SyncRootManager`) contains it.
    SyncRoot(RootPath),
}

impl fmt::Display for CloudWhy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Folder(p) => write!(f, "{p} is a cloud files folder"),
            Self::SyncRoot(p) => write!(f, "it lies in the sync root {p}"),
        }
    }
}

/// A game's folder below a known folder of the user (module docs).
#[derive(Debug)]
pub struct UserDataDir<'s> {
    dir: Box<dyn DirWrite + 's>,
    path: RootPath,
    info: RootInfo,
    base: UserBase,
    sub: RelPath,
}

/// Opens `name` (relative to `parent`, never through a reparse point), read side.
fn open_rel<'d>(
    parent: &'d dyn Dir,
    at: &RelPath,
    base: &RootPath,
) -> Result<Box<dyn Dir + 'd>, RootError> {
    parent.open_dir(at).map_err(|e| {
        if e.kind == SysErrorKind::ReparsePoint {
            RootError::Reparse {
                store: base.clone(),
                at: at.clone(),
            }
        } else {
            RootError::Sys(e)
        }
    })
}

/// A folder on the way (or the folder) that refuses: case-sensitive, or cloud.
fn plain(path: &RootPath, info: &RootInfo, what: &RelPath) -> Result<(), RootError> {
    if info.case_sensitive {
        // The same anomaly as a case-sensitive `steamapps\common`.
        classify(what.file_name(), true)?;
    }
    if info.cloud && !knob::cloud_unchecked() {
        return Err(RootError::CloudSynced {
            path: path.clone(),
            why: CloudWhy::Folder(path.clone()),
        });
    }
    Ok(())
}

impl<'s> UserDataDir<'s> {
    /// Opens `<base>\<sub>` (module docs).
    pub fn open(
        sys: &'s dyn System,
        fr: &ForbiddenRoots,
        base: UserBase,
        sub: &RelPath,
    ) -> Result<Self, RootError> {
        user_dir_ok(base, sub).map_err(|why| RootError::UserDir {
            sub: sub.clone(),
            why,
        })?;
        // Rule 2: the base.
        let raw = sys.known_folders().get(base.known_folder())?;
        let lexical = RootPath::new(&raw)?;
        fr.check(&lexical).map_err(|reason| RootError::Forbidden {
            path: lexical.clone(),
            reason,
        })?;
        let docs = open_abs_write(sys, lexical.path())?;
        let docs_info = docs.info().map_err(raced)?;
        let docs_path = RootPath::from_final_path(&docs_info.final_path)?;
        check_canonical(fr, &docs_path, &docs_info)?;
        if docs_info.case_sensitive {
            return Err(RootError::Anomaly(crate::path::Anomaly {
                name: base.known_folder().to_string(),
                reason: "a case-sensitive folder",
            }));
        }
        if docs_info.cloud && !knob::cloud_unchecked() {
            return Err(RootError::CloudSynced {
                path: docs_path.clone(),
                why: CloudWhy::Folder(docs_path),
            });
        }
        // Rule 3: the folder, one segment at a time below the base's handle.
        let mut at: Option<RelPath> = None;
        let mut expected = docs_path.clone();
        for seg in sub.segments() {
            let next = match &at {
                None => RelPath::from_segment(seg)?,
                Some(p) => p.child(seg)?,
            };
            expected = expected.child(seg)?;
            let d = open_rel(&*docs, &next, &docs_path)?;
            let info = d.info().map_err(raced)?;
            plain(&expected, &info, &next)?;
            at = Some(next);
        }
        let rel = open_rel(&*docs, sub, &docs_path)?;
        let rel_id = RootId::of(&rel.info().map_err(raced)?);
        drop(rel);
        let dir = open_abs_write(sys, expected.path())?;
        let info = dir.info().map_err(raced)?;
        if RootId::of(&info) != rel_id {
            return Err(RootError::Sys(SysError::new(
                SysErrorKind::Busy,
                format!("{expected} changed while it was opened"),
            )));
        }
        let path = RootPath::from_final_path(&info.final_path)?;
        if path != expected || info.volume_serial != docs_info.volume_serial {
            return Err(RootError::Escaped {
                store: docs_path,
                child: path,
            });
        }
        check_canonical(fr, &path, &info)?;
        plain(&path, &info, sub)?;
        if !info.user_writable {
            return Err(RootError::Sys(SysError::new(
                SysErrorKind::AccessDenied,
                format!("{path} cannot be written by the current user"),
            )));
        }
        // Rule 4 (b): the registered sync roots.
        if !knob::cloud_unchecked() {
            for sr in sync_roots(sys)? {
                for p in [&lexical, &docs_path, &path] {
                    if sr.contains(p) {
                        return Err(RootError::CloudSynced {
                            path: p.clone(),
                            why: CloudWhy::SyncRoot(sr),
                        });
                    }
                }
            }
        }
        Ok(Self {
            dir,
            path,
            info,
            base,
            sub: sub.clone(),
        })
    }

    /// Aborts unless this is the directory recorded in a plan.
    pub fn ensure_id(&self, expected: RootId) -> Result<(), RootError> {
        ensure(&self.path, &self.info, expected)
    }

    /// Canonical path as of opening (`<canonical base>\<sub>`).
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

    /// The base.
    pub fn base(&self) -> UserBase {
        self.base
    }

    /// The folder below the base, as named by the Topo or step file.
    pub fn sub(&self) -> &RelPath {
        &self.sub
    }

    /// The handle, read side only.
    pub fn dir(&self) -> &dyn Dir {
        &*self.dir
    }

    /// The handle with the write capability, for `exec` only (`clippy.toml`). `Unsupported` on
    /// a volume without POSIX delete and rename semantics (exFAT on a USB drive), as for a game
    /// folder.
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

/// The registered cloud sync roots (module docs, rule 4 b): every `REG_SZ` of every
/// `SyncRootManager\<provider>\UserSyncRoots` that is a drive-letter path. A missing
/// `SyncRootManager` or `UserSyncRoots` is none; any other failure, or more than the bounds,
/// refuses.
pub fn sync_roots(sys: &dyn System) -> Result<Vec<RootPath>, RootError> {
    let reg = sys.registry();
    let top = RegKey::new(Hive::LocalMachine, RegView::Native, SYNC_ROOT_MANAGER);
    let providers = match reg.subkeys(&top) {
        Ok(p) => p,
        Err(e) if e.kind == SysErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(RootError::Sys(e)),
    };
    if providers.len() > MAX_SYNC_PROVIDERS {
        return Err(RootError::Sys(SysError::too_large(
            "SyncRootManager",
            u64::try_from(MAX_SYNC_PROVIDERS).unwrap_or(u64::MAX),
        )));
    }
    let mut out = Vec::new();
    for p in providers {
        let k = top.join(&p).join("UserSyncRoots");
        let values = match reg.values(&k) {
            Ok(v) => v,
            Err(e) if e.kind == SysErrorKind::NotFound => continue,
            Err(e) => return Err(RootError::Sys(e)),
        };
        if values.len() > MAX_SYNC_ROOTS_PER_KEY {
            return Err(RootError::Sys(SysError::too_large(
                "SyncRootManager UserSyncRoots",
                u64::try_from(MAX_SYNC_ROOTS_PER_KEY).unwrap_or(u64::MAX),
            )));
        }
        for (_, v) in values {
            // Only a string names a folder; a share or any other form cannot contain a
            // drive-letter folder.
            let RegValue::String(s) = v else { continue };
            if let Ok(r) = RootPath::new(&s).or_else(|_| RootPath::from_final_path(&s)) {
                out.push(r);
            }
        }
    }
    Ok(out)
}

/// The test knob of control K-U1 (ADR 0007 amendment P4-12): both cloud signals off.
#[cfg(test)]
pub(crate) mod knob {
    use std::cell::Cell;

    thread_local! {
        static CLOUD_UNCHECKED: Cell<bool> = const { Cell::new(false) };
    }

    /// K-U1: the cloud checks are skipped.
    pub(crate) fn uncheck_cloud(on: bool) {
        CLOUD_UNCHECKED.with(|s| s.set(on));
    }
    pub(crate) fn cloud_unchecked() -> bool {
        CLOUD_UNCHECKED.with(Cell::get)
    }
}

#[cfg(not(test))]
mod knob {
    pub(super) fn cloud_unchecked() -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
