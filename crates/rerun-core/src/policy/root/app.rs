//! [`AppDir`]: Rerun's own folder `<LocalAppData>\Rerun` (ADR 0019), the third root kind.
//!
//! Opening (ADR 0019, P2-6):
//! 1. `LocalAppData` comes from [`KnownFolders`](crate::sys::KnownFolders) (process token,
//!    never the environment), passes [`RootPath::new`] lexically and is opened by absolute
//!    path like a store root, so a redirection above it is followed. Its canonical path must
//!    pass [`RootPath::from_final_path`] (drive letter, no network) and must not be a volume
//!    root. It is **not** checked against [`ForbiddenRoots`](super::ForbiddenRoots): the
//!    `LocalAppData\Rerun` entry there keeps game and store roots out of this folder.
//! 2. `Rerun` is opened **relative** to that handle with the write capability, never
//!    following a reparse point ([`RootError::Reparse`]). If it is missing and the caller
//!    asked for [`Create::IfMissing`], it is created with `create_dir` and opened again; a
//!    different file ID than the one `create_dir` returned is `Busy` (swapped in between).
//! 3. The handle that is kept is opened by its canonical absolute path (a handle opened
//!    relative to the `LocalAppData` handle would borrow it) and must be the same directory
//!    as the relative open (volume serial and file ID, else `Busy`), at exactly
//!    `<canonical LocalAppData>\Rerun` on the same volume (else [`RootError::Escaped`]).
//!
//! Below it, [`AppDir::sub`] and [`AppDir::sub_write`] open `journal`, `plans` and
//! `packages` (and `launch`, read side only) the same way, one directory at a time. Nothing
//! persisted refers to an `AppDir`, so it has no `ensure_id`; [`AppDir::id`] is for snapshots
//! and display.

use super::{Forbidden, RootError, RootId, open_abs_write};
use crate::path::{RelPath, RootPath};
use crate::sys::fs::RootInfo;
use crate::sys::{Dir, DirWrite, KnownFolder, SysError, SysErrorKind, SysResult, System};

/// Name of Rerun's folder below `LocalAppData`.
const RERUN: &str = "Rerun";

/// Whether a missing folder is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Create {
    /// Never create; a missing folder is `Ok(None)` (`status`, `plan --dry-run`).
    Never,
    /// Create the folder (one level) if it is missing.
    IfMissing,
}

/// A fixed folder below [`AppDir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppSub {
    /// `journal` (ADR 0019).
    Journal,
    /// `plans` (ADR 0020).
    Plans,
    /// `packages` (ADR 0020, D11).
    Packages,
    /// `launch`: the result files of `rerun-launch` (ADR 0022 amendment P3-2); read only
    /// here, the shim writes them.
    Launch,
}

impl AppSub {
    fn rel(self) -> RelPath {
        let name = match self {
            Self::Journal => "journal",
            Self::Plans => "plans",
            Self::Packages => "packages",
            Self::Launch => "launch",
        };
        match RelPath::from_segment(name) {
            Ok(p) => p,
            Err(e) => unreachable!("{name} is a fixed valid segment: {e}"),
        }
    }
}

/// Opens the child directory `name` of `parent` with the write capability, never following
/// a reparse point; creates it first if it is missing and `create` says so.
pub(super) fn open_or_create<'d>(
    parent: &'d dyn DirWrite,
    name: &RelPath,
    create: Create,
    store: &RootPath,
) -> Result<Option<Box<dyn DirWrite + 'd>>, RootError> {
    let reparse = |e: SysError| {
        if e.kind == SysErrorKind::ReparsePoint {
            RootError::Reparse {
                store: store.clone(),
                at: name.clone(),
            }
        } else {
            RootError::Sys(e)
        }
    };
    match parent.open_dir_write(name) {
        Ok(d) => return Ok(Some(d)),
        Err(e) if e.kind == SysErrorKind::NotFound && create == Create::IfMissing => {}
        Err(e) if e.kind == SysErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(reparse(e)),
    }
    let created = match parent.create_dir(name) {
        Ok(id) => Some(id),
        // Created by someone else in between: open it like an existing one.
        Err(e) if e.kind == SysErrorKind::AlreadyExists => None,
        Err(e) => return Err(RootError::Sys(e)),
    };
    let dir = parent.open_dir_write(name).map_err(reparse)?;
    if let Some(id) = created
        && dir.info()?.file_id != id
    {
        return Err(RootError::Sys(SysError::new(
            SysErrorKind::Busy,
            format!("{name} below {store} changed while it was created"),
        )));
    }
    Ok(Some(dir))
}

/// Rerun's own folder `<LocalAppData>\Rerun` (ADR 0019).
#[derive(Debug)]
pub struct AppDir<'s> {
    dir: Box<dyn DirWrite + 's>,
    path: RootPath,
    info: RootInfo,
}

impl<'s> AppDir<'s> {
    /// Opens `<LocalAppData>\Rerun` (module docs). `Ok(None)`: it is missing and `create` is
    /// [`Create::Never`]; nothing is created then.
    pub fn open(sys: &'s dyn System, create: Create) -> Result<Option<Self>, RootError> {
        let lad = sys.known_folders().get(KnownFolder::LocalAppData)?;
        let lexical = RootPath::new(&lad)?;
        let base = open_abs_write(sys, lexical.path())?;
        let base_info = base.info()?;
        let base_path = RootPath::from_final_path(&base_info.final_path)?;
        if base_info.volume_first_segment().is_none() {
            return Err(RootError::Forbidden {
                path: base_path,
                reason: Forbidden::VolumeRoot,
            });
        }
        let name = RelPath::from_segment(RERUN)?;
        let Some(rel) = open_or_create(&*base, &name, create, &base_path)? else {
            return Ok(None);
        };
        let rel_id = RootId::of(&rel.info()?);
        let expected = base_path.child(RERUN)?;
        let dir = open_abs_write(sys, expected.path())?;
        let info = dir.info()?;
        if RootId::of(&info) != rel_id {
            return Err(RootError::Sys(SysError::new(
                SysErrorKind::Busy,
                format!("{expected} changed while it was opened"),
            )));
        }
        let path = RootPath::from_final_path(&info.final_path)?;
        if path != expected || info.volume_serial != base_info.volume_serial {
            return Err(RootError::Escaped {
                store: base_path,
                child: path,
            });
        }
        Ok(Some(Self { dir, path, info }))
    }

    /// Canonical path as of opening.
    pub fn path(&self) -> &RootPath {
        &self.path
    }

    /// Identity (for snapshots and display; nothing persisted refers to it).
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

impl AppDir<'_> {
    /// The handle with the write capability, for the journal and plan storage only
    /// (`clippy.toml`). `Unsupported` on a volume without POSIX delete and rename semantics
    /// (FAT, exFAT; ADR 0017), as of opening; `sys` checks again per operation.
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

    /// Opens (and with [`Create::IfMissing`] creates) the folder `s` with the write
    /// capability, handle-relative; a reparse point there is [`RootError::Reparse`].
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0019: the sub folders of AppDir are opened through its write handle"
    )]
    pub(crate) fn sub_write(
        &self,
        s: AppSub,
        create: Create,
    ) -> Result<Option<Box<dyn DirWrite + '_>>, RootError> {
        open_or_create(self.dir_write()?, &s.rel(), create, &self.path)
    }

    /// Opens the folder `s` read-only, handle-relative. `Ok(None)` if it is missing; a
    /// reparse point there is [`RootError::Reparse`].
    pub(crate) fn sub(&self, s: AppSub) -> Result<Option<Box<dyn Dir + '_>>, RootError> {
        let at = s.rel();
        match self.dir.open_dir(&at) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.kind == SysErrorKind::NotFound => Ok(None),
            Err(e) if e.kind == SysErrorKind::ReparsePoint => Err(RootError::Reparse {
                store: self.path.clone(),
                at,
            }),
            Err(e) => Err(RootError::Sys(e)),
        }
    }
}

#[cfg(test)]
mod tests;
