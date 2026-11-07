//! The checks before anything is written (ADR 0020, "Apply", steps 3 to 5): every root
//! reopened through `policy::root` and checked by identity, the Steam app state re-read, the
//! game closed (`users()` of every existing target and each main executable, user decision
//! D4), and the old state of every op and every source re-observed (`Mismatch`).
//!
//! Roots (P2-10a, user decisions 6b-d and E3): an apply needs every root open, and writable
//! if it has file ops (S1: D4 needs read access only), and the main executable of every root
//! a plain file there (audit A2 should-item 8; a revert tolerates a missing one)
//! ([`Roots::all`], [`main_exe_present`]). A revert and `verify` open each root on its own ([`Roots::each`]) and
//! sort it:
//! - **open**: reopened and checked by identity. If the current user cannot write it (or its
//!   volume lacks POSIX semantics), its file ops cannot run; D4 still asks it.
//! - **absent**: gone. A manual folder or a Steam library whose path is not found, a Steam app
//!   without manifest, installed in another folder, not installed, or whose folder is not
//!   found. Only a `NotFound` of the open itself: `policy::root` reports a folder that changes
//!   while it is opened as `Busy` (review S-1). No D4 for it; its file ops cannot run.
//! - **undecided**: anything else (an update pending, a manifest that cannot be read now, a
//!   folder that is another one now (`IdentityMismatch`; after a reinstall too, until a rebind,
//!   D5), busy, access denied, a reparse point, forbidden): the revert is refused before any
//!   change.
//!
//! The revert loop halts at the newest file op whose root cannot run file ops, without a
//! record (`exec::Halt`).
//!
//! Every root is opened where it is bound (`exec::bind`, P2-14): the head's root, or the folder
//! the last `Rebind` of that root names; messages name the bound path.

use super::bind::{Binding, Bindings, Proof};
use super::{ExecCtx, Refusal, op_ix};
use crate::detect::steam::{AppState, app_manifest};
use crate::escape;
use crate::path::{RelPath, RootPath};
use crate::plan::{ContentRef, Op, Plan, PlanOrigin, Target};
use crate::policy::registry::RegSlot;
use crate::policy::root::{AppSub, GameDir, RootError, StoreDir};
use crate::prim::file_install::{hash_file, open_package};
use crate::sys::fs::FileGuard;
use crate::sys::{DirWrite, SysErrorKind};

/// The store of each Steam root as bound (`None` for a manual one), reopened and checked by
/// identity; an error stays with its root.
pub(super) fn open_stores<'s>(
    cx: &ExecCtx<'s>,
    b: &Bindings,
) -> Vec<Option<Result<StoreDir<'s>, RootError>>> {
    b.iter()
        .map(|r| match &r.origin {
            PlanOrigin::Steam {
                store, store_id, ..
            } => Some(StoreDir::open(cx.sys, cx.fr, store.path()).and_then(|s| {
                s.ensure_id(*store_id)?;
                Ok(s)
            })),
            PlanOrigin::Manual => None,
        })
        .collect()
}

/// Why the file ops of a root cannot run (a clonable [`Refusal`] for [`super::Halt`]).
#[derive(Debug, Clone)]
pub(super) enum NoFiles {
    /// The root cannot be opened, is gone, or cannot be written (POSIX semantics).
    Root(Box<RootError>),
    /// The Steam app is gone: no manifest, installed in another folder, or not installed.
    Steam {
        /// The app.
        app_id: u32,
        /// Which of the three.
        gone: super::SteamGone,
    },
    /// The current user cannot write the root (phase 3: the elevated helper).
    NeedsHelper,
}

impl NoFiles {
    /// As a refusal.
    pub(super) fn refusal(&self) -> Refusal {
        match self {
            Self::Root(e) => Refusal::Root(e.clone()),
            Self::Steam {
                app_id,
                gone: super::SteamGone::NotInstalled,
            } => Refusal::Steam {
                app_id: *app_id,
                state: AppState::NotInstalled,
            },
            Self::Steam { app_id, gone } => Refusal::SteamGone {
                app_id: *app_id,
                gone: *gone,
            },
            Self::NeedsHelper => Refusal::NeedsHelper,
        }
    }
}

/// One root of a plan as reopened.
#[expect(
    clippy::large_enum_variant,
    reason = "one per root of a plan (at most 16), never moved after opening"
)]
enum Slot<'g> {
    /// Opened and checked by identity; `no_files`: why its file ops cannot run.
    Open {
        game: GameDir<'g>,
        no_files: Option<NoFiles>,
    },
    /// Gone (E3): no D4, no file ops.
    Absent(NoFiles),
}

/// The roots of a plan as reopened, by index, where they are bound (P2-14).
pub(super) struct Roots<'g> {
    slots: Vec<Slot<'g>>,
    /// The bound path of each root (messages).
    paths: Vec<RootPath>,
    /// How the created folders of each root are proven.
    proofs: Vec<Proof>,
}

/// Why a root did not open: gone, or undecided (E3).
enum Failed {
    Absent(NoFiles),
    Undecided(Refusal),
}

impl<'g> Roots<'g> {
    /// Apply: every root open and checked by identity, and writable if a file op targets it
    /// (S1); else its refusal, stores first, then the roots in order.
    pub(super) fn all(
        cx: &ExecCtx<'g>,
        plan: &Plan,
        b: &Bindings,
        stores: &'g [Option<Result<StoreDir<'g>, RootError>>],
    ) -> Result<Self, Refusal> {
        for s in stores.iter().flatten() {
            if let Err(e) = s {
                return Err(e.clone().into());
            }
        }
        let mut slots = Vec::with_capacity(b.len());
        for (i, (r, store)) in b.iter().zip(stores).enumerate() {
            let game = open_root(cx, r, store.as_ref()).map_err(|f| match f {
                Failed::Absent(n) => n.refusal(),
                Failed::Undecided(r) => r,
            })?;
            let no_files = no_files(&game);
            if let Some(n) = &no_files
                && has_file_ops(plan, i)
            {
                return Err(n.refusal());
            }
            slots.push(Slot::Open { game, no_files });
        }
        Ok(Self::new(slots, b))
    }

    /// Revert and verify: each root on its own (module docs, E3); an undecided one refuses.
    pub(super) fn each(
        cx: &ExecCtx<'g>,
        b: &Bindings,
        stores: &'g [Option<Result<StoreDir<'g>, RootError>>],
    ) -> Result<Self, Refusal> {
        let mut slots = Vec::with_capacity(b.len());
        for (r, store) in b.iter().zip(stores) {
            let slot = match open_root(cx, r, store.as_ref()) {
                Ok(game) => Slot::Open {
                    no_files: no_files(&game),
                    game,
                },
                Err(Failed::Absent(n)) => Slot::Absent(n),
                Err(Failed::Undecided(r)) => return Err(r),
            };
            slots.push(slot);
        }
        #[cfg(test)]
        if super::knob::opening_eagerly() {
            // K-R9: the roots as before P2-10a, every one must open for file ops.
            for s in &slots {
                match s {
                    Slot::Open { no_files: None, .. } => {}
                    Slot::Open {
                        no_files: Some(n), ..
                    }
                    | Slot::Absent(n) => return Err(n.refusal()),
                }
            }
        }
        Ok(Self::new(slots, b))
    }

    fn new(slots: Vec<Slot<'g>>, b: &Bindings) -> Self {
        Self {
            slots,
            paths: b.iter().map(|r| r.path.clone()).collect(),
            proofs: b.iter().map(|r| r.proof.clone()).collect(),
        }
    }

    /// How the created folders of root `i` are proven (P2-14).
    pub(super) fn proof(&self, i: u16) -> &Proof {
        self.proofs.get(usize::from(i)).unwrap_or(&Proof::Done)
    }

    /// From now on, the created folders of root `i` are proven by `p` (a rebind once its record
    /// is written: the folder stays the one opened, its proofs the recorded file IDs).
    pub(super) fn set_proof(&mut self, i: u16, p: Proof) {
        if let Some(x) = self.proofs.get_mut(usize::from(i)) {
            *x = p;
        }
    }

    /// `<root>\<path>` for a message, with the bound path of the root.
    pub(super) fn shown(&self, root: usize, p: &RelPath) -> escape::Shown<'static> {
        let base = self
            .paths
            .get(root)
            .map(ToString::to_string)
            .unwrap_or_default();
        escape::path(&format!(r"{base}\{p}")).into_owned()
    }

    /// The open root `i` (D4 asks it), `None` if it is absent.
    pub(super) fn game(&self, i: usize) -> Option<&GameDir<'g>> {
        match self.slots.get(i)? {
            Slot::Open { game, .. } => Some(game),
            Slot::Absent(_) => None,
        }
    }

    /// Root `i` for file ops, or why its file ops cannot run.
    pub(super) fn for_files(&self, i: usize) -> Result<&GameDir<'g>, NoFiles> {
        match self.slots.get(i) {
            Some(Slot::Open {
                game,
                no_files: None,
            }) => Ok(game),
            Some(
                Slot::Open {
                    no_files: Some(n), ..
                }
                | Slot::Absent(n),
            ) => Err(n.clone()),
            None => Err(NoFiles::Root(Box::new(RootError::Sys(
                crate::sys::SysError::new(SysErrorKind::NotFound, "root of the plan"),
            )))),
        }
    }
}

/// A file op of `plan` targets root `i`.
fn has_file_ops(plan: &Plan, i: usize) -> bool {
    plan.ops
        .iter()
        .any(|o| matches!(o.target(), Target::File { root, .. } if usize::from(root.0) == i))
}

/// A2 should-item 8, for an apply: the main executable of every root is a plain file there
/// (not missing, not a folder, link or other reparse point, not restricted); else D4 would
/// ask nothing about it. A revert does not ask this (the game may be gone).
pub(super) fn main_exe_present(plan: &Plan, roots: &Roots<'_>) -> Result<(), Refusal> {
    for i in 0..plan.roots.len() {
        main_exe_at(plan, roots, i)?;
    }
    Ok(())
}

/// A2 should-item 8 for root `i` alone (also the folder a rebind binds, P2-14: a cheap hint that
/// it is the game, and D4 asks it).
pub(super) fn main_exe_at(plan: &Plan, roots: &Roots<'_>, i: usize) -> Result<(), Refusal> {
    let Some(r) = plan.roots.get(i) else {
        return Ok(());
    };
    let (Some(m), Some(g)) = (&r.main_exe, roots.game(i)) else {
        return Ok(());
    };
    match g.dir().metadata(m) {
        Ok(Some(md))
            if md.kind == crate::sys::fs::EntryKind::File
                && md.reparse.is_none()
                && !md.restricted =>
        {
            Ok(())
        }
        Ok(_) => Err(Refusal::MainExe(roots.shown(i, m))),
        Err(e) if matches!(e.kind, SysErrorKind::NotFound | SysErrorKind::ReparsePoint) => {
            Err(Refusal::MainExe(roots.shown(i, m)))
        }
        Err(e) => Err(e.into()),
    }
}

/// How the folder a binding names opens now (P2-14, user decision E-R1), opened and dropped.
#[derive(Debug)]
pub(super) enum Probe {
    /// Opened and checked by identity.
    Opens,
    /// Gone (the library or the folder not found, no manifest, not installed) or another folder
    /// now (`IdentityMismatch` of the library or of the game folder): a rebind may bind it.
    Gone(Refusal),
    /// Anything else (an update pending, installed in another folder, a manifest that cannot
    /// be read, busy, access denied, a reparse point, forbidden): not now.
    Undecided(Refusal),
}

/// [`Probe`] of binding `b` (a Steam root through its library, a manual one by path).
pub(super) fn probe(cx: &ExecCtx<'_>, b: &Binding) -> Probe {
    let store = match &b.origin {
        PlanOrigin::Steam {
            store, store_id, ..
        } => Some(StoreDir::open(cx.sys, cx.fr, store.path()).and_then(|s| {
            s.ensure_id(*store_id)?;
            Ok(s)
        })),
        PlanOrigin::Manual => None,
    };
    let mismatch = |r: &Refusal| matches!(r, Refusal::Root(e) if matches!(**e, RootError::IdentityMismatch { .. }));
    match open_root(cx, b, store.as_ref()) {
        Ok(_) => Probe::Opens,
        Err(Failed::Absent(NoFiles::Steam {
            app_id,
            gone: super::SteamGone::OtherFolder,
        })) => Probe::Undecided(Refusal::SteamGone {
            app_id,
            gone: super::SteamGone::OtherFolder,
        }),
        Err(Failed::Absent(n)) => Probe::Gone(n.refusal()),
        Err(Failed::Undecided(r)) if mismatch(&r) => Probe::Gone(r),
        Err(Failed::Undecided(r)) => Probe::Undecided(r),
    }
}

/// The game folder of the head's Steam root `head` in the library at `lib` (P2-14): the library
/// opened by its path, the head's app installed there with the head's install folder, the
/// folder opened through the library (no reparse point, the forbidden roots), with the
/// identities found. Opened and dropped; the caller opens it again by these identities.
pub(super) fn candidate(
    cx: &ExecCtx<'_>,
    head: &crate::plan::PlanRoot,
    lib: &RootPath,
) -> Result<Binding, super::RebindRefusal> {
    use super::RebindRefusal as R;
    let PlanOrigin::Steam {
        app_id, installdir, ..
    } = &head.origin
    else {
        return Err(R::Manual);
    };
    let not_found =
        |e: &RootError| matches!(e, RootError::Sys(s) if s.kind == SysErrorKind::NotFound);
    let store = StoreDir::open(cx.sys, cx.fr, lib.path()).map_err(|e| {
        if not_found(&e) {
            R::NoCandidate
        } else {
            R::Candidate(Box::new(e.into()))
        }
    })?;
    let app = match app_manifest(&store, *app_id) {
        Ok(Some(a)) => a,
        Ok(None) => return Err(R::NoCandidate),
        Err(_) => {
            return Err(R::Candidate(Box::new(Refusal::SteamManifest {
                app_id: *app_id,
            })));
        }
    };
    if app.install_dir != *installdir {
        return Err(R::OtherInstallDir);
    }
    match app.state() {
        AppState::Installed => {}
        AppState::NotInstalled => return Err(R::NoCandidate),
        AppState::UpdatePending => return Err(R::UpdatePending),
    }
    let game = store.game(cx.fr, installdir.as_str()).map_err(|e| {
        if not_found(&e) {
            R::NoCandidate
        } else {
            R::Candidate(Box::new(e.into()))
        }
    })?;
    Binding::steam(head, store.path(), store.id(), game.id(), Proof::Found).ok_or(R::Candidate(
        Box::new(Refusal::Plan(crate::plan::PlanError::Invalid {
            op: None,
            why: "a game folder path that is no root path",
        })),
    ))
}

/// Why the file ops of an opened root cannot run: the current user cannot write it, or its
/// volume has no POSIX semantics.
fn no_files(game: &GameDir<'_>) -> Option<NoFiles> {
    if !game.info().user_writable {
        return Some(NoFiles::NeedsHelper);
    }
    write_handle(game)
        .err()
        .map(|e| NoFiles::Root(Box::new(RootError::Sys(e))))
}

/// Opens root `r` (a Steam root after its app state, with the plan's install folder, through
/// its store; a manual one by absolute path) and checks its identity; a failure sorted as
/// absent or undecided (module docs).
fn open_root<'g>(
    cx: &ExecCtx<'g>,
    r: &Binding,
    store: Option<&'g Result<StoreDir<'g>, RootError>>,
) -> Result<GameDir<'g>, Failed> {
    // `NotFound` here is the open of a missing path; `policy::root` turns the races after
    // an open into `Busy` (review S-1).
    let by_root = |e: RootError| {
        if matches!(&e, RootError::Sys(s) if s.kind == SysErrorKind::NotFound) {
            Failed::Absent(NoFiles::Root(Box::new(e)))
        } else {
            Failed::Undecided(e.into())
        }
    };
    let game = match (&r.origin, store) {
        (
            PlanOrigin::Steam {
                app_id, installdir, ..
            },
            Some(store),
        ) => {
            let store = store.as_ref().map_err(|e| by_root(e.clone()))?;
            let gone = |gone| {
                Failed::Absent(NoFiles::Steam {
                    app_id: *app_id,
                    gone,
                })
            };
            let app = match app_manifest(store, *app_id) {
                Ok(Some(a)) => a,
                Ok(None) => return Err(gone(super::SteamGone::NoManifest)),
                // Unreadable now (Steam may be rewriting it): transient, not "gone".
                Err(_) => {
                    return Err(Failed::Undecided(Refusal::SteamManifest {
                        app_id: *app_id,
                    }));
                }
            };
            if app.install_dir != *installdir {
                return Err(gone(super::SteamGone::OtherFolder));
            }
            match app.state() {
                AppState::Installed => {}
                AppState::NotInstalled => return Err(gone(super::SteamGone::NotInstalled)),
                state @ AppState::UpdatePending => {
                    return Err(Failed::Undecided(Refusal::Steam {
                        app_id: *app_id,
                        state,
                    }));
                }
            }
            store.game(cx.fr, installdir.as_str()).map_err(by_root)?
        }
        (PlanOrigin::Manual, None) => {
            GameDir::open_manual(cx.sys, cx.fr, r.path.path()).map_err(by_root)?
        }
        (PlanOrigin::Steam { .. }, None) | (PlanOrigin::Manual, Some(_)) => {
            return Err(Failed::Undecided(Refusal::Plan(
                crate::plan::PlanError::Invalid {
                    op: None,
                    why: "a root without its store",
                },
            )));
        }
    };
    // Another folder now: undecided (a rebind, D5, may bind it), never absent.
    game.ensure_id(r.id)
        .map_err(|e| Failed::Undecided(e.into()))?;
    Ok(game)
}

/// The write handle of a game folder (`clippy.toml`: only `exec` and `journal`).
#[expect(
    clippy::disallowed_methods,
    reason = "ADR 0020: exec writes the game folders of a plan"
)]
pub(super) fn write_handle<'g>(game: &'g GameDir<'_>) -> crate::sys::SysResult<&'g dyn DirWrite> {
    game.dir_write()
}

/// `p` has no users, or does not exist (a directory or reparse point is no file to ask); an
/// absent root has nothing to ask.
fn unused(roots: &Roots<'_>, root: usize, p: &RelPath) -> Result<(), Refusal> {
    let Some(g) = roots.game(root) else {
        return Ok(());
    };
    // Decided from the entry itself, not from the error of `users()` (where a folder and a
    // restricted file are both `AccessDenied`): no entry, a folder or a link is no file to
    // ask; a file that cannot be asked refuses (fail closed, review N3).
    match g.dir().metadata(p)? {
        None => return Ok(()),
        Some(m) if m.restricted => return Err(Refusal::Unchecked(roots.shown(root, p))),
        Some(m) if m.kind != crate::sys::fs::EntryKind::File => return Ok(()),
        Some(_) => {}
    }
    match g.dir().users(p) {
        Ok(pids) if pids.is_empty() => Ok(()),
        Ok(_) => Err(Refusal::Busy(roots.shown(root, p))),
        Err(e) if e.kind == SysErrorKind::NotFound => Ok(()),
        Err(e) if e.kind == SysErrorKind::AccessDenied => {
            Err(Refusal::Unchecked(roots.shown(root, p)))
        }
        Err(e) => Err(e.into()),
    }
}

/// D4: the game is closed: no existing file target of the ops `ops`, no executable of a
/// compatibility layer (P2-11) and no main executable of an open root is in use.
pub(super) fn game_closed(plan: &Plan, roots: &Roots<'_>, ops: &[u16]) -> Result<(), Refusal> {
    for k in ops {
        let Some(op) = plan.ops.get(usize::from(*k)) else {
            continue;
        };
        match op.target() {
            Target::File {
                root,
                path,
                dir: false,
            } => unused(roots, usize::from(root.0), path)?,
            // P2-11: the executable a compatibility layer is for (not always the main one).
            Target::Value {
                slot: RegSlot::CompatLayers { root, exe },
            } => unused(roots, usize::from(root.0), exe)?,
            // A registry op has no file to ask: the main executables below are (E2).
            Target::File { dir: true, .. } | Target::Key { .. } | Target::Value { .. } => {}
        }
    }
    for (i, r) in plan.roots.iter().enumerate() {
        if let Some(m) = &r.main_exe {
            unused(roots, i, m)?;
        }
    }
    Ok(())
}

/// Step 5: a created object is still missing (in any spelling), a replaced file still has its
/// old state (on a guard: the stored spelling of its name exactly as planned, hash, length,
/// R/H/S, one link), and every source still has its hash and length.
pub(super) fn old_state(cx: &ExecCtx<'_>, plan: &Plan, roots: &Roots<'_>) -> Result<(), Refusal> {
    let packages = cx.app.sub(AppSub::Packages)?;
    for (k, op) in plan.ops.iter().enumerate() {
        let mismatch = || Refusal::Mismatch { op: op_ix(k) };
        // Registry ops: `exec::reg::old_state`.
        let Target::File { root, .. } = op.target() else {
            continue;
        };
        let g = roots.game(usize::from(root.0)).ok_or_else(mismatch)?;
        match op {
            Op::CreateDir { path, .. } | Op::CreateFile { path, .. } => {
                if g.dir().metadata(path)?.is_some() {
                    return Err(mismatch());
                }
            }
            Op::ReplaceFile { path, old, .. } | Op::IniValue { path, old, .. } => {
                let base = write_handle(g)?;
                let name = RelPath::from_segment(path.file_name()).map_err(|_| mismatch())?;
                let parent;
                let dir: &dyn DirWrite = match path.parent() {
                    None => base,
                    Some(p) => {
                        parent = base.open_dir_write(&p)?;
                        &*parent
                    }
                };
                let mut guard = match dir.guard(&name) {
                    Ok(gd) => gd,
                    Err(e)
                        if matches!(
                            e.kind,
                            SysErrorKind::NotFound
                                | SysErrorKind::Linked
                                | SysErrorKind::AccessDenied
                                | SysErrorKind::ReparsePoint
                        ) =>
                    {
                        return Err(mismatch());
                    }
                    Err(e) => return Err(e.into()),
                };
                // A2-B1: the plan holds the stored spelling; another one since is a change.
                if !guard.name().same_spelling(&name) || !same_state(&mut *guard, old)? {
                    return Err(mismatch());
                }
            }
            Op::CreateKey { .. } | Op::SetValue { .. } | Op::TokenList { .. } => {}
        }
        if let Some(ContentRef::Package {
            id,
            version,
            file,
            sha256,
            len,
            ..
        }) = op.content()
        {
            let pk = packages.as_deref().ok_or_else(mismatch)?;
            let src = open_package(pk, id, version).map_err(|_| mismatch())?;
            match hash_file(&*src, file) {
                Ok((s, l)) if s == *sha256 && l == *len => {}
                _ => return Err(mismatch()),
            }
        }
    }
    Ok(())
}

/// The guard holds exactly `old`: hash, length, R/H/S (one link: the guard refuses others).
pub(super) fn same_state(
    g: &mut dyn FileGuard,
    old: &crate::plan::FileState,
) -> crate::sys::SysResult<bool> {
    let m = g.metadata()?;
    Ok(!is_placeholder(&m)
        && m.len == old.len
        && m.attrs == old.attrs
        && m.is_single_link()
        && g.sha256()? == old.sha256)
}

/// A cloud files placeholder (`0x9000_x01A`): never hashed or read here, it would be
/// downloaded (ADR 0007); a target that became one is `Mismatch` or `Foreign`.
pub(super) fn is_placeholder(m: &crate::sys::fs::Metadata) -> bool {
    m.reparse
        .as_ref()
        .is_some_and(|r| r.tag & 0xFFFF_0FFF == crate::sys::fs::tag::CLOUD)
}
