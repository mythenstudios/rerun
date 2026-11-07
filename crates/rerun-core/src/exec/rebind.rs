//! Rebind (P2-14a; ADR 0020 amendment P2-14, user decisions E-R1 to E-R6): an applied
//! transaction whose Steam game folder is gone (the library or the folder not found, no
//! manifest, not installed) or is another folder now (`IdentityMismatch` of the library or of
//! the game folder) is bound, after a preview the user confirms, to the head's install folder in
//! another (or the same) Steam library, and reverted there.
//!
//! Two steps (E-R5): [`rebind_check`] runs every check read only and returns the binding with
//! the preview ([`RebindPreview`]); [`revert_rebound`] takes exactly that binding ([`RebindTo`]),
//! derives it again under the lock and refuses with [`RebindRefusal::Changed`] before its record
//! on any difference, then writes the `Rebind` record (flushed) and runs the revert loop in the
//! same run on the folder it opened and checked. The head is never rewritten; registry ops stay
//! on the head's locations (E-R4 a).
//!
//! In this cut the library is passed by the caller; the Steam scan that finds it (exactly one
//! library with the app installed, E-R1) comes with P2-14b.
//!
//! The conditions (refused without a record, [`RebindRefusal`]): the transaction applied;
//! exactly one root does not open, and it is a Steam root; every other root opens; no file op of
//! that root has a `RevertIntent` (E-R3); the library holds the head's app installed in the
//! head's install folder, not updating, and its folder opens through `policy::root` with another
//! binding than before; the current user can write it; LIFO against later transactions with the
//! objects at the head's roots, the folder bound before and the new one (E-R6); the game closed
//! there (D4) and its main executable a plain file; every file op of the root observes `Before`,
//! `After` or `Drifted` there (E-R4 a: only `Foreign` refuses); room in the record budget. The
//! file IDs of the created folders found empty (but for what later ops remove) go into the record
//! (E-R2 a); a created folder without one is `Foreign` unless it is missing.

use std::collections::BTreeMap;

use super::bind::{Binding, Bindings, Proof, file_ops};
use super::roots::{self, Probe};
use super::{
    ExecCtx, ExecError, Refusal, RevertReport, Seen, Touched, Verified, knob_rewrite_head,
    load_resumable, op_ix, refused_early, revert_listed, revert_plan, revert_run, stack,
    standard_user, verify_seen,
};
use crate::journal::{DirProof, Journal, JournalError, Listing, OpLog, RebindArgs, TxnId};
use crate::path::RootPath;
use crate::plan::{Op, Plan};
use crate::policy::root::{RootError, RootId, StoreDir};

/// The binding a user confirmed (rule 5, like `PlanHash`): from the preview to the revert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindTo {
    /// Root index in the head.
    pub root: u16,
    /// The Steam library (canonical path).
    pub store: RootPath,
    /// Identity of the library.
    pub store_id: RootId,
    /// Identity of the game folder.
    pub id: RootId,
    /// The created folders by the file ID found there, by op ascending (E-R2 a).
    pub dirs: Vec<DirProof>,
}

/// The binding before a rebind (the head's, or the last rebind's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindFrom {
    /// Canonical path of the game folder.
    pub path: RootPath,
    /// Its identity.
    pub id: RootId,
    /// The Steam library.
    pub store: RootPath,
    /// Identity of the library.
    pub store_id: RootId,
}

/// What [`rebind_check`] found: the binding to confirm and what the revert meets there.
#[derive(Debug)]
pub struct RebindPreview {
    /// The binding; [`revert_rebound`] takes exactly this.
    pub to: RebindTo,
    /// The game folder it names.
    pub path: RootPath,
    /// The binding before.
    pub from: RebindFrom,
    /// Why the binding before does not open.
    pub why: Box<Refusal>,
    /// What each op observes with the new binding (newest first, as `verify`); a created folder
    /// that counts there is "not provably Rerun's" (its file ID is the one found, `to.dirs`).
    pub verified: Verified,
}

/// Why a rebind is refused (nothing written).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RebindRefusal {
    /// Every folder of the transaction opens as bound: revert it without a rebind.
    #[error("every folder of the transaction opens as recorded; revert it without a rebind")]
    NotNeeded,
    /// The folder that does not open is one the user chose: never rebound (D5).
    #[error("a folder you chose is never rebound; only forget closes the transaction")]
    Manual,
    /// The transaction is not applied (an interrupted apply).
    #[error("only an applied transaction can be rebound; revert or forget it")]
    NotApplied,
    /// The folder cannot be checked now (an update, another install folder, a manifest that
    /// cannot be read, busy, access denied, a reparse point, forbidden).
    #[error("the folder cannot be checked now ({0}); try again later")]
    Undecided(Box<Refusal>),
    /// More than one folder of the transaction does not open.
    #[error("more than one folder of the transaction does not open; a rebind binds one")]
    MoreThanOne,
    /// The library does not hold the app installed.
    #[error("the app is not installed in that Steam library")]
    NoCandidate,
    /// Steam is updating the app in that library.
    #[error("Steam is updating the app in that library; try again when it has finished")]
    UpdatePending,
    /// The app is installed in another folder in that library.
    #[error("the app is installed in another folder in that library")]
    OtherInstallDir,
    /// The library or the folder in it cannot be opened.
    #[error("the folder in that library cannot be opened: {0}")]
    Candidate(Box<Refusal>),
    /// The current user cannot write the folder there (phase 3: the elevated helper), or its
    /// volume lacks POSIX semantics.
    #[error("the folder in that library cannot be written by Rerun")]
    NotWritable,
    /// Op `op` meets a state there Rerun did not leave.
    #[error("op {op} is changed in that folder; only forget closes the transaction")]
    Foreign {
        /// Op index.
        op: u16,
    },
    /// A revert of op `op` of that folder has begun (E-R3).
    #[error("the revert of op {op} of that folder has begun; only forget closes the transaction")]
    RevertPending {
        /// Op index.
        op: u16,
    },
    /// The folder changed since the preview.
    #[error("the folder changed since the preview; check it again")]
    Changed,
    /// The journal of the transaction has no room for the rebind and the rest of the revert.
    #[error("the journal of the transaction has no room for a rebind; only forget closes it")]
    NoRoom,
}

impl From<RebindRefusal> for Refusal {
    fn from(r: RebindRefusal) -> Self {
        Self::Rebind(r)
    }
}

/// The root to rebind and its new binding (before anything is opened for the revert).
struct Target {
    root: u16,
    /// The bindings with root `root` bound to `new`.
    overlay: Bindings,
    new: Binding,
    from: RebindFrom,
    why: Refusal,
}

impl Target {
    /// The binding as [`RebindTo`] (without the folder proofs).
    fn is(&self, to: &RebindTo) -> bool {
        self.root == to.root
            && self.new.store() == Some((&to.store, to.store_id))
            && self.new.id == to.id
    }
}

/// Which root needs the rebind, and the folder of the head's install folder in `lib`.
fn target(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    b: &Bindings,
    ops: &BTreeMap<u16, OpLog>,
    applied: bool,
    lib: &RootPath,
) -> Result<Target, Refusal> {
    if !applied {
        return Err(RebindRefusal::NotApplied.into());
    }
    let mut gone = Vec::new();
    for (i, x) in b.iter().enumerate() {
        match roots::probe(cx, x) {
            Probe::Opens => {}
            Probe::Gone(why) => gone.push((i, why)),
            Probe::Undecided(why) => return Err(RebindRefusal::Undecided(Box::new(why)).into()),
        }
    }
    if gone.len() > 1 {
        return Err(RebindRefusal::MoreThanOne.into());
    }
    let Some((i, why)) = gone.pop() else {
        return Err(RebindRefusal::NotNeeded.into());
    };
    let (Some(head), Some(cur)) = (plan.roots.get(i), b.get(i)) else {
        return Err(RebindRefusal::NotNeeded.into());
    };
    let Some((store, store_id)) = cur.store() else {
        return Err(RebindRefusal::Manual.into());
    };
    let from = RebindFrom {
        path: cur.path.clone(),
        id: cur.id,
        store: store.clone(),
        store_id,
    };
    let root = op_ix(i);
    if let Some(op) =
        file_ops(plan, root).find(|k| ops.get(k).is_some_and(|o| !o.reverts.is_empty()))
    {
        return Err(RebindRefusal::RevertPending { op }.into());
    }
    let new = roots::candidate(cx, head, lib)?;
    if new.store() == cur.store() && new.id == cur.id {
        return Err(RebindRefusal::NotNeeded.into());
    }
    let overlay = b.with(i, new.clone()).ok_or(RebindRefusal::NotNeeded)?;
    Ok(Target {
        root,
        overlay,
        new,
        from,
        why,
    })
}

/// The checks with the new binding opened (it stays open for the revert), and the file IDs of
/// the created folders found there.
struct Checked<'g> {
    roots: roots::Roots<'g>,
    verified: Verified,
    dirs: Vec<DirProof>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the one chain of a rebind's checks"
)]
fn checked<'g>(
    cx: &ExecCtx<'g>,
    plan: &Plan,
    b: &Bindings,
    tg: &Target,
    j: &Journal<'_>,
    listing: &Listing,
    t: &TxnId,
    ops: &BTreeMap<u16, OpLog>,
    stores: &'g [Option<Result<StoreDir<'g>, RootError>>],
) -> Result<Checked<'g>, Refusal> {
    let blocked = || Refusal::Blocked { txn: *t };
    // E-R6: LIFO with the objects at the head's roots, the folder bound before and the new one.
    let mut objects = b.objects(plan).map_err(|_| blocked())?;
    objects.extend(tg.overlay.objects(plan).map_err(|_| blocked())?);
    stack::for_revert(j, listing, t, &objects)?;
    let mismatch = |r: &Refusal| matches!(r, Refusal::Root(e) if matches!(**e, RootError::IdentityMismatch { .. }));
    let roots = roots::Roots::each(cx, &tg.overlay, stores).map_err(|r| {
        if mismatch(&r) {
            RebindRefusal::Changed.into()
        } else {
            r
        }
    })?;
    let i = usize::from(tg.root);
    if roots.game(i).is_none() {
        return Err(RebindRefusal::Changed.into());
    }
    if roots.for_files(i).is_err() {
        return Err(RebindRefusal::NotWritable.into());
    }
    roots::main_exe_at(plan, &roots, i)?;
    let intended: Vec<u16> = ops.keys().copied().collect();
    roots::game_closed(plan, &roots, &intended)?;
    let (mut verified, seen) = {
        let mut touched = Touched::new(cx.sys, &roots);
        verify_seen(plan, &mut touched, &roots, ops).map_err(refused_early)?
    };
    if let Some(h) = verified.halted.take() {
        return Err(RebindRefusal::Undecided(h.why).into());
    }
    let mut dirs = Vec::new();
    for k in file_ops(plan, tg.root) {
        let observed = verified.ops.iter().find(|(x, _)| *x == k).map(|(_, o)| *o);
        if observed == Some(crate::journal::Observed::Foreign) {
            return Err(RebindRefusal::Foreign { op: k }.into());
        }
        if let (Some(Op::CreateDir { .. }), Some(Seen::File(s))) =
            (plan.ops.get(usize::from(k)), seen.get(&k))
            && let Some(id) = s.actions.iter().find_map(|a| match a {
                super::file::Action::RemoveDir(id) => Some(*id),
                _ => None,
            })
        {
            dirs.push(DirProof { op: k, file_id: id });
        }
    }
    Ok(Checked {
        roots,
        verified,
        dirs,
    })
}

/// Every check of [`revert_rebound`] before its record, read only (an existing lock file held
/// read side): the binding of root `root` to the head's install folder in the Steam library
/// `lib`, and what the revert meets there. P2-14b finds `lib` by the Steam scan.
pub fn rebind_check(cx: &ExecCtx<'_>, t: &TxnId, lib: &RootPath) -> Result<RebindPreview, Refusal> {
    standard_user(cx.sys)?;
    let j = Journal::new(cx.app, cx.tag);
    let hold = j.hold()?;
    let listing = j.list()?;
    revert_listed(&listing, t)?;
    let (v, head) = load_resumable(&j, t)?;
    let before = |k: u16, d: &crate::journal::Digest, max: u64| j.read_backup(t, k, d, max);
    let (plan, b) = revert_plan(t, &head, &v.ops, &v.rebinds, &before)?;
    let applied = v.state == crate::journal::TxnState::Applied;
    let tg = target(cx, &plan, &b, &v.ops, applied, lib)?;
    let stores = roots::open_stores(cx, &tg.overlay);
    let c = checked(cx, &plan, &b, &tg, &j, &listing, t, &v.ops, &stores)?;
    if !j.rebind_fits(&v) {
        return Err(RebindRefusal::NoRoom.into());
    }
    drop(c.roots);
    drop(hold);
    let Some((store, store_id)) = tg.new.store() else {
        return Err(RebindRefusal::Manual.into());
    };
    Ok(RebindPreview {
        to: RebindTo {
            root: tg.root,
            store: store.clone(),
            store_id,
            id: tg.new.id,
            dirs: c.dirs,
        },
        path: tg.new.path.clone(),
        from: tg.from,
        why: Box::new(tg.why),
        verified: c.verified,
    })
}

/// Binds transaction `t` as the user confirmed (`to`, from [`rebind_check`]) and reverts it in
/// the same run (module docs). Every refusal comes before the `Rebind` record; after it, the
/// errors of a revert (the transaction stays open and bound). A transaction already bound to
/// exactly `to` (the record written, the revert interrupted) is reverted as it is.
pub fn revert_rebound(
    cx: &ExecCtx<'_>,
    t: &TxnId,
    to: &RebindTo,
) -> Result<RevertReport, ExecError> {
    standard_user(cx.sys)?;
    let j = Journal::new(cx.app, cx.tag);
    let lock = j.lock().map_err(Refusal::from)?;
    let listing = j.list().map_err(Refusal::from)?;
    revert_listed(&listing, t)?;
    let mut w = lock.resume(t).map_err(Refusal::from)?;
    let before = |k: u16, _: &crate::journal::Digest, max: u64| w.before_bytes(k, max);
    let (plan, b) = revert_plan(t, w.head(), w.ops(), w.rebinds(), &before)?;
    let bound = b.get(usize::from(to.root)).is_some_and(|x| {
        x.store() == Some((&to.store, to.store_id)) && x.id == to.id && x.proof != Proof::Done
    });
    if bound {
        drop(w);
        drop(lock);
        return super::revert(cx, t);
    }
    let ops = w.ops().clone();
    let tg = target(cx, &plan, &b, &ops, w.is_applied(), &to.store)?;
    // Rule 5: the binding written is the binding shown, derived again under the lock.
    if !tg.is(to) {
        return Err(Refusal::from(RebindRefusal::Changed).into());
    }
    let stores = roots::open_stores(cx, &tg.overlay);
    let mut c = checked(cx, &plan, &b, &tg, &j, &listing, t, &ops, &stores)?;
    if c.dirs != to.dirs {
        return Err(Refusal::from(RebindRefusal::Changed).into());
    }
    let old = tg.from.id;
    let n = w.rebinds().len();
    let args = RebindArgs {
        root: to.root,
        old,
        store: &to.store,
        store_id: to.store_id,
        id: to.id,
        dirs: &c.dirs,
    };
    if let Err(e) = w.rebind(&args) {
        // On disk although its flush failed: the transaction is bound now.
        if w.rebinds().len() > n {
            return Err(ExecError::Journal(e));
        }
        return Err(match e {
            JournalError::TooLarge { .. } => Refusal::from(RebindRefusal::NoRoom),
            e => Refusal::from(e),
        }
        .into());
    }
    // From the record on, the created folders are proven by its file IDs (the folder stays the
    // one opened and checked above).
    let ids: BTreeMap<u16, u128> = c.dirs.iter().map(|d| (d.op, d.file_id)).collect();
    c.roots.set_proof(to.root, Proof::Rebound(ids));
    let rebound = Bindings::of(&plan, w.rebinds()).ok_or(ExecError::Journal(
        JournalError::Order("a rebind that does not fit its head"),
    ))?;
    let plan = knob_rewrite_head(&plan, &rebound).unwrap_or(plan);
    revert_run(cx, &j, t, &plan, w, &c.roots, false)
}
