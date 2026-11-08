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
//! The library comes from the Steam scan only (P2-14b, E-R1): exactly one library with the app
//! installed, every listed library and every registry candidate that could name another Steam
//! folder readable ([`steam_library`]).
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
use crate::escape::{self, Shown};
use crate::journal::{
    DirProof, Journal, JournalError, Listing, OpLog, RebindArgs, RebindRec, TxnId,
};
use crate::path::RootPath;
use crate::plan::{Op, Plan, PlanOrigin};
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
    /// The binding before, as the preview showed it (compared under the lock, review N2).
    pub from: RebindFrom,
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
    /// Why the binding before does not open.
    pub why: Box<Refusal>,
    /// What each op observes with the new binding (newest first, as `verify`); a created folder
    /// that counts there is "not provably Rerun's" (its file ID is the one found, `to.dirs`).
    pub verified: Verified,
    /// Every folder the plan created in that root, with its path there (P2-14b condition e).
    pub created: Vec<CreatedDir>,
}

/// A folder the plan created, as a rebind meets it in the new folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedDir {
    /// Op index.
    pub op: u16,
    /// `<new folder><path>`, escaped.
    pub path: Shown<'static>,
    /// Found there and bound by the file ID found (`RebindTo::dirs`): not provably Rerun's, removed
    /// by the revert only if empty; `false`: missing there (only a missing folder fits later).
    pub found: bool,
}

/// Why a rebind is refused (nothing written).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RebindRefusal {
    /// Every folder of the transaction opens as bound: revert it without a rebind.
    #[error("every folder of the transaction opens as recorded; revert it without a rebind")]
    NotNeeded,
    /// Every folder opens, and root `root` is bound to `path` by an earlier rebind: the revert
    /// goes on there without a new one (P2-14b condition c).
    #[error("the transaction is bound to {path} already; revert it without a rebind")]
    AlreadyBound {
        /// Root index.
        root: u16,
        /// The bound game folder, escaped.
        path: Shown<'static>,
    },
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
    /// No Steam library holds the app (or Steam is not found).
    #[error("no Steam library holds the app now")]
    NoCandidate,
    /// More than one Steam library holds the app (E-R1: `DuplicateApp`).
    #[error("the app is in more than one Steam library: {}", list(.0))]
    Ambiguous(Vec<Shown<'static>>),
    /// A listed Steam library (or the library list) cannot be read: it could hold the app
    /// (E-R1: every listed library readable, also the old one; P2-14b condition b).
    #[error(
        "a rebind needs every library Steam lists, and this app's manifest, readable ({0}); try \
         again later"
    )]
    LibraryUnreadable(Shown<'static>),
    /// Steam is updating the app in that library.
    #[error(
        "Steam is updating the app in the library that holds it; try again when it has finished"
    )]
    UpdatePending,
    /// The app is installed in another folder in that library.
    #[error("the app is installed in another folder in the library that holds it")]
    OtherInstallDir,
    /// The library or the folder in it cannot be opened.
    #[error("the folder in the library that holds the app cannot be opened: {0}")]
    Candidate(Box<Refusal>),
    /// The folder there is the folder of another root of the transaction, or lies inside or
    /// around one (apps sharing an install folder; P2-14 security review S1).
    #[error("the folder in that library is another folder of the transaction already")]
    SharedFolder,
    /// The revert would halt at another folder of the transaction (it is gone or cannot be
    /// written): it must be available before the rebind.
    #[error(
        "the revert would stop at another folder of the transaction ({0}); make it available first"
    )]
    Halts(Box<Refusal>),
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
    /// The rebind record would be larger than a record may be.
    #[error("the rebind record would be too large for the journal")]
    TooLarge,
    /// The journal of the transaction has no room for the rebind and the rest of the revert.
    #[error("the journal of the transaction has no room for a rebind; only forget closes it")]
    NoRoom,
}

/// The libraries of an [`RebindRefusal::Ambiguous`], for its text.
fn list(v: &[Shown<'_>]) -> String {
    v.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
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
            && self.from == to.from
    }
}

/// Which root needs the rebind, and the folder of the head's install folder in the one Steam
/// library that holds the head's app now ([`steam_library`]).
fn target(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    b: &Bindings,
    ops: &BTreeMap<u16, OpLog>,
    applied: bool,
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
        // Condition c: a root bound by an earlier rebind that opens there is not "not needed".
        if let Some((i, x)) = b.iter().enumerate().find(|(_, x)| x.proof != Proof::Done) {
            return Err(RebindRefusal::AlreadyBound {
                root: op_ix(i),
                path: escape::path(&x.path.to_string()).into_owned(),
            }
            .into());
        }
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
    let PlanOrigin::Steam { app_id, .. } = &head.origin else {
        return Err(RebindRefusal::Manual.into());
    };
    let lib = steam_library(cx, *app_id)?;
    let new = roots::candidate(cx, head, &lib)?;
    if new.store() == cur.store() && new.id == cur.id {
        return Err(RebindRefusal::NotNeeded.into());
    }
    let overlay = b.with(i, new.clone()).ok_or(RebindRefusal::NotNeeded)?;
    if overlay.clashes(i) {
        return Err(RebindRefusal::SharedFolder.into());
    }
    Ok(Target {
        root,
        overlay,
        new,
        from,
        why,
    })
}

/// E-R1 (P2-14b): the one Steam library that holds `app_id` now, from the Steam scan. Refused:
/// no Steam or no library with the app (`NoCandidate`); the app in more than one library, also
/// a `DuplicateApp` of the scan (`Ambiguous`); and every problem of a listed library or of the
/// library list (missing, unreadable, case-sensitive, too many entries, condition b: the old
/// library too), of a manifest of this app, and another Steam folder the scan does not cover
/// (`RootsDisagree`) (`LibraryUnreadable`, naming it). Problems of another app's manifest are not
/// this app's and do not refuse.
///
/// Registry candidates (P2-14b review S1): a candidate that ranks before the chosen root in
/// `RootSource::ALL` (all of them when no root was found) refuses with any problem (its folder
/// not found may be an unplugged drive with the real Steam on it, while a later candidate names
/// an old copy); "no value" reports no problem. A candidate after the chosen root is ignored only
/// when it has no value, a value that is no path, or a folder that is not found; anything else
/// (access denied, busy, a reparse point, forbidden, `RootsDisagree`) refuses.
fn steam_library(cx: &ExecCtx<'_>, app_id: u32) -> Result<RootPath, RebindRefusal> {
    use crate::detect::steam::{IssueKind, Location, RootSource, scan};
    let s = scan(cx.sys, cx.fr);
    let rank = |r: RootSource| RootSource::ALL.iter().position(|x| *x == r);
    let chosen = s.root.and_then(rank);
    let ours = format!("appmanifest_{app_id}.acf");
    let mut dup = false;
    for i in &s.issues {
        let unreadable = match (&i.at, &i.kind) {
            (Location::Registry(r), kind) => match (rank(*r), chosen) {
                (Some(a), Some(c)) if a > c => !harmless_after_root(kind),
                _ => true,
            },
            (Location::Manifest { .. }, IssueKind::DuplicateApp { app_id: a, .. }) => {
                dup |= *a == app_id;
                false
            }
            (Location::Manifest { name, .. }, _) => name.eq_ignore_ascii_case(&ours),
            // The library list, a listed library, a library itself, and anything new: fail closed.
            _ => true,
        };
        if unreadable {
            return Err(RebindRefusal::LibraryUnreadable(
                escape::text(&i.to_string()).into_owned(),
            ));
        }
    }
    if s.root.is_none() {
        return Err(RebindRefusal::NoCandidate);
    }
    let holders: Vec<&RootPath> = s
        .libraries
        .iter()
        .filter(|l| l.app(app_id).is_some())
        .map(|l| l.path())
        .collect();
    match holders.as_slice() {
        [] => Err(RebindRefusal::NoCandidate),
        [one] if !dup => Ok((*one).clone()),
        many => Err(RebindRefusal::Ambiguous(
            many.iter()
                .map(|p| escape::path(&p.to_string()).into_owned())
                .collect(),
        )),
    }
}

/// A problem of a registry candidate after the chosen Steam root that cannot hide another Steam
/// folder: a value that is no path, or a folder that is not found.
fn harmless_after_root(kind: &crate::detect::steam::IssueKind) -> bool {
    use crate::detect::steam::IssueKind;
    match kind {
        IssueKind::RegistryValue(_) => true,
        IssueKind::Root(e) => {
            matches!(&**e, RootError::Sys(s) if s.kind == crate::sys::SysErrorKind::NotFound)
        }
        _ => false,
    }
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
    if roots.opened(i).is_none() {
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
        return Err(RebindRefusal::Halts(h.why).into());
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
/// read side): the binding of the one root that does not open to the head's install folder in
/// the one Steam library the Steam scan finds holding the app (E-R1), and what the revert meets
/// there.
pub fn rebind_check(cx: &ExecCtx<'_>, t: &TxnId) -> Result<RebindPreview, Refusal> {
    standard_user(cx.sys)?;
    let j = Journal::new(cx.app, cx.tag);
    let hold = j.hold()?;
    let listing = j.list()?;
    revert_listed(&listing, t)?;
    let (v, head) = load_resumable(&j, t)?;
    let before = |k: u16, d: &crate::journal::Digest, max: u64| j.read_backup(t, k, d, max);
    let (plan, b) = revert_plan(t, &head, &v.ops, &v.rebinds, &before)?;
    let applied = v.state == crate::journal::TxnState::Applied;
    let tg = target(cx, &plan, &b, &v.ops, applied)?;
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
    let created = file_ops(&plan, tg.root)
        .filter_map(|k| match plan.ops.get(usize::from(k)) {
            Some(Op::CreateDir { path, .. }) => Some(CreatedDir {
                op: k,
                path: escape::path(&format!(r"{}\{path}", tg.new.path)).into_owned(),
                found: c.dirs.iter().any(|d| d.op == k),
            }),
            _ => None,
        })
        .collect();
    Ok(RebindPreview {
        created,
        to: RebindTo {
            root: tg.root,
            store: store.clone(),
            store_id,
            id: tg.new.id,
            dirs: c.dirs,
            from: tg.from,
        },
        path: tg.new.path.clone(),
        why: Box::new(tg.why),
        verified: c.verified,
    })
}

/// Whether `t` holds more than `n` rebinds on disk now; `None` if the journal cannot be read
/// (never claim "nothing changed" then).
fn rebound_now(j: &Journal<'_>, t: &TxnId, n: usize) -> Option<bool> {
    j.load(t, crate::journal::VerifyBackups::Length)
        .ok()
        .map(|v| v.rebinds.len() > n)
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
        // Exactly the binding shown: the same folder proofs and the same binding before it
        // (review N1, N2); anything else is another decision than the one confirmed.
        let last = w.rebinds().iter().rev().find(|r| r.root == to.root);
        if last.is_none_or(|r| r.dirs != to.dirs || r.old != to.from.id) {
            return Err(Refusal::from(RebindRefusal::Changed).into());
        }
        drop(w);
        drop(lock);
        return super::revert(cx, t);
    }
    let ops = w.ops().clone();
    // Condition a: the Steam scan again, under the lock; rule 5: the binding written is the
    // binding shown, derived again.
    let tg = target(cx, &plan, &b, &ops, w.is_applied())?;
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
    // The record as the next run will read it must fit the head (`Bindings::of`), checked before
    // it is written (review nit): a rebind exec would call `Blocked` is never written.
    let mut next = w.rebinds().to_vec();
    next.push(RebindRec {
        root: to.root,
        old,
        store: to.store.clone(),
        store_id: to.store_id,
        id: to.id,
        dirs: c.dirs.clone(),
        reverting: ops
            .iter()
            .find(|(_, o)| !o.reverts.is_empty())
            .map(|(k, _)| *k),
    });
    let Some(rebound) = Bindings::of(&plan, &next) else {
        return Err(
            Refusal::from(JournalError::Order("a rebind that does not fit its head")).into(),
        );
    };
    if let Err(e) = w.rebind(&args) {
        // On disk although the call failed (its flush, or a failure after its rename): the
        // transaction is bound now. Decided by the writer, else by reading the journal again
        // under the lock (as a closing entry, security review N1); a journal that cannot be read
        // again is `Unconfirmed` (review N3).
        if w.rebinds().len() > n {
            return Err(ExecError::Journal(e));
        }
        return Err(match rebound_now(&j, t, n) {
            Some(true) => ExecError::Journal(e),
            None => ExecError::RebindUnconfirmed(e),
            Some(false) => match e {
                JournalError::TooLarge {
                    what: "a record", ..
                } => Refusal::from(RebindRefusal::TooLarge).into(),
                JournalError::TooLarge { .. } => Refusal::from(RebindRefusal::NoRoom).into(),
                e => Refusal::from(e).into(),
            },
        });
    }
    // From the record on, the created folders are proven by its file IDs (the folder stays the
    // one opened and checked above).
    let ids: BTreeMap<u16, u128> = c.dirs.iter().map(|d| (d.op, d.file_id)).collect();
    c.roots.set_proof(to.root, Proof::Rebound(ids));
    let plan = knob_rewrite_head(&plan, &rebound).unwrap_or(plan);
    revert_run(cx, &j, t, &plan, w, &c.roots, false)
}
