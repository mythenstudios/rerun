//! The journal as a front end shows it (`rerun status`, and the head of `rerun revert` and
//! `rerun forget`; P2-13). Journal only: no lock, no game folder, no registry, nothing
//! observed (what is on disk now is [`super::verify`]'s business).
//!
//! Per transaction: its state, whether a forget marker closed it, the preview of its head
//! (with the recorded rules and without registry data, `plan::preview_head`), and per op
//! (newest first) how far it got, where its old state is kept ([`Backup`]) and the `.old`
//! files a step left next to its target (pending cleanup: a `.old` still mapped as an image
//! when the step ended; audit A2, "later").

use super::Backup;
use crate::escape::{self, Shown};
use crate::journal::{
    Closing, Damage, InstanceTag, Journal, JournalError, Listed, Observed, OpLog, TxnId, TxnState,
    VerifyBackups,
};
use crate::path::RelPath;
use crate::plan::{self, Plan, PlanOrigin, Preview, Target};
use crate::policy::root::{AppDir, RootId};

/// Every transaction of the journal.
#[derive(Debug)]
pub struct Status {
    /// The transactions, oldest first.
    pub txns: Vec<TxnStatus>,
    /// Entries of `journal\` that are no part of the journal.
    pub foreign_entries: usize,
}

/// One transaction.
#[derive(Debug)]
pub struct TxnStatus {
    /// The transaction.
    pub id: TxnId,
    /// Its state as read.
    pub state: TxnLine,
    /// A forget marker closed it (user decision D2); its backups stay.
    pub forgotten: bool,
    /// Its folder `<AppDir>\journal\<txn>` (escaped).
    pub folder: Shown<'static>,
    /// The preview of its head, or why there is none; `None` where it was not built
    /// ([`status`] builds it only for a transaction a front end shows in full).
    pub preview: Option<Result<Preview, Shown<'static>>>,
    /// Its ops, newest first.
    pub ops: Vec<OpStatus>,
    /// Its `Rebind` records, in order (P2-14b condition d; the last one of a root holds).
    pub rebinds: Vec<RebindLine>,
}

/// A `Rebind` of a transaction as `status` shows it (journal only, never observed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindLine {
    /// Root index.
    pub root: u16,
    /// The Steam library, escaped.
    pub library: Shown<'static>,
    /// The game folder `<library>\steamapps\common\<installdir>` with the head's install folder
    /// (`None` if the head cannot be read).
    pub folder: Option<Shown<'static>>,
    /// Identity of the game folder bound.
    pub id: RootId,
    /// Identity of the game folder bound before.
    pub old: RootId,
}

impl TxnStatus {
    /// Closed (reverted, rolled back or forgotten), forgotten by a marker, or empty (it
    /// changed nothing and blocks nothing; review S8).
    pub fn is_settled(&self) -> bool {
        self.forgotten || matches!(self.state, TxnLine::Closed(_) | TxnLine::Empty)
    }

    /// Forgotten, by a `Closed` record or a marker (review S8: shown alike).
    pub fn is_forgotten(&self) -> bool {
        self.forgotten || self.state == TxnLine::Closed(Closing::Forgotten)
    }
}

/// The state of a transaction as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnLine {
    /// Only its head: nothing changed.
    Empty,
    /// Neither applied nor closed: in progress, or interrupted (an apply, or its rollback).
    Open,
    /// Applied, not closed (a revert may have begun: see its ops).
    Applied,
    /// Closed.
    Closed(Closing),
    /// Not a valid journal; only `forget` closes it.
    Damaged(Damage),
    /// Its folder cannot be read (the error, escaped).
    Unreadable(Shown<'static>),
}

/// One op of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpStatus {
    /// Op index.
    pub op: u16,
    /// How far it got.
    pub state: OpState,
    /// Where its old state is kept, if it has one.
    pub backup: Option<Backup>,
    /// `.old` files a step of it left next to its target (relative to its root, escaped).
    pub cleanup: Vec<Shown<'static>>,
}

/// How far an op got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpState {
    /// Its intent, no `Done`: interrupted while it was applied.
    Interrupted,
    /// Applied.
    Applied,
    /// A revert began and did not finish.
    RevertInterrupted,
    /// Reverted; what the revert observed.
    Reverted(Observed),
}

/// Every transaction (module docs). Without `journal\` an empty status. A preview is built for
/// the transactions that are not settled ([`TxnStatus::is_settled`]) and for any that left a
/// `.old` (its path comes from the head).
pub fn status(app: &AppDir<'_>) -> Result<Status, JournalError> {
    let j = Journal::new(app, InstanceTag::new());
    let listing = j.list()?;
    let txns = listing
        .txns
        .iter()
        .map(|l| one(&j, app, l, false))
        .collect();
    Ok(Status {
        txns,
        foreign_entries: listing.foreign,
    })
}

/// One transaction, with its preview whenever its head can be read (`revert`, `forget`).
pub fn txn_status(app: &AppDir<'_>, t: &TxnId) -> Result<TxnStatus, JournalError> {
    let j = Journal::new(app, InstanceTag::new());
    let listing = j.list()?;
    let l = listing
        .txns
        .iter()
        .find(|l| l.id == *t)
        .ok_or(JournalError::NotFound(*t))?;
    Ok(one(&j, app, l, true))
}

fn one(j: &Journal<'_>, app: &AppDir<'_>, l: &Listed, always: bool) -> TxnStatus {
    let folder = escape::path(&format!(r"{}\journal\{}", app.path(), l.id)).into_owned();
    let v = match &l.view {
        Ok(v) => v,
        Err(e) => {
            return TxnStatus {
                id: l.id,
                state: TxnLine::Unreadable(escape::text(&e.to_string()).into_owned()),
                forgotten: l.forgotten,
                folder,
                preview: None,
                ops: Vec::new(),
                rebinds: Vec::new(),
            };
        }
    };
    let state = match &v.state {
        TxnState::Empty => TxnLine::Empty,
        TxnState::Open => TxnLine::Open,
        TxnState::Applied => TxnLine::Applied,
        TxnState::Closed(c) => TxnLine::Closed(*c),
        TxnState::Damaged(d) => TxnLine::Damaged(d.clone()),
    };
    let settled = l.forgotten || matches!(state, TxnLine::Closed(_) | TxnLine::Empty);
    let leftover = v.ops.values().any(|o| old_left(o).next().is_some());
    let head = (always || !settled || leftover).then(|| head(j, l, v.head_sha256.as_ref()));
    let plan = head.as_ref().and_then(|h| h.as_ref().ok()).map(|(p, _)| p);
    let ops = v
        .ops
        .iter()
        .rev()
        .map(|(k, o)| op_status(app, &l.id, *k, o, plan))
        .collect();
    let rebinds = v
        .rebinds
        .iter()
        .map(|r| RebindLine {
            root: r.root,
            library: escape::path(&r.store.to_string()).into_owned(),
            folder: plan
                .and_then(|p| p.roots.get(usize::from(r.root)))
                .and_then(|h| match &h.origin {
                    PlanOrigin::Steam { installdir, .. } => Some(installdir),
                    PlanOrigin::Manual => None,
                })
                .map(|d| escape::path(&format!(r"{}\steamapps\common\{d}", r.store)).into_owned()),
            id: r.id,
            old: r.old,
        })
        .collect();
    TxnStatus {
        id: l.id,
        state,
        forgotten: l.forgotten,
        folder,
        preview: head.map(|h| h.map(|(_, p)| p)),
        ops,
        rebinds,
    }
}

/// The head of `l`, loaded once more (the listing keeps no head), as a plan and its preview;
/// a head that is missing, damaged, other than the listed one or that does not decode is the
/// reason as text.
fn head(
    j: &Journal<'_>,
    l: &Listed,
    listed: Option<&[u8; 32]>,
) -> Result<(Plan, Preview), Shown<'static>> {
    let why = |s: &str| escape::text(s).into_owned();
    let full = j
        .load(&l.id, VerifyBackups::Length)
        .map_err(|e| why(&e.to_string()))?;
    if !full.head_usable() || full.head_sha256.as_ref() != listed {
        return Err(why("its head cannot be read or was changed"));
    }
    let bytes = full.head.as_deref().unwrap_or_default();
    let plan = super::decode_head(bytes).map_err(|e| why(&e.to_string()))?;
    let preview = plan::preview_head(bytes).map_err(|e| why(&e.to_string()))?;
    Ok((plan, preview))
}

/// The `.old` names the journal says a step of `o` left (P2-15: exactly
/// [`OpLog::pending_old`], the list of its `RevertDone` once it has one).
fn old_left(o: &OpLog) -> impl Iterator<Item = RelPath> + '_ {
    o.pending_old().into_iter().map(|(_, t)| t.old())
}

fn op_status(app: &AppDir<'_>, t: &TxnId, k: u16, o: &OpLog, plan: Option<&Plan>) -> OpStatus {
    let state = match (&o.reverted, o.reverts.is_empty(), &o.done) {
        (Some(r), _, _) => OpState::Reverted(r.observed),
        (None, false, _) => OpState::RevertInterrupted,
        (None, true, Some(_)) => OpState::Applied,
        (None, true, None) => OpState::Interrupted,
    };
    // The folder of the op's target, if the head names it.
    let folder = plan
        .and_then(|p| p.ops.get(usize::from(k)))
        .and_then(|op| match op.target() {
            Target::File { path, .. } => Some(path.parent()),
            Target::Key { .. } | Target::Value { .. } => None,
        });
    let cleanup = old_left(o)
        .map(|name| {
            let full = match &folder {
                Some(Some(f)) => f.child(name.as_str()).unwrap_or(name),
                _ => name,
            };
            escape::path(full.as_str()).into_owned()
        })
        .collect();
    OpStatus {
        op: k,
        state,
        backup: Backup::of(app, t, k, &o.intent),
        cleanup,
    }
}
