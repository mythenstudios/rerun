//! The journal as a front end shows it (`rerun status`, and the head of `rerun revert` and
//! `rerun forget`; P2-13). Journal only: no lock, no game folder, no registry, nothing
//! observed (what is on disk now is [`super::verify`]'s business).
//!
//! Per transaction: its state, whether a forget marker closed it, the preview of its head
//! (with the recorded rules and without registry data, `plan::preview_head`), and per op
//! (newest first) how far it got, where its old state is kept ([`Backup`]) and the `.old`
//! files a step left next to its target (pending cleanup: a `.old` still mapped as an image
//! when the step ended; P2-15: exactly the sequences the journal names, none for a transaction
//! closed `Reverted` or `RolledBack`, which a revert closes only once they are gone; for a
//! forgotten one they may remain).

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
    /// P4-8b (E6): files and folders other transactions created that its ops rely on, and what
    /// becomes of them (journal only; an applied or interrupted transaction, not forgotten).
    pub shares: Vec<ShareLine>,
    /// The other transactions could not be read for [`Self::shares`] (escaped), e.g. more than
    /// `MAX_SHARE_HEADS` (review follow-up, senior N-6): shown, never swallowed.
    pub shares_error: Option<Shown<'static>>,
}

/// A file or folder another transaction created that an op relies on (P4-8b), journal only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareLine {
    /// The op that relies on it.
    pub op: u16,
    /// The path below the root (escaped).
    pub path: Shown<'static>,
    /// A folder.
    pub dir: bool,
    /// What becomes of it.
    pub kind: ShareKind,
}

/// What becomes of a shared file or folder (P4-8b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareKind {
    /// Handed over: this transaction's revert removes it if it is unchanged; `forget` leaves it
    /// until a later transaction that relies on it is reverted.
    Inherits {
        /// The transaction that created it.
        from: TxnId,
    },
    /// The revert of `by` removes it once nothing else relies on it (the creator, or another
    /// transaction that relies on it): after `forget` this transaction no longer keeps it.
    RemovedBy {
        /// The transaction that created it.
        from: TxnId,
        /// The transaction whose revert removes it.
        by: TxnId,
    },
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
    /// Every op reverted, none foreign, but the journal still names a `.old` of Rerun's
    /// (P2-15): not closed; `rerun revert <txn>` deletes it once it is free and closes. An
    /// applied transaction or a rolled-back apply alike.
    CleanupPending,
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
    /// `.old` files the journal says a step of it left next to its target (relative to its
    /// root, escaped; P2-15: none once closed `Reverted` or `RolledBack`).
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
    // Review follow-up (senior N-6): the other transactions read once for every line.
    let others = super::share::read(&j, &listing, None, true);
    let txns = listing
        .txns
        .iter()
        .map(|l| one(&j, app, l, false, &others))
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
    let others = super::share::read(&j, &listing, None, true);
    Ok(one(&j, app, l, true, &others))
}

fn one(
    j: &Journal<'_>,
    app: &AppDir<'_>,
    l: &Listed,
    always: bool,
    others: &Result<super::share::Others, super::Refusal>,
) -> TxnStatus {
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
                shares: Vec::new(),
                shares_error: None,
            };
        }
    };
    let state = match &v.state {
        TxnState::Empty => TxnLine::Empty,
        TxnState::Open | TxnState::Applied if cleanup_pending(&v.ops) => TxnLine::CleanupPending,
        TxnState::Open => TxnLine::Open,
        TxnState::Applied => TxnLine::Applied,
        TxnState::Closed(c) => TxnLine::Closed(*c),
        TxnState::Damaged(d) => TxnLine::Damaged(d.clone()),
    };
    let settled = l.forgotten || matches!(state, TxnLine::Closed(_) | TxnLine::Empty);
    // P2-15: closed as reverted, nothing of Rerun's is left (a revert closes only then).
    let exact = !l.forgotten
        && matches!(
            state,
            TxnLine::Closed(Closing::Reverted | Closing::RolledBack)
        );
    let leftover = !exact && v.ops.values().any(|o| old_left(o).next().is_some());
    let head = (always || !settled || leftover).then(|| head(j, l, v.head_sha256.as_ref()));
    let plan = head.as_ref().and_then(|h| h.as_ref().ok()).map(|(p, _)| p);
    let ops = v
        .ops
        .iter()
        .rev()
        .map(|(k, o)| op_status(app, &l.id, *k, o, plan, exact))
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
                    PlanOrigin::Manual | PlanOrigin::AppDir => None,
                })
                .map(|d| escape::path(&format!(r"{}\steamapps\common\{d}", r.store)).into_owned()),
            id: r.id,
            old: r.old,
        })
        .collect();
    // P4-8b: what becomes of the shared objects of a transaction that is not closed (applied, or
    // an interrupted apply: it counts as relying and inherits as well, review follow-up 1).
    let wanted = plan.filter(|p| {
        !l.forgotten
            && matches!(v.state, TxnState::Applied | TxnState::Open)
            && super::share::may_inherit(p, &v.ops)
    });
    let shares_error = match (wanted, others) {
        (Some(_), Err(e)) => Some(escape::text(&e.to_string()).into_owned()),
        _ => None,
    };
    let shares = match (wanted, others) {
        (Some(p), Ok(o)) => super::share::lines(o, &l.id, p, &v.ops)
            .into_iter()
            .map(|(op, path, dir, line)| ShareLine {
                op,
                path: escape::path(path.as_str()).into_owned(),
                dir,
                kind: match line {
                    super::share::Line::Inherits { from } => ShareKind::Inherits { from },
                    super::share::Line::RemovedBy { from, by } => ShareKind::RemovedBy { from, by },
                },
            })
            .collect(),
        _ => Vec::new(),
    };
    TxnStatus {
        id: l.id,
        state,
        forgotten: l.forgotten,
        folder,
        preview: head.map(|h| h.map(|(_, p)| p)),
        ops,
        rebinds,
        shares,
        shares_error,
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

/// Every op reverted, none foreign, and a `.old` left by the journal (P2-15).
pub(super) fn cleanup_pending(ops: &std::collections::BTreeMap<u16, OpLog>) -> bool {
    let all = ops.values().all(|o| {
        o.reverted
            .as_ref()
            .is_some_and(|r| r.observed != Observed::Foreign)
    });
    all && ops.values().any(|o| !o.pending_old().is_empty())
}

fn op_status(
    app: &AppDir<'_>,
    t: &TxnId,
    k: u16,
    o: &OpLog,
    plan: Option<&Plan>,
    exact: bool,
) -> OpStatus {
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
            Target::Key { .. } | Target::Value { .. } | Target::Rule { .. } => None,
        });
    let cleanup = old_left(o)
        .filter(|_| !exact)
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

/// Why [`firewall_orphans`] has no list (security review N1 of P4-2d: each with its own words).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrphansError {
    /// The firewall cannot be read.
    #[error("the firewall cannot be read now: {0}")]
    Firewall(crate::sys::SysError),
    /// The journal cannot be listed.
    #[error("the journal cannot be read now: {0}")]
    Journal(JournalError),
}

/// A Rerun firewall rule that no transaction of this account owns (ADR 0023 §6, A4 N6; P4-2d).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanRule {
    /// Its name (escaped).
    pub name: Shown<'static>,
    /// Its program (escaped).
    pub program: Shown<'static>,
}

/// The Rerun rules (group `Rerun` or Rerun's name form, one enumeration) that no transaction of
/// this account that is not closed names. The firewall is machine-wide: the rules of other
/// Windows accounts are among them, and a rule `forget` left in place. A transaction whose head
/// cannot be read names nothing (its rules are listed rather than hidden). Read only.
///
/// # Errors
/// [`OrphansError`]: the firewall or the journal cannot be read.
pub fn firewall_orphans(
    sys: &dyn crate::sys::System,
    app: &AppDir<'_>,
) -> Result<Vec<OrphanRule>, OrphansError> {
    use crate::policy::firewall::{RuleName, orphans, rerun_rules};
    let rules = rerun_rules(sys.firewall()).map_err(OrphansError::Firewall)?;
    if rules.is_empty() {
        return Ok(Vec::new());
    }
    let j = Journal::new(app, InstanceTag::new());
    let listing = j.list().map_err(OrphansError::Journal)?;
    let mut owned = Vec::new();
    for l in &listing.txns {
        let open = !l.forgotten
            && l.view
                .as_ref()
                .is_ok_and(|v| !matches!(v.state, TxnState::Closed(_)));
        if !open {
            continue;
        }
        let Ok(full) = j.load(&l.id, VerifyBackups::Length) else {
            continue;
        };
        let Some(plan) = full
            .head
            .as_deref()
            .and_then(|h| super::decode_head(h).ok())
        else {
            continue;
        };
        if let Some((first, last)) = super::helper::batch_of(&plan) {
            owned.extend(
                (first..=last)
                    .filter_map(|k| super::helper::rule_of(&plan, &l.id, k))
                    .filter_map(|r| RuleName::parse(&r.rule.name)),
            );
        }
    }
    Ok(orphans(&rules, &owned)
        .into_iter()
        .map(|r| OrphanRule {
            name: escape::text(&r.name).into_owned(),
            program: escape::path(&r.program).into_owned(),
        })
        .collect())
}
