//! Revert, rebind and forget (ADR 0027 amendment P5-2b): a preview step that runs every check of
//! the operation read only and returns what the caller shows with a `*Shown` token, then the
//! operation, which takes only that token.
//!
//! - [`revert_preview`] → [`revert`]: the gates of the transaction (`Forgotten`, `Closed`, an
//!   empty one without a head, damaged or unreadable), `exec::revert_check` before
//!   `exec::verify` (so no preview offers a revert that is refused anyway), the fate of the
//!   launch profile (X12), the administrator prompt a firewall rule still there brings, and the
//!   question the caller asks ([`RevertAsk`]: the pending cleanup as [`CleanupAsk`]).
//! - [`rebind_preview`] → [`rebind`]: the same gates, then `exec::rebind_check` (P2-14b).
//! - [`forget_preview`] → [`forget`]: the transaction, what is on disk now if its head can be
//!   read, the fate of the launch profile and whether a revert would finish it cleanly.
//!
//! A token carries the transaction and SHA-256 digests of what the preview showed: the
//! transaction as the journal holds it ([`TxnStatus`]) and the observation (`Verified`, or why
//! there is none). The operation takes the journal lock, observes again and compares before
//! anything is written: on any difference it is [`ActError::Changed`] (show the preview
//! again). A rebind compares the transaction right after the lock and its own observation with
//! the new binding after its checks, both before its record. The digest is taken over the
//! `Debug` form of these values, which holds every field and is the same for the same state.
//!
//! The proof tokens are a naming convention (as `Previewed`): nothing proves the caller showed
//! the preview, but there is no `revert` without a [`RevertShown`] and no token outside this
//! module.

use sha2::{Digest, Sha256};

use crate::elevate::PromptState;
use crate::exec::launch_result::ProfileId;
use crate::exec::{
    self, ExecCtx, ExecError, Halt, Look, OldSeen, OpState, PendingOld, RebindPreview, RebindTo,
    Refusal, RevertReport, TxnLine, TxnStatus, Verified,
};
use crate::journal::{Closing, InstanceTag, Journal, JournalError, Observed, TxnId};
use crate::policy::root::AppDir;

use super::{Guarded, head, profile_id_of, profile_op};

// ---------- What is shown ----------

/// Why a revert, a rebind or a forget is not offered (nothing written).
#[derive(Debug)]
pub enum RevertGate {
    /// Rerun's folder does not exist: there is no transaction.
    NoAppDir,
    /// The journal names no such transaction (the error says which).
    NotFound(JournalError),
    /// The journal cannot be read.
    Journal(JournalError),
    /// The transaction was forgotten.
    Forgotten,
    /// The transaction is closed.
    Closed(Closing),
    /// An empty transaction without a readable head: it changed nothing (revert only).
    Empty,
    /// Damaged or unreadable: only forget closes it (revert only).
    Blocked,
    /// A check of the operation refused.
    Refused(Refusal),
    /// The observation failed otherwise.
    Failed(ExecError),
}

/// What becomes of a transaction's launch profile (X12, review M1/B1): the launch option Rerun
/// does not change depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileFate {
    /// No profile at the name any more (a created profile reverted, or `profiles` gone): the
    /// shim finds none, the option should go.
    Gone,
    /// A replaced profile reverted: the profile from before is back and applies.
    PreviousBack,
    /// The profile stays and applies (not reverted, changed by someone else, a halt before it,
    /// `forget`).
    Stays,
    /// An earlier run left it as found (changed by someone else); whether it is still there is
    /// not known now (its folder may be gone: `verify` shows such an op as recorded).
    Left,
}

/// The launch profile of a transaction and what becomes of it (X12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchOption {
    /// The profile.
    pub id: ProfileId,
    /// What becomes of it.
    pub fate: ProfileFate,
}

/// The question before a revert that only cleans up (P2-15): Rerun's copies it deletes, of
/// which `in_use` are in use now (a process holding one with delete sharing lets it go all the
/// same, review S1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupAsk {
    /// The copies the revert tries to delete.
    pub n: usize,
    /// Of those, the ones in use now.
    pub in_use: usize,
}

/// What the caller asks before a revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertAsk {
    /// Nothing: an empty transaction, or only a cleanup with nothing to delete.
    Nothing,
    /// The cleanup question (P2-15).
    Cleanup(CleanupAsk),
    /// Revert `ops` ops.
    Revert {
        /// The ops `verify` observed.
        ops: usize,
    },
}

/// What a revert does now (rule 5).
#[derive(Debug)]
pub struct RevertPreview {
    /// The transaction as the journal holds it (its head's preview built).
    pub status: TxnStatus,
    /// What a revert does now, newest op first.
    pub verified: Verified,
    /// An empty transaction with a head: the revert only closes it.
    pub empty: bool,
    /// The launch profile and its fate once the revert completes (not for an empty one).
    pub launch_option: Option<LaunchOption>,
    /// The administrator prompt state, when a firewall rule is still there (ADR 0023 §10).
    pub prompt: Option<PromptState>,
    /// The question.
    pub ask: RevertAsk,
}

/// What the preview showed (digests, module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    status: [u8; 32],
    fates: [u8; 32],
}

/// The transaction and digests of the revert preview shown (module docs). Only
/// [`revert_preview`] builds one:
///
/// ```compile_fail,E0451
/// # fn f(t: rerun_core::journal::TxnId) {
/// // Every field named: only their privacy refuses it.
/// let s = rerun_core::flow::RevertShown { txn: t, seen: todo!(), profile: todo!() };
/// # }
/// ```
#[derive(Debug)]
pub struct RevertShown {
    txn: TxnId,
    seen: Seen,
    profile: Option<ProfileSeen>,
}

impl RevertShown {
    /// The transaction.
    pub fn txn(&self) -> TxnId {
        self.txn
    }
}

/// What a rebind does (P2-14b, rule 5).
#[derive(Debug)]
pub struct RebindView {
    /// The transaction as the journal holds it.
    pub status: TxnStatus,
    /// The binding, the folders and what the revert meets there.
    pub rebind: RebindPreview,
    /// The launch profile and its fate once the revert there completes.
    pub launch_option: Option<LaunchOption>,
}

/// The transaction, the binding and digests of the rebind preview shown. Only
/// [`rebind_preview`] builds one.
#[derive(Debug)]
pub struct RebindShown {
    txn: TxnId,
    to: RebindTo,
    seen: Seen,
    profile: Option<ProfileSeen>,
}

impl RebindShown {
    /// The transaction.
    pub fn txn(&self) -> TxnId {
        self.txn
    }
}

/// How a forget's preview ends when a revert would finish the transaction cleanly instead
/// (review S7: nothing foreign, nothing halts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertWould {
    /// Revert it, cleanly.
    BeClean,
    /// A copy of Rerun's is kept next to a file that changed (it stays either way).
    KeepCopy,
    /// A copy of Rerun's is in use; a revert deletes it once it is free.
    CleanUp,
}

/// What forget does (it changes nothing on disk).
#[derive(Debug)]
pub struct ForgetPreview {
    /// The transaction as the journal holds it.
    pub status: TxnStatus,
    /// What is on disk now (`verify`), if the head can be read.
    pub verified: Option<Result<Verified, ExecError>>,
    /// The launch profile and its fate (as it is now: forget changes nothing).
    pub launch_option: Option<LaunchOption>,
    /// A revert would finish it cleanly.
    pub revert_would: Option<RevertWould>,
}

/// The transaction and digests of the forget preview shown. Only [`forget_preview`] builds
/// one.
#[derive(Debug)]
pub struct ForgetShown {
    txn: TxnId,
    seen: Seen,
}

impl ForgetShown {
    /// The transaction.
    pub fn txn(&self) -> TxnId {
        self.txn
    }
}

/// How a revert ended (the closing line of the report).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertEnd {
    /// Closed.
    Closed,
    /// Halted: open.
    Halted,
    /// Copies of Rerun's still in use: open (P2-15).
    InUse(usize),
    /// A copy of Rerun's kept next to a file that changed: open (P2-15).
    Kept,
    /// An op was foreign: open, only forget closes it.
    Foreign,
}

/// What a revert or a rebind did.
#[derive(Debug)]
pub struct RevertOutcome {
    /// The report of `exec`.
    pub report: RevertReport,
    /// How it ended.
    pub end: RevertEnd,
    /// The launch profile and what became of it (X12).
    pub launch_option: Option<LaunchOption>,
}

/// Why a revert, a rebind or a forget did not go through.
#[derive(Debug)]
pub enum ActError {
    /// What is observed under the lock differs from the preview: nothing written, show it
    /// again.
    Changed,
    /// `exec`'s error (a refusal: nothing written). A rebind's
    /// `Exec(Refused(Rebind(`[`exec::RebindRefusal::Changed`]`)))` (the folder or a created folder
    /// is another one than the preview showed) also means "show the preview again".
    Exec(ExecError),
}

impl From<ExecError> for ActError {
    fn from(e: ExecError) -> Self {
        match e {
            ExecError::Refused(Refusal::Changed { .. }) => Self::Changed,
            e => Self::Exec(e),
        }
    }
}

// ---------- The digests ----------

/// The `Debug` form of a value streamed into SHA-256 (no string of the whole form is built).
struct Hashing(Sha256);

impl std::fmt::Write for Hashing {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.update(s.as_bytes());
        Ok(())
    }
}

/// The digest of `v`'s `Debug` form. The types in it derive `Debug` (never a manual impl, a
/// source rule of `rerun-core`), so it holds every field.
fn sha(v: &impl std::fmt::Debug) -> [u8; 32] {
    let mut h = Hashing(Sha256::new());
    // Writing into the hasher cannot fail; a `Debug` impl that fails would only hash less.
    let _ = std::fmt::Write::write_fmt(&mut h, format_args!("{v:?}"));
    h.0.finalize().into()
}

fn seen_of(st: &TxnStatus, v: Option<Result<&Verified, &ExecError>>) -> Seen {
    Seen {
        status: sha(st),
        fates: sha(&v),
    }
}

/// The transaction as the journal holds it now (under the lock).
fn status_now(app: &AppDir<'_>, t: &TxnId) -> Option<[u8; 32]> {
    exec::txn_status(app, t).ok().map(|st| sha(&st))
}

/// The transaction and its observation now, as the preview took them (`observe`: the head can
/// be read; a revert always observes), under the lock.
fn seen_now(cx: &ExecCtx<'_>, t: &TxnId, forget: bool) -> Option<Seen> {
    let st = exec::txn_status(cx.app, t).ok()?;
    let j = Journal::new(cx.app, cx.tag);
    let v = (!forget || head(&st).is_some()).then(|| exec::verify_in(cx, &j, t));
    Some(seen_of(&st, v.as_ref().map(Result::as_ref)))
}

// ---------- The gates ----------

fn ctx<'a>(g: &'a Guarded<'_>, app: &'a AppDir<'a>) -> ExecCtx<'a> {
    ExecCtx {
        sys: g.env().sys,
        fr: g.fr(),
        app,
        tag: InstanceTag::new(),
    }
}

/// The transaction from the journal.
fn load(app: &AppDir<'_>, t: &TxnId) -> Result<TxnStatus, RevertGate> {
    exec::txn_status(app, t).map_err(|e| match e {
        JournalError::NotFound(_) => RevertGate::NotFound(e),
        e => RevertGate::Journal(e),
    })
}

/// The gates of a revert and a rebind, in the CLI's order.
fn revert_gates(st: &TxnStatus) -> Result<(), RevertGate> {
    if st.is_forgotten() {
        return Err(RevertGate::Forgotten);
    }
    match st.state {
        TxnLine::Closed(how) => Err(RevertGate::Closed(how)),
        // Review nit: an empty transaction without a readable head changed nothing.
        TxnLine::Empty if head(st).is_none() => Err(RevertGate::Empty),
        // Only forget closes these; one text with the core (`Refusal::Blocked`).
        TxnLine::Damaged(_) | TxnLine::Unreadable(_) => Err(RevertGate::Blocked),
        _ => Ok(()),
    }
}

// ---------- X12 ----------

/// What a revert's observation of the profile op means for the profile.
fn fate_of(replace: bool, o: Observed) -> ProfileFate {
    match o {
        Observed::Before | Observed::After if replace => ProfileFate::PreviousBack,
        Observed::Before | Observed::After => ProfileFate::Gone,
        Observed::Drifted | Observed::Foreign | Observed::Kept => ProfileFate::Stays,
    }
}

/// The op `k` was left as found by an earlier revert (`verify` shows it as recorded when its
/// folder cannot be read, review L-a).
fn left_earlier(st: &TxnStatus, k: u16) -> bool {
    st.ops
        .iter()
        .any(|o| o.op == k && o.state == OpState::Reverted(Observed::Foreign))
}

/// The fate of the profile op `k` from the journal (an earlier run reverted it), else `None`.
fn recorded_fate(st: &TxnStatus, k: u16, replace: bool) -> Option<ProfileFate> {
    st.ops
        .iter()
        .find(|o| o.op == k)
        .and_then(|o| match o.state {
            OpState::Reverted(obs) => Some(fate_of(replace, obs)),
            _ => None,
        })
}

/// A revert's halt: at the profile op (its folder is missing: no profile) or before it.
fn halted_fate(h: &Halt, k: u16) -> ProfileFate {
    if h.op == k {
        ProfileFate::Gone
    } else {
        ProfileFate::Stays
    }
}

/// The profile op of the head and its ID.
fn profile_of_head(st: &TxnStatus) -> Option<(u16, bool, ProfileId)> {
    let p = head(st)?;
    let (k, replace) = profile_op(p)?;
    Some((k, replace, profile_id_of(p)?))
}

/// What the fate after a revert needs of the transaction as the preview showed it (the same
/// under the lock: the digest says so; a closed transaction's head is not read again).
#[derive(Debug, Clone, Copy)]
struct ProfileSeen {
    k: u16,
    replace: bool,
    id: ProfileId,
    left: bool,
    recorded: Option<ProfileFate>,
}

fn profile_seen(st: &TxnStatus) -> Option<ProfileSeen> {
    let (k, replace, id) = profile_of_head(st)?;
    Some(ProfileSeen {
        k,
        replace,
        id,
        left: left_earlier(st, k),
        recorded: recorded_fate(st, k, replace),
    })
}

/// X12 before a revert (review M1/B1): what the revert `verify` describes will leave.
pub(crate) fn fate_before(st: &TxnStatus, v: &Verified) -> Option<LaunchOption> {
    let (k, replace, id) = profile_of_head(st)?;
    let fate = if left_earlier(st, k) {
        ProfileFate::Left
    } else if let Some((_, o)) = v.ops.iter().find(|(x, _)| *x == k) {
        // A halt is newest first: the profile op is observed only if it is reached.
        fate_of(replace, *o)
    } else if let Some(h) = &v.halted {
        halted_fate(h, k)
    } else {
        recorded_fate(st, k, replace).unwrap_or(ProfileFate::Stays)
    };
    Some(LaunchOption { id, fate })
}

/// X12 after a revert of `st` (as the preview showed it): what its report says became of the
/// profile.
#[cfg(test)]
pub(crate) fn fate_after(st: &TxnStatus, rep: &RevertReport) -> Option<LaunchOption> {
    fate_after_seen(profile_seen(st), rep)
}

fn fate_after_seen(p: Option<ProfileSeen>, rep: &RevertReport) -> Option<LaunchOption> {
    let p = p?;
    let fate = if let Some(o) = rep.ops.iter().find(|o| o.op == p.k) {
        fate_of(p.replace, o.observed)
    } else if p.left {
        ProfileFate::Left
    } else if let Some(h) = &rep.halted {
        halted_fate(h, p.k)
    } else {
        p.recorded.unwrap_or(ProfileFate::Stays)
    };
    Some(LaunchOption { id: p.id, fate })
}

/// X12 before `forget`: the profile as it is now (forget changes nothing).
pub(crate) fn fate_forget(st: &TxnStatus, v: Option<&Verified>) -> Option<LaunchOption> {
    let (k, replace, id) = profile_of_head(st)?;
    let halted_here = v.and_then(|v| v.halted.as_ref()).is_some_and(|h| h.op == k);
    let fate = if left_earlier(st, k) {
        ProfileFate::Left
    } else {
        recorded_fate(st, k, replace).unwrap_or_else(|| {
            match v.and_then(|v| v.ops.iter().find(|(x, _)| *x == k)) {
                Some((_, Observed::Before)) if replace => ProfileFate::PreviousBack,
                Some((_, Observed::Before)) => ProfileFate::Gone,
                // `profiles` missing: `verify` halts at the profile op itself (review L-a).
                None if halted_here => ProfileFate::Gone,
                _ => ProfileFate::Stays,
            }
        })
    };
    Some(LaunchOption { id, fate })
}

// ---------- Revert ----------

/// An earlier revert left an op of `st` as found (changed by someone else): only forget closes
/// it.
pub fn left_foreign(st: &TxnStatus) -> bool {
    st.ops
        .iter()
        .any(|o| o.state == OpState::Reverted(Observed::Foreign))
}

/// The `.old` files of `items` that keep the transaction open: (in use, kept).
pub fn holding(items: &[PendingOld]) -> (usize, usize) {
    let n = |s: OldSeen| items.iter().filter(|p| p.seen == s).count();
    (n(OldSeen::InUse), n(OldSeen::Kept))
}

/// How the revert of `rep` ended: closed; halted, foreign, or a file of Rerun's still left
/// (P2-15): open.
pub(crate) fn revert_end(rep: &RevertReport) -> RevertEnd {
    let (in_use, kept) = holding(&rep.cleanup);
    if rep.closed.is_some() {
        RevertEnd::Closed
    } else if rep.halted.is_some() {
        RevertEnd::Halted
    } else if in_use > 0 {
        RevertEnd::InUse(in_use)
    } else if kept > 0 {
        RevertEnd::Kept
    } else {
        RevertEnd::Foreign
    }
}

/// The question before a revert (P2-15: a revert that only cleans up asks before it deletes;
/// nothing to delete, no question; an empty transaction changed nothing: no question).
fn ask_of(st: &TxnStatus, v: &Verified, empty: bool) -> RevertAsk {
    let count = |s: OldSeen| v.cleanup.iter().filter(|p| p.seen == s).count();
    let (ours, in_use) = (count(OldSeen::Ours), count(OldSeen::InUse));
    if st.state == TxnLine::CleanupPending {
        if ours + in_use > 0 {
            RevertAsk::Cleanup(CleanupAsk {
                n: ours + in_use,
                in_use,
            })
        } else {
            RevertAsk::Nothing
        }
    } else if empty {
        RevertAsk::Nothing
    } else {
        RevertAsk::Revert { ops: v.ops.len() }
    }
}

/// A firewall rule of the head is still there: the administrator prompt it brings (P4-2d,
/// ADR 0023 §10).
fn prompt_of(g: &Guarded<'_>, st: &TxnStatus, v: &Verified) -> Option<PromptState> {
    let p = head(st)?;
    p.firewall.as_ref()?;
    let rule_there = v.ops.iter().any(|(k, o)| {
        *o == Observed::After
            && p.ops
                .get(usize::from(*k))
                .is_some_and(|x| x.firewall.is_some())
    });
    rule_there.then(|| crate::elevate::prompt::read(g.env().sys))
}

/// The preview of the revert of `t` (module docs). Writes nothing.
pub fn revert_preview(
    g: &Guarded<'_>,
    t: &TxnId,
) -> Result<(RevertPreview, RevertShown), RevertGate> {
    let app = g.app().ok_or(RevertGate::NoAppDir)?;
    let st = load(app, t)?;
    revert_gates(&st)?;
    let cx = ctx(g, app);
    // Senior-dev S-a: every check of the revert first, so neither the preview nor the question
    // offers a revert that is refused anyway.
    exec::revert_check(&cx, t).map_err(RevertGate::Refused)?;
    let v = exec::verify(&cx, t).map_err(|e| match e {
        ExecError::Refused(r) => RevertGate::Refused(r),
        e => RevertGate::Failed(e),
    })?;
    let seen = seen_of(&st, Some(Ok(&v)));
    let profile = profile_seen(&st);
    let empty = st.state == TxnLine::Empty;
    let preview = RevertPreview {
        launch_option: if empty { None } else { fate_before(&st, &v) },
        prompt: prompt_of(g, &st, &v),
        ask: ask_of(&st, &v, empty),
        empty,
        verified: v,
        status: st,
    };
    Ok((
        preview,
        RevertShown {
            txn: *t,
            seen,
            profile,
        },
    ))
}

/// Reverts the transaction of `s` ([`exec::revert`]), after comparing what it observes under
/// the lock with the preview `s` was made from: on any difference [`ActError::Changed`], nothing
/// written. Takes the token, never a transaction ID:
///
/// ```compile_fail,E0308
/// # fn f(g: &rerun_core::flow::Guarded<'_>, t: rerun_core::journal::TxnId) {
/// let _ = rerun_core::flow::revert(g, t);
/// # }
/// ```
///
/// The path through the API:
///
/// ```no_run
/// # fn f(g: rerun_core::flow::Guarded<'_>, t: rerun_core::journal::TxnId) {
/// if let Ok((preview, shown)) = rerun_core::flow::revert_preview(&g, &t) {
///     // … the caller renders `preview` and asks `preview.ask` …
///     let _ = rerun_core::flow::revert(&g, shown);
/// }
/// # }
/// ```
pub fn revert(g: &Guarded<'_>, s: RevertShown) -> Result<RevertOutcome, ActError> {
    let app = g.app().ok_or(ActError::Changed)?;
    let cx = ctx(g, app);
    let t = s.txn;
    let same = |l: Look<'_>| match l {
        Look::Early => seen_now(&cx, &t, false) == Some(s.seen),
        Look::Rebound(_) => false,
    };
    let report = exec::revert_seen(&cx, &t, &same)?;
    Ok(outcome(s.profile, report))
}

/// The outcome of a revert: how it ended, and what became of the profile.
fn outcome(profile: Option<ProfileSeen>, report: RevertReport) -> RevertOutcome {
    RevertOutcome {
        end: revert_end(&report),
        launch_option: fate_after_seen(profile, &report),
        report,
    }
}

// ---------- Rebind ----------

/// The preview of the rebind of `t` (P2-14b; module docs): the gates of a revert, then
/// `exec::rebind_check`. A transaction bound already is
/// `Refused(Refusal::Rebind(`[`exec::RebindRefusal::AlreadyBound`]`))`: the caller reverts it as it
/// is ([`revert_preview`]). Writes nothing.
pub fn rebind_preview(g: &Guarded<'_>, t: &TxnId) -> Result<(RebindView, RebindShown), RevertGate> {
    let app = g.app().ok_or(RevertGate::NoAppDir)?;
    let st = load(app, t)?;
    revert_gates(&st)?;
    let cx = ctx(g, app);
    let p = exec::rebind_check(&cx, t).map_err(RevertGate::Refused)?;
    let seen = Seen {
        status: sha(&st),
        fates: sha(&p.verified),
    };
    let shown = RebindShown {
        txn: *t,
        to: p.to.clone(),
        seen,
        profile: profile_seen(&st),
    };
    let view = RebindView {
        launch_option: fate_before(&st, &p.verified),
        status: st,
        rebind: p,
    };
    Ok((view, shown))
}

/// Binds and reverts the transaction of `s` ([`exec::revert_rebound`]), after comparing the
/// transaction under the lock and the observation with the new binding before the record with
/// the preview: on any difference [`ActError::Changed`], nothing written.
pub fn rebind(g: &Guarded<'_>, s: RebindShown) -> Result<RevertOutcome, ActError> {
    let app = g.app().ok_or(ActError::Changed)?;
    let cx = ctx(g, app);
    let t = s.txn;
    let same = |l: Look<'_>| match l {
        Look::Early => status_now(app, &t) == Some(s.seen.status),
        Look::Rebound(v) => sha(v) == s.seen.fates,
    };
    let report = exec::revert_rebound_seen(&cx, &t, &s.to, &same)?;
    Ok(outcome(s.profile, report))
}

// ---------- Forget ----------

/// Whether a revert would finish `st` cleanly (review S7: nothing foreign, nothing halts), and
/// how.
fn revert_would(st: &TxnStatus, v: Option<&Verified>) -> Option<RevertWould> {
    let v = v?;
    if v.halted.is_some() || v.ops.iter().any(|(_, o)| *o == Observed::Foreign) || left_foreign(st)
    {
        return None;
    }
    Some(match holding(&v.cleanup) {
        (0, 0) => RevertWould::BeClean,
        (0, _) => RevertWould::KeepCopy,
        _ => RevertWould::CleanUp,
    })
}

/// The preview of forgetting `t` (module docs): `Forgotten` and `Closed` are its gates. Writes
/// nothing.
pub fn forget_preview(
    g: &Guarded<'_>,
    t: &TxnId,
) -> Result<(ForgetPreview, ForgetShown), RevertGate> {
    let app = g.app().ok_or(RevertGate::NoAppDir)?;
    let st = load(app, t)?;
    if st.is_forgotten() {
        return Err(RevertGate::Forgotten);
    }
    if let TxnLine::Closed(how) = st.state {
        return Err(RevertGate::Closed(how));
    }
    let cx = ctx(g, app);
    // What is on disk now, if the head can be read (`verify` writes nothing).
    let verified = head(&st).map(|_| exec::verify(&cx, t));
    let seen = seen_of(&st, verified.as_ref().map(Result::as_ref));
    let ok = verified.as_ref().and_then(|r| r.as_ref().ok());
    let preview = ForgetPreview {
        launch_option: fate_forget(&st, ok),
        revert_would: revert_would(&st, ok),
        status: st,
        verified,
    };
    Ok((preview, ForgetShown { txn: *t, seen }))
}

/// Forgets the transaction of `s` ([`exec::forget`]), after comparing it and what is on disk
/// under the lock with the preview: on any difference [`ActError::Changed`], nothing written.
pub fn forget(g: &Guarded<'_>, s: ForgetShown) -> Result<(), ActError> {
    let app = g.app().ok_or(ActError::Changed)?;
    let cx = ctx(g, app);
    let t = s.txn;
    let same = |l: Look<'_>| match l {
        Look::Early => seen_now(&cx, &t, true) == Some(s.seen),
        Look::Rebound(_) => false,
    };
    exec::forget_seen(&cx, &t, &same).map_err(ActError::from)
}

#[cfg(test)]
#[path = "revert_tests.rs"]
mod tests;
