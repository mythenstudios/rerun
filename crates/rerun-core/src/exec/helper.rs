//! The elevated helper's batch in `exec` (ADR 0023 §7 to §9; A4 S7, S8, N5, N9; P4-2d).
//!
//! A plan's `FirewallRule` ops are its last ops, the helper batch. Only the elevated helper
//! changes them; the CLI observes the rules itself (outcome A of §8: the firewall is readable
//! without administrator rights) and records the batch in the journal:
//!
//! - **Before the lock** ([`ready`]): the installed helper passes the pre-check of §2
//!   (`policy::root::helper_for_this_build`: also no test-key helper for a release CLI, N5 of
//!   P4-2c; else [`Refusal::HelperUnsafe`]), and Windows allows an
//!   elevation at all (`elevate::prompt`: `Denied` and `UacOff` are
//!   [`Refusal::NoElevation`]). No prompt is shown for a plan that is refused anyway.
//! - **Before `begin`** ([`recheck`], A4 S7): the engine's derivation again, non-elevated, from
//!   the signed index the plan names and the game folder as it is now; the plan's rule ops must
//!   be exactly the anchors of `elevate::check_plan`. A helper refusal can then only mean that
//!   something changed in between or was tampered with.
//! - **Apply** ([`run_batch`]): after every other op is done, observed `After` and flushed (the
//!   game folders and `HKCU`, so that only `Done` records and `Applied` follow the helper), the
//!   request file is written under the journal lock (N9: a name already taken moves on to the
//!   next number; leftovers of earlier runs are deleted first, bounded), then `HelperBatch`
//!   (flushed), then the one helper run. `Done(k)` for every op only when the helper reports
//!   `Done` with every op `After` and the CLI's own observation agrees (N5: nothing for
//!   `LeftOpen`). A declined prompt, a refusal, a helper rollback or a start that failed lead to
//!   the rollback of the earlier ops (exit 4), which observes the batch again and records it
//!   `Before` without a helper; anything else stays open ([`super::ApplyError::HelperOpen`],
//!   exit 5): a second prompt in the same run never happens (R3).
//! - **Revert** ([`revert_batch`], LIFO: the batch first): `ensure_idle` before a batch without
//!   a result is observed (A4 S8); the rules observed; without a rule of Rerun's left, a
//!   `RevertBatch` without a request and a `RevertDone` per op (no helper, no prompt). Else a
//!   remove request, `RevertBatch` with its digest (flushed), the helper, and `RevertDone(k)`
//!   from the highest op down while the helper's report and the CLI's observation agree. A
//!   declined prompt, a refusal, an unknown result or a disagreement halts the revert there
//!   ([`super::Halt`]): nothing below the batch is reverted in that run (LIFO), the transaction
//!   stays open (exit 5) and the next revert asks again. A rollback never starts the helper.
//!
//! Remove requests are formed from the journal head alone (R1): the program path the head
//! records, never a rebound root, never an index or a hash.

use sha2::{Digest as _, Sha256};

use super::{ExecCtx, ExecError, Halt, OpReport, Refusal};
use crate::catalog::model::Id;
use crate::elevate::request::{
    AddOp, Body, DirRef, RemoveOp, Request, RequestName, RequestRef, RootRef, encode,
};
use crate::elevate::{ExitClass, Judged, OpResult, PlanRefusal, PromptKind, Reason, check_plan};
use crate::journal::{Digest, JournalError, Observed, OpLog, Reverting, TxnId, TxnWriter};
use crate::path::RelPath;
use crate::plan::{Op, Plan, RootIx, RootKind};
use crate::policy::firewall::{self as pf, Program};
use crate::policy::root::{AppSub, Create, HelperImage, RootId};
use crate::sys::fs::{Attrs, NewFile, TmpName};
use crate::sys::{FwRule, SysError, SysErrorKind, System};

/// Why the helper batch did not end as planned (ADR 0023 §7, §8).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HelperFailure {
    /// The UAC prompt was declined: nothing ran.
    #[error("administrator approval was declined")]
    Declined,
    /// The helper refused before it changed anything.
    #[error("the helper refused: {}", reason_words(*.0))]
    Refused(Reason),
    /// The helper failed after a change and undid its own changes.
    #[error("the helper failed and undid its own changes")]
    RolledBack,
    /// The helper failed and could not undo every change.
    #[error("the helper failed and could not undo all of its changes")]
    LeftOpen,
    /// The run cannot be trusted (A4 S2): the process was not shown to be Rerun's elevated
    /// helper, or its exit code is none of the helper's.
    #[error(
        "the result of the helper cannot be trusted (the process that ran was not shown to be \
         Rerun's elevated helper, or it ended without the helper's report)"
    )]
    Unknown,
    /// The helper's report and the CLI's own observation of the firewall differ.
    #[error("the firewall does not hold what the helper reported")]
    Disagree,
    /// No helper process was created (`ShellExecuteExW` failed; blocked by WDAC or Smart App
    /// Control: os error 4551). Only then: once a process may exist, a missing handle or a
    /// failed wait is `HelperRun::Lost`, judged [`Self::Unknown`] (P4-2d review follow-up).
    #[error("the helper could not be started: {0}")]
    Start(SysError),
    /// The firewall cannot be read now.
    #[error("the firewall rules cannot be read now: {0}")]
    Unreadable(SysError),
    /// A helper of an earlier run may still be running, or its lock is held (A4 S8).
    #[error("{0}")]
    Busy(SysError),
    /// A rollback met a rule of Rerun's: removing it needs the helper, which the same run never
    /// starts twice (R3).
    #[error("a firewall rule of this transaction is there; only rerun revert removes it")]
    NeedsRevert,
}

impl HelperFailure {
    /// The apply's rollback may run: nothing of the helper's can be left (the rollback observes
    /// every rule again and records it only if it is not there).
    pub(super) fn rolls_back(&self) -> bool {
        matches!(
            self,
            Self::Declined | Self::Refused(_) | Self::RolledBack | Self::Start(_)
        )
    }
}

/// The words of a refusal reason (for the report; ADR 0023 §7).
pub fn reason_words(r: Reason) -> &'static str {
    match r {
        Reason::Usage => "its command line is not the helper's form",
        Reason::NotElevated => "it does not run with administrator rights",
        Reason::ImageFolder => "it is not the helper installed in Program Files\\Rerun",
        Reason::Build => "the installed helper is from another build of Rerun",
        Reason::Request => "the request file was changed or cannot be read",
        Reason::Index => "the signed index cannot be used",
        Reason::Topo => "the Topo or a variant cannot be used",
        Reason::Root => "the game folder is not the one planned or is not allowed",
        Reason::Program => "an executable is not there with the SHA-256 the Topo signs",
        Reason::AntiCheat => "an anti-cheat system was found",
        Reason::Ops => "the rules asked for are not those the Topo authorises",
        Reason::DuplicateName => "a rule of the same name already exists",
        Reason::Firewall => "the firewall refused or cannot be reached",
        Reason::Internal => "an internal error",
        Reason::Busy => "another helper is running",
    }
}

/// The helper batch of a plan: its first and last op, if it has one (the last ops, `plan`
/// checks the order).
pub(super) fn batch_of(plan: &Plan) -> Option<(u16, u16)> {
    let first = plan.ops.iter().position(|o| o.target().is_helper())?;
    let first = u16::try_from(first).ok()?;
    let last = u16::try_from(plan.ops.len().checked_sub(1)?).ok()?;
    Some((first, last))
}

/// The Topo of a plan with helper ops (`plan` requires a source for them).
fn topo_of(plan: &Plan) -> Option<Id> {
    plan.source.as_ref().and_then(|s| Id::parse(&s.topo))
}

/// One rule of the batch: the rule, its program and direction as the head records them.
pub(super) struct RuleOf {
    /// The rule of Rerun's form.
    pub(super) rule: FwRule,
    /// Its program.
    pub(super) program: Program,
    /// Its direction.
    pub(super) direction: pf::Direction,
}

/// The rule of op `k` of `plan` in transaction `txn`: the head's planned root path and program
/// (R1, A4 S6 a), never a rebound root. `None` for an op that is no rule (never in a decoded
/// plan's batch).
pub(super) fn rule_of(plan: &Plan, txn: &TxnId, k: u16) -> Option<RuleOf> {
    let Some(Op::FirewallRule {
        root,
        program,
        direction,
    }) = plan.ops.get(usize::from(k))
    else {
        return None;
    };
    let r = plan.roots.get(usize::from(root.0))?;
    let p = Program::new(&r.path, program).ok()?;
    Some(RuleOf {
        rule: pf::rule(&topo_of(plan)?, txn, k, &p, *direction),
        program: p,
        direction: *direction,
    })
}

/// The rules of ops `first..=last`.
fn rules_of(plan: &Plan, txn: &TxnId, first: u16, last: u16) -> Result<Vec<RuleOf>, ExecError> {
    (first..=last)
        .map(|k| rule_of(plan, txn, k).ok_or_else(|| not_a_rule(k)))
        .collect()
}

/// A rule op as the plan names it: its index, program and direction.
type NamedRule<'p> = (u16, &'p RelPath, pf::Direction);

/// The rule ops `first..=last` as the plan names them, all on one root (the engine plans root
/// 0): the root and per op its index, program and direction; `Err(k)` at the first op that is no
/// rule or names another root.
fn rule_ops(plan: &Plan, first: u16, last: u16) -> Result<(RootIx, Vec<NamedRule<'_>>), u16> {
    let mut root_ix = None;
    let mut out = Vec::new();
    for k in first..=last {
        let Some(Op::FirewallRule {
            root,
            program,
            direction,
        }) = plan.ops.get(usize::from(k))
        else {
            return Err(k);
        };
        if root_ix.is_some_and(|r| r != *root) {
            return Err(k);
        }
        root_ix = Some(*root);
        out.push((k, program, *direction));
    }
    root_ix.map(|r| (r, out)).ok_or(first)
}

/// What a decoded helper report says beyond `Done` (`None` for `Done`).
fn failure_of(e: &crate::elevate::HelperExit) -> Option<HelperFailure> {
    match e.class {
        ExitClass::Done => None,
        ExitClass::Refused => Some(HelperFailure::Refused(e.reason.unwrap_or(Reason::Internal))),
        ExitClass::RolledBack => Some(HelperFailure::RolledBack),
        ExitClass::LeftOpen => Some(HelperFailure::LeftOpen),
    }
}

fn not_a_rule(k: u16) -> ExecError {
    ExecError::Op {
        op: k,
        source: SysError::new(SysErrorKind::Other, "not a firewall rule op"),
    }
}

/// `policy::firewall`'s observation as the journal's.
fn journal_obs(o: pf::Observed) -> Observed {
    match o {
        pf::Observed::Before => Observed::Before,
        pf::Observed::After => Observed::After,
        pf::Observed::Foreign => Observed::Foreign,
    }
}

/// Every rule op of `plan` (its batch) observed now in one enumeration (A4 S11), by op.
pub(super) fn observe_rules(
    sys: &dyn System,
    plan: &Plan,
    txn: &TxnId,
) -> Result<Vec<(u16, Observed)>, ExecError> {
    let Some((first, last)) = batch_of(plan) else {
        return Ok(Vec::new());
    };
    let fw: Vec<FwRule> = rules_of(plan, txn, first, last)?
        .into_iter()
        .map(|r| r.rule)
        .collect();
    let seen = pf::observe_all(sys.firewall(), &fw).map_err(|e| ExecError::Op {
        op: first,
        source: e,
    })?;
    Ok((first..=last)
        .zip(seen)
        .map(|(k, o)| (k, journal_obs(o)))
        .collect())
}

/// What a run needs of the helper, checked before the lock (module docs).
#[derive(Debug, Clone)]
pub(super) struct Ready {
    image: HelperImage,
}

/// [`Ready`] for a plan with helper ops, `None` for one without (module docs).
pub(super) fn ready(sys: &dyn System, plan: &Plan) -> Result<Option<Ready>, Refusal> {
    if batch_of(plan).is_none() {
        return Ok(None);
    }
    ready_now(sys).map(Some)
}

fn ready_now(sys: &dyn System) -> Result<Ready, Refusal> {
    helper_ready_with(sys).map(|(image, _)| Ready { image })
}

/// Whether a run that needs the helper could start it now, checked as `apply` and `revert` check
/// it before the lock (module docs: the pre-check of the installed helper, then whether Windows
/// allows an elevation at all), with the UAC prompt state the user will meet. Read only; no
/// prompt. A front end shows the state before the click and locks what would be refused anyway
/// (ADR 0023 amendment P5-5c); `exec` checks again in every run.
///
/// # Errors
/// [`Refusal::HelperUnsafe`] (not installed, or not admin-only, or a test-key helper for a
/// release build), [`Refusal::NoElevation`] (`Denied`, `UacOff`) or [`Refusal::Elevated`].
pub fn helper_ready(sys: &dyn System) -> Result<crate::elevate::PromptState, Refusal> {
    helper_ready_with(sys).map(|(_, state)| state)
}

fn helper_ready_with(
    sys: &dyn System,
) -> Result<(HelperImage, crate::elevate::PromptState), Refusal> {
    // N5 (P4-2c security review): a test-key helper is refused unless this is a test-key CLI.
    let image = crate::policy::root::helper_for_this_build(sys)
        .map_err(|e| Refusal::HelperUnsafe(Box::new(e)))?;
    let state = crate::elevate::prompt::read(sys);
    match state.kind {
        k @ (PromptKind::Denied | PromptKind::UacOff) => Err(Refusal::NoElevation(k)),
        PromptKind::Elevated => Err(Refusal::Elevated),
        PromptKind::Consent
        | PromptKind::Credentials
        | PromptKind::NoPrompt
        | PromptKind::Unknown => Ok((image, state)),
    }
}

/// The keys an index must be signed with to authorise an add (the helper's: release slots).
fn add_keys() -> Vec<crate::catalog::PublicKey> {
    #[cfg(test)]
    if let Some(k) = knob::index_keys() {
        return k;
    }
    crate::catalog::trusted_keys()
}

/// A4 S7 before `begin` (module docs): the anchors of `elevate::check_plan` on the signed index
/// the plan names and the game folder as opened now are exactly the plan's rule ops.
pub(super) fn recheck(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    roots: &super::roots::Roots<'_>,
) -> Result<(), Refusal> {
    let Some((first, last)) = batch_of(plan) else {
        return Ok(());
    };
    let changed = |why: PlanRefusal| Refusal::HelperPlan(Box::new(why));
    let source = plan
        .source
        .as_ref()
        .ok_or(Refusal::Mismatch { op: first })?;
    let dir = cx
        .app
        .sub(AppSub::Index)?
        .ok_or(Refusal::Mismatch { op: first })?;
    let catalog = crate::catalog::store::load(&*dir, &source.index, &add_keys())
        .map_err(|_| Refusal::Mismatch { op: first })?;
    let topo = catalog
        .topo(&source.topo)
        .filter(|t| t.rev == source.rev)
        .ok_or(Refusal::Mismatch { op: first })?;
    // Every rule op names the same game root (`plan::rule_check`: a game root; the engine
    // plans root 0).
    let (root, want) = rule_ops(plan, first, last).map_err(|k| Refusal::Mismatch { op: k })?;
    let Some(super::roots::Opened::Game(game)) = roots.opened(usize::from(root.0)) else {
        return Err(Refusal::Mismatch { op: first });
    };
    let facts = crate::topo::read_game(game, topo);
    let anchors = check_plan(topo, &source.picks, game.info(), &facts).map_err(changed)?;
    let same = anchors.len() == want.len()
        && anchors
            .iter()
            .zip(&want)
            .all(|(a, (_, p, d))| a.exe.same_spelling(p) && a.direction == *d);
    if !same {
        return Err(Refusal::Mismatch { op: first });
    }
    Ok(())
}

/// Most request names tried in one run (N9).
const MAX_NAMES: u32 = 64;
/// Most leftover request files deleted in one run (N9).
const MAX_SWEEP: usize = 64;

/// A request file written (module docs).
struct Written {
    at: RequestRef,
    sha256: [u8; 32],
    digest: Digest,
    batch: usize,
}

/// Deletes up to [`MAX_SWEEP`] request files of earlier runs (N9): under the journal lock no
/// other Rerun runs, so every file of the request form is a leftover. Best effort.
fn sweep(dir: &dyn crate::sys::DirWrite) {
    let Ok(entries) = dir.read_dir_limited(None, 4 * MAX_SWEEP) else {
        return;
    };
    for e in entries
        .iter()
        .filter(|e| RequestName::parse(&e.name).is_some())
        .take(MAX_SWEEP)
    {
        if let Ok(name) = RelPath::from_segment(&e.name) {
            delete(dir, &name);
        }
    }
}

/// Deletes the request files of earlier runs in `<AppDir>\elevate` if the folder exists (N9; a
/// revert of a batch without a result and `forget`, under the journal lock; security review L2).
/// Best effort: nothing is created and no error is reported.
pub(super) fn sweep_leftovers(cx: &ExecCtx<'_>) {
    if let Ok(Some(dir)) = cx.app.sub_write(AppSub::Elevate, Create::Never) {
        sweep(&*dir);
    }
}

/// Deletes the request file `name` with the hash it has now (Rerun's own file; best effort).
fn delete(dir: &dyn crate::sys::DirWrite, name: &RelPath) {
    if let Ok(mut g) = dir.guard(name)
        && let Ok(sha) = g.sha256()
    {
        let _ = g.delete(&sha);
    }
}

/// Writes `req` as `<AppDir>\elevate\<txn>-<n>.req` under the journal lock (N9), flushed.
fn write_request(
    cx: &ExecCtx<'_>,
    tmp: impl Fn() -> TmpName,
    req: &Request,
) -> Result<Written, ExecError> {
    let bytes = encode(req).map_err(|e| {
        ExecError::Helper(HelperFailure::Start(SysError::new(
            SysErrorKind::Other,
            format!("the request cannot be written: {e}"),
        )))
    })?;
    let dir = cx
        .app
        .sub_write(AppSub::Elevate, Create::IfMissing)
        .map_err(|e| ExecError::Sys(SysError::new(SysErrorKind::Other, e.to_string())))?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "elevate"))?;
    sweep(&*dir);
    let info = dir.info()?;
    let volume = info.volume_guid.ok_or_else(|| {
        SysError::new(
            SysErrorKind::Unsupported,
            "Rerun's folder is on a volume without a GUID path",
        )
    })?;
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    for n in 1..=MAX_NAMES {
        let Some(name) = RequestName::new(req.txn, n) else {
            continue;
        };
        let rel = RelPath::from_segment(name.as_str())
            .map_err(|e| SysError::new(SysErrorKind::InvalidPath, e.to_string()))?;
        let new = NewFile {
            tmp: tmp(),
            attrs: Attrs::default(),
            sha256,
            max_len: len,
        };
        match dir.create_new(&rel, &mut &bytes[..], &new) {
            Ok(_) => {}
            Err(e) if e.kind == SysErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
        dir.flush()?;
        return Ok(Written {
            at: RequestRef {
                dir: DirRef {
                    volume,
                    file_id: info.file_id,
                },
                name,
            },
            sha256,
            digest: Digest { sha256, len },
            batch: req.op_count(),
        });
    }
    Err(SysError::new(
        SysErrorKind::AlreadyExists,
        "every request name of this transaction is taken",
    )
    .into())
}

/// The helper run for a written request, then the file deleted (best effort).
fn run_helper(cx: &ExecCtx<'_>, image: &HelperImage, w: &Written) -> Result<Judged, SysError> {
    let judged =
        crate::elevate::client::start(cx.sys.elevation(), image, &w.at, &w.sha256, w.batch);
    if let Ok(Some(dir)) = cx.app.sub_write(AppSub::Elevate, Create::IfMissing)
        && let Ok(rel) = RelPath::from_segment(w.at.name.as_str())
    {
        delete(&*dir, &rel);
    }
    judged
}

/// The add request of ops `first..=last`.
fn add_request(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    roots: &super::roots::Roots<'_>,
    txn: TxnId,
    first: u16,
    last: u16,
) -> Result<Request, ExecError> {
    let unsupported = |what: &str| {
        ExecError::Sys(SysError::new(
            SysErrorKind::Unsupported,
            format!("{what} has no volume GUID path"),
        ))
    };
    let source = plan.source.clone().ok_or_else(|| not_a_rule(first))?;
    let index = cx
        .app
        .sub(AppSub::Index)
        .map_err(|e| ExecError::Sys(SysError::new(SysErrorKind::Other, e.to_string())))?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "index"))?
        .info()?;
    let (root, named) = rule_ops(plan, first, last).map_err(not_a_rule)?;
    let ops: Vec<AddOp> = named
        .into_iter()
        .map(|(k, program, direction)| AddOp {
            op: k,
            program: program.clone(),
            direction,
        })
        .collect();
    let planned = plan
        .roots
        .get(usize::from(root.0))
        .filter(|r| r.kind == RootKind::Game)
        .ok_or_else(|| not_a_rule(first))?;
    let info = roots
        .opened(usize::from(root.0))
        .map(super::roots::Opened::info)
        .ok_or_else(|| not_a_rule(first))?;
    Ok(Request {
        build: crate::BUILD_ID.to_owned(),
        txn,
        body: Body::Add {
            source,
            index_dir: DirRef {
                volume: index
                    .volume_guid
                    .ok_or_else(|| unsupported("the index folder"))?,
                file_id: index.file_id,
            },
            root: RootRef {
                volume: info
                    .volume_guid
                    .ok_or_else(|| unsupported("the game folder"))?,
                id: RootId {
                    volume_serial: info.volume_serial,
                    file_id: info.file_id,
                },
                path: planned.path.clone(),
            },
            ops,
        },
    })
}

/// The apply's batch (module docs): `Ok` once every `Done` is recorded.
pub(super) fn run_batch(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    w: &mut TxnWriter<'_>,
    roots: &super::roots::Roots<'_>,
    ready: &Ready,
) -> Result<(), ExecError> {
    let Some((first, last)) = batch_of(plan) else {
        return Ok(());
    };
    let txn = *w.id();
    let rules: Vec<FwRule> = rules_of(plan, &txn, first, last)?
        .into_iter()
        .map(|r| r.rule)
        .collect();
    let req = add_request(cx, plan, roots, txn, first, last)?;
    let written = write_request(cx, || w.tmp(), &req)?;
    w.helper_batch(first, last, written.digest)?;
    // `Err` only when no process was created (`Elevation::run_helper`): `Start`, rolled back.
    let judged = run_helper(cx, &ready.image, &written)
        .map_err(|e| ExecError::Helper(HelperFailure::Start(e)))?;
    // The run's own verdict first (review follow-up): a declined prompt stays `Declined` (exit 4)
    // even if the firewall cannot be read afterwards; the rollback observes again anyway.
    let report = match judged {
        Judged::Declined => return Err(ExecError::Helper(HelperFailure::Declined)),
        Judged::Unknown => return Err(ExecError::Helper(HelperFailure::Unknown)),
        Judged::Exit(e) => e,
    };
    if let Some(f) = failure_of(&report) {
        return Err(ExecError::Helper(f));
    }
    let seen = pf::observe_all(cx.sys.firewall(), &rules)
        .map_err(|e| ExecError::Helper(HelperFailure::Unreadable(e)))?;
    let agree = seen.iter().all(|o| *o == pf::Observed::After)
        && report.ops[..rules.len()]
            .iter()
            .all(|o| *o == OpResult::After);
    if !agree {
        return Err(ExecError::Helper(HelperFailure::Disagree));
    }
    for k in first..=last {
        w.done(k, None, false)?;
    }
    Ok(())
}

/// The batch ops of `ops` have no result yet (A4 S8): an intent without `Done` (the apply ended
/// before the helper's report was recorded), or a `RevertBatch` without its `RevertDone`.
fn unfinished(ops: &std::collections::BTreeMap<u16, OpLog>) -> bool {
    ops.values()
        .filter(|o| o.intent.batch)
        .any(|o| o.reverted.is_none() && (o.done.is_none() || !o.reverts.is_empty()))
}

/// A halt of the revert at the batch's op `k` for `why`.
fn halt(plan: &Plan, k: u16, why: HelperFailure) -> Halt {
    let root = match plan.ops.get(usize::from(k)) {
        Some(Op::FirewallRule { root, .. }) => root.0,
        _ => 0,
    };
    Halt {
        op: k,
        root,
        why: Box::new(Refusal::Helper(why)),
    }
}

/// The revert of the batch (module docs): its reports, newest op first, and the halt if it
/// stops. `start`: the helper may be started (a revert); a rollback never starts it.
pub(super) fn revert_batch<W: Reverting>(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    w: &mut W,
    start: bool,
) -> Result<(Vec<OpReport>, Option<Halt>), ExecError> {
    let (first, _) = w.batch().ok_or(ExecError::Journal(JournalError::Order(
        "a batch revert without a helper batch",
    )))?;
    let last = w
        .next_revert()
        .ok_or(ExecError::Journal(JournalError::Order(
            "a batch revert with nothing left",
        )))?;
    let txn = *w.id();
    let rules = rules_of(plan, &txn, first, last)?;
    // A4 S8: a batch without a result may still be acted on by a helper of an earlier run.
    // Its request file goes first (security review L2): a helper that starts late, after this
    // revert observed no rule, then finds no request to act on; then no helper may run.
    if start && unfinished(w.ops()) {
        sweep_leftovers(cx);
        let image = crate::policy::root::helper_image(cx.sys)
            .map_err(|e| Refusal::HelperUnsafe(Box::new(e)))?;
        crate::elevate::client::ensure_idle(cx.sys.elevation(), &image)
            .map_err(|e| Refusal::Helper(HelperFailure::Busy(e)))?;
    }
    let fw: Vec<FwRule> = rules.iter().map(|r| r.rule.clone()).collect();
    let seen = pf::observe_all(cx.sys.firewall(), &fw).map_err(|e| ExecError::Op {
        op: last,
        source: e,
    })?;
    let ops: Vec<u16> = (first..=last).collect();
    if !seen.contains(&pf::Observed::After) {
        // Nothing of Rerun's left: no helper, no prompt.
        w.revert_batch(first, last, None)?;
        let mut reports = Vec::new();
        for (k, o) in ops.iter().zip(&seen).rev() {
            let observed = journal_obs(*o);
            w.revert_done(*k, observed, &[])?;
            reports.push(report(*k, observed));
        }
        return Ok((reports, None));
    }
    if !start {
        return Err(ExecError::Helper(HelperFailure::NeedsRevert));
    }
    let ready = ready_now(cx.sys)?;
    let topo = topo_of(plan).ok_or_else(|| not_a_rule(first))?;
    let req = Request {
        build: crate::BUILD_ID.to_owned(),
        txn,
        body: Body::Remove {
            topo,
            ops: ops
                .iter()
                .zip(&rules)
                .map(|(k, r)| RemoveOp {
                    op: *k,
                    program: r.program.clone(),
                    direction: r.direction,
                })
                .collect(),
        },
    };
    let written = write_request(cx, || w.tmp(), &req)?;
    w.revert_batch(first, last, Some(written.digest))?;
    let judged = match run_helper(cx, &ready.image, &written) {
        Ok(j) => j,
        Err(e) => return Ok((Vec::new(), Some(halt(plan, last, HelperFailure::Start(e))))),
    };
    let exit = match judged {
        Judged::Declined => {
            return Ok((Vec::new(), Some(halt(plan, last, HelperFailure::Declined))));
        }
        Judged::Unknown => return Ok((Vec::new(), Some(halt(plan, last, HelperFailure::Unknown)))),
        Judged::Exit(e) => e,
    };
    if let Some(f) = failure_of(&exit) {
        return Ok((Vec::new(), Some(halt(plan, last, f))));
    }
    let now = match pf::observe_all(cx.sys.firewall(), &fw) {
        Ok(v) => v,
        Err(e) => {
            return Ok((
                Vec::new(),
                Some(halt(plan, last, HelperFailure::Unreadable(e))),
            ));
        }
    };
    let mut reports = Vec::new();
    for (i, k) in ops.iter().enumerate().rev() {
        let agree = match (now[i], exit.ops[i]) {
            (pf::Observed::Before, OpResult::Before) => Some(journal_obs(seen[i])),
            (pf::Observed::Foreign, OpResult::Foreign) => Some(Observed::Foreign),
            _ => None,
        };
        // A rule seen foreign before and gone now was not Rerun's to remove: `Before`.
        let Some(observed) = agree.map(|o| match o {
            Observed::Foreign if now[i] == pf::Observed::Before => Observed::Before,
            o => o,
        }) else {
            return Ok((reports, Some(halt(plan, *k, HelperFailure::Disagree))));
        };
        w.revert_done(*k, observed, &[])?;
        reports.push(report(*k, observed));
    }
    Ok((reports, None))
}

fn report(op: u16, observed: Observed) -> OpReport {
    OpReport {
        op,
        observed,
        left: Vec::new(),
        backup: None,
        detail: None,
    }
}

#[cfg(test)]
pub(crate) mod knob {
    //! The keys an add's index is checked against in tests (the test key; release slots are
    //! empty, ADR 0024).

    use std::cell::RefCell;

    use crate::catalog::PublicKey;

    thread_local! {
        static KEYS: RefCell<Option<Vec<PublicKey>>> = const { RefCell::new(None) };
    }

    /// From now on (this thread) the index of an add is checked against `keys`.
    pub(crate) fn set_index_keys(keys: Option<Vec<PublicKey>>) {
        KEYS.with(|k| *k.borrow_mut() = keys);
    }

    pub(super) fn index_keys() -> Option<Vec<PublicKey>> {
        KEYS.with(|k| k.borrow().clone())
    }
}
