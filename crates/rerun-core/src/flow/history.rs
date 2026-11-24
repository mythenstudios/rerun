//! Keeping the history short (P5-6d-1b, ADR 0027 amendment P5-6d, ADR 0019 amendment P5-6d).
//!
//! `flow` only selects; the safety rules are enforced below it: `exec::purge_seen` (a hand-over
//! kept fail closed, forgotten ones, profile holders) and `JournalLock::purge` (only settled
//! transactions, Rerun's own files, the tombstone, the anchor of `seq`).
//!
//! - **The cap (user decisions E1, E2; senior-dev S3, S6):** after a successful write of Rerun's
//!   own (`apply`, `revert`, `rebind`, `forget`), with its result final and its lock released,
//!   [`tidy`] keeps the newest [`HISTORY_KEEP`] entries that are "undone" or "rolled back" and
//!   removes older ones that are removable now, and empty ones, at most [`TIDY_PER_RUN`] per run,
//!   oldest first. Entries that stay (a hand-over, foreign content) count towards the cap and
//!   are skipped. Forgotten ones are never removed here (P5-6d-2). A failure of the cap never
//!   turns the write into an error: it is the `tidied` of the result. Never on start, never on a
//!   timer (rule 1). Rule 5 exception: no preview of each, because nothing removed changes the
//!   system or takes a recovery away (`docs/06-security.md`, Principles).
//! - **"Clear history":** [`clear_preview`] lists what goes (game, number, state) and what stays
//!   and why, and the launch results that go or stay; [`clear`] removes exactly what was shown
//!   (`PurgeMode::Exact`: anything no longer removable, or another head, is
//!   [`ActError::Changed`], nothing written) and deletes the launch results whose bytes are still
//!   the ones the preview read (user decision E5).

use crate::exec::launch_result::ProfileId;
use crate::exec::{
    self, ExecCtx, ExecError, Keep, PurgeMode, PurgeReport, Refusal, TxnLine, TxnStatus,
};
use crate::journal::{Closing, InstanceTag, JournalError, TxnId, TxnState};
use crate::policy::root::AppDir;

use super::launch::{LaunchNote, launch_lines};
use super::revert::ActError;
use super::{Guarded, head};

/// The cap: the newest entries "undone" or "rolled back" that always stay (user decision E1).
pub const HISTORY_KEEP: usize = 100;

/// At most this many entries removed by one run of the cap (senior-dev S3).
pub const TIDY_PER_RUN: usize = 5;

/// What the cap removed after a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tidied {
    /// Entries removed (a front end mentions them only when there are some).
    pub removed: usize,
}

/// Why the cap removed nothing after a write that succeeded (the write stays a success).
#[derive(Debug)]
pub enum TidyNote {
    /// The journal could not be listed.
    Journal(JournalError),
    /// The purge failed.
    Exec(ExecError),
}

/// The cap's outcome, carried by every write result.
pub type Tidy = Result<Tidied, TidyNote>;

/// The entries the cap removes now, oldest first: of the transactions "undone" or "rolled back"
/// (not forgotten), the newest [`HISTORY_KEEP`] stay whatever their rules say (they count); older
/// ones that may be purged now, and empty ones, are picked, at most [`TIDY_PER_RUN`]. Each pick
/// says whether it is an entry the history shows (undone or rolled back; an empty one is not).
fn tidy_picks(classes: &[exec::PurgeClass]) -> Vec<(TxnId, Option<[u8; 32]>, bool)> {
    let mut undone = 0;
    let mut picks = Vec::new();
    for c in classes.iter().rev() {
        if c.forgotten {
            continue;
        }
        let (pick, shown) = match &c.state {
            Some(TxnState::Closed(Closing::Reverted | Closing::RolledBack)) => {
                undone += 1;
                (undone > HISTORY_KEEP, true)
            }
            Some(TxnState::Empty) => (true, false),
            _ => (false, false),
        };
        if pick && c.keep.is_none() {
            picks.push((c.id, c.head, shown));
        }
    }
    picks.reverse();
    picks.truncate(TIDY_PER_RUN);
    picks
}

/// The cap after a successful write (module docs). Nothing to pick: it returns before the lock is
/// taken. Another Rerun holding the lock: nothing, silently (the next write tries again); a
/// change between the listing and the lock is a [`TidyNote`] (a front end only logs it).
/// [`Tidied::removed`] counts the entries the history shows (undone or rolled back); empty ones
/// go silently (review S2).
pub(crate) fn tidy(g: &Guarded<'_>) -> Tidy {
    let Some(app) = g.app() else {
        return Ok(Tidied::default());
    };
    let classes = exec::purge_classes(app).map_err(TidyNote::Journal)?;
    let picks = tidy_picks(&classes);
    if picks.is_empty() {
        return Ok(Tidied::default());
    }
    let ids: Vec<(TxnId, Option<[u8; 32]>)> = picks.iter().map(|(t, h, _)| (*t, *h)).collect();
    match exec::purge_seen(&ctx(g, app), &ids, PurgeMode::Lenient) {
        Ok(r) => Ok(Tidied {
            removed: picks
                .iter()
                .filter(|(t, _, shown)| *shown && r.removed.contains(t))
                .count(),
        }),
        Err(ExecError::Refused(Refusal::JournalBusy)) => Ok(Tidied::default()),
        Err(e) => Err(TidyNote::Exec(e)),
    }
}

pub(super) fn ctx<'a>(g: &'a Guarded<'_>, app: &'a AppDir<'a>) -> ExecCtx<'a> {
    ExecCtx {
        sys: g.env().sys,
        fr: g.fr(),
        app,
        tag: InstanceTag::new(),
    }
}

/// One entry "clear history" removes.
#[derive(Debug, Clone)]
pub struct ClearItem {
    /// The transaction (its number is `txn.seq()`).
    pub txn: TxnId,
    /// The Steam app of its head, if it names one.
    pub app: Option<u32>,
    /// Its state.
    pub line: TxnLine,
    /// A forget marker or record closed it (`TxnStatus::is_forgotten`).
    pub forgotten: bool,
}

/// Why a launch result stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKeep {
    /// Its start says the Steam launch option still points at Rerun: it stays as the reminder
    /// to remove the option by hand.
    OptionStillSet,
    /// It cannot be read (never acted on).
    Unreadable,
}

/// What "clear history" would do (rule 5: the list, not a count).
#[derive(Debug)]
pub struct ClearPreview {
    /// The entries that go, oldest first.
    pub remove: Vec<ClearItem>,
    /// The entries that stay, with the reason, oldest first.
    pub stays: Vec<(ClearItem, Keep)>,
    /// The launch results that go (by profile).
    pub results: Vec<ProfileId>,
    /// The launch results that stay, with the reason.
    pub results_stay: Vec<(ProfileId, ResultKeep)>,
}

/// The entries and launch results the preview showed, each with the hash it was read with. Only
/// [`clear_preview`] builds one.
#[derive(Debug)]
pub struct ClearShown {
    items: Vec<(TxnId, Option<[u8; 32]>)>,
    results: Vec<(ProfileId, [u8; 32])>,
}

impl ClearShown {
    /// Nothing would be removed.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.results.is_empty()
    }
}

/// Why "clear history" shows nothing.
#[derive(Debug)]
pub enum ClearGate {
    /// Rerun's folder does not exist: there is no history.
    NoAppDir,
    /// The journal cannot be read.
    Journal(JournalError),
}

/// The Steam app of a transaction's head.
pub(super) fn app_of(st: &TxnStatus) -> Option<u32> {
    head(st)?
        .roots
        .iter()
        .find_map(|r| r.steam.as_ref().map(|(a, _)| *a))
}

/// The preview of "clear history" (module docs). Reads only.
///
/// # Errors
/// [`ClearGate`]. A launch folder that cannot be read lists no result (none is deleted).
pub fn clear_preview(g: &Guarded<'_>) -> Result<(ClearPreview, ClearShown), ClearGate> {
    let app = g.app().ok_or(ClearGate::NoAppDir)?;
    let classes = exec::purge_classes(app).map_err(ClearGate::Journal)?;
    let status = exec::status_with(app, true).map_err(ClearGate::Journal)?;
    // A transaction gone between the two listings is not shown (review N11): `clear` would
    // count it as done anyway.
    let item = |id: &TxnId| {
        status
            .txns
            .iter()
            .find(|s| s.id == *id)
            .map(|st| ClearItem {
                txn: *id,
                app: app_of(st),
                line: st.state.clone(),
                forgotten: st.is_forgotten(),
            })
    };
    let mut preview = ClearPreview {
        remove: Vec::new(),
        stays: Vec::new(),
        results: Vec::new(),
        results_stay: Vec::new(),
    };
    let mut shown = ClearShown {
        items: Vec::new(),
        results: Vec::new(),
    };
    for c in &classes {
        let Some(i) = item(&c.id) else { continue };
        match c.keep {
            None => {
                preview.remove.push(i);
                shown.items.push((c.id, c.head));
            }
            Some(k) => preview.stays.push((i, k)),
        }
    }
    if let Ok(Some((results, hashes))) = exec::launch_results_hashed(app) {
        let holders = super::status::holders(app, &status);
        for line in launch_lines(&results, &holders) {
            let still_set = matches!(
                line.note,
                Some(LaunchNote::OptionStillSet { .. } | LaunchNote::OptionStillSetForgotten)
            );
            let sha = hashes
                .iter()
                .find(|(id, _)| *id == line.id)
                .map(|(_, s)| *s);
            match (line.result.is_ok(), still_set, sha) {
                (true, false, Some(sha)) => {
                    preview.results.push(line.id);
                    shown.results.push((line.id, sha));
                }
                (true, true, _) => preview
                    .results_stay
                    .push((line.id, ResultKeep::OptionStillSet)),
                _ => preview.results_stay.push((line.id, ResultKeep::Unreadable)),
            }
        }
    }
    Ok((preview, shown))
}

/// Removes exactly what the preview `s` showed (module docs): the entries with
/// `PurgeMode::Exact` (an entry no longer removable, or with another head, is
/// [`ActError::Changed`] and nothing is written; one removed meanwhile counts as done), then
/// the launch results whose bytes are still the ones the preview read (best effort).
///
/// # Errors
/// [`ActError::Changed`] (show the preview again), or `exec`'s error.
pub fn clear(g: &Guarded<'_>, s: ClearShown) -> Result<PurgeReport, ActError> {
    let app = g.app().ok_or(ActError::Changed)?;
    let mut report = if s.items.is_empty() {
        exec::standard_user(g.env().sys).map_err(|r| ActError::Exec(r.into()))?;
        PurgeReport::default()
    } else {
        exec::purge_seen(&ctx(g, app), &s.items, PurgeMode::Exact)?
    };
    // Best effort: a launch folder that cannot be opened now keeps its results (they show again
    // in the next preview); the entries are removed already.
    report.results = exec::purge_results(app, &s.results).unwrap_or(0);
    Ok(report)
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
