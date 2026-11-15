//! The history page and the last start of a game (P5-6a, ADR 0027 amendment P5-6a): what the
//! journal and the launch results say, drawn as groups and rows. Reads only; the words are the
//! app's, the values are `flow`'s ([`flow::journal`], [`flow::launch_lines`]).
//!
//! The journal has no time stamps (ADR 0019): the entries come newest first by their sequence
//! number, with their ID, and no date. A launch result has a time (`unix_s`): the row says how
//! long ago it was, from the `now` the worker passes in, and the exact UTC time next to it (no
//! time zone is read from Windows).

use rerun_core::escape::Shown;
use rerun_core::exec::TxnLine;
use rerun_core::exec::launch_result::{Check, LaunchResult, Outcome, ProfileId};
use rerun_core::flow::{self, JournalView, LaunchLine, LaunchNote};
use rerun_core::journal::{Closing, JournalError, TxnId};
use rerun_core::plan::profile_id;

use super::write::{app_of, card, head_ops};
use super::{Badge, FactVm, Names, OpVm, Value, shown_error};
use crate::text::{Lang, Msg, Sym, t};

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// The group of a history entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistGroup {
    /// Not closed: still under Applied.
    Open,
    /// Applied, then undone completely.
    Reverted,
    /// An apply that failed and was rolled back.
    RolledBack,
    /// Closed without undoing it.
    Forgotten,
    /// Began and changed nothing.
    Empty,
}

/// One transaction in the history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistEntryVm {
    /// The transaction.
    pub txn: TxnId,
    /// Its ID as text (the order is the journal's: newest first).
    pub id: String,
    /// The game: its name (escaped) or "Steam app N", if the head names one.
    pub game: Option<Value>,
    /// State glyph and word.
    pub state: Badge,
    /// What is wrong, if something is (an open entry).
    pub problem: Option<String>,
    /// Everything in it, collapsed by the window.
    pub ops: Vec<OpVm>,
    /// A forgotten entry: the folder that keeps its backups.
    pub backups: Option<Shown<'static>>,
    /// Files that may remain next to the game's files (`.old`), relative to their root.
    pub may_remain: Vec<Shown<'static>>,
    /// A note (a forgotten entry that still holds a launch profile).
    pub note: Option<String>,
}

/// One group of the history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistGroupVm {
    /// Which.
    pub kind: HistGroup,
    /// Its heading.
    pub title: String,
    /// One sentence under it.
    pub hint: Option<String>,
    /// Its entries, newest first.
    pub entries: Vec<HistEntryVm>,
}

/// The last start of one game or profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRowVm {
    /// The game's name, or the profile ID when no game of the journal or the library has it.
    pub game: Value,
    /// The game is not known: `game` is the profile ID (drawn in the monospaced font).
    pub game_is_id: bool,
    /// How long ago.
    pub when: String,
    /// The exact time, UTC (`None`: an unreadable file has none).
    pub exact: Option<String>,
    /// What came of the rule.
    pub outcome: Badge,
    /// What happened.
    pub line: String,
    /// What Rerun adds (the option still set, a launcher, the method watch).
    pub note: Option<String>,
    /// A path or an error, untrusted.
    pub detail: Option<Shown<'static>>,
}

/// The history page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryVm {
    /// How the entries are ordered.
    pub order: String,
    /// The groups that have entries, open first.
    pub groups: Vec<HistGroupVm>,
    /// Nothing to show, or the journal cannot be read: its title and second line.
    pub empty: Option<(String, String)>,
    /// The core's text if the journal could not be read (escaped).
    pub detail: Option<Shown<'static>>,
    /// Entries of the journal folder that are not Rerun's.
    pub foreign: Option<String>,
    /// The heading of the launch results (`None`: there are none).
    pub launch_title: Option<String>,
    /// Its intro.
    pub launch_intro: String,
    /// The last start per profile, newest first.
    pub launches: Vec<LaunchRowVm>,
    /// Entries of the launch folder that are not Rerun's, or that it cannot be read.
    pub launch_note: Option<String>,
    /// The core's text if the launch folder cannot be read (escaped).
    pub launch_detail: Option<Shown<'static>>,
}

/// The seconds since 1970-01-01 UTC as `YYYY-MM-DD hh:mm:ss UTC`.
pub fn utc(unix_s: u64) -> String {
    /// The last second shown as a date (9999-12-31 23:59:59).
    const MAX_SHOWN: u64 = 253_402_300_799;
    if unix_s > MAX_SHOWN {
        return format!("{unix_s} s");
    }
    let days = unix_s / 86_400;
    let secs = unix_s % 86_400;
    // H. Hinnant, `civil_from_days`, for days >= 0.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// How long ago `then` was at `now` (a time in the future counts as now: the clock may differ).
pub fn ago(now: u64, then: u64, lang: Lang) -> String {
    let d = now.saturating_sub(then);
    let m = match d {
        0..60 => Msg::AgoNow,
        60..3_600 => Msg::AgoMinutes { n: d / 60 },
        3_600..172_800 => Msg::AgoHours { n: d / 3_600 },
        _ => Msg::AgoDays { n: d / 86_400 },
    };
    tx(lang, m)
}

fn game_value(app_id: u32, names: &Names, lang: Lang) -> Value {
    match names.get(&app_id) {
        Some(n) if !n.as_str().is_empty() => Value::Shown(n.clone()),
        _ => Value::Text(tx(lang, Msg::UnnamedGame { app_id })),
    }
}

// ---------- the journal ----------

fn group_of(st: &rerun_core::exec::TxnStatus) -> HistGroup {
    if !st.is_settled() {
        HistGroup::Open
    } else if st.is_forgotten() {
        HistGroup::Forgotten
    } else {
        match &st.state {
            TxnLine::Closed(Closing::Reverted) => HistGroup::Reverted,
            TxnLine::Closed(Closing::RolledBack) => HistGroup::RolledBack,
            // `Closed(Forgotten)` is forgotten above; the rest of the settled lines is empty.
            _ => HistGroup::Empty,
        }
    }
}

fn entry(
    st: &rerun_core::exec::TxnStatus,
    group: HistGroup,
    holders: &[flow::Holder],
    names: &Names,
    lang: Lang,
) -> HistEntryVm {
    // An open entry is its card (the same state, problem and ops as under Applied).
    if group == HistGroup::Open
        && let Some(c) = card(st, names, lang)
    {
        return HistEntryVm {
            txn: st.id,
            id: c.id,
            game: c.game,
            state: c.state,
            problem: c.problem,
            ops: c.ops,
            backups: None,
            may_remain: Vec::new(),
            note: None,
        };
    }
    let (sym, word, quiet) = match group {
        HistGroup::Reverted => (Sym::None, Msg::HistStateReverted, false),
        HistGroup::RolledBack => (Sym::None, Msg::HistStateRolledBack, false),
        HistGroup::Forgotten => (Sym::Unconfirmed, Msg::HistStateForgotten, true),
        HistGroup::Empty | HistGroup::Open => (Sym::NotHere, Msg::HistStateEmpty, true),
    };
    let forgotten = group == HistGroup::Forgotten;
    // Review S8 of the status: a forgotten entry always says where its backups stay.
    let backups = forgotten.then(|| st.folder.clone());
    let may_remain = st
        .ops
        .iter()
        .flat_map(|o| o.cleanup.iter().cloned())
        .collect();
    let holds = forgotten && holders.iter().any(|h| h.txn == st.id && h.forgotten);
    HistEntryVm {
        txn: st.id,
        id: st.id.to_string(),
        game: app_of(st).map(|a| game_value(a, names, lang)),
        state: Badge {
            sym,
            word: tx(lang, word),
            quiet,
        },
        problem: None,
        ops: head_ops(st, lang),
        backups,
        may_remain,
        note: holds.then(|| tx(lang, Msg::HolderForgotten)),
    }
}

fn group(kind: HistGroup, entries: Vec<HistEntryVm>, lang: Lang) -> HistGroupVm {
    let (title, hint) = match kind {
        HistGroup::Open => (Msg::HistGroupOpen, Some(Msg::HistGroupOpenHint)),
        HistGroup::Reverted => (Msg::HistGroupReverted, None),
        HistGroup::RolledBack => (Msg::HistGroupRolledBack, Some(Msg::HistGroupRolledBackHint)),
        HistGroup::Forgotten => (Msg::HistGroupForgotten, Some(Msg::HistGroupForgottenHint)),
        HistGroup::Empty => (Msg::HistGroupEmpty, Some(Msg::HistGroupEmptyHint)),
    };
    HistGroupVm {
        kind,
        title: tx(lang, title),
        hint: hint.map(|m| tx(lang, m)),
        entries,
    }
}

/// The profiles of the games Rerun knows (the library's names and the journal's heads), to name
/// a launch result by its profile ID (one profile per game).
fn known_profiles(view: &JournalView, names: &Names) -> Vec<(ProfileId, u32)> {
    let mut apps: Vec<u32> = names.keys().copied().collect();
    apps.extend(view.status.txns.iter().filter_map(app_of));
    apps.sort_unstable();
    apps.dedup();
    apps.into_iter().map(|a| (profile_id(a), a)).collect()
}

/// The history page from the journal; `None`: Rerun's folder does not exist. `now` is seconds
/// since 1970-01-01 UTC.
pub fn history(
    view: Option<Result<&JournalView, &JournalError>>,
    names: &Names,
    now: u64,
    lang: Lang,
) -> HistoryVm {
    let mut vm = HistoryVm {
        order: tx(lang, Msg::HistoryOrder),
        groups: Vec::new(),
        empty: None,
        detail: None,
        foreign: None,
        launch_title: None,
        launch_intro: tx(lang, Msg::LaunchIntro),
        launches: Vec::new(),
        launch_note: None,
        launch_detail: None,
    };
    let nothing = |vm: &mut HistoryVm| {
        vm.empty = Some((tx(lang, Msg::HistoryEmpty), tx(lang, Msg::HistoryEmptySub)));
    };
    let v = match view {
        None => {
            nothing(&mut vm);
            return vm;
        }
        Some(Err(e)) => {
            vm.empty = Some((tx(lang, Msg::HistoryUnreadable), String::new()));
            vm.detail = Some(shown_error(e));
            return vm;
        }
        Some(Ok(v)) => v,
    };
    // Newest first: the listing is in order, so reverse it.
    let mut order: Vec<_> = v.status.txns.iter().collect();
    order.sort_by_key(|st| std::cmp::Reverse(st.id));
    for kind in [
        HistGroup::Open,
        HistGroup::Reverted,
        HistGroup::RolledBack,
        HistGroup::Forgotten,
        HistGroup::Empty,
    ] {
        let entries: Vec<HistEntryVm> = order
            .iter()
            .filter(|st| group_of(st) == kind)
            .map(|st| entry(st, kind, &v.holders, names, lang))
            .collect();
        if !entries.is_empty() {
            vm.groups.push(group(kind, entries, lang));
        }
    }
    if v.status.foreign_entries > 0 {
        vm.foreign = Some(tx(
            lang,
            Msg::HistoryForeignEntries {
                n: v.status.foreign_entries,
            },
        ));
    }
    match &v.launch {
        Err(e) => {
            vm.launch_title = Some(tx(lang, Msg::LaunchTitle));
            vm.launch_note = Some(tx(lang, Msg::LaunchFolderUnreadable));
            vm.launch_detail = Some(shown_error(e));
        }
        Ok(None) => {}
        Ok(Some(r)) => {
            let known = known_profiles(v, names);
            let mut lines = flow::launch_lines(r, &v.holders);
            // Newest first; a file that cannot be read has no time and goes last.
            lines.sort_by_key(|l| std::cmp::Reverse(l.result.as_ref().ok().map(|r| r.unix_s)));
            vm.launches = lines
                .iter()
                .map(|l| launch_row(l, &known, names, now, lang))
                .collect();
            if !vm.launches.is_empty() || r.other > 0 {
                vm.launch_title = Some(tx(lang, Msg::LaunchTitle));
            }
            if r.other > 0 {
                vm.launch_note = Some(tx(lang, Msg::LaunchOther { n: r.other }));
            }
        }
    }
    if vm.groups.is_empty() && vm.launches.is_empty() && vm.launch_title.is_none() {
        nothing(&mut vm);
    }
    vm
}

// ---------- the launch results ----------

/// The badge and the sentence of a result.
fn outcome(res: &LaunchResult, watch: bool, lang: Lang) -> (Badge, String) {
    let badge = |sym, m, quiet| Badge {
        sym,
        word: tx(lang, m),
        quiet,
    };
    match &res.outcome {
        Outcome::Applied {
            cpu,
            priority,
            check,
        } => {
            let soft = cpu.is_some_and(|c| c.mode == rerun_core::exec::launch_result::Mode::Soft);
            let set = tx(
                lang,
                Msg::LaunchSet {
                    cpu: *cpu,
                    priority: *priority,
                },
            );
            let (b, c) = match check {
                Check::Ok => (
                    badge(Sym::Applied, Msg::LaunchBadgeApplied, false),
                    Msg::LaunchCheckOk { soft, watch },
                ),
                Check::Narrowed => (
                    badge(Sym::Applied, Msg::LaunchBadgeApplied, false),
                    Msg::LaunchCheckNarrowed,
                ),
                Check::Reset { cpu, priority } => (
                    badge(Sym::Attention, Msg::LaunchBadgeReset, false),
                    Msg::LaunchCheckReset {
                        cpu: *cpu,
                        priority: *priority,
                    },
                ),
                Check::ExitedEarly => (
                    badge(Sym::Unknown, Msg::LaunchBadgeEnded, false),
                    Msg::LaunchCheckExitedEarly { watch },
                ),
                Check::Failed { code } => (
                    badge(Sym::Attention, Msg::LaunchBadgeFailed, false),
                    Msg::LaunchCheckFailed { code: *code },
                ),
            };
            (b, format!("{set}. {}", tx(lang, c)))
        }
        Outcome::Skipped {
            reason,
            start,
            ended,
            ..
        } => {
            let mut line = format!(
                "{} {}",
                tx(lang, Msg::LaunchSkipWhy { reason: *reason }),
                tx(
                    lang,
                    Msg::LaunchStart {
                        start: *start,
                        watch
                    }
                )
            );
            if let Some(e) = ended {
                line.push(' ');
                line.push_str(&tx(lang, Msg::LaunchEnded { ended: *e }));
            }
            (badge(Sym::NotHere, Msg::LaunchBadgeSkipped, true), line)
        }
    }
}

/// What Rerun adds to a line: the sentence, and the path (untrusted) it refers to.
fn notes(l: &LaunchLine, lang: Lang) -> (Option<String>, Option<Shown<'static>>) {
    let mut parts: Vec<String> = Vec::new();
    let mut detail = None;
    match &l.note {
        Some(LaunchNote::OptionStillSet { held }) => {
            parts.push(tx(lang, Msg::LaunchOptionStillSet));
            if let Some(txn) = held {
                parts.push(tx(lang, Msg::LaunchHeldBy { txn: *txn }));
            }
        }
        Some(LaunchNote::OptionStillSetForgotten) => {
            parts.push(tx(lang, Msg::LaunchOptionStillSetForgotten));
        }
        Some(LaunchNote::CheckedLauncher(start)) => {
            parts.push(tx(lang, Msg::LaunchCheckedLauncher));
            detail = Some(start.clone());
        }
        Some(LaunchNote::Watched(target)) => {
            parts.push(tx(lang, Msg::LaunchWatched));
            detail = Some(target.clone());
        }
        None => {}
    }
    if let Some(code) = l.restore_failed {
        parts.push(tx(lang, Msg::LaunchPriorityNotRestored { code }));
    }
    ((!parts.is_empty()).then(|| parts.join(" ")), detail)
}

fn launch_row(
    l: &LaunchLine,
    known: &[(ProfileId, u32)],
    names: &Names,
    now: u64,
    lang: Lang,
) -> LaunchRowVm {
    let app = known.iter().find(|(id, _)| *id == l.id).map(|(_, a)| *a);
    let (game, game_is_id) = match app {
        Some(a) => (game_value(a, names, lang), false),
        None => (
            Value::Text(format!("{} {}", tx(lang, Msg::LaunchProfileOf), l.id)),
            true,
        ),
    };
    let (note, detail) = notes(l, lang);
    match &l.result {
        Err(why) => LaunchRowVm {
            game,
            game_is_id,
            when: String::new(),
            exact: None,
            outcome: Badge {
                sym: Sym::Attention,
                word: tx(lang, Msg::LaunchBadgeUnreadable),
                quiet: false,
            },
            line: tx(lang, Msg::LaunchUnreadable),
            note,
            detail: Some(why.clone()),
        },
        Ok(res) => {
            let (outcome, line) = outcome(res, l.watch, lang);
            LaunchRowVm {
                game,
                game_is_id,
                when: ago(now, res.unix_s, lang),
                exact: Some(utc(res.unix_s)),
                outcome,
                line,
                note,
                detail,
            }
        }
    }
}

/// The last start of a game for its page: the fact (when and what came of it) and the notes
/// under the hero (what Rerun adds). `None` for a file that cannot be read: the history says why.
pub fn last_launch(l: &LaunchLine, now: u64, lang: Lang) -> Option<(FactVm, Vec<String>)> {
    let res = l.result.as_ref().ok()?;
    let (outcome, _) = outcome(res, l.watch, lang);
    let (note, _) = notes(l, lang);
    Some((
        FactVm {
            label: tx(lang, Msg::LaunchLast),
            value: Value::Text(format!(
                "{} \u{b7} {}",
                ago(now, res.unix_s, lang),
                outcome.word
            )),
            mono: false,
        },
        note.into_iter().collect(),
    ))
}
