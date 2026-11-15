//! The clear dialog and its results (P5-6d-1b, ADR 0027 amendment P5-6d). Rule 5: the dialog
//! lists every entry and launch result that goes, then every one that stays with its reason; a
//! count would not let the user see what is lost. The words are the app's, the values are
//! `flow`'s ([`flow::clear_preview`]); nothing here reads or writes the system.

use rerun_core::exec::launch_result::ProfileId;
use rerun_core::exec::{Keep, PurgeReport, TxnLine};
use rerun_core::flow::{ClearGate, ClearItem, ClearPreview, ResultKeep};
use rerun_core::journal::Closing;
use rerun_core::plan::profile_id;

use super::history::game_value;
use super::write::{DialogKind, DialogVm, ListVm, ResultVm, Tone, result, with_detail};
use super::{Names, shown_error};
use crate::text::{Lang, Msg, t};

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// The word of an entry's state, as the history says it. A forgotten entry's line is the
/// journal's (`Applied` with a marker), so `keep` says it.
fn state_word(line: &TxnLine, keep: Option<Keep>) -> Msg {
    if keep == Some(Keep::Forgotten) {
        return Msg::HistStateForgotten;
    }
    match line {
        TxnLine::Empty => Msg::HistStateEmpty,
        TxnLine::Open => Msg::StateInterrupted,
        TxnLine::Applied => Msg::StateApplied,
        TxnLine::CleanupPending => Msg::StateCleanup,
        TxnLine::Damaged(_) => Msg::StateDamaged,
        TxnLine::Unreadable(_) => Msg::StateUnreadable,
        TxnLine::Closed(Closing::Reverted) => Msg::HistStateReverted,
        TxnLine::Closed(Closing::RolledBack) => Msg::HistStateRolledBack,
        TxnLine::Closed(Closing::Forgotten) => Msg::HistStateForgotten,
    }
}

/// Why an entry stays, in one short sentence.
fn keep_reason(k: Keep) -> Msg {
    match k {
        Keep::NotSettled => Msg::ClearKeepNotSettled,
        Keep::Unreadable => Msg::ClearKeepUnreadable,
        Keep::HoldsProfile => Msg::ClearKeepHoldsProfile,
        Keep::HandedOver => Msg::ClearKeepHandedOver,
        Keep::Foreign => Msg::ClearKeepForeign,
        Keep::TooManyEntries => Msg::ClearKeepTooMany,
        Keep::Forgotten => Msg::ClearKeepForgotten,
        Keep::InUse => Msg::ClearKeepInUse,
        // A reason a later version adds.
        _ => Msg::ClearKeepOther,
    }
}

/// Why a launch result stays, in one short sentence.
fn result_reason(k: ResultKeep) -> Msg {
    match k {
        ResultKeep::OptionStillSet => Msg::ClearResultOptionSet,
        ResultKeep::Unreadable => Msg::ClearResultUnreadable,
    }
}

/// One entry as a line: the game (as the history names it, when the head names one), the number
/// and the state; with the reason after it for an entry that stays.
fn item_line(i: &ClearItem, keep: Option<Keep>, names: &Names, lang: Lang) -> String {
    let mut parts = Vec::new();
    if let Some(a) = i.app {
        parts.push(game_value(a, names, lang).as_str().to_owned());
    }
    parts.push(tx(lang, Msg::ClearNumber { n: i.txn.seq() }));
    parts.push(tx(lang, state_word(&i.line, keep)));
    let line = parts.join(" \u{b7} ");
    match keep {
        Some(k) => format!("{line}. {}", tx(lang, keep_reason(k))),
        None => line,
    }
}

/// A launch result as a line: the game of its profile, or the profile ID when no game of the
/// journal or the library has it (the history's rule); with the reason for a result that stays.
fn result_line(
    id: ProfileId,
    reason: Option<ResultKeep>,
    known: &[(ProfileId, u32)],
    names: &Names,
    lang: Lang,
) -> String {
    let who = match known.iter().find(|(p, _)| *p == id) {
        Some((_, a)) => game_value(*a, names, lang).as_str().to_owned(),
        None => format!("{} {id}", tx(lang, Msg::LaunchProfileOf)),
    };
    match reason {
        Some(r) => format!("{who}. {}", tx(lang, result_reason(r))),
        None => who,
    }
}

/// The clear dialog for a preview (rule 5): the entries that go (newest first, as the history
/// lists them), the launch results that go, then what stays with its reason, and that the game
/// folders, the registry and the firewall are not touched. Nothing to remove: it says so and has
/// no confirm. `changed`: the history changed since the dialog the user looked at.
pub fn clear_vm(
    p: &ClearPreview,
    names: &Names,
    changed: bool,
    nonce: u64,
    lang: Lang,
) -> DialogVm {
    // The games whose launch results are named: the library's and the journal's.
    let mut apps: Vec<u32> = names.keys().copied().collect();
    apps.extend(
        p.remove
            .iter()
            .chain(p.stays.iter().map(|(i, _)| i))
            .filter_map(|i| i.app),
    );
    apps.sort_unstable();
    apps.dedup();
    let known: Vec<(ProfileId, u32)> = apps.into_iter().map(|a| (profile_id(a), a)).collect();

    let nothing = p.remove.is_empty() && p.results.is_empty();
    let mut lists = Vec::new();
    if !p.remove.is_empty() {
        lists.push(ListVm {
            heading: tx(lang, Msg::ClearEntriesHeading { n: p.remove.len() }),
            lines: p
                .remove
                .iter()
                .rev()
                .map(|i| item_line(i, None, names, lang))
                .collect(),
        });
    }
    if !p.results.is_empty() {
        lists.push(ListVm {
            heading: tx(lang, Msg::ClearResultsHeading { n: p.results.len() }),
            lines: p
                .results
                .iter()
                .map(|id| result_line(*id, None, &known, names, lang))
                .collect(),
        });
    }
    let stays = p.stays.len() + p.results_stay.len();
    if stays > 0 {
        let mut lines: Vec<String> = p
            .stays
            .iter()
            .rev()
            .map(|(i, k)| item_line(i, Some(*k), names, lang))
            .collect();
        lines.extend(
            p.results_stay
                .iter()
                .map(|(id, k)| result_line(*id, Some(*k), &known, names, lang)),
        );
        lists.push(ListVm {
            heading: tx(lang, Msg::ClearStaysHeading { n: stays }),
            lines,
        });
    }
    DialogVm {
        kind: DialogKind::Clear,
        nonce,
        txn: None,
        title: tx(lang, Msg::ClearTitle),
        intro: tx(
            lang,
            if nothing {
                Msg::ClearNothing
            } else {
                Msg::ClearIntro
            },
        ),
        changed: changed.then(|| tx(lang, Msg::ClearChanged)),
        ops: Vec::new(),
        notes: vec![tx(lang, Msg::ClearUnchanged)],
        details: Vec::new(),
        launch: None,
        confirm: tx(lang, Msg::ClearTitle),
        can_confirm: !nothing,
        blocked: None,
        secondary: None,
        lists,
    }
}

/// Why the clear dialog is not shown.
pub fn clear_gate(g: &ClearGate, lang: Lang) -> ResultVm {
    match g {
        ClearGate::NoAppDir => result(
            Tone::Calm,
            lang,
            Msg::RefNothingTitle,
            Msg::RefNothingBody,
            false,
        ),
        ClearGate::Journal(e) => with_detail(
            result(
                Tone::Attention,
                lang,
                Msg::RefUnexpectedTitle,
                Msg::RefUnexpectedBody,
                false,
            ),
            shown_error(e),
        ),
    }
}

/// What a clear came to: the quiet line says how many entries and launch results went.
pub fn clear_done(r: &PurgeReport, lang: Lang) -> ResultVm {
    result(
        Tone::Done,
        lang,
        Msg::ClearDoneTitle,
        Msg::ClearDoneBody {
            entries: r.removed.len(),
            results: r.results,
        },
        false,
    )
}
