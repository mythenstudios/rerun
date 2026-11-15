//! The clear dialog and the quiet lines of the history's upkeep (P5-6d-1b), as view models on
//! values built by hand, in both languages.
//! - VH2 the dialog lists every entry and launch result that goes (game, number, state) and every
//!   one that stays with its reason, then the sentence that nothing else is touched; nothing to
//!   remove: no confirm.
//! - VT1 the quiet line of the cap: only for more than none, plural-correct, never for a failure
//!   of the cap; and the result of a clear.
//! - VH3 the history page says what Rerun keeps (the cap from the core) and offers the button,
//!   unless there is no history.

use rerun_core::escape;
use rerun_core::exec::{Keep, PurgeReport, TxnLine};
use rerun_core::flow::{ClearGate, ClearItem, ClearPreview, ResultKeep, Tidied, TidyNote};
use rerun_core::journal::{Closing, JournalError, TxnId};
use rerun_core::plan::profile_id;

use crate::text::{Lang, Msg, t};
use crate::vm::{DialogKind, Names, clear_done, clear_gate, clear_vm, tidy_line};

fn id(seq: u32) -> TxnId {
    format!("{seq:08}-0123456789abcdef").parse().unwrap()
}

fn item(seq: u32, app: Option<u32>, line: TxnLine) -> ClearItem {
    ClearItem {
        txn: id(seq),
        app,
        line,
        forgotten: false,
    }
}

/// A change closed without undoing: the journal line is the open one, the marker says forgotten.
fn forgotten(seq: u32, app: Option<u32>) -> ClearItem {
    ClearItem {
        forgotten: true,
        ..item(seq, app, TxnLine::Applied)
    }
}

fn names() -> Names {
    let mut n = Names::new();
    n.insert(220, escape::text("Invented W").into_owned());
    n
}

fn preview() -> ClearPreview {
    ClearPreview {
        // Oldest first, as the core lists them.
        remove: vec![
            item(2, Some(220), TxnLine::Closed(Closing::Reverted)),
            item(5, None, TxnLine::Closed(Closing::RolledBack)),
            item(7, Some(330), TxnLine::Empty),
            item(13, None, TxnLine::Empty),
        ],
        stays: vec![
            item(1, Some(220), TxnLine::Applied),
            forgotten(3, Some(220)),
            item(4, Some(220), TxnLine::Closed(Closing::Reverted)),
            item(
                6,
                None,
                TxnLine::Unreadable(escape::text("bad").into_owned()),
            ),
            item(8, Some(220), TxnLine::Closed(Closing::Reverted)),
            item(9, Some(220), TxnLine::Closed(Closing::Reverted)),
            item(10, Some(220), TxnLine::Closed(Closing::Reverted)),
            forgotten(11, Some(220)),
            forgotten(12, Some(220)),
            item(14, None, TxnLine::Empty),
        ]
        .into_iter()
        .zip([
            Keep::NotSettled,
            Keep::Forgotten,
            Keep::HandedOver,
            Keep::Unreadable,
            Keep::Foreign,
            Keep::TooManyEntries,
            Keep::InUse,
            Keep::HoldsProfile,
            Keep::Forgotten,
            Keep::Foreign,
        ])
        .collect(),
        results: vec![profile_id(220), profile_id(999)],
        results_stay: vec![
            (profile_id(330), ResultKeep::OptionStillSet),
            (profile_id(331), ResultKeep::Unreadable),
        ],
    }
}

fn lines<'a>(d: &'a crate::vm::DialogVm, start: &str) -> &'a [String] {
    &d.lists
        .iter()
        .find(|l| l.heading.starts_with(start))
        .unwrap_or_else(|| panic!("no list {start:?} in {:?}", d.lists))
        .lines
}

#[test]
fn vh2_the_dialog_lists_what_goes_and_what_stays_with_its_reason() {
    let d = clear_vm(&preview(), &names(), false, 7, Lang::En);
    assert_eq!((d.kind, d.nonce, d.txn), (DialogKind::Clear, 7, None));
    assert!(d.can_confirm && d.changed.is_none() && d.blocked.is_none());
    assert_eq!(d.title, "Clear history");
    assert_eq!(d.confirm, "Clear history");
    assert_eq!(
        d.intro,
        "These entries and launch results are removed from the history."
    );
    assert_eq!(
        d.notes,
        ["Game folders, the registry and the firewall stay unchanged."]
    );
    // What goes: newest first, the game as the history names it (a name, "Steam app N", or
    // nothing when the head names none), the number, the state.
    assert_eq!(
        lines(&d, "Entries removed (4)"),
        [
            "No. 5 \u{b7} Rolled back",
            "Invented W \u{b7} No. 2 \u{b7} Undone",
            // The two that changed nothing are one line, not a row each.
            "2 empty entries (changed nothing)",
        ]
    );
    // Launch results by game, or by profile when no game has it.
    let r = lines(&d, "Launch results removed (2)");
    assert_eq!(r[0], "Invented W");
    assert_eq!(
        r[1],
        format!("Profile {}", profile_id(999)),
        "a profile no known game has"
    );
    // What stays: every entry with its reason, then the results that stay.
    let stays = lines(&d, "Stays (12)");
    let want = [
        "Invented W \u{b7} No. 12 \u{b7} Closed without undo. Its backups stay.",
        "Invented W \u{b7} No. 11 \u{b7} Closed without undo. It still holds a launch profile.",
        "Invented W \u{b7} No. 10 \u{b7} Undone. A backup is in use right now; a later clean-up removes the entry.",
        "Invented W \u{b7} No. 9 \u{b7} Undone. Its folder has too many files.",
        "Invented W \u{b7} No. 8 \u{b7} Undone. Its folder holds something Rerun did not write there.",
        "No. 6 \u{b7} Unreadable. Its folder cannot be read.",
        "Invented W \u{b7} No. 4 \u{b7} Undone. It handed files over to a later change that is not finished yet.",
        "Invented W \u{b7} No. 3 \u{b7} Closed without undo. Its backups stay.",
        "Invented W \u{b7} No. 1 \u{b7} Applied. Not finished: undo it or close it first.",
        "1 empty entry (changed nothing)",
    ];
    assert_eq!(&stays[..10], want.as_slice());
    // A result of a game the journal names (330, from the entry that changed nothing) goes by
    // its game; one of a profile no game has goes by the profile.
    assert_eq!(
        stays[10],
        "Steam app 330. The Steam launch option still points at Rerun: remove it by hand first."
    );
    assert_eq!(
        stays[11],
        format!("Profile {}. It cannot be read.", profile_id(331))
    );
    // The headings are in this order.
    let heads: Vec<&str> = d.lists.iter().map(|l| l.heading.as_str()).collect();
    assert_eq!(
        heads,
        [
            "Entries removed (4)",
            "Launch results removed (2)",
            "Stays (12)"
        ]
    );
}

#[test]
fn vh2_every_keep_and_result_keep_has_its_own_words_in_both_languages() {
    // One entry per reason: the reason of each is a different sentence, in each language.
    let keeps = [
        Keep::NotSettled,
        Keep::Unreadable,
        Keep::HoldsProfile,
        Keep::HandedOver,
        Keep::Foreign,
        Keep::TooManyEntries,
        Keep::Forgotten,
        Keep::InUse,
    ];
    for lang in Lang::ALL {
        let mut seen = Vec::new();
        for k in keeps {
            let p = ClearPreview {
                remove: Vec::new(),
                stays: vec![(item(1, None, TxnLine::Applied), k)],
                results: Vec::new(),
                results_stay: Vec::new(),
            };
            let d = clear_vm(&p, &Names::new(), false, 1, lang);
            let line = lines(&d, "").first().cloned().unwrap();
            assert!(!seen.contains(&line), "{lang:?} {k:?}: {line}");
            seen.push(line);
        }
        for k in [ResultKeep::OptionStillSet, ResultKeep::Unreadable] {
            let p = ClearPreview {
                remove: Vec::new(),
                stays: Vec::new(),
                results: Vec::new(),
                results_stay: vec![(profile_id(5), k)],
            };
            let d = clear_vm(&p, &Names::new(), false, 1, lang);
            let line = lines(&d, "").first().cloned().unwrap();
            assert!(!seen.contains(&line), "{lang:?} {k:?}: {line}");
            seen.push(line);
        }
    }
    // German spot checks.
    let d = clear_vm(&preview(), &names(), false, 7, Lang::De);
    assert_eq!(d.title, "Verlauf leeren");
    assert_eq!(
        d.notes,
        ["Spielordner, Registry und Firewall bleiben unverändert."]
    );
    assert_eq!(
        lines(&d, "Entfernte Einträge (4)"),
        [
            "Nr. 5 \u{b7} Zurückgerollt",
            "Invented W \u{b7} Nr. 2 \u{b7} Rückgängig gemacht",
            "2 leere Einträge (nichts geändert)",
        ]
    );
    let stays = lines(&d, "Bleibt (12)");
    assert_eq!(
        stays[0],
        "Invented W \u{b7} Nr. 12 \u{b7} Ohne Rückgängig abgeschlossen. Seine Sicherungen bleiben."
    );
    assert_eq!(stays[9], "1 leerer Eintrag (nichts geändert)");
    assert!(
        stays[8]
            .ends_with("Nicht abgeschlossen: Mache sie zuerst rückgängig oder schliesse sie ab."),
        "{stays:?}"
    );
}

#[test]
fn vh2_nothing_to_remove_has_no_confirm_and_a_changed_note_is_shown() {
    let p = ClearPreview {
        remove: Vec::new(),
        stays: vec![(item(1, Some(220), TxnLine::Applied), Keep::NotSettled)],
        results: Vec::new(),
        results_stay: Vec::new(),
    };
    let d = clear_vm(&p, &names(), true, 3, Lang::En);
    assert!(!d.can_confirm);
    assert_eq!(
        d.intro,
        "There is nothing Rerun can remove from the history now."
    );
    assert_eq!(
        d.changed.as_deref(),
        Some("The history changed; look at it again.")
    );
    // Only what stays is listed.
    assert_eq!(d.lists.len(), 1);
    assert_eq!(d.lists[0].heading, "Stays (1)");
    // A launch result alone is enough to confirm.
    let p = ClearPreview {
        remove: Vec::new(),
        stays: Vec::new(),
        results: vec![profile_id(220)],
        results_stay: Vec::new(),
    };
    assert!(clear_vm(&p, &names(), false, 1, Lang::En).can_confirm);
}

#[test]
fn vh2_the_gate_says_why_there_is_no_dialog() {
    let r = clear_gate(&ClearGate::NoAppDir, Lang::En);
    assert_eq!(r.notice.title, t(Lang::En, Msg::RefNothingTitle));
    let e = JournalError::Busy;
    let r = clear_gate(&ClearGate::Journal(e), Lang::En);
    assert_eq!(r.notice.title, t(Lang::En, Msg::RefUnexpectedTitle));
    assert_eq!(r.notice.details.len(), 1);
}

#[test]
fn vt1_the_quiet_line_names_how_many_went_and_never_a_failure() {
    let ok = |n| Ok(Tidied { removed: n });
    assert_eq!(tidy_line(&ok(0), Lang::En), None);
    assert_eq!(
        tidy_line(&ok(1), Lang::En).as_deref(),
        Some("1 older history entry removed")
    );
    assert_eq!(
        tidy_line(&ok(5), Lang::En).as_deref(),
        Some("5 older history entries removed")
    );
    assert_eq!(
        tidy_line(&ok(1), Lang::De).as_deref(),
        Some("1 älterer Verlaufseintrag entfernt")
    );
    assert_eq!(
        tidy_line(&ok(2), Lang::De).as_deref(),
        Some("2 ältere Verlaufseinträge entfernt")
    );
    // A failure of the cap is never shown.
    let note = TidyNote::Journal(JournalError::Busy);
    assert_eq!(tidy_line(&Err(note), Lang::En), None);

    // The result of a clear says how many entries and launch results went, plural-correct.
    let report = |n: u32, results| PurgeReport {
        removed: (1..=n).map(id).collect(),
        results,
        ..PurgeReport::default()
    };
    let r = clear_done(&report(1, 1), Lang::En);
    assert_eq!(r.notice.title, "History cleared");
    assert_eq!(r.notice.body, "1 entry and 1 launch result removed.");
    assert_eq!(
        clear_done(&report(3, 0), Lang::En).notice.body,
        "3 entries and 0 launch results removed."
    );
    assert_eq!(
        clear_done(&report(2, 2), Lang::De).notice.body,
        "2 Einträge und 2 Startergebnisse entfernt."
    );
}

/// VT2 an entry the core refused at delete time is listed under "Stays" with its reason, and one
/// that was gone already counts as done with the removed ones.
#[test]
fn vt2_the_result_lists_what_the_core_refused_and_counts_gone_as_done() {
    let r = PurgeReport {
        removed: vec![id(1)],
        gone: vec![id(2), id(3)],
        refused: vec![(id(4), Keep::InUse), (id(5), Keep::Foreign)],
        results: 1,
    };
    let en = clear_done(&r, Lang::En);
    assert_eq!(en.notice.body, "3 entries and 1 launch result removed.");
    let d: Vec<(Option<&str>, &str)> = en
        .notice
        .details
        .iter()
        .map(|d| (d.who.as_ref().map(|w| w.as_str()), d.what.as_str()))
        .collect();
    assert_eq!(
        d,
        [
            (None, "Stays (2)"),
            (
                Some("No. 4"),
                "A backup is in use right now; a later clean-up removes the entry."
            ),
            (
                Some("No. 5"),
                "Its folder holds something Rerun did not write there."
            ),
        ]
    );
    let de = clear_done(&r, Lang::De);
    assert_eq!(de.notice.details[0].what.as_str(), "Bleibt (2)");
    assert_eq!(
        de.notice.details[1].what.as_str(),
        "Eine Sicherung ist gerade in Gebrauch; die nächste Aufräumung entfernt den Eintrag."
    );
    // Nothing refused: no "Stays" detail at all.
    let clean = PurgeReport {
        removed: vec![id(1)],
        ..PurgeReport::default()
    };
    assert!(clear_done(&clean, Lang::En).notice.details.is_empty());
}
