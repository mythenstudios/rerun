//! Keeping the history short and clearing it through the worker (P5-6d-1b, ADR 0027 amendment
//! P5-6d), in the fake world of the write tests; every history is made by real applies, undos and
//! closings.
//! - AH1 an open change, three undone, one closed without undoing, two launch results: the clear
//!   dialog lists what goes and what stays; a confirm removes the three undone and the results
//!   and nothing else (the open and the closed one stay, the game folder is bit-identical), and
//!   the history page is sent again.
//! - AH2 a confirm that carries another nonce than the shown dialog's writes nothing and shows
//!   the current preview again.
//! - AH3 an apply that finds 101 undone entries: the result first, then the quiet line "1 older
//!   history entry removed"; the undone ones that were over the cap are the ones that went.
//! - AH4 something changed since the preview: the core says so, nothing is written and the
//!   preview is shown again with its note.
//! - AH5 nothing to remove: the dialog says so, has no confirm, and a confirm that arrives anyway
//!   writes nothing.

use super::write::{RERUN, Rig, applied_of, dialog_of, result_of};
use super::*;

use rerun_core::journal::TxnId;

use crate::vm::DialogKind;

/// One applied change, undone: the undo's events.
fn apply_and_undo(rig: &mut Rig) -> (TxnId, Vec<Event>) {
    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = applied_of(&ev).cards[0].txn;
    rig.run(Job::RevertPreview { txn });
    let ev = rig.revert(txn);
    (txn, ev)
}

/// [`apply_and_undo`] with the one cheap fix (a single ini edit): AH3 needs 101 of them. The page
/// must have been read once (a plan is refused as stale without it).
fn apply_and_undo_cheap(rig: &mut Rig) -> (TxnId, Vec<Event>) {
    let pv = rig.preview_of(vec![super::write::pick("display", "ini")]);
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = applied_of(&ev).cards[0].txn;
    rig.run(Job::RevertPreview { txn });
    let ev = rig.revert(txn);
    (txn, ev)
}

/// One applied change, left open: its transaction.
fn apply_open(rig: &mut Rig) -> TxnId {
    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    applied_of(&ev).cards[0].txn
}

/// A launch result that ends in a note-less line (the rule was applied), for `app_id`.
fn put_applied_result(rig: &Rig, app_id: u32, unix_s: u64) {
    let id = rerun_core::plan::profile_id(app_id);
    let body = format!(
        "rerun-result 1\nprofile={id}\ntime={unix_s}\nrule=applied\ncpu=none\npriority=none\ncheck=ok\nstart=created\nrule_child=none\n"
    );
    rig.sys
        .fake_fs()
        .put_file(
            Path::new(&format!(r"{RERUN}\launch\{id}.result")),
            body.as_bytes(),
        )
        .unwrap();
    rig.sys.fake_fs().sync_all();
}

/// A file Rerun did not write in the transaction's journal folder: the entry stays (foreign).
fn plant_stray(rig: &Rig, txn: TxnId) -> String {
    let path = format!(r"{RERUN}\journal\{txn}\stray.txt");
    rig.sys
        .fake_fs()
        .put_file(Path::new(&path), b"not Rerun's")
        .unwrap();
    rig.sys.fake_fs().sync_all();
    path
}

fn history_of(ev: &[Event]) -> &vm::HistoryVm {
    ev.iter()
        .find_map(|e| match e {
            Event::History(h) => Some(&**h),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no history in {ev:?}"))
}

fn lines<'a>(d: &'a vm::DialogVm, heading_starts: &str) -> &'a [String] {
    &d.lists
        .iter()
        .find(|l| l.heading.starts_with(heading_starts))
        .unwrap_or_else(|| panic!("no list {heading_starts:?} in {:?}", d.lists))
        .lines
}

#[test]
fn ah1_clear_removes_the_undone_entries_and_results_and_nothing_else() {
    let mut rig = Rig::with_nvidia(Lang::En);
    let mut undone = Vec::new();
    for _ in 0..3 {
        undone.push(apply_and_undo(&mut rig).0);
    }
    // Closed without undoing (the game.ini change), then another change that stays open (the
    // compatibility layer): two changes that touch different things, so both can be applied.
    let pv = rig.preview_of(vec![super::write::pick("display", "ini")]);
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let forgotten = applied_of(&ev).cards[0].txn;
    rig.run(Job::ForgetPreview { txn: forgotten });
    let ev = rig.forget(forgotten);
    assert_eq!(result_of(&ev).notice.title, "Closed");
    let pv = rig.preview_of(vec![super::write::pick("online", "layer")]);
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let open = applied_of(&ev).cards[0].txn;
    // The game is named by the library (a game page was opened), the second result is for a
    // profile no game has.
    rig.page();
    put_applied_result(&rig, 220, 1_762_600_000);
    put_applied_result(&rig, 999, 1_762_600_000);
    let game = rig.snap();

    let ev = rig.run(Job::ClearPreview);
    let d = dialog_of(&ev);
    assert_eq!(d.kind, DialogKind::Clear);
    assert!(d.can_confirm && d.txn.is_none());
    // Newest first, as the history lists them: game, number, state.
    let goes = lines(d, "Entries removed (3)");
    let expect: Vec<String> = undone
        .iter()
        .rev()
        .map(|t| format!("Invented W \u{b7} No. {} \u{b7} Undone", t.seq()))
        .collect();
    assert_eq!(goes, expect.as_slice());
    let results = lines(d, "Launch results removed (2)");
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|l| l == "Invented W"), "{results:?}");
    assert!(
        results.iter().any(|l| l.starts_with("Profile ")),
        "{results:?}"
    );
    let stays = lines(d, "Stays (2)");
    assert!(
        stays
            .iter()
            .any(|l| l.contains(&format!("No. {}", open.seq()))
                && l.contains("Applied")
                && l.contains("Not finished")),
        "{stays:?}"
    );
    assert!(
        stays.contains(&format!(
            "Invented W \u{b7} No. {} \u{b7} Closed without undo. Its backups stay.",
            forgotten.seq()
        )),
        "{stays:?}"
    );
    assert_eq!(
        d.notes.last().map(String::as_str),
        Some("Game folders, the registry and the firewall stay unchanged.")
    );

    // The confirm.
    let nonce = rig.nonce;
    let ev = rig.run(Job::Clear { nonce });
    let r = result_of(&ev);
    assert_eq!(r.notice.title, "History cleared");
    assert_eq!(r.notice.body, "3 entries and 2 launch results removed.");
    let h = history_of(&ev);
    let kinds: Vec<(vm::HistGroup, usize)> = h.groups.iter().map(|g| (g.kind, g.count)).collect();
    assert_eq!(
        kinds,
        [(vm::HistGroup::Open, 1), (vm::HistGroup::Forgotten, 1)]
    );
    assert!(h.launches.is_empty());
    let ids: Vec<TxnId> = h
        .groups
        .iter()
        .flat_map(|g| g.entries.iter().map(|e| e.txn))
        .collect();
    assert!(ids.contains(&open) && ids.contains(&forgotten));
    assert!(rig.snap() == game, "the game folder is as it was");

    // Again: the open and the closed one stay, there is nothing left to remove.
    let ev = rig.run(Job::ClearPreview);
    let d = dialog_of(&ev);
    assert!(!d.can_confirm);
    assert_eq!(d.lists.len(), 1);
    assert_eq!(d.lists[0].heading, "Stays (2)");
}

#[test]
fn ah2_a_confirm_of_another_dialog_writes_nothing() {
    let mut rig = Rig::new(Lang::En);
    apply_and_undo(&mut rig);
    put_applied_result(&rig, 220, 1_762_600_000);
    let first = {
        let ev = rig.run(Job::ClearPreview);
        dialog_of(&ev).nonce
    };
    let ev = rig.run(Job::ClearPreview);
    let second = dialog_of(&ev).nonce;
    assert_ne!(first, second);
    let before = rig.snap_app();

    // The older dialog's confirm: nothing is written, the current preview is shown again.
    let ev = rig.run(Job::Clear { nonce: first });
    let d = dialog_of(&ev);
    assert_eq!(d.kind, DialogKind::Clear);
    assert_eq!(d.nonce, rig.nonce);
    assert_ne!(d.nonce, first);
    assert!(d.changed.is_some());
    assert!(ev.iter().all(|e| !matches!(e, Event::Result(_))), "{ev:?}");
    assert!(rig.snap_app() == before, "nothing was written");
    // A nonce nobody was shown.
    let ev = rig.run(Job::Clear { nonce: 9_999 });
    assert!(matches!(ev.as_slice(), [Event::Dialog(_)]), "{ev:?}");
    assert!(rig.snap_app() == before, "nothing was written");
    // The token is used once: the dialog that was shown last can be confirmed, once.
    let nonce = rig.nonce;
    let ev = rig.run(Job::Clear { nonce });
    assert_eq!(result_of(&ev).notice.title, "History cleared");
    let after = rig.snap_app();
    let ev = rig.run(Job::Clear { nonce });
    assert!(matches!(ev.as_slice(), [Event::Dialog(_)]), "{ev:?}");
    assert!(rig.snap_app() == after, "a second click writes nothing");
}

#[test]
fn ah3_an_apply_that_finds_101_undone_entries_says_how_many_went() {
    let mut rig = Rig::new(Lang::En);
    rig.page();
    let (oldest, ev) = apply_and_undo_cheap(&mut rig);
    assert!(result_of(&ev).note.is_none());
    // The oldest entry holds a file that is not Rerun's: the cap skips it, so the entries pile up
    // past the cap without anything going (a failure of the cap would look the same).
    let stray = plant_stray(&rig, oldest);
    for _ in 1..=rerun_core::flow::HISTORY_KEEP {
        let (_, ev) = apply_and_undo_cheap(&mut rig);
        assert!(result_of(&ev).note.is_none(), "{:?}", result_of(&ev));
    }
    let ev = rig.run(Job::History);
    let undone = &history_of(&ev).groups[0];
    assert_eq!(
        (undone.kind, undone.count),
        (vm::HistGroup::Reverted, 101),
        "101 undone entries"
    );
    // The stray file is gone: the oldest entry can be removed now.
    rig.sys.fake_fs().remove_abs(Path::new(&stray)).unwrap();
    rig.sys.fake_fs().sync_all();

    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    // The result comes first and is the apply's own; the quiet line follows it.
    let Some(Event::Result(r)) = ev.first() else {
        panic!("{ev:?}");
    };
    assert_eq!(r.notice.title, "Applied");
    assert_eq!(r.note.as_deref(), Some("1 older history entry removed"));
    let ev = rig.run(Job::History);
    let undone = &history_of(&ev).groups[1];
    assert_eq!((undone.kind, undone.count), (vm::HistGroup::Reverted, 100));
    assert!(
        undone.entries.iter().all(|e| e.txn != oldest),
        "the oldest entry went"
    );

    // German.
    rig.lang = Lang::De;
    let txn = applied_of(&rig.run(Job::Status)).cards[0].txn;
    rig.run(Job::RevertPreview { txn });
    let ev = rig.revert(txn);
    assert_eq!(
        result_of(&ev).note.as_deref(),
        Some("1 älterer Verlaufseintrag entfernt")
    );
}

#[test]
fn ah4_a_history_that_changed_since_the_preview_is_shown_again() {
    let mut rig = Rig::new(Lang::En);
    let (a, _) = apply_and_undo(&mut rig);
    let (b, _) = apply_and_undo(&mut rig);
    rig.run(Job::ClearPreview);
    // After the preview, a file that is not Rerun's appears in an entry that was to go.
    plant_stray(&rig, a);
    let before = rig.snap_app();
    let nonce = rig.nonce;
    let ev = rig.run(Job::Clear { nonce });
    assert!(ev.iter().all(|e| !matches!(e, Event::Result(_))), "{ev:?}");
    let d = dialog_of(&ev);
    assert_eq!(
        d.changed.as_deref(),
        Some("The history changed; look at it again.")
    );
    assert!(rig.snap_app() == before, "nothing was written");
    // The new preview lists the one that can still go and keeps the other with its reason.
    assert_eq!(
        lines(d, "Entries removed (1)"),
        [format!("Invented W \u{b7} No. {} \u{b7} Undone", b.seq())]
    );
    assert!(
        lines(d, "Stays (1)")[0].contains("holds something Rerun did not write"),
        "{:?}",
        d.lists
    );
    // And that dialog can be confirmed.
    let nonce = rig.nonce;
    let ev = rig.run(Job::Clear { nonce });
    assert_eq!(
        result_of(&ev).notice.body,
        "1 entry and 0 launch results removed."
    );
}

#[test]
fn ah5_with_nothing_to_remove_the_dialog_says_so_and_a_confirm_writes_nothing() {
    let mut rig = Rig::new(Lang::En);
    apply_open(&mut rig);
    let before = rig.snap_app();
    let ev = rig.run(Job::ClearPreview);
    let d = dialog_of(&ev);
    assert!(!d.can_confirm);
    assert_eq!(
        d.intro,
        "There is nothing Rerun can remove from the history now."
    );
    assert!(d.lists.iter().all(|l| l.heading.starts_with("Stays")));
    let nonce = rig.nonce;
    let ev = rig.run(Job::Clear { nonce });
    assert!(matches!(ev.as_slice(), [Event::Dialog(_)]), "{ev:?}");
    assert!(rig.snap_app() == before, "nothing was written");
    // The window cannot close while a clear is queued (a write job).
    assert!(Job::Clear { nonce: 1 }.writes());
    assert!(!Job::ClearPreview.writes());
}
