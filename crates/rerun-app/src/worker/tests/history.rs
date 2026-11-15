//! The history page and the last start through the worker (P5-6a, ADR 0027 amendment P5-6a), in
//! the fake world of the write tests.
//! - AV1 apply, then undo: the history lists the transaction first under "Open", then under
//!   "Undone" with the game and everything in it; nothing is written by looking; no Rerun folder
//!   means an empty history and creates none.
//! - AV2 a launch result of the game: the game page says when and what came of it, the history
//!   names the row by the game; the time comes from the session's clock.
//! - AV3 the timing of the history with 100 transactions.

use std::time::Instant;

use super::write::Rig;
use super::*;
use crate::text::Sym;

fn history_of(ev: &[Event]) -> &vm::HistoryVm {
    ev.iter()
        .find_map(|e| match e {
            Event::History(h) => Some(&**h),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no history in {ev:?}"))
}

#[test]
fn av1_apply_then_undo_moves_the_entry_between_groups() {
    let mut rig = Rig::new(Lang::En);
    // No Rerun folder yet: an empty history, and looking creates none.
    let bare = steam_world("Invented W");
    let ev = events(&bare, &Job::History, Lang::En);
    let h = history_of(&ev);
    assert!(h.groups.is_empty() && h.empty.is_some());
    assert!(AppDir::open(&bare, Create::Never).unwrap().is_none());

    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = super::write::applied_of(&ev).cards[0].txn;
    let before = rig.snap_app();
    let ev = rig.run(Job::History);
    let h = history_of(&ev);
    assert_eq!(h.groups.len(), 1);
    assert_eq!(h.groups[0].kind, vm::HistGroup::Open);
    let e = &h.groups[0].entries[0];
    assert_eq!(e.txn, txn);
    assert_eq!(e.game.as_ref().map(Value::as_str), Some("Invented W"));
    assert_eq!(
        (e.state.sym, e.state.word.as_str()),
        (Sym::Applied, "Applied")
    );
    assert!(!e.ops.is_empty());
    assert!(rig.snap_app() == before, "looking writes nothing");

    let ev = rig.run(Job::RevertPreview { txn });
    assert!(matches!(ev.as_slice(), [Event::Dialog(_)]));
    let ev = rig.revert(txn);
    assert_eq!(super::write::applied_of(&ev).open, 0);
    let after = rig.snap_app();
    let ev = rig.run(Job::History);
    let h = history_of(&ev);
    assert_eq!(h.groups.len(), 1, "{h:?}");
    let g = &h.groups[0];
    assert_eq!(
        (g.kind, g.title.as_str()),
        (vm::HistGroup::Reverted, "Undone")
    );
    let e = &g.entries[0];
    assert_eq!(e.txn, txn);
    assert_eq!(e.id, txn.to_string());
    // The closed entry still names its game and lists everything it changed (every head read).
    assert_eq!(e.game.as_ref().map(Value::as_str), Some("Invented W"));
    assert!(!e.ops.is_empty());
    assert_eq!((e.state.sym, e.state.word.as_str()), (Sym::None, "Undone"));
    assert!(e.backups.is_none());
    assert!(rig.snap_app() == after, "looking writes nothing");

    // German words.
    rig.lang = Lang::De;
    let ev = rig.run(Job::History);
    let h = history_of(&ev);
    assert_eq!(h.groups[0].title, "Rückgängig gemacht");
    assert_eq!(h.groups[0].entries[0].state.word, "Rückgängig gemacht");
}

fn put_result(rig: &Rig, app_id: u32, unix_s: u64, rule: &str) {
    let id = rerun_core::plan::profile_id(app_id);
    let body = format!(
        "rerun-result 1\nprofile={id}\ntime={unix_s}\nrule={rule}\ncpu=none\npriority=none\ncheck=none\nstart=created\nrule_child=none\n"
    );
    rig.sys
        .fake_fs()
        .put_file(
            Path::new(&format!(r"{}\launch\{id}.result", super::write::RERUN)),
            body.as_bytes(),
        )
        .unwrap();
    rig.sys.fake_fs().sync_all();
}

#[test]
fn av2_the_game_page_says_when_it_was_last_started() {
    let mut rig = Rig::new(Lang::En);
    rig.session.now = Some(1_762_600_000 + 2 * 3_600 + 30);
    // No result yet: no fact.
    let page = rig.page();
    assert!(page.facts.iter().all(|f| f.label != "Last start"));
    // A result of this game and one of another profile.
    put_result(&rig, 220, 1_762_600_000, "skipped:profile_missing");
    put_result(&rig, 999, 1_762_600_000, "skipped:profile_missing");
    let page = rig.page();
    let f = page.facts.iter().find(|f| f.label == "Last start").unwrap();
    assert_eq!(
        f.value.as_str(),
        "2 hours ago \u{b7} Rule not applied",
        "{:?}",
        page.facts
    );
    assert!(
        page.notes
            .iter()
            .any(|n| n.contains("launch option for Rerun's launcher was still set")),
        "{:?}",
        page.notes
    );
    // The history names the row by the game, the other one by its profile.
    let ev = rig.run(Job::History);
    let h = history_of(&ev);
    assert_eq!(h.launches.len(), 2);
    let names: Vec<(&str, bool)> = h
        .launches
        .iter()
        .map(|r| (r.game.as_str(), r.game_is_id))
        .collect();
    assert!(names.contains(&("Invented W", false)), "{names:?}");
    assert_eq!(names.iter().filter(|n| n.1).count(), 1);
    assert_eq!(h.launches[0].when, "2 hours ago");
    assert_eq!(
        h.launches[0].exact.as_deref(),
        Some("2025-11-08 11:06:40 UTC")
    );
    assert!(h.launch_title.is_some());
}

/// AV3 the history of 100 transactions (each an apply and its undo, so each has a head, ops and
/// a closing) is read in the time of the applied page's order of magnitude: the test measures
/// the job and holds it to a generous bound (the real figure goes to the timing trace and
/// `docs/09-testing.md`).
#[test]
fn av3_a_history_of_100_transactions_is_fast() {
    let mut rig = Rig::new(Lang::En);
    for _ in 0..100 {
        let pv = rig.preview();
        let ev = rig.run(Job::Apply { hash: pv.hash });
        let txn = super::write::applied_of(&ev).cards[0].txn;
        rig.run(Job::RevertPreview { txn });
        let ev = rig.revert(txn);
        assert_eq!(super::write::result_of(&ev).notice.title, "Undone");
    }
    let began = Instant::now();
    let ev = rig.run(Job::History);
    let took = began.elapsed();
    let h = history_of(&ev);
    assert_eq!(h.groups.len(), 1);
    assert_eq!(h.groups[0].entries.len(), 100);
    // Newest first.
    let seqs: Vec<u32> = h.groups[0].entries.iter().map(|e| e.txn.seq()).collect();
    assert!(seqs.windows(2).all(|w| w[0] > w[1]), "{seqs:?}");
    eprintln!("history of 100 transactions: {took:?}");
    assert!(
        took < std::time::Duration::from_millis(2_000),
        "the history of 100 transactions took {took:?}"
    );
}
