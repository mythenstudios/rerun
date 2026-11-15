//! Problem states through the worker (P5-6b, ADR 0027 amendment P5-6b), in the fake world of the
//! write tests.
//! - AR1 a real crash in the middle of an apply (a fault on a rename, then a power loss): the
//!   next status shows the change as interrupted and the band counts it; the undo preview, the
//!   undo, the game folder bit-identical to before, the band gone. Looking writes nothing.
//! - AR3 someone else changed Rerun's file: the undo reports it per change (left as found, where
//!   the old state is), the card says "Needs you" and the band counts it, "Close without undoing"
//!   closes it, the band goes and the history lists it as closed without undoing.
//! - AO1 the orphaned firewall rules: read by their own job, not by the status; a rule of
//!   Rerun's no change owns is listed; none, no folder.
//!
//! AR2 (a cleanup that is still pending) is covered where the files are: the card state and the
//! band by VR1, the report of a copy in use or kept by VR2, the revert itself by the core's
//! cleanup tests; the world of these tests has no step that replaces a file.

use std::collections::BTreeMap;

use rerun_core::sys::fake::{Fault, Prim};

use super::write::{RERUN, Rig, applied_of, result_of};
use super::*;
use crate::vm::{Tone, attention};

#[test]
fn ar1_a_crash_in_the_middle_of_an_apply_is_interrupted_then_undone() {
    // Find a rename the apply reaches after something is written, so the crash leaves the
    // transaction open with changes on disk.
    let mut found = None;
    for nth in 2..=12usize {
        let mut rig = Rig::new(Lang::En);
        let before = rig.snap();
        let pv = rig.preview();
        rig.sys
            .fake_fs()
            .fault(Prim::Rename, nth, Fault::CrashAfter);
        rig.run(Job::Apply { hash: pv.hash });
        let crashed = rig.sys.fake_fs().crashed();
        // The process dies; what was durable stays.
        rig.sys.power_loss(&BTreeMap::new());
        rig.sys.fake_fs().restart();
        if !crashed {
            continue;
        }
        let ev = rig.run(Job::Status);
        let a = applied_of(&ev);
        if a.cards.iter().any(|c| c.state.word == "Interrupted") {
            found = Some((rig, before, nth));
            break;
        }
    }
    let (mut rig, before, nth) = found.expect("some rename leaves an open transaction");
    assert!(nth >= 2);
    let ev = rig.run(Job::Status);
    let a = applied_of(&ev);
    assert_eq!(a.open, 1, "{a:?}");
    let card = &a.cards[0];
    assert_eq!(card.state.word, "Interrupted");
    assert!(card.problem.is_some() && card.can_undo);
    // The band counts it; it only says so.
    let band = attention(a, Lang::En).expect("the band");
    assert_eq!((band.count, band.title.as_str()), (1, "1 change needs you"));
    let txn = card.txn;
    // Looking at the history and the undo preview writes nothing.
    let app_before = rig.snap_app();
    let ev = rig.run(Job::History);
    assert!(
        matches!(ev.as_slice(), [Event::History(h)] if h.groups[0].kind == vm::HistGroup::Open)
    );
    let ev = rig.run(Job::RevertPreview { txn });
    assert!(matches!(ev.as_slice(), [Event::Dialog(_)]));
    assert!(rig.snap_app() == app_before, "the preview writes nothing");
    // The undo puts the game folder back, bit for bit, and the band goes.
    let ev = rig.revert(txn);
    let r = result_of(&ev);
    assert_eq!(r.tone, Tone::Done, "{r:?}");
    let a = applied_of(&ev);
    assert_eq!(a.open, 0);
    assert!(attention(a, Lang::En).is_none());
    let after = rig.snap();
    assert!(after == before, "{:#?}", before.diff(&after));
}

#[test]
fn ar3_someone_elses_change_is_reported_per_change_and_closed_without_undoing() {
    let mut rig = Rig::new(Lang::En);
    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let card = &applied_of(&ev).cards[0];
    let txn = card.txn;
    let profile = card
        .ops
        .iter()
        .find(|o| o.target.as_str().ends_with(".profile"))
        .unwrap()
        .target
        .as_str()
        .to_owned();
    rig.sys
        .fake_fs()
        .put_file(
            std::path::Path::new(&format!(r"{RERUN}\profiles\{profile}")),
            b"someone else was here",
        )
        .unwrap();
    rig.run(Job::RevertPreview { txn });
    let ev = rig.revert(txn);
    let r = result_of(&ev);
    assert_eq!(r.tone, Tone::Attention);
    // The report names the change that was left as found, with its target and where its old
    // state is kept.
    let who: Vec<&str> = r
        .notice
        .details
        .iter()
        .filter_map(|d| d.who.as_ref().map(|w| w.as_str()))
        .collect();
    assert!(
        who.iter().any(|w| w.starts_with("Someone else changed it")),
        "{who:?}"
    );
    let left = r
        .notice
        .details
        .iter()
        .find(|d| {
            d.who
                .as_ref()
                .is_some_and(|w| w.as_str().starts_with("Someone else changed it"))
        })
        .unwrap();
    assert!(left.what.as_str().ends_with(".profile"), "{:?}", left.what);
    // The card and the band.
    let a = applied_of(&ev);
    assert_eq!(a.cards[0].state.word, "Needs you");
    assert_eq!(attention(a, Lang::En).map(|b| b.count), Some(1));
    // Close without undoing: the card goes, the band with it, the history keeps the entry.
    rig.run(Job::ForgetPreview { txn });
    let ev = rig.forget(txn);
    let a = applied_of(&ev);
    assert_eq!(a.open, 0);
    assert!(attention(a, Lang::En).is_none());
    let ev = rig.run(Job::History);
    let Some(Event::History(h)) = ev.first() else {
        panic!("{ev:?}");
    };
    assert_eq!(h.groups.len(), 1);
    assert_eq!(h.groups[0].kind, vm::HistGroup::Forgotten);
    assert_eq!(h.groups[0].entries[0].txn, txn);
    assert!(h.groups[0].entries[0].backups.is_some());
}

fn seed_rule(rig: &Rig, name: &str) {
    use rerun_core::sys::firewall::{FwRest, FwRule};
    rig.sys.fake_firewall().push(FwRule {
        name: name.to_owned(),
        description: String::new(),
        grouping: "Rerun".to_owned(),
        program: r"D:\SteamLibrary\steamapps\common\G\game.exe".to_owned(),
        direction: 2,
        action: 0,
        profiles: 0x7fff_ffff,
        protocol: 256,
        enabled: true,
        rest: FwRest::default(),
    });
}

#[test]
fn ao1_the_orphaned_rules_come_from_their_own_job() {
    let mut rig = Rig::new(Lang::En);
    // None: no section.
    let ev = rig.run(Job::Orphans);
    assert!(
        matches!(ev.as_slice(), [Event::Orphans(o)] if !o.shown),
        "{ev:?}"
    );
    // A rule of Rerun's that no open change owns is listed, with how to remove it.
    seed_rule(&rig, "Rerun orphan rule");
    let ev = rig.run(Job::Orphans);
    let [Event::Orphans(o)] = ev.as_slice() else {
        panic!("{ev:?}");
    };
    assert!(o.shown);
    assert_eq!(o.rules.len(), 1);
    assert_eq!(o.rules[0].name.as_str(), "Rerun orphan rule");
    assert!(o.hint.contains("Windows Defender Firewall"));
    // The status job answers with the journal only.
    let ev = rig.run(Job::Status);
    assert!(matches!(ev.as_slice(), [Event::Applied(_)]));
    // The firewall fails: said, not an error of the page.
    rig.sys
        .fake_firewall()
        .fail_with(Some(rerun_core::sys::SysErrorKind::Other));
    let ev = rig.run(Job::Orphans);
    let [Event::Orphans(o)] = ev.as_slice() else {
        panic!("{ev:?}");
    };
    assert!(o.shown && o.rules.is_empty() && o.note.is_some() && o.detail.is_some());
    // No Rerun folder: nothing is read, nothing is created.
    let bare = steam_world("Invented W");
    let ev = events(&bare, &Job::Orphans, Lang::En);
    assert!(
        matches!(ev.as_slice(), [Event::Orphans(o)] if !o.shown),
        "{ev:?}"
    );
    assert!(AppDir::open(&bare, Create::Never).unwrap().is_none());
}
