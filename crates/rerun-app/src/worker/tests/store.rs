//! Removing packages through the worker (P5-8b-3, ADR 0027 amendment P5-8b-3), in the fake world
//! of the download tests: the page, the dialog, the nonce, the stay of a used package and a
//! fix card that asks for the download again.
//! - AS1 a downloaded package: the page lists it, the dialog lists its files and archive, a
//!   confirm of another nonce removes nothing and shows the dialog again, the right one removes
//!   exactly that; the folders are empty, the page is read again and the fix asks for the download
//!   again.
//! - AS2 a package of an applied change stays: the page names the game and the change, the dialog
//!   has no confirm and a confirm that arrives anyway removes nothing; after the undo it goes, and
//!   the game folder is as before the apply.
//! - AS3 a package used between the preview and the confirm: the core refuses, the dialog is shown
//!   again with its note, nothing is removed.
//! - AS4 only the removal is a write job (the window does not close while it runs).
//! - AS5 an empty store: the page says so, and nothing is created.

use rerun_core::flow;
use rerun_core::journal::TxnId;
use rerun_core::plan::Pick;
use rerun_core::sys::fake::FakeReply;

use super::download::{DRig, ended, upper};
use super::*;
use crate::text::{Msg, t};
use crate::vm::{DialogKind, DialogVm, Offer, ResultVm, Selection, StoreVm, Tone};
use crate::worker::DownloadOutcome;

/// Each line as one string.
fn flat(lines: &[crate::vm::TextLine]) -> Vec<String> {
    lines.iter().map(crate::vm::TextLine::flat).collect()
}

fn rig(lang: Lang) -> DRig {
    DRig::new(lang, |a| FakeReply::ok(a).chunked(16 * 1024))
}

/// The fix's package is downloaded (the consent, then the confirm).
fn downloaded(lang: Lang) -> DRig {
    let mut r = rig(lang);
    r.page();
    let d = r.ask();
    let ev = r.run(Job::Download { nonce: d.nonce });
    assert_eq!(ended(&ev), Some(DownloadOutcome::Done), "{ev:?}");
    r
}

fn store_of(ev: &[Event]) -> &StoreVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Store(v) => Some(&**v),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no store page in {ev:?}"))
}

fn dialog(ev: &[Event]) -> &DialogVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Dialog(d) => Some(&**d),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no dialog in {ev:?}"))
}

fn result(ev: &[Event]) -> &ResultVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Result(r) => Some(r),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no result in {ev:?}"))
}

fn pick() -> flow::Pick {
    flow::Pick::Package {
        id: "fix-pack".to_owned(),
        version: "1.0".to_owned(),
    }
}

/// Applies the fix (the downloaded package): the change's number.
fn apply_fix(r: &mut DRig) -> TxnId {
    let page = r.page();
    let mut sel = Selection::default();
    sel.toggle(&page, 0);
    let ev = r.run(Job::Plan {
        app_id: 220,
        choices: Vec::new(),
        picks: vec![Pick {
            issue: "crash".to_owned(),
            variant: "fix-pack".to_owned(),
        }],
    });
    let hash = match ev.as_slice() {
        [Event::Preview { vm, .. }] => vm.hash.clone(),
        other => panic!("{other:?}"),
    };
    r.run(Job::PreviewShown { hash: hash.clone() });
    let ev = r.run(Job::Apply { hash });
    assert_eq!(result(&ev).tone, Tone::Done, "{ev:?}");
    ev.iter()
        .find_map(|e| match e {
            Event::Applied(a) => a.cards.first().map(|c| c.txn),
            _ => None,
        })
        .expect("the applied card")
}

fn undo(r: &mut DRig, txn: TxnId) {
    let ev = r.run(Job::RevertPreview { txn });
    let nonce = dialog(&ev).nonce;
    let ev = r.run(Job::Revert { txn, nonce });
    assert_eq!(result(&ev).tone, Tone::Done, "{ev:?}");
}

#[test]
fn as1_a_confirm_of_the_shown_dialog_removes_exactly_that_package() {
    for lang in Lang::ALL {
        let w = |m| t(lang, m).into_owned();
        let mut r = downloaded(lang);
        let key = upper(&r.archive).to_ascii_lowercase();

        let ev = r.run(Job::Store);
        let page = store_of(&ev);
        assert_eq!(page.rows.len(), 1);
        let row = &page.rows[0];
        assert_eq!(row.title.as_str(), "Fix pack");
        assert_eq!(row.ident.as_str(), "fix-pack 1.0");
        assert!(row.can_remove && row.note.is_none());
        assert_eq!(flat(&row.used), [w(Msg::PkNotUsed)]);
        assert_eq!(page.remove_all, Some(w(Msg::PkRemoveAllBtn)));

        // The dialog (reads only): the package, every file and its archive.
        let ev = r.run(Job::RemovePreview { pick: pick() });
        let d = dialog(&ev);
        assert_eq!(d.kind, DialogKind::Packages);
        assert!(d.can_confirm && d.changed.is_none());
        assert!(
            d.lists[0].lines[0]
                .flat()
                .starts_with("Fix pack \u{b7} fix-pack 1.0")
        );
        let files = &d.lists[1];
        assert!(files.fold.is_some());
        let files_lines = flat(&files.lines);
        assert!(files_lines.contains(&"packages\\fix-pack\\1.0\\bin\\fix.dll".to_owned()));
        assert!(files_lines.contains(&"packages\\fix-pack\\1.0\\fix.ini".to_owned()));
        assert!(
            files_lines.contains(&format!("cache\\{key}")),
            "{files_lines:?}"
        );
        let nonce = d.nonce;
        assert_eq!(r.listed("packages"), Some(vec!["fix-pack".to_owned()]));

        // Another dialog's nonce: nothing is removed, the dialog comes again with its note.
        let ev = r.run(Job::RemovePackages { nonce: nonce + 1 });
        let d = dialog(&ev);
        assert_eq!(d.changed, Some(w(Msg::PkDlgChanged)));
        assert!(d.nonce > nonce);
        assert_eq!(r.listed("packages"), Some(vec!["fix-pack".to_owned()]));
        assert_eq!(r.listed("cache"), Some(vec![key.clone()]));
        // The dialog it replaced cannot confirm any more.
        let ev = r.run(Job::RemovePackages { nonce });
        let nonce = dialog(&ev).nonce;
        assert_eq!(r.listed("packages"), Some(vec!["fix-pack".to_owned()]));

        // The fix card is read once more so the next read shows whether the cache is dropped.
        r.page();
        let reads = r.session.games.reads();
        let ev = r.run(Job::RemovePackages { nonce });
        let res = result(&ev);
        assert_eq!(res.tone, Tone::Done, "{ev:?}");
        assert_eq!(res.notice.title, w(Msg::PkDoneTitle));
        // The counts of what the dialog listed: one package and its archive.
        let want = w(Msg::PkDoneBody {
            packages: 1,
            archives: 1,
            leftovers: 0,
            bytes: 0,
        });
        assert_eq!(
            res.notice.body.split(", ").next(),
            want.split(", ").next(),
            "{}",
            res.notice.body
        );
        let page = store_of(&ev);
        assert!(page.rows.is_empty() && page.empty_title.is_some());
        assert_eq!(r.listed("packages"), Some(Vec::new()));
        assert_eq!(r.listed("cache"), Some(Vec::new()));
        // The same confirm again has nothing to confirm: the package is gone, the list again.
        let ev = r.run(Job::RemovePackages { nonce });
        assert_eq!(result(&ev).notice.title, w(Msg::PkGoneTitle), "{ev:?}");
        assert!(store_of(&ev).rows.is_empty());

        // The session forgot what it read of the games: the fix asks for the download again.
        let page = r.page();
        assert!(r.session.games.reads() > reads, "the files were read again");
        assert_eq!(page.fixes[0].offer, Offer::NeedsDownload);
    }
}

#[test]
fn as2_a_package_a_change_uses_stays_until_the_change_is_undone() {
    for lang in Lang::ALL {
        let w = |m| t(lang, m).into_owned();
        let mut r = downloaded(lang);
        let before = r.snap();
        let txn = apply_fix(&mut r);

        let ev = r.run(Job::Store);
        let row = &store_of(&ev).rows[0];
        assert!(!row.can_remove);
        assert_eq!(row.keep, Some(w(Msg::PkKeepInUse)));
        assert_eq!(row.used.len(), 1);
        let used = flat(&row.used);
        assert!(
            used[0].starts_with(&format!("{} Invented P", w(Msg::PkUsedBy)))
                && used[0].contains(&w(Msg::ClearNumber { n: txn.seq() }))
                && used[0].ends_with(&w(Msg::StateApplied)),
            "{:?}",
            used
        );

        // The dialog for the one package, and the one for everything unused: no confirm.
        for p in [pick(), flow::Pick::Unused] {
            let ev = r.run(Job::RemovePreview { pick: p.clone() });
            let d = dialog(&ev);
            assert!(!d.can_confirm, "{p:?}");
            assert_eq!(d.intro, w(Msg::PkDlgNothing));
            assert_eq!(d.lists.len(), 1);
            assert!(
                d.lists[0]
                    .lines
                    .iter()
                    .any(|l| l.name.as_ref().is_some_and(|n| n.as_str() == "Invented P"))
            );
            // A confirm that arrives anyway removes nothing.
            let ev = r.run(Job::RemovePackages { nonce: d.nonce });
            assert!(!dialog(&ev).can_confirm);
            assert_eq!(r.listed("packages"), Some(vec!["fix-pack".to_owned()]));
        }

        // Undone: the package may go, and the game folder is as before the apply.
        undo(&mut r, txn);
        assert!(r.snap() == before);
        let ev = r.run(Job::RemovePreview {
            pick: flow::Pick::Unused,
        });
        let d = dialog(&ev);
        assert!(d.can_confirm, "{ev:?}");
        let ev = r.run(Job::RemovePackages { nonce: d.nonce });
        assert_eq!(result(&ev).tone, Tone::Done, "{ev:?}");
        assert!(store_of(&ev).rows.is_empty());
        assert_eq!(r.listed("packages"), Some(Vec::new()));
        assert!(r.snap() == before, "the game folder is untouched");
    }
}

#[test]
fn as3_a_package_used_after_the_preview_is_not_removed() {
    for lang in Lang::ALL {
        let mut r = downloaded(lang);
        let ev = r.run(Job::RemovePreview { pick: pick() });
        let nonce = dialog(&ev).nonce;
        assert!(dialog(&ev).can_confirm);

        // Between the dialog and the click, another change uses it.
        apply_fix(&mut r);
        let ev = r.run(Job::RemovePackages { nonce });
        let d = dialog(&ev);
        assert_eq!(d.changed, Some(t(lang, Msg::PkDlgChanged).into_owned()));
        assert!(!d.can_confirm);
        assert_eq!(r.listed("packages"), Some(vec!["fix-pack".to_owned()]));
        assert!(
            !ev.iter().any(|e| matches!(e, Event::Result(_))),
            "the dialog again, no result: {ev:?}"
        );
    }
}

#[test]
fn as4_only_the_removal_is_a_write_job() {
    assert!(Job::RemovePackages { nonce: 1 }.writes());
    assert!(!Job::RemovePreview { pick: pick() }.writes());
    assert!(!Job::Store.writes());
}

#[test]
fn as5_an_empty_store_says_so_and_creates_nothing() {
    for lang in Lang::ALL {
        let mut r = rig(lang);
        let ev = r.run(Job::Store);
        let page = store_of(&ev);
        assert_eq!(page.empty_title, Some(t(lang, Msg::PkEmpty).into_owned()));
        assert!(page.remove_all.is_none());
        assert_eq!(r.listed("packages"), None);
        assert_eq!(r.listed("cache"), None);
        // A package that is not in the store (gone since the list): a calm result, the list again.
        let ev = r.run(Job::RemovePreview { pick: pick() });
        assert_eq!(
            result(&ev).notice.title,
            t(lang, Msg::PkGoneTitle).into_owned(),
            "{ev:?}"
        );
        assert!(matches!(ev.last(), Some(Event::Store(_))));
        assert_eq!(r.listed("packages"), None);
    }
}
