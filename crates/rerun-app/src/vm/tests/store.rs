//! Settings > Packages and its removal dialog (P5-8b-3), as view models on values built by hand,
//! in both languages.
//! - VP1 the page lists every package (name or ID, version, size, files, archives, state, who
//!   uses it with the game and the number), says so for a package the index no longer lists, and
//!   gives a package that is used or whose folder holds something Rerun does not remove a
//!   disabled button with the reason.
//! - VP2 the dialog lists every package that goes with its files behind a fold, downloads without
//!   a package, leftovers, and what stays with its reason and users; nothing to remove: no confirm.
//! - VP3 an empty store, and a store that cannot be read, say so (and the core's words).
//! - VP4 the result of a removal (counts, room, what stopped) and the refusals of the core.

use rerun_core::escape;
use rerun_core::exec::{Refusal, TxnLine};
use rerun_core::flow::{
    PackageKeep, RemovePreview, StoreGate, StoreView, StoredPackage, StoredState, UsedBy,
};
use rerun_core::journal::{JournalError, TxnId};
use rerun_core::pkg::store::{Removed, StoreError, StoreKeep};

use crate::text::{Lang, Msg, Sym, t};
use crate::vm::{
    DialogKind, Names, Tone, refusal, store, store_dialog, store_done, store_gate,
    store_unavailable,
};

fn id(seq: u32) -> TxnId {
    format!("{seq:08}-0123456789abcdef").parse().unwrap()
}

fn names() -> Names {
    let mut n = Names::new();
    n.insert(220, escape::text("Invented W").into_owned());
    n
}

fn package(id: &str, version: &str, name: Option<&str>) -> StoredPackage {
    StoredPackage {
        id: id.to_owned(),
        version: version.to_owned(),
        name: name.map(str::to_owned),
        in_index: name.is_some(),
        state: StoredState::Unpacked,
        files: 2,
        paths: vec!["bin\\fix.dll".to_owned(), "fix.ini".to_owned()],
        bytes: 1_500_000,
        archives: vec!["ab".repeat(32)],
        used_by: Vec::new(),
        keep: None,
    }
}

fn used(seq: u32, app: Option<u32>, line: TxnLine) -> UsedBy {
    UsedBy {
        txn: id(seq),
        app,
        line,
    }
}

fn view() -> StoreView {
    let mut busy = package("busy-pack", "2.0", Some("Busy pack"));
    busy.used_by = vec![
        used(12, Some(220), TxnLine::Applied),
        used(14, None, TxnLine::Open),
    ];
    busy.keep = Some(PackageKeep::InUse);
    let mut link = package("link-pack", "1.0", Some("Link pack"));
    link.keep = Some(PackageKeep::Store(StoreKeep::Reparse));
    let mut half = package("half-pack", "1.0", None);
    half.state = StoredState::Incomplete;
    StoreView {
        packages: vec![
            package("fix-pack", "1.0", Some("Fix pack")),
            busy,
            link,
            half,
        ],
        loose_archives: vec![("cd".repeat(32), 2048), ("ef".repeat(32), 1024)],
        leftovers: (2, 4096),
        foreign: vec![("packages\\stray".to_owned(), StoreKeep::BadName)],
    }
}

#[test]
fn vp1_the_page_lists_every_package_with_its_use_and_its_reason() {
    for lang in Lang::ALL {
        let vm = store(&view(), &names(), lang);
        let w = |m| t(lang, m).into_owned();
        assert_eq!(vm.rows.len(), 4);
        let r = &vm.rows[0];
        assert_eq!(r.title.as_str(), "Fix pack");
        assert_eq!(r.ident.as_str(), "fix-pack 1.0");
        assert_eq!((r.id.as_str(), r.version.as_str()), ("fix-pack", "1.0"));
        assert_eq!(
            r.facts,
            w(Msg::PkFacts {
                bytes: 1_500_000,
                files: 2,
                archives: 1
            })
        );
        assert_eq!(r.state.word, w(Msg::PkStateUnpacked));
        assert_eq!(r.used, [w(Msg::PkNotUsed)]);
        assert!(r.can_remove && r.keep.is_none() && r.note.is_none());

        // Used by two changes: the game, the number and the state of each; the button is off.
        let r = &vm.rows[1];
        assert!(!r.can_remove);
        assert_eq!(r.keep.as_deref(), Some(&*w(Msg::PkKeepInUse)));
        assert_eq!(
            r.used,
            [
                format!(
                    "{} Invented W \u{b7} {} \u{b7} {}",
                    w(Msg::PkUsedBy),
                    w(Msg::ClearNumber { n: 12 }),
                    w(Msg::StateApplied)
                ),
                format!(
                    "{} {} \u{b7} {}",
                    w(Msg::PkUsedBy),
                    w(Msg::ClearNumber { n: 14 }),
                    w(Msg::StateInterrupted)
                ),
            ]
        );
        // Something Rerun does not remove in its folder.
        assert!(!vm.rows[2].can_remove);
        assert_eq!(vm.rows[2].keep.as_deref(), Some(&*w(Msg::PkKeepReparse)));
        // Not in the index: the ID is the title, and it says it cannot be downloaded again; an
        // incomplete package has a symbol and a word.
        let r = &vm.rows[3];
        assert_eq!(r.title.as_str(), "half-pack");
        assert_eq!(r.note.as_deref(), Some(&*w(Msg::PkNotInIndex)));
        assert_eq!(r.state.word, w(Msg::PkStateIncomplete));
        assert_eq!(r.state.sym, Sym::Attention);
        assert!(r.can_remove);

        assert_eq!(
            vm.extra,
            [
                w(Msg::PkLoose { n: 2, bytes: 3072 }),
                w(Msg::PkLeftovers { n: 2, bytes: 4096 })
            ]
        );
        assert_eq!(vm.foreign_heading, Some(w(Msg::PkForeignHeading { n: 1 })));
        assert_eq!(
            vm.foreign,
            [format!("packages\\stray: {}", w(Msg::PkKeepBadName))]
        );
        assert_eq!(vm.remove_all, Some(w(Msg::PkRemoveAllBtn)));
        assert!(vm.can_remove_all);
        assert_eq!(vm.remove, w(Msg::PkRemoveBtn));
        assert!(vm.empty_title.is_none());
    }
}

#[test]
fn vp1_remove_all_is_off_when_every_package_stays() {
    let mut v = view();
    v.packages.retain(|p| p.keep.is_some());
    v.loose_archives.clear();
    v.leftovers = (0, 0);
    let vm = store(&v, &names(), Lang::En);
    assert!(vm.remove_all.is_some() && !vm.can_remove_all);
}

#[test]
fn vp1_names_from_the_index_are_escaped() {
    let mut v = view();
    v.packages[0].name = Some("Fix\u{202e}pack".to_owned());
    let vm = store(&v, &names(), Lang::En);
    assert!(!vm.rows[0].title.as_str().contains('\u{202e}'));
}

fn preview() -> RemovePreview {
    let mut shared = package("half-pack", "1.0", None);
    shared.archives.clear();
    let mut busy = package("busy-pack", "2.0", Some("Busy pack"));
    busy.paths.clear();
    busy.used_by = vec![used(12, Some(220), TxnLine::Applied)];
    busy.keep = Some(PackageKeep::InUse);
    let mut shares = package("share-pack", "1.0", Some("Share pack"));
    shares.keep = Some(PackageKeep::SharedArchive);
    RemovePreview {
        remove: vec![package("fix-pack", "1.0", Some("Fix pack")), shared],
        loose_archives: vec![("cd".repeat(32), 2048)],
        leftovers: (2, 4096),
        stays: vec![busy, shares],
        bytes: 14_300_000,
    }
}

#[test]
fn vp2_the_dialog_lists_what_goes_with_its_files_and_what_stays_with_its_reason() {
    for lang in Lang::ALL {
        let w = |m| t(lang, m).into_owned();
        let d = store_dialog(&preview(), &names(), false, 7, lang);
        assert_eq!(d.kind, DialogKind::Packages);
        assert_eq!((d.nonce, d.txn), (7, None));
        assert_eq!(d.title, w(Msg::PkDlgTitle));
        assert_eq!(d.confirm, w(Msg::PkDlgTitle));
        assert_eq!(d.intro, w(Msg::PkDlgIntro));
        assert!(d.can_confirm && d.changed.is_none());

        // Heading, then the package lines, then each package's files behind a fold, then the
        // downloads without a package and what stays.
        let headings: Vec<&str> = d.lists.iter().map(|l| l.heading.as_str()).collect();
        assert_eq!(
            headings,
            [
                w(Msg::PkDlgGoesHeading { n: 2 }).as_str(),
                "Fix pack 1.0",
                "half-pack 1.0",
                w(Msg::PkDlgLooseHeading { n: 1 }).as_str(),
                w(Msg::ClearStaysHeading { n: 2 }).as_str(),
            ]
        );
        let goes = &d.lists[0];
        assert!(goes.fold.is_none());
        assert_eq!(goes.lines.len(), 2);
        assert!(
            goes.lines[0].starts_with("Fix pack \u{b7} fix-pack 1.0 \u{b7} "),
            "{:?}",
            goes.lines[0]
        );
        // A package the index does not list says it cannot be downloaded again.
        assert!(
            goes.lines[1].ends_with(&w(Msg::PkNotInIndex)),
            "{:?}",
            goes.lines[1]
        );
        assert!(!goes.lines[0].contains(&w(Msg::PkNotInIndex)));

        // Every file and the archive, folded away behind a button.
        let files = &d.lists[1];
        assert_eq!(
            files.fold,
            Some((w(Msg::PkDlgFilesShow { n: 3 }), w(Msg::PkDlgFilesHide)))
        );
        assert_eq!(
            files.lines,
            [
                "packages\\fix-pack\\1.0\\bin\\fix.dll".to_owned(),
                "packages\\fix-pack\\1.0\\fix.ini".to_owned(),
                format!("cache\\{}", "ab".repeat(32)),
            ]
        );
        // A package that is only its files has no archive line.
        assert_eq!(d.lists[2].lines.len(), 2);
        assert_eq!(d.lists[3].lines, [format!("cache\\{}", "cd".repeat(32))]);

        let stays = &d.lists[4];
        assert_eq!(stays.lines.len(), 3, "{:?}", stays.lines);
        assert!(stays.lines[0].starts_with("Busy pack \u{b7} busy-pack 2.0."));
        assert!(stays.lines[0].ends_with(&w(Msg::PkKeepInUse)));
        assert!(stays.lines[1].contains("Invented W"), "{:?}", stays.lines);
        assert!(stays.lines[2].ends_with(&w(Msg::PkKeepShared)));

        assert_eq!(
            d.notes,
            [
                w(Msg::PkDlgLeftovers { n: 2, bytes: 4096 }),
                w(Msg::PkDlgFreed { bytes: 14_300_000 }),
                w(Msg::PkDlgUnchanged),
            ]
        );

        // The store changed since the dialog the user looked at.
        let d = store_dialog(&preview(), &names(), true, 8, lang);
        assert_eq!(d.changed, Some(w(Msg::PkDlgChanged)));
    }
}

#[test]
fn vp2_a_package_that_stays_has_a_dialog_without_a_confirm() {
    for lang in Lang::ALL {
        let mut p = preview();
        p.remove.clear();
        p.loose_archives.clear();
        p.leftovers = (0, 0);
        p.bytes = 0;
        let d = store_dialog(&p, &names(), false, 3, lang);
        assert!(!d.can_confirm);
        assert_eq!(d.intro, t(lang, Msg::PkDlgNothing));
        assert_eq!(d.lists.len(), 1, "only what stays");
        assert!(
            d.notes
                .iter()
                .all(|n| *n != t(lang, Msg::PkDlgFreed { bytes: 0 }))
        );
    }
}

#[test]
fn vp3_an_empty_store_and_an_unreadable_one_say_so() {
    for lang in Lang::ALL {
        let empty = StoreView {
            packages: Vec::new(),
            loose_archives: Vec::new(),
            leftovers: (0, 0),
            foreign: Vec::new(),
        };
        let vm = store(&empty, &names(), lang);
        assert_eq!(vm.empty_title, Some(t(lang, Msg::PkEmpty).into_owned()));
        assert!(vm.remove_all.is_none() && vm.rows.is_empty());

        let vm = store_unavailable(&StoreGate::NoAppDir, lang);
        assert_eq!(vm.empty_title, Some(t(lang, Msg::PkEmpty).into_owned()));
        assert!(vm.detail.is_none());

        let vm = store_unavailable(&StoreGate::Store(StoreError::Elevated), lang);
        assert_eq!(
            vm.empty_title,
            Some(t(lang, Msg::PkUnreadableTitle).into_owned())
        );
        assert_eq!(
            vm.empty_sub,
            Some(t(lang, Msg::PkUnreadableBody).into_owned())
        );
        assert!(vm.detail.is_some() && vm.remove_all.is_none());
    }
}

#[test]
fn vp3_the_gates_of_the_dialog_are_calm_results() {
    for lang in Lang::ALL {
        let r = store_gate(&StoreGate::NotFound, lang);
        assert_eq!(r.notice.title, t(lang, Msg::PkGoneTitle));
        let r = store_gate(&StoreGate::NoAppDir, lang);
        assert_eq!(r.notice.title, t(lang, Msg::RefNothingTitle));
        let r = store_gate(&StoreGate::Journal(JournalError::Busy), lang);
        assert_eq!(r.tone, Tone::Attention);
        assert_eq!(r.notice.details.len(), 1, "the core's words");
    }
}

#[test]
fn vp4_a_removal_says_how_much_went_and_what_stopped() {
    for lang in Lang::ALL {
        let w = |m| t(lang, m).into_owned();
        let removed = Removed {
            packages: vec![
                ("fix-pack".to_owned(), "1.0".to_owned()),
                ("half-pack".to_owned(), "1.0".to_owned()),
            ],
            archives: 1,
            leftovers: 0,
            bytes: 14_300_000,
            gone: 0,
            stopped: Vec::new(),
        };
        let r = store_done(&removed, lang);
        assert_eq!(r.tone, Tone::Done);
        assert_eq!(r.notice.title, w(Msg::PkDoneTitle));
        assert_eq!(
            r.notice.body,
            w(Msg::PkDoneBody {
                packages: 2,
                archives: 1,
                leftovers: 0,
                bytes: 14_300_000
            })
        );
        assert!(r.notice.details.is_empty() && !r.refresh);

        // A file a scanner holds stops its package: calm, with the name and the reason.
        let removed = Removed {
            stopped: vec![("busy-pack@2.0".to_owned(), StoreKeep::Busy)],
            ..removed
        };
        let r = store_done(&removed, lang);
        assert_eq!(r.tone, Tone::Calm);
        assert_eq!(r.notice.details.len(), 2);
        assert_eq!(
            r.notice.details[1].who.as_ref().unwrap().as_str(),
            "busy-pack@2.0"
        );
        assert_eq!(r.notice.details[1].what.as_str(), w(Msg::PkKeepBusy));

        let r = store_done(&Removed::default(), lang);
        assert_eq!(r.notice.body, w(Msg::PkDoneNothing));
    }
    // The sentences: the empty counts are left out, the last part follows "and".
    assert_eq!(
        t(
            Lang::En,
            Msg::PkDoneBody {
                packages: 2,
                archives: 1,
                leftovers: 0,
                bytes: 14_300_000
            }
        ),
        "2 packages and 1 archive removed, 13.6 MB freed."
    );
    assert_eq!(
        t(
            Lang::De,
            Msg::PkDoneBody {
                packages: 2,
                archives: 1,
                leftovers: 3,
                bytes: 1_500_000
            }
        ),
        "2 Pakete, 1 Archiv und 3 Reste entfernt, 1,4 MB frei."
    );
}

#[test]
fn vp4_every_refusal_of_a_removal_is_a_calm_message() {
    for lang in Lang::ALL {
        let w = |m| t(lang, m).into_owned();
        let r = refusal(
            &Refusal::PackageInUse {
                package: escape::text("fix-pack@1.0").into_owned(),
                txn: id(12),
            },
            lang,
        );
        assert_eq!(r.notice.title, w(Msg::RefPkInUseTitle));
        assert_eq!(r.tone, Tone::Attention);
        assert!(
            !r.notice.details.is_empty(),
            "the core's words stand under it"
        );
        let r = refusal(&Refusal::StoreChanged, lang);
        assert_eq!(r.notice.title, w(Msg::RefPkChangedTitle));
        let r = refusal(&Refusal::StoreBusy, lang);
        assert_eq!(r.notice.title, w(Msg::RefPkBusyTitle));
        assert_eq!(r.tone, Tone::Calm);
    }
}
