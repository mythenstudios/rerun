//! The history and the last start (P5-6a, ADR 0027 amendment P5-6a), as view models on values
//! built by hand, in both languages.
//! - VV1 every state of the journal lands in its group with its symbol and word, newest first.
//! - VV2 every skip reason, start, end and check has words; the notes; unreadable files and
//!   folders.
//! - VV3 the game page's "Last start" by the game's profile ID.

use rerun_core::escape::{self, Shown};
use rerun_core::exec::launch_result::{
    AppliedCpu, Check, Ended, LaunchResult, Mode, Outcome, Priority, ProfileId, SkipReason, Start,
};
use rerun_core::exec::{LaunchEntry, LaunchResults, OpState, OpStatus, Status, TxnLine, TxnStatus};
use rerun_core::flow::{Holder, JournalView};
use rerun_core::journal::{Closing, Damage, TxnId};
use rerun_core::plan::profile_id;
use rerun_core::prim::launch_method::ProfileMethod;

use crate::text::{Lang, Msg, Sym, t};
use crate::vm::{
    HISTORY_PAGE, HistGroup, HistoryVm, LaunchRowVm, Names, Value, ago, history, last_launch, utc,
};

fn id(seq: u32) -> TxnId {
    format!("{seq:08}-0123456789abcdef").parse().unwrap()
}

fn st(seq: u32, state: TxnLine, forgotten: bool, cleanup: &[&str]) -> TxnStatus {
    TxnStatus {
        id: id(seq),
        state,
        forgotten,
        folder: escape::path(&format!(r"C:\R\journal\{}", id(seq))).into_owned(),
        preview: None,
        ops: vec![OpStatus {
            op: 0,
            state: OpState::Applied,
            backup: None,
            cleanup: cleanup
                .iter()
                .map(|c| escape::path(c).into_owned())
                .collect(),
        }],
        rebinds: Vec::new(),
        shares: Vec::new(),
        shares_error: None,
    }
}

fn view(txns: Vec<TxnStatus>, launch: Option<LaunchResults>, holders: Vec<Holder>) -> JournalView {
    JournalView {
        status: Status {
            txns,
            foreign_entries: 0,
        },
        launch: Ok(launch),
        holders,
    }
}

fn page(v: &JournalView, lang: Lang) -> HistoryVm {
    history(Some(Ok(v)), &Names::new(), 2_000_000_000, lang)
}

#[test]
fn vv1_every_state_lands_in_its_group() {
    let holder = Holder {
        id: profile_id(1),
        txn: id(6),
        forgotten: true,
        launcher: None,
        watch: None,
    };
    let v = view(
        vec![
            st(1, TxnLine::Applied, false, &[]),
            st(2, TxnLine::Open, false, &[]),
            st(3, TxnLine::CleanupPending, false, &[r"game\x.dll.old"]),
            st(4, TxnLine::Damaged(Damage::HeadMissing), false, &[]),
            st(
                5,
                TxnLine::Unreadable(escape::text("bad").into_owned()),
                false,
                &[],
            ),
            st(
                6,
                TxnLine::Closed(Closing::Forgotten),
                false,
                &[r"game\y.dll.old"],
            ),
            st(7, TxnLine::Applied, true, &[]),
            st(8, TxnLine::Closed(Closing::Reverted), false, &[]),
            st(9, TxnLine::Closed(Closing::RolledBack), false, &[]),
            st(10, TxnLine::Empty, false, &[]),
        ],
        None,
        vec![holder],
    );
    for lang in Lang::ALL {
        let h = page(&v, lang);
        let kinds: Vec<HistGroup> = h.groups.iter().map(|g| g.kind).collect();
        assert_eq!(
            kinds,
            [
                HistGroup::Open,
                HistGroup::Reverted,
                HistGroup::RolledBack,
                HistGroup::Forgotten
            ]
        );
        assert!(h.empty.is_none() && h.launch_title.is_none());
        let seqs =
            |g: usize| -> Vec<u32> { h.groups[g].entries.iter().map(|e| e.txn.seq()).collect() };
        // Newest first inside a group; the open group holds everything not settled.
        assert_eq!(seqs(0), [5, 4, 3, 2, 1]);
        assert_eq!((seqs(1), seqs(2), seqs(3)), (vec![8], vec![9], vec![7, 6]));
        let word = |g: usize, i: usize| {
            let e = &h.groups[g].entries[i];
            (e.state.sym, e.state.word.clone())
        };
        let w = |m| t(lang, m).into_owned();
        assert_eq!(word(0, 4), (Sym::Applied, w(Msg::StateApplied)));
        assert_eq!(word(0, 3), (Sym::Attention, w(Msg::StateInterrupted)));
        assert_eq!(word(0, 2), (Sym::Attention, w(Msg::StateCleanup)));
        assert_eq!(word(0, 1), (Sym::Attention, w(Msg::StateDamaged)));
        assert_eq!(word(0, 0), (Sym::Attention, w(Msg::StateUnreadable)));
        assert_eq!(word(1, 0), (Sym::None, w(Msg::HistStateReverted)));
        assert_eq!(word(2, 0), (Sym::None, w(Msg::HistStateRolledBack)));
        assert_eq!(word(3, 0), (Sym::Unconfirmed, w(Msg::HistStateForgotten)));
        // The empty transaction (10) is in no group: the view leaves it out (P5-6d-0).
        assert_eq!(h.groups.iter().map(|g| g.count).sum::<usize>(), 9);
        // A forgotten one (by a record, or by a marker) says where its backups stay.
        for e in &h.groups[3].entries {
            assert_eq!(
                e.backups.as_ref().map(Shown::as_str),
                Some(&*format!(r"C:\R\journal\{}", e.txn))
            );
        }
        assert_eq!(
            h.groups[3].entries[1].may_remain[0].as_str(),
            r"game\y.dll.old"
        );
        // Only the forgotten one that still holds a profile says so.
        assert_eq!(
            h.groups[3].entries[1].note.as_deref(),
            Some(&*w(Msg::HolderForgotten))
        );
        assert!(h.groups[3].entries[0].note.is_none());
        assert!(h.groups[1].entries[0].backups.is_none());
    }
    // No Rerun folder: nothing yet; an unreadable journal: said, with the core's text.
    let none = history(None, &Names::new(), 0, Lang::En);
    assert_eq!(
        none.empty.as_ref().map(|e| e.0.as_str()),
        Some("Nothing in the journal yet")
    );
    let err = rerun_core::journal::JournalError::NotFound(id(1));
    let bad = history(Some(Err(&err)), &Names::new(), 0, Lang::En);
    assert_eq!(
        bad.empty.as_ref().map(|e| e.0.as_str()),
        Some("The journal could not be read.")
    );
    assert!(bad.detail.is_some() && bad.groups.is_empty());
    // An empty journal says so too.
    assert!(
        page(&view(Vec::new(), None, Vec::new()), Lang::En)
            .empty
            .is_some()
    );
}

fn entry(file: ProfileId, outcome: Outcome, method: Option<ProfileMethod>) -> LaunchEntry {
    LaunchEntry {
        id: file,
        result: Ok(LaunchResult {
            profile: file,
            unix_s: 1_762_600_000,
            outcome,
            method,
        }),
    }
}

fn view_launch(launch: Option<LaunchResults>, holders: Vec<Holder>) -> JournalView {
    view(Vec::new(), launch, holders)
}

fn self_rows(entries: Vec<LaunchEntry>, holders: Vec<Holder>, lang: Lang) -> Vec<LaunchRowVm> {
    let v = view_launch(Some(LaunchResults { entries, other: 0 }), holders);
    history(Some(Ok(&v)), &Names::new(), 1_762_600_000 + 7_200, lang).launches
}

const REASONS: [SkipReason; 24] = [
    SkipReason::ProfileMissing,
    SkipReason::ProfileUnreadable { code: 5 },
    SkipReason::ProfileReparsePoint,
    SkipReason::ProfileNotAFile,
    SkipReason::ProfileInvalid,
    SkipReason::MethodUnsupported,
    SkipReason::PathMismatch,
    SkipReason::TopologyUnavailable,
    SkipReason::TopologyInvalid,
    SkipReason::SelectionEmpty,
    SkipReason::MaskTooWide,
    SkipReason::SpawnFailed { code: 5 },
    SkipReason::JobFailed { code: 5 },
    SkipReason::ReadBackFailed { code: 5 },
    SkipReason::Mismatch,
    SkipReason::CpuSetsFailed { code: 5 },
    SkipReason::ResumeFailed { code: 5 },
    SkipReason::ElevationRequired,
    SkipReason::TargetNotFound,
    SkipReason::JobIneffective,
    SkipReason::TargetElevated,
    SkipReason::TargetDenied { code: 5 },
    SkipReason::SearchFailed { code: 5 },
    SkipReason::PriorityFailed { code: 5 },
];

/// A closed entry whose plan cannot be read says why, escaped, instead of an empty entry; the
/// exact-time formatter keeps the bound of the CLI's `Utc` (rerun-cli `txn/launch_tests.rs`).
#[test]
fn vv1_an_unreadable_plan_says_why_and_utc_keeps_its_bound() {
    let mut bad = st(1, TxnLine::Closed(Closing::Reverted), false, &[]);
    bad.preview = Some(Err(escape::text("head.json \u{202e} damaged").into_owned()));
    let h = page(&view(vec![bad], None, Vec::new()), Lang::En);
    let e = &h.groups[0].entries[0];
    assert_eq!(
        e.problem.as_deref(),
        Some("Its plan cannot be read, so what it changed cannot be listed.")
    );
    let d = e.detail.as_ref().unwrap().as_str();
    assert!(d.contains("damaged") && !d.contains('\u{202e}'), "{d}");
    assert!(e.ops.is_empty());

    assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
    assert_eq!(utc(4_107_542_400), "2100-03-01 00:00:00 UTC");
    assert_eq!(utc(253_402_300_799), "9999-12-31 23:59:59 UTC");
    assert_eq!(utc(253_402_300_800), "253402300800 s");
    assert_eq!(utc(u64::MAX), "18446744073709551615 s");
}

#[test]
fn vv2_every_reason_and_check_has_words() {
    let hard = Some(AppliedCpu {
        mode: Mode::Hard,
        threads: 8,
        of: 32,
    });
    let starts = [
        Start::Created,
        Start::Shell,
        Start::ShellNoProcess,
        Start::NotExe,
        Start::Failed { code: 5 },
    ];
    let ends = [
        None,
        Some(Ended::Ended),
        Some(Ended::Failed { code: 5 }),
        Some(Ended::NotConfirmed { code: 258 }),
    ];
    let checks = [
        Check::Ok,
        Check::Narrowed,
        Check::Reset {
            cpu: true,
            priority: true,
        },
        Check::Reset {
            cpu: true,
            priority: false,
        },
        Check::Reset {
            cpu: false,
            priority: true,
        },
        Check::ExitedEarly,
        Check::Failed { code: 5 },
    ];
    for lang in Lang::ALL {
        // Profile IDs are 16 bytes: a counter in the first two.
        let mut n = 0u16;
        let mut next = || {
            n += 1;
            let mut b = [0u8; 16];
            b[..2].copy_from_slice(&n.to_le_bytes());
            ProfileId(b)
        };
        let mut entries = Vec::new();
        for reason in &REASONS {
            for start in starts {
                for ended in ends {
                    entries.push(entry(
                        next(),
                        Outcome::Skipped {
                            reason: *reason,
                            start,
                            ended,
                            priority_restore: None,
                        },
                        None,
                    ));
                }
            }
        }
        for check in checks {
            for method in [
                None,
                Some(ProfileMethod::Direct),
                Some(ProfileMethod::Watch),
            ] {
                entries.push(entry(
                    next(),
                    Outcome::Applied {
                        cpu: hard,
                        priority: Some(Priority::High),
                        check,
                    },
                    method,
                ));
            }
        }
        let rows = self_rows(entries, Vec::new(), lang);
        let mut lines = std::collections::BTreeSet::new();
        for r in &rows {
            assert!(
                !r.line.trim().is_empty() && !r.line.contains('!'),
                "{lang:?}: {}",
                r.line
            );
            assert_eq!(r.exact.as_deref(), Some("2025-11-08 11:06:40 UTC"), "{r:?}");
            assert!(r.game_is_id, "{r:?}");
            if lang == Lang::De {
                assert!(!r.line.contains('\u{df}'), "{}", r.line);
            }
            lines.insert(r.line.clone());
        }
        // Every reason x start x end says another line (`shell` and `shell_no_process` say the
        // same).
        assert!(
            lines.len() >= REASONS.len() * (starts.len() - 1) * ends.len(),
            "{lang:?}: {}",
            lines.len()
        );
        // A skip is quiet and a dash; an applied rule is a filled square.
        let skipped = rows.iter().find(|r| r.outcome.sym == Sym::NotHere).unwrap();
        assert!(skipped.outcome.quiet);
        assert!(
            rows.iter()
                .any(|r| r.outcome.sym == Sym::Applied && !r.outcome.quiet)
        );
        assert!(rows.iter().any(|r| r.outcome.sym == Sym::Attention));
        assert!(rows.iter().any(|r| r.outcome.sym == Sym::Unknown));
    }
    // Relative time, both languages; the exact time is UTC.
    assert_eq!(ago(1_000, 1_000, Lang::En), "just now");
    assert_eq!(ago(1_000, 1_100, Lang::En), "just now");
    assert_eq!(ago(10_000, 10_000 - 120, Lang::En), "2 minutes ago");
    assert_eq!(ago(100_000, 100_000 - 7_200, Lang::En), "2 hours ago");
    assert_eq!(
        ago(10_000_000, 10_000_000 - 3 * 86_400, Lang::De),
        "vor 3 Tagen"
    );
    assert_eq!(utc(1_762_600_000), "2025-11-08 11:06:40 UTC");
}

#[test]
fn vv2_notes_unreadable_files_and_folders() {
    let applied = |check| Outcome::Applied {
        cpu: None,
        priority: None,
        check,
    };
    let missing = Outcome::Skipped {
        reason: SkipReason::ProfileMissing,
        start: Start::Created,
        ended: None,
        priority_restore: None,
    };
    let hold = |i: u32, forgotten, launcher: bool, watch: bool| Holder {
        id: profile_id(i),
        txn: id(i),
        forgotten,
        launcher: launcher.then(|| escape::path(r"D:\G\launcher.exe").into_owned()),
        watch: watch.then(|| escape::path("D:\\G\\evil\u{202e}.exe").into_owned()),
    };
    let entries = vec![
        entry(profile_id(1), missing.clone(), None),
        entry(profile_id(2), missing.clone(), None),
        entry(profile_id(3), missing, None),
        entry(
            profile_id(4),
            applied(Check::Ok),
            Some(ProfileMethod::Direct),
        ),
        entry(
            profile_id(5),
            applied(Check::Ok),
            Some(ProfileMethod::Watch),
        ),
        entry(
            profile_id(6),
            Outcome::Skipped {
                reason: SkipReason::JobFailed { code: 5 },
                start: Start::Created,
                ended: None,
                priority_restore: Some(5),
            },
            Some(ProfileMethod::Watch),
        ),
        LaunchEntry {
            id: profile_id(7),
            result: Err(escape::text("line 2: bad").into_owned()),
        },
    ];
    let holders = vec![
        hold(2, false, false, false),
        hold(3, true, false, false),
        hold(4, false, true, false),
        hold(5, false, false, true),
    ];
    let rows = self_rows(entries, holders, Lang::En);
    let by = |i: u32| {
        rows.iter()
            .find(|r| r.game.as_str().ends_with(&profile_id(i).to_string()))
            .unwrap()
    };
    let note = |i: u32| by(i).note.clone().unwrap_or_default();
    assert!(note(1).contains("remove the option in Steam"));
    assert!(!note(1).contains("holds this profile"));
    assert!(note(2).contains(&format!("Change {} holds this profile now", id(2))));
    // A held profile is needed by a reapplied fix: no advice to remove the option.
    assert!(!note(2).contains("remove"), "{}", note(2));
    let de = self_rows(
        vec![entry(
            profile_id(2),
            Outcome::Skipped {
                reason: SkipReason::ProfileMissing,
                start: Start::Created,
                ended: None,
                priority_restore: None,
            },
            None,
        )],
        vec![hold(2, false, false, false)],
        Lang::De,
    );
    let held_de = de[0].note.clone().unwrap();
    assert!(
        held_de.contains(&id(2).to_string()) && !held_de.contains("entfern"),
        "{held_de}"
    );
    assert!(note(1).contains("remove the option"));
    assert!(note(3).contains("closed without undoing it left a profile"));
    assert!(note(4).contains("check covered the launcher"));
    assert_eq!(
        by(4).detail.as_ref().map(Shown::as_str),
        Some(r"D:\G\launcher.exe")
    );
    assert!(note(5).contains("Method watch"));
    // The target is untrusted: escaped, never a bidi control.
    assert!(!by(5).detail.as_ref().unwrap().as_str().contains('\u{202e}'));
    assert!(note(6).contains("could not be put back (Windows error 5)"));
    // A file that cannot be read: a row at the end with the core's text, no time.
    let last = rows.last().unwrap();
    assert!(last.game.as_str().ends_with(&profile_id(7).to_string()));
    assert_eq!(
        (last.outcome.word.as_str(), last.exact.is_none()),
        ("Unreadable", true)
    );
    assert_eq!(last.detail.as_ref().map(Shown::as_str), Some("line 2: bad"));
    // The folder cannot be read, or holds other entries.
    let mut v = view_launch(None, Vec::new());
    v.launch = Err(rerun_core::policy::root::RootError::Sys(
        rerun_core::sys::SysError::new(rerun_core::sys::SysErrorKind::Other, "launch: denied"),
    ));
    let h = page(&v, Lang::En);
    assert_eq!(
        h.launch_note.as_deref(),
        Some("The launch results cannot be read.")
    );
    assert!(h.launch_detail.is_some() && h.empty.is_none());
    let v = view_launch(
        Some(LaunchResults {
            entries: Vec::new(),
            other: 2,
        }),
        Vec::new(),
    );
    let h = page(&v, Lang::De);
    assert_eq!(
        h.launch_note.as_deref(),
        Some("2 andere Einträge im Startordner, nicht von Rerun (nicht gelesen)")
    );
}

#[test]
fn vv3_the_last_start_of_a_game_by_its_profile() {
    let skipped = Outcome::Skipped {
        reason: SkipReason::ProfileMissing,
        start: Start::Created,
        ended: None,
        priority_restore: None,
    };
    let results = LaunchResults {
        entries: vec![
            entry(
                profile_id(220),
                Outcome::Applied {
                    cpu: None,
                    priority: Some(Priority::High),
                    check: Check::Ok,
                },
                Some(ProfileMethod::Direct),
            ),
            entry(profile_id(230), skipped, None),
        ],
        other: 0,
    };
    let lines = rerun_core::flow::launch_lines(&results, &[]);
    let now = 1_762_600_000 + 2 * 3_600 + 5;
    let l = rerun_core::flow::launch_of(&lines, 220).unwrap();
    let (fact, notes) = last_launch(l, now, Lang::En).unwrap();
    assert_eq!(fact.label, "Last start");
    assert_eq!(
        fact.value,
        Value::Text("2 hours ago \u{b7} Rule applied".to_owned())
    );
    assert!(notes.is_empty());
    let l = rerun_core::flow::launch_of(&lines, 230).unwrap();
    let (fact, notes) = last_launch(l, now, Lang::De).unwrap();
    assert_eq!(fact.label, "Letzter Start");
    assert_eq!(
        fact.value.as_str(),
        "vor 2 Stunden \u{b7} Regel nicht angewendet"
    );
    assert_eq!(notes.len(), 1, "the option is still set");
    assert!(rerun_core::flow::launch_of(&lines, 999).is_none());
    // In the history the library's name labels the row.
    let mut names = Names::new();
    names.insert(220, escape::text("Invented W").into_owned());
    let v = view_launch(
        Some(LaunchResults {
            entries: vec![entry(
                profile_id(220),
                Outcome::Applied {
                    cpu: None,
                    priority: None,
                    check: Check::Ok,
                },
                None,
            )],
            other: 0,
        }),
        Vec::new(),
    );
    let h = history(Some(Ok(&v)), &names, 1_762_600_000, Lang::En);
    assert_eq!(
        h.launches[0].game,
        Value::Shown(escape::text("Invented W").into_owned())
    );
    assert!(!h.launches[0].game_is_id);
}

/// VH1 (P5-6d-0) the tidy view: the open group is first and always shown in full, the closed
/// groups start collapsed with their numbers, expanded they show the newest page and "Show older"
/// reveals the next one, the empty transactions are in no group, the session's reveal is plain
/// data (nothing is stored), and German has its own words.
#[test]
fn vh1_closed_groups_are_collapsed_counted_and_paged() {
    use crate::vm::{group_view, initial_reveal, revealed_more, toggled};
    // 2 open, 45 undone, 3 rolled back, 5 forgotten, 4 empty: interleaved by number.
    let mut txns = Vec::new();
    for seq in 1..=59u32 {
        let state = match seq {
            1..=2 => TxnLine::Applied,
            3..=47 => TxnLine::Closed(Closing::Reverted),
            48..=50 => TxnLine::Closed(Closing::RolledBack),
            51..=55 => TxnLine::Closed(Closing::Forgotten),
            _ => TxnLine::Empty,
        };
        txns.push(st(seq, state, false, &[]));
    }
    let v = view(txns, None, Vec::new());
    for lang in Lang::ALL {
        let h = page(&v, lang);
        // Open first, then the closed groups; the empty ones are nowhere.
        let kinds: Vec<(HistGroup, usize)> = h.groups.iter().map(|g| (g.kind, g.count)).collect();
        assert_eq!(
            kinds,
            [
                (HistGroup::Open, 2),
                (HistGroup::Reverted, 45),
                (HistGroup::RolledBack, 3),
                (HistGroup::Forgotten, 5)
            ]
        );
        assert_eq!(h.groups.iter().map(|g| g.entries.len()).sum::<usize>(), 55);
        // The numbers are in the headings.
        assert_eq!(h.groups[1].heading, format!("{} (45)", h.groups[1].title));
        // The open group: not collapsible, all entries, no button, its sentence.
        let open = group_view(&h.groups[0], initial_reveal(HistGroup::Open), lang);
        assert!(
            open.expanded && !open.collapsible && open.toggle.is_empty() && open.more.is_none()
        );
        assert_eq!(open.entries.len(), 2);
        assert!(open.hint.is_some());
        // A closed group starts collapsed: no entries, no sentence, no older button, the "Show"
        // button, and the number is still there.
        let closed = group_view(&h.groups[1], initial_reveal(HistGroup::Reverted), lang);
        assert!(!closed.expanded && closed.collapsible);
        assert!(closed.entries.is_empty() && closed.more.is_none());
        assert_eq!(closed.toggle, t(lang, Msg::HistShowGroup));
        assert_eq!(closed.heading, h.groups[1].heading);
        // Expanded: the newest page, newest first, and the button says how many are not shown.
        let r = toggled(initial_reveal(HistGroup::Reverted));
        assert_eq!(r, Some(HISTORY_PAGE));
        let page1 = group_view(&h.groups[1], r, lang);
        assert!(page1.expanded);
        assert_eq!(page1.toggle, t(lang, Msg::HistHideGroup));
        let seqs: Vec<u32> = page1.entries.iter().map(|e| e.txn.seq()).collect();
        assert_eq!(seqs.len(), HISTORY_PAGE);
        assert_eq!(seqs[0], 47, "newest first");
        assert_eq!(seqs[HISTORY_PAGE - 1], 28, "the 20th newest of 3..=47");
        assert_eq!(
            page1.more,
            Some(t(lang, Msg::HistShowOlder { n: 25 }).into_owned())
        );
        // Show older: the next page, then the rest, then no button.
        let r2 = revealed_more(r);
        let page2 = group_view(&h.groups[1], r2, lang);
        assert_eq!(page2.entries.len(), 2 * HISTORY_PAGE);
        assert_eq!(
            page2.more,
            Some(t(lang, Msg::HistShowOlder { n: 5 }).into_owned())
        );
        let page3 = group_view(&h.groups[1], revealed_more(r2), lang);
        assert_eq!(page3.entries.len(), 45);
        assert!(page3.more.is_none(), "everything is shown");
        assert_eq!(page3.entries.last().map(|e| e.txn.seq()), Some(3));
        // A group of a few: expanded shows all of it and no older button; hidden again.
        let few = group_view(&h.groups[2], toggled(None), lang);
        assert_eq!((few.entries.len(), few.more.is_none()), (3, true));
        assert!(
            group_view(&h.groups[2], toggled(toggled(None)), lang)
                .entries
                .is_empty()
        );
        // The open group cannot be capped by a reveal either.
        assert_eq!(group_view(&h.groups[0], Some(1), lang).entries.len(), 1);
    }
    assert_eq!(
        t(Lang::En, Msg::HistShowOlder { n: 25 }),
        "Show older (25 not shown)"
    );
    assert_eq!(
        t(Lang::De, Msg::HistShowOlder { n: 25 }),
        "Ältere zeigen (25 nicht angezeigt)"
    );
}

/// VH1 a journal of only empty transactions is as good as none: the page says nothing is there.
#[test]
fn vh1_a_journal_of_empty_transactions_shows_nothing() {
    let v = view(
        vec![
            st(1, TxnLine::Empty, false, &[]),
            st(2, TxnLine::Empty, false, &[]),
        ],
        None,
        Vec::new(),
    );
    let h = page(&v, Lang::En);
    assert!(h.groups.is_empty());
    assert_eq!(
        h.empty.as_ref().map(|e| e.0.as_str()),
        Some("Nothing in the journal yet")
    );
}
