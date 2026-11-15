//! Problem states as view models (P5-6b, ADR 0027 amendment P5-6b), on values built by hand.
//! - VR1 every journal state: the card, the band (yes or no, how many), `revert_begun`,
//!   `left_foreign`, the dismissal; the history's open entries say the same as the cards.
//! - VR2 the report of an undo per change (every `Observed`, every `OldSeen`, a backup file and
//!   an inline one, profiles set back elsewhere); nothing for a change that went back as
//!   expected.
//! - VR3 `Unconfirmed` and `RebindUnconfirmed` have their own words.
//! - VR4 the firewall rules no change owns: none, a list, the firewall or the journal unreadable.

use rerun_core::escape;
use rerun_core::exec::{
    Backup, ExecError, OldSeen, OpReport, OpState, OpStatus, OrphanRule, OrphansError, PendingOld,
    ProfilesMoved, RevertReport, Status, TxnLine, TxnStatus,
};
use rerun_core::flow::{ActError, RevertEnd, RevertOutcome, revert_begun};
use rerun_core::journal::{Closing, Damage, JournalError, Observed, TxnId};
use rerun_core::path::RelPath;

use crate::text::{Lang, Msg, Sym, t};
use crate::vm::{
    Names, OpVm, Tone, act_error, applied, attention, attention_shown, history, orphans,
    revert_result,
};

fn id(seq: u32) -> TxnId {
    format!("{seq:08}-0123456789abcdef").parse().unwrap()
}

fn st(seq: u32, state: TxnLine, forgotten: bool, ops: &[OpState]) -> TxnStatus {
    TxnStatus {
        id: id(seq),
        state,
        forgotten,
        folder: escape::path(&format!(r"C:\R\journal\{}", id(seq))).into_owned(),
        preview: None,
        ops: ops
            .iter()
            .enumerate()
            .map(|(i, s)| OpStatus {
                op: u16::try_from(i).unwrap(),
                state: *s,
                backup: None,
                cleanup: Vec::new(),
            })
            .collect(),
        rebinds: Vec::new(),
        shares: Vec::new(),
        shares_error: None,
    }
}

fn status(txns: Vec<TxnStatus>) -> Status {
    Status {
        txns,
        foreign_entries: 0,
    }
}

const A: OpState = OpState::Applied;
const BEFORE: OpState = OpState::Reverted(Observed::Before);
const FOREIGN: OpState = OpState::Reverted(Observed::Foreign);

#[test]
fn vr1_every_journal_state_is_a_card_and_counts_for_the_band() {
    let cases: Vec<(TxnStatus, Option<(Sym, Msg)>)> = vec![
        // An applied change alone never counts.
        (st(1, TxnLine::Applied, false, &[A, A]), None),
        (
            st(2, TxnLine::Open, false, &[A]),
            Some((Sym::Attention, Msg::StateInterrupted)),
        ),
        // F3: an undo began (one op back, one not).
        (
            st(3, TxnLine::Applied, false, &[A, BEFORE]),
            Some((Sym::Attention, Msg::StateUndoInterrupted)),
        ),
        (
            st(4, TxnLine::Applied, false, &[A, FOREIGN]),
            Some((Sym::Attention, Msg::StateForeign)),
        ),
        (
            st(5, TxnLine::CleanupPending, false, &[BEFORE]),
            Some((Sym::Attention, Msg::StateCleanup)),
        ),
        (
            st(6, TxnLine::Damaged(Damage::HeadMissing), false, &[]),
            Some((Sym::Attention, Msg::StateDamaged)),
        ),
        (
            st(
                7,
                TxnLine::Unreadable(escape::text("bad").into_owned()),
                false,
                &[],
            ),
            Some((Sym::Attention, Msg::StateUnreadable)),
        ),
        // Settled: no card, no band.
        (
            st(8, TxnLine::Closed(Closing::Reverted), false, &[BEFORE]),
            None,
        ),
        (
            st(9, TxnLine::Closed(Closing::Forgotten), false, &[A]),
            None,
        ),
        (st(10, TxnLine::Applied, true, &[A, BEFORE]), None),
        (st(11, TxnLine::Empty, false, &[]), None),
    ];
    // `revert_begun`: only an applied, not forgotten transaction with an op that is not applied.
    let begun: Vec<bool> = cases.iter().map(|(s, _)| revert_begun(s)).collect();
    assert_eq!(
        begun,
        [
            false, false, true, true, false, false, false, false, false, false, false
        ]
    );
    for lang in Lang::ALL {
        for (s, want) in &cases {
            let a = applied(
                Some(Ok(&status(vec![st(
                    s.id.seq(),
                    s.state.clone(),
                    s.forgotten,
                    &s.ops.iter().map(|o| o.state).collect::<Vec<_>>(),
                )]))),
                &Names::new(),
                lang,
            );
            let band = attention(&a, lang);
            match want {
                None => {
                    assert!(band.is_none(), "{:?}", s.state);
                    // An applied card has no problem line.
                    assert!(a.cards.iter().all(|c| c.problem.is_none()));
                }
                Some((sym, word)) => {
                    let c = &a.cards[0];
                    assert_eq!(
                        (c.state.sym, c.state.word.clone()),
                        (*sym, t(lang, *word).into_owned()),
                        "{:?}",
                        s.state
                    );
                    assert!(c.problem.is_some());
                    assert_eq!(band.as_ref().map(|b| b.count), Some(1));
                }
            }
        }
        // The undo-interrupted card says what to do.
        let a = applied(
            Some(Ok(&status(vec![st(
                3,
                TxnLine::Applied,
                false,
                &[A, BEFORE],
            )]))),
            &Names::new(),
            lang,
        );
        assert_eq!(
            a.cards[0].problem.as_deref(),
            Some(&*t(lang, Msg::ProblemUndoInterrupted))
        );
        assert!(a.cards[0].can_undo && a.cards[0].can_forget);
    }
    // Several: the band counts only the problems, names them, and says what Rerun does not do.
    let all = status(cases.into_iter().map(|(s, _)| s).collect());
    let a = applied(Some(Ok(&all)), &Names::new(), Lang::En);
    let band = attention(&a, Lang::En).unwrap();
    assert_eq!(band.count, 6);
    assert_eq!(band.title, "6 changes need you");
    assert!(band.body.starts_with("Rerun changes nothing by itself"));
    assert_eq!(band.action, "View");
    let de = attention(&a, Lang::De).unwrap();
    assert_eq!(
        (de.title.as_str(), de.action.as_str()),
        ("6 Änderungen brauchen dich", "Ansehen")
    );
    // A single one is singular; nothing open and no folder: no band.
    let one = applied(
        Some(Ok(&status(vec![st(2, TxnLine::Open, false, &[A])]))),
        &Names::new(),
        Lang::En,
    );
    assert_eq!(
        attention(&one, Lang::En).unwrap().title,
        "1 change needs you"
    );
    assert!(attention(&applied(None, &Names::new(), Lang::En), Lang::En).is_none());
    // The dismissal holds for the changes it was made for; a new problem shows it again.
    let b = attention(&one, Lang::En).unwrap();
    assert!(attention_shown(&b, &[]));
    assert!(!attention_shown(&b, &[id(2)]));
    assert!(attention_shown(&band, &[id(2), id(3)]));
    // Resolved (the card is gone): no band at all.
    let solved = applied(
        Some(Ok(&status(vec![st(
            2,
            TxnLine::Closed(Closing::Reverted),
            false,
            &[BEFORE],
        )]))),
        &Names::new(),
        Lang::En,
    );
    assert!(attention(&solved, Lang::En).is_none());
    // The history's open entries are the same cards: the same word for an interrupted undo.
    let j = rerun_core::flow::JournalView {
        status: status(vec![st(3, TxnLine::Applied, false, &[A, BEFORE])]),
        launch: Ok(None),
        holders: Vec::new(),
    };
    let h = history(Some(Ok(&j)), &Names::new(), 0, Lang::En);
    assert_eq!(h.groups[0].entries[0].state.word, "Undo interrupted");
}

fn op(index: usize, target: &str) -> OpVm {
    OpVm {
        index,
        action: String::new(),
        target: escape::path(target).into_owned(),
        lines: Vec::new(),
        undo: None,
        fate: None,
    }
}

fn op_report(op: u16, observed: Observed, backup: Option<Backup>) -> OpReport {
    OpReport {
        op,
        observed,
        left: Vec::new(),
        backup,
        detail: None,
    }
}

fn old(op: u16, name: &str, seen: OldSeen) -> PendingOld {
    PendingOld {
        op,
        root: 0,
        path: RelPath::parse(name).unwrap(),
        sha256: [0; 32],
        seen,
    }
}

fn outcome(rep: RevertReport, end: RevertEnd) -> RevertOutcome {
    RevertOutcome {
        report: rep,
        end,
        launch_option: None,
    }
}

#[test]
fn vr2_the_report_of_an_undo_names_what_did_not_go_back_as_expected() {
    let ops = [
        op(0, "game.ini"),
        op(1, "data.dll"),
        op(2, "x.cfg"),
        op(3, "y.cfg"),
    ];
    let rep = RevertReport {
        txn: id(1),
        closed: None,
        ops: vec![
            op_report(3, Observed::Drifted, None),
            op_report(
                2,
                Observed::Foreign,
                Some(Backup::Bin {
                    path: escape::path(r"C:\R\journal\x\op-0002.bin").into_owned(),
                    len: 12,
                }),
            ),
            op_report(1, Observed::Foreign, Some(Backup::Inline)),
            op_report(0, Observed::Kept, None),
            op_report(5, Observed::After, None),
            op_report(6, Observed::Before, None),
        ],
        halted: None,
        cleanup: vec![
            old(0, "a.dll.old", OldSeen::InUse),
            old(1, "b.dll.old", OldSeen::Kept),
            old(2, "c.dll.old", OldSeen::Foreign),
            old(3, "d.dll.old", OldSeen::Ours),
            old(3, "e.dll.old", OldSeen::Deleted),
            old(3, "f.dll.old", OldSeen::Gone),
        ],
        profiles_moved: Some(ProfilesMoved {
            planned: escape::path(r"C:\Old\profiles").into_owned(),
            now: escape::path(r"C:\New\profiles").into_owned(),
        }),
    };
    for lang in Lang::ALL {
        let r = revert_result(&outcome(rep_clone(&rep), RevertEnd::Foreign), &ops, lang);
        assert_eq!(r.tone, Tone::Attention);
        let d: Vec<(String, String)> = r
            .notice
            .details
            .iter()
            .map(|d| {
                (
                    d.who
                        .as_ref()
                        .map(|s| s.as_str().to_owned())
                        .unwrap_or_default(),
                    d.what.as_str().to_owned(),
                )
            })
            .collect();
        let w = |m| t(lang, m).into_owned();
        let want = vec![
            (w(Msg::ReportDrifted), "y.cfg".to_owned()),
            (w(Msg::ReportForeign), "x.cfg".to_owned()),
            (
                w(Msg::HistoryBackupsIn),
                r"C:\R\journal\x\op-0002.bin".to_owned(),
            ),
            (w(Msg::ReportForeign), "data.dll".to_owned()),
            (w(Msg::ReportForeignInline), String::new()),
            (w(Msg::ReportKept), "game.ini".to_owned()),
            (w(Msg::ReportOldInUse), "a.dll.old".to_owned()),
            (w(Msg::ReportOldKept), "b.dll.old".to_owned()),
            (w(Msg::ReportOldForeign), "c.dll.old".to_owned()),
            (w(Msg::ReportProfilesMoved), r"C:\New\profiles".to_owned()),
        ];
        assert_eq!(d, want, "{lang:?}");
    }
    // A change that went back as expected says nothing.
    let quiet = RevertReport {
        txn: id(1),
        closed: Some(Closing::Reverted),
        ops: vec![
            op_report(0, Observed::Before, None),
            op_report(1, Observed::After, None),
        ],
        halted: None,
        cleanup: vec![old(0, "a.old", OldSeen::Deleted)],
        profiles_moved: None,
    };
    let r = revert_result(&outcome(quiet, RevertEnd::Closed), &ops, Lang::En);
    assert!(r.notice.details.is_empty());
    assert_eq!(r.tone, Tone::Done);
    // A target the head does not list is shown empty, never a wrong one.
    let r = revert_result(&outcome(rep_clone(&rep), RevertEnd::Foreign), &[], Lang::En);
    assert_eq!(r.notice.details[0].what.as_str(), "");
}

fn rep_clone(r: &RevertReport) -> RevertReport {
    RevertReport {
        txn: r.txn,
        closed: r.closed,
        ops: r
            .ops
            .iter()
            .map(|o| OpReport {
                op: o.op,
                observed: o.observed,
                left: o.left.clone(),
                backup: o.backup.clone(),
                detail: None,
            })
            .collect(),
        halted: None,
        cleanup: r
            .cleanup
            .iter()
            .map(|p| PendingOld {
                op: p.op,
                root: p.root,
                path: p.path.clone(),
                sha256: p.sha256,
                seen: p.seen,
            })
            .collect(),
        profiles_moved: r.profiles_moved.as_ref().map(|m| ProfilesMoved {
            planned: m.planned.clone(),
            now: m.now.clone(),
        }),
    }
}

#[test]
fn vr3_an_unconfirmed_close_and_an_unconfirmed_rebind_have_their_own_words() {
    let e = || JournalError::NotFound(id(1));
    for lang in Lang::ALL {
        let u = act_error(&ActError::Exec(ExecError::Unconfirmed(e())), lang);
        let r = act_error(&ActError::Exec(ExecError::RebindUnconfirmed(e())), lang);
        assert_eq!(u.notice.title, t(lang, Msg::ResUnconfirmedTitle));
        assert_eq!(r.notice.title, t(lang, Msg::ResRebindUnconfirmedTitle));
        assert_eq!(r.notice.body, t(lang, Msg::ResRebindUnconfirmedBody));
        assert_ne!(u.notice.title, r.notice.title);
        assert_eq!((u.tone, r.tone), (Tone::Attention, Tone::Attention));
        // The core's text stays an escaped detail.
        assert_eq!(r.notice.details.len(), 1);
    }
}

#[test]
fn vr4_the_orphaned_rules_are_listed_or_the_reason_they_cannot_be() {
    for lang in Lang::ALL {
        // No Rerun folder, or no rule: no section.
        assert!(!orphans(None, lang).shown);
        assert!(!orphans(Some(&Ok(Vec::new())), lang).shown);
        // A list: name and program, escaped, with how to remove them.
        let rules = Ok(vec![OrphanRule {
            name: escape::text("Rerun - a \u{202e} rule").into_owned(),
            program: escape::path(r"D:\G\game.exe").into_owned(),
        }]);
        let o = orphans(Some(&rules), lang);
        assert!(o.shown && o.note.is_none() && o.detail.is_none());
        assert_eq!(o.rules.len(), 1);
        assert!(!o.rules[0].name.as_str().contains('\u{202e}'));
        assert_eq!(o.rules[0].program.as_str(), r"D:\G\game.exe");
        assert_eq!(o.title, t(lang, Msg::OrphansTitle));
        assert_eq!(o.hint, t(lang, Msg::OrphansHint));
        // The firewall or the journal cannot be read: said, each in its own words.
        let fw: Result<Vec<OrphanRule>, OrphansError> = Err(OrphansError::Firewall(
            rerun_core::sys::SysError::new(rerun_core::sys::SysErrorKind::Other, "fw: denied"),
        ));
        let o = orphans(Some(&fw), lang);
        assert!(o.shown && o.rules.is_empty());
        assert_eq!(o.note.as_deref(), Some(&*t(lang, Msg::OrphansUnreadable)));
        assert!(o.detail.is_some());
        let j: Result<Vec<OrphanRule>, OrphansError> =
            Err(OrphansError::Journal(JournalError::NotFound(id(1))));
        let o = orphans(Some(&j), lang);
        assert_eq!(o.note.as_deref(), Some(&*t(lang, Msg::OrphansNoJournal)));
    }
}
