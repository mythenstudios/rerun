//! The options section as view models (ADR 0032, plan P5-OE "UI"), on values built by hand, in both
//! languages.
//! - VO1 an option without a live value: "Unchanged" first and checked, every value with its
//!   status word, accessible names "<option>: <value>", a row for up to four values and a list
//!   from five on.
//! - VO2 a live value: "Active: <value> (change No. N)", it is the checked choice, and "Unchanged"
//!   means undoing that change (the explanation and the change, no plan).
//! - VO3 a refused value stays visible and off with its reason: anti-cheat, the program it
//!   starts is not there, another change holds files for another program (the same program is
//!   fine), the journal's state.
//! - VO4 the rules of the choices: a value is a choice, the live value is none, "Unchanged" drops
//!   the choice, a value that is off is ignored, a refresh keeps only what is still offered.
//! - VO5 the journal's state as the game's notice, per `LiveError`.
//! - VO6 the launch profile part by part with its origin, and the sentence of the fallback.
//! - VO7 the warnings of option values and of kept parts have words.

use rerun_core::catalog::model::TopoOption;
use rerun_core::escape;
use rerun_core::exec::{LiveChoice, LiveError, LiveExe, LiveState};
use rerun_core::flow::{OptionView, ValueView};
use rerun_core::journal::TxnId;
use rerun_core::path::RelPath;
use rerun_core::plan::{Choice, Pick};
use rerun_core::topo::{LaunchParts, PartFrom, StepKind, ValueRefusal, Warning};

use crate::text::{Lang, Msg, t};
use crate::vm::{Choices, OptionsVm, Sym, options, parts_vm, warning_vm};

fn txn(seq: u32) -> TxnId {
    format!("{seq:08}-0123456789abcdef").parse().unwrap()
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

/// An option with the given values (ID, title, status, step).
fn option(values: &[(&str, &str, &str)]) -> TopoOption {
    let v: Vec<String> = values
        .iter()
        .map(|(id, title, status)| {
            format!(
                r#"{{"id":"{id}","title":"{title}","status":"{status}","steps":[{{"start":"{id}.exe"}}]}}"#
            )
        })
        .collect();
    serde_json::from_str(&format!(
        r#"{{"id":"graphics-api","title":"Graphics API","sources":[{{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented"}}],"values":[{}]}}"#,
        v.join(",")
    ))
    .unwrap()
}

fn view(o: &TopoOption, refused: &[Option<ValueRefusal>]) -> OptionView {
    OptionView {
        option: o.clone(),
        values: o
            .values
            .iter()
            .zip(refused.iter().chain(std::iter::repeat(&None)))
            .map(|(v, r)| ValueView {
                value: v.clone(),
                refused: *r,
                warned: Vec::new(),
            })
            .collect(),
    }
}

fn dx() -> TopoOption {
    option(&[
        ("dx9", "DirectX 9", "verified"),
        ("dx10", "DirectX 10", "unverified"),
    ])
}

fn nothing_live() -> Result<LiveState, LiveError> {
    Ok(LiveState::default())
}

fn live_dx9(seq: u32) -> Result<LiveState, LiveError> {
    Ok(LiveState {
        choices: vec![LiveChoice {
            txn: txn(seq),
            topo: "invented".to_owned(),
            option: "graphics-api".to_owned(),
            value: "dx9".to_owned(),
        }],
        ..LiveState::default()
    })
}

fn section(views: &[OptionView], live: &Result<LiveState, LiveError>, lang: Lang) -> OptionsVm {
    options(views, live, "invented", lang)
}

#[test]
fn vo1_an_option_starts_with_unchanged_and_names_every_value() {
    let o = dx();
    for lang in Lang::ALL {
        let s = section(&[view(&o, &[])], &nothing_live(), lang);
        assert_eq!(s.title, t(lang, Msg::OptionsTitle));
        assert_eq!(s.intro, t(lang, Msg::OptionsIntro));
        assert!(s.notice.is_none());
        let opt = &s.options[0];
        assert_eq!(opt.title.as_str(), "Graphics API");
        assert!(!opt.list, "three choices are a row");
        let keys: Vec<&str> = opt.choices.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["", "dx9", "dx10"]);
        // Unchanged: its words, what it means, no status, always offered.
        let u = &opt.choices[0];
        assert_eq!(u.label.as_str(), t(lang, Msg::OptUnchanged));
        assert_eq!(u.note.as_deref(), Some(&*t(lang, Msg::OptUnchangedDesc)));
        assert!(u.status.is_none() && u.enabled && u.is_unchanged());
        assert_eq!(
            u.name,
            format!("Graphics API: {}", t(lang, Msg::OptUnchanged))
        );
        // The values: the Topo's titles, the status as symbol and word, the accessible name.
        let d9 = &opt.choices[1];
        assert_eq!(d9.label.as_str(), "DirectX 9");
        assert_eq!(d9.name, "Graphics API: DirectX 9");
        let b = d9.status.as_ref().expect("a status");
        assert_eq!(
            (b.sym, b.word.as_str()),
            (Sym::Verified, &*t(lang, Msg::StatusVerified))
        );
        let b = opt.choices[2].status.as_ref().unwrap();
        assert_eq!(
            (b.sym, b.word.as_str()),
            (Sym::Unconfirmed, &*t(lang, Msg::StatusUnverified))
        );
        assert!(d9.note.is_none() && d9.enabled);
        // The source is text, escaped, in its own element.
        assert_eq!(opt.sources.len(), 1);
        assert!(opt.sources[0].as_str().contains("pcgamingwiki.com"));
        // Nothing is live; Unchanged is checked.
        assert!(opt.live.is_none());
        assert_eq!(Choices::default().checked(&s), [0]);
    }
    // The words: the German ones are the user's ("bestätigt" / "nicht bestätigt").
    assert_eq!(t(Lang::De, Msg::OptUnchanged), "Unverändert");
    assert_eq!(t(Lang::De, Msg::StatusUnverified), "Nicht bestätigt");
    assert_eq!(t(Lang::De, Msg::StatusVerified), "Bestätigt");
}

#[test]
fn vo1_five_values_are_a_list() {
    let o = option(&[
        ("a", "A", "verified"),
        ("b", "B", "verified"),
        ("c", "C", "verified"),
        ("d", "D", "verified"),
    ]);
    assert!(!section(&[view(&o, &[])], &nothing_live(), Lang::En).options[0].list);
    let o = option(&[
        ("a", "A", "verified"),
        ("b", "B", "verified"),
        ("c", "C", "verified"),
        ("d", "D", "verified"),
        ("e", "E", "verified"),
    ]);
    let s = section(&[view(&o, &[])], &nothing_live(), Lang::En);
    assert!(s.options[0].list);
    assert_eq!(s.options[0].choices.len(), 6);
}

#[test]
fn vo2_a_live_value_is_active_checked_and_unchanged_means_undoing_it() {
    let o = dx();
    for lang in Lang::ALL {
        let s = section(&[view(&o, &[])], &live_dx9(3), lang);
        let opt = &s.options[0];
        let live = opt.live.as_ref().expect("a live value");
        assert_eq!((live.value.as_str(), live.txn), ("dx9", txn(3)));
        // "Active: <value> (change No. 3)": the value is its own element.
        assert_eq!(live.line.name.as_ref().unwrap().as_str(), "DirectX 9");
        assert_eq!(
            live.line.flat(),
            format!(
                "{} DirectX 9 {}",
                t(lang, Msg::OptActive),
                t(lang, Msg::OptActiveChange { n: 3 })
            )
        );
        assert_eq!(live.undo_hint, t(lang, Msg::OptUndoHint { n: 3 }));
        assert_eq!(live.undo_button, t(lang, Msg::OptUndoBtn { n: 3 }));
        // The live value is the checked choice, with nothing selected.
        let mut c = Choices::default();
        assert_eq!(c.checked(&s), [1]);
        assert!(c.to_plan(&s).is_empty());
        // "Unchanged": explains, plans nothing, keeps the live value checked.
        c.choose(&s, 0, 0);
        assert_eq!(c.hint(), Some(0));
        assert_eq!(c.checked(&s), [1]);
        assert!(c.to_plan(&s).is_empty() && c.is_empty());
        // Any other click takes the explanation away.
        c.choose(&s, 0, 2);
        assert_eq!(c.hint(), None);
        assert_eq!(c.checked(&s), [2]);
        // Back to Unchanged while another value is picked: the pick is dropped, the live one is
        // back, and the explanation is shown.
        c.choose(&s, 0, 0);
        assert_eq!((c.checked(&s), c.hint()), (vec![1], Some(0)));
    }
    // A live choice of another Topo or another option is not this page's.
    let s = options(&[view(&o, &[])], &live_dx9(3), "another-topo", Lang::En);
    assert!(s.options[0].live.is_none());
    let mut other = live_dx9(3).unwrap();
    other.choices[0].option = "other".to_owned();
    assert!(
        section(&[view(&o, &[])], &Ok(other), Lang::En).options[0]
            .live
            .is_none()
    );
    // A live value the Topo no longer has shows nothing live.
    let mut gone = live_dx9(3).unwrap();
    gone.choices[0].value = "dx8".to_owned();
    assert!(
        section(&[view(&o, &[])], &Ok(gone), Lang::En).options[0]
            .live
            .is_none()
    );
}

#[test]
fn vo3_a_refused_value_stays_visible_off_with_its_reason() {
    let o = option(&[
        ("dx9", "DirectX 9", "verified"),
        ("dx10", "DirectX 10", "verified"),
        ("dx11", "DirectX 11", "verified"),
    ]);
    for lang in Lang::ALL {
        let v = view(
            &o,
            &[
                Some(ValueRefusal::AntiCheat(StepKind::Start)),
                Some(ValueRefusal::NotMatched),
                None,
            ],
        );
        let s = section(&[v], &nothing_live(), lang);
        let c = &s.options[0].choices;
        assert_eq!(c.len(), 4);
        assert!(!c[1].enabled && !c[2].enabled && c[3].enabled);
        assert_eq!(
            c[1].note.as_deref(),
            Some(&*t(lang, Msg::OptNotOfferedAntiCheat))
        );
        assert_eq!(
            c[2].note.as_deref(),
            Some(&*t(lang, Msg::OptNotOfferedNotMatched))
        );
        // Visible: the status and the name stay.
        assert_eq!(c[1].label.as_str(), "DirectX 9");
        assert!(c[1].status.is_some());
        // A click on an off value does nothing.
        let mut ch = Choices::default();
        ch.choose(&s, 0, 1);
        ch.choose(&s, 0, 2);
        assert!(ch.is_empty());
        ch.choose(&s, 0, 3);
        assert_eq!(
            ch.to_plan(&s),
            [Choice {
                option: "graphics-api".to_owned(),
                value: "dx11".to_owned()
            }]
        );
    }
}

#[test]
fn vo3_another_program_under_a_live_change_refuses_the_value_and_names_it() {
    let o = option(&[
        ("dx9", "DirectX 9", "verified"),
        ("dx10", "DirectX 10", "verified"),
    ]);
    // Change 5 installed package files for dx9.exe; dx10.exe would switch the program (E4 b).
    let live = Ok(LiveState {
        exes: vec![LiveExe {
            txn: txn(5),
            exe: rel("DX9.exe"),
        }],
        ..LiveState::default()
    });
    for lang in Lang::ALL {
        let s = section(&[view(&o, &[])], &live, lang);
        let c = &s.options[0].choices;
        assert!(c[1].enabled, "the same program (folded) is fine");
        assert!(!c[2].enabled);
        assert_eq!(
            c[2].note.as_deref(),
            Some(&*t(lang, Msg::OptNotOfferedExeSwitch { n: 5 }))
        );
    }
    // The text says undo it first, then choose, then apply the fix again.
    let text = t(Lang::En, Msg::OptNotOfferedExeSwitch { n: 5 });
    assert!(
        text.contains("No. 5") && text.contains("Undo it first"),
        "{text}"
    );
}

#[test]
fn vo3_a_journal_state_that_forbids_plans_turns_every_value_off() {
    let o = dx();
    for lang in Lang::ALL {
        let s = section(
            &[view(&o, &[])],
            &Err(LiveError::Changed { txn: txn(7) }),
            lang,
        );
        let c = &s.options[0].choices;
        assert!(c[0].enabled, "Unchanged stays");
        assert!(!c[1].enabled && !c[2].enabled);
        assert_eq!(
            c[1].note.as_deref(),
            Some(&*t(lang, Msg::OptNotOfferedLive))
        );
        assert!(s.notice.is_some());
    }
}

#[test]
fn vo5_the_journal_state_is_the_notice_of_the_game() {
    let o = dx();
    let cases = [
        (
            LiveError::Interrupted { txn: txn(4) },
            Msg::OptLiveInterrupted { n: 4 },
            true,
        ),
        (
            LiveError::Unreadable { txn: txn(4) },
            Msg::OptLiveUnreadable { n: 4 },
            true,
        ),
        (
            LiveError::Changed { txn: txn(4) },
            Msg::OptLiveChanged { n: 4 },
            true,
        ),
        (
            LiveError::Journal("a path \u{202e}evil".to_owned()),
            Msg::OptLiveJournal,
            false,
        ),
    ];
    for lang in Lang::ALL {
        for (e, m, has_txn) in &cases {
            let s = section(&[view(&o, &[])], &Err(e.clone()), lang);
            let n = s.notice.expect("a notice");
            assert_eq!(n.title, t(lang, Msg::OptLiveTitle));
            assert_eq!(n.body, t(lang, *m));
            assert_eq!(n.txn.is_some(), *has_txn);
            assert_eq!(n.undo_button.is_some(), *has_txn);
            if *has_txn {
                assert_eq!(
                    n.undo_button,
                    Some(t(lang, Msg::OptUndoBtn { n: 4 }).into_owned())
                );
                assert!(n.detail.is_none());
            } else {
                // The journal's own text is an escaped detail, never part of the sentence.
                let d = n.detail.expect("the journal's text");
                assert!(!d.as_str().contains('\u{202e}'), "{}", d.as_str());
                assert!(!n.body.contains("evil"));
            }
        }
    }
    // The section is there for a game without options too: the notice alone.
    let s = section(&[], &Err(LiveError::Changed { txn: txn(4) }), Lang::En);
    assert!(s.options.is_empty() && s.notice.is_some());
}

#[test]
fn vo4_a_refresh_keeps_only_what_is_still_offered() {
    let o = dx();
    let s = section(&[view(&o, &[])], &nothing_live(), Lang::En);
    let mut c = Choices::default();
    c.choose(&s, 0, 2);
    assert_eq!(c.checked(&s), [2]);
    // The page is read again: dx10 is off now (refused), the choice goes.
    let off = section(
        &[view(&o, &[None, Some(ValueRefusal::NotMatched)])],
        &nothing_live(),
        Lang::En,
    );
    let mut kept = c.clone();
    kept.keep(&off);
    assert!(kept.is_empty());
    // Still offered: it stays.
    let mut kept = c.clone();
    kept.keep(&s);
    assert_eq!(kept.to_plan(&s).len(), 1);
    // The chosen value became the live one (it was applied): no choice is left.
    let live = section(
        &[view(&o, &[])],
        &Ok(LiveState {
            choices: vec![LiveChoice {
                txn: txn(2),
                topo: "invented".to_owned(),
                option: "graphics-api".to_owned(),
                value: "dx10".to_owned(),
            }],
            ..LiveState::default()
        }),
        Lang::En,
    );
    let mut kept = c.clone();
    kept.keep(&live);
    assert!(kept.is_empty());
    assert_eq!(kept.checked(&live), [2]);
    // An explanation goes when no value is live any more.
    let mut hinted = Choices::default();
    let with_live = section(&[view(&o, &[])], &live_dx9(1), Lang::En);
    hinted.choose(&with_live, 0, 0);
    assert_eq!(hinted.hint(), Some(0));
    hinted.keep(&s);
    assert_eq!(hinted.hint(), None);
}

#[test]
fn vo6_the_launch_profile_is_shown_part_by_part_with_its_origin() {
    let pick = Pick {
        issue: "crash".to_owned(),
        variant: "limit-8".to_owned(),
    };
    let choice = Choice {
        option: "graphics-api".to_owned(),
        value: "dx9".to_owned(),
    };
    for lang in Lang::ALL {
        let parts = LaunchParts {
            method: rerun_core::prim::MethodSpec::Direct,
            start: rel("FFLauncher.exe"),
            rule: Some(PartFrom::Fix(pick.clone())),
            run: Some((rel("game_dx9.exe"), PartFrom::Option(choice.clone()))),
            args: Some((
                vec!["-windowed".to_owned(), "-w=1280".to_owned()],
                PartFrom::Kept(txn(3)),
            )),
        };
        let p = parts_vm(&parts, lang);
        assert_eq!(p.heading, t(lang, Msg::PvPartsHeading));
        assert_eq!(p.parts.len(), 3);
        // The rule: from the fix, whose ID is its own element.
        assert_eq!(p.parts[0].label, t(lang, Msg::PvPartRule));
        assert_eq!(p.parts[0].from, t(lang, Msg::PvFromFix));
        assert_eq!(p.parts[0].from_name.as_ref().unwrap().as_str(), "limit-8");
        // The program: from the option value.
        assert_eq!(p.parts[1].label, t(lang, Msg::PvPartRun));
        assert_eq!(p.parts[1].detail.as_ref().unwrap().as_str(), "game_dx9.exe");
        assert_eq!(p.parts[1].from, t(lang, Msg::PvFromOption));
        assert_eq!(
            p.parts[1].from_name.as_ref().unwrap().as_str(),
            "graphics-api = dx9"
        );
        // The arguments: kept from change 3, with the order of the two undos.
        assert_eq!(p.parts[2].label, t(lang, Msg::PvPartArgs));
        assert_eq!(
            p.parts[2].detail.as_ref().unwrap().as_str(),
            "-windowed -w=1280"
        );
        assert_eq!(p.parts[2].from, t(lang, Msg::PvFromKept { n: 3 }));
        assert!(p.parts[2].from_name.is_none());
        // The fallback: Steam's command, from the parts the profile has; the program is its
        // own element.
        assert_eq!(
            p.fallback.before,
            format!(
                "{} ",
                t(
                    lang,
                    Msg::PvFallback {
                        run: true,
                        rule: true,
                        args: true
                    }
                )
            )
        );
        assert_eq!(p.fallback.name.as_ref().unwrap().as_str(), "FFLauncher.exe");
    }
    // Only what the profile has: a rule alone says "without the rule", no program to start.
    let rule_only = LaunchParts {
        method: rerun_core::prim::MethodSpec::Direct,
        start: rel("FFLauncher.exe"),
        rule: Some(PartFrom::Kept(txn(1))),
        run: None,
        args: None,
    };
    let p = parts_vm(&rule_only, Lang::En);
    assert_eq!(p.parts.len(), 1);
    assert!(
        p.fallback.before.contains("without the rule,")
            || p.fallback.before.contains("without the rule:")
    );
    assert!(!p.fallback.before.contains("without the rule and"));
    assert!(!p.fallback.before.contains("program cannot be started"));
    let en = t(
        Lang::En,
        Msg::PvFallback {
            run: true,
            rule: false,
            args: true,
        },
    );
    assert!(en.contains("program cannot be started") && en.contains("without the arguments"));
    assert!(!en.contains("without the rule"));
    let de = t(
        Lang::De,
        Msg::PvFallback {
            run: false,
            rule: true,
            args: true,
        },
    );
    assert!(de.contains("ohne die Regel und die Argumente"), "{de}");
}

#[test]
fn vo7_option_and_kept_warnings_have_words() {
    for lang in Lang::ALL {
        let w = warning_vm(
            &Warning::OptionAntiCheat {
                option: "graphics-api".to_owned(),
                value: "dx9".to_owned(),
                step: StepKind::Start,
            },
            lang,
        )
        .unwrap();
        assert_eq!(w.text, t(lang, Msg::OptWarned));
        assert_eq!(w.detail.unwrap().as_str(), "graphics-api = dx9");
        let w = warning_vm(
            &Warning::KeptAntiCheat {
                txn: txn(9),
                step: StepKind::Start,
            },
            lang,
        )
        .unwrap();
        assert_eq!(w.text, t(lang, Msg::WarnKeptAntiCheat));
        assert_eq!(
            w.detail.unwrap().as_str(),
            t(lang, Msg::ClearNumber { n: 9 })
        );
        let _ = escape::text("");
    }
}
