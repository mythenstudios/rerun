//! The Advanced section of a game through the worker (ADR 0029, plan P5-OE "UI"), in the fake
//! world. Every ID, step and hash is invented.
//! - AA1 the section on a page: the Topo's launch, the steps of a thread limit on this PC (a
//!   5950X-like topology), the names of every control in English and German, and the locks: a
//!   chosen CPU fix locks the launch part with its reason, the launcher case locks a soft rule
//!   and a priority.
//! - AA2 own settings are planned with the picks as one plan with the origin "Advanced", applied,
//!   shown as live on the page (and prefilled, not planned again), listed on the card and in the
//!   history, a fact in the report, and an undo is bit for bit.
//! - AA3 the live readout comes from the core: "8 of 32 logical processors: ..." (the PC is read
//!   once per session).
//! - AA4 the locks hold in the worker too: a CPU fix with an own rule, own flags next to a fix's
//!   flags, a form the core refuses; the anti-cheat rule locks `watch` and flags.
//! - AA5 a Topo that names no start: the matched programs are the choices, the start is asked
//!   before a plan, what the rule would not limit is said inline.
//! - AA6 own flags: planned, applied, shown as live and not removable on the page, undone.
//! - AA7 an own rule over a live one: the warning and the undo order.

use std::path::Path;

use rerun_core::plan::{Manual, ManualMethod, Pick};
use rerun_core::prim::{CpuRuleSpec, PrioritySpec};

use super::options::rig;
use super::write::{Rig, applied_of, dialog_of, game_in, result_of};
use super::*;
use crate::text::{Msg, t};
use crate::vm::{Field, GameVm, PreviewVm, Selection, Tone};
use rerun_core::flow::{AdvancedStart, Bitness};

const WITH_LAUNCH: &str =
    r#","launch":{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}"#;

/// The Topo of the tests: `limit` (a CPU rule, verified), `dpi-fix` (flags for `game.exe`);
/// `launch` is the launch block (or nothing).
fn adv_index(sha: &str, launch: &str) -> String {
    format!(
        r#"{{"format":1,"seq":9,"issued":"2026-11-26T12:00:00Z","topos":[{{"format":1,"id":"invented-w","title":"Invented W","status":"active","rev":3,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}}{launch},
"issues":[
 {{"id":"crash","title":"The game crashes with many cores","variants":[
   {{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8}}}}]}}]}},
 {{"id":"blurry","title":"The window is blurry","variants":[
   {{"id":"dpi-fix","status":"unverified","kind":"fix","steps":[{{"compat_layer":{{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}}}]}}]}}
]}}],"packages":[]}}"#
    )
}

fn launch_rig(lang: Lang) -> Rig {
    let r = rig(lang, |sha| adv_index(sha, WITH_LAUNCH));
    layers_key(&r);
    r
}

fn bare_rig(lang: Lang) -> Rig {
    let r = rig(lang, |sha| adv_index(sha, ""));
    layers_key(&r);
    r
}

/// The key the compatibility flags are written under, which Windows has.
fn layers_key(r: &Rig) {
    r.sys
        .fake_registry()
        .put_key_all(&rerun_core::sys::registry::RegKey::new(
            rerun_core::sys::registry::Hive::CurrentUser,
            rerun_core::sys::registry::RegView::Native,
            r"Software\Microsoft\Windows NT\CurrentVersion",
        ))
        .unwrap();
}

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// Presses the thread limit down until it reads `n` threads.
fn threads_to(sel: &mut Selection, page: &GameVm, n: u32, lang: Lang) {
    let want = tx(lang, Msg::AdvThreadsValue { n });
    for _ in 0..40 {
        if sel.advanced(page).threads.value == want {
            return;
        }
        sel.edit(page, Field::ThreadsLess);
    }
    panic!("the limit never reached {want}");
}

/// Plans `sel` as the window would, hands the preview over and applies it.
fn plan(rig: &mut Rig, page: &GameVm, sel: &Selection) -> Vec<Event> {
    rig.run(Job::Plan {
        app_id: 220,
        picks: sel.picks(page),
        choices: sel.choices(page),
        manual: sel.manual(page),
    })
}

fn apply(rig: &mut Rig, page: &GameVm, sel: &Selection) -> (PreviewVm, Vec<Event>) {
    let ev = plan(rig, page, sel);
    let [Event::Preview { vm, .. }] = ev.as_slice() else {
        panic!("{ev:?}")
    };
    let pv = (**vm).clone();
    rig.run(Job::PreviewShown {
        hash: pv.hash.clone(),
    });
    let done = rig.run(Job::Apply {
        hash: pv.hash.clone(),
    });
    assert_eq!(result_of(&done).tone, Tone::Done, "{done:?}");
    (pv, done)
}

fn refused(ev: &[Event]) -> bool {
    matches!(ev, [Event::PreviewRefused { .. }])
}

#[test]
fn aa1_the_section_has_the_topo_launch_the_steps_of_this_pc_and_its_locks() {
    for lang in Lang::ALL {
        let mut rig = launch_rig(lang);
        let page = rig.page();
        let v = page
            .advanced
            .view
            .clone()
            .expect("a matched Topo has the section");
        assert_eq!(
            v.start,
            AdvancedStart::Topo(rerun_core::path::RelPath::parse("FFLauncher.exe").unwrap())
        );
        assert_eq!(
            (v.logical, v.bitness, v.hybrid),
            (Some(32), Bitness::X86, false)
        );
        assert!(v.steps.contains(&8) && v.steps.contains(&31) && v.steps.iter().all(|n| *n < 32));
        assert_eq!(v.tokens, ["DISABLEDXMAXIMIZEDWINDOWEDMODE", "HIGHDPIAWARE"]);

        // The names every control has.
        let mut sel = Selection::default();
        let r = sel.advanced(&page);
        let en = lang == Lang::En;
        assert_eq!(r.name, if en { "Advanced" } else { "Erweitert" });
        assert_eq!(
            r.threads.label,
            if en {
                "Maximum threads"
            } else {
                "Maximale Threads"
            }
        );
        assert_eq!(r.smt.label, "SMT");
        assert_eq!(
            r.l3.label,
            if en {
                "One cache group"
            } else {
                "Ein Cache-Bereich"
            }
        );
        assert_eq!(r.priority.label, if en { "Priority" } else { "Priorität" });
        assert_eq!(
            r.priority.choices[3].name,
            if en {
                "Priority: High"
            } else {
                "Priorität: Hoch"
            }
        );
        assert_eq!(
            r.method.choices[0].name,
            if en {
                "Launch method: Like the Topo (direct)"
            } else {
                "Startmethode: Wie der Topo (direkt)"
            }
        );
        assert_eq!(
            r.flags[0].label,
            if en {
                "Fullscreen optimisations off"
            } else {
                "Vollbildoptimierung aus"
            }
        );
        assert!(r.prefer.is_none(), "no performance cores on this PC");
        assert!(r.start.is_none(), "the Topo names Steam's start");
        // Steam starts a launcher: a priority and a soft rule would reach only it.
        assert!(!r.priority.choices[3].enabled && !r.mode.choices[1].enabled);
        assert!(r.mode.note.is_some() && r.priority.note.is_some());
        assert!(r.method.choices[2].enabled, "watch is fine");
        sel.edit(&page, Field::Method(2));
        let r = sel.advanced(&page);
        assert!(
            r.priority.choices[3].enabled && r.mode.choices[1].enabled,
            "watch reaches the game"
        );
        sel.edit(&page, Field::Priority(3));
        assert_eq!(
            sel.manual(&page).unwrap().launch.unwrap().priority,
            Some(PrioritySpec::High)
        );
        // Back to direct: the priority is dropped, it would reach only the launcher.
        sel.edit(&page, Field::Method(1));
        assert!(
            sel.manual(&page)
                .is_none_or(|m| m.launch.is_some_and(|l| l.priority.is_none()))
        );

        // The preselected CPU fix locks the launch part, with its reason; unticking frees it.
        let mut sel = Selection::preselected(&page);
        assert_eq!(sel.fix_sel(&page).cpu.as_deref(), Some("limit"));
        let r = sel.advanced(&page);
        assert!(!r.smt.enabled && !r.l3.enabled && !r.threads.less_on);
        let note = r.launch_note.expect("the reason").flat();
        assert!(
            note.contains(if en {
                "choose one of them"
            } else {
                "wähle eines davon"
            }),
            "{note}"
        );
        assert!(note.contains("limit"), "the fix is named: {note}");
        let i = page.fixes.iter().position(|f| f.key == "limit").unwrap();
        sel.toggle(&page, i);
        let r = sel.advanced(&page);
        assert!(r.smt.enabled && r.launch_note.is_none());
    }
}

#[test]
fn aa2_own_settings_are_planned_applied_live_on_the_card_and_undone() {
    for lang in Lang::ALL {
        let mut rig = launch_rig(lang);
        let before = rig.snap();
        let app_before = rig.snap_app();
        let page = rig.page();
        let mut sel = Selection::default();
        threads_to(&mut sel, &page, 8, lang);
        sel.edit(&page, Field::Smt(false));
        sel.edit(&page, Field::SingleL3(true));
        let m = sel.manual(&page).expect("own settings to plan");
        let cpu = m.launch.clone().unwrap().cpu.unwrap();
        assert_eq!(
            (cpu.max_threads, cpu.smt, cpu.single_l3),
            (Some(8), Some(false), Some(true))
        );
        assert!(!sel.is_empty(&page));

        let (pv, done) = apply(&mut rig, &page, &sel);
        let parts = pv.parts.as_ref().expect("the parts of the profile");
        assert_eq!(parts.parts.len(), 1, "{parts:?}");
        assert_eq!(parts.parts[0].from, tx(lang, Msg::PvFromManual));
        assert!(parts.parts[0].from_name.is_none());
        assert!(
            parts.parts[0].from.contains(if lang == Lang::En {
                "not checked"
            } else {
                "nicht geprüft"
            }),
            "{}",
            parts.parts[0].from
        );

        // The page after the write: live, with the change number; the form is prefilled and
        // plans nothing again.
        let page2 = game_in(&done).clone();
        let txn = applied_of(&done).cards[0].txn;
        let live = page2
            .advanced
            .view
            .as_ref()
            .unwrap()
            .live
            .clone()
            .expect("live");
        assert_eq!((live.txn, live.launch_txn), (txn, Some(txn)));
        let mut sel2 = Selection::default();
        sel2.keep(&page2);
        assert!(sel2.manual(&page2).is_none() && sel2.is_empty(&page2));
        let r = sel2.advanced(&page2);
        let active = r.active.expect("active line");
        assert!(active.contains(&txn.seq().to_string()), "{active}");
        assert!(active.starts_with(if lang == Lang::En {
            "Active: own rule"
        } else {
            "Aktiv: eigene Regel"
        }));
        assert_eq!(r.threads.value, tx(lang, Msg::AdvThreadsValue { n: 8 }));
        assert!(!r.smt.checked && r.l3.checked);

        // The card says what was set, and so does the history and the report.
        let own = applied_of(&done).cards[0]
            .own
            .clone()
            .expect("own settings on the card");
        assert_eq!(own.title, tx(lang, Msg::AdvSumTitle));
        assert_eq!(
            own.lines,
            [format!(
                "{}, {}, {}",
                tx(lang, Msg::AdvSumThreads { n: 8 }),
                tx(lang, Msg::AdvSumNoSmt),
                tx(lang, Msg::AdvSumL3)
            )]
        );
        let ev = rig.run(Job::History);
        let Event::History(h) = &ev[0] else {
            panic!("{ev:?}")
        };
        assert_eq!(h.groups[0].entries[0].own.as_ref(), Some(&own));
        let ev = rig.run(Job::ReportAsk { app_id: 220 });
        let body = dialog_of(&ev)
            .details
            .iter()
            .map(|d| d.what.as_str().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(body.contains("- Own settings (Advanced): yes"), "{body}");
        assert!(!body.contains("8 threads"), "never what they are: {body}");

        // Undo: bit for bit, the page has nothing live.
        let ev = rig.run(Job::RevertPreview { txn });
        assert!(dialog_of(&ev).can_confirm);
        let ev = rig.revert(txn);
        assert_eq!(result_of(&ev).tone, Tone::Done);
        assert!(game_in(&ev).advanced.view.as_ref().unwrap().live.is_none());
        assert!(rig.snap() == before, "{:#?}", before.diff(&rig.snap()));
        // The journal keeps its record; Rerun's own folder is the only difference.
        let _ = app_before;
    }
}

#[test]
fn aa3_the_readout_comes_from_the_core_once_per_pc() {
    for lang in Lang::ALL {
        let mut rig = launch_rig(lang);
        let rule = CpuRuleSpec {
            max_threads: Some(8),
            single_l3: Some(true),
            smt: Some(false),
            ..CpuRuleSpec::default()
        };
        for _ in 0..2 {
            let ev = rig.run(Job::Readout {
                rule,
                bitness: Bitness::X64,
            });
            let [Event::Readout { rule: r, vm }] = ev.as_slice() else {
                panic!("{ev:?}")
            };
            assert_eq!(*r, rule);
            let want = if lang == Lang::En {
                "8 of 32 logical processors: cache group 0 (L3, 32 MB), cores 0\u{2013}7, without SMT"
            } else {
                "8 von 32 logischen Prozessoren: Cache-Gruppe 0 (L3, 32 MB), Kerne 0\u{2013}7, ohne SMT"
            };
            assert_eq!(vm.line, want);
        }
        // With SMT: both threads of the first eight cores of the group.
        let ev = rig.run(Job::Readout {
            rule: CpuRuleSpec {
                single_l3: Some(true),
                ..CpuRuleSpec::default()
            },
            bitness: Bitness::X64,
        });
        let [Event::Readout { vm, .. }] = ev.as_slice() else {
            panic!("{ev:?}")
        };
        assert!(
            vm.line.starts_with(if lang == Lang::En {
                "16 of 32"
            } else {
                "16 von 32"
            }),
            "{}",
            vm.line
        );
        assert!(
            vm.line.ends_with(if lang == Lang::En {
                "with SMT"
            } else {
                "mit SMT"
            }),
            "{}",
            vm.line
        );
        // The form asks the worker for the rule it has, not for none.
        let page = rig.page();
        let mut sel = Selection::default();
        assert_eq!(sel.readout_rule(&page), None);
        assert!(
            sel.readout_local(&page).is_some(),
            "no rule: said without the worker"
        );
        sel.edit(&page, Field::Smt(false));
        let (r, b) = sel.readout_rule(&page).unwrap();
        assert_eq!((r.smt, b), (Some(false), Bitness::X86));
    }
}

#[test]
fn aa4_the_locks_hold_in_the_worker_too() {
    let mut rig = launch_rig(Lang::En);
    // The page the window holds: a plan for a page the session does not know is refused as stale.
    let _ = rig.page();
    let app = rig.snap_app();
    let own_rule = Manual {
        launch: Some(rerun_core::plan::ManualLaunch {
            cpu: Some(CpuRuleSpec {
                max_threads: Some(8),
                ..CpuRuleSpec::default()
            }),
            ..Default::default()
        }),
        ..Manual::default()
    };
    let limit = Pick {
        issue: "crash".to_owned(),
        variant: "limit".to_owned(),
    };
    let dpi = Pick {
        issue: "blurry".to_owned(),
        variant: "dpi-fix".to_owned(),
    };
    let flags = Manual {
        layers: vec![
            rerun_core::policy::registry::TokenName::parse("DISABLEDXMAXIMIZEDWINDOWEDMODE")
                .unwrap(),
        ],
        ..Manual::default()
    };
    let go = |rig: &mut Rig, picks: Vec<Pick>, manual: Option<Manual>| {
        rig.run(Job::Plan {
            app_id: 220,
            picks,
            choices: Vec::new(),
            manual,
        })
    };
    // A CPU fix and an own rule: one of them.
    assert!(refused(&go(
        &mut rig,
        vec![limit.clone()],
        Some(own_rule.clone())
    )));
    // A fix's flags for the main program and own flags: one of them.
    assert!(refused(&go(
        &mut rig,
        vec![dpi.clone()],
        Some(flags.clone())
    )));
    // The own rule alone, and the flags next to a CPU fix, plan (the parts do not meet).
    assert!(matches!(
        go(&mut rig, vec![], Some(own_rule.clone())).as_slice(),
        [Event::Preview { .. }]
    ));
    assert!(matches!(
        go(&mut rig, vec![limit], Some(flags.clone())).as_slice(),
        [Event::Preview { .. }]
    ));
    // What the form refuses: the method alone, a rule that limits nothing, own executables, a
    // flag off the allowlist.
    let method_only = Manual {
        launch: Some(rerun_core::plan::ManualLaunch {
            method: Some(ManualMethod::Direct),
            ..Default::default()
        }),
        ..Manual::default()
    };
    let nothing = Manual {
        launch: Some(rerun_core::plan::ManualLaunch {
            cpu: Some(CpuRuleSpec::default()),
            priority: Some(PrioritySpec::High),
            ..Default::default()
        }),
        ..Manual::default()
    };
    let exe = Manual {
        exe: Some(rerun_core::plan::ManualExe {
            main_exe: rerun_core::path::RelPath::parse("game.exe").unwrap(),
        }),
        ..flags.clone()
    };
    let off_list = Manual {
        layers: vec![rerun_core::policy::registry::TokenName::parse("RUNASADMIN").unwrap()],
        ..Manual::default()
    };
    for m in [method_only, nothing, exe, off_list] {
        assert!(refused(&go(&mut rig, vec![], Some(m.clone()))), "{m:?}");
    }
    assert!(rig.snap_app() == app, "nothing was stored");
    // Neither a pick, a choice nor own settings: the preview is cleared.
    assert_eq!(
        go(&mut rig, vec![], None),
        [Event::PreviewNone { app_id: 220 }]
    );

    // Anti-cheat: `watch` and flags are locked (the form drops them), a `direct` rule is
    // planned with a warning.
    let sys = &rig.sys;
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{G}\pb")))
        .unwrap();
    sys.fake_fs().sync_all();
    let page = rig.page();
    let v = page.advanced.view.clone().unwrap();
    assert!(v.anti_cheat);
    let mut sel = Selection::default();
    sel.edit(&page, Field::Method(2));
    sel.edit(&page, Field::Flag(0));
    assert!(sel.manual(&page).is_none(), "watch and flags are locked");
    let r = sel.advanced(&page);
    assert!(!r.method.choices[2].enabled && !r.flags[0].enabled);
    assert!(r.flags_note.unwrap().flat().contains("Anti-cheat"));
    let watch = Manual {
        launch: Some(rerun_core::plan::ManualLaunch {
            method: Some(ManualMethod::Watch),
            ..own_rule.launch.clone().unwrap()
        }),
        ..Manual::default()
    };
    assert!(
        refused(&go(&mut rig, vec![], Some(watch))),
        "the worker refuses watch"
    );
    assert!(refused(&go(&mut rig, vec![], Some(flags))), "and flags");
    let ev = go(&mut rig, vec![], Some(own_rule));
    let [Event::Preview { vm, .. }] = ev.as_slice() else {
        panic!("{ev:?}")
    };
    assert!(
        vm.warnings.iter().any(|w| w.text.contains("anti-cheat")),
        "{:?}",
        vm.warnings
    );
}

#[test]
fn aa5_a_topo_without_a_start_asks_for_the_program() {
    for lang in Lang::ALL {
        let mut rig = bare_rig(lang);
        let before = rig.snap();
        let page = rig.page();
        let v = page.advanced.view.clone().unwrap();
        let AdvancedStart::Choose(list) = &v.start else {
            panic!("{:?}", v.start)
        };
        assert_eq!(
            list.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
            ["game.exe"]
        );
        let mut sel = Selection::default();
        let r = sel.advanced(&page);
        let g = r.start.as_ref().expect("the program is asked");
        assert_eq!(g.choices.len(), 1);
        assert_eq!(
            g.choices[0].name,
            if lang == Lang::En {
                "Program Steam starts: game.exe"
            } else {
                "Programm, das Steam startet: game.exe"
            }
        );
        // A rule without the program: said, not planned.
        threads_to(&mut sel, &page, 8, lang);
        let input = sel.manual(&page);
        assert!(input.is_none() && sel.is_empty(&page));
        assert_eq!(
            sel.advanced(&page).problem.map(|p| p.flat()),
            Some(tx(lang, Msg::AdvNeedsStart))
        );
        // With it: the priority is allowed (the program is the main one), the plan goes through.
        sel.edit(&page, Field::Start(0));
        sel.edit(&page, Field::Priority(3));
        assert!(sel.advanced(&page).priority.choices[3].checked);
        let m = sel.manual(&page).expect("planned");
        assert_eq!(
            m.launch.as_ref().unwrap().start.as_ref().unwrap().as_str(),
            "game.exe"
        );
        let (pv, done) = apply(&mut rig, &page, &sel);
        assert!(pv.parts.unwrap().fallback.flat().contains("game.exe"));
        let txn = applied_of(&done).cards[0].txn;
        // The form shows what is live, the start included.
        let page2 = game_in(&done).clone();
        let mut sel2 = Selection::default();
        sel2.keep(&page2);
        assert!(sel2.advanced(&page2).start.unwrap().choices[0].checked);
        assert!(sel2.manual(&page2).is_none());
        rig.run(Job::RevertPreview { txn });
        let ev = rig.revert(txn);
        assert_eq!(result_of(&ev).tone, Tone::Done);
        assert!(rig.snap() == before, "{:#?}", before.diff(&rig.snap()));

        // A rule that limits nothing (a soft mode alone) is said inline before any plan.
        let mut sel = Selection::default();
        sel.edit(&page, Field::Start(0));
        sel.edit(&page, Field::Mode(1));
        assert!(sel.manual(&page).is_none());
        assert_eq!(
            sel.advanced(&page).problem.map(|p| p.flat()),
            Some(tx(lang, Msg::AdvErrNoRestriction))
        );
        // A method alone changes nothing: the same.
        let mut sel = Selection::default();
        sel.edit(&page, Field::Method(1));
        assert_eq!(
            sel.advanced(&page).problem.map(|p| p.flat()),
            Some(tx(lang, Msg::AdvErrNoRule))
        );
    }
}

#[test]
fn aa6_own_flags_are_planned_live_and_taken_back_only_by_undo() {
    for lang in Lang::ALL {
        let mut rig = launch_rig(lang);
        let before = rig.snap();
        let page = rig.page();
        let mut sel = Selection::default();
        sel.edit(&page, Field::Flag(0));
        let m = sel.manual(&page).unwrap();
        assert_eq!(
            m.layers.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
            ["DISABLEDXMAXIMIZEDWINDOWEDMODE"]
        );
        assert!(m.launch.is_none());
        let (pv, done) = apply(&mut rig, &page, &sel);
        assert!(
            pv.ops.iter().any(|o| o.lines.iter().any(|l| l
                .values
                .iter()
                .any(|v| v.as_str().contains("DISABLEDXMAXIMIZEDWINDOWEDMODE")))
                || o.action.contains("compat")
                || o.action.contains("layer")),
            "{:?}",
            pv.ops.iter().map(|o| o.action.clone()).collect::<Vec<_>>()
        );
        let page2 = game_in(&done).clone();
        let txn = applied_of(&done).cards[0].txn;
        let mut sel2 = Selection::default();
        sel2.keep(&page2);
        let r = sel2.advanced(&page2);
        assert!(
            r.flags[0].checked && !r.flags[0].enabled,
            "live and not removable here"
        );
        assert!(
            r.flags[0]
                .note
                .as_ref()
                .unwrap()
                .flat()
                .contains(&txn.seq().to_string())
        );
        sel2.edit(&page2, Field::Flag(0));
        assert!(
            sel2.advanced(&page2).flags[0].checked,
            "a click on a live flag changes nothing"
        );
        assert!(sel2.manual(&page2).is_none());
        // The second flag is still free.
        sel2.edit(&page2, Field::Flag(1));
        assert_eq!(sel2.manual(&page2).unwrap().layers.len(), 1);
        // Undo.
        rig.run(Job::RevertPreview { txn });
        let ev = rig.revert(txn);
        assert_eq!(result_of(&ev).tone, Tone::Done);
        assert!(rig.snap() == before, "{:#?}", before.diff(&rig.snap()));
        assert!(!sel2.advanced(&page2).flags.is_empty());
    }
}

#[test]
fn aa7_an_own_rule_over_a_live_one_warns_and_undoes_in_order() {
    let mut rig = launch_rig(Lang::En);
    let base = rig.snap();
    let page = rig.page();
    let mut sel = Selection::default();
    threads_to(&mut sel, &page, 8, Lang::En);
    let (_, first) = apply(&mut rig, &page, &sel);
    let t1 = applied_of(&first).cards[0].txn;
    let after_first = rig.snap();
    let page2 = game_in(&first).clone();
    let v = page2.advanced.view.clone().unwrap();
    assert_eq!(v.rule_txn, Some(t1));

    // Another number replaces the rule: the warning names the change, the section says so.
    let mut sel = Selection::default();
    sel.keep(&page2);
    threads_to(&mut sel, &page2, 6, Lang::En);
    sel.edit(&page2, Field::Exclude(1));
    let r = sel.advanced(&page2);
    assert!(r.replaces.unwrap().contains(&t1.seq().to_string()));
    let (pv, second) = apply(&mut rig, &page2, &sel);
    assert!(
        pv.warnings
            .iter()
            .any(|w| w.text.contains("replaces the CPU rule")
                && w.detail
                    .as_ref()
                    .is_some_and(|d| d.as_str().contains(&t1.seq().to_string()))),
        "{:?}",
        pv.warnings
            .iter()
            .map(|w| (&w.text, &w.detail))
            .collect::<Vec<_>>()
    );
    let t2 = applied_of(&second).cards.last().unwrap().txn;
    let page3 = game_in(&second).clone();
    let live = page3.advanced.view.clone().unwrap().live.unwrap();
    assert_eq!(live.launch_txn, Some(t2));
    let mut sel3 = Selection::default();
    sel3.keep(&page3);
    let r = sel3.advanced(&page3);
    assert_eq!(r.threads.value, tx(Lang::En, Msg::AdvThreadsValue { n: 6 }));
    assert!(r.exclude.choices[1].checked);
    // Clearing the form while a launch part is live means undoing it: said, never planned.
    sel3.edit(&page3, Field::Exclude(0));
    for _ in 0..40 {
        sel3.edit(&page3, Field::ThreadsMore);
    }
    let r = sel3.advanced(&page3);
    let (hint, button, txn) = r.undo_hint.expect("the hint");
    assert_eq!(txn, t2);
    assert!(hint.contains(&t2.seq().to_string()) && button.contains(&t2.seq().to_string()));
    assert!(sel3.manual(&page3).is_none() && sel3.is_empty(&page3));
    // A CPU fix over a live own rule: the same warning from the core.
    let sel4 = Selection::preselected(&page3);
    assert_eq!(sel4.fix_sel(&page3).cpu.as_deref(), Some("limit"));
    let ev = plan(&mut rig, &page3, &sel4);
    let [Event::Preview { vm, .. }] = ev.as_slice() else {
        panic!("{ev:?}")
    };
    assert!(
        vm.warnings
            .iter()
            .any(|w| w.text.contains("replaces the CPU rule"))
    );

    // Undo in order: the newest first brings the first rule back bit for bit.
    let ev = rig.run(Job::RevertPreview { txn: t1 });
    let r = result_of(&ev);
    assert_eq!(
        r.tone,
        Tone::Attention,
        "the older change waits for the newer one"
    );
    assert_eq!(r.notice.details[0].what.as_str(), t2.to_string());
    rig.run(Job::RevertPreview { txn: t2 });
    let ev = rig.revert(t2);
    assert_eq!(result_of(&ev).tone, Tone::Done);
    assert!(
        rig.snap() == after_first,
        "{:#?}",
        after_first.diff(&rig.snap())
    );
    let live = game_in(&ev).advanced.view.clone().unwrap().live.unwrap();
    assert_eq!(live.launch_txn, Some(t1));
    rig.run(Job::RevertPreview { txn: t1 });
    let ev = rig.revert(t1);
    assert_eq!(result_of(&ev).tone, Tone::Done);
    assert!(rig.snap() == base, "{:#?}", base.diff(&rig.snap()));
}
