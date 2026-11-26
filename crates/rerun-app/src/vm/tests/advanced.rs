//! The Advanced section as view models (ADR 0029, plan P5-OE "UI"), on values built by hand and
//! on the CPU fixtures of the core, in both languages.
//! - VA1 the live readout in words, from the core's selection on a 5950X-like PC (one cache
//!   group, cores, SMT), a processor group of a large PC, a 32-bit program on it, a hybrid PC, a
//!   rule that selects nothing, an unreadable topology (escaped); core numbers as ranges.
//! - VA2 the thread limit steps through the PC's steps and ends in "no limit".
//! - VA3 what the user changed from what is live: nothing is planned for a form that equals the
//!   live state, a changed launch part replaces it, a cleared one means undoing, a live flag
//!   stays on; the form prefilled from the live state.
//! - VA4 the locks with their reasons: a chosen CPU fix, a fix's flags on the same program,
//!   anti-cheat, a launcher (soft rule and priority), a kept `run` (watch), an unavailable launch;
//!   what becomes forbidden is dropped from the form.
//! - VA5 the form's problems before any plan, and the program of a Topo that names none.
//! - VA6 the own settings in words (cards, history), and what the worker accepts.

use rerun_core::exec::LiveManual;
use rerun_core::flow::{AdvancedStart, AdvancedView, Bitness, rule_view};
use rerun_core::hw::CpuTopology;
use rerun_core::journal::TxnId;
use rerun_core::path::RelPath;
use rerun_core::plan::{Manual, ManualLaunch, ManualMethod};
use rerun_core::policy::registry::TokenName;
use rerun_core::prim::{CpuRuleSpec, ExcludeFirstSpec, ModeSpec, PrioritySpec};
use rerun_core::topo::LaunchProblem;

use crate::text::{Lang, Msg, t};
use crate::vm::{AdvancedVm, Field, FixSel, Form, LockWhy, Locks, Problem, manual_lines, readout};

const R5950X: &str = include_str!("../../../../../tests/fixtures/cpu/ryzen9-5950x.json");
const TR7980X: &str = include_str!("../../../../../tests/fixtures/cpu/threadripper-7980x.json");
const I9: &str = include_str!("../../../../../tests/fixtures/cpu/i9-14900k.json");

fn txn(seq: u32) -> TxnId {
    format!("{seq:08}-0123456789abcdef").parse().unwrap()
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn tok(s: &str) -> TokenName {
    TokenName::parse(s).unwrap()
}

fn topo(json: &str) -> Result<CpuTopology, String> {
    Ok(serde_json::from_str(json).unwrap())
}

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// The view of a game whose Topo starts `FFLauncher.exe` (a launcher) with the main program
/// `game.exe`, on a 32-processor PC.
fn view() -> AdvancedView {
    AdvancedView {
        main_exe: Some(rel("game.exe")),
        bitness: Bitness::X64,
        start: AdvancedStart::Topo(rel("FFLauncher.exe")),
        default_method: ManualMethod::Direct,
        anti_cheat: false,
        kept_run: false,
        rule_txn: None,
        tokens: &["DISABLEDXMAXIMIZEDWINDOWEDMODE", "HIGHDPIAWARE"],
        live: None,
        logical: Some(32),
        steps: vec![1, 2, 4, 8, 16, 31],
        hybrid: false,
    }
}

fn vm(v: AdvancedView, lang: Lang) -> AdvancedVm {
    AdvancedVm {
        view: Some(v),
        lang,
    }
}

fn live(manual: Manual, launch: Option<u32>, flags: &[(&str, u32)]) -> LiveManual {
    LiveManual {
        txn: txn(9),
        manual,
        launch_txn: launch.map(txn),
        flags: flags.iter().map(|(t, n)| (tok(t), txn(*n))).collect(),
    }
}

fn rule(n: u16) -> Manual {
    Manual {
        launch: Some(ManualLaunch {
            cpu: Some(CpuRuleSpec {
                max_threads: Some(n),
                ..CpuRuleSpec::default()
            }),
            ..ManualLaunch::default()
        }),
        ..Manual::default()
    }
}

fn press(f: &mut Form, a: &AdvancedVm, fixes: &FixSel, fields: &[Field]) {
    for x in fields {
        f.edit(a, fixes, *x);
    }
}

#[test]
fn va1_the_readout_in_words() {
    let rule5950 = CpuRuleSpec {
        max_threads: Some(8),
        single_l3: Some(true),
        smt: Some(false),
        ..CpuRuleSpec::default()
    };
    for lang in Lang::ALL {
        let en = lang == Lang::En;
        let r = readout(&rule_view(&topo(R5950X), &rule5950, Bitness::X64), lang);
        assert_eq!(
            r.line,
            if en {
                "8 of 32 logical processors: cache group 0 (L3, 32 MB), cores 0\u{2013}7, without SMT"
            } else {
                "8 von 32 logischen Prozessoren: Cache-Gruppe 0 (L3, 32 MB), Kerne 0\u{2013}7, ohne SMT"
            }
        );
        assert!(r.note.is_none() && r.detail.is_none());
        // Both threads of the cores of one cache group, and a single core.
        let group = CpuRuleSpec {
            single_l3: Some(true),
            ..CpuRuleSpec::default()
        };
        let r = readout(&rule_view(&topo(R5950X), &group, Bitness::X64), lang);
        assert!(
            r.line.ends_with(if en { "with SMT" } else { "mit SMT" }),
            "{}",
            r.line
        );
        assert!(r.line.contains("0\u{2013}7"), "{}", r.line);
        let one = CpuRuleSpec {
            max_threads: Some(1),
            ..CpuRuleSpec::default()
        };
        let r = readout(&rule_view(&topo(R5950X), &one, Bitness::X64), lang);
        assert!(
            r.line.contains(if en { "core 0" } else { "Kern 0" }),
            "{}",
            r.line
        );
        assert!(
            r.line
                .ends_with(if en { "without SMT" } else { "ohne SMT" }),
            "{}",
            r.line
        );
        // Several processor groups: the group is named; a 32-bit program is capped.
        let any = CpuRuleSpec {
            smt: Some(true),
            ..CpuRuleSpec::default()
        };
        let r = readout(&rule_view(&topo(TR7980X), &any, Bitness::X86), lang);
        assert!(
            r.line.contains(if en {
                "processor group"
            } else {
                "Prozessorgruppe"
            }),
            "{}",
            r.line
        );
        assert!(r.note.unwrap().contains("32"));
        // A hybrid PC with the performance cores.
        let perf = CpuRuleSpec {
            prefer: Some(rerun_core::prim::PreferSpec::Performance),
            ..CpuRuleSpec::default()
        };
        let r = readout(&rule_view(&topo(I9), &perf, Bitness::X64), lang);
        assert!(
            r.line.contains(if en {
                "logical processors"
            } else {
                "logischen Prozessoren"
            }),
            "{}",
            r.line
        );
        // The topology cannot be read: the reason is its own element, escaped.
        let r = readout(
            &rule_view(
                &Err("no topology \u{1b}[31m".to_owned()),
                &rule5950,
                Bitness::X64,
            ),
            lang,
        );
        assert_eq!(r.line, tx(lang, Msg::AdvReadTopology));
        assert!(!r.detail.unwrap().as_str().contains('\u{1b}'));
        // No rule at all.
        let r = readout(
            &rule_view(&topo(R5950X), &CpuRuleSpec::default(), Bitness::X64),
            lang,
        );
        assert!(!r.line.is_empty());
    }
}

#[test]
fn va2_the_thread_limit_steps_through_the_steps_of_this_pc() {
    let a = vm(view(), Lang::En);
    let fixes = FixSel::default();
    let mut f = Form::default();
    let value = |f: &Form| a.render(f, &fixes).threads.value;
    assert_eq!(value(&f), "No limit");
    // Less from "no limit" goes to the last step, then down; the first step is the floor.
    press(&mut f, &a, &fixes, &[Field::ThreadsLess]);
    assert_eq!(value(&f), "31 threads");
    for want in [
        "16 threads",
        "8 threads",
        "4 threads",
        "2 threads",
        "1 thread",
        "1 thread",
    ] {
        press(&mut f, &a, &fixes, &[Field::ThreadsLess]);
        assert_eq!(value(&f), want);
    }
    assert!(!a.render(&f, &fixes).threads.less_on, "nothing below 1");
    // More goes up and ends in "no limit".
    for want in [
        "2 threads",
        "4 threads",
        "8 threads",
        "16 threads",
        "31 threads",
        "No limit",
    ] {
        press(&mut f, &a, &fixes, &[Field::ThreadsMore]);
        assert_eq!(value(&f), want);
    }
    assert!(!a.render(&f, &fixes).threads.more_on && a.render(&f, &fixes).threads.less_on);
    // German words.
    let de = vm(view(), Lang::De);
    let r = de.render(&Form::default(), &fixes);
    assert_eq!(r.threads.value, "Keine Begrenzung");
    assert_eq!(r.threads.less, "Maximale Threads: weniger");
}

#[test]
fn va3_what_changed_from_what_is_live() {
    for lang in Lang::ALL {
        let mut v = view();
        v.live = Some(live(rule(8), Some(5), &[("HIGHDPIAWARE", 6)]));
        v.rule_txn = Some(txn(5));
        let a = vm(v, lang);
        let fixes = FixSel::default();
        // Prefilled: shown, not planned again.
        let mut f = Form::prefilled(&a);
        let r = a.render(&f, &fixes);
        assert_eq!(r.threads.value, tx(lang, Msg::AdvThreadsValue { n: 8 }));
        assert_eq!(r.active, Some(tx(lang, Msg::AdvActive { n: 5 })));
        assert_eq!(f.input(&a, &fixes).manual, None);
        // A live flag is on and stays on; the other one can be added.
        assert!(r.flags[1].checked && !r.flags[1].enabled);
        assert_eq!(
            r.flags[1].note.as_ref().unwrap().flat(),
            tx(lang, Msg::AdvFlagActive { n: 6 })
        );
        press(&mut f, &a, &fixes, &[Field::Flag(1)]);
        assert!(a.render(&f, &fixes).flags[1].checked);
        assert_eq!(f.input(&a, &fixes).manual, None, "a live flag is no change");
        press(&mut f, &a, &fixes, &[Field::Flag(0)]);
        let m = f.input(&a, &fixes).manual.unwrap();
        assert!(m.launch.is_none(), "the launch part did not change");
        assert_eq!(m.layers, [tok("DISABLEDXMAXIMIZEDWINDOWEDMODE")]);
        press(&mut f, &a, &fixes, &[Field::Flag(0)]);
        // A changed number replaces the live rule: planned, with the note about it.
        press(&mut f, &a, &fixes, &[Field::ThreadsLess]);
        let m = f.input(&a, &fixes).manual.unwrap();
        assert_eq!(m.launch.unwrap().cpu.unwrap().max_threads, Some(4));
        assert!(m.layers.is_empty());
        assert_eq!(
            a.render(&f, &fixes).replaces,
            Some(tx(lang, Msg::AdvReplaces { n: 5 }))
        );
        // Back to what is live: nothing to plan.
        press(&mut f, &a, &fixes, &[Field::ThreadsMore]);
        assert_eq!(f.input(&a, &fixes).manual, None);
        // Cleared: that would mean undoing the change; nothing is planned.
        let mut f = Form::prefilled(&a);
        for _ in 0..6 {
            press(&mut f, &a, &fixes, &[Field::ThreadsMore]);
        }
        let i = f.input(&a, &fixes);
        assert_eq!((i.manual, i.clearing), (None, Some(txn(5))));
        let (hint, button, t) = a.render(&f, &fixes).undo_hint.unwrap();
        assert_eq!(t, txn(5));
        assert_eq!(hint, tx(lang, Msg::AdvUndoHint { n: 5 }));
        assert_eq!(button, tx(lang, Msg::OptUndoBtn { n: 5 }));
        // A page read again after a write: an untouched form shows what is live now, a touched
        // one keeps what was typed.
        let mut g = Form::default();
        g.keep(&a);
        assert_eq!(
            a.render(&g, &fixes).threads.value,
            tx(lang, Msg::AdvThreadsValue { n: 8 })
        );
        let mut g = Form::prefilled(&a);
        press(&mut g, &a, &fixes, &[Field::Smt(false)]);
        g.keep(&a);
        assert!(
            !a.render(&g, &fixes).smt.checked,
            "typed values survive a refresh"
        );
    }
}

#[test]
fn va4_the_locks_with_their_reasons() {
    for lang in Lang::ALL {
        let en = lang == Lang::En;
        // A chosen CPU fix: the whole launch part, with the fix named; the part stays in the form
        // and comes back when the fix is unticked, but is never part of the plan meanwhile.
        let a = vm(view(), lang);
        let mut f = Form::default();
        press(&mut f, &a, &FixSel::default(), &[Field::Smt(false)]);
        let fix = FixSel {
            cpu: Some("limit".to_owned()),
            layer: None,
        };
        let r = a.render(&f, &fix);
        assert!(
            !r.smt.enabled && !r.l3.enabled && !r.threads.less_on && !r.exclude.choices[1].enabled
        );
        let note = r.launch_note.unwrap();
        assert_eq!(note.name.as_ref().unwrap().as_str(), "limit");
        assert!(note.before.contains(if en {
            "choose one of them"
        } else {
            "wähle eines davon"
        }));
        assert_eq!(f.input(&a, &fix).manual, None);
        assert_eq!(f.readout_rule(&a, &fix), None);
        assert_eq!(
            a.readout_local(&f, &fix).unwrap().line,
            tx(lang, Msg::AdvReadLocked)
        );
        press(&mut f, &a, &fix, &[Field::Smt(true)]);
        assert!(
            !a.render(&f, &fix).smt.checked,
            "a locked field cannot be changed"
        );
        assert!(
            f.input(&a, &FixSel::default()).manual.is_some(),
            "unticked: back"
        );
        // Flags are not part of that lock; a fix's flags for the main program lock only them.
        let both = FixSel {
            cpu: None,
            layer: Some("dpi-fix".to_owned()),
        };
        let r = a.render(&f, &both);
        assert!(r.flags.iter().all(|x| !x.enabled) && r.smt.enabled);
        assert_eq!(r.flags_note.unwrap().name.unwrap().as_str(), "dpi-fix");
        let mut g = Form::default();
        press(&mut g, &a, &both, &[Field::Flag(0)]);
        assert_eq!(g.input(&a, &both).manual, None);

        // Anti-cheat: `watch` and flags are locked, a `direct` rule is not.
        let mut v = view();
        v.anti_cheat = true;
        let ac = vm(v, lang);
        let none = FixSel::default();
        let mut f = Form::default();
        press(
            &mut f,
            &ac,
            &none,
            &[Field::Method(2), Field::Flag(0), Field::Smt(false)],
        );
        let m = f.input(&ac, &none).manual.unwrap();
        assert_eq!(m.launch.unwrap().method, None);
        assert!(m.layers.is_empty());
        let r = ac.render(&f, &none);
        assert!(!r.method.choices[2].enabled && r.flags.iter().all(|x| !x.enabled));
        assert_eq!(
            r.method.note.unwrap().flat(),
            tx(lang, Msg::AdvLockAntiCheat)
        );

        // The launcher case: Steam starts a launcher, so a soft rule and a priority are off with
        // `direct`; `watch` reaches the game and frees them; back to `direct` drops them.
        let a = vm(view(), lang);
        let mut f = Form::default();
        let r = a.render(&f, &none);
        assert!(!r.priority.choices[2].enabled && !r.mode.choices[1].enabled);
        assert_eq!(r.mode.note.unwrap().flat(), tx(lang, Msg::AdvLockLauncher));
        press(&mut f, &a, &none, &[Field::Priority(2), Field::Mode(1)]);
        assert_eq!(f.input(&a, &none).manual, None, "locked, nothing was set");
        press(
            &mut f,
            &a,
            &none,
            &[
                Field::Method(2),
                Field::Priority(2),
                Field::Mode(1),
                Field::Smt(false),
            ],
        );
        let l = f.input(&a, &none).manual.unwrap().launch.unwrap();
        assert_eq!(
            (l.method, l.priority, l.cpu.unwrap().mode),
            (
                Some(ManualMethod::Watch),
                Some(PrioritySpec::AboveNormal),
                Some(ModeSpec::Soft)
            )
        );
        press(&mut f, &a, &none, &[Field::Method(1)]);
        let l = f.input(&a, &none).manual.unwrap().launch.unwrap();
        assert_eq!(
            (l.priority, l.cpu.unwrap().mode),
            (None, None),
            "dropped, not hidden"
        );
        // Steam starts the main program: nothing is off.
        let mut v = view();
        v.start = AdvancedStart::Topo(rel("Game.exe"));
        let main = vm(v, lang);
        assert_eq!(
            Form::default().locks(main.view.as_ref().unwrap(), &none),
            Locks::default()
        );

        // A kept `run` (an option value starts another program): no `watch`, everything else free.
        let mut v = view();
        v.kept_run = true;
        let run = vm(v, lang);
        let l = Form::default().locks(run.view.as_ref().unwrap(), &none);
        assert_eq!(
            (l.watch, l.soft, l.priority),
            (Some(LockWhy::Run), None, None)
        );
        assert_eq!(
            run.render(&Form::default(), &none)
                .method
                .note
                .unwrap()
                .flat(),
            tx(lang, Msg::AdvLockRun)
        );

        // A launch method of a later phase: no own launch part, flags still work.
        let mut v = view();
        v.start = AdvancedStart::Unavailable(LaunchProblem::NotYet("hold"));
        let hold = vm(v, lang);
        let mut f = Form::default();
        press(&mut f, &hold, &none, &[Field::Smt(false), Field::Flag(0)]);
        let m = f.input(&hold, &none).manual.unwrap();
        assert!(m.launch.is_none() && m.layers.len() == 1);
        assert_eq!(
            hold.render(&f, &none).unavailable,
            Some(tx(lang, Msg::AdvUnavailable))
        );
    }
}

#[test]
fn va5_problems_before_any_plan_and_the_program_of_a_topo_without_a_start() {
    for lang in Lang::ALL {
        let mut v = view();
        v.start = AdvancedStart::Choose(vec![rel("game.exe"), rel(r"bin\launcher.exe")]);
        let a = vm(v, lang);
        let none = FixSel::default();
        let r = a.render(&Form::default(), &none);
        let g = r.start.unwrap();
        assert_eq!(g.choices.len(), 2);
        assert_eq!(g.choices[1].label.as_str(), r"bin\launcher.exe");
        assert!(g.choices.iter().all(|c| !c.checked && c.enabled));
        // A rule without the program.
        let mut f = Form::default();
        press(&mut f, &a, &none, &[Field::Smt(false)]);
        let i = f.input(&a, &none);
        assert_eq!((i.manual, i.problem), (None, Some(Problem::NeedsStart)));
        assert_eq!(
            a.render(&f, &none).problem.unwrap().flat(),
            tx(lang, Msg::AdvNeedsStart)
        );
        // With a launcher as the program, a priority is off (it would reach only the launcher).
        press(&mut f, &a, &none, &[Field::Start(1)]);
        assert!(!a.render(&f, &none).priority.choices[1].enabled);
        let m = f.input(&a, &none).manual.unwrap();
        assert_eq!(m.launch.unwrap().start, Some(rel(r"bin\launcher.exe")));
        // With the main program it is on.
        press(&mut f, &a, &none, &[Field::Start(0)]);
        assert!(a.render(&f, &none).priority.choices[1].enabled);
        // A start that is gone on the next page is dropped.
        let mut v = view();
        v.start = AdvancedStart::Choose(vec![rel("game.exe")]);
        let b = vm(v, lang);
        press(&mut f, &a, &none, &[Field::Start(1)]);
        f.keep(&b);
        assert_eq!(f.input(&b, &none).problem, Some(Problem::NeedsStart));
        // The form's own problems.
        let mut f = Form::default();
        press(&mut f, &a, &none, &[Field::Method(1)]);
        assert_eq!(f.input(&a, &none).problem, Some(Problem::NoRule));
        let mut f = Form::default();
        press(&mut f, &a, &none, &[Field::Start(0), Field::Mode(1)]);
        let i = f.input(&a, &none);
        assert_eq!((i.manual, i.problem), (None, Some(Problem::NoRestriction)));
        assert_eq!(
            a.render(&f, &none).problem.unwrap().flat(),
            tx(lang, Msg::AdvErrNoRestriction)
        );
        // Performance cores are offered only where the PC has them.
        assert!(a.render(&f, &none).prefer.is_none());
        let mut v = view();
        v.hybrid = true;
        let h = vm(v, lang);
        assert!(h.render(&Form::default(), &none).prefer.is_some());
        let mut f = Form::default();
        press(&mut f, &h, &none, &[Field::Prefer(1), Field::Exclude(2)]);
        let c = f
            .input(&h, &none)
            .manual
            .unwrap()
            .launch
            .unwrap()
            .cpu
            .unwrap();
        assert_eq!(
            (c.prefer, c.exclude_first),
            (
                Some(rerun_core::prim::PreferSpec::Performance),
                Some(ExcludeFirstSpec::Core)
            )
        );
    }
}

#[test]
fn va6_own_settings_in_words_and_what_the_worker_accepts() {
    for lang in Lang::ALL {
        let m = Manual {
            launch: Some(ManualLaunch {
                method: Some(ManualMethod::Watch),
                cpu: Some(CpuRuleSpec {
                    max_threads: Some(8),
                    smt: Some(false),
                    single_l3: Some(true),
                    exclude_first: Some(ExcludeFirstSpec::Thread),
                    mode: Some(ModeSpec::Soft),
                    ..CpuRuleSpec::default()
                }),
                priority: Some(PrioritySpec::High),
                ..ManualLaunch::default()
            }),
            layers: vec![tok("HIGHDPIAWARE"), tok("DISABLEDXMAXIMIZEDWINDOWEDMODE")],
            ..Manual::default()
        };
        let lines = manual_lines(&m, lang);
        assert_eq!(lines.len(), 2);
        let want = [
            tx(lang, Msg::AdvSumThreads { n: 8 }),
            tx(lang, Msg::AdvSumNoSmt),
            tx(lang, Msg::AdvSumL3),
            tx(lang, Msg::AdvSumExclude { core: false }),
            tx(lang, Msg::AdvSumSoft),
        ];
        for w in &want {
            assert!(lines[0].contains(w.as_str()), "{} / {w}", lines[0]);
        }
        assert!(lines[0].ends_with(&tx(lang, Msg::AdvSumMethod { watch: true })));
        assert_eq!(lines[1], tx(lang, Msg::AdvSumFlags { n: 2 }));
        assert!(manual_lines(&Manual::default(), lang).is_empty());
        assert_eq!(
            crate::vm::own_settings(Some(&m), lang).unwrap().title,
            tx(lang, Msg::AdvSumTitle)
        );
        assert!(crate::vm::own_settings(None, lang).is_none());
    }
}
