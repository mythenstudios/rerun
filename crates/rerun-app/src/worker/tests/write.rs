//! The write side through the worker (P5-5a, ADR 0027 amendment P5-5a): select, preview, apply,
//! undo, in the fake world, without a window. Every ID, step and hash is invented.
//! - AW12 the selection rules: preselection (verified and affects this PC only), fixes of one
//!   problem exclude each other, a fix that solves two problems is selected and picked once,
//!   fixes that need the helper or a download or that the core refuses cannot be selected.
//! - AW13 the preview lists every change and stores nothing; an apply needs the shown preview
//!   with exactly its hash; apply then undo through the worker leaves the game folder and the
//!   launch profiles bit-identical; a game changed since the preview and a state changed since
//!   the undo preview are calm and write nothing; a game in use refuses and the preview stays;
//!   a foreign change offers "close without undoing".
//! - AW14 the session: a plan reads the executables again, a plan for a game that reads
//!   differently now hands the page back; the window cannot close while a write is queued or
//!   runs.

use std::path::Path;
use std::sync::Mutex;
use std::sync::mpsc;

use rerun_core::journal::TxnId;
use rerun_core::plan::Pick;
use rerun_core::sys::System;
use rerun_core::sys::fake::Prim;
use rerun_core::sys::fs::Fs;
use rerun_core::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};

use super::*;
use crate::vm::{
    DialogKind, DialogVm, Offer, PreviewVm, ResultVm, Selection, Tone, TxnCardVm, Value,
};

const WRITE_INI: &str = "[Display]\r\nWidth=800\r\n";
const RERUN: &str = r"C:\Users\Player\AppData\Local\Rerun";

/// The Topo of the write tests: `limit` and `limit-4` are two answers to one problem; `ini`
/// solves two problems with identical steps; `layer` is verified but its problem does not
/// affect this PC; `block` needs the helper.
fn write_index(sha: &str) -> String {
    let ini = r#"{"ini_set":{"file":"game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}"#;
    let layer = r#"{"compat_layer":{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}"#;
    let repo = r#"{"type":"repo","url":"https://github.com/example/patch"}"#;
    let wiki = r#"{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented_W"}"#;
    format!(
        r#"{{"format":1,"seq":8,"issued":"2026-11-12T12:00:00Z","topos":[{{"format":1,"id":"invented-w","title":"Invented W","status":"active","rev":2,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"launch":{{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}},
"issues":[
 {{"id":"crash","title":"The game crashes with many cores","variants":[
   {{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8}}}}],"tradeoffs":["uses fewer cores"]}},
   {{"id":"limit-4","status":"reported","kind":"fix","steps":[{{"cpu":{{"max_threads":4}}}}]}}]}},
 {{"id":"display","title":"Wrong resolution","variants":[{{"id":"ini","status":"verified","kind":"fix","steps":[{ini}],"sources":[{repo}]}}]}},
 {{"id":"menu","title":"Menu glitch","variants":[{{"id":"ini","status":"unverified","kind":"fix","steps":[{ini}],"sources":[{wiki}]}}]}},
 {{"id":"online","title":"Online services are gone","when":{{"gpu.vendor":"nvidia"}},"variants":[{{"id":"layer","status":"verified","kind":"fix","steps":[{layer}]}}]}},
 {{"id":"net","title":"The game phones home","variants":[{{"id":"block","status":"verified","kind":"fix","steps":[{{"firewall_rule":{{"exe":"game.exe","direction":"out"}}}}]}}]}}
]}}],"packages":[]}}"#
    )
}

/// Steam with the game and its `game.ini`, the write Topo imported.
fn write_world() -> FakeSystem {
    let sys = steam_world("Invented W");
    sys.fake_fs()
        .put_file(Path::new(&format!(r"{G}\game.ini")), WRITE_INI.as_bytes())
        .unwrap();
    let ix = write_index(&sha256_of(&sys, "game.exe"));
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    catalog::store::import(
        &app,
        ix.as_bytes(),
        &test_key::sign(ix.as_bytes()),
        &catalog::trusted_keys(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    drop(app);
    sys.fake_fs().sync_all();
    sys
}

/// A world, a session and a language: jobs run as the worker thread runs them.
struct Rig {
    sys: FakeSystem,
    session: Session,
    lang: Lang,
    /// The nonce of the last dialog the worker showed (what a confirm click carries).
    nonce: u64,
}

impl Rig {
    fn new(lang: Lang) -> Self {
        Self {
            sys: write_world(),
            session: Session::default(),
            lang,
            nonce: 0,
        }
    }

    fn run(&mut self, job: Job) -> Vec<Event> {
        let http = FakeHttp::default();
        let install = install();
        let env = Env {
            sys: &self.sys,
            http: &http,
            install: &install,
        };
        let mut out = Vec::new();
        let _ = run_in(
            env,
            &job,
            self.lang,
            &mut self.session,
            &mut || None,
            &mut |e| {
                out.push(e);
            },
        );
        if let Some(Event::Dialog(d)) = out.iter().rev().find(|e| matches!(e, Event::Dialog(_))) {
            self.nonce = d.nonce;
        }
        out
    }

    /// The click on "Undo this change" of the dialog last shown.
    fn revert(&mut self, txn: TxnId) -> Vec<Event> {
        let nonce = self.nonce;
        self.run(Job::Revert { txn, nonce })
    }

    /// The click on "Close without undoing" of the dialog last shown.
    fn forget(&mut self, txn: TxnId) -> Vec<Event> {
        let nonce = self.nonce;
        self.run(Job::Forget { txn, nonce })
    }

    fn page(&mut self) -> GameVm {
        let ev = self.run(Job::Game {
            app_id: 220,
            name: Some(escape::text("Invented W").into_owned()),
        });
        match ev.as_slice() {
            [Event::Game(g)] => g.clone(),
            other => panic!("{other:?}"),
        }
    }

    /// The game folder: what an undo must restore bit for bit.
    fn snap(&self) -> Snapshot {
        let fr = ForbiddenRoots::resolve(&self.sys, Path::new(INSTALL)).unwrap();
        let g = GameDir::open_manual(&self.sys, &fr, Path::new(G)).unwrap();
        snapshot(
            System::registry(&self.sys),
            &Scope {
                dirs: vec![SnapRoot::new(g.dir(), G)],
                keys: Vec::new(),
            },
        )
        .unwrap()
    }

    /// Rerun's whole folder: plans, journal, index.
    fn snap_app(&self) -> Snapshot {
        let app = AppDir::open(&self.sys, Create::Never).unwrap().unwrap();
        snapshot(
            System::registry(&self.sys),
            &Scope {
                dirs: vec![SnapRoot::new(app.dir(), "app")],
                keys: Vec::new(),
            },
        )
        .unwrap()
    }

    #[allow(clippy::disallowed_methods, reason = "test: read a fixture file")]
    fn try_read(&self, abs: &str) -> Option<Vec<u8>> {
        let p = Path::new(abs);
        let d = self.sys.fake_fs().open_dir(p.parent()?).ok()?;
        d.read(&RelPath::parse(&p.file_name()?.to_string_lossy()).ok()?)
            .ok()
    }

    fn read(&self, abs: &str) -> Vec<u8> {
        self.try_read(abs)
            .unwrap_or_else(|| panic!("{abs} is missing"))
    }

    /// Plans the preselection and hands the preview over (the window did render it).
    fn preview(&mut self) -> PreviewVm {
        let page = self.page();
        let picks = Selection::preselected(&page).picks(&page);
        self.preview_of(picks)
    }

    fn preview_of(&mut self, picks: Vec<Pick>) -> PreviewVm {
        let ev = self.run(Job::Plan { app_id: 220, picks });
        let pv = match ev.as_slice() {
            [Event::Preview { vm, .. }] => (**vm).clone(),
            other => panic!("{other:?}"),
        };
        let ready = self.run(Job::PreviewShown {
            hash: pv.hash.clone(),
        });
        assert_eq!(
            ready,
            [Event::PreviewReady {
                hash: pv.hash.clone()
            }]
        );
        pv
    }
}

fn result_of(ev: &[Event]) -> &ResultVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Result(r) => Some(r),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no result in {ev:?}"))
}

fn dialog_of(ev: &[Event]) -> &DialogVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Dialog(d) => Some(&**d),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no dialog in {ev:?}"))
}

fn applied_of(ev: &[Event]) -> &vm::AppliedVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Applied(a) => Some(a),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no applied page in {ev:?}"))
}

fn game_in(ev: &[Event]) -> &GameVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Game(g) => Some(g),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no game page in {ev:?}"))
}

fn pick(issue: &str, variant: &str) -> Pick {
    Pick {
        issue: issue.to_owned(),
        variant: variant.to_owned(),
    }
}

/// The file name of the launch profile on a card.
fn profile_of(card: &TxnCardVm) -> String {
    card.ops
        .iter()
        .find(|o| o.target.as_str().ends_with(".profile"))
        .expect("the profile op")
        .target
        .as_str()
        .to_owned()
}

fn keys(g: &GameVm) -> Vec<&str> {
    g.fixes.iter().map(|f| f.key.as_str()).collect()
}

// ---------- AW12 the selection ----------

#[test]
fn aw12_the_preselection_is_verified_and_affects_this_pc() {
    let mut rig = Rig::new(Lang::En);
    let g = rig.page();
    assert_eq!(keys(&g), ["limit", "limit-4", "ini", "layer", "block"]);
    let offers: Vec<Offer> = g.fixes.iter().map(|f| f.offer).collect();
    assert_eq!(
        offers,
        [
            Offer::Selectable,
            Offer::Selectable,
            Offer::Selectable,
            Offer::Selectable,
            Offer::NeedsHelper
        ]
    );
    // `limit` and `ini` are verified for a problem that affects this PC; `limit-4` is only
    // reported; `layer` is verified but its problem does not affect this PC; `block` is verified
    // and affects it, but needs the helper.
    let pre: Vec<bool> = g.fixes.iter().map(|f| f.preselect).collect();
    assert_eq!(pre, [true, false, true, false, false]);
    let sel = Selection::preselected(&g);
    assert_eq!(
        sel.picks(&g),
        [pick("crash", "limit"), pick("display", "ini")]
    );
    assert_eq!(sel.flags(&g), [true, false, true, false, false]);
    assert!(g.fixes[0].preselect_note.is_some() && g.fixes[1].preselect_note.is_none());
}

#[test]
fn aw12_fixes_of_one_problem_exclude_each_other() {
    let mut rig = Rig::new(Lang::En);
    let g = rig.page();
    assert_eq!(g.fixes[0].conflicts, [1]);
    assert_eq!(g.fixes[1].conflicts, [0]);
    assert_eq!(
        g.fixes[0]
            .exclusive
            .iter()
            .map(|e| e.as_str())
            .collect::<Vec<_>>(),
        ["limit-4"]
    );
    assert!(g.fixes[2].conflicts.is_empty() && g.fixes[3].conflicts.is_empty());

    let mut sel = Selection::preselected(&g);
    sel.toggle(&g, 1);
    assert!(sel.contains("limit-4") && !sel.contains("limit"), "{sel:?}");
    assert_eq!(
        sel.picks(&g),
        [pick("crash", "limit-4"), pick("display", "ini")]
    );
    sel.toggle(&g, 0);
    assert!(sel.contains("limit") && !sel.contains("limit-4"));
    // Deselecting is plain.
    sel.toggle(&g, 0);
    assert!(!sel.contains("limit"));
    // The unrelated fix is picked for its own problem and does not disturb the others.
    sel.toggle(&g, 3);
    assert_eq!(
        sel.picks(&g),
        [pick("display", "ini"), pick("online", "layer")]
    );
}

#[test]
fn aw12_a_fix_for_two_problems_is_selected_and_picked_once() {
    let mut rig = Rig::new(Lang::En);
    let g = rig.page();
    let ini = &g.fixes[2];
    assert_eq!(ini.solves.len(), 2, "one fix, two solved problems");
    // Picked for the problem it is verified for, which affects this PC.
    assert_eq!(ini.pick_issue, "display");
    let mut sel = Selection::default();
    sel.toggle(&g, 2);
    let picks = sel.picks(&g);
    assert_eq!(picks, [pick("display", "ini")]);
    // The evidence stays per problem: tradeoffs and sources of each copy.
    assert_eq!(
        g.fixes[0].solves[0]
            .tradeoffs
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>(),
        ["uses fewer cores"]
    );
    let sources: Vec<Vec<&str>> = ini
        .solves
        .iter()
        .map(|s| s.sources.iter().map(|x| x.as_str()).collect())
        .collect();
    assert_eq!(
        sources,
        [
            vec!["Repository: https://github.com/example/patch"],
            vec!["PCGamingWiki: https://www.pcgamingwiki.com/wiki/Invented_W"]
        ]
    );
}

#[test]
fn aw12_a_fix_that_needs_the_helper_or_that_the_core_refuses_cannot_be_selected() {
    for lang in Lang::ALL {
        let mut rig = Rig::new(lang);
        let g = rig.page();
        let block = &g.fixes[4];
        assert_eq!(block.offer, Offer::NeedsHelper);
        let note = block.note.as_deref().unwrap();
        assert!(
            note.contains(match lang {
                Lang::En => "administrator helper",
                Lang::De => "Administrator-Helfer",
            }),
            "{note}"
        );
        let mut sel = Selection::preselected(&g);
        let before = sel.clone();
        sel.toggle(&g, 4);
        assert_eq!(sel, before, "the helper fix cannot be selected");
        assert!(!sel.contains("block"));
    }

    // Anti-cheat refuses the compatibility layer and the firewall rule (aw1: per variant):
    // shown with the reason, not selectable.
    let mut rig = Rig::new(Lang::En);
    rig.sys
        .fake_fs()
        .mkdir_all(Path::new(&format!(r"{G}\BattlEye")))
        .unwrap();
    rig.sys.fake_fs().sync_all();
    let g = rig.page();
    for i in [3, 4] {
        assert_eq!(g.fixes[i].offer, Offer::Refused, "{}", g.fixes[i].key);
        assert!(g.fixes[i].refused.is_some() && g.fixes[i].note.is_none());
    }
    let mut sel = Selection::preselected(&g);
    let before = sel.clone();
    sel.toggle(&g, 3);
    sel.toggle(&g, 4);
    assert_eq!(sel, before, "a refused fix cannot be selected");
}

// ---------- AW13 preview, apply, undo ----------

#[test]
fn aw13_the_preview_lists_every_change_and_stores_nothing() {
    let mut rig = Rig::new(Lang::En);
    let page = rig.page();
    let picks = Selection::preselected(&page).picks(&page);
    let app_before = rig.snap_app();
    let before = rig.snap();
    rig.sys.fake_fs().record_calls(true);
    let ev = rig.run(Job::Plan { app_id: 220, picks });
    let calls = rig.sys.fake_fs().take_calls();
    assert!(!calls.is_empty());
    assert!(
        !calls.iter().any(|c| matches!(
            c,
            Prim::CreateTmp
                | Prim::CreateDir
                | Prim::Rename
                | Prim::Write
                | Prim::SetAttrs
                | Prim::PosixDelete
        )),
        "planning wrote nothing: {calls:?}"
    );
    // Neither Rerun's folder (no plan stored: S6) nor the game folder changed.
    assert!(rig.snap_app() == app_before && rig.snap() == before);
    let [Event::Preview { app_id: 220, vm }] = ev.as_slice() else {
        panic!("{ev:?}");
    };
    assert_eq!(vm.hash.len(), 64);
    assert!(vm.can_apply && vm.nothing.is_none());
    assert_eq!(
        vm.summary
            .split(' ')
            .next()
            .map(|n| n.parse::<usize>().is_ok()),
        Some(true)
    );
    assert_eq!(vm.folder.as_ref().map(|f| f.as_str()), Some(G));
    // The INI key: its file, section, key, old and new value, each in its own element.
    let ini = vm
        .ops
        .iter()
        .find(|o| o.action == "Edit INI file")
        .expect("the INI op");
    assert_eq!(ini.target.as_str(), "game.ini");
    let key = ini.lines.iter().find(|l| l.label == "Key").unwrap();
    let vals: Vec<&str> = key.values.iter().map(Value::as_str).collect();
    assert_eq!(vals, ["Display", "Width"]);
    let now = ini.lines.iter().find(|l| l.label == "Now").unwrap();
    let new = ini.lines.iter().find(|l| l.label == "Set to").unwrap();
    assert_eq!(now.values[0].as_str(), "800");
    assert_eq!(new.values[0].as_str(), "1920");
    assert_eq!(
        ini.undo.as_deref(),
        Some("Undo sets back only the keys Rerun changed")
    );
    // The launch profile (the cpu fix): a file in Rerun's profiles folder, with the rule.
    let prof = vm
        .ops
        .iter()
        .find(|o| o.target.as_str().ends_with(".profile"))
        .expect("the profile op");
    assert_eq!(prof.action, "Create file");
    assert!(prof.lines.iter().any(|l| l.label == "Launch profile"));
    assert!(prof.lines.iter().any(|l| l.label == "Limit"));
    assert_eq!(prof.undo.as_deref(), Some("Undo removes it"));
    // The Steam launch option the user pastes, and what is wrong with it here.
    let launch = vm
        .launch
        .as_ref()
        .expect("a launch profile brings a launch option");
    let option = launch.option.as_ref().expect("the option").as_str();
    assert!(
        option.contains("rerun-launch.exe") && option.contains("--profile"),
        "{option}"
    );
    assert!(
        launch.lines[0].starts_with("The game is limited to 8 of 32 threads"),
        "{:?}",
        launch.lines
    );
    assert_eq!(
        launch.problems.len(),
        1,
        "the shim is missing in the fake install folder"
    );
    assert!(
        launch.problems[0]
            .text
            .starts_with("rerun-launch.exe is not in")
    );
    assert_eq!(vm.admin, "Administrator rights: not needed");
    assert!(vm.undo.contains("whole plan back together"));
    assert!(vm.notes.iter().any(|n| n.starts_with("INI files")));
    assert!(vm.notes.iter().any(|n| n.starts_with("Launch profile")));
    assert!(
        vm.notes
            .iter()
            .any(|n| n.starts_with("Undo restores existence"))
    );

    // German: the same plan, every word from the catalogue.
    let mut de = Rig::new(Lang::De);
    let g = de.page();
    let pv = de.run(Job::Plan {
        app_id: 220,
        picks: Selection::preselected(&g).picks(&g),
    });
    let [Event::Preview { vm, .. }] = pv.as_slice() else {
        panic!("{pv:?}");
    };
    assert_eq!(vm.admin, "Administratorrechte: nicht nötig");
    assert!(vm.ops.iter().any(|o| o.action == "INI-Datei bearbeiten"));
    assert!(vm.notes.iter().any(|n| n.starts_with("INI-Dateien")));
}

#[test]
fn aw13_an_apply_needs_the_shown_preview_with_exactly_its_hash() {
    let mut rig = Rig::new(Lang::En);
    let page = rig.page();
    let picks = Selection::preselected(&page).picks(&page);
    let before = rig.snap();
    let ev = rig.run(Job::Plan { app_id: 220, picks });
    let [Event::Preview { vm, .. }] = ev.as_slice() else {
        panic!("{ev:?}");
    };
    let hash = vm.hash.clone();
    // Planned, but the window has not reported the preview rendered: nothing to apply.
    let app = rig.snap_app();
    let ev = rig.run(Job::Apply { hash: hash.clone() });
    assert_eq!(
        result_of(&ev).notice.title,
        "The preview is no longer current"
    );
    assert_eq!(result_of(&ev).tone, Tone::Calm);
    assert!(
        rig.snap() == before && rig.snap_app() == app,
        "nothing stored, nothing written"
    );
    // Rendered; a click that carries another hash applies nothing and keeps the preview.
    rig.run(Job::PreviewShown { hash: hash.clone() });
    let ev = rig.run(Job::Apply {
        hash: "0".repeat(64),
    });
    assert_eq!(
        result_of(&ev).notice.title,
        "The preview is no longer current"
    );
    assert!(rig.snap() == before && rig.snap_app() == app);
    // The right hash still works afterwards.
    let ev = rig.run(Job::Apply { hash });
    assert_eq!(result_of(&ev).tone, Tone::Done, "{ev:?}");
    assert!(rig.snap() != before);
}

fn dialog_ops(d: &DialogVm) -> Vec<(&str, Option<&str>)> {
    d.ops
        .iter()
        .map(|o| (o.action.as_str(), o.fate.as_ref().map(|(_, w)| w.as_str())))
        .collect()
}

#[test]
fn aw13_apply_then_undo_through_the_worker_is_bit_identical() {
    let mut rig = Rig::new(Lang::En);
    let before = rig.snap();
    let pv = rig.preview();
    let ev = rig.run(Job::Apply {
        hash: pv.hash.clone(),
    });
    let r = result_of(&ev);
    assert_eq!((r.tone, r.notice.title.as_str()), (Tone::Done, "Applied"));
    assert!(r.refresh);
    // The applied page: one card for the one transaction, listing everything in it.
    let a = applied_of(&ev);
    assert_eq!(a.open, 1);
    let card: &TxnCardVm = &a.cards[0];
    let profile_file = profile_of(card);
    assert!(
        rig.try_read(&format!(r"{RERUN}\profiles\{profile_file}"))
            .is_some(),
        "the launch profile is there"
    );
    assert_eq!(card.app_id, Some(220));
    assert_eq!(card.game.as_ref().map(Value::as_str), Some("Invented W"));
    assert_eq!(
        (card.state.sym, card.state.word.as_str()),
        (Sym::Applied, "Applied")
    );
    assert_eq!(
        card.ops.len(),
        pv.ops.len(),
        "everything of the plan is on the card"
    );
    assert!(
        card.note
            .starts_with(&format!("This card holds {} changes", card.ops.len()))
    );
    assert!(card.note.contains("the launch profile included"));
    assert!(card.can_undo && card.can_forget && card.problem.is_none());
    // The game page shows the same card (the game page's applied section).
    let g = game_in(&ev);
    assert_eq!(g.applied, a.cards);
    assert_eq!(
        rig.read(&format!(r"{G}\game.ini")),
        b"[Display]\r\nWidth=1920\r\n"
    );
    assert!(rig.snap() != before);

    // The undo preview: what is restored, the option to remove by hand, the closed game.
    let txn = card.txn;
    let ev = rig.run(Job::RevertPreview { txn });
    let d = dialog_of(&ev);
    assert_eq!(d.kind, DialogKind::Undo);
    assert_eq!(d.title, "Undo this change?");
    assert!(d.can_confirm && d.blocked.is_none() && d.changed.is_none());
    assert!(
        dialog_ops(d)
            .iter()
            .all(|(_, f)| *f == Some("Will be set back")),
        "{:?}",
        dialog_ops(d)
    );
    assert!(
        d.notes
            .iter()
            .any(|n| n.starts_with("The game must be closed"))
    );
    let l = d
        .launch
        .as_ref()
        .expect("the launch option goes back by hand");
    assert!(l.lines[0].starts_with("Remove this launch option"));
    assert!(l.option.as_ref().unwrap().as_str().contains("--profile"));
    // Nothing changed by looking.
    assert!(rig.snap() != before);

    let ev = rig.revert(txn);
    let r = result_of(&ev);
    assert_eq!((r.tone, r.notice.title.as_str()), (Tone::Done, "Undone"));
    assert!(
        r.notice.body.contains("remove the option by hand"),
        "{}",
        r.notice.body
    );
    assert!(r.notice.details[0].what.as_str().contains("--profile"));
    assert_eq!(applied_of(&ev).open, 0);
    assert!(game_in(&ev).applied.is_empty());
    // The game folder is as it was, bit for bit, and the launch profile file is gone.
    let after = rig.snap();
    assert!(after == before, "{:#?}", before.diff(&after));
    assert!(
        rig.try_read(&format!(r"{RERUN}\profiles\{profile_file}"))
            .is_none()
    );
}

#[test]
fn aw13_a_game_changed_since_the_preview_is_calm_and_applies_nothing() {
    let mut rig = Rig::new(Lang::En);
    let pv = rig.preview();
    // Steam updates the game between the preview and the click.
    let mut exe = x86();
    exe[900] = 0x5a;
    rig.sys
        .fake_fs()
        .put_file(Path::new(&format!(r"{G}\game.exe")), &exe)
        .unwrap();
    let ini = rig.read(&format!(r"{G}\game.ini"));
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let r = result_of(&ev);
    assert_eq!(r.tone, Tone::Calm, "not an error: {r:?}");
    assert_eq!(r.notice.title, "The game changed since the preview");
    assert!(r.notice.body.starts_with("This is not a problem."));
    assert!(r.refresh);
    // Nothing was applied; the page and the applied list are read again.
    assert_eq!(applied_of(&ev).open, 0);
    assert!(game_in(&ev).applied.is_empty());
    assert_eq!(rig.read(&format!(r"{G}\game.ini")), ini);
}

#[test]
fn aw13_a_game_in_use_refuses_and_the_same_preview_applies_when_it_is_closed() {
    let mut rig = Rig::new(Lang::En);
    let pv = rig.preview();
    let before = rig.snap();
    let running = rig
        .sys
        .fake_fs()
        .map_image_as(4242, Path::new(&format!(r"{G}\game.exe")))
        .unwrap();
    let ev = rig.run(Job::Apply {
        hash: pv.hash.clone(),
    });
    let r = result_of(&ev);
    assert_eq!(r.notice.title, "A file of the game is in use");
    assert_eq!(
        r.notice.body,
        "Close the game, then try again. Nothing was changed."
    );
    assert!(
        !r.refresh,
        "the page stays, the same preview is still there"
    );
    assert!(
        ev.contains(&Event::PreviewReady {
            hash: pv.hash.clone()
        }),
        "Apply is offered again: {ev:?}"
    );
    assert!(rig.snap() == before);
    drop(running);
    let ev = rig.run(Job::Apply { hash: pv.hash });
    assert_eq!(result_of(&ev).notice.title, "Applied", "{ev:?}");
}

#[test]
fn aw13_a_state_changed_since_the_undo_preview_shows_the_preview_again() {
    let mut rig = Rig::new(Lang::En);
    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = applied_of(&ev).cards[0].txn;
    let ev = rig.run(Job::RevertPreview { txn });
    assert!(dialog_of(&ev).changed.is_none());
    // The game rewrites its INI between the preview and the click.
    rig.sys
        .fake_fs()
        .put_file(
            Path::new(&format!(r"{G}\game.ini")),
            b"[Display]\r\nWidth=1920\r\nHeight=1080\r\n",
        )
        .unwrap();
    let state = rig.snap();
    let ev = rig.revert(txn);
    // Calm: the dialog again with a note; no result, no error, nothing written.
    assert_eq!(ev.len(), 1, "{ev:?}");
    let d = dialog_of(&ev);
    assert_eq!(
        d.changed.as_deref(),
        Some(
            "The preview was updated. Something changed since you looked; please look at it again."
        )
    );
    assert!(d.can_confirm);
    assert!(rig.snap() == state);
    assert!(
        dialog_ops(d)
            .iter()
            .any(|(_, f)| f.is_some_and(|f| f.starts_with("Rerun's part"))),
        "the INI is semantic now: {:?}",
        dialog_ops(d)
    );
    // Confirmed on the new preview: Rerun's key goes back, the game's key stays.
    let ev = rig.revert(txn);
    assert_eq!(result_of(&ev).notice.title, "Undone", "{ev:?}");
    assert_eq!(
        rig.read(&format!(r"{G}\game.ini")),
        b"[Display]\r\nWidth=800\r\nHeight=1080\r\n"
    );
}

#[test]
fn aw13_a_foreign_change_offers_closing_without_undoing() {
    let mut rig = Rig::new(Lang::En);
    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let card = &applied_of(&ev).cards[0];
    let txn = card.txn;
    // Someone else rewrites the launch profile Rerun wrote.
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
            Path::new(&format!(r"{RERUN}\profiles\{profile}")),
            b"someone else was here",
        )
        .unwrap();
    let ev = rig.run(Job::RevertPreview { txn });
    let d = dialog_of(&ev);
    assert!(
        dialog_ops(d)
            .iter()
            .any(|(_, f)| *f == Some("Someone else changed it. Rerun leaves it as it is")),
        "{:?}",
        dialog_ops(d)
    );
    let ev = rig.revert(txn);
    let r = result_of(&ev);
    assert_eq!(r.notice.title, "Part of it was changed by someone else");
    assert_eq!(r.tone, Tone::Attention);
    // The card says so and offers the way out.
    let a = applied_of(&ev);
    assert_eq!(a.open, 1);
    let card = &a.cards[0];
    assert_eq!(card.state.word, "Needs you");
    assert!(
        card.problem
            .as_deref()
            .unwrap()
            .starts_with("Someone else changed a file")
    );
    assert!(card.can_forget);
    // Forget: its own preview first, then the closing.
    let ev = rig.run(Job::ForgetPreview { txn });
    let d = dialog_of(&ev);
    assert_eq!(d.kind, DialogKind::Forget);
    assert_eq!(d.title, "Close this change without undoing it?");
    assert_eq!(d.confirm, "Close without undoing");
    assert!(d.notes.iter().any(|n| n.starts_with("This is on disk now")));
    let ev = rig.forget(txn);
    assert_eq!(result_of(&ev).notice.title, "Closed");
    assert_eq!(applied_of(&ev).open, 0);
}

#[test]
fn aw13_an_undo_without_its_preview_shows_the_preview_first() {
    let mut rig = Rig::new(Lang::En);
    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = applied_of(&ev).cards[0].txn;
    let before = rig.snap();
    // A click that names a transaction nobody previewed: the dialog, not the undo.
    let ev = rig.revert(txn);
    assert_eq!(ev.len(), 1);
    assert_eq!(dialog_of(&ev).kind, DialogKind::Undo);
    assert!(rig.snap() == before);
    let ev = rig.forget(txn);
    assert_eq!(dialog_of(&ev).kind, DialogKind::Forget);
    assert!(rig.snap() == before);
}

// ---------- AW14 the session and the window ----------

#[test]
fn aw14_a_plan_reads_the_executables_again() {
    let mut rig = Rig::new(Lang::En);
    let page = rig.page();
    rig.page();
    assert_eq!(
        (rig.session.games.reads(), rig.session.games.hits()),
        (1, 1),
        "the second visit came from the session"
    );
    let picks = Selection::preselected(&page).picks(&page);
    let ev = rig.run(Job::Plan { app_id: 220, picks });
    assert!(matches!(ev.as_slice(), [Event::Preview { .. }]), "{ev:?}");
    assert_eq!(
        rig.session.games.reads(),
        2,
        "the entry was dropped and read again"
    );
}

#[test]
fn aw14_a_game_that_reads_differently_hands_the_page_back_instead_of_a_preview() {
    let mut rig = Rig::new(Lang::En);
    let page = rig.page();
    let picks = Selection::preselected(&page).picks(&page);
    // The executable is replaced by one of the same length: the session's display would not
    // notice (the layer reports no timestamps), the plan does.
    let mut exe = x86();
    exe[900] = 0x5a;
    rig.sys
        .fake_fs()
        .put_file(Path::new(&format!(r"{G}\game.exe")), &exe)
        .unwrap();
    let ev = rig.run(Job::Plan { app_id: 220, picks });
    assert!(
        !ev.iter().any(|e| matches!(e, Event::Preview { .. })),
        "{ev:?}"
    );
    // The fresh page: no Topo matches this build.
    assert!(game_in(&ev).fixes.is_empty());
    // The note comes first (the window clears its selection), then the page; no preview.
    let result = result_of(&ev);
    assert!(matches!(ev.first(), Some(Event::Result(_))));
    assert_eq!(
        (result.tone, result.notice.title.as_str()),
        (Tone::Calm, "The game changed since the preview")
    );
    // Nothing selected: the panel is cleared and the worker forgets what it held.
    let ev = rig.run(Job::Plan {
        app_id: 220,
        picks: Vec::new(),
    });
    assert_eq!(ev, [Event::PreviewNone { app_id: 220 }]);
}

/// Blocks the worker thread in `wake` until released, so a test can look at the worker while a
/// job is still running.
struct Hold {
    gate: Mutex<mpsc::Receiver<()>>,
}

impl Wake for Hold {
    fn wake(&self) {
        let _ = self.gate.lock().unwrap().recv();
    }
}

#[test]
fn aw14_the_window_cannot_close_while_a_write_is_queued_or_runs() {
    let (release, gate) = mpsc::channel::<()>();
    let make = || {
        Ok(World {
            sys: Box::new(write_world()),
            http: Box::new(FakeHttp::default()),
            install: install(),
        })
    };
    let worker = Worker::start(
        Lang::En,
        make,
        Box::new(Hold {
            gate: Mutex::new(gate),
        }),
    )
    .unwrap();
    assert!(!worker.busy_writing());
    // The first job's wake holds the thread; a read job is no write.
    worker.send(Job::Status);
    worker.send(Job::Game {
        app_id: 220,
        name: None,
    });
    assert!(
        !worker.busy_writing(),
        "reading is no reason to keep the window"
    );
    // A write job counts from the moment it is queued: the click and the thread's pick-up have
    // no gap in which the window could close.
    worker.send(Job::Apply {
        hash: "0".repeat(64),
    });
    assert!(worker.busy_writing());
    worker.send(Job::Revert {
        txn: "00000001-0000000000000001".parse().unwrap(),
        nonce: 0,
    });
    assert!(worker.busy_writing());
    // Let every job run (one release per event of each).
    for _ in 0..8 {
        let _ = release.send(());
    }
    let mut seen = Vec::new();
    for _ in 0..2000 {
        while let Some(e) = worker.poll() {
            seen.push(e);
        }
        if !worker.busy_writing() && seen.len() >= 4 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(!worker.busy_writing(), "both writes are over: {seen:?}");
    assert!(
        seen.iter().any(|e| matches!(e, Event::Result(_))),
        "the writes ran (and were refused: no preview, no such transaction): {seen:?}"
    );
}

// ---------- AW15 a confirm is bound to the dialog that was shown (review H1) ----------

fn rewrite_ini(rig: &Rig) {
    rig.sys
        .fake_fs()
        .put_file(
            Path::new(&format!(r"{G}\game.ini")),
            b"[Display]\r\nWidth=1920\r\nHeight=1080\r\n",
        )
        .unwrap();
}

#[test]
fn aw15_a_second_undo_confirm_never_takes_a_preview_the_user_did_not_see() {
    let mut rig = Rig::new(Lang::En);
    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = applied_of(&ev).cards[0].txn;
    let ev = rig.run(Job::RevertPreview { txn });
    let first = dialog_of(&ev).nonce;
    rewrite_ini(&rig);
    let state = rig.snap();
    // The first confirm finds the state changed: the dialog comes again, nothing is written.
    let c1 = rig.run(Job::Revert { txn, nonce: first });
    assert_eq!(c1.len(), 1, "{c1:?}");
    let second = dialog_of(&c1).nonce;
    assert_ne!(second, first);
    assert!(dialog_of(&c1).changed.is_some());
    // A second click queued behind it still carries the first dialog's nonce: it writes
    // nothing and shows the preview again, with yet another nonce.
    let c2 = rig.run(Job::Revert { txn, nonce: first });
    assert_eq!(c2.len(), 1, "no result, only the dialog: {c2:?}");
    let third = dialog_of(&c2).nonce;
    assert!(third != first && third != second);
    assert!(rig.snap() == state, "nothing was written");
    // Only the confirm of the dialog on screen goes through.
    let ev = rig.run(Job::Revert { txn, nonce: third });
    assert_eq!(result_of(&ev).notice.title, "Undone", "{ev:?}");
}

#[test]
fn aw15_a_second_forget_confirm_never_takes_a_preview_the_user_did_not_see() {
    let mut rig = Rig::new(Lang::En);
    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = applied_of(&ev).cards[0].txn;
    let ev = rig.run(Job::ForgetPreview { txn });
    let first = dialog_of(&ev).nonce;
    rewrite_ini(&rig);
    let state = rig.snap();
    let c1 = rig.run(Job::Forget { txn, nonce: first });
    assert_eq!(c1.len(), 1, "{c1:?}");
    assert!(dialog_of(&c1).changed.is_some());
    let c2 = rig.run(Job::Forget { txn, nonce: first });
    assert_eq!(c2.len(), 1, "{c2:?}");
    assert_ne!(dialog_of(&c2).nonce, dialog_of(&c1).nonce);
    assert!(rig.snap() == state);
    let open = rig.run(Job::Status);
    assert_eq!(
        applied_of(&open).open,
        1,
        "still open: nothing was forgotten"
    );
    let nonce = dialog_of(&c2).nonce;
    let ev = rig.run(Job::Forget { txn, nonce });
    assert_eq!(result_of(&ev).notice.title, "Closed", "{ev:?}");
}

#[test]
fn aw15_a_fix_that_needs_the_helper_is_never_planned_whatever_is_sent() {
    let mut rig = Rig::new(Lang::En);
    rig.page();
    let app = rig.snap_app();
    let game = rig.snap();
    let ev = rig.run(Job::Plan {
        app_id: 220,
        picks: vec![pick("net", "block")],
    });
    assert!(
        !ev.iter().any(|e| matches!(e, Event::Preview { .. })),
        "{ev:?}"
    );
    let [Event::PreviewRefused { result, .. }] = ev.as_slice() else {
        panic!("{ev:?}");
    };
    assert_eq!(result.notice.title, "Not available yet");
    // Nothing shown, so nothing to apply; nothing stored or written.
    let ev = rig.run(Job::Apply {
        hash: "0".repeat(64),
    });
    assert_eq!(
        result_of(&ev).notice.title,
        "The preview is no longer current"
    );
    assert!(rig.snap_app() == app && rig.snap() == game);
}

#[test]
fn aw15_after_a_rescan_the_first_plan_hands_the_page_back() {
    let mut rig = Rig::new(Lang::En);
    let page = rig.page();
    let picks = Selection::preselected(&page).picks(&page);
    rig.session.pages.clear();
    let ev = rig.run(Job::Plan { app_id: 220, picks });
    assert!(matches!(ev.first(), Some(Event::Result(_))), "{ev:?}");
    assert!(matches!(ev.last(), Some(Event::Game(_))), "{ev:?}");
    assert!(!ev.iter().any(|e| matches!(e, Event::Preview { .. })));
}

/// Lets the first `free` wakes pass and blocks the next one (the worker is then inside the job
/// that emitted it).
struct HoldAfter {
    free: std::sync::atomic::AtomicUsize,
    gate: Mutex<mpsc::Receiver<()>>,
}

impl Wake for HoldAfter {
    fn wake(&self) {
        if self.free.load(Ordering::SeqCst) > 0 {
            self.free.fetch_sub(1, Ordering::SeqCst);
        } else {
            let _ = self.gate.lock().unwrap().recv();
        }
    }
}

#[test]
fn aw14_the_window_cannot_close_while_an_apply_is_really_running() {
    let (release, gate) = mpsc::channel::<()>();
    let make = || {
        Ok(World {
            sys: Box::new(write_world()),
            http: Box::new(FakeHttp::default()),
            install: install(),
        })
    };
    // Game, Plan and PreviewShown pass; the wake of the Apply's result blocks, inside the job.
    let worker = Worker::start(
        Lang::En,
        make,
        Box::new(HoldAfter {
            free: std::sync::atomic::AtomicUsize::new(3),
            gate: Mutex::new(gate),
        }),
    )
    .unwrap();
    worker.send(Job::Game {
        app_id: 220,
        name: None,
    });
    let ev = wait_for(&worker, 1);
    let page = game_in(&ev).clone();
    worker.send(Job::Plan {
        app_id: 220,
        picks: Selection::preselected(&page).picks(&page),
    });
    let hash = match &wait_for(&worker, 1)[0] {
        Event::Preview { vm, .. } => vm.hash.clone(),
        other => panic!("{other:?}"),
    };
    worker.send(Job::PreviewShown { hash: hash.clone() });
    wait_for(&worker, 1);
    assert!(!worker.busy_writing());
    worker.send(Job::Apply { hash });
    // The result is emitted from inside the running job; its wake holds the thread.
    let ev = wait_for(&worker, 1);
    assert!(
        matches!(&ev[0], Event::Result(r) if r.tone == Tone::Done),
        "{ev:?}"
    );
    assert!(
        worker.busy_writing(),
        "the apply has not ended: closing is refused"
    );
    for _ in 0..3 {
        let _ = release.send(());
    }
    for _ in 0..2000 {
        if !worker.busy_writing() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("the write never ended");
}
