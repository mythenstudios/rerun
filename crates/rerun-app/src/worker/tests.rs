//! The worker's jobs and the view models against the fake system layer (P5-3, ADR 0027):
//! fake world → `flow` → `vm`, without a window. Every ID, step and hash is invented; the index
//! is signed with the published test key (dev-dependency `rerun-core/test-key`).
//! - AW1 (AC1-like) the game page: two problems, the variant `patch` listed under both issues is
//!   one fix with two solved issues (each with its own `when` and evidence), `limit` its own fix;
//!   the hero counts one problem on this PC and two fixes; the facts; German.
//! - AW2 the library: the row is streamed before the summary, grouped under "Topo available",
//!   the index in the status bar; a game Steam is updating is not ready; the search and the
//!   grouping.
//! - AW3 elevated: one blocking event, nothing of the file system read.
//! - AW4 no Steam and no index: the notices; a Topo for an app no library lists.
//! - AW5 nothing is created: no job creates Rerun's folder (S6); the applied page without it.
//! - AW6 untrusted text: a Steam name with a bidi control reaches the view model escaped.
//! - AW7 the system page from the fake profile.
//! - AW8 the worker thread: jobs in order, every event woken, a failed system is blocked.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rerun_core::catalog::{self, key::test_key};
use rerun_core::detect::exe::{HashLimits, HashOutcome, inspect_exe};
use rerun_core::detect::pe::Limits;
use rerun_core::detect::steam::RootSource;
use rerun_core::escape;
use rerun_core::flow::Env;
use rerun_core::path::RelPath;
use rerun_core::policy::root::{AppDir, Create, ForbiddenRoots, GameDir};
use rerun_core::sys::fake::{FakeHttp, FakeSystem, FakeSystemBuilder};
use rerun_core::sys::registry::RegValue;

use super::{Event, Job, Wake, Worker, World, run};
use crate::text::{Lang, Sym};
use crate::vm::{self, GameVm, Group, RowVm, Value};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const STEAM: &str = r"C:\Program Files (x86)\Steam";
const LIB: &str = r"D:\SteamLibrary";
const G: &str = r"D:\SteamLibrary\steamapps\common\G";
const RYZEN_5950X: &str = include_str!("../../../../tests/fixtures/cpu/ryzen9-5950x.json");

/// A synthetic PE image from its non-zero byte runs (the sparse bytes of `rerun-core`'s test
/// builder, as in `rerun-cli`'s tests).
fn pe(runs: &[(usize, &str)]) -> Vec<u8> {
    let mut b = vec![0u8; 1024];
    for (at, hex) in runs {
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(pair).unwrap();
            b[at + i] = u8::from_str_radix(s, 16).unwrap();
        }
    }
    b
}

fn x86() -> Vec<u8> {
    pe(&[
        (0x0, "4d5a"),
        (0x3c, "80"),
        (0x80, "5045"),
        (0x84, "4c0101"),
        (0x94, "e0"),
        (0x96, "02010b01"),
        (0xb6, "40"),
        (0xd5, "02"),
        (0xdc, "02"),
        (0xde, "4081"),
        (0xf4, "10"),
        (0x178, "2e7264617461"),
        (0x180, "01"),
        (0x185, "10"),
        (0x189, "02"),
        (0x18d, "02"),
    ])
}

fn x64() -> Vec<u8> {
    pe(&[
        (0x0, "4d5a"),
        (0x3c, "80"),
        (0x80, "5045"),
        (0x84, "648601"),
        (0x94, "f0"),
        (0x96, "22"),
        (0x98, "0b02"),
        (0xb3, "4001"),
        (0xd5, "02"),
        (0xdc, "02"),
        (0xde, "6081"),
        (0x104, "10"),
        (0x188, "2e7264617461"),
        (0x190, "01"),
        (0x195, "10"),
        (0x199, "02"),
        (0x19d, "02"),
    ])
}

fn lib_vdf() -> String {
    let mut out = String::from("\"libraryfolders\"\n{\n");
    for (i, p) in [STEAM, LIB].iter().enumerate() {
        out.push_str(&format!(
            "\t\"{i}\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n",
            p.replace('\\', r"\\")
        ));
    }
    out.push_str("}\n");
    out
}

fn acf(app_id: u32, name: &str, flags: u32, dir: &str) -> String {
    format!(
        "\"AppState\"\n{{\n\t\"appid\"\t\t\"{app_id}\"\n\t\"name\"\t\t\"{name}\"\n\t\"StateFlags\"\t\t\"{flags}\"\n\t\"installdir\"\t\t\"{dir}\"\n}}\n"
    )
}

fn bare() -> FakeSystemBuilder {
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .topology_json(RYZEN_5950X)
}

/// Steam with app 220 in `G` (an x86 game and an x64 launcher) named `name`, and app 230 that
/// Steam is updating.
fn steam_world(name: &str) -> FakeSystem {
    let sys = bare()
        .value(
            RootSource::CurrentUser.key(),
            RootSource::CurrentUser.value_name(),
            RegValue::String(STEAM.to_owned()),
        )
        .file(
            format!(r"{STEAM}\steamapps\libraryfolders.vdf"),
            lib_vdf().into_bytes(),
        )
        .file(
            format!(r"{LIB}\steamapps\appmanifest_220.acf"),
            acf(220, name, 4, "G").into_bytes(),
        )
        .file(
            format!(r"{LIB}\steamapps\appmanifest_230.acf"),
            acf(230, "Busy Game", 6, "Busy").into_bytes(),
        )
        .file(format!(r"{G}\game.exe"), x86())
        .file(format!(r"{G}\FFLauncher.exe"), x64())
        .dir(format!(r"{LIB}\steamapps\common\Busy"))
        .build()
        .unwrap();
    sys.fake_fs().sync_all();
    sys
}

fn sha256_of(sys: &FakeSystem, rel: &str) -> String {
    let fr = ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap();
    let g = GameDir::open_manual(sys, &fr, Path::new(G)).unwrap();
    let f = inspect_exe(
        &g,
        &RelPath::parse(rel).unwrap(),
        &Limits::DEFAULT,
        Some(&HashLimits::DEFAULT),
    )
    .unwrap();
    match f.hashes {
        HashOutcome::Done(h) => h.sha256,
        other => panic!("{other}"),
    }
}

/// The index in the shape of Assassin's Creed: the variant `patch` under two issues with
/// identical steps (`online` has a `when` that is no here), a second variant with a CPU rule;
/// and a Topo for app 240, which no library lists.
fn index(sha: &str) -> String {
    let step = r#"{"compat_layer":{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}"#;
    let repo = r#"{"type":"repo","url":"https://github.com/example/patch"}"#;
    let wiki = r#"{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented_Game"}"#;
    format!(
        r#"{{"format":1,"seq":7,"issued":"2026-11-11T12:00:00Z","topos":[{{"format":1,"id":"invented-ac","title":"Invented AC","status":"active","rev":3,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"launch":{{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}},
"issues":[
 {{"id":"controller","title":"Controllers are not recognised","variants":[{{"id":"patch","status":"unverified","kind":"fix","steps":[{step}],"sources":[{repo}]}}]}},
 {{"id":"online","title":"Online services are gone","when":{{"gpu.vendor":"nvidia"}},"variants":[
   {{"id":"patch","status":"verified","kind":"fix","steps":[{step}],"sources":[{repo},{wiki}]}},
   {{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8}}}}]}}]}}
]}},{{"format":1,"id":"invented-other","title":"Invented Other","status":"active","rev":1,
"match":{{"steam_appid":240,"exes":[{{"path":"other.exe","sha256":"{sha}","api":"d3d9"}}]}},
"issues":[{{"id":"x","title":"X","variants":[{{"id":"y","status":"verified","kind":"fix","steps":[{step}]}}]}}]}}],"packages":[]}}"#
    )
}

/// [`steam_world`] with the index imported (Rerun's folder created by the import, as a CLI
/// run would).
fn indexed(name: &str) -> FakeSystem {
    let sys = steam_world(name);
    let ix = index(&sha256_of(&sys, "game.exe"));
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    catalog::store::import(
        &app,
        ix.as_bytes(),
        &test_key::sign(ix.as_bytes()),
        &catalog::trusted_keys(),
    )
    .unwrap();
    drop(app);
    sys.fake_fs().sync_all();
    sys
}

fn install() -> Result<PathBuf, String> {
    Ok(PathBuf::from(INSTALL))
}

/// Runs `job` in `lang` and returns every event.
fn events(sys: &FakeSystem, job: &Job, lang: Lang) -> Vec<Event> {
    let http = FakeHttp::default();
    let install = install();
    let env = Env {
        sys,
        http: &http,
        install: &install,
    };
    let mut out = Vec::new();
    run(env, job, lang, &mut |e| out.push(e));
    out
}

fn game_of(sys: &FakeSystem, app_id: u32, lang: Lang) -> GameVm {
    let job = Job::Game {
        app_id,
        name: Some(escape::text("Invented AC").into_owned()),
    };
    match events(sys, &job, lang).as_slice() {
        [Event::Game(g)] => g.clone(),
        other => panic!("{other:?}"),
    }
}

fn rows_of(ev: &[Event]) -> Vec<&RowVm> {
    ev.iter()
        .filter_map(|e| match e {
            Event::Row(r) => Some(r),
            _ => None,
        })
        .collect()
}

#[test]
fn aw1_the_game_page_lists_a_shared_fix_once() {
    let sys = indexed("Invented AC");
    let g = game_of(&sys, 220, Lang::En);
    assert_eq!(g.title.as_str(), "Invented AC");
    // Two problems: the one that affects this PC first.
    let problems: Vec<(&str, &str, bool)> = g
        .problems
        .iter()
        .map(|p| (p.title.as_str(), p.when.word.as_str(), p.quiet))
        .collect();
    assert_eq!(
        problems,
        [
            ("Controllers are not recognised", "Affects this PC", false),
            ("Online services are gone", "Does not affect this PC", true),
        ]
    );
    let fixes_for: Vec<Vec<&str>> = g
        .problems
        .iter()
        .map(|p| p.fixes.iter().map(|f| f.as_str()).collect())
        .collect();
    assert_eq!(fixes_for, [vec!["patch"], vec!["patch", "limit"]]);
    // EaglePatch once: one fix per variant ID, with every issue it solves.
    let ids: Vec<&str> = g.fixes.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["patch", "limit"]);
    let patch = &g.fixes[0];
    let solves: Vec<(&str, &str, &str)> = patch
        .solves
        .iter()
        .map(|s| {
            (
                s.issue.as_str(),
                s.when.word.as_str(),
                s.status.word.as_str(),
            )
        })
        .collect();
    assert_eq!(
        solves,
        [
            (
                "Controllers are not recognised",
                "Affects this PC",
                "Not confirmed"
            ),
            (
                "Online services are gone",
                "Does not affect this PC",
                "Verified"
            ),
        ]
    );
    assert_eq!(patch.state.word, "Available");
    assert_eq!(patch.state.sym, Sym::Open);
    assert_eq!(patch.refused, None);
    assert_eq!(patch.kind, "Fix");
    assert_eq!(g.fixes[1].solves.len(), 1);
    // The hero: one problem on this PC; one fix offered for it (`limit` solves only the issue
    // that does not affect this PC).
    assert_eq!(g.hero.sym, Sym::Affects);
    assert_eq!(
        g.hero.line,
        "1 problem affects your PC \u{b7} 1 fix available"
    );
    assert!(g.hero.sub.is_some());
    let facts: Vec<(&str, &str)> = g
        .facts
        .iter()
        .map(|f| (f.label.as_str(), f.value.as_str()))
        .collect();
    assert_eq!(
        facts,
        [
            ("Steam app", "220"),
            ("Program", "game.exe"),
            ("Graphics", "Direct3D 9"),
            ("Topo", "Revision 3 \u{b7} active"),
        ]
    );
    assert!(matches!(g.facts[1].value, Value::Shown(_)));
    assert!(g.notes.is_empty() && g.detail.is_none());

    // German: the same page, every word from the catalogue.
    let de = game_of(&sys, 220, Lang::De);
    assert_eq!(
        de.hero.line,
        "1 Problem betrifft deinen PC \u{b7} 1 Fix verfügbar"
    );
    assert_eq!(de.problems[1].when.word, "Betrifft diesen PC nicht");
    assert_eq!(de.fixes[0].solves[0].status.word, "Nicht bestätigt");
    assert_eq!(de.fixes[0].state.word, "Verfügbar");
}

#[test]
fn aw1_an_anti_cheat_folder_refuses_the_shared_fix_once() {
    let sys = indexed("Invented AC");
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{G}\BattlEye")))
        .unwrap();
    sys.fake_fs().sync_all();
    let g = game_of(&sys, 220, Lang::En);
    let patch = &g.fixes[0];
    assert_eq!(patch.id.as_str(), "patch");
    assert_eq!(patch.state.word, "Not offered");
    assert_eq!(
        patch.refused.as_deref(),
        Some("Not offered: an anti-cheat system was found.")
    );
    // The CPU rule is only warned, but it solves no issue of this PC: nothing left on offer.
    assert!(g.fixes[1].refused.is_none() && g.fixes[1].warned.is_some());
    assert_eq!(g.hero.line, "Rerun cannot offer a fix on this PC.");
    assert_eq!(g.hero.sym, Sym::Attention);
    assert!(g.notes.iter().any(|n| n.starts_with("Anti-cheat found")));
}

#[test]
fn aw2_the_library_streams_rows_then_the_summary() {
    let sys = indexed("Invented AC");
    let ev = events(&sys, &Job::Library, Lang::En);
    assert!(matches!(ev.first(), Some(Event::Steam(s)) if s.found));
    assert!(matches!(ev.last(), Some(Event::LibraryDone(_))));
    let rows = rows_of(&ev);
    let got: Vec<(u32, &str, Group, &str)> = rows
        .iter()
        .map(|r| (r.app_id, r.name.as_str(), r.group, r.badge.word.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (220, "Invented AC", Group::Topo, "Topo"),
            (230, "Busy Game", Group::NotReady, "Updating"),
        ]
    );
    assert_eq!(rows[0].exe.as_ref().map(|e| e.as_str()), Some("game.exe"));
    assert_eq!(rows[1].detail, "Steam is updating this game");
    let Some(Event::LibraryDone(done)) = ev.last() else {
        unreachable!()
    };
    assert_eq!(done.index.status, "Topo index 7");
    assert_eq!(done.index.signature, "Signature checked");
    assert_eq!(
        done.summary,
        "2 games in 2 Steam libraries. Choose a game to see what is wrong."
    );
    assert!(done.notices.is_empty(), "{:?}", done.notices);

    // The sections: by status, or one; the search filters by name.
    let rows: Vec<RowVm> = rows.into_iter().cloned().collect();
    let titles = |s: &[vm::SectionVm]| -> Vec<(String, Vec<usize>)> {
        s.iter()
            .map(|x| (x.title.clone(), x.rows.clone()))
            .collect()
    };
    assert_eq!(
        titles(&vm::sections(&rows, "", true, Lang::En)),
        [
            ("Topo available".to_owned(), vec![0]),
            ("Not ready".to_owned(), vec![1]),
        ]
    );
    assert_eq!(
        titles(&vm::sections(&rows, "", false, Lang::En)),
        [("All games".to_owned(), vec![1, 0])]
    );
    assert_eq!(
        titles(&vm::sections(&rows, "  invented ", true, Lang::En)),
        [("Topo available".to_owned(), vec![0])]
    );
    assert!(vm::sections(&rows, "zzz", true, Lang::En).is_empty());
}

#[test]
fn aw3_an_elevated_process_reads_nothing() {
    let sys = indexed("Invented AC");
    sys.fake_registry().set_elevated(true);
    sys.fake_fs().record_calls(true);
    for job in [
        Job::Library,
        Job::Game {
            app_id: 220,
            name: None,
        },
        Job::Status,
        Job::System,
    ] {
        match events(&sys, &job, Lang::En).as_slice() {
            [Event::Blocked(b)] => {
                assert!(b.elevated, "{job:?}");
                assert_eq!(b.notice.title, "Rerun runs as administrator.");
                assert!(b.notice.body.starts_with("Start it normally."));
            }
            other => panic!("{job:?}: {other:?}"),
        }
    }
    let calls = sys.fake_fs().take_calls();
    assert!(calls.is_empty(), "{calls:?}");
    // Control: the same jobs read when not elevated (the record above bites).
    sys.fake_registry().set_elevated(false);
    let _ = events(&sys, &Job::Library, Lang::En);
    assert!(!sys.fake_fs().take_calls().is_empty());
}

#[test]
fn aw4_no_steam_and_no_index() {
    let sys = bare().build().unwrap();
    let ev = events(&sys, &Job::Library, Lang::En);
    assert!(rows_of(&ev).is_empty());
    let Some(Event::LibraryDone(done)) = ev.last() else {
        panic!("{ev:?}")
    };
    let titles: Vec<&str> = done.notices.iter().map(|n| n.title.as_str()).collect();
    assert_eq!(
        titles,
        ["Rerun has no Topo list yet.", "Steam was not found."]
    );
    assert_eq!(done.index.status, "No Topo index");

    // Without an index every game is listed, nothing offered.
    let sys = steam_world("Invented AC");
    let ev = events(&sys, &Job::Library, Lang::En);
    let rows = rows_of(&ev);
    assert_eq!(rows[0].group, Group::NoTopo);
    assert_eq!(rows[0].badge.word, "No Topo list");
    let g = game_of(&sys, 220, Lang::En);
    assert_eq!(
        g.hero.line,
        "Rerun has no Topo list yet. It offers nothing and changes nothing."
    );
    assert!(g.problems.is_empty() && g.fixes.is_empty());

    // With the index: no Topo for an app; a Topo for an app no library lists.
    let sys = indexed("Invented AC");
    let g = game_of(&sys, 230, Lang::En);
    assert_eq!(
        g.hero.line,
        "There is no Topo for this game. Rerun offers nothing and changes nothing."
    );
    let g = game_of(&sys, 240, Lang::En);
    assert_eq!(g.hero.line, "No Steam library lists this game any more.");
    assert_eq!(g.hero.sym, Sym::NotHere);
}

#[test]
fn aw4_another_build_of_the_game_is_no_match() {
    let sys = indexed("Invented AC");
    sys.fake_fs()
        .put_file(Path::new(&format!(r"{G}\game.exe")), &x64())
        .unwrap();
    sys.fake_fs().sync_all();
    let g = game_of(&sys, 220, Lang::En);
    assert_eq!(g.hero.line, "Rerun does not know this version of the game.");
    assert!(g.hero.sub.is_some());
    assert!(g.fixes.is_empty());
}

#[test]
fn aw5_no_job_creates_rerun_s_folder() {
    let sys = steam_world("Invented AC");
    for job in [
        Job::Library,
        Job::Game {
            app_id: 220,
            name: None,
        },
        Job::Status,
        Job::System,
    ] {
        let _ = events(&sys, &job, Lang::En);
        assert!(
            AppDir::open(&sys, Create::Never).unwrap().is_none(),
            "{job:?}"
        );
    }
    match events(&sys, &Job::Status, Lang::En).as_slice() {
        [Event::Applied(a)] => {
            assert_eq!(a.open, 0);
            assert_eq!(a.title, "Nothing applied");
        }
        other => panic!("{other:?}"),
    }
    // With Rerun's folder (an imported index), still nothing open.
    let sys = indexed("Invented AC");
    match events(&sys, &Job::Status, Lang::En).as_slice() {
        [Event::Applied(a)] => assert_eq!((a.open, a.detail.is_none()), (0, true)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn aw6_a_steam_name_reaches_the_view_model_escaped() {
    let sys = indexed("Evil\u{202E}exe.txt");
    let ev = events(&sys, &Job::Library, Lang::En);
    let rows = rows_of(&ev);
    let name = rows[0].name.as_str();
    assert!(!name.contains('\u{202E}'), "{name}");
    assert!(name.contains(r"\u{202e}"), "{name}");
    // The game page's title is the escaped name the row handed on, never the raw one.
    let job = Job::Game {
        app_id: 220,
        name: Some(rows[0].name.clone()),
    };
    match events(&sys, &job, Lang::En).as_slice() {
        [Event::Game(g)] => assert_eq!(g.title.as_str(), name),
        other => panic!("{other:?}"),
    }
    // A game without a name gets one from the catalogue.
    let g = vm::title_of(220, None, Lang::De);
    assert_eq!(g.as_str(), "Steam-App 220");
}

#[test]
fn aw7_the_system_page() {
    let sys = steam_world("Invented AC");
    let lines = match events(&sys, &Job::System, Lang::En).as_slice() {
        [Event::System(s)] => s.lines.clone(),
        other => panic!("{other:?}"),
    };
    let labels: Vec<&str> = lines.iter().map(|l| l.label.as_str()).collect();
    assert_eq!(
        labels,
        [
            "Graphics",
            "Processor",
            "Windows",
            "Smart App Control",
            "Steam"
        ]
    );
    assert_eq!(
        lines[1].values,
        [Value::Text(
            "32 logical processors \u{b7} 16 cores \u{b7} 2 cache groups".to_owned()
        )]
    );
    assert_eq!(
        lines[4].values,
        [Value::Text("Found, 2 libraries".to_owned())]
    );
}

struct Count(Arc<AtomicUsize>);

impl Wake for Count {
    fn wake(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn wait_for(worker: &Worker, n: usize) -> Vec<Event> {
    let mut out = Vec::new();
    for _ in 0..2000 {
        while let Some(e) = worker.poll() {
            out.push(e);
        }
        if out.len() >= n {
            return out;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("{} of {n} events: {out:?}", out.len());
}

#[test]
fn aw8_the_worker_runs_jobs_in_order_and_wakes_for_each_event() {
    let woken = Arc::new(AtomicUsize::new(0));
    let make = || {
        Ok(World {
            sys: Box::new(indexed("Invented AC")),
            http: Box::new(FakeHttp::default()),
            install: install(),
        })
    };
    let worker = Worker::start(Lang::En, make, Box::new(Count(woken.clone()))).unwrap();
    worker.send(Job::Status);
    worker.send(Job::Game {
        app_id: 220,
        name: None,
    });
    let ev = wait_for(&worker, 2);
    assert!(matches!(ev[0], Event::Applied(_)), "{ev:?}");
    assert!(
        matches!(&ev[1], Event::Game(g) if g.fixes.len() == 2),
        "{ev:?}"
    );
    assert_eq!(woken.load(Ordering::SeqCst), 2);
    drop(worker);

    // A system layer that cannot be created: every job is answered with the blocking page.
    let make = || Err(escape::text("no system").into_owned());
    let worker = Worker::start(Lang::En, make, Box::new(Count(woken))).unwrap();
    worker.send(Job::Library);
    match wait_for(&worker, 1).as_slice() {
        [Event::Blocked(b)] => {
            assert!(!b.elevated);
            assert_eq!(b.notice.details[0].what.as_str(), "no system");
        }
        other => panic!("{other:?}"),
    }
}
