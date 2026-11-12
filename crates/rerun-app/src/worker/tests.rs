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
//! - AW9 the session (P5-3b): reopening a game reads no executable again, a changed executable
//!   and a rescan do; the system page comes from the session until a rescan, the applied page
//!   is read each visit.
//! - AW10 a library scan lets a waiting job run between two games, and a second scan restarts it.
//! - AW11 the game page at once from the library row, before the worker has read the folder.
//! - AW-FX set-aside Topos (ADR 0024 amendment "Forward compatibility" §10, FX11): the library
//!   row and the game page of a game whose only Topo needs a newer Rerun, and of one whose only
//!   Topo this version does not support; a usable Topo next to a set-aside one; the count in the
//!   status bar; English and German.

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

use super::{Event, Job, Session, Wake, Worker, World, run, run_in};
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
    // The scan announces itself (the rows of an earlier scan are void), then streams.
    assert_eq!(ev.first(), Some(&Event::LibraryStarted));
    assert!(matches!(ev.get(1), Some(Event::Row(_))), "{ev:?}");
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
fn aw4_no_games_scan_problems_and_refused_indexes() {
    // Steam with one library that lists only a game that is not installed: no games.
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
            format!(r"{LIB}\steamapps\appmanifest_250.acf"),
            acf(250, "Gone", 0, "Gone").into_bytes(),
        )
        .build()
        .unwrap();
    sys.fake_fs().sync_all();
    let ev = events(&sys, &Job::Library, Lang::En);
    let Some(Event::LibraryDone(done)) = ev.last() else {
        panic!("{ev:?}")
    };
    let titles: Vec<&str> = done.notices.iter().map(|n| n.title.as_str()).collect();
    assert_eq!(titles, ["Rerun has no Topo list yet.", "No games found."]);

    // Scan problems: the count names all, at most MAX_PROBLEMS details are listed.
    let steam = vm::SteamVm {
        found: true,
        problems: Vec::new(),
    };
    let problems: Vec<vm::DetailVm> = (0..60)
        .map(|i| vm::DetailVm {
            who: Some(escape::text(&format!("Game {i}")).into_owned()),
            what: escape::text("game folder: denied").into_owned(),
        })
        .collect();
    let facts = rerun_core::flow::LibraryFacts {
        counts: rerun_core::flow::LibraryCounts {
            libraries: 1,
            apps: 60,
            installed: 60,
            ..Default::default()
        },
        missing: Vec::new(),
    };
    let index = vm::index(&rerun_core::flow::IndexState::None, Lang::En);
    let done = vm::library_done(&facts, &steam, &problems, index, Lang::En);
    let scan = done.notices.last().unwrap();
    assert_eq!(scan.title, "60 problems while reading.");
    assert_eq!(scan.details.len(), vm::MAX_PROBLEMS);
    assert_eq!(
        scan.details[0].who.as_ref().map(|w| w.as_str()),
        Some("Game 0")
    );

    // A refused index: NoKeys has its own notice and no detail; any other refusal names it.
    use rerun_core::catalog::IndexError;
    use rerun_core::catalog::store::StoreError;
    let no_keys = vm::index(
        &rerun_core::flow::IndexState::Refused(StoreError::Index(IndexError::NoKeys)),
        Lang::En,
    );
    assert_eq!(no_keys.status, "Topo index refused");
    let n = no_keys.notice.unwrap();
    assert_eq!(n.title, "This build of Rerun trusts no index key yet.");
    assert!(n.details.is_empty());
    let damaged = vm::index(
        &rerun_core::flow::IndexState::Refused(StoreError::Damaged("pointer".to_owned())),
        Lang::De,
    );
    let n = damaged.notice.unwrap();
    assert_eq!(n.title, "Der gespeicherte Topo-Index wird abgelehnt.");
    assert_eq!(
        n.details[0].what.as_str(),
        "the stored index is damaged: pointer"
    );
    assert_eq!(damaged.signature, "Keine Signatur zu prüfen");
}

#[test]
fn aw4_a_game_folder_that_cannot_be_opened() {
    // Steam lists app 220 in `G`, but the folder is not there.
    let sys = indexed("Invented AC");
    let gone = bare()
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
            acf(220, "Invented AC", 4, "G").into_bytes(),
        )
        .dir(format!(r"{LIB}\steamapps\common"))
        .build()
        .unwrap();
    // The same index as `indexed`, imported into the world without the game folder.
    let ix = index(&sha256_of(&sys, "game.exe"));
    let app = AppDir::open(&gone, Create::IfMissing).unwrap().unwrap();
    catalog::store::import(
        &app,
        ix.as_bytes(),
        &test_key::sign(ix.as_bytes()),
        &catalog::trusted_keys(),
    )
    .unwrap();
    drop(app);
    gone.fake_fs().sync_all();
    let g = game_of(&gone, 220, Lang::En);
    assert_eq!(g.hero.line, "Rerun cannot open the game folder.");
    assert_eq!(g.hero.sym, Sym::Attention);
    assert!(g.detail.is_some(), "{g:?}");
    assert!(g.problems.is_empty() && g.fixes.is_empty());
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
    let make = |_| {
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
    // The wake follows the send: wait for it rather than race it (review of P5-3).
    for _ in 0..2000 {
        if woken.load(Ordering::SeqCst) >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(woken.load(Ordering::SeqCst), 2);
    drop(worker);

    // A system layer that cannot be created: every job is answered with the blocking page.
    let make = |_| Err(escape::text("no system").into_owned());
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

/// Runs `job` in `session` (jobs that wait: none) and returns every event.
fn events_in(sys: &FakeSystem, session: &mut Session, job: &Job) -> Vec<Event> {
    let http = FakeHttp::default();
    let install = install();
    let env = Env {
        sys,
        http: &http,
        install: &install,
    };
    let mut out = Vec::new();
    let _ = run_in(env, job, Lang::En, session, &mut || None, &mut |e| {
        out.push(e);
    });
    out
}

fn game_job() -> Job {
    Job::Game {
        app_id: 220,
        name: Some(escape::text("Invented AC").into_owned()),
    }
}

fn the_game(ev: Vec<Event>) -> GameVm {
    match ev.as_slice() {
        [Event::Game(g)] => g.clone(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn aw9_reopening_a_game_reads_no_executable_again() {
    let sys = indexed("Invented AC");
    let mut session = Session::default();
    let served = |sys: &FakeSystem| sys.fake_fs().bytes_served();

    let before = served(&sys);
    let first = the_game(events_in(&sys, &mut session, &game_job()));
    let first_cost = served(&sys) - before;
    assert_eq!((session.games.reads(), session.games.hits()), (1, 0));

    let before = served(&sys);
    let second = the_game(events_in(&sys, &mut session, &game_job()));
    let second_cost = served(&sys) - before;
    assert_eq!((session.games.reads(), session.games.hits()), (1, 1));
    assert_eq!(first, second);
    // The executable (1 KiB here) was parsed and hashed the first time, not the second.
    assert!(
        first_cost >= second_cost + 1024,
        "first {first_cost}, second {second_cost}"
    );

    // Another build of the executable (another length): read again, and it no longer matches.
    let exe = PathBuf::from(format!(r"{G}\game.exe"));
    let mut longer = x86();
    longer.extend_from_slice(b"another build");
    sys.fake_fs().put_file(&exe, &longer).unwrap();
    let changed = the_game(events_in(&sys, &mut session, &game_job()));
    assert_eq!((session.games.reads(), session.games.hits()), (2, 1));
    assert_ne!(changed, first);
    assert!(changed.fixes.is_empty(), "{changed:?}");

    // The same file again: served again.
    let _ = the_game(events_in(&sys, &mut session, &game_job()));
    assert_eq!((session.games.reads(), session.games.hits()), (2, 2));
}

#[test]
fn aw9_a_rescan_forgets_the_session() {
    let sys = indexed("Invented AC");
    let mut session = Session::default();
    let _ = the_game(events_in(&sys, &mut session, &game_job()));
    let _ = the_game(events_in(&sys, &mut session, &game_job()));
    assert_eq!((session.games.reads(), session.games.hits()), (1, 1));
    events_in(&sys, &mut session, &Job::Status);
    events_in(&sys, &mut session, &Job::System);
    assert!(session.system.is_some());

    events_in(&sys, &mut session, &Job::Library);
    assert!(session.system.is_none());
    let _ = the_game(events_in(&sys, &mut session, &game_job()));
    // Read again after the scan (the counters are not reset, the entries are).
    assert_eq!((session.games.reads(), session.games.hits()), (2, 1));
}

#[test]
fn aw9_the_system_page_comes_from_the_session_and_the_applied_page_never_does() {
    let sys = indexed("Invented AC");
    let mut session = Session::default();
    let applied = |ev: &[Event]| match ev {
        [Event::Applied(a)] => a.clone(),
        other => panic!("{other:?}"),
    };
    // Nothing of the applied page is kept: another process may apply or revert meanwhile.
    let first = applied(&events_in(&sys, &mut session, &Job::Status));
    assert_eq!(applied(&events_in(&sys, &mut session, &Job::Status)), first);

    let system = |ev: &[Event]| match ev {
        [Event::System(s)] => s.clone(),
        other => panic!("{other:?}"),
    };
    let read = system(&events_in(&sys, &mut session, &Job::System));
    let mut planted = read.clone();
    planted.lines.clear();
    session.system = Some(planted.clone());
    assert_eq!(
        system(&events_in(&sys, &mut session, &Job::System)),
        planted
    );
}

/// The kind of each event, for the order of a scan.
fn kinds(ev: &[Event]) -> Vec<&'static str> {
    ev.iter()
        .map(|e| match e {
            Event::Blocked(_) => "blocked",
            Event::LibraryStarted => "started",
            Event::Row(_) => "row",
            Event::LibraryDone(_) => "done",
            Event::Game(_) => "game",
            Event::Applied(_) => "applied",
            Event::System(_) => "system",
            Event::Preview { .. } => "preview",
            Event::PreviewNone { .. } => "preview-none",
            Event::PreviewRefused { .. } => "preview-refused",
            Event::PreviewReady { .. } => "preview-ready",
            Event::Dialog(_) => "dialog",
            Event::Result(_) => "result",
            Event::Download(_) => "download",
            Event::DownloadEnded(_) => "download-ended",
            Event::WaitingForUac(_) => "uac",
        })
        .collect()
}

#[test]
fn aw10_a_scan_lets_a_waiting_job_run_between_two_games() {
    let sys = indexed("Invented AC");
    let http = FakeHttp::default();
    let install = install();
    let env = Env {
        sys: &sys,
        http: &http,
        install: &install,
    };
    let mut session = Session::default();
    let mut queue = vec![Job::Status, game_job()];
    let mut out = Vec::new();
    // The jobs are queued before the scan starts: they run after its first game.
    let next = run_in(
        env,
        &Job::Library,
        Lang::En,
        &mut session,
        &mut || (!queue.is_empty()).then(|| queue.remove(0)),
        &mut |e| out.push(e),
    );
    assert!(next.is_none());
    assert_eq!(
        kinds(&out),
        ["started", "row", "applied", "game", "row", "done"]
    );
    // The page of the game that was asked for is whole, though the scan was not done.
    assert!(
        matches!(&out[3], Event::Game(g) if g.fixes.len() == 2),
        "{out:?}"
    );
}

#[test]
fn aw10_a_second_scan_restarts_the_first() {
    let sys = indexed("Invented AC");
    let http = FakeHttp::default();
    let install = install();
    let env = Env {
        sys: &sys,
        http: &http,
        install: &install,
    };
    let mut session = Session::default();
    let mut queue = vec![Job::Library];
    let mut out = Vec::new();
    let next = run_in(
        env,
        &Job::Library,
        Lang::En,
        &mut session,
        &mut || (!queue.is_empty()).then(|| queue.remove(0)),
        &mut |e| out.push(e),
    );
    // Stopped after the first game, no summary; the newer scan is handed back to run next.
    assert_eq!(kinds(&out), ["started", "row"]);
    assert_eq!(next, Some(Job::Library));
    let again = run_in(
        env,
        &Job::Library,
        Lang::En,
        &mut session,
        &mut || None,
        &mut |e| out.push(e),
    );
    assert!(again.is_none());
    assert_eq!(
        kinds(&out),
        ["started", "row", "started", "row", "row", "done"]
    );
}

#[test]
fn aw10_a_click_during_a_scan_on_the_worker_thread_is_answered_before_the_summary() {
    // The world is built only once every job is queued, so the jobs wait while the scan runs.
    let sent = Arc::new(std::sync::Barrier::new(2));
    let gate = sent.clone();
    let make = move |_| {
        gate.wait();
        Ok(World {
            sys: Box::new(indexed("Invented AC")),
            http: Box::new(FakeHttp::default()),
            install: install(),
        })
    };
    let woken = Arc::new(AtomicUsize::new(0));
    let worker = Worker::start(Lang::En, make, Box::new(Count(woken))).unwrap();
    worker.send(Job::Library);
    worker.send(game_job());
    worker.send(Job::Status);
    sent.wait();
    let ev = wait_for(&worker, 6);
    let k = kinds(&ev);
    let at = |name: &str| k.iter().position(|x| *x == name).unwrap();
    assert!(at("game") < at("done"), "{k:?}");
    assert!(at("applied") < at("done"), "{k:?}");
}

#[test]
fn aw11_the_game_page_is_there_before_the_folder_is_read() {
    let sys = indexed("Invented AC");
    let ev = events(&sys, &Job::Library, Lang::En);
    let rows = rows_of(&ev);
    let row = rows.iter().find(|r| r.app_id == 220).unwrap();

    let name = Some(row.name.clone());
    let loading = vm::game_loading(220, name.as_ref(), Some(row), Lang::En);
    assert_eq!(loading.title.as_str(), "Invented AC");
    // The hero is the row's status, glyph and word; its second line the row's.
    assert_eq!(loading.hero.sym, row.badge.sym);
    assert_eq!(loading.hero.line, row.badge.word);
    assert_eq!(loading.hero.sub.as_deref(), Some(row.detail.as_str()));
    // No problems or fixes yet (the page shows its reading text), the Steam app is known.
    assert!(loading.problems.is_empty() && loading.fixes.is_empty());
    assert_eq!(loading.facts.len(), 1);
    assert_eq!(loading.facts[0].value, Value::Text("220".to_owned()));

    // The whole page is for the same app, title and facts the loading page showed.
    let whole = game_of(&sys, 220, Lang::En);
    assert_eq!(whole.app_id, loading.app_id);
    assert_eq!(whole.title, loading.title);
    assert_eq!(whole.facts[0], loading.facts[0]);

    // A game the library does not list: a neutral hero and the app number as the title.
    let unlisted = vm::game_loading(999, None, None, Lang::De);
    assert!(unlisted.title.as_str().contains("999"));
    assert_eq!(unlisted.hero.line, "Rerun liest den Spielordner ein.");
}

/// AW-FX: [`indexed`]'s world with app 250 ("Future Game") and 260 ("Odd Game") installed, and
/// an index in which the only Topo of 250 is of entry format 2, the only Topo of 260 has a key
/// this version does not know, and 220 has a usable Topo and a format-2 one.
fn aside_world() -> FakeSystem {
    let sys = steam_world("Invented AC");
    for (app, name, dir) in [(250, "Future Game", "F"), (260, "Odd Game", "O")] {
        sys.fake_fs()
            .put_file(
                Path::new(&format!(r"{LIB}\steamapps\appmanifest_{app}.acf")),
                acf(app, name, 4, dir).as_bytes(),
            )
            .unwrap();
        sys.fake_fs()
            .put_file(
                Path::new(&format!(r"{LIB}\steamapps\common\{dir}\game.exe")),
                &x86(),
            )
            .unwrap();
    }
    let sha = sha256_of(&sys, "game.exe");
    let step = r#"{"compat_layer":{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}"#;
    let ix = format!(
        r#"{{"format":1,"seq":7,"issued":"2026-11-12T12:00:00Z","topos":[
{{"format":2,"id":"future-game","match":{{"steam_appid":250}},"future":true}},
{{"format":1,"id":"invented-ac","title":"Invented AC","status":"active","rev":3,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"issues":[{{"id":"display","title":"Display","variants":[{{"id":"layer","status":"verified","kind":"fix","steps":[{step}]}}]}}]}},
{{"format":2,"id":"invented-ac-next","match":{{"steam_appid":220}}}},
{{"format":1,"id":"odd-game","match":{{"steam_appid":260}},"future":1}}
],"packages":[]}}"#
    );
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

#[test]
fn aw_fx_set_aside_topos_on_the_row_and_the_game_page() {
    let sys = aside_world();
    for (lang, newer, unsupported, status, note) in [
        (
            Lang::En,
            "Needs a newer version of Rerun",
            "Not supported by this version of Rerun",
            "Topo index 7 \u{b7} 3 entries not usable",
            "Another Topo for this game needs a newer version of Rerun.",
        ),
        (
            Lang::De,
            "Braucht eine neuere Rerun-Version",
            "Von dieser Rerun-Version nicht unterstützt",
            "Topo-Index 7 \u{b7} 3 Einträge nicht nutzbar",
            "Ein weiterer Topo für dieses Spiel braucht eine neuere Rerun-Version.",
        ),
    ] {
        let ev = events(&sys, &Job::Library, lang);
        let rows = rows_of(&ev);
        let row = |app: u32| *rows.iter().find(|r| r.app_id == app).unwrap();
        // The row: symbol and word, listed with the games Rerun offers nothing for.
        assert_eq!(row(250).group, Group::NoTopo);
        assert_eq!(
            (row(250).badge.sym, row(250).badge.word.as_str()),
            (Sym::Attention, newer)
        );
        assert_eq!(row(260).group, Group::NoTopo);
        assert_eq!(
            (row(260).badge.sym, row(260).badge.word.as_str()),
            (Sym::NotHere, unsupported)
        );
        assert_eq!(row(220).group, Group::Topo);
        let Some(Event::LibraryDone(done)) = ev.last() else {
            panic!("{ev:?}")
        };
        assert_eq!(done.index.status, status);

        // The game page: the row's status as the hero, nothing offered, why behind the details.
        let g = game_of(&sys, 250, lang);
        assert_eq!((g.hero.sym, g.hero.line.as_str()), (Sym::Attention, newer));
        assert_eq!(
            g.hero.sub.as_deref(),
            Some(&*crate::text::t(lang, crate::text::Msg::HeroNeedsNewerSub))
        );
        assert!(g.problems.is_empty() && g.fixes.is_empty());
        assert_eq!(g.aside.len(), 1);
        assert_eq!(g.aside[0].who.as_ref().unwrap().as_str(), "future-game");
        assert!(
            g.aside[0]
                .what
                .as_str()
                .starts_with("entry format 2 needs a newer version"),
            "{:?}",
            g.aside[0].what
        );
        let g = game_of(&sys, 260, lang);
        assert_eq!(
            (g.hero.sym, g.hero.line.as_str()),
            (Sym::NotHere, unsupported)
        );
        assert_eq!(
            g.hero.sub.as_deref(),
            Some(&*crate::text::t(lang, crate::text::Msg::HeroUnsupportedSub))
        );
        assert!(g.fixes.is_empty());
        assert!(
            g.aside[0]
                .what
                .as_str()
                .starts_with("not readable by this build"),
            "{:?}",
            g.aside[0].what
        );

        // A usable Topo next to a set-aside one: the Topo's page with a hint and why.
        let g = game_of(&sys, 220, lang);
        assert_eq!(g.fixes.len(), 1);
        assert!(g.notes.iter().any(|n| n == note), "{:?}", g.notes);
        assert_eq!(g.aside.len(), 1);
        assert_eq!(
            g.aside[0].who.as_ref().unwrap().as_str(),
            "invented-ac-next"
        );
    }
}

mod download;
mod helper;
mod write;
