//! FX11, the CLI (ADR 0024 amendment "Forward compatibility" §10) against the fake, with an
//! index signed by the published test key. Every Topo, package and ID is invented.
//! - C-FX1 `index import` and `index show`: one line for the entries that need a newer Rerun,
//!   one for the ones this version cannot use (with the reason); the exit code unchanged.
//! - C-FX2 `plan <app-id>` for an app with a usable and a set-aside Topo: the set-aside one
//!   named, the usable one reported and planned.
//! - C-FX3 `plan <app-id>` for an app whose only Topos are set aside: named with the reason,
//!   nothing offered; `--pick` refused (exit 3).
//! - C-FX4 `package fetch` of a set-aside package: refused (exit 3), nothing fetched.
//! - C-FX5 a hostile reason is escaped on every line that shows it.

use std::path::Path;

use rerun_core::catalog::key::test_key;
use rerun_core::catalog::model::Id;
use rerun_core::catalog::{Aside, AsideWhy, EntryKind, RuleError};
use rerun_core::escape;
use rerun_core::sys::fake::FakeSystem;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::lm_tests::{lm_sys, steps};
use crate::messages::{IndexMsg, PackageMsg, TopoMsg};
use crate::tests::expect;
use crate::topo_tests::sha256_of;

const INDEX: &str = r"D:\Work\index.json";
const SIG: &str = r"D:\Work\index.json.sig";

/// App 220 (installed): a usable Topo and one of entry format 2. App 230: only a format-2
/// Topo. App 240: only a format-1 Topo with a key this build does not know. A format-2
/// package and a format-1 package with an unknown key.
fn index(sha: &str) -> String {
    format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-12T12:00:00Z","topos":[
{{"format":1,"id":"invented-game","title":"Invented Game","status":"active","rev":1,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"issues":[{{"id":"display","title":"Display","variants":[{{"id":"layer","status":"verified","kind":"fix","steps":[{{"compat_layer":{{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}}}]}}]}}]}},
{{"format":2,"id":"invented-game-next","match":{{"steam_appid":220}},"future":true}},
{{"format":2,"id":"only-newer","match":{{"steam_appid":230}}}},
{{"format":1,"id":"only-unusable","match":{{"steam_appid":240}},"future":1}}
],"packages":[
{{"format":2,"id":"future-pack"}},
{{"format":1,"id":"odd-pack","future":1}}
]}}"#
    )
}

fn sys() -> (FakeSystem, crate::tests::Ran) {
    let sys = lm_sys(false, &steps(8));
    let ix = index(&sha256_of(&sys, "game.exe"));
    sys.fake_fs()
        .put_file(Path::new(INDEX), ix.as_bytes())
        .unwrap();
    sys.fake_fs()
        .put_file(Path::new(SIG), &test_key::sign(ix.as_bytes()))
        .unwrap();
    sys.fake_fs().sync_all();
    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
    (sys, r)
}

const NEWER: &str = "  3 entries need a newer version of Rerun: topo invented-game-next, topo only-newer, package future-pack\n";
const UNUSABLE: &str = "  2 entries cannot be used by this version of Rerun: topo only-unusable (not readable by this build (data at line 1, column ";

#[test]
fn c_fx1_index_import_and_show_name_the_set_aside_entries() {
    let (sys, r) = sys();
    assert!(
        r.stdout
            .starts_with("index 1 imported\nindex 1: 1 topos, 0 packages, key "),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains(NEWER), "{}", r.stdout);
    assert!(r.stdout.contains(UNUSABLE), "{}", r.stdout);
    assert!(
        r.stdout
            .contains("), package odd-pack (not readable by this build (data at line 1, column "),
        "{}",
        r.stdout
    );
    let r = expect(&sys, &["index", "show"], Answer::No, Exit::Report);
    assert!(r.stdout.contains(NEWER), "{}", r.stdout);
    assert!(r.stdout.contains(UNUSABLE), "{}", r.stdout);
    // The newer line before the other, both after the facts.
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert!(lines[2].starts_with("  3 entries need"), "{}", r.stdout);
    assert!(lines[3].starts_with("  2 entries cannot"), "{}", r.stdout);
    assert_eq!(lines.len(), 4, "{}", r.stdout);
}

#[test]
fn c_fx1_one_entry_and_none() {
    let sys = lm_sys(false, &steps(8));
    let ix = br#"{"format":1,"seq":1,"issued":"2026-11-12T12:00:00Z","topos":[{"format":2,"id":"only-newer","match":{"steam_appid":230}}],"packages":[]}"#;
    sys.fake_fs().put_file(Path::new(INDEX), ix).unwrap();
    sys.fake_fs()
        .put_file(Path::new(SIG), &test_key::sign(ix))
        .unwrap();
    sys.fake_fs().sync_all();
    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
    assert!(
        r.stdout
            .ends_with("\n  1 entry needs a newer version of Rerun: topo only-newer\n"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("cannot be used"), "{}", r.stdout);
}

#[test]
fn c_fx2_a_usable_topo_next_to_a_set_aside_one() {
    let (sys, _) = sys();
    let r = expect(&sys, &["plan", "220"], Answer::No, Exit::Report);
    for line in [
        "Topo invented-game-next for this game needs a newer version of Rerun\n",
        "Topo invented-game rev 1 (active): Invented Game\n",
        "    display/layer: verified fix\n",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
    let r = expect(
        &sys,
        &["plan", "220", "--pick", "display/layer", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        r.stdout
            .contains("from Topo invented-game rev 1 of the signed index "),
        "{}",
        r.stdout
    );
}

#[test]
fn c_fx3_only_set_aside_topos_offer_nothing_and_a_pick_is_refused() {
    let (sys, _) = sys();
    let none = "has no Topo for this game that this version of Rerun can use: nothing is offered\n";
    for (app, line) in [
        (
            "230",
            "Topo only-newer for this game needs a newer version of Rerun\n",
        ),
        (
            "240",
            "Topo only-unusable for this game cannot be used by this version of Rerun (not readable by this build (data at line 1, column ",
        ),
    ] {
        let r = expect(&sys, &["plan", app], Answer::No, Exit::Report);
        assert!(
            r.stdout.starts_with(&format!("app {app}: index 1 {none}")),
            "{}",
            r.stdout
        );
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
        let r = expect(
            &sys,
            &["plan", app, "--pick", "display/layer"],
            Answer::No,
            Exit::Refused,
        );
        assert!(r.stdout.contains(none), "{}", r.stdout);
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
}

#[test]
fn c_fx4_a_set_aside_package_is_not_fetched() {
    let (sys, _) = sys();
    let r = expect(
        &sys,
        &["package", "fetch", "future-pack@1.0"],
        Answer::No,
        Exit::Refused,
    );
    assert_eq!(
        r.stderr,
        "rerun: package future-pack needs a newer version of Rerun: nothing fetched\n"
    );
    let r = expect(
        &sys,
        &["package", "fetch", "odd-pack@1.0"],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        r.stderr.starts_with(
            "rerun: package odd-pack cannot be used by this version of Rerun (not readable by this build (data at line 1, column "
        ),
        "{}",
        r.stderr
    );
    assert!(r.stderr.ends_with(")): nothing fetched\n"), "{}", r.stderr);
}

#[test]
fn c_fx5_a_hostile_reason_is_escaped() {
    let a = Aside {
        kind: EntryKind::Topo,
        id: Id::parse("evil").unwrap(),
        format: 1,
        steam_appid: Some(230),
        why: AsideWhy::Refused(RuleError {
            at: String::new(),
            what: "fine\u{202e}txt.exe\u{1b}[2J".to_owned(),
        }),
    };
    let why = crate::index::aside_why(&a).unwrap();
    let want = r#""breaks a rule of this build: fine\u{202e}txt.exe\u{1b}[2J""#;
    assert_eq!(why.as_str(), want);
    let lines = [
        TopoMsg::Aside {
            id: escape::text(a.id.as_str()).into_owned(),
            newer: false,
            why: Some(why.clone()),
        }
        .to_string(),
        PackageMsg::Aside {
            id: escape::text(a.id.as_str()).into_owned(),
            newer: false,
            why: Some(why),
        }
        .to_string(),
        IndexMsg::AsideUnusable {
            entries: vec![crate::index::aside_shown(&a)],
        }
        .to_string(),
    ];
    for l in &lines {
        assert!(
            !l.contains('\u{202e}') && !l.contains('\u{1b}'),
            "{}",
            l.escape_debug()
        );
        assert!(l.contains(r"\u{202e}"), "{l}");
        // An empty `at` adds no ": :".
        assert!(!l.contains(": :"), "{l}");
    }
    assert_eq!(
        lines[0],
        format!("Topo evil for this game cannot be used by this version of Rerun ({want})")
    );
}
