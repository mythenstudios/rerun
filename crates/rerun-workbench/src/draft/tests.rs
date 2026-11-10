//! `draft` (P4-14) end to end against `FakeHttp` with the synthetic replies of
//! `tests/fixtures/pcgw/` (D3 b): T2 the golden draft and its requests, T5 the YAML stays
//! data, T6 it loads like a source Topo and is never released, T7 `--into` never overwrites and
//! writes nothing on an error.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rerun_core::catalog::Topo;
use rerun_core::catalog::check::{self, Rules};
use rerun_core::catalog::model::{Api, Id};
use rerun_core::sys::fake::{FakeHttp, FakeReply};
use serde_json::Value;

use super::*;
use crate::bundle::{SourceFile, build as bundle_build};
use crate::pcgw::tests::{QUEST, RACER, RACER_LOOKUP, RACER_URL};
use crate::pcgw::{ApiFacts, PageName};

const QUEST_URL: &str = "https://www.pcgamingwiki.com/w/api.php?action=parse&format=json&formatversion=2&prop=wikitext%7Csections&page=Invented_Quest%3A_Gold_Edition";

const RACER_GOLDEN: &str = r#"# Draft from PCGamingWiki (rerun-workbench draft): facts and links only.
# Curate it (docs/02-topo-format.md) before it leaves status draft.
# Page: https://www.pcgamingwiki.com/wiki/Invented_Racer_2
format: 1
id: "invented-racer-2"
title: "Invented Racer 2"
status: "draft"
rev: 1
match:
  steam_appid: 1234560
  exes:
    # TODO: the executable's path and hash (computed from the game files)
    - { path: "TODO", sha256: "TODO", api: "d3d9" }
# PCGW API: Direct3D 9; 32-bit exe yes, 64-bit exe no
# TODO: PCGW: field of view hackable - https://www.pcgamingwiki.com/wiki/Invented_Racer_2#Video
# TODO: PCGW: 60 FPS hackable - https://www.pcgamingwiki.com/wiki/Invented_Racer_2#Video
# TODO launch: chain, method and start (docs/02-topo-format.md, launch.start); never guessed.
issues: []
# TODO issue: https://www.pcgamingwiki.com/wiki/Invented_Racer_2#Skip_intro_videos
# TODO issue: https://www.pcgamingwiki.com/wiki/Invented_Racer_2#Crash_on_start
# TODO issue: https://www.pcgamingwiki.com/wiki/Invented_Racer_2#Stutter_with_many_cores
# TODO issue: https://www.pcgamingwiki.com/wiki/Invented_Racer_2#Audio_desync
links:
  pcgw: "Invented_Racer_2"
"#;

fn http() -> FakeHttp {
    let h = FakeHttp::default();
    h.reply(
        RACER_LOOKUP,
        FakeReply::redirect(302, "https://www.pcgamingwiki.com/wiki/Invented_Racer_2"),
    );
    h.reply(RACER_URL, FakeReply::ok(RACER));
    h.reply(QUEST_URL, FakeReply::ok(QUEST));
    h
}

fn req(target: Target) -> Request {
    Request {
        target,
        id: None,
        title: None,
    }
}

fn page(s: &str) -> Target {
    Target::Page(PageName::parse(s).unwrap())
}

fn run(h: &FakeHttp, r: &Request) -> Result<(Draft, String), String> {
    make(h, r, Duration::ZERO, Duration::from_secs(60))
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ---------- T2 ----------

#[test]
fn t2_an_app_id_gives_the_golden_draft_in_two_requests() {
    let h = http();
    let (d, text) = run(&h, &req(Target::SteamApp(1_234_560))).unwrap();
    assert_eq!(text, RACER_GOLDEN);
    assert_eq!(h.requests(), [RACER_LOOKUP, RACER_URL]);
    assert!(
        h.requests()
            .iter()
            .all(|u| u.starts_with("https://www.pcgamingwiki.com/"))
    );
    assert_eq!(d.exes, Exes::Stub(Api::D3d9));
    // The same page by name: one request, the same draft.
    let h = http();
    assert_eq!(
        run(&h, &req(page("Invented_Racer_2"))).unwrap().1,
        RACER_GOLDEN
    );
    assert_eq!(h.requests(), [RACER_URL]);
}

#[test]
fn t2_no_text_of_the_page_reaches_the_draft() {
    let (_, text) = run(&http(), &req(page("Invented Racer 2"))).unwrap();
    for marker in [
        "NEVER-COPIED",
        "Nobody Studio",
        "commercial",
        "Fixbox",
        "Some Link",
    ] {
        assert!(!text.contains(marker), "{marker}");
    }
    assert!(text.is_ascii());
}

#[test]
fn t2_an_app_id_the_page_does_not_name_is_refused() {
    let h = http();
    h.reply(
        "https://www.pcgamingwiki.com/api/appid.php?appid=99",
        FakeReply::redirect(302, "https://www.pcgamingwiki.com/wiki/Invented_Racer_2"),
    );
    let e = run(&h, &req(Target::SteamApp(99))).unwrap_err();
    assert!(e.contains("does not name Steam app 99"), "{e}");
}

#[test]
fn t2_several_apis_need_the_executable() {
    let e = run(&http(), &req(page("Invented Quest: Gold Edition"))).unwrap_err();
    assert!(e.contains("Direct3D 9, 10; OpenGL"), "{e}");
    assert!(e.contains("match.exes"), "{e}");
}

#[test]
fn t2_ids_titles_and_apis() {
    let id = |s: &str| derive_id(&PageName::parse(s).unwrap()).map(|i| i.to_string());
    assert_eq!(id("Invented Racer 2").as_deref(), Some("invented-racer-2"));
    assert_eq!(
        id("Invented's Quest: Gold (2004)").as_deref(),
        Some("inventeds-quest-gold-2004")
    );
    assert_eq!(id("-a--b-").as_deref(), Some("a-b"));
    assert_eq!(id(&"ab ".repeat(30)).map(|s| s.len()), Some(64));
    // Cut at 64, a hyphen left at the end goes.
    assert_eq!(id(&"abc ".repeat(30)).map(|s| s.len()), Some(63));
    assert_eq!(id("\u{00C9}tude"), None);
    assert_eq!(id("!!!"), None);
    assert!(check_title("A \"quoted\" title").is_some());
    for bad in ["", " a", "a\u{202E}", "a\nb", "a\u{0}", &"a".repeat(201)] {
        assert!(check_title(bad).is_none(), "{bad:?}");
    }
    let api = |d3d: &[u8], ddraw, opengl, vulkan| ApiFacts {
        d3d: d3d.to_vec(),
        ddraw,
        opengl,
        vulkan,
        glide: false,
    };
    assert_eq!(stub_api(&api(&[9], false, false, false)), Some(Api::D3d9));
    assert_eq!(stub_api(&api(&[7], true, false, false)), Some(Api::Ddraw));
    assert_eq!(stub_api(&api(&[], false, true, false)), Some(Api::Opengl));
    assert_eq!(stub_api(&api(&[9, 10], false, false, false)), None);
    assert_eq!(stub_api(&api(&[11], false, false, true)), None);
    assert_eq!(stub_api(&api(&[12], false, false, false)), None);
    assert_eq!(stub_api(&api(&[], false, false, false)), None);
}

/// The quest with one API: several app IDs become a comment, the hand-given ID and title are
/// used, a non-ASCII anchor is encoded.
fn quest_one_api() -> (FakeHttp, Request) {
    let h = http();
    let body = String::from_utf8(QUEST.to_vec())
        .unwrap()
        .replace("9.0c, 10, 10.1", "9")
        .replace("|opengl versions = true\\n", "");
    h.reply(QUEST_URL, FakeReply::ok(body.as_bytes()));
    let r = Request {
        id: Some(Id::parse("invented-quest").unwrap()),
        title: Some("Invented Quest: \"Gold\" \\ Edition".into()),
        ..req(page("Invented Quest: Gold Edition"))
    };
    (h, r)
}

#[test]
fn t2_page_target_with_several_app_ids() {
    let (h, r) = quest_one_api();
    let (d, text) = run(&h, &r).unwrap();
    assert_eq!(d.steam_appid, None);
    assert!(
        text.contains("# TODO match.steam_appid: PCGW names several app IDs: 2345670, 2345671\n")
    );
    assert!(text.contains("# PCGW: no {{Video}} template on the page\n"));
    assert!(text.contains("#.22modern.22_GPUs_and_%C3%A9\n"));
    assert!(text.contains("title: \"Invented Quest: \\\"Gold\\\" \\\\ Edition\"\n"));
    assert!(text.contains("pcgw: \"Invented_Quest:_Gold_Edition\"\n"));
}

// ---------- T5 ----------

/// Every line that is not a comment is one of the template's.
fn template_line(l: &str) -> bool {
    const FIXED: [&str; 8] = [
        "format: 1",
        "status: \"draft\"",
        "rev: 1",
        "match:",
        "  exes:",
        "issues: []",
        "links:",
        "",
    ];
    FIXED.contains(&l)
        || l.trim_start().starts_with("# ")
        || ["id: \"", "title: \"", "  pcgw: \""]
            .iter()
            .any(|p| l.starts_with(p) && l.ends_with('"'))
        || l.starts_with("  steam_appid: ") && l[15..].bytes().all(|c| c.is_ascii_digit())
        || l.starts_with("    - { path: \"") && l.ends_with(" }")
}

#[test]
fn t5_titles_stay_data() {
    for title in [
        "A \"B\" \\ C",
        "# not a comment",
        "key: value",
        "{ flow: map }",
        "- item",
        "[a, b]",
        "&anchor *alias !tag",
        "'single' %YAML",
        "TODO",
        "\u{00E9}\u{4E00} \u{0627}",
    ] {
        let r = Request {
            title: Some(title.into()),
            ..req(page("Invented Racer 2"))
        };
        let result = run(&http(), &r);
        if title == "TODO" {
            // A TODO title is a draft still: allowed, and it reads back as given.
            let (_, text) = result.unwrap();
            assert!(text.contains("title: \"TODO\"\n"));
            continue;
        }
        let (_, text) = result.unwrap();
        let t: Topo = serde_json::from_value(load_yaml(&text).unwrap()).unwrap();
        assert_eq!(t.title, title);
        for l in text.lines() {
            assert!(template_line(l), "{l:?}");
        }
        let data: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect();
        for word in ["steps:", "variants:", "launch:", "tips:"] {
            assert!(data.iter().all(|l| !l.contains(word)), "{word}");
        }
    }
}

#[test]
fn t5_the_self_check_refuses_text_that_reads_back_otherwise() {
    let (d, text) = run(&http(), &req(page("Invented Racer 2"))).unwrap();
    for (from, to) in [
        ("rev: 1", "rev: 2"),
        ("status: \"draft\"", "status: \"active\""),
        ("issues: []", "issues: [}"),
        ("api: \"d3d9\"", "api: \"d3d10\""),
        ("  pcgw: \"Invented_Racer_2\"", "  pcgw: \"Other\""),
        (
            "issues: []",
            "issues: []\nlaunch: { chain: [steam], method: auto, start: \"TODO\" }",
        ),
        ("# Page", "# \u{00E9} Page"),
    ] {
        let bad = text.replacen(from, to, 1);
        assert_ne!(bad, text);
        assert!(self_check(&bad, &d).is_err(), "{to}");
    }
}

// ---------- T6 ----------

fn schema() -> jsonschema::Validator {
    let v: Value = serde_json::from_str(
        &fs::read_to_string(repo().join("schema").join("topo.schema.json")).unwrap(),
    )
    .unwrap();
    jsonschema::validator_for(&v).unwrap()
}

#[test]
fn t6_drafts_load_as_source_never_as_release() {
    let v = schema();
    let (h, r) = quest_one_api();
    for (h, r) in [
        (http(), req(Target::SteamApp(1_234_560))),
        (http(), req(page("Invented Racer 2"))),
        (h, r),
    ] {
        let (d, text) = run(&h, &r).unwrap();
        let doc = load_yaml(&text).unwrap();
        let errors: Vec<String> = v.iter_errors(&doc).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "{errors:?}");
        let t: Topo = serde_json::from_value(doc).unwrap();
        check::topo(&t, Rules::Source).unwrap();
        assert!(check::topo(&t, Rules::Release).is_err());
        let b = bundle_build(
            &[SourceFile {
                name: format!("{}.yaml", d.id),
                text: text.clone(),
            }],
            &[],
            1,
            "2026-11-10T12:00:00Z",
        )
        .unwrap();
        assert_eq!(b.excluded, [format!("topo {}", d.id)]);
        assert!(b.index.topos.is_empty());
    }
}

// ---------- T7 ----------

/// A new empty folder below the temp folder (no system change), removed by the caller.
fn temp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("rerun-workbench-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir(&p).unwrap();
    p
}

#[test]
fn t7_into_never_overwrites() {
    let dir = temp("draft-into");
    let (d, text) = run(&http(), &req(page("Invented Racer 2"))).unwrap();
    let p = write_into(&dir, &d, &text).unwrap();
    assert_eq!(p, dir.join("invented-racer-2.yaml"));
    assert_eq!(fs::read_to_string(&p).unwrap(), text);
    // A second write fails and leaves the file as it was.
    fs::write(&p, b"curated by hand").unwrap();
    assert!(write_into(&dir, &d, &text).is_err());
    assert_eq!(fs::read(&p).unwrap(), b"curated by hand");
    // Other files of the folder that name the app ID are named (the file overwritten by hand
    // above no longer does).
    fs::write(dir.join("other.yaml"), "match:\n  steam_appid: 1234560\n").unwrap();
    fs::write(dir.join("third.yaml"), "match:\n  steam_appid: 7\n").unwrap();
    assert_eq!(same_app(&dir, 1_234_560), ["other.yaml"]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn t7_nothing_on_an_error() {
    let h = FakeHttp::default();
    h.reply(RACER_URL, FakeReply::status(503));
    let e = run(&h, &req(page("Invented Racer 2"))).unwrap_err();
    assert!(e.contains("try later"), "{e}");
    // `make` returns no text on an error; with nothing returned, nothing can be written.
    let h = FakeHttp::default();
    let e = run(&h, &req(page("Invented Racer 2"))).unwrap_err();
    assert!(e.contains("www.pcgamingwiki.com"), "{e}");
    assert_eq!(h.requests(), [RACER_URL]);
}
