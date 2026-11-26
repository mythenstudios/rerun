//! The options of a game through the worker (ADR 0032, plan P5-OE "UI"), in the fake world. Every
//! ID, step and hash is invented.
//! - OW1 the page lists an option with "Unchanged" first; a chosen value is planned with the
//!   picks as one plan, applied, shown as live with the change number, and an undo is bit for
//!   bit.
//! - OW2 a choice the page does not offer (a value that is not there, "Unchanged") plans nothing
//!   and says so.

use std::path::Path;

use rerun_core::plan::Choice;

use super::write::{Rig, applied_of, dialog_of, game_in, result_of};
use super::*;
use crate::vm::{Selection, Tone};

const VIDEO_INI: &str = "[Video]\r\nMode=0\r\n";

/// The Topo of the option tests: the option `mode` (two `ini_set` values on `video.ini`), a fix
/// `limit` (a CPU rule) for the problem `crash`. `extra` adds `match.exes` entries, `launch` an
/// option with `start` values.
fn options_index(sha: &str, extra: &str, launch: &str, status: &str) -> String {
    let mode = |v: &str| {
        format!(
            r#"{{"ini_set":{{"file":"video.ini","values":[{{"section":"Video","key":"Mode","value":"{v}"}}]}}}}"#
        )
    };
    let wiki = r#"{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented_W"}"#;
    format!(
        r#"{{"format":1,"seq":9,"issued":"2026-11-26T12:00:00Z","topos":[{{"format":1,"id":"invented-w","title":"Invented W","status":"{status}","rev":3,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}{extra}]}},
"launch":{{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}},
"options":[{{"id":"mode","title":"Window mode","sources":[{wiki}],"values":[
 {{"id":"windowed","title":"Windowed","status":"verified","steps":[{win}]}},
 {{"id":"fullscreen","title":"Fullscreen","status":"unverified","steps":[{full}]}}]}}{launch}],
"issues":[
 {{"id":"crash","title":"The game crashes with many cores","variants":[
   {{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8}}}}]}}]}}
]}}],"packages":[]}}"#,
        win = mode("1"),
        full = mode("2"),
    )
}

pub(super) fn world_with(index: impl Fn(&str) -> String) -> FakeSystem {
    let sys = steam_world_gpu("Invented W", None);
    sys.fake_fs()
        .put_file(Path::new(&format!(r"{G}\video.ini")), VIDEO_INI.as_bytes())
        .unwrap();
    // Two more builds of the game, for the launch values.
    for exe in ["game_dx9.exe", "game_dx10.exe"] {
        sys.fake_fs()
            .put_file(Path::new(&format!(r"{G}\{exe}")), &x86())
            .unwrap();
    }
    let ix = index(&sha256_of(&sys, "game.exe"));
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

pub(super) fn rig(lang: Lang, index: impl Fn(&str) -> String) -> Rig {
    Rig {
        sys: world_with(index),
        session: Session::default(),
        lang,
        nonce: 0,
    }
}

fn ini_rig(lang: Lang) -> Rig {
    rig(lang, |sha| options_index(sha, "", "", "active"))
}

fn choice(option: &str, value: &str) -> Choice {
    Choice {
        option: option.to_owned(),
        value: value.to_owned(),
    }
}

#[test]
fn ow1_a_chosen_value_is_planned_applied_shown_as_live_and_undone() {
    for lang in Lang::ALL {
        let mut rig = ini_rig(lang);
        let before = rig.snap();
        let page = rig.page();
        assert_eq!(page.options.options.len(), 1);
        let o = &page.options.options[0];
        assert_eq!(o.key, "mode");
        let keys: Vec<&str> = o.choices.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["", "windowed", "fullscreen"], "Unchanged first");
        assert!(o.live.is_none() && page.options.notice.is_none());

        // One selection: the preselected fix and a value, one preview.
        let mut sel = Selection::preselected(&page);
        sel.choose(&page, 0, 1);
        assert_eq!(sel.checked(&page), [1]);
        let ev = rig.run(Job::Plan {
            manual: None,
            app_id: 220,
            picks: sel.picks(&page),
            choices: sel.choices(&page),
        });
        let [Event::Preview { vm: pv, .. }] = ev.as_slice() else {
            panic!("{ev:?}")
        };
        assert!(
            pv.ops
                .iter()
                .any(|o| o.target.as_str().contains("video.ini")),
            "the INI edit of the option is in the preview"
        );
        let parts = pv.parts.as_ref().expect("the parts of the profile");
        assert_eq!(parts.parts.len(), 1, "only the fix sets a part");
        assert_eq!(
            parts.parts[0].from_name.as_ref().map(|n| n.as_str()),
            Some("limit")
        );
        assert!(
            parts.fallback.flat().contains("FFLauncher.exe"),
            "{}",
            parts.fallback.flat()
        );
        let hash = pv.hash.clone();
        rig.run(Job::PreviewShown { hash: hash.clone() });
        let ev = rig.run(Job::Apply { hash });
        assert_eq!(result_of(&ev).tone, Tone::Done);
        assert_eq!(
            rig.read(&format!(r"{G}\video.ini")),
            b"[Video]\r\nMode=1\r\n"
        );

        // The page after the apply: the value is live, with the change number, and checked.
        let page = game_in(&ev).clone();
        let txn = applied_of(&ev).cards[0].txn;
        let live = page.options.options[0].live.as_ref().expect("live value");
        assert_eq!((live.value.as_str(), live.txn), ("windowed", txn));
        let line = live.line.flat();
        assert!(line.contains("Windowed"), "{line}");
        assert!(line.contains(&txn.seq().to_string()), "{line}");
        let mut sel = Selection::default();
        sel.keep(&page);
        assert_eq!(sel.checked(&page), [1], "the live value is preselected");
        assert!(sel.choices(&page).is_empty(), "what is live is no choice");

        // "Unchanged" while it is live explains, plans nothing and selects nothing.
        sel.choose(&page, 0, 0);
        assert_eq!(sel.hint(), Some(0));
        assert_eq!(sel.checked(&page), [1]);
        assert!(sel.is_empty(&page));
        // Another value replaces it: a choice, in one plan.
        sel.choose(&page, 0, 2);
        assert_eq!(sel.choices(&page), [choice("mode", "fullscreen")]);
        assert_eq!(sel.hint(), None);

        // Undo: the page has no live value, the game folder is as it was.
        let ev = rig.run(Job::RevertPreview { txn });
        assert!(dialog_of(&ev).can_confirm);
        let ev = rig.revert(txn);
        assert_eq!(result_of(&ev).tone, Tone::Done);
        assert!(game_in(&ev).options.options[0].live.is_none());
        let after = rig.snap();
        assert!(after == before, "{:#?}", before.diff(&after));
    }
}

#[test]
fn ow2_a_choice_the_page_does_not_offer_plans_nothing() {
    let mut rig = ini_rig(Lang::En);
    let _ = rig.page();
    let before = rig.snap_app();
    for c in [
        choice("mode", "unchanged"),
        choice("mode", "borderless"),
        choice("nothing", "windowed"),
    ] {
        let ev = rig.run(Job::Plan {
            manual: None,
            app_id: 220,
            picks: Vec::new(),
            choices: vec![c],
        });
        assert!(
            matches!(ev.as_slice(), [Event::PreviewRefused { .. }]),
            "{ev:?}"
        );
    }
    // Neither a pick nor a choice: the preview is cleared.
    let ev = rig.run(Job::Plan {
        manual: None,
        app_id: 220,
        picks: Vec::new(),
        choices: Vec::new(),
    });
    assert_eq!(ev, [Event::PreviewNone { app_id: 220 }]);
    assert!(rig.snap_app() == before, "nothing was stored");
}
