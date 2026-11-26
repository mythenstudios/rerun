//! The loader rules of `options` (ADR 0032 and its amendment P5-OE, slice O-1). The schema side
//! and the parity with it are `tests/schema.rs` and `tests/catalog_parity.rs` (fixtures
//! `topo-options.yaml` and `topo-option-*.yaml`).
//!
//! - OX1 a Topo with `ini_set` values only loads outside a draft and round-trips; without
//!   `options` the bytes do not change; the floor stays at format 1.
//! - OX2 option IDs are unique and none is an issue ID.
//! - OX3 values: `unchanged` is reserved, IDs unique, 1 to 8, never two with the same steps.
//! - OX4 two options never set the same INI file (folded, per root); one value sets a file once.
//! - OX5 `start`: an `.exe` of `match.exes` in exactly its spelling, every entry with a
//!   `sha256`, not `launch.start`.
//! - OX6 `start` and `launch_args` need Steam's own start the profile can take over: chain
//!   `[steam]`, method `auto` or `direct`, `launch.start` named.
//! - OX7 `launch_args` without `start` only when `launch.start` is an executable of
//!   `match.exes` (else the arguments reach a launcher).
//! - OX8 the argument rules: the pattern, 1 to 8, at most 512 bytes joined.
//! - OX9 the gate: `start` and `launch_args` draft only until reviewed; `ini_set` values not.
//! - OX10 per value at most one `start`, one `launch_args`, 1 to 4 steps; at most 8 options.
//! - OX11 an `ini_set` in the user data folder needs the Topo's `user_data`.
//! - OX12 `start` lies in the folder of `launch.start` (folded; review S3).
//! - OX13 `start` (`launch_args`) in every value of an option or in none (O-2b review S1).

use serde_json::{Value, json};

use super::super::check::{self, OPTION_LAUNCH_REVIEWED, RuleError, Rules, topo_floor};
use super::super::model::Topo;

const S1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const S2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn ini(file: &str, value: &str) -> Value {
    json!({ "ini_set": { "file": file, "values": [{ "section": "S", "key": "k", "value": value }] } })
}

fn value(id: &str, steps: Value) -> Value {
    json!({ "id": id, "title": id, "status": "unverified", "steps": steps })
}

fn option(id: &str, values: Value) -> Value {
    json!({
        "id": id,
        "title": "An option",
        "sources": [{ "type": "pcgw", "url": "https://www.pcgamingwiki.com/wiki/Invented" }],
        "values": values,
    })
}

/// An active Topo: `game.exe` (sha256), `game_dx9.exe` (sha256), `tool.exe` (sha1 only); Steam
/// starts `launcher.exe`, no executable of `match.exes`; option `cap` with two `ini_set` values;
/// issue `crash`.
fn base() -> Value {
    json!({
        "format": 1, "id": "invented-game", "title": "Invented Game", "status": "active", "rev": 1,
        "match": { "steam_appid": 220, "exes": [
            { "path": "game.exe", "sha256": S1, "api": "d3d10" },
            { "path": "game_dx9.exe", "sha256": S2, "api": "d3d9" },
            { "path": "tool.exe", "sha1": "0000000000000000000000000000000000000000", "api": "d3d9" }
        ] },
        "launch": { "chain": ["steam"], "method": "auto", "start": "launcher.exe" },
        "options": [option("cap", json!([
            value("off", json!([ini("game.ini", "0")])),
            value("sixty", json!([ini("game.ini", "60")]))
        ]))],
        "issues": [{ "id": "crash", "title": "Crash", "variants": [] }]
    })
}

fn draft(mut v: Value) -> Value {
    v["status"] = json!("draft");
    v
}

fn parse(v: &Value) -> Topo {
    serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{e}: {v}"))
}

fn ok(v: &Value) {
    check::topo(&parse(v), Rules::Source).unwrap_or_else(|e| panic!("{e}: {v}"));
}

fn refused(v: &Value) -> RuleError {
    match check::topo(&parse(v), Rules::Source) {
        Err(e) => e,
        Ok(()) => panic!("loaded: {v}"),
    }
}

fn refused_at(v: &Value, at: &str, what: &str) {
    let e = refused(v);
    assert_eq!(e.at, at, "{e}");
    assert!(e.what.contains(what), "{what}: {e}");
}

/// `base` with option `api` holding `values` (a draft, so the gate does not speak).
fn with_api(values: Value) -> Value {
    let mut v = draft(base());
    v["options"]
        .as_array_mut()
        .unwrap()
        .push(option("api", values));
    v
}

#[test]
fn ox1_ini_values_load_outside_a_draft_and_round_trip() {
    let v = base();
    ok(&v);
    let t = parse(&v);
    check::topo(&t, Rules::Release).unwrap();
    let a = serde_json::to_string(&t).unwrap();
    let back: Topo = serde_json::from_str(&a).unwrap();
    assert_eq!(back, t);
    assert_eq!(serde_json::to_string(&back).unwrap(), a);
    assert_eq!(topo_floor(&t).format, 1);
    // Without options: no key on the wire.
    let mut plain = t.clone();
    plain.options.clear();
    let b = serde_json::to_string(&plain).unwrap();
    assert!(!b.contains("options"), "{b}");
    // Unknown fields of an option, a value or a step never parse.
    for (at, extra) in [
        ("/options/0", "x"),
        ("/options/0/values/0", "x"),
        ("/options/0/values/0/steps/0", "cpu"),
    ] {
        let mut w = base();
        w.pointer_mut(at)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(extra.to_owned(), json!({ "max_threads": 8 }));
        assert!(serde_json::from_value::<Topo>(w).is_err(), "{at}.{extra}");
    }
}

#[test]
fn ox2_option_ids_are_unique_and_never_an_issue_id() {
    let mut v = base();
    v["options"][0]["id"] = json!("crash");
    refused_at(&v, "options", "differ from every issue ID");
    let mut v = base();
    let o = v["options"][0].clone();
    v["options"].as_array_mut().unwrap().push(o);
    refused_at(&v, "options", "unique");
}

#[test]
fn ox3_values_unchanged_is_reserved_ids_unique_steps_differ() {
    let mut v = base();
    v["options"][0]["values"][1]["id"] = json!("unchanged");
    refused_at(&v, "options[0].values[1].id", "implicit default");
    let mut v = base();
    v["options"][0]["values"][1]["id"] = json!("off");
    refused_at(&v, "options[0].values", "unique");
    let mut v = base();
    v["options"][0]["values"][1]["steps"] = v["options"][0]["values"][0]["steps"].clone();
    refused_at(
        &v,
        "options[0].values[1].steps",
        "the same steps as value off",
    );
    let mut v = base();
    v["options"][0]["values"] = json!([]);
    refused_at(&v, "options[0].values", "1 to 8 values");
    let mut v = base();
    v["options"][0]["values"] = Value::Array(
        (0..9)
            .map(|i| value(&format!("v{i}"), json!([ini("game.ini", &i.to_string())])))
            .collect(),
    );
    refused_at(&v, "options[0].values", "1 to 8 values");
    let mut v = base();
    v["options"][0]["sources"] = json!([]);
    refused_at(&v, "options[0].sources", "at least one source");
    let mut v = base();
    v["options"][0]["sources"][0]["url"] = json!("https://example.org/");
    refused_at(&v, "options[0].sources[0].url", "not a link");
    let mut v = base();
    v["options"][0]["title"] = json!("");
    refused_at(&v, "options[0].title", "1 to 200");
}

#[test]
fn ox4_two_options_never_set_one_ini_file() {
    let mut v = base();
    v["options"].as_array_mut().unwrap().push(option(
        "other",
        json!([value("on", json!([ini("GAME.INI", "1")]))]),
    ));
    refused_at(
        &v,
        "options[1]",
        "option other sets an INI file option cap sets too",
    );
    // The same name in the user data folder is another file.
    let mut v = base();
    v["user_data"] = json!({ "documents": "My Games\\Invented" });
    let mut ud = ini("game.ini", "1");
    ud["ini_set"]["root"] = json!("user_data");
    v["options"]
        .as_array_mut()
        .unwrap()
        .push(option("other", json!([value("on", json!([ud]))])));
    ok(&v);
    // One value sets a file once.
    let mut v = base();
    v["options"][0]["values"][0]["steps"] = json!([ini("game.ini", "0"), ini("Game.ini", "1")]);
    refused_at(
        &v,
        "options[0].values[0].steps[1].ini_set.file",
        "one ini_set per file",
    );
}

#[test]
fn ox5_start_is_a_build_of_match_exes() {
    ok(&with_api(json!([value(
        "dx9",
        json!([{ "start": "game_dx9.exe" }])
    )])));
    for (start, want) in [
        ("other.exe", "an executable of match.exes"),
        // Exactly its spelling (a case-folded match is no anchor).
        ("GAME_DX9.exe", "an executable of match.exes"),
        ("tool.exe", "needs a sha256"),
        ("game_dx9.dll", "a .exe"),
    ] {
        refused_at(
            &with_api(json!([value("x", json!([{ "start": start }]))])),
            "options[1].values[0].steps[0].start",
            want,
        );
    }
    // `launch.start` itself changes nothing.
    let mut v = with_api(json!([value("x", json!([{ "start": "game.exe" }]))]));
    v["launch"]["start"] = json!("game.exe");
    refused_at(
        &v,
        "options[1].values[0].steps[0].start",
        "the same as launch.start",
    );
}

#[test]
fn ox6_start_and_args_need_steam_s_own_start() {
    let values = json!([value(
        "dx9",
        json!([{ "start": "game_dx9.exe" }, { "launch_args": ["-dx9"] }])
    )]);
    ok(&with_api(values.clone()));
    let need = "needs launch.chain [steam], launch.method auto or direct and launch.start";
    for change in [
        json!({ "chain": ["steam", "upc"], "method": "auto", "start": "launcher.exe" }),
        json!({ "chain": ["steam"], "method": "watch", "start": "launcher.exe" }),
        json!({ "chain": ["steam"], "method": "hold" }),
        json!({ "chain": ["steam"], "method": "direct", "start": "TODO" }),
        json!({ "chain": ["steam"] }),
    ] {
        let mut v = with_api(values.clone());
        v["launch"] = change.clone();
        refused_at(&v, "options[1].values[0].steps[0].start", need);
    }
    let mut v = with_api(values.clone());
    v.as_object_mut().unwrap().remove("launch");
    refused_at(&v, "options[1].values[0].steps[0].start", need);
    let mut v = with_api(json!([value("q", json!([{ "launch_args": ["-q"] }]))]));
    v["launch"]["method"] = json!("watch");
    v["launch"]["start"] = json!("game.exe");
    refused_at(&v, "options[1].values[0].steps[0].launch_args", need);
}

#[test]
fn ox7_args_without_start_only_when_steam_starts_the_game() {
    let args = json!([value("q", json!([{ "launch_args": ["-q"] }]))]);
    // Steam starts the launcher: the arguments would reach it.
    refused_at(
        &with_api(args.clone()),
        "options[1].values[0].steps[0].launch_args",
        "only when launch.start is an executable of match.exes",
    );
    // Steam starts the game itself.
    let mut v = with_api(args);
    v["launch"]["start"] = json!("game.exe");
    ok(&v);
    // With a start in the same value, whatever launch.start is.
    ok(&with_api(json!([value(
        "q",
        json!([{ "launch_args": ["-q"] }, { "start": "game_dx9.exe" }])
    )])));
}

#[test]
fn ox8_the_argument_rules() {
    let at = "options[1].values[0].steps[1].launch_args";
    let with_args = |a: Value| {
        with_api(json!([value(
            "q",
            json!([{ "start": "game_dx9.exe" }, { "launch_args": a }])
        )]))
    };
    ok(&with_args(json!(["-a", "+set=1", "-x.y_z"])));
    refused_at(&with_args(json!([])), at, "1 to 8 arguments");
    let nine: Vec<String> = (0..9).map(|i| format!("-a{i}")).collect();
    refused_at(&with_args(json!(nine)), at, "1 to 8 arguments");
    // Eight of 64 bytes are 519 bytes joined.
    let long: Vec<String> = (0..8).map(|i| format!("-{i}{}", "a".repeat(62))).collect();
    refused_at(&with_args(json!(long)), at, "at most 512 bytes");
    let fit: Vec<String> = (0..8).map(|i| format!("-{i}{}", "a".repeat(61))).collect();
    ok(&with_args(json!(fit)));
    for bad in ["-a b", "-a\"", "x", "-", "%COMMAND%", "-a%b", "-é"] {
        refused_at(
            &with_args(json!([bad])),
            &format!("{at}[0]"),
            "one game argument",
        );
    }
}

#[test]
fn ox9_the_gate() {
    const _: () = assert!(
        !OPTION_LAUNCH_REVIEWED,
        "the gate opens in its own commit after the O-2b review and the [DEV] run"
    );
    let gated = "draft only until start and launch_args of options are reviewed";
    let mut v = with_api(json!([value("dx9", json!([{ "start": "game_dx9.exe" }]))]));
    ok(&v);
    v["status"] = json!("active");
    refused_at(&v, "options[1].values[0].steps[0].start", gated);
    let mut v = with_api(json!([value("q", json!([{ "launch_args": ["-q"] }]))]));
    v["launch"]["start"] = json!("game.exe");
    ok(&v);
    v["status"] = json!("needs-retest");
    refused_at(&v, "options[1].values[0].steps[0].launch_args", gated);
    // A release index holds no draft: none of them is ever released.
    let v = with_api(json!([value("dx9", json!([{ "start": "game_dx9.exe" }]))]));
    assert!(check::topo(&parse(&v), Rules::Release).is_err());
}

#[test]
fn ox10_the_counts() {
    let at = "options[1].values[0].steps";
    refused_at(
        &with_api(json!([value(
            "x",
            json!([{ "start": "game_dx9.exe" }, { "start": "game.exe" }])
        )])),
        at,
        "at most one start",
    );
    let mut v = with_api(json!([value(
        "x",
        json!([{ "launch_args": ["-a"] }, { "launch_args": ["-b"] }])
    )]));
    v["launch"]["start"] = json!("game.exe");
    refused_at(&v, at, "at most one launch_args");
    refused_at(
        &with_api(json!([value("x", json!([]))])),
        at,
        "1 to 4 steps",
    );
    refused_at(
        &with_api(json!([value(
            "x",
            json!([
                ini("a.ini", "1"),
                ini("b.ini", "1"),
                ini("c.ini", "1"),
                ini("d.ini", "1"),
                ini("e.ini", "1")
            ])
        )])),
        at,
        "1 to 4 steps",
    );
    let mut v = base();
    v["options"] = Value::Array(
        (0..9)
            .map(|i| {
                option(
                    &format!("o{i}"),
                    json!([value("on", json!([ini(&format!("f{i}.ini"), "1")]))]),
                )
            })
            .collect(),
    );
    refused_at(&v, "options", "at most 8 options");
}

#[test]
fn ox11_an_ini_value_in_the_user_data_folder_needs_user_data() {
    let mut ud = ini("settings.ini", "1");
    ud["ini_set"]["root"] = json!("user_data");
    let mut v = base();
    v["options"][0]["values"][1]["steps"] = json!([ud]);
    refused_at(
        &v,
        "options[0].values[1].steps[0].ini_set.root",
        "user_data needs the Topo's user_data folder",
    );
    v["user_data"] = json!({ "documents": "My Games\\Invented" });
    ok(&v);
    // The INI rules of a variant hold for a value too.
    let mut v = base();
    v["options"][0]["values"][1]["steps"] = json!([ini("game.cfg", "1")]);
    refused_at(
        &v,
        "options[0].values[1].steps[0].ini_set.file",
        "a .ini file",
    );
}

#[test]
fn ox12_start_lies_in_the_folder_of_launch_start() {
    let with_start = |launch_start: &str, start: &str| {
        let mut v = with_api(json!([value("dx9", json!([{ "start": start }]))]));
        v["match"]["exes"][1]["path"] = json!(start);
        v["launch"]["start"] = json!(launch_start);
        v
    };
    // The same folder, also in another case.
    ok(&with_start(r"bin\launcher.exe", r"bin\game_dx9.exe"));
    ok(&with_start(r"Bin\launcher.exe", r"bin\game_dx9.exe"));
    ok(&with_start("launcher.exe", "game_dx9.exe"));
    let at = "options[1].values[0].steps[0].start";
    let want = "in the folder of launch.start";
    // Below, above and beside the folder of launch.start.
    refused_at(&with_start("launcher.exe", r"bin\game_dx9.exe"), at, want);
    refused_at(&with_start(r"bin\launcher.exe", "game_dx9.exe"), at, want);
    refused_at(
        &with_start(r"bin\launcher.exe", r"bin64\game_dx9.exe"),
        at,
        want,
    );
    refused_at(
        &with_start(r"bin\launcher.exe", r"bin\x\game_dx9.exe"),
        at,
        want,
    );
}

/// O-2b review S1: if a value of an option starts an executable (passes arguments), every value
/// of it does, so a value switch always replaces both parts of the launch profile.
#[test]
fn ox13_launch_parts_in_every_value_of_an_option_or_none() {
    let both = |a: Value, b: Value| with_api(json!([value("a", a), value("b", b)]));
    // Every value starts an executable, one also passes arguments: loads.
    let mut v = both(
        json!([{ "start": "game_dx9.exe" }]),
        json!([{ "start": "game.exe" }]),
    );
    v["launch"]["start"] = json!("launcher.exe");
    ok(&v);
    // One value with `start`, the other with an `ini_set` only.
    refused_at(
        &both(
            json!([{ "start": "game_dx9.exe" }]),
            json!([ini("game.ini", "1")]),
        ),
        "options[1].values[1].steps",
        "every value of it needs start",
    );
    // The same for `launch_args` (with `start` in both).
    refused_at(
        &both(
            json!([{ "start": "game_dx9.exe" }, { "launch_args": ["-a"] }]),
            json!([{ "start": "game.exe" }]),
        ),
        "options[1].values[1].steps",
        "every value of it needs launch_args",
    );
    ok(&both(
        json!([{ "start": "game_dx9.exe" }, { "launch_args": ["-a"] }]),
        json!([{ "start": "game.exe" }, { "launch_args": ["-b"] }]),
    ));
}
