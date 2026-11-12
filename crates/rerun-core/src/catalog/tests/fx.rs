//! Forward compatibility of the signed index (ADR 0024 amendment "Forward compatibility"):
//! FX1 to FX7 of the core, against the fake. FX1's planning is `topo::tests`, FX8 and FX9 the
//! helper chain and `exec`, FX10 the workbench and the parity tests.

use serde_json::{Value, json};

use super::super::check::{self, Floor, RuleError, Rules, TEST_FLOOR, package_floor, topo_floor};
use super::super::entries::classify;
use super::super::model::ENTRY_FORMAT;
use super::super::{Aside, AsideWhy, EntryKind, check_bundle};
use super::*;

/// The index of `tests` as a JSON value (one Topo `a-game` on package `fix-pack`).
fn base() -> Value {
    serde_json::to_value(index(1)).unwrap()
}

fn text(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap()
}

/// Signed with the test key and read like the client.
fn read(v: &Value) -> Result<Catalog, IndexError> {
    let t = text(v);
    catalog(t.as_bytes(), &test_key::sign(t.as_bytes()))
}

fn aside_of(v: &Value) -> Vec<Aside> {
    read(v).unwrap().aside().to_vec()
}

fn one(v: &Value) -> Aside {
    let a = aside_of(v);
    assert_eq!(a.len(), 1, "{a:?}");
    a.into_iter().next().unwrap()
}

/// A change of an entry or an index.
type Change = fn(&mut Value);

/// A second Topo `b-game` of app 7 that needs nothing.
fn other_topo() -> Value {
    let mut t = serde_json::to_value(topo("b-game", "fix-pack")).unwrap();
    t["match"]["steam_appid"] = json!(7);
    t["match"]["exes"][0]["sha256"] = json!("22".repeat(32));
    t["issues"][0]["variants"][0]["steps"] = json!([{ "steam_input": "enable" }]);
    t
}

fn with_topo(t: Value) -> Value {
    let mut v = base();
    v["topos"].as_array_mut().unwrap().push(t);
    v
}

// ---------- FX1 / FX2: newer and unreadable ----------

/// FX1: a Topo of entry format 2 with an unknown field and an unknown step kind is set aside as
/// newer with its app; the rest loads (planning: `topo::tests::fx1_*`).
#[test]
fn fx1_a_future_topo_is_set_aside_and_the_rest_loads() {
    let mut t = other_topo();
    t["format"] = json!(2);
    t["new_field"] = json!({ "anything": [1, 2] });
    t["issues"][0]["variants"][0]["steps"] = json!([{ "teleport": { "to": "mars" } }]);
    let c = read(&with_topo(t)).unwrap();
    assert!(c.topo("a-game").is_some());
    assert!(c.package("fix-pack").is_some());
    assert!(c.topo("b-game").is_none());
    assert_eq!(c.topos().len(), 1);
    let a = c.aside_for(7).collect::<Vec<_>>();
    assert_eq!(
        a,
        vec![&Aside {
            kind: EntryKind::Topo,
            id: id("b-game"),
            format: 2,
            steam_appid: Some(7),
            why: AsideWhy::Newer { format: 2 },
        }]
    );
    assert!(c.aside_for(440).next().is_none());
    assert_eq!(c.aside_entry(EntryKind::Topo, "b-game"), Some(a[0]));
    assert_eq!(c.aside_entry(EntryKind::Package, "b-game"), None);
    assert!(a[0].why.needs_newer());
}

/// FX2: in format 1 an unknown step kind, an unknown field and an unknown enum value are each
/// unreadable (not "needs newer"), by position; the same content in format 2 is newer.
#[test]
fn fx2_unknown_content_of_a_known_format_is_unreadable() {
    let cases: Vec<(&str, Change)> = vec![
        ("unknown step kind", |t| {
            t["issues"][0]["variants"][0]["steps"] = json!([{ "teleport": {} }]);
        }),
        ("unknown field", |t| t["new_field"] = json!(true)),
        ("unknown enum value", |t| {
            t["match"]["exes"][0]["api"] = json!("d3d12");
        }),
        ("unknown nested field", |t| {
            t["issues"][0]["variants"][0]["extra"] = json!(1);
        }),
    ];
    for (what, change) in cases {
        let mut t = other_topo();
        change(&mut t);
        let a = one(&with_topo(t.clone()));
        assert_eq!(a.id.as_str(), "b-game", "{what}");
        assert!(
            matches!(
                a.why,
                AsideWhy::Unreadable {
                    class: "data",
                    line: 1..,
                    column: 1..
                }
            ),
            "{what}: {a:?}"
        );
        assert!(!a.why.needs_newer(), "{what}");
        let c = read(&with_topo(t.clone())).unwrap();
        assert!(c.topo("a-game").is_some(), "{what}");
        t["format"] = json!(2);
        assert_eq!(
            one(&with_topo(t)).why,
            AsideWhy::Newer { format: 2 },
            "{what}"
        );
    }
}

// ---------- FX3: refused by a rule of this build ----------

/// FX3: a known entry that breaks a release rule is refused, the rest loads; both Topos of an
/// overlapping pair are refused; a floor above the entry's format is refused.
#[test]
fn fx3_a_broken_rule_refuses_the_entry_only() {
    // A draft.
    let mut t = other_topo();
    t["status"] = json!("draft");
    let a = one(&with_topo(t));
    assert!(
        matches!(&a.why, AsideWhy::Refused(e) if e.at == "status"),
        "{a:?}"
    );
    assert!(!a.why.needs_newer());
    // A TODO.
    let mut t = other_topo();
    t["match"]["exes"][0]["sha256"] = json!("TODO");
    assert!(matches!(one(&with_topo(t)).why, AsideWhy::Refused(_)));
    // A missing package.
    let mut t = other_topo();
    t["issues"][0]["variants"][0]["steps"] = json!([{ "package": "gone" }]);
    let a = one(&with_topo(t));
    assert_eq!(
        a.why,
        AsideWhy::Refused(RuleError {
            at: "issues[0].variants[0].steps[0].package".into(),
            what: "package gone is not in the index".into(),
        })
    );
    // supports_exe_sha1.
    let mut v = base();
    v["topos"][0]["match"]["exes"][0]["sha1"] = json!("22".repeat(20));
    v["packages"][0]["supports_exe_sha1"] = json!(["33".repeat(20)]);
    let a = one(&v);
    assert_eq!(a.id.as_str(), "a-game");
    assert!(matches!(&a.why, AsideWhy::Refused(e) if e.at == "match.exes[0].sha1"));
    // Two overlapping Topos: both, the third stays.
    let mut t = other_topo();
    t["id"] = json!("c-game");
    t["match"] = base()["topos"][0]["match"].clone();
    let v = with_topo(t);
    let c = read(&v).unwrap();
    let ids: Vec<&str> = c.aside().iter().map(|a| a.id.as_str()).collect();
    assert_eq!(ids, ["a-game", "c-game"]);
    assert!(
        c.aside()
            .iter()
            .all(|a| matches!(&a.why, AsideWhy::Refused(e) if e.at == "match"))
    );
    assert!(c.topos().is_empty());
    assert!(c.package("fix-pack").is_some());
    // Format 0 is below every floor.
    let mut t = other_topo();
    t["format"] = json!(0);
    let a = one(&with_topo(t));
    assert!(
        matches!(&a.why, AsideWhy::Refused(e) if e.at == "format"),
        "{a:?}"
    );
}

/// FX3: an entry whose content needs a higher format than it says is refused, naming the
/// feature (a test-only floor: every floor is 1 until the first format bump).
#[test]
fn fx3_a_floor_above_the_format_is_refused() {
    TEST_FLOOR.with(|f| {
        f.set(Some(Floor {
            format: 2,
            at: "issues",
        }));
    });
    let c = read(&base());
    TEST_FLOOR.with(|f| f.set(None));
    let c = c.unwrap();
    assert!(c.topos().is_empty() && c.packages().is_empty());
    let a = c.aside_entry(EntryKind::Topo, "a-game").unwrap();
    assert_eq!(
        a.why,
        AsideWhy::Refused(RuleError {
            at: "issues".into(),
            what: "uses issues of entry format 2; set format: 2".into(),
        })
    );
    assert!(!a.why.needs_newer());
    // A source file gets the same rule.
    TEST_FLOOR.with(|f| {
        f.set(Some(Floor {
            format: 2,
            at: "issues",
        }));
    });
    let e = check::topo(&topo("a-game", "fix-pack"), Rules::Source);
    TEST_FLOOR.with(|f| f.set(None));
    assert_eq!(e.unwrap_err().at, "issues");
}

/// A Topo that uses every step kind, every optional part and most enum values.
const FULL_TOPO: &str = r#"{
        "format": 1, "id": "full", "title": "Full", "status": "active", "rev": 1,
        "tested_on": ["x64", "arm64"],
        "match": { "steam_appid": 1, "exes": [
            { "path": "a.exe", "sha1": "1111111111111111111111111111111111111111", "api": "ddraw" },
            { "path": "b.exe", "sha256": "1111111111111111111111111111111111111111111111111111111111111111", "api": "d3d8" },
            { "path": "c.exe", "sha256": "1212121212121212121212121212121212121212121212121212121212121212", "api": "d3d9" },
            { "path": "d.exe", "sha256": "1313131313131313131313131313131313131313131313131313131313131313", "api": "d3d10" },
            { "path": "e.exe", "sha256": "1414141414141414141414141414141414141414141414141414141414141414", "api": "d3d11" },
            { "path": "f.exe", "sha256": "1515151515151515151515151515151515151515151515151515151515151515", "api": "opengl" }
        ]},
        "launch": { "chain": ["steam", "upc", "ea-app", "rockstar", "battlenet", "epic", "gog-galaxy"],
            "method": "watch", "fallback": "hold", "start": "a.exe", "priority": "above_normal",
            "cpu": { "max_threads": 4, "prefer": "performance", "single_l3": true,
                "prefer_l3": "largest", "smt": false, "mode": "soft", "exclude_first": "core" } },
        "anti_cheat": { "dead": ["easy-anti-cheat", "battleye", "punkbuster", "gameguard",
            "xigncode", "ea-anticheat"],
            "source": { "type": "official", "url": "https://example.org/news" } },
        "user_data": { "documents": "My Games\\Full" },
        "issues": [{ "id": "i", "title": "I",
            "when": { "gpu.vendor": "nvidia", "gpu.arch": ["turing"], "gpu.integrated": false,
                "gpu.hybrid": true, "cpu.threads": { "gt": 1, "gte": 2, "lt": 9, "lte": 8, "eq": 4 },
                "cpu.hybrid": false, "os.build": { "gte": 1 } },
            "checks": [{ "runtime": "vcredist-x86" }, { "runtime": "vcredist-x64" },
                { "runtime": "directx-jun2010" }],
            "variants": [{ "id": "v", "status": "unverified", "kind": "enhancement",
                "tradeoffs": ["t"],
                "sources": [{ "type": "repo", "url": "https://github.com/o/r" },
                    { "type": "steam-guide", "url": "https://steamcommunity.com/sharedfiles/filedetails/?id=1" },
                    { "type": "pcgw", "url": "https://www.pcgamingwiki.com/wiki/Full" }],
                "steps": [
                    { "package": "p" }, { "steam_input": "enable" }, { "cpu": { "mode": "hard" } },
                    { "registry_set": { "key": "HKCU\\Software\\V\\P",
                        "values": [{ "name": "a", "dword": 1 }, { "name": "b", "qword": "2" },
                            { "name": "c", "sz": "x" }] } },
                    { "compat_layer": { "exe": "a.exe", "layers": ["WIN98"] } },
                    { "ini_set": { "root": "user_data", "file": "a.ini",
                        "values": [{ "section": "S", "key": "K", "value": "1" }] } },
                    { "firewall_rule": { "exe": "b.exe", "direction": "out" } },
                    { "laa_patch": { "exe": "b.exe" } },
                    { "gpu_preference": { "exe": "a.exe", "preference": "high_performance" } }
                ] }, { "id": "w", "status": "verified", "kind": "fix", "steps": [{ "cpu": { "prefer": "any", "mode": "hard", "exclude_first": "thread" } }] },
                { "id": "x", "status": "reported", "kind": "fix", "steps": [{ "cpu": { "max_threads": 2 } }] }] }],
        "tips": { "launch_options": ["-w"], "notes": [{ "text": "n",
            "source": { "type": "steam-thread", "url": "https://steamcommunity.com/app/1/discussions/0/1/" } }] },
        "links": { "pcgw": "Full" }
    }"#;

/// A package that uses every optional part.
const FULL_PACKAGE: &str = r#"{
        "format": 1, "id": "p", "name": "P", "status": "active", "tier": "community",
        "source": { "repo": "https://github.com/o/r", "page": "https://example.org/p" },
        "version": "1", "license": "MIT", "arch": ["x86", "x64"],
        "assets": [{ "arch": "x86", "url": "https://github.com/o/r/releases/download/v1/a.zip",
            "sha256": "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB" }],
        "apis": ["d3d9", "d3d11"], "slots": ["d3d9.dll"],
        "slots_by_api": { "d3d11": ["d3d11.dll"] },
        "requires": ["q"], "requires_gpu": ["vulkan"], "supports_exe_sha1": ["1111111111111111111111111111111111111111"],
        "files": [{ "from": "d3d9.dll", "to": "d3d9.dll", "sha256": "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD",
            "config": true, "arch": ["x86"], "api": ["d3d9"] }],
        "options": { "a": { "ini": { "file": "a.ini", "section": "S", "key": "K" },
            "default": true, "kind": "fix" },
            "b": { "ini": { "file": "a.ini", "section": "S", "key": "L" }, "default": 3 },
            "c": { "ini": { "file": "a.ini", "section": "S", "key": "M" }, "default": "x" } }
    }"#;

/// FX3: the floor functions walk every type of the model (a Topo and a package that use every
/// step kind, every optional part and every enum value): all format 1 until the first release.
#[test]
fn fx3_the_floors_are_format_1() {
    let t: Topo = serde_json::from_str(FULL_TOPO).unwrap();
    assert_eq!(topo_floor(&t), Floor::BASE);
    for (status, method) in [
        ("draft", "auto"),
        ("needs-retest", "direct"),
        ("retired", "ifeo"),
    ] {
        let mut u = t.clone();
        u.status = serde_json::from_value(json!(status)).unwrap();
        u.launch.as_mut().unwrap().method = Some(serde_json::from_value(json!(method)).unwrap());
        assert_eq!(topo_floor(&u), Floor::BASE);
    }
    let p: Package = serde_json::from_str(FULL_PACKAGE).unwrap();
    assert_eq!(package_floor(&p), Floor::BASE);
    let mut q = p.clone();
    q.arch = serde_json::from_value(json!("TODO")).unwrap();
    q.tier = serde_json::from_value(json!("official")).unwrap();
    assert_eq!(package_floor(&q), Floor::BASE);
    assert_eq!(package_floor(&package("fix-pack")), Floor::BASE);
    assert_eq!(ENTRY_FORMAT, 1, "format 1 until the first release (A6)");
}

// ---------- FX4: packages ----------

/// A package entry of format 2 the client cannot read (an unknown key, no other content).
fn future_package(name: &str) -> Value {
    json!({ "format": 2, "id": name, "shiny": true })
}

fn needs(t: &mut Value, pkg: &str) {
    t["issues"][0]["variants"][0]["steps"] = json!([{ "package": pkg }]);
}

/// FX4: a Topo on a newer package, transitively through `requires`, on an unreadable package;
/// a `requires` cycle with a set-aside member; a package entry with a `match` key.
#[test]
fn fx4_packages_set_aside_what_needs_them() {
    // A Topo on a format-2 package: needs newer.
    let mut v = base();
    v["packages"]
        .as_array_mut()
        .unwrap()
        .push(future_package("z-pack"));
    let mut t = other_topo();
    needs(&mut t, "z-pack");
    v["topos"].as_array_mut().unwrap().push(t);
    let a = aside_of(&v);
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!(a[0].id.as_str(), "b-game");
    assert_eq!(
        a[0].why,
        AsideWhy::Package {
            id: id("z-pack"),
            newer: true
        }
    );
    assert!(a[0].why.needs_newer());
    assert_eq!(a[1].why, AsideWhy::Newer { format: 2 });
    assert_eq!(a[1].steam_appid, None);

    // Transitive: fix-pack requires the format-2 package; a-game on fix-pack.
    let mut v = base();
    v["packages"][0]["requires"] = json!(["z-pack"]);
    v["packages"]
        .as_array_mut()
        .unwrap()
        .push(future_package("z-pack"));
    let c = read(&v).unwrap();
    assert!(c.topos().is_empty() && c.packages().is_empty());
    let fix = c.aside_entry(EntryKind::Package, "fix-pack").unwrap();
    assert_eq!(
        fix.why,
        AsideWhy::Package {
            id: id("z-pack"),
            newer: true
        }
    );
    let game = c.aside_entry(EntryKind::Topo, "a-game").unwrap();
    assert_eq!(
        game.why,
        AsideWhy::Package {
            id: id("fix-pack"),
            newer: true
        }
    );

    // A Topo on an unreadable package: cannot be used, not "needs newer".
    let mut v = base();
    v["packages"][0]["unknown"] = json!(1);
    let c = read(&v).unwrap();
    let game = c.aside_entry(EntryKind::Topo, "a-game").unwrap();
    assert_eq!(
        game.why,
        AsideWhy::Package {
            id: id("fix-pack"),
            newer: false
        }
    );
    assert!(!game.why.needs_newer());

    // A cycle a -> b -> fix-pack -> a with a member that needs newer (b also requires z):
    // the loop ends, the whole cycle set aside.
    let mut v = base();
    let mut pa = serde_json::to_value(package("a-pack")).unwrap();
    pa["requires"] = json!(["b-pack"]);
    let mut pb = serde_json::to_value(package("b-pack")).unwrap();
    pb["requires"] = json!(["fix-pack", "z-pack"]);
    v["packages"][0]["requires"] = json!(["a-pack"]);
    let list = v["packages"].as_array_mut().unwrap();
    list.insert(0, pb);
    list.insert(0, pa);
    list.push(future_package("z-pack"));
    let c = read(&v).unwrap();
    assert!(c.packages().is_empty() && c.topos().is_empty());
    for p in ["a-pack", "b-pack", "fix-pack"] {
        let a = c.aside_entry(EntryKind::Package, p).unwrap();
        assert!(
            matches!(a.why, AsideWhy::Package { newer: true, .. }),
            "{p}: {a:?}"
        );
    }
    // A cycle of known packages alone is no reason (nothing set aside).
    let mut v = base();
    let mut pa = serde_json::to_value(package("a-pack")).unwrap();
    pa["requires"] = json!(["fix-pack"]);
    v["packages"][0]["requires"] = json!(["a-pack"]);
    v["packages"].as_array_mut().unwrap().insert(0, pa);
    assert!(aside_of(&v).is_empty());

    // A package entry with `match`: ignored by its head, unreadable in format 1, newer without
    // an app in format 2.
    let mut v = base();
    v["packages"][0]["match"] = json!({ "steam_appid": 440 });
    let c = read(&v).unwrap();
    let p = c.aside_entry(EntryKind::Package, "fix-pack").unwrap();
    assert!(matches!(p.why, AsideWhy::Unreadable { .. }), "{p:?}");
    assert_eq!(p.steam_appid, None);
    v["packages"][0]["format"] = json!(2);
    let c = read(&v).unwrap();
    let p = c.aside_entry(EntryKind::Package, "fix-pack").unwrap();
    assert_eq!(p.why, AsideWhy::Newer { format: 2 });
    assert_eq!(p.steam_appid, None);
    assert!(c.aside_for(440).all(|a| a.kind == EntryKind::Topo));
}

/// FX4b: overlap is computed last over the Topos still known. A known Topo that overlaps a
/// newer, an unreadable or a package-set-aside Topo stays known; two known ones are refused.
#[test]
fn fx4b_overlap_counts_only_known_topos() {
    let twin = || {
        let mut t = serde_json::to_value(topo("b-game", "fix-pack")).unwrap();
        t["issues"][0]["variants"][0]["steps"] = json!([{ "steam_input": "enable" }]);
        t
    };
    type Extend = fn(&Value) -> Value;
    let cases: Vec<(&str, Change, Extend)> = vec![
        ("newer", |t| t["format"] = json!(2), |v| v.clone()),
        ("unreadable", |t| t["extra"] = json!(1), |v| v.clone()),
        (
            "package aside",
            |t| needs(t, "z-pack"),
            |v| {
                let mut v = v.clone();
                v["packages"]
                    .as_array_mut()
                    .unwrap()
                    .push(future_package("z-pack"));
                v
            },
        ),
    ];
    for (what, change, extend) in cases {
        let mut t = twin();
        change(&mut t);
        let c = read(&extend(&with_topo(t))).unwrap();
        assert!(c.topo("a-game").is_some(), "{what}");
        assert!(c.topo("b-game").is_none(), "{what}");
        let b = c.aside_entry(EntryKind::Topo, "b-game").unwrap();
        assert!(
            !matches!(&b.why, AsideWhy::Refused(e) if e.at == "match"),
            "{what}: {b:?}"
        );
    }
    let c = read(&with_topo(twin())).unwrap();
    assert!(c.topos().is_empty());
    assert_eq!(c.aside().len(), 2);
}

// ---------- FX5: the envelope stays strict ----------

fn refused(v: &Value) -> IndexError {
    read(v).unwrap_err()
}

fn head_refused(v: &Value) -> bool {
    matches!(refused(v), IndexError::Head { .. })
}

/// FX5: envelope format 2 with an unknown key is "needs newer"; an unknown key in format 1, an
/// entry that is not an object, a broken head, `steam_appid: 0`, unsorted or duplicate IDs over
/// known and set-aside entries refuse the whole index.
#[test]
fn fx5_the_envelope_and_the_heads_refuse_the_whole_index() {
    let mut v = base();
    v["format"] = json!(2);
    v["extra"] = json!(1);
    let e = refused(&v);
    assert_eq!(e, IndexError::Format(2));
    assert!(
        e.to_string().contains("needs a newer version of Rerun"),
        "{e}"
    );
    let mut v = base();
    v["extra"] = json!(1);
    assert!(matches!(
        refused(&v),
        IndexError::Parse { class: "data", .. }
    ));
    // An envelope that is not an object.
    let arr = json!([1, 1, "2026-11-09T12:00:00Z", [], []]);
    assert!(matches!(refused(&arr), IndexError::Parse { .. }));

    let heads: Vec<(&str, &str, Change)> = vec![
        ("topos", "an array", |v| {
            v["topos"][0] = json!([1, "a-game"])
        }),
        ("topos", "a string", |v| v["topos"][0] = json!("a-game")),
        ("topos", "no format", |v| {
            v["topos"][0].as_object_mut().unwrap().remove("format");
        }),
        ("topos", "no id", |v| {
            v["topos"][0].as_object_mut().unwrap().remove("id");
        }),
        ("topos", "a malformed id", |v| {
            v["topos"][0]["id"] = json!("A Game")
        }),
        ("topos", "format as text", |v| {
            v["topos"][0]["format"] = json!("1")
        }),
        ("topos", "a negative format", |v| {
            v["topos"][0]["format"] = json!(-1)
        }),
        ("topos", "steam_appid 0", |v| {
            v["topos"][0]["match"]["steam_appid"] = json!(0);
        }),
        ("topos", "steam_appid too large", |v| {
            v["topos"][0]["match"]["steam_appid"] = json!(4_294_967_296_u64);
        }),
        ("topos", "steam_appid as text", |v| {
            v["topos"][0]["match"]["steam_appid"] = json!("440");
        }),
        ("topos", "steam_appid null", |v| {
            v["topos"][0]["match"]["steam_appid"] = Value::Null;
        }),
        ("topos", "match an array", |v| {
            v["topos"][0]["match"] = json!([440]);
        }),
        ("topos", "match null", |v| {
            v["topos"][0]["match"] = Value::Null
        }),
        ("packages", "no id", |v| {
            v["packages"][0].as_object_mut().unwrap().remove("id");
        }),
        ("packages", "an array", |v| v["packages"][0] = json!([1])),
    ];
    for (list, what, change) in heads {
        let mut v = base();
        // Even in a future entry the head is frozen.
        v[list][0]["format"] = json!(2);
        change(&mut v);
        assert!(head_refused(&v), "{list}: {what}: {:?}", refused(&v));
    }
    // A duplicate head key, in the raw text (a JSON value cannot hold one).
    let t = text(&base()).replacen(
        "\"id\": \"a-game\"",
        "\"id\": \"a-game\", \"id\": \"b-game\"",
        1,
    );
    assert!(matches!(
        catalog(t.as_bytes(), &test_key::sign(t.as_bytes())).unwrap_err(),
        IndexError::Head {
            list: "topos",
            pos: 0,
            ..
        }
    ));
    // steam_appid 0 refuses the index, while the Topo of format 1 would be refused by its rule.
    let mut v = base();
    v["topos"][0]["match"]["steam_appid"] = json!(0);
    assert!(head_refused(&v));
    // Unsorted, and duplicate across a known and a set-aside entry.
    let mut t = other_topo();
    t["id"] = json!("a-game");
    t["format"] = json!(2);
    let v = with_topo(t);
    assert!(matches!(refused(&v), IndexError::Rule(r) if r.contains("sorted")));
    let mut t = other_topo();
    t["id"] = json!("0-game");
    t["format"] = json!(2);
    assert!(matches!(refused(&with_topo(t)), IndexError::Rule(r) if r.contains("sorted")));
    let mut v = base();
    v["packages"]
        .as_array_mut()
        .unwrap()
        .push(future_package("fix-pack"));
    assert!(matches!(refused(&v), IndexError::Rule(r) if r.contains("packages")));
}

// ---------- FX6: the signature covers every byte ----------

/// FX6: a byte changed inside a set-aside entry breaks the signature; a revoked key is refused
/// on every path, also for an index with set-aside entries.
#[test]
fn fx6_the_signature_covers_the_set_aside_entries() {
    let mut t = other_topo();
    t["format"] = json!(2);
    t["shiny"] = json!("abc");
    let s = text(&with_topo(t));
    let sig = test_key::sign(s.as_bytes());
    assert!(catalog(s.as_bytes(), &sig).is_ok());
    let at = s.find("abc").unwrap();
    let mut changed = s.clone().into_bytes();
    changed[at] = b'x';
    assert_eq!(catalog(&changed, &sig).unwrap_err(), IndexError::Signature);
    // Revoked: verify, and the store's load (the helper's and the recheck's path).
    let pk = test_key::public();
    assert_eq!(
        super::super::verify_with(s.as_bytes(), &sig, &[pk], &[*pk.bytes()]).unwrap_err(),
        IndexError::Revoked(pk.id())
    );
    let sys = sys();
    import(&sys, &(s.clone().into_bytes(), sig.to_vec())).unwrap();
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    let dir = app
        .sub(crate::policy::root::AppSub::Index)
        .unwrap()
        .unwrap();
    let sha: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(s.as_bytes()).into()
    };
    assert!(matches!(
        store::load_with(&*dir, &sha, &[pk], &[*pk.bytes()]),
        Err(StoreError::Index(IndexError::Revoked(_)))
    ));
    assert_eq!(
        store::load_with(&*dir, &sha, &[pk], &[])
            .unwrap()
            .aside()
            .len(),
        1
    );
}

// ---------- FX7: the store ----------

fn signed_value(v: &Value) -> (Vec<u8>, Vec<u8>) {
    let t = text(v).into_bytes();
    let s = test_key::sign(&t).to_vec();
    (t, s)
}

/// FX7: an index with set-aside entries is imported and raises the floor; rollback and the
/// same-`seq` rule are unchanged; `current` and `by_hash` give the same set-aside list; a stored
/// index whose entries this build does not read loads with them set aside (the downgrade).
#[test]
fn fx7_the_store_treats_an_index_with_set_aside_entries_like_any_other() {
    let sys = sys();
    let mut t = other_topo();
    t["format"] = json!(2);
    let mut v = with_topo(t);
    v["seq"] = json!(4);
    let future = signed_value(&v);
    assert!(matches!(
        import(&sys, &future).unwrap(),
        Imported::New { previous: None, .. }
    ));
    assert_eq!(current_seq(&sys), Some(4));
    assert_eq!(
        import(&sys, &signed(3)).unwrap_err(),
        StoreError::Rollback {
            current: 4,
            offered: 3
        }
    );
    assert_eq!(
        import(&sys, &signed(4)).unwrap_err(),
        StoreError::SameSeq { seq: 4 }
    );
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    let cur = store::current(&app, &keys()).unwrap().unwrap();
    let sha: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&future.0).into()
    };
    let by = store::by_hash_with(&app, &sha, &keys()).unwrap();
    assert_eq!(cur.aside(), by.aside());
    assert_eq!(cur.aside().len(), 1);
    // The next import checks its floor against the stored index: not damaged.
    assert!(matches!(
        import(&sys, &signed(5)).unwrap(),
        Imported::New {
            previous: Some(4),
            ..
        }
    ));
}

/// FX7, the downgrade: a newer build accepted an index whose entries this build does not read
/// (here: format-2 entries stored as `current.json` names them); this build reads it with those
/// entries set aside instead of calling it damaged, and imports a newer one on top.
#[test]
fn fx7_a_stored_index_with_newer_entries_is_not_damaged() {
    let sys = sys();
    let mut v = base();
    v["seq"] = json!(7);
    v["topos"][0]["format"] = json!(2);
    v["topos"][0]["a_format_2_field"] = json!(true);
    v["packages"][0]["format"] = json!(2);
    let (b, s) = signed_value(&v);
    let sha: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&b).into()
    };
    let h = crate::wire::hex32::to_string(&sha);
    let fs = sys.fake_fs();
    fs.mkdir_all(Path::new(INDEX_DIR)).unwrap();
    fs.put_file(Path::new(&format!(r"{INDEX_DIR}\{h}.json")), &b)
        .unwrap();
    fs.put_file(Path::new(&format!(r"{INDEX_DIR}\{h}.sig")), &s)
        .unwrap();
    fs.put_file(
        Path::new(&format!(r"{INDEX_DIR}\{}", store::CURRENT)),
        format!(r#"{{"format":1,"seq":7,"sha256":"{h}"}}"#).as_bytes(),
    )
    .unwrap();
    sys.sync_all();
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    let c = store::current(&app, &keys()).unwrap().unwrap();
    assert_eq!(c.seq(), 7);
    assert!(c.topos().is_empty() && c.packages().is_empty());
    assert!(c.aside().iter().all(|a| a.why.needs_newer()));
    assert_eq!(c.aside().len(), 2);
    assert!(matches!(
        import(&sys, &signed(8)).unwrap(),
        Imported::New {
            previous: Some(7),
            ..
        }
    ));
    assert_eq!(
        import(&sys, &signed(6)).unwrap_err(),
        StoreError::Rollback {
            current: 8,
            offered: 6
        }
    );
}

/// `check_bundle` (the workbench's use) classifies like the client, without a signature, and
/// refuses what the client refuses as a whole.
#[test]
fn check_bundle_is_the_clients_classification() {
    let mut t = other_topo();
    t["format"] = json!(2);
    let v = with_topo(t);
    let b = text(&v).into_bytes();
    let a = check_bundle(&b).unwrap();
    assert_eq!(a, read(&v).unwrap().aside());
    assert_eq!(classify(&b).unwrap().index.topos.len(), 1);
    let mut v = base();
    v["format"] = json!(2);
    assert_eq!(
        check_bundle(text(&v).as_bytes()).unwrap_err(),
        IndexError::Format(2)
    );
    let mut big = vec![b' '; MAX_INDEX_BYTES + 1];
    big[0] = b'{';
    assert!(matches!(
        check_bundle(&big).unwrap_err(),
        IndexError::TooLarge { .. }
    ));
}

/// The frozen format-1 bundle (`tests/fixtures/index/format-1.json`, signed with the test key;
/// frozen at A6): every later build loads it with nothing set aside (FX10, backward
/// compatibility).
#[test]
fn fx10_the_frozen_format_1_bundle_loads_with_nothing_set_aside() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/index");
    #[expect(
        clippy::disallowed_methods,
        reason = "reads a repository fixture, never a game folder"
    )]
    let (b, s) = (
        std::fs::read(dir.join("format-1.json")).unwrap(),
        std::fs::read(dir.join("format-1.json.sig")).unwrap(),
    );
    let c = catalog(&b, &s).unwrap();
    assert!(c.aside().is_empty(), "{:?}", c.aside());
    assert!(!c.topos().is_empty() && !c.packages().is_empty());
    assert_eq!(c.index().format, 1);
    assert!(c.topos().iter().all(|t| t.format == 1));
    assert!(c.packages().iter().all(|p| p.format == 1));
}
