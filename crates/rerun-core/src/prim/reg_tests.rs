//! T9-R: the `registry_set` planner against the fake (P2-10b, C5): new, equal (omitted),
//! replaced, another type, raw and large old values; missing keys top-down and once over every
//! step; registry ops after every file op whatever the order of the steps; every refusal; the
//! step's wire form.

use std::path::Path;

use super::tests::{GAME, app, builder, entry, fr, rel, spec};
use super::{PlanCtx, RegValueEntry, RegistrySetSpec, Step, plan};
use crate::plan::{NewValue, OLD_INLINE, Op, Plan, PlanError, Target, ValueState};
use crate::policy::registry::RegPolicy;
use crate::policy::root::GameDir;
use crate::sys::contract::RegFixture;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, reg_type};

pub(crate) fn hkcu(p: &str) -> RegKey {
    RegKey::new(Hive::CurrentUser, RegView::Native, p)
}

pub(crate) fn dword(name: &str, v: u32) -> RegValueEntry {
    RegValueEntry {
        name: name.to_owned(),
        dword: Some(v),
        qword: None,
        sz: None,
    }
}

pub(crate) fn qword(name: &str, v: &str) -> RegValueEntry {
    RegValueEntry {
        name: name.to_owned(),
        dword: None,
        qword: Some(v.to_owned()),
        sz: None,
    }
}

pub(crate) fn sz(name: &str, v: &str) -> RegValueEntry {
    RegValueEntry {
        name: name.to_owned(),
        dword: None,
        qword: None,
        sz: Some(v.to_owned()),
    }
}

pub(crate) fn step(key: &str, values: Vec<RegValueEntry>) -> Step {
    Step::RegistrySet(RegistrySetSpec {
        key: key.to_owned(),
        values,
    })
}

/// 20 KiB, above the journal's inline limit of 16 KiB.
pub(crate) const BIG: usize = 20 << 10;

/// The game folder of [`builder`] and an existing key `Software\Vendor\Game` with values of
/// every kind the table needs.
pub(crate) fn reg_builder() -> FakeSystemBuilder {
    let k = hkcu(r"Software\Vendor\Game");
    builder()
        .value(k.clone(), "Same", RegValue::Dword(1))
        .value(k.clone(), "Replace", RegValue::Dword(5))
        .value(k.clone(), "TypeChange", RegValue::String("text".into()))
        .raw_value(k.clone(), "Raw", reg_type::REG_SZ, &[0x61, 0x00])
        .value(k, "Big", RegValue::Binary(vec![7; BIG]))
}

/// Plans `steps` for the manual game folder (main executable `game.exe` unless `main` is
/// `None`).
pub(crate) fn plan_steps(
    sys: &FakeSystem,
    steps: &[Step],
    main: Option<&str>,
) -> Result<Plan, PlanError> {
    let fr = fr(sys);
    let game = GameDir::open_manual(sys, &fr, Path::new(GAME)).unwrap();
    let app = app(sys);
    let main = main.map(rel);
    plan(
        steps,
        &PlanCtx {
            game: &game,
            app: Some(&app),
            steam_app: None,
            main_exe: main.as_ref(),
            reg: RegPolicy.reader(sys),
        },
    )
}

/// The keys the `CreateKey` ops of `p` create, in order.
fn created(p: &Plan) -> Vec<String> {
    p.ops
        .iter()
        .filter_map(|o| match o {
            Op::CreateKey { .. } => {
                let Target::Key { slot, segs } = o.target() else {
                    return None;
                };
                Some(crate::plan::created_key(p, slot, segs, 0).ok()?.1.path)
            }
            _ => None,
        })
        .collect()
}

/// The `SetValue` ops of `p` as (name, old, new).
fn sets(p: &Plan) -> Vec<(String, Option<ValueState>, NewValue)> {
    p.ops
        .iter()
        .filter_map(|o| match o {
            Op::SetValue { slot, old, new } => {
                let av = crate::plan::allowed(p, slot, 0).ok()?;
                Some((av.name().to_owned(), old.clone(), new.clone()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn t9r_plans_new_replaced_and_omitted_values_and_missing_keys_once() {
    let sys = reg_builder()
        .file(format!(r"{}\new.dll", super::tests::PKG), b"n".to_vec())
        .build()
        .unwrap();
    let steps = [
        step(
            r"HKCU\Software\Vendor\Game",
            vec![
                dword("Same", 1),
                dword("Replace", 6),
                dword("TypeChange", 2),
                sz("Raw", "x"),
                qword("Big", "0"),
                sz("New", "en, mode 2"),
            ],
        ),
        step(r"HKCU\Software\New\Prod\Sub", vec![dword("A", 1)]),
        // The same keys in another spelling: created once, in the first step's spelling.
        step(
            r"HKCU\Software\NEW\prod",
            vec![qword("B", "18446744073709551615")],
        ),
        // A file step after the registry steps: its ops still come first.
        Step::FileInstall(spec(vec![entry("new.dll", "new.dll", b"n")])),
    ];
    let p = plan_steps(&sys, &steps, Some("game.exe")).unwrap();
    // File ops first (6b-d), then the registry ops in step order.
    let first_reg = p.ops.iter().position(|o| o.target().is_registry()).unwrap();
    assert_eq!(first_reg, 1, "{:?}", p.ops);
    assert!(p.ops[first_reg..].iter().all(|o| o.target().is_registry()));
    assert_eq!(
        created(&p),
        [
            r"Software\New",
            r"Software\New\Prod",
            r"Software\New\Prod\Sub"
        ]
    );
    let s = sets(&p);
    let names: Vec<&str> = s.iter().map(|(n, _, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["Replace", "TypeChange", "Raw", "Big", "New", "A", "B"]
    );
    let old = |n: &str| s.iter().find(|x| x.0 == n).unwrap().1.clone();
    assert_eq!(old("Replace"), ValueState::of(&RegValue::Dword(5)));
    assert_eq!(
        old("TypeChange"),
        ValueState::of(&RegValue::String("text".into()))
    );
    let raw = old("Raw").unwrap();
    assert_eq!((raw.kind, raw.len), (reg_type::REG_SZ, 2));
    assert_eq!(raw.data.as_deref(), Some(&[0x61, 0x00][..]));
    // 20 KiB: in the head by type, length and hash only (the bytes go to the journal).
    let big = old("Big").unwrap();
    assert_eq!(
        (big.kind, big.len as usize, big.data),
        (reg_type::REG_BINARY, BIG, None)
    );
    const { assert!(BIG > OLD_INLINE) };
    assert_eq!(old("New"), None);
    assert_eq!(old("A"), None);
    assert_eq!(old("B"), None);
    // The bytes are the one form, and planning again gives them again.
    let again = plan_steps(&sys, &steps, Some("game.exe")).unwrap();
    assert_eq!(again.encode().unwrap(), p.encode().unwrap());
    // Another order of the steps: still every file op first.
    let mut rev = steps.to_vec();
    rev.reverse();
    let q = plan_steps(&sys, &rev, Some("game.exe")).unwrap();
    assert!(!q.ops[0].target().is_registry());
    assert!(q.ops[1..].iter().all(|o| o.target().is_registry()));
}

/// Every value equal: no ops, nothing to do.
#[test]
fn t9r_equal_values_are_no_ops() {
    let sys = reg_builder().build().unwrap();
    let p = plan_steps(
        &sys,
        &[step(r"HKCU\Software\Vendor\Game", vec![dword("Same", 1)])],
        Some("game.exe"),
    )
    .unwrap();
    assert!(p.ops.is_empty(), "{:?}", p.ops);
}

#[test]
fn t9r_refusals() {
    let k = r"HKCU\Software\Vendor\Game";
    let one = |e: RegValueEntry| vec![step(k, vec![e])];
    let both = RegValueEntry {
        sz: Some("x".into()),
        ..dword("Two", 1)
    };
    let none = RegValueEntry {
        dword: None,
        ..dword("None", 1)
    };
    type Case = (&'static str, Vec<Step>, &'static str);
    let cases: Vec<Case> = vec![
        (
            "HKLM",
            vec![step(r"HKLM\Software\Vendor\Game", vec![dword("A", 1)])],
            "helper",
        ),
        (
            "HKEY_LOCAL_MACHINE (review N2)",
            vec![step(
                r"hkey_local_machine\SOFTWARE\Vendor\Game",
                vec![dword("A", 1)],
            )],
            "helper",
        ),
        (
            "prefix case",
            vec![step(r"HKCU\SOFTWARE\Vendor\Game", vec![dword("A", 1)])],
            r"HKCU\Software",
        ),
        (
            "full hive name",
            vec![step(r"HKEY_CURRENT_USER\Software\V\G", vec![dword("A", 1)])],
            r"HKCU\Software",
        ),
        (
            "vendor only",
            vec![step(r"HKCU\Software\Vendor", vec![dword("A", 1)])],
            "<Product>",
        ),
        (
            "deny list",
            vec![step(r"HKCU\Software\Valve\Steam", vec![dword("A", 1)])],
            "vendor key",
        ),
        (
            "deny list folded",
            vec![step(r"HKCU\Software\MICROSOFT\X", vec![dword("A", 1)])],
            "vendor key",
        ),
        (
            "five segments",
            vec![step(r"HKCU\Software\V\P\a\b\c\d\e", vec![dword("A", 1)])],
            "4 segments",
        ),
        (
            "empty segment",
            vec![step(r"HKCU\Software\V\\P", vec![dword("A", 1)])],
            "1 to 64",
        ),
        ("no values", vec![step(k, vec![])], "1 to 32"),
        (
            "33 values",
            vec![step(
                k,
                (0..33).map(|i| dword(&format!("v{i}"), 1)).collect(),
            )],
            "1 to 32",
        ),
        (
            "a name twice",
            vec![step(k, vec![dword("A", 1), dword("a", 2)])],
            "twice",
        ),
        (
            "a name with a colon",
            one(dword("a:b", 1)),
            "path or variable",
        ),
        ("two types", one(both), "exactly one"),
        ("no type", one(none), "exactly one"),
        ("qword leading zero", one(qword("Q", "01")), "decimal"),
        ("qword not a number", one(qword("Q", "-1")), "decimal"),
        (
            "qword too large",
            one(qword("Q", "18446744073709551616")),
            "decimal",
        ),
        ("sz with a path", one(sz("S", r"C:\x")), "path or variable"),
        (
            "sz with a variable",
            one(sz("S", "%TEMP%")),
            "path or variable",
        ),
        ("sz not ASCII", one(sz("S", "caf\u{e9}")), "printable ASCII"),
        ("sz too long", one(sz("S", &"x".repeat(1_025))), "1,024"),
        (
            "the same value in two steps",
            vec![
                step(k, vec![dword("A", 1)]),
                step(r"HKCU\Software\VENDOR\game", vec![dword("a", 2)]),
            ],
            "two steps",
        ),
    ];
    for (what, steps, want) in cases {
        let sys = reg_builder().build().unwrap();
        let e = plan_steps(&sys, &steps, Some("game.exe")).expect_err(what);
        let shown = e.to_string();
        let ok = if want == "helper" {
            matches!(e, PlanError::NeedsHelper)
        } else {
            shown.contains(want)
        };
        assert!(ok, "{what}: {shown}");
    }
    // E2: registry steps need the main executable.
    let sys = reg_builder().build().unwrap();
    let e = plan_steps(&sys, &one(dword("A", 1)), None).unwrap_err();
    assert!(e.to_string().contains("main executable"), "{e}");
}

/// A link or volatile key on the way, and an old value over 1 MiB, are refused; a link is
/// never followed.
#[test]
fn t9r_a_link_or_volatile_key_on_the_way_is_refused() {
    let k = r"HKCU\Software\Vendor\Game";
    // A link at `Software\Vendor` to another key.
    let sys = builder()
        .key(hkcu(r"Software\Elsewhere\Game"))
        .build()
        .unwrap();
    sys.fake_registry()
        .link(&hkcu(r"Software\Vendor"), &hkcu(r"Software\Elsewhere"))
        .unwrap();
    let e = plan_steps(&sys, &[step(k, vec![dword("A", 1)])], Some("game.exe")).unwrap_err();
    assert!(e.to_string().contains("symbolic-link key"), "{e}");
    // A volatile key.
    let sys = builder().key(hkcu(r"Software\Vendor")).build().unwrap();
    sys.fake_registry()
        .put_volatile_key(&hkcu(r"Software\Vendor\Game"))
        .unwrap();
    let e = plan_steps(&sys, &[step(k, vec![dword("A", 1)])], Some("game.exe")).unwrap_err();
    assert!(e.to_string().contains("volatile key"), "{e}");
    // An old value over 1 MiB.
    let sys = builder()
        .value(
            hkcu(r"Software\Vendor\Game"),
            "Huge",
            RegValue::Binary(vec![0; (1 << 20) + 1]),
        )
        .build()
        .unwrap();
    let e = plan_steps(&sys, &[step(k, vec![dword("Huge", 1)])], Some("game.exe")).unwrap_err();
    assert!(e.to_string().contains("larger than 1 MiB"), "{e}");
}

/// The step's wire form (N5): `deny_unknown_fields`, `qword` a string, `sz: null` refused.
#[test]
fn t9r_the_step_parses_strictly() {
    let ok = r#"{"registry_set":{"key":"HKCU\\Software\\V\\P","values":[{"name":"Windowed","dword":1},{"name":"Lang","sz":"en"},{"name":"Seed","qword":"0"}]}}"#;
    let s: Step = serde_json::from_str(ok).unwrap();
    let Step::RegistrySet(spec) = &s else {
        panic!("{s:?}")
    };
    assert_eq!(spec.values.len(), 3);
    assert_eq!(
        serde_json::to_string(&s).unwrap(),
        ok,
        "written back the same"
    );
    for bad in [
        ok.replace(r#""sz":"en""#, r#""sz":null"#),
        ok.replace(r#""qword":"0""#, r#""qword":0"#),
        ok.replace(r#""dword":1"#, r#""dword":"1""#),
        ok.replace(r#""dword":1"#, r#""dword":-1"#),
        ok.replace(r#""dword":1"#, r#""dword":4294967296"#),
        ok.replace(
            r#""name":"Windowed","#,
            r#""name":"Windowed","binary":"00","#,
        ),
        ok.replace(r#""values":"#, r#""extra":1,"values":"#),
    ] {
        assert!(serde_json::from_str::<Step>(&bad).is_err(), "{bad}");
    }
}
