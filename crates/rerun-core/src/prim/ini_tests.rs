//! T9-I: the `ini_set` planner against the fake (P2-12, C3): an existing value, a new key, a new
//! section, values already set (omitted; all set: no op), the stored spelling, the order of the
//! values (same hash), every refusal of the file (missing, folder, link, placeholder, restricted,
//! hard-linked, system, too large, extension, `desktop.ini`, UTF-16, NUL, lone CR, unclear
//! section, ambiguous, unusual old value, a new section without a header), of the values (names,
//! the rule in force now, twice, nine), of the plan (two steps, a `file_install` of the same
//! file, no main executable), and the step's wire form.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::reg_tests::plan_steps;
use super::tests::{GAME, builder, entry, rel, spec};
use super::{IniSetSpec, IniSetValue, Step};
use crate::plan::{FileHash, Op, Plan, PlanError};
use crate::policy::ini::{self, IniEdit, IniName, IniText, Old};
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::fs::{Attrs, tag};

/// The INI file of the tests.
pub(crate) const INI: &str = r"cfg\Game.ini";

/// Its content.
pub(crate) const INI_TEXT: &[u8] = b"; written by the game\r\n[Display]\r\nWidth=1280\r\nHeight = 720\r\n\r\n[Audio]\r\nVolume=5\r\n";

pub(crate) fn ini_abs(p: &str) -> String {
    format!(r"{GAME}\{p}")
}

/// [`builder`] with [`INI`] holding `text`.
pub(crate) fn ini_builder(text: &[u8]) -> FakeSystemBuilder {
    builder().file(ini_abs(INI), text.to_vec())
}

pub(crate) fn ini_step(file: &str, values: &[(&str, &str, &str)]) -> Step {
    Step::IniSet(IniSetSpec {
        root: super::StepRoot::Game,
        file: rel(file),
        values: values
            .iter()
            .map(|(s, k, v)| IniSetValue {
                section: (*s).to_owned(),
                key: (*k).to_owned(),
                value: (*v).to_owned(),
            })
            .collect(),
    })
}

/// The values every test sets: an existing key, a new key, a new section.
pub(crate) fn three() -> Step {
    ini_step(
        INI,
        &[
            ("Display", "Width", "1920"),
            ("Display", "Fullscreen", "1"),
            ("Zz Extra", "Mode", "2"),
        ],
    )
}

fn plan_one(sys: &FakeSystem, step: Step) -> Result<Plan, PlanError> {
    plan_steps(sys, &[step], Some("game.exe"))
}

fn refused(sys: &FakeSystem, step: Step, want: &str) {
    match plan_one(sys, step) {
        Err(PlanError::Step(e)) => assert!(e.contains(want), "{want}: {e}"),
        other => panic!("{want}: {other:?}"),
    }
}

fn ed(section: &str, key: &str, old: Old, new: &str) -> IniEdit {
    IniEdit {
        section: IniName::parse(section).unwrap(),
        key: IniName::parse(key).unwrap(),
        old,
        new: IniText::parse(new).unwrap(),
    }
}

#[test]
fn t9_i_plans_one_op_per_file_with_its_edits() {
    let sys = ini_builder(INI_TEXT).build().unwrap();
    sys.fake_fs()
        .set_attrs(
            Path::new(&ini_abs(INI)),
            Attrs {
                readonly: true,
                hidden: false,
                system: false,
            },
        )
        .unwrap();
    let p = plan_one(&sys, three()).unwrap();
    let [
        Op::IniValue {
            root,
            path,
            old,
            new,
            edits,
        },
    ] = p.ops.as_slice()
    else {
        panic!("{:?}", p.ops);
    };
    assert_eq!(root.0, 0);
    assert_eq!(path.as_str(), INI);
    assert_eq!(old.sha256, <[u8; 32]>::from(Sha256::digest(INI_TEXT)));
    assert_eq!(old.len, u64::try_from(INI_TEXT.len()).unwrap());
    assert!(old.attrs.readonly, "the old R/H/S, kept by the new content");
    let want = vec![
        ed("Display", "Fullscreen", Old::NoKey, "1"),
        ed(
            "Display",
            "Width",
            Old::Value(IniText::parse("1280").unwrap()),
            "1920",
        ),
        ed("Zz Extra", "Mode", Old::NoSection, "2"),
    ];
    assert_eq!(*edits, want);
    let bytes = ini::edit(INI_TEXT, &want).unwrap();
    assert_eq!(
        *new,
        FileHash {
            sha256: Sha256::digest(&bytes).into(),
            len: u64::try_from(bytes.len()).unwrap(),
        }
    );
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "; written by the game\r\n[Display]\r\nFullscreen=1\r\nWidth=1920\r\nHeight = 720\r\n\r\n[Audio]\r\nVolume=5\r\n[Zz Extra]\r\nMode=2\r\n"
    );
    assert_eq!(p.roots[0].main_exe, Some(rel("game.exe")));
}

#[test]
fn t9_i_values_already_set_are_left_out() {
    let sys = ini_builder(INI_TEXT).build().unwrap();
    let p = plan_one(
        &sys,
        ini_step(
            INI,
            &[("display", "WIDTH", "1280"), ("Audio", "Volume", "7")],
        ),
    )
    .unwrap();
    let [Op::IniValue { edits, .. }] = p.ops.as_slice() else {
        panic!("{:?}", p.ops);
    };
    assert_eq!(
        *edits,
        [ed(
            "Audio",
            "Volume",
            Old::Value(IniText::parse("5").unwrap()),
            "7"
        )]
    );
    // Every value set already: no op, nothing to do.
    let p = plan_one(&sys, ini_step(INI, &[("Display", "Height", "720")])).unwrap();
    assert!(p.ops.is_empty());
}

#[test]
fn t9_i_the_plan_names_the_stored_spelling_and_ignores_the_order() {
    let sys = ini_builder(INI_TEXT).build().unwrap();
    let a = plan_one(
        &sys,
        ini_step(
            r"CFG\GAME.INI",
            &[("Display", "Width", "1920"), ("Audio", "Volume", "7")],
        ),
    )
    .unwrap();
    let b = plan_one(
        &sys,
        ini_step(
            r"cfg\game.ini",
            &[("Audio", "Volume", "7"), ("Display", "Width", "1920")],
        ),
    )
    .unwrap();
    let Op::IniValue { path, .. } = &a.ops[0] else {
        panic!()
    };
    assert_eq!(path.as_str(), INI, "the disk's spelling");
    assert_eq!(a.encode().unwrap().hash(), b.encode().unwrap().hash());
}

#[test]
fn t9_i_every_refusal_of_the_file() {
    let file = |text: &[u8]| ini_builder(text).build().unwrap();
    let sys = file(INI_TEXT);
    refused(
        &sys,
        ini_step(r"cfg\none.ini", &[("A", "b", "1")]),
        "missing; start the game once",
    );
    refused(
        &sys,
        ini_step(r"cfg\Game.cfg", &[("A", "b", "1")]),
        "is no .ini file",
    );
    refused(
        &sys,
        ini_step("desktop.ini", &[("A", "b", "1")]),
        "is no .ini file",
    );
    let sys = builder().dir(ini_abs("cfg\\dir.ini")).build().unwrap();
    refused(
        &sys,
        ini_step(r"cfg\dir.ini", &[("A", "b", "1")]),
        "not a plain file",
    );
    let sys = builder()
        .dir(ini_abs("real"))
        .file(ini_abs(r"real\x.ini"), INI_TEXT.to_vec())
        .junction(ini_abs("cfg"), &ini_abs("real"))
        .build()
        .unwrap();
    refused(
        &sys,
        ini_step(r"cfg\x.ini", &[("A", "b", "1")]),
        "a folder on the way is not a plain folder",
    );
    let sys = builder()
        .tagged_file(ini_abs("cloud.ini"), INI_TEXT.to_vec(), tag::CLOUD)
        .build()
        .unwrap();
    refused(
        &sys,
        ini_step("cloud.ini", &[("A", "b", "1")]),
        "not a plain file",
    );
    let sys = ini_builder(INI_TEXT)
        .restricted(ini_abs(INI))
        .build()
        .unwrap();
    refused(&sys, ini_step(INI, &[("A", "b", "1")]), "not a plain file");
    let sys = ini_builder(INI_TEXT)
        .hardlink(ini_abs(INI), ini_abs("other.ini"))
        .build()
        .unwrap();
    refused(&sys, ini_step(INI, &[("A", "b", "1")]), "hard-linked");
    let sys = file(INI_TEXT);
    sys.fake_fs()
        .set_attrs(
            Path::new(&ini_abs(INI)),
            Attrs {
                readonly: false,
                hidden: true,
                system: true,
            },
        )
        .unwrap();
    refused(&sys, ini_step(INI, &[("A", "b", "1")]), "a system file");
    let mut big = INI_TEXT.to_vec();
    big.resize(ini::MAX_INI_BYTES + 1, b' ');
    refused(
        &file(&big),
        ini_step(INI, &[("A", "b", "1")]),
        "larger than 1 MiB",
    );
    let sys = builder()
        .case_sensitive_dir(ini_abs("cs"))
        .file(ini_abs(r"cs\x.ini"), INI_TEXT.to_vec())
        .build()
        .unwrap();
    refused(
        &sys,
        ini_step(r"cs\x.ini", &[("A", "b", "1")]),
        "case-sensitive",
    );
    for (text, want) in [
        (&b"\xFF\xFE[\x00A\x00]\x00"[..], "UTF-16"),
        (b"[A]\nb=\x00", "NUL"),
        (b"[A]\rb=1", "carriage return"),
        (b"[A\nb=1", "sections are unclear"),
    ] {
        refused(&file(text), ini_step(INI, &[("A", "b", "1")]), want);
    }
    for (text, want) in [
        (
            &b"[A]\nb=1\n[a]\nc=2"[..],
            "[A] b: value 0: its section or key is ambiguous",
        ),
        (b"[A]\nb=1\nB=2", "ambiguous"),
        (b"[ A ]\nb=1", "ambiguous"),
        (b"[A]\nb=\xE9t\xE9", "[A] b: value 0: an unusual value"),
        (
            b"b=1\nc=2",
            "a new section in a file without any section header",
        ),
    ] {
        refused(&file(text), ini_step(INI, &[("A", "b", "3")]), want);
    }
}

#[test]
fn t9_i_every_refusal_of_the_values_and_the_plan() {
    let sys = ini_builder(INI_TEXT).build().unwrap();
    refused(&sys, ini_step(INI, &[]), "1 to 8 values");
    let nine: Vec<(String, String, String)> = (0..9)
        .map(|i| ("A".to_owned(), format!("k{i}"), "1".to_owned()))
        .collect();
    let nine: Vec<(&str, &str, &str)> = nine
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
        .collect();
    refused(&sys, ini_step(INI, &nine), "1 to 8 values");
    refused(
        &sys,
        ini_step(INI, &[("A", "b", "1"), ("a", "B", "2")]),
        "[a] B twice",
    );
    refused(
        &sys,
        ini_step(INI, &[("A=", "b", "1")]),
        "not a section or key name",
    );
    refused(
        &sys,
        ini_step(INI, &[("A", " b", "1")]),
        "not a section or key name",
    );
    refused(&sys, ini_step(INI, &[("A", "b", "a\tb")]), "not a value");
    refused(&sys, ini_step(INI, &[("A", "b", "")]), "an empty value");
    refused(&sys, ini_step(INI, &[("A", "b", r"C:\x")]), "no paths");
    refused(&sys, ini_step(INI, &[("A", "b", "..")]), "holds ..");
    // A new section spelled two ways.
    refused(
        &sys,
        ini_step(INI, &[("New", "a", "1"), ("NEW", "b", "2")]),
        "a section spelled two ways",
    );
    // Two steps for one file; a `file_install` of the same file (either order).
    let e = plan_steps(
        &sys,
        &[
            ini_step(INI, &[("A", "b", "1")]),
            ini_step(r"CFG\game.INI", &[("A", "c", "1")]),
        ],
        Some("game.exe"),
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("two steps for"), "{e}");
    let sys = ini_builder(INI_TEXT)
        .file(super::tests::PKG.to_owned() + r"\game.ini", b"x".to_vec())
        .build()
        .unwrap();
    let fi = Step::FileInstall(spec(vec![entry("game.ini", INI, b"x")]));
    for steps in [
        vec![fi.clone(), ini_step(INI, &[("A", "b", "1")])],
        vec![ini_step(INI, &[("A", "b", "1")]), fi],
    ] {
        let e = plan_steps(&sys, &steps, Some("game.exe"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("ini_set and file_install for the same file"),
            "{e}"
        );
    }
    // E5: an INI fix needs the game's main executable.
    let e = plan_steps(&sys, &[three()], None).unwrap_err().to_string();
    assert!(
        e.contains("registry and INI fixes need the game's main executable"),
        "{e}"
    );
}

#[test]
fn t9_i_the_step_has_one_wire_form() {
    let s: Step = serde_json::from_str(
        r#"{"ini_set":{"file":"cfg\\game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}"#,
    )
    .unwrap();
    assert_eq!(
        s,
        ini_step(r"cfg\game.ini", &[("Display", "Width", "1920")])
    );
    for bad in [
        r#"{"ini_set":{"file":"cfg\\game.ini","values":[],"x":1}}"#,
        r#"{"ini_set":{"file":"cfg\\game.ini","values":[{"section":"D","key":"W","value":"1","x":1}]}}"#,
        r#"{"ini_set":{"file":"C:\\game.ini","values":[]}}"#,
        r#"{"ini_set":{"values":[]}}"#,
    ] {
        assert!(serde_json::from_str::<Step>(bad).is_err(), "{bad}");
    }
}
