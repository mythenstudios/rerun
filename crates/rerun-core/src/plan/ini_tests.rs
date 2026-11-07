//! P (P2-12, C2): `IniValue` in the plan format. One form on the wire; every rule of `check` on
//! encode and decode, `IniText::check_new` only with `Rules::Current` (a recorded head keeps the
//! form, the extension and the dialect); the op budget; the objects; `needs_main_exe`; the
//! preview.

use super::super::{
    FileHash, FileState, INI_NOTE, MAX_OP_BYTES, Object, Op, Plan, PlanError, RootIx, decode,
    decode_recorded, overlap, preview,
};
use super::{r, sample, sha};
use crate::policy::ini::{IniEdit, IniName, IniText, Old};
use crate::sys::fs::Attrs;

fn ed(section: &str, key: &str, old: Old, new: &str) -> IniEdit {
    IniEdit {
        section: IniName::parse(section).unwrap(),
        key: IniName::parse(key).unwrap(),
        old,
        new: IniText::parse(new).unwrap(),
    }
}

fn val(v: &str) -> Old {
    Old::Value(IniText::parse(v).unwrap())
}

/// `sample` (two roots, both with a main executable, three file ops) plus one `IniValue` on
/// root 0's `cfg\game.ini`.
fn ini_plan() -> Plan {
    let mut p = sample();
    p.roots[1].main_exe = Some(r("g2.exe"));
    p.ops.push(Op::IniValue {
        root: RootIx(0),
        path: r(r"cfg\game.ini"),
        old: FileState {
            sha256: sha(b"old ini"),
            len: 7,
            attrs: Attrs {
                readonly: true,
                hidden: false,
                system: false,
            },
        },
        new: FileHash {
            sha256: sha(b"new ini"),
            len: 7,
        },
        edits: vec![
            ed("Display", "Fullscreen", Old::NoKey, "1"),
            ed("Display", "Width", val("1280"), "1920"),
            ed("New", "k", Old::NoSection, "2"),
        ],
    });
    p
}

fn with(base: &Plan, f: &dyn Fn(&mut Plan)) -> Plan {
    let mut p = base.clone();
    f(&mut p);
    p
}

/// The last op's `IniValue` fields.
fn last_ini(
    p: &mut Plan,
) -> (
    &mut RelPathOf,
    &mut FileState,
    &mut FileHash,
    &mut Vec<IniEdit>,
) {
    match p.ops.last_mut() {
        Some(Op::IniValue {
            path,
            old,
            new,
            edits,
            ..
        }) => (path, old, new, edits),
        _ => panic!("no INI op"),
    }
}

type RelPathOf = crate::path::RelPath;

/// `p` is refused on encode and, written by hand, on decode (either rule set).
fn refused(p: &Plan, want: &str) {
    let e = p.encode().expect_err(want).to_string();
    assert!(e.contains(want), "encode, {want}: {e}");
    let bytes = serde_json::to_vec(p).unwrap();
    let e = decode(&bytes).expect_err(want).to_string();
    assert!(e.contains(want), "decode, {want}: {e}");
    let e = decode_recorded(&bytes).expect_err(want).to_string();
    assert!(e.contains(want), "decode_recorded, {want}: {e}");
}

#[test]
fn p_i1_ini_values_round_trip_in_one_form() {
    let p = ini_plan();
    let b = p.encode().unwrap();
    assert_eq!(decode(b.bytes()).unwrap(), p);
    assert_eq!(decode_recorded(b.bytes()).unwrap(), p);
    let s = std::str::from_utf8(b.bytes()).unwrap();
    let want = format!(
        concat!(
            r#"{{"ini_value":{{"root":0,"path":"cfg\\game.ini","old":{{"sha256":"{}","len":7,"#,
            r#""attrs":{{"readonly":true,"hidden":false,"system":false}}}},"new":{{"sha256":"{}","len":7}},"#,
            r#""edits":[{{"section":"Display","key":"Fullscreen","old":"no_key","new":"1"}},"#,
            r#"{{"section":"Display","key":"Width","old":{{"value":"1280"}},"new":"1920"}},"#,
            r#"{{"section":"New","key":"k","old":"no_section","new":"2"}}]}}}}"#
        ),
        crate::wire::hex32::to_string(&sha(b"old ini")),
        crate::wire::hex32::to_string(&sha(b"new ini")),
    );
    assert!(s.contains(&want), "{want} not in {s}");
    for (from, to) in [
        (r#""old":"no_key""#, r#""old":"No_Key""#),
        (r#""old":"no_key""#, r#""old":null"#),
        (r#""new":"1920""#, r#""new":" 1920""#),
        (r#""section":"New""#, r#""section":"[New]""#),
        (r#""len":7}"#, r#""len":7,"x":1}"#),
        (r#""new_section""#, r#""x""#),
    ] {
        let bad = s.replacen(from, to, 1);
        if bad == s {
            continue;
        }
        assert!(
            matches!(
                decode_recorded(bad.as_bytes()),
                Err(PlanError::Unparsable | PlanError::NotOneForm)
            ),
            "{to}"
        );
    }
}

#[test]
fn p_i2_every_rule_on_encode_and_decode() {
    let p = ini_plan();
    refused(
        &with(&p, &|p| *last_ini(p).0 = r(r"cfg\game.cfg")),
        "only in a .ini file",
    );
    refused(
        &with(&p, &|p| *last_ini(p).0 = r(r"cfg\Desktop.INI")),
        "only in a .ini file",
    );
    refused(&with(&p, &|p| last_ini(p).3.clear()), "1 to 8 INI values");
    refused(
        &with(&p, &|p| {
            *last_ini(p).3 = (0..9)
                .map(|i| ed("Display", &format!("k{i}"), Old::NoKey, "1"))
                .collect();
        }),
        "1 to 8 INI values",
    );
    refused(
        &with(&p, &|p| last_ini(p).3.swap(0, 1)),
        "unique and in order",
    );
    refused(
        &with(&p, &|p| {
            last_ini(p).3[0] = ed("Display", "WIDTH", Old::NoKey, "1");
            last_ini(p).3.swap(0, 1);
        }),
        "unique and in order",
    );
    refused(
        &with(&p, &|p| {
            last_ini(p).3[1] = ed("Display", "Width", val("1920"), "1920")
        }),
        "set to the value it has",
    );
    refused(
        &with(&p, &|p| {
            last_ini(p).3[0] = ed("Display", "Fullscreen", Old::NoSection, "1")
        }),
        "both new and existing",
    );
    refused(
        &with(&p, &|p| {
            let (_, old, new, _) = last_ini(p);
            new.sha256 = old.sha256;
        }),
        "do not change the file",
    );
    refused(
        &with(&p, &|p| last_ini(p).1.len = (1 << 20) + 1),
        "larger than 1 MiB",
    );
    refused(
        &with(&p, &|p| last_ini(p).2.len = (1 << 20) + 1),
        "larger than 1 MiB",
    );
    // E5: an INI op needs the main executable of every root.
    refused(
        &with(&p, &|p| p.roots[1].main_exe = None),
        "registry and INI ops need the main executable",
    );
}

/// `Rules::Current` alone checks the new values against the rule in force now; a recorded head
/// with a value the rule refuses since is still readable (its revert writes only old values).
#[test]
fn p_i3_the_new_value_rule_is_current_only() {
    let p = with(&ini_plan(), &|p| {
        last_ini(p).3[1] = ed("Display", "Width", val("1280"), "C:/x");
    });
    let e = p.encode().unwrap_err().to_string();
    assert!(e.contains("no paths"), "{e}");
    let bytes = serde_json::to_vec(&p).unwrap();
    assert!(decode(&bytes).is_err());
    assert_eq!(decode_recorded(&bytes).unwrap(), p);
}

#[test]
fn p_i4_needs_main_exe_and_objects() {
    let p = ini_plan();
    let ini = p.ops.last().unwrap();
    assert!(ini.needs_main_exe());
    assert!(!p.ops[2].needs_main_exe(), "a replace asks its target");
    // The object is the file, as for a file op: a `file_install` of the same file overlaps.
    let objs = Object::of(&p).unwrap();
    let mut other = sample();
    other.ops = vec![Op::CreateFile {
        root: RootIx(0),
        path: r(r"CFG\GAME.ini"),
        content: match &sample().ops[1] {
            Op::CreateFile { content, .. } => content.clone(),
            _ => unreachable!(),
        },
        attrs: Attrs::default(),
    }];
    assert!(overlap(&objs[3..], &Object::of(&other).unwrap()));
    // A file op and an INI op on the same file in one plan.
    let mut two = p.clone();
    if let Some(Op::IniValue { path, .. }) = two.ops.last_mut() {
        *path = r(r"mods\a.ini");
    }
    two.ops.insert(
        1,
        Op::CreateFile {
            root: RootIx(0),
            path: r(r"mods\A.INI"),
            content: match &sample().ops[1] {
                Op::CreateFile { content, .. } => content.clone(),
                _ => unreachable!(),
            },
            attrs: Attrs::default(),
        },
    );
    two.ops.remove(2);
    let e = two.encode().unwrap_err().to_string();
    assert!(e.contains("a second op on the same object"), "{e}");
}

/// The worst case of one `IniValue` fits the op budget: the longest relative path (240
/// characters, outside the BMP: 4 bytes each), eight edits with 64-character names and
/// 128-character old and new values of quotes (escaped to 2 bytes each). The edits are bounded
/// by `policy::ini`, the path by `RelPath`, so no `IniValue` can break the budget.
#[test]
fn p_i5_the_worst_case_ini_value_fits_the_op_budget() {
    let mut p = ini_plan();
    let path = format!(
        r"{}\{}.ini",
        "\u{20000}".repeat(118),
        "\u{20000}".repeat(117)
    );
    assert_eq!(path.chars().count(), crate::path::RelPath::MAX_LEN);
    let quotes = "\"".repeat(128);
    let section = format!("S{}", "x".repeat(63));
    let edits: Vec<IniEdit> = (0..8)
        .map(|i| {
            ed(
                &section,
                &format!("{i}{}", "k".repeat(63)),
                val(&quotes),
                &format!("{}1", "\"".repeat(127)),
            )
        })
        .collect();
    {
        let (pp, _, _, e) = last_ini(&mut p);
        *pp = r(&path);
        *e = edits;
    }
    let size = serde_json::to_vec(p.ops.last().unwrap()).unwrap().len();
    eprintln!("P-I5: worst-case IniValue is {size} bytes");
    assert!(size < MAX_OP_BYTES, "{size}");
    assert!(size > 6_000, "{size}: the worst case is the worst case");
    p.encode().unwrap();
}

#[test]
fn p_i6_the_preview_shows_every_key_and_the_note() {
    let p = ini_plan();
    let v = preview(&p);
    let o = v.ops.last().unwrap();
    assert_eq!(o.action, "edit ini");
    assert_eq!(o.path.as_str(), r"cfg\game.ini");
    assert_eq!(o.attrs.as_deref(), Some("R"));
    assert_eq!(
        o.content,
        Some((crate::wire::hex32::to_string(&sha(b"new ini")), 7))
    );
    assert_eq!(o.old.as_ref().map(|x| x.1), Some(7));
    let keys: Vec<String> = o
        .ini
        .iter()
        .map(|k| format!("[{}] {}: {} -> {}", k.section, k.key, k.old, k.new))
        .collect();
    assert_eq!(
        keys,
        [
            "[Display] Fullscreen: missing -> 1",
            "[Display] Width: 1280 -> 1920",
            "[New] k: missing (new section) -> 2"
        ]
    );
    assert_eq!(v.ini, Some(INI_NOTE));
    let text = v.to_string();
    assert!(text.contains("edit ini 0:cfg\\game.ini"), "{text}");
    assert!(
        text.contains("     [Display] Width: 1280 -> 1920"),
        "{text}"
    );
    assert!(text.contains(&format!("note: {INI_NOTE}")), "{text}");
    assert_eq!(preview(&sample()).ini, None);
}
