//! P (P2-10b, C4): registry ops in the plan format. One form on the wire; every rule of
//! `check` on encode and on decode (the journal head is untrusted); the op budget of the worst
//! case; the objects of keys and values; the preview.

use super::super::{
    MAX_OP_BYTES, NewValue, OLD_INLINE, Object, Op, Plan, PlanError, RootIx, ValueState, decode,
    overlap, preview,
};
use super::{r, sample, sha};
use crate::policy::registry::{AsciiName, AsciiSeg, GameKey, RegSlot};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, reg_type};

fn seg(s: &str) -> AsciiSeg {
    AsciiSeg::parse(s).unwrap()
}

/// `HKCU\Software\<vendor>\<product>[\rest]` @ `name`.
pub(crate) fn slot(vendor: &str, product: &str, rest: &[&str], name: &str) -> RegSlot {
    RegSlot::GameValue {
        key: GameKey::new(
            seg(vendor),
            seg(product),
            rest.iter().map(|s| seg(s)).collect(),
        )
        .unwrap(),
        name: AsciiName::parse(name).unwrap(),
    }
}

fn hkcu(p: &str) -> RegKey {
    RegKey::new(Hive::CurrentUser, RegView::Native, p)
}

fn sz(s: &str) -> RegValue {
    RegValue::String(s.to_owned())
}

/// `sample` (two roots, three file ops) plus registry ops: two created keys and a new value
/// in them, a replaced value of another type in an existing key.
fn sample_reg() -> Plan {
    let mut p = sample();
    p.roots[1].main_exe = Some(r("g2.exe"));
    let win = slot("Ubisoft", "AC", &[], "Windowed");
    p.ops.extend([
        Op::CreateKey {
            slot: win.clone(),
            segs: 2,
        },
        Op::CreateKey {
            slot: win.clone(),
            segs: 3,
        },
        Op::SetValue {
            slot: win,
            old: None,
            new: NewValue::Dword(1),
        },
        Op::SetValue {
            slot: slot("Vendor", "Game", &["Settings"], "Seed"),
            old: ValueState::of(&sz("old")),
            new: NewValue::Qword(u64::MAX),
        },
    ]);
    p
}

/// `p` is refused on encode and, written by hand, on decode, with `want` in the message.
fn refused(p: &Plan, want: &str) {
    let e = p.encode().expect_err(want).to_string();
    assert!(e.contains(want), "encode, {want}: {e}");
    let bytes = serde_json::to_vec(p).unwrap();
    let e = decode(&bytes).expect_err(want).to_string();
    assert!(e.contains(want), "decode, {want}: {e}");
}

#[test]
fn p6_registry_ops_round_trip_in_one_form() {
    let p = sample_reg();
    let b = p.encode().unwrap();
    assert_eq!(decode(b.bytes()).unwrap(), p);
    let s = std::str::from_utf8(b.bytes()).unwrap();
    for want in [
        r#"{"create_key":{"slot":{"game_value":{"vendor":"Ubisoft","product":"AC","rest":[],"name":"Windowed"}},"segs":2}}"#,
        r#""old":null,"new":{"dword":1}}}"#,
        r#""rest":["Settings"],"name":"Seed"}},"old":{"kind":1,"len":8,"sha256":""#,
        r#""data":"6f006c0064000000"},"new":{"qword":"18446744073709551615"}}}"#,
    ] {
        assert!(s.contains(want), "{want} not in {s}");
    }
    // Other spellings of the same plan are not its one form.
    for (from, to) in [
        (
            r#""qword":"18446744073709551615""#,
            r#""qword":18446744073709551615"#,
        ),
        (r#"{"dword":1}"#, r#"{"dword":"1"}"#),
        (r#""data":"6f00"#, r#""data":"6F00"#),
        (r#""rest":[],"#, ""),
        (r#""vendor":"Ubisoft""#, r#""vendor":"Ubisoft","x":1"#),
    ] {
        let bad = s.replacen(from, to, 1);
        assert_ne!(bad, s, "{from}");
        assert!(decode(bad.as_bytes()).is_err(), "{to}");
    }
}

/// Every rule of `check` for registry ops, on encode and decode.
#[test]
fn p7_registry_ops_break_no_rule() {
    let base = sample_reg();
    let with = |f: &dyn Fn(&mut Plan)| {
        let mut p = base.clone();
        f(&mut p);
        p
    };
    // A registry op before a file op (6b-d, checklist P2-10b).
    refused(
        &with(&|p| {
            let v = p.ops.remove(5);
            p.ops.insert(0, v);
        }),
        "a file op after a registry op",
    );
    refused(
        &with(&|p| {
            let f = p.ops.remove(2);
            p.ops.push(f);
        }),
        "a file op after a registry op",
    );
    // One op per key and per value (folded).
    refused(
        &with(&|p| {
            p.ops.push(Op::SetValue {
                slot: slot("UBISOFT", "ac", &[], "WINDOWED"),
                old: None,
                new: NewValue::Dword(2),
            });
        }),
        "a second op on the same object",
    );
    refused(
        &with(&|p| {
            p.ops.insert(
                5,
                Op::CreateKey {
                    slot: slot("ubisoft", "x", &[], "y"),
                    segs: 2,
                },
            );
        }),
        "a second op on the same object",
    );
    // `segs` outside (anchor, key].
    for segs in [0, 1, 4, 200] {
        refused(
            &with(&|p| {
                if let Op::CreateKey { segs: s, .. } = &mut p.ops[3] {
                    *s = segs;
                }
            }),
            "a created key outside its slot",
        );
    }
    // A key below a created key before it; a value in a created key with an old value.
    refused(
        &with(&|p| p.ops.swap(3, 4)),
        "a key or value below a created key comes before it",
    );
    refused(
        &with(&|p| {
            let v = p.ops.remove(5);
            p.ops.insert(4, v);
        }),
        "a key or value below a created key comes before it",
    );
    refused(
        &with(&|p| {
            if let Op::SetValue { old, .. } = &mut p.ops[5] {
                *old = ValueState::of(&RegValue::Dword(0));
            }
        }),
        "a value in a created key with an old value",
    );
    // The old value: data wrong, missing, too long, the length over 1 MiB.
    let old = |f: &dyn Fn(&mut ValueState)| {
        with(&|p| {
            if let Op::SetValue { old: Some(o), .. } = &mut p.ops[6] {
                f(o);
            }
        })
    };
    let fit = "an old value whose length, hash or inline data do not fit";
    refused(&old(&|o| o.data = Some(b"x".to_vec())), fit);
    refused(&old(&|o| o.data = None), fit);
    refused(&old(&|o| o.sha256 = sha(b"other")), fit);
    refused(
        &old(&|o| {
            o.len = u32::try_from(OLD_INLINE + 1).unwrap();
            o.data = Some(vec![0; OLD_INLINE + 1]);
            o.sha256 = sha(&vec![0; OLD_INLINE + 1]);
        }),
        fit,
    );
    refused(
        &old(&|o| {
            o.len = (1 << 20) + 1;
            o.data = None;
        }),
        fit,
    );
    // The old value equals the new one.
    refused(
        &with(&|p| {
            if let Op::SetValue { old, .. } = &mut p.ops[6] {
                *old = ValueState::of(&RegValue::Qword(u64::MAX));
            }
        }),
        "a value set to the value it has",
    );
    // The new value against `check_new` (G1: no path characters in a REG_SZ).
    refused(
        &with(&|p| {
            if let Op::SetValue { new, .. } = &mut p.ops[6] {
                *new = NewValue::Sz(r"C:\x".to_owned());
            }
        }),
        "no path or variable characters",
    );
    // Slots: compatibility layers until P2-11 (N2), the reserved GPU slot.
    refused(
        &with(&|p| {
            p.ops.push(Op::SetValue {
                slot: RegSlot::CompatLayers {
                    root: RootIx(0),
                    exe: r("game.exe"),
                },
                old: None,
                new: NewValue::Sz("~ WIN7RTM".to_owned()),
            });
        }),
        "compatibility layers come with compat_layer",
    );
    refused(
        &with(&|p| {
            p.ops.push(Op::SetValue {
                slot: RegSlot::GpuPreference {
                    root: RootIx(0),
                    exe: r("game.exe"),
                },
                old: None,
                new: NewValue::Dword(1),
            });
        }),
        "reserved",
    );
    // E2, M1: registry ops need a root, and a main executable for every root.
    refused(
        &with(&|p| p.roots[1].main_exe = None),
        "registry ops need the main executable of every root",
    );
    refused(
        &Plan {
            roots: Vec::new(),
            ops: base.ops[3..].to_vec(),
            ..base.clone()
        },
        "registry ops need the main executable of every root",
    );
    // A file plan without main executables stays allowed.
    let mut files = sample();
    files.roots[0].main_exe = None;
    assert!(files.encode().is_ok());
}

/// Slots in the head go through the parsers of `policy::registry` (amendment P2-9): a vendor
/// on the deny list, a value name with `:`, a fifth segment, a `qword` as a number are refused
/// on decode.
#[test]
fn p7_a_manipulated_slot_or_value_is_refused_on_decode() {
    let good = String::from_utf8(sample_reg().encode().unwrap().bytes().to_vec()).unwrap();
    for (from, to, why) in [
        (r#""vendor":"Ubisoft""#, r#""vendor":"Valve""#, "vendor"),
        (
            r#""vendor":"Ubisoft""#,
            r#""vendor":"micro\u0073oft""#,
            "vendor",
        ),
        (r#""name":"Windowed""#, r#""name":"a:b""#, "name"),
        (
            r#""rest":[]"#,
            r#""rest":["a","b","c","d","e"]"#,
            "segments",
        ),
        (r#""rest":[]"#, r#""rest":["a\\b"]"#, "backslash"),
        (
            r#""qword":"18446744073709551615""#,
            r#""qword":"018446744073709551615""#,
            "qword",
        ),
        (r#""qword":"18446744073709551615""#, r#""qword":1"#, "qword"),
        (r#""new":{"dword":1}"#, r#""new":{"sz":null}"#, "sz null"),
        (
            r#""new":{"dword":1}"#,
            r#""new":{"dword":1,"sz":"x"}"#,
            "two",
        ),
    ] {
        let bad = good.replacen(from, to, 1);
        assert_ne!(bad, good, "{why}");
        assert!(
            matches!(decode(bad.as_bytes()), Err(PlanError::Unparsable)),
            "{why}: {bad}"
        );
    }
}

/// The worst case of one `SetValue` (the longest slot, a 1 KiB old value inline, a REG_SZ of
/// 1,024 characters that each need escaping) fits the op budget of 8 KiB.
#[test]
fn p8_the_worst_case_registry_op_fits_the_op_budget() {
    // `"` is allowed in segments, names and REG_SZ data and costs 2 bytes escaped (review nit 6).
    let long = "\"".repeat(64);
    let rest = [long.as_str(); 4];
    let mut p = sample();
    p.ops.push(Op::SetValue {
        slot: slot(&long, &long, &rest, &"\"".repeat(128)),
        old: ValueState::of(&RegValue::Binary(vec![0xff; OLD_INLINE])),
        new: NewValue::Sz("\"".repeat(1_024)),
    });
    p.roots[1].main_exe = Some(r("g2.exe"));
    let size = serde_json::to_vec(&p.ops[3]).unwrap().len();
    eprintln!("P8: worst-case SetValue is {size} bytes");
    assert!(size < MAX_OP_BYTES, "{size}");
    assert!(size > 5_300, "{size}: the worst case is the worst case");
    let b = p.encode().unwrap();
    assert_eq!(decode(b.bytes()).unwrap(), p);
}

#[test]
fn p5_registry_objects_overlap_by_key_and_name() {
    let objs = Object::of(&sample_reg()).unwrap();
    assert_eq!(objs.len(), 7);
    let key = |p: &str, created| Object::Key {
        key: hkcu(p),
        created,
    };
    let value = |p: &str, n: &str| Object::Value {
        key: hkcu(p),
        name: crate::fold::fold(n),
    };
    // A created key holds everything below it.
    assert!(overlap(&objs, &[value(r"Software\ubisoft\other", "x")]));
    assert!(overlap(&objs, &[key(r"SOFTWARE\Ubisoft\AC\deep", true)]));
    assert!(overlap(
        &objs,
        &[value(r"Software\Vendor\Game\Settings", "SEED")]
    ));
    assert!(!overlap(
        &objs,
        &[value(r"Software\Vendor\Game\Settings", "Other")]
    ));
    // An existing key holds nothing: only the value itself.
    assert!(!overlap(&objs, &[value(r"Software\Vendor\Game", "Seed")]));
    assert!(!overlap(
        &[key(r"Software\A", false)],
        &[value(r"Software\A", "x")]
    ));
    assert!(overlap(
        &[key(r"Software\A", true)],
        &[key(r"Software\a", false)]
    ));
    // A file and a registry object never overlap.
    assert!(!overlap(&objs[3..], &Object::of(&sample()).unwrap()));
}

#[test]
fn p4_the_preview_shows_keys_values_and_the_registry_note() {
    let mut p = sample_reg();
    if let Op::SetValue { slot: s, .. } = &mut p.ops[5] {
        *s = slot("Ubisoft", "AC", &[], "");
    }
    let text = preview(&p).to_string();
    for want in [
        r"  3. create key HKCU\Software\Ubisoft",
        r"  4. create key HKCU\Software\Ubisoft\AC",
        r"  5. set value HKCU\Software\Ubisoft\AC @ (default)",
        "     old missing",
        "     new REG_DWORD 1 (0x00000001)",
        r"  6. set value HKCU\Software\Vendor\Game\Settings @ Seed",
        "     old REG_SZ: old\n",
        "     new REG_QWORD 18446744073709551615 (0xffffffffffffffff)",
        "the type of the value changes",
        "note: registry: if the game fills a created key",
        "not the last-write times of registry keys",
    ] {
        assert!(text.contains(want), "{want:?} not in\n{text}");
    }
    assert_eq!(text.matches("the type of the value changes").count(), 1);
    assert_eq!(text.matches("note: registry").count(), 1);
    assert!(!preview(&sample()).to_string().contains("note: registry"));
    // Old data above the inline limit, and raw data, by type, length and hash; control
    // characters in an old string escaped.
    let mut q = sample_reg();
    if let Op::SetValue { old, .. } = &mut q.ops[6] {
        *old = ValueState::of(&RegValue::Binary(vec![1; OLD_INLINE + 1]));
    }
    let text = preview(&q).to_string();
    assert!(
        text.contains("old REG_BINARY, 1025 bytes, sha256 "),
        "{text}"
    );
    if let Op::SetValue { old, .. } = &mut q.ops[6] {
        *old = ValueState::of(&RegValue::decode(reg_type::REG_SZ, &[0x61, 0]));
    }
    assert!(
        preview(&q).to_string().contains("old REG_SZ, 2 bytes"),
        "raw"
    );
    if let Op::SetValue { old, .. } = &mut q.ops[6] {
        *old = ValueState::of(&sz("a\u{1b}[2Jb"));
    }
    let text = preview(&q).to_string();
    assert!(!text.contains('\u{1b}'), "{text}");
    // Review S3: the untrusted text is a `Shown`, last on its line; a `"` in it cannot close
    // a quote of the preview or make anything look like it follows.
    if let Op::SetValue { old, .. } = &mut q.ops[6] {
        *old = ValueState::of(&sz(r#"x" new REG_DWORD 0"#));
    }
    let pv = preview(&q);
    let o = pv.ops[6].old_value.as_ref().unwrap();
    assert_eq!(o.kind, "REG_SZ");
    assert_eq!(o.text.as_ref().unwrap().as_str(), r#"x" new REG_DWORD 0"#);
    let text = pv.to_string();
    let line = text
        .lines()
        .find(|l| l.starts_with("     old REG"))
        .unwrap();
    assert_eq!(line, r#"     old REG_SZ: x" new REG_DWORD 0"#);
    let new = pv.ops[6].new_value.as_ref().unwrap();
    assert!(
        new.text.is_none() && new.kind.starts_with("REG_QWORD "),
        "{new:?}"
    );
}
