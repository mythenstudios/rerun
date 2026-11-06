//! P (P2-11, C2): `TokenList` in the plan format. One form on the wire; every rule of `check`
//! on encode and decode, the token rules only with `Rules::Current` (a recorded head keeps the
//! form only, user decision E4); the op budget; the objects of the shared keys; the preview.
//! Synthetic tokens only (review S8).

use super::super::{
    MAX_OP_BYTES, NewValue, Object, Op, Plan, PlanError, RootIx, ValueState, decode,
    decode_recorded, overlap, preview,
};
use super::{r, sample};
use crate::policy::registry::{RegSlot, TokenName};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, reg_type};

const LAYERS: &str = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";

fn layers_slot(root: u16, exe: &str) -> RegSlot {
    RegSlot::CompatLayers {
        root: RootIx(root),
        exe: r(exe),
    }
}

fn ts(s: &[&str]) -> Vec<TokenName> {
    s.iter().map(|x| TokenName::parse(x).unwrap()).collect()
}

fn old_sz(s: &str) -> Option<ValueState> {
    ValueState::of(&RegValue::String(s.to_owned()))
}

/// `sample` (two roots, three file ops) plus the two created shared keys and a new
/// compatibility-layer value of root 0's `game.exe`.
fn layer_plan() -> Plan {
    let mut p = sample();
    p.roots[1].main_exe = Some(r("g2.exe"));
    let s = layers_slot(0, "game.exe");
    p.ops.extend([
        Op::CreateKey {
            slot: s.clone(),
            segs: 5,
        },
        Op::CreateKey {
            slot: s.clone(),
            segs: 6,
        },
        Op::TokenList {
            slot: s,
            old: None,
            add: ts(&["ZZ_FLAG_A", "ZZ_OS_A"]),
            new: "~ ZZ_FLAG_A ZZ_OS_A".to_owned(),
        },
    ]);
    p
}

/// `sample` plus one token list on an existing value of root 1's `g2.exe`.
fn merge_plan() -> Plan {
    let mut p = sample();
    p.roots[1].main_exe = Some(r("g2.exe"));
    p.ops.push(Op::TokenList {
        slot: layers_slot(1, r"bin\g2.exe"),
        old: old_sz("~ RUNASADMIN"),
        add: ts(&["ZZ_DPI_A"]),
        new: "~ RUNASADMIN ZZ_DPI_A".to_owned(),
    });
    p
}

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

/// `p` is refused by the current rules only: a recorded head with it is still readable (E4).
fn refused_now(p: &Plan, want: &str) {
    let e = p.encode().expect_err(want).to_string();
    assert!(e.contains(want), "encode, {want}: {e}");
    let bytes = serde_json::to_vec(p).unwrap();
    let e = decode(&bytes).expect_err(want).to_string();
    assert!(e.contains(want), "decode, {want}: {e}");
    assert_eq!(
        decode_recorded(&bytes).unwrap(),
        *p,
        "decode_recorded, {want}"
    );
}

fn with(base: &Plan, f: &dyn Fn(&mut Plan)) -> Plan {
    let mut p = base.clone();
    f(&mut p);
    p
}

/// The last op's token list fields.
fn last_tokens(p: &mut Plan) -> (&mut Option<ValueState>, &mut Vec<TokenName>, &mut String) {
    match p.ops.last_mut() {
        Some(Op::TokenList { old, add, new, .. }) => (old, add, new),
        _ => panic!("no token list"),
    }
}

#[test]
fn p_l1_token_lists_round_trip_in_one_form() {
    for p in [layer_plan(), merge_plan()] {
        let b = p.encode().unwrap();
        assert_eq!(decode(b.bytes()).unwrap(), p);
        assert_eq!(decode_recorded(b.bytes()).unwrap(), p);
    }
    let b = layer_plan().encode().unwrap();
    let s = std::str::from_utf8(b.bytes()).unwrap();
    for want in [
        r#"{"create_key":{"slot":{"compat_layers":{"root":0,"exe":"game.exe"}},"segs":5}}"#,
        r#"{"token_list":{"slot":{"compat_layers":{"root":0,"exe":"game.exe"}},"old":null,"add":["ZZ_FLAG_A","ZZ_OS_A"],"new":"~ ZZ_FLAG_A ZZ_OS_A"}}"#,
    ] {
        assert!(s.contains(want), "{want} not in {s}");
    }
    for (from, to) in [
        (r#""add":["ZZ_FLAG_A""#, r#""add":["zz_flag_a""#),
        (r#""add":["ZZ_FLAG_A""#, r#""add":["ZZ FLAG""#),
        (r#""add":["ZZ_FLAG_A","ZZ_OS_A"]"#, r#""add":"ZZ_FLAG_A""#),
        (r#""new":"~ ZZ_FLAG_A ZZ_OS_A""#, r#""new":null"#),
        (r#""old":null,"#, ""),
    ] {
        let bad = s.replacen(from, to, 1);
        assert_ne!(bad, s, "{from}");
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
fn p_l2_token_lists_break_no_rule() {
    let base = layer_plan();
    let merge = merge_plan();
    // Only on a compatibility-layer slot; and such a value is never set (review N2, P2-11).
    refused(
        &with(&base, &|p| {
            p.ops.push(Op::TokenList {
                slot: super::reg_tests::slot("Vendor", "Game", &[], "x"),
                old: None,
                add: ts(&["ZZ_OS_A"]),
                new: "~ ZZ_OS_A".to_owned(),
            });
        }),
        "tokens are only added to a compatibility-layer value",
    );
    refused(
        &with(&base, &|p| {
            p.ops.push(Op::SetValue {
                slot: layers_slot(1, "g2.exe"),
                old: None,
                new: NewValue::Sz("~ ZZ_OS_A".to_owned()),
            });
        }),
        "a compatibility-layer value is never set",
    );
    // 1 to 8 tokens, unique, in byte order.
    let tokens = "1 to 8 tokens, unique and in byte order";
    refused(&with(&base, &|p| last_tokens(p).1.clear()), tokens);
    refused(
        &with(&base, &|p| {
            *last_tokens(p).1 = ts(&["ZZ_OS_A", "ZZ_FLAG_A"])
        }),
        tokens,
    );
    refused(
        &with(&base, &|p| *last_tokens(p).1 = ts(&["ZZ_OS_A", "ZZ_OS_A"])),
        tokens,
    );
    refused(
        &with(&base, &|p| {
            *last_tokens(p).1 = ts(&["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9"]);
        }),
        tokens,
    );
    // Already in the old value (folded).
    refused(
        &with(&merge, &|p| {
            let (old, add, new) = last_tokens(p);
            *old = old_sz("~ zz_dpi_a");
            *add = ts(&["ZZ_DPI_A"]);
            *new = "~ zz_dpi_a ZZ_DPI_A".to_owned();
        }),
        "a token already in the old value",
    );
    // The old value: another type, not inline, outside the grammar, a REG_SZ without its NUL,
    // a hash that does not fit.
    let old = "an old compatibility-layer value that is no inline REG_SZ in the grammar";
    for o in [
        ValueState::of(&RegValue::Dword(1)),
        ValueState::of(&RegValue::ExpandString("~ X".into())),
        old_sz(&"X".repeat(600)),
        old_sz("~  X"),
        old_sz("~ X\tY"),
        ValueState::of(&RegValue::decode(reg_type::REG_SZ, b"~\0 \0X\0")),
        old_sz("~ X").map(|mut s| {
            s.sha256 = [0; 32];
            s
        }),
    ] {
        refused(&with(&merge, &|p| *last_tokens(p).0 = o.clone()), old);
    }
    // The new value: outside the grammar, equal to the old one.
    let new = "outside the grammar or equal to the old one";
    refused(
        &with(&base, &|p| *last_tokens(p).2 = "~  ZZ_OS_A".into()),
        new,
    );
    refused(&with(&base, &|p| *last_tokens(p).2 = String::new()), new);
    refused(
        &with(&merge, &|p| *last_tokens(p).2 = "~ RUNASADMIN".into()),
        new,
    );
    // An old value in a key the plan creates.
    refused(
        &with(&base, &|p| {
            let (old, _, new) = last_tokens(p);
            *old = old_sz("~ X");
            *new = "~ X ZZ_FLAG_A ZZ_OS_A".to_owned();
        }),
        "a value in a created key with an old value",
    );
    // One op per value (folded name).
    refused(
        &with(&base, &|p| {
            p.ops.push(Op::TokenList {
                slot: layers_slot(0, "GAME.EXE"),
                old: None,
                add: ts(&["ZZ_RES_A"]),
                new: "~ ZZ_RES_A".to_owned(),
            });
        }),
        "a second op on the same object",
    );
    // The current rules only (E4): the allowlist, the groups, the merge.
    refused_now(
        &with(&merge, &|p| {
            let (_, add, new) = last_tokens(p);
            *add = ts(&["RUNASINVOKER"]);
            *new = "~ RUNASADMIN RUNASINVOKER".to_owned();
        }),
        "not on the allowlist",
    );
    refused_now(
        &with(&merge, &|p| {
            let (old, add, new) = last_tokens(p);
            *old = old_sz("~ ZZ_OS_C");
            *add = ts(&["ZZ_OS_A"]);
            *new = "~ ZZ_OS_C ZZ_OS_A".to_owned();
        }),
        "two tokens of one group",
    );
    // Both rule sets (security review S-1): `new` is the old value with the tokens appended,
    // so a recorded head cannot make the restore of `After` add a word.
    refused(
        &with(&merge, &|p| {
            *last_tokens(p).2 = "~ ZZ_DPI_A RUNASADMIN".to_owned();
        }),
        "not the old one with the tokens appended",
    );
    refused(
        &with(&merge, &|p| {
            *last_tokens(p).2 = "~ RUNASADMIN RUNASHIGHEST ZZ_DPI_A".to_owned();
        }),
        "not the old one with the tokens appended",
    );
    refused(
        &with(&base, &|p| *last_tokens(p).2 = "~ ZZ_FLAG_A".to_owned()),
        "not the old one with the tokens appended",
    );
    refused(
        &with(&base, &|p| {
            *last_tokens(p).2 = "~ ZZ_FLAG_A ZZ_OS_A X".to_owned()
        }),
        "not the old one with the tokens appended",
    );
    // Without an old value the prefix is the current rules' business only.
    refused_now(
        &with(&base, &|p| {
            *last_tokens(p).2 = "$ ZZ_FLAG_A ZZ_OS_A".to_owned()
        }),
        "other than the old one with the tokens appended",
    );
    refused_now(
        &with(&base, &|p| {
            *last_tokens(p).2 = "ZZ_FLAG_A ZZ_OS_A".to_owned()
        }),
        "other than the old one with the tokens appended",
    );
}

/// The worst case of one `TokenList` fits the op budget: the longest relative path (240
/// characters, each outside the BMP: 4 bytes of UTF-8, review N-a), the longest old value (509
/// quote characters: 4 hex digits per UTF-16 byte pair inline, and again in `new`, escaped to 2
/// bytes each) and one token (a character of a token costs 2 bytes, one of the old value 6, so
/// fewer tokens is worse). `RelPath` bounds the path and the grammar both values, so no
/// `TokenList` can break the budget (the root's path is not part of the op).
#[test]
fn p_l3_the_worst_case_token_list_fits_the_op_budget() {
    let mut p = sample();
    p.roots[1].main_exe = Some(r("g2.exe"));
    let exe = format!(
        r"{}\{}.exe",
        "\u{20000}".repeat(120),
        "\u{20000}".repeat(115)
    );
    assert_eq!(exe.chars().count(), crate::path::RelPath::MAX_LEN);
    let old = "\"".repeat(509);
    p.ops.push(Op::TokenList {
        slot: layers_slot(0, &exe),
        old: old_sz(&old),
        add: ts(&["A"]),
        new: format!("{old} A"),
    });
    let size = serde_json::to_vec(&p.ops[3]).unwrap().len();
    eprintln!("P-L3: worst-case TokenList is {size} bytes");
    assert!(size < MAX_OP_BYTES, "{size}");
    assert!(size > 4_000, "{size}: the worst case is the worst case");
    // Eight tokens of 40 characters instead cost less.
    let tokens: Vec<String> = (0..8).map(|i| format!("{i}{}", "Z".repeat(39))).collect();
    let tokens: Vec<&str> = tokens.iter().map(String::as_str).collect();
    let short = "\"".repeat(511 - 328);
    let mut q = p.clone();
    q.ops[3] = Op::TokenList {
        slot: layers_slot(0, &exe),
        old: old_sz(&short),
        add: ts(&tokens),
        new: format!("{short} {}", tokens.join(" ")),
    };
    let other = serde_json::to_vec(&q.ops[3]).unwrap().len();
    assert!(other < size, "{other} < {size}");
    assert_eq!(
        decode_recorded(&serde_json::to_vec(&q).unwrap()).unwrap(),
        q
    );
    let bytes = serde_json::to_vec(&p).unwrap();
    assert_eq!(decode_recorded(&bytes).unwrap(), p);
}

/// E7 (M2): the created `AppCompatFlags` and `Layers` are shared Windows keys, one object
/// each; the value is the key and the folded executable path.
#[test]
fn p_l4_shared_keys_are_only_the_key_itself() {
    let objs = Object::of(&layer_plan()).unwrap();
    let key = |p: &str| RegKey::new(Hive::CurrentUser, RegView::Native, p);
    assert!(objs.contains(&Object::Key {
        key: key(LAYERS),
        created: false,
    }));
    let value = |exe: &str| Object::Value {
        key: key(LAYERS),
        name: crate::fold::fold(exe),
    };
    assert!(overlap(&objs, &[value(r"d:\games\g\GAME.exe")]));
    assert!(!overlap(&objs, &[value(r"D:\Games\Other\game.exe")]));
    // A game key the plan creates still holds everything below it.
    let reg = Object::of(&super::reg_tests::sample_reg()).unwrap();
    assert!(
        reg.iter()
            .any(|o| matches!(o, Object::Key { created: true, .. }))
    );
}

#[test]
fn p_l5_the_preview_shows_tokens_old_new_and_the_layers_note() {
    let text = preview(&layer_plan()).to_string();
    for want in [
        &format!(r"  3. create key HKCU\{}", &LAYERS[..LAYERS.len() - 7]) as &str,
        &format!(r"  5. add tokens HKCU\{LAYERS} @ D:\Games\G\game.exe"),
        "     adds ZZ_FLAG_A ZZ_OS_A\n",
        "     old missing\n",
        "     new REG_SZ: ~ ZZ_FLAG_A ZZ_OS_A\n",
        "note: compatibility layers: a revert removes only the tokens Rerun added",
        "reverting that transaction removes it",
        "another order than newest first can leave them empty for good",
    ] {
        assert!(text.contains(want), "{want:?} not in\n{text}");
    }
    assert_eq!(text.matches("note: compatibility layers").count(), 1);
    let text = preview(&merge_plan()).to_string();
    assert!(text.contains("     old REG_SZ: ~ RUNASADMIN\n"), "{text}");
    assert!(
        text.contains(r"@ D:\SteamLibrary\steamapps\common\G2\bin\g2.exe"),
        "{text}"
    );
    assert!(
        !preview(&sample())
            .to_string()
            .contains("compatibility layers")
    );
}
