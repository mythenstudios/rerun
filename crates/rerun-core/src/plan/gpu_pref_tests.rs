//! P (P4-11): `GpuPref` in the plan format. One form on the wire; the rules of `check` on
//! encode and decode, the version-independent relation `new = old with Rerun's pair` in both
//! rule sets (a manipulated head is refused also for a revert), the grammar and `check_pref`
//! only with `Rules::Current`; the op budget of the worst case (P-G3).

use super::super::{
    MAX_OP_BYTES, Op, Plan, RootIx, ValueState, decode, decode_recorded, pref_relation, preview,
};
use super::{r, sample};
use crate::policy::registry::{GpuPref, RegSlot};
use crate::sys::registry::RegValue;

const HP: GpuPref = GpuPref::HighPerformance;

fn pref_slot(root: u16, exe: &str) -> RegSlot {
    RegSlot::GpuPreference {
        root: RootIx(root),
        exe: r(exe),
    }
}

fn old_sz(s: &str) -> Option<ValueState> {
    ValueState::of(&RegValue::String(s.to_owned()))
}

/// `sample` plus the two created shared keys and a new value of root 0's `game.exe`.
fn new_plan() -> Plan {
    let mut p = sample();
    p.roots[1].main_exe = Some(r("g2.exe"));
    let s = pref_slot(0, "game.exe");
    p.ops.extend([
        Op::CreateKey {
            slot: s.clone(),
            segs: 3,
        },
        Op::CreateKey {
            slot: s.clone(),
            segs: 4,
        },
        Op::GpuPref {
            slot: s,
            old: None,
            pref: HP,
            new: "GpuPreference=2;".to_owned(),
        },
    ]);
    p
}

/// `sample` plus a merge into an existing value of root 1's `g2.exe`.
fn merge_plan(old: &str, new: &str) -> Plan {
    let mut p = sample();
    p.roots[1].main_exe = Some(r("g2.exe"));
    p.ops.push(Op::GpuPref {
        slot: pref_slot(1, r"bin\g2.exe"),
        old: old_sz(old),
        pref: HP,
        new: new.to_owned(),
    });
    p
}

/// Refused on encode and on decode with either rule set.
fn refused(p: &Plan, want: &str) {
    let e = p.encode().expect_err(want).to_string();
    assert!(e.contains(want), "encode, {want}: {e}");
    let bytes = serde_json::to_vec(p).unwrap();
    let e = decode(&bytes).expect_err(want).to_string();
    assert!(e.contains(want), "decode, {want}: {e}");
    let e = decode_recorded(&bytes).expect_err(want).to_string();
    assert!(e.contains(want), "decode_recorded, {want}: {e}");
}

/// Refused by the current rules only: a recorded head is still readable (E4 of P2-11).
fn refused_now(p: &Plan) {
    assert!(p.encode().is_err());
    let bytes = serde_json::to_vec(p).unwrap();
    assert!(decode(&bytes).is_err());
    assert_eq!(decode_recorded(&bytes).unwrap(), *p);
}

#[test]
fn p_g1_gpu_prefs_round_trip_in_one_form() {
    for p in [
        new_plan(),
        merge_plan("AutoHDREnable=1;", "AutoHDREnable=1;GpuPreference=2;"),
        merge_plan(
            "AutoHDREnable=1;GpuPreference=0;SwapEffectUpgradeEnable=1;",
            "AutoHDREnable=1;GpuPreference=2;SwapEffectUpgradeEnable=1;",
        ),
    ] {
        let b = p.encode().unwrap();
        assert_eq!(decode(b.bytes()).unwrap(), p);
        assert_eq!(decode_recorded(b.bytes()).unwrap(), p);
    }
    let b = new_plan().encode().unwrap();
    let s = std::str::from_utf8(b.bytes()).unwrap();
    let want = r#"{"gpu_pref":{"slot":{"gpu_preference":{"root":0,"exe":"game.exe"}},"old":null,"pref":"high_performance","new":"GpuPreference=2;"}}"#;
    assert!(s.contains(want), "{want} not in {s}");
    let bad = s.replacen("high_performance", "power_saving", 1);
    assert!(decode_recorded(bad.as_bytes()).is_err());
}

/// A manipulated head: `new` is not the old value with Rerun's pair. Refused by both rule
/// sets (the relation is version-independent, the S-1 analogue), so a revert's restore of
/// `After` can never write another pair; the control K-G1 shows `pref_relation` bites.
#[test]
fn p_g2_the_relation_holds_in_both_rule_sets() {
    let want = "Rerun's graphics preference";
    // Another pair changed as well.
    refused(
        &merge_plan("AutoHDREnable=1;", "AutoHDREnable=0;GpuPreference=2;"),
        want,
    );
    // Appended although the pair was there.
    refused(
        &merge_plan("GpuPreference=0;", "GpuPreference=0;GpuPreference=2;"),
        want,
    );
    // Without an old value: anything but the pair alone.
    let mut p = new_plan();
    if let Some(Op::GpuPref { new, .. }) = p.ops.last_mut() {
        *new = "GpuPreference=2;AutoHDREnable=1;".to_owned();
    }
    refused(&p, want);
    // Equal to the old value.
    refused(&merge_plan("GpuPreference=2;", "GpuPreference=2;"), want);
    // A value op on a graphics preference slot is never a plain set.
    let mut p = sample();
    p.roots[1].main_exe = Some(r("g2.exe"));
    p.ops.push(Op::SetValue {
        slot: pref_slot(0, "game.exe"),
        old: None,
        new: super::super::NewValue::Sz("GpuPreference=2;".to_owned()),
    });
    refused(&p, "never set as a whole");
    // K-G1: the relation itself.
    assert!(pref_relation(None, "GpuPreference=2;", HP));
    assert!(pref_relation(Some("A=1;"), "A=1;GpuPreference=2;", HP));
    assert!(pref_relation(
        Some("A=1;GpuPreference=1;B=2;"),
        "A=1;GpuPreference=2;B=2;",
        HP
    ));
    assert!(!pref_relation(Some("A=1;"), "A=0;GpuPreference=2;", HP));
    assert!(!pref_relation(None, "GpuPreference=1;", HP));
}

/// Current rules only: the user's "Power saving" (E-G3 a) and an old value outside the
/// grammar; a recorded head with them still decodes (a tighter rule never blocks a revert).
#[test]
fn p_g2_current_rules_only() {
    refused_now(&merge_plan("GpuPreference=1;", "GpuPreference=2;"));
    refused_now(&merge_plan("A=1;B= 2;", "A=1;B= 2;GpuPreference=2;"));
}

/// P-G3: the worst case of one `GpuPref` fits the op budget: the longest relative path (240
/// characters outside the BMP, 4 bytes each), an old value of 476 characters of `"` in pairs
/// (inline hex and again, escaped, in `new`).
#[test]
fn p_g3_the_worst_case_fits_the_op_budget() {
    let exe = format!(
        r"{}\{}.exe",
        "\u{20000}".repeat(120),
        "\u{20000}".repeat(115)
    );
    assert_eq!(exe.chars().count(), crate::path::RelPath::MAX_LEN);
    let old: String = (0..7)
        .map(|i| format!("A{i}={};", "\"".repeat(64)))
        .collect();
    let new = format!("{old}GpuPreference=2;");
    let mut p = sample();
    p.roots[1].main_exe = Some(r("g2.exe"));
    p.ops.push(Op::GpuPref {
        slot: pref_slot(0, &exe),
        old: old_sz(&old),
        pref: HP,
        new,
    });
    let size = serde_json::to_vec(&p.ops[3]).unwrap().len();
    eprintln!("P-G3: worst-case GpuPref is {size} bytes");
    assert!(size < MAX_OP_BYTES, "{size}");
    assert_eq!(
        decode_recorded(&serde_json::to_vec(&p).unwrap()).unwrap(),
        p
    );
}

#[test]
fn p_g4_the_preview_names_the_value() {
    let v = preview(&new_plan());
    let o = v.ops.last().unwrap();
    assert_eq!(o.action, "set gpu preference");
    let note = v.gpu_pref.unwrap();
    // X3 (ADR 0020): the shared keys can stay behind, empty, after another revert order.
    assert!(
        note.contains("DirectX and UserGpuPreferences are shared")
            && note.contains("another order than newest first can leave them empty for good"),
        "{note}"
    );
}
