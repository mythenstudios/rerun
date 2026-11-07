//! L (P2-11, pure): the grammar, the token form, the allowlist and groups, `merge` and
//! `unmerge` exhaustively over a small alphabet, and the controls K-L1 and K-L4 through
//! [`l1_check`], all with synthetic tokens. L-P1 to L-P7 (P2-11b): the production tables
//! against the SB-L1 fixture, with the control K-L5 through [`unobserved`].

use super::super::{AllowedValue, RegPolicy, RegSlot};
use super::{
    Group, MAX_ADD, MAX_LAYERS_BYTES, PREFIX_NEW, TokenName, Unmerged, allowed, check, group_of,
    knob, merge, parse, unmerge,
};
use crate::path::{RelPath, RootPath};
use crate::plan::RootIx;

fn t(s: &str) -> TokenName {
    TokenName::parse(s).unwrap()
}

fn ts(s: &[&str]) -> Vec<TokenName> {
    s.iter().map(|x| t(x)).collect()
}

/// Resets the knobs of this module when dropped.
struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        knob::production(false);
        knob::drop_token(None);
        knob::reverse(false);
        knob::normalise_old(false);
        knob::first_only(false);
    }
}

#[test]
fn l_the_grammar_is_strict() {
    for ok in ["A", "~ A", "$ ~ RUNASADMIN X_1", "a!b ~", &"A".repeat(511)] {
        assert!(parse(ok).is_ok(), "{ok:?}");
    }
    assert_eq!(parse("~ A B").unwrap().words(), ["~", "A", "B"]);
    for bad in [
        "",
        " ",
        " A",
        "A ",
        "A  B",
        "A\tB",
        "A\u{a0}B",
        "A\u{e9}",
        "A\nB",
        "A\0",
        &"A".repeat(512),
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
    // 1 KiB with the NUL: 511 characters.
    assert_eq!(MAX_LAYERS_BYTES, 1024);
}

#[test]
fn l_a_token_has_its_form_on_the_wire_and_off_it() {
    for ok in ["A", "ZZ_OS_A", "X1", "_", &"A".repeat(40), "RUNASADMIN"] {
        assert!(TokenName::parse(ok).is_ok(), "{ok}");
    }
    for bad in ["", "a", "A-B", "A B", "~", "$", "Ä", &"A".repeat(41)] {
        assert!(TokenName::parse(bad).is_err(), "{bad:?}");
    }
    let j: Vec<TokenName> = serde_json::from_str(r#"["ZZ_OS_A","B"]"#).unwrap();
    assert_eq!(j, ts(&["ZZ_OS_A", "B"]));
    assert!(serde_json::from_str::<Vec<TokenName>>(r#"["zz_os_a"]"#).is_err());
    assert_eq!(
        serde_json::to_string(&t("ZZ_OS_A")).unwrap(),
        r#""ZZ_OS_A""#
    );
    // Byte order (review M1), not allowlist order.
    let mut v = ts(&["ZZ_OS_A", "ZZ_COLOR_A", "A_", "A1", "A"]);
    v.sort();
    let s: Vec<&str> = v.iter().map(TokenName::as_str).collect();
    assert_eq!(s, ["A", "A1", "A_", "ZZ_COLOR_A", "ZZ_OS_A"]);
}

#[test]
fn l_the_allowlist_and_the_groups() {
    let _r = Reset;
    assert!(allowed(&t("ZZ_OS_A")));
    assert!(
        !allowed(&t("ZZ_OS_C")),
        "a group-table token is not addable"
    );
    assert!(!allowed(&t("RUNASADMIN")));
    assert!(!allowed(&t("RUNASHIGHEST")));
    assert_eq!(group_of("zz_os_c"), Some(Group::OsMode), "folded (S4)");
    assert_eq!(group_of("ZZ_FLAG_A"), None, "not listed: no group");
    // The production tables know no synthetic token.
    knob::production(true);
    assert!(!allowed(&t("ZZ_OS_A")));
    assert!(check(None, &ts(&["ZZ_OS_A"])).is_err());
    knob::production(false);
    // No production token may ever be an elevation token, whatever the list says.
    assert!(
        super::LAYER_TOKENS
            .iter()
            .all(|x| !x.starts_with(super::ELEVATION))
    );
}

#[test]
fn l_check_refuses_every_broken_rule() {
    let _r = Reset;
    assert!(check(None, &ts(&["ZZ_FLAG_A", "ZZ_OS_A"])).is_ok());
    assert!(check(Some("~ RUNASADMIN ZZ_OS_C_X"), &ts(&["ZZ_OS_A"])).is_ok());
    let refused = |old: Option<&str>, add: &[&str], want: &str| {
        let e = check(old, &ts(add)).expect_err(want).to_string();
        assert!(e.contains(want), "{old:?} {add:?}: {e}");
    };
    refused(None, &[], "1 to 8 tokens");
    let nine = [
        "ZZ_COLOR_A",
        "ZZ_DPI_A",
        "ZZ_FLAG_A",
        "ZZ_FLAG_B",
        "ZZ_FLAG_C",
        "ZZ_FLAG_D",
        "ZZ_FLAG_E",
        "ZZ_FLAG_F",
        "ZZ_FLAG_G",
    ];
    assert_eq!(nine.len(), MAX_ADD + 1);
    refused(None, &nine, "1 to 8 tokens");
    assert!(check(None, &ts(&nine[..MAX_ADD])).is_ok());
    refused(None, &["ZZ_OS_A", "ZZ_FLAG_A"], "byte order");
    refused(None, &["ZZ_FLAG_A", "ZZ_FLAG_A"], "byte order");
    refused(None, &["RUNASADMIN"], "not on the allowlist");
    refused(None, &["ZZ_OS_C"], "not on the allowlist");
    refused(Some("~ ZZ_FLAG_A"), &["ZZ_FLAG_A"], "already in the value");
    refused(Some("~ zz_flag_a"), &["ZZ_FLAG_A"], "already in the value");
    refused(None, &["ZZ_OS_A", "ZZ_OS_B"], "two tokens of one group");
    refused(Some("~ ZZ_OS_C"), &["ZZ_OS_A"], "two tokens of one group");
    refused(Some("~ zz_os_c"), &["ZZ_OS_A"], "two tokens of one group");
    refused(Some("ZZ_DPI_B"), &["ZZ_DPI_A"], "two tokens of one group");
    refused(Some("~  X"), &["ZZ_OS_A"], "an unusual value");
    refused(Some(""), &["ZZ_OS_A"], "an unusual value");
    // The merged value must fit too.
    let long = format!("~ {}", "X".repeat(500));
    refused(Some(&long), &["ZZ_COLOR_A", "ZZ_OS_A"], "longer than 511");
    // A dropped token (R-L8) is refused.
    knob::drop_token(Some("ZZ_OS_A"));
    refused(None, &["ZZ_OS_A"], "not on the allowlist");
}

#[test]
fn l_check_tokens_takes_only_compatibility_layers() {
    let roots = [RootPath::new(r"D:\Games\G").unwrap()];
    let layers: AllowedValue = RegPolicy
        .check(
            &RegSlot::CompatLayers {
                root: RootIx(0),
                exe: RelPath::parse("game.exe").unwrap(),
            },
            &roots,
        )
        .unwrap();
    assert!(layers.shared_keys());
    assert_eq!(layers.name(), r"D:\Games\G\game.exe");
    assert!(
        RegPolicy
            .check_tokens(&layers, None, &ts(&["ZZ_OS_A"]))
            .is_ok()
    );
    let game = RegPolicy
        .check(
            &RegSlot::GameValue {
                key: super::super::GameKey::new(
                    super::super::AsciiSeg::parse("Vendor").unwrap(),
                    super::super::AsciiSeg::parse("Game").unwrap(),
                    Vec::new(),
                )
                .unwrap(),
                name: super::super::AsciiName::parse("x").unwrap(),
            },
            &roots,
        )
        .unwrap();
    assert!(!game.shared_keys());
    assert!(
        RegPolicy
            .check_tokens(&game, None, &ts(&["ZZ_OS_A"]))
            .is_err()
    );
    // A new value is never set on a compatibility-layer slot (only through tokens).
    assert!(
        RegPolicy
            .check_new(
                &layers,
                &crate::sys::registry::RegValue::String("~ ZZ_OS_A".into())
            )
            .is_err()
    );
}

/// The small alphabet of the exhaustive tests: prefixes, foreign words, Rerun's tokens.
const PREFIXES: [&[&str]; 4] = [&[], &["~"], &["$"], &["~", "$"]];
const FOREIGN: [&[&str]; 4] = [&[], &["X1"], &["RUNASADMIN"], &["Y_2", "a!b"]];
const OURS: [&str; 3] = ["ZZ_DPI_A", "ZZ_FLAG_A", "ZZ_OS_A"];

/// Every non-empty subset of [`OURS`], in byte order.
fn subsets() -> Vec<Vec<TokenName>> {
    (1u8..8)
        .map(|m| {
            OURS.iter()
                .enumerate()
                .filter(|(i, _)| m & (1 << i) != 0)
                .map(|(_, s)| t(s))
                .collect()
        })
        .collect()
}

/// R-L1 at the level of `policy` as a check (review N1): `merge` keeps the bytes of the old
/// value and appends; `unmerge` of the merged value is the old value (missing, or nothing but
/// prefix words: deleted, S2); `unmerge` of the merged value with its words reordered (as the
/// compatibility tab might write it) keeps the order of the other words; every finding named.
/// The controls K-L1 and K-L4 must make it report.
pub(crate) fn l1_check() -> Vec<String> {
    let mut f = Vec::new();
    for p in PREFIXES {
        for fw in FOREIGN {
            let words: Vec<&str> = p.iter().chain(fw.iter()).copied().collect();
            let old = (!words.is_empty()).then(|| words.join(" "));
            for add in subsets() {
                let new = merge(old.as_deref(), &add);
                let tail: Vec<&str> = add.iter().map(TokenName::as_str).collect();
                let want_new = match &old {
                    Some(o) => format!("{o} {}", tail.join(" ")),
                    None => format!("{PREFIX_NEW}{}", tail.join(" ")),
                };
                if new != want_new {
                    f.push(format!("L1 merge {old:?} + {tail:?}: {new:?}"));
                }
                // Nothing but prefix words left: deleted (S2), also when there was an old value.
                let want = old
                    .clone()
                    .filter(|o| !o.split(' ').all(|w| super::PREFIX_WORDS.contains(&w)));
                let got = unmerge(&new, &add);
                if got != Unmerged::Rest(want.clone()) {
                    f.push(format!("L1 unmerge {new:?} - {tail:?}: {got:?}"));
                }
                // Reordered: Rerun's tokens first, the rest in its order.
                let others: Vec<&str> = new.split(' ').filter(|w| !tail.contains(w)).collect();
                let moved: Vec<&str> = tail.iter().chain(others.iter()).copied().collect();
                let got = unmerge(&moved.join(" "), &add);
                let rest = (!others.iter().all(|w| super::PREFIX_WORDS.contains(w)))
                    .then(|| others.join(" "));
                if got != Unmerged::Rest(rest) {
                    f.push(format!("L1 unmerge reordered {moved:?}: {got:?}"));
                }
            }
        }
    }
    f
}

#[test]
fn l1_merge_and_unmerge_round_trip_over_the_alphabet() {
    let _r = Reset;
    let f = l1_check();
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn l_unmerge_finds_foreign_and_untouched_values() {
    let ours = ts(&["ZZ_FLAG_A", "ZZ_OS_A"]);
    for (cur, want) in [
        ("~ ZZ_FLAG_A X ZZ_OS_A", Unmerged::Rest(Some("~ X".into()))),
        ("$ X ZZ_OS_A", Unmerged::Rest(Some("$ X".into()))),
        // One of ours removed by the user (E2 b): the rest of ours goes.
        ("~ X ZZ_OS_A", Unmerged::Rest(Some("~ X".into()))),
        // S2: only prefix words left, also when there was an old value.
        ("~ ZZ_OS_A", Unmerged::Rest(None)),
        ("ZZ_OS_A ZZ_FLAG_A", Unmerged::Rest(None)),
        // `$` is an ordinary word (P2-11b, B4.1): it stays.
        ("~ $ ZZ_OS_A", Unmerged::Rest(Some("~ $".into()))),
        ("$ ZZ_OS_A", Unmerged::Rest(Some("$".into()))),
        // None of ours left.
        ("~ X", Unmerged::Untouched),
        ("~", Unmerged::Untouched),
        // Not Rerun's state.
        ("~ ZZ_OS_A ZZ_OS_A", Unmerged::Foreign),
        ("~ zz_os_a", Unmerged::Foreign),
        ("~ Zz_Os_A ZZ_FLAG_A", Unmerged::Foreign),
        ("~  ZZ_OS_A", Unmerged::Foreign),
        ("~ ZZ_OS_A ", Unmerged::Foreign),
        ("", Unmerged::Foreign),
    ] {
        assert_eq!(unmerge(cur, &ours), want, "{cur:?}");
    }
    let long = format!("~ {} ZZ_OS_A", "X".repeat(600));
    assert_eq!(unmerge(&long, &ours), Unmerged::Foreign);
}

/// K-L4: `merge` normalising the old value (sorting its words) fails L1.
#[test]
fn k_l4_merge_normalising_the_old_value_breaks_l1() {
    let _r = Reset;
    knob::normalise_old(true);
    let f = l1_check();
    assert!(f.iter().any(|x| x.starts_with("L1 merge")), "{f:#?}");
}

/// K-L1: `unmerge` removing only the first of Rerun's tokens fails L1.
#[test]
fn k_l1_unmerge_removing_only_the_first_token_breaks_l1() {
    let _r = Reset;
    knob::first_only(true);
    let f = l1_check();
    assert!(f.iter().any(|x| x.starts_with("L1 unmerge")), "{f:#?}");
}

// --- P2-11b: the production tables against the SB-L1 fixture ---------------------------------

/// The words of `list` that no value the compatibility tab wrote in `tab` holds (the planted
/// `01-foreign` does not count): what a list may not contain (L-P2; never invent,
/// `docs/05-sources-policy.md`).
pub(crate) fn unobserved(list: &[&str], tab: &[(&str, &str, &str)]) -> Vec<String> {
    list.iter()
        .filter(|w| {
            !tab.iter()
                .filter(|(label, _, _)| *label != "01-foreign")
                .any(|(_, _, d)| d.split(' ').any(|x| x == **w))
        })
        .map(|w| (*w).to_owned())
        .collect()
}

fn group_words() -> Vec<&'static str> {
    super::LAYER_GROUPS.iter().map(|(w, _)| *w).collect()
}

/// L-P1: the add allowlist is in byte order, unique, of the token form, allowed, never an
/// elevation token and nothing of the never-list; the group table is unique (folded).
#[test]
fn l_p1_the_production_lists_are_clean() {
    let _r = Reset;
    knob::production(true);
    let list = super::LAYER_TOKENS;
    assert!(!list.is_empty());
    assert!(list.windows(2).all(|w| w[0] < w[1]), "byte order, unique");
    for x in list {
        assert!(allowed(&t(x)), "{x}");
        assert!(!super::NEVER_ADD.contains(x), "{x}");
        assert!(!x.starts_with(super::ELEVATION), "{x}");
    }
    for x in super::NEVER_ADD {
        assert!(!allowed(&t(x)), "{x}");
    }
    let mut folded: Vec<String> = group_words()
        .iter()
        .map(|w| {
            assert!(TokenName::parse(w).is_ok(), "{w}");
            crate::fold::fold(w)
        })
        .collect();
    let n = folded.len();
    folded.sort();
    folded.dedup();
    assert_eq!(folded.len(), n, "the group table is unique");
    // The groups of the observed options (B3 a: all three DPI words; the modes seen).
    for (w, g) in [
        ("HIGHDPIAWARE", Some(Group::Dpi)),
        ("DPIUNAWARE", Some(Group::Dpi)),
        ("GDIDPISCALING", Some(Group::Dpi)),
        ("16BITCOLOR", Some(Group::Color)),
        ("256COLOR", Some(Group::Color)),
        ("640X480", Some(Group::Res)),
        ("WINXPSP3", Some(Group::OsMode)),
        ("WIN7RTM", Some(Group::OsMode)),
        ("DISABLEDXMAXIMIZEDWINDOWEDMODE", None),
        ("RUNASADMIN", None),
    ] {
        assert_eq!(group_of(w), g, "{w}");
    }
}

/// L-P2: every word of both production tables is in a value the tab wrote (SB-L1). K-L5: a
/// planted unobserved word is reported.
#[test]
fn l_p2_every_listed_word_was_observed() {
    let tab = super::sb_l1_tab();
    assert_eq!(tab.len(), 17);
    let mut labels: Vec<&str> = tab.iter().map(|(l, _, _)| *l).collect();
    labels.dedup();
    assert_eq!(labels.len(), tab.len(), "labels unique");
    assert!(tab.iter().all(|(_, h, _)| *h == "HKCU" || *h == "HKLM"));
    assert_eq!(unobserved(super::LAYER_TOKENS, &tab), Vec::<String>::new());
    assert_eq!(unobserved(&group_words(), &tab), Vec::<String>::new());
    // K-L5: the check bites.
    let mut planted = super::LAYER_TOKENS.to_vec();
    planted.push("WIN8RTM");
    assert_eq!(unobserved(&planted, &tab), ["WIN8RTM"]);
    // A word only the planted value holds is not observed either.
    let only_planted = [("01-foreign", "HKCU", "~ ZZ_PLANTED")];
    assert_eq!(unobserved(&["ZZ_PLANTED"], &only_planted), ["ZZ_PLANTED"]);
}

/// L-P3: the strict grammar takes every value the tab wrote, each begins with `PREFIX_NEW`,
/// and every word after it has the token form.
#[test]
fn l_p3_the_grammar_takes_every_tab_value() {
    for (label, _, d) in super::sb_l1_tab() {
        let l = parse(d).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(d.starts_with(PREFIX_NEW), "{label}");
        assert!(super::PREFIX_WORDS.contains(&l.words()[0]), "{label}");
        for w in &l.words()[1..] {
            assert!(TokenName::parse(w).is_ok(), "{label}: {w}");
        }
    }
}

/// What `check` says to one token on one tab value (L-P4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Says {
    Ok,
    Already,
    Group,
}

/// The tokens of the columns of [`L_P4`]: a token taken off the allowlist keeps its column,
/// whose rows then all expect "not on the allowlist".
const L_P4_COLS: [&str; 2] = ["DISABLEDXMAXIMIZEDWINDOWEDMODE", "HIGHDPIAWARE"];

/// L-P4: every tab value of the fixture x every token, fixed.
const L_P4: [(&str, [Says; 2]); 17] = [
    ("01-foreign", [Says::Ok, Says::Ok]),
    ("02-xpsp3", [Says::Ok, Says::Ok]),
    ("03-win7", [Says::Ok, Says::Ok]),
    ("04-color16", [Says::Ok, Says::Ok]),
    ("05-640x480", [Says::Ok, Says::Ok]),
    ("06-nofso", [Says::Already, Says::Ok]),
    ("07-admin", [Says::Ok, Says::Ok]),
    ("08-restart", [Says::Ok, Says::Ok]),
    ("09-icc", [Says::Ok, Says::Ok]),
    ("10-dpi-app", [Says::Ok, Says::Already]),
    ("12-combined", [Says::Already, Says::Already]),
    ("13-resave", [Says::Already, Says::Already]),
    ("14-cleared", [Says::Ok, Says::Ok]),
    ("15-allusers", [Says::Ok, Says::Ok]),
    ("21-dpi-system", [Says::Ok, Says::Group]),
    ("22-dpi-sysenh", [Says::Ok, Says::Group]),
    ("23-xpsp3-plus", [Says::Ok, Says::Group]),
];

#[test]
fn l_p4_the_conflicts_with_every_tab_value() {
    let _r = Reset;
    knob::production(true);
    let tab = super::sb_l1_tab();
    assert_eq!(
        tab.iter().map(|(l, _, _)| *l).collect::<Vec<_>>(),
        L_P4.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
        "a row for every tab value"
    );
    assert!(
        super::LAYER_TOKENS.iter().all(|x| L_P4_COLS.contains(x)),
        "a column for every token"
    );
    for ((label, _, d), (_, says)) in tab.iter().zip(L_P4) {
        for (col, want) in L_P4_COLS.iter().zip(says) {
            let got = check(Some(d), &ts(&[col]));
            let has = |s: &str| got.as_ref().is_err_and(|e| e.to_string().contains(s));
            let ok = match (super::LAYER_TOKENS.contains(col), want) {
                (false, _) => has("not on the allowlist"),
                (true, Says::Ok) => got.is_ok(),
                (true, Says::Already) => has("already in the value"),
                (true, Says::Group) => has("two tokens of one group"),
            };
            assert!(ok, "{label} + {col}: {got:?}, want {want:?}");
        }
    }
    // All tokens together: on a new value and after the foreign token.
    let all = ts(super::LAYER_TOKENS);
    assert!(check(None, &all).is_ok());
    assert!(check(Some("~ RUNASINVOKER"), &all).is_ok());
}

/// L-P5: `merge` in byte order, appended (B8 a: not the tab's order).
#[test]
fn l_p5_merge_is_pinned() {
    let four = ts(&[
        "256COLOR",
        "640X480",
        "DISABLEDXMAXIMIZEDWINDOWEDMODE",
        "HIGHDPIAWARE",
    ]);
    assert_eq!(
        merge(None, &four),
        "~ 256COLOR 640X480 DISABLEDXMAXIMIZEDWINDOWEDMODE HIGHDPIAWARE"
    );
    assert_eq!(
        merge(Some("~ RUNASINVOKER"), &ts(&["HIGHDPIAWARE"])),
        "~ RUNASINVOKER HIGHDPIAWARE"
    );
}

/// L-P6: `unmerge` after the tab reordered a value (derived from the order SB-L1 saw in
/// 12-combined, not observed on a value of Rerun's: SB-L1b): the old value exactly.
#[test]
fn l_p6_unmerge_after_the_tab_reordered() {
    let four = ts(&[
        "256COLOR",
        "640X480",
        "DISABLEDXMAXIMIZEDWINDOWEDMODE",
        "HIGHDPIAWARE",
    ]);
    assert_eq!(
        unmerge(
            "~ DISABLEDXMAXIMIZEDWINDOWEDMODE 640X480 HIGHDPIAWARE 256COLOR",
            &four
        ),
        Unmerged::Rest(None)
    );
    let h = ts(&["HIGHDPIAWARE"]);
    assert_eq!(
        unmerge("~ HIGHDPIAWARE RUNASINVOKER", &h),
        Unmerged::Rest(Some("~ RUNASINVOKER".into()))
    );
    assert_eq!(
        unmerge("~ RUNASADMIN HIGHDPIAWARE RUNASINVOKER", &h),
        Unmerged::Rest(Some("~ RUNASADMIN RUNASINVOKER".into()))
    );
}

/// L-P7: the prefixes. A lone `~` holds none of ours (B4.2 as decided: left); `$` is an
/// ordinary word (B4.1); a prefix joined to a word or after a word is refused by `check`
/// only (B4.3), at the start it is fine.
#[test]
fn l_p7_prefixes() {
    let _r = Reset;
    knob::production(true);
    let ours = ts(&["DISABLEDXMAXIMIZEDWINDOWEDMODE", "HIGHDPIAWARE"]);
    assert_eq!(super::PREFIX_WORDS, ["~"]);
    assert_eq!(unmerge("~", &ours), Unmerged::Untouched);
    assert_eq!(unmerge("$", &ours), Unmerged::Untouched);
    assert_eq!(
        unmerge("$ HIGHDPIAWARE", &ours),
        Unmerged::Rest(Some("$".into()))
    );
    let h = ts(&["HIGHDPIAWARE"]);
    let d = ts(&["DISABLEDXMAXIMIZEDWINDOWEDMODE"]);
    for old in [
        "~HIGHDPIAWARE",
        "~ ~HIGHDPIAWARE",
        "$HIGHDPIAWARE",
        "~ X $Y",
        "WIN7RTM ~",
        "~ WIN7RTM $",
        "~~",
    ] {
        for add in [&h, &d] {
            let e = check(Some(old), add).expect_err(old).to_string();
            assert!(e.contains("a prefix joined to a word"), "{old}: {e}");
        }
    }
    for old in ["~", "$", "$ ~", "~ $ RUNASADMIN", "$ RUNASADMIN", "X~ Y$"] {
        assert!(check(Some(old), &h).is_ok(), "{old}");
    }
    // The grammar and the revert take such a value as any other.
    assert!(parse("WIN7RTM ~").is_ok());
    assert_eq!(
        unmerge("~HIGHDPIAWARE HIGHDPIAWARE", &h),
        Unmerged::Rest(Some("~HIGHDPIAWARE".into()))
    );
}
