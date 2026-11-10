//! G-P1: the grammar, merge and revert of a `UserGpuPreferences` value (P4-11). Every value is
//! of the documented form (`docs/03b-gpu-display.md`, "Sources"); the SB-G1 dump of what
//! Settings writes is pending (`tests/fixtures/gpu-pref/`).

use super::*;

const HP: GpuPref = GpuPref::HighPerformance;

#[test]
fn parse_keeps_pairs_in_order() {
    let p = parse("AutoHDREnable=1;SwapEffectUpgradeEnable=1;GpuPreference=0;").unwrap();
    assert_eq!(
        p.pairs(),
        [
            ("AutoHDREnable", "1"),
            ("SwapEffectUpgradeEnable", "1"),
            ("GpuPreference", "0"),
        ]
    );
    assert_eq!(current(&p), Current::Digit(0));
    assert_eq!(
        current(&parse("AutoHDREnable=1;").unwrap()),
        Current::Absent
    );
    assert_eq!(
        current(&parse("GpuPreference=1;").unwrap()),
        Current::Digit(1)
    );
    // A value of another form than a digit is fine for a pair Rerun does not touch.
    assert!(parse("VendorKey=abc_1.2-x;").is_ok());
}

/// The unusual corpus: everything outside the strict grammar.
#[test]
fn unusual_values_are_refused() {
    let long_name = format!("{}=1;", "A".repeat(MAX_PAIR_NAME + 1));
    let long_value = format!("A={};", "1".repeat(MAX_PAIR_VALUE + 1));
    let too_long = "A1=1;".repeat(103); // 515 characters
    for s in [
        "",
        ";",
        "GpuPreference=2",
        "GpuPreference=2; ",
        " GpuPreference=2;",
        "GpuPreference = 2;",
        "GpuPreference==2;",
        "GpuPreference=;",
        "=2;",
        "GpuPreference=2;;",
        "GpuPreference=2;AutoHDREnable=1",
        "gpupreference=2;",
        "GPUPREFERENCE=0;",
        "GpuPreference=3;",
        "GpuPreference=02;",
        "GpuPreference=2;GpuPreference=2;",
        "AutoHDREnable=1;autohdrenable=0;",
        "1Name=1;",
        "Na-me=1;",
        "Name=ä;",
        "Näme=1;",
        "Name=1\u{0};",
        "Name=a b;",
        long_name.as_str(),
        long_value.as_str(),
        too_long.as_str(),
    ] {
        assert!(parse(s).is_err(), "{s:?}");
        assert_eq!(unset(s, HP, None), Unset::Foreign, "{s:?}");
        assert!(check(Some(s), HP).is_err(), "{s:?}");
    }
    // The limit is in UTF-16 bytes with the NUL (N3): 511 characters fit, 512 do not.
    let at = format!("A={};", "1".repeat(MAX_PAIR_VALUE - 1));
    assert!(fits(&"x".repeat(511)));
    assert!(!fits(&"x".repeat(512)));
    assert!(parse(&at).is_ok());
}

#[test]
fn set_merges_only_rerun_s_pair() {
    assert_eq!(set(None, HP).unwrap(), "GpuPreference=2;");
    assert_eq!(
        set(Some("AutoHDREnable=1;SwapEffectUpgradeEnable=1;"), HP).unwrap(),
        "AutoHDREnable=1;SwapEffectUpgradeEnable=1;GpuPreference=2;"
    );
    // In its place.
    assert_eq!(
        set(
            Some("AutoHDREnable=1;GpuPreference=0;SwapEffectUpgradeEnable=1;"),
            HP
        )
        .unwrap(),
        "AutoHDREnable=1;GpuPreference=2;SwapEffectUpgradeEnable=1;"
    );
    assert!(set(Some("odd"), HP).is_err());
}

#[test]
fn check_refuses_power_saving_and_a_set_preference() {
    assert_eq!(check(None, HP).unwrap(), "GpuPreference=2;");
    assert_eq!(
        check(Some("GpuPreference=0;"), HP).unwrap(),
        "GpuPreference=2;"
    );
    // E-G3 a: the user's "Power saving" is never overridden.
    let e = check(Some("AutoHDREnable=1;GpuPreference=1;"), HP).unwrap_err();
    assert!(e.to_string().contains("Power saving"), "{e}");
    // `=2` already: the planner makes no op; the check itself refuses a write.
    assert!(check(Some("GpuPreference=2;"), HP).is_err());
    // The merged value must fit as well: 500 characters plus 16 do not.
    let big: String = (0..8)
        .map(|i| format!("A{i}={};", "1".repeat(59)))
        .collect(); // 8 x 63 = 504
    assert!(parse(&big).is_ok());
    assert!(check(Some(&big), HP).is_err());
}

#[test]
fn unset_takes_back_only_rerun_s_pair() {
    // Nothing changed since the apply: the old value comes back exactly.
    for old in [
        None,
        Some("AutoHDREnable=1;SwapEffectUpgradeEnable=1;"),
        Some("AutoHDREnable=1;GpuPreference=0;SwapEffectUpgradeEnable=1;"),
        Some("GpuPreference=0;"),
    ] {
        let new = set(old, HP).unwrap();
        assert_eq!(
            unset(&new, HP, old),
            Unset::Rest(old.map(str::to_owned)),
            "{old:?}"
        );
    }
    // Windows added a pair since: only Rerun's pair goes back.
    assert_eq!(
        unset("AutoHDREnable=0;GpuPreference=2;", HP, None),
        Unset::Rest(Some("AutoHDREnable=0;".to_owned()))
    );
    assert_eq!(
        unset(
            "GpuPreference=2;AutoHDREnable=0;",
            HP,
            Some("GpuPreference=0;")
        ),
        Unset::Rest(Some("GpuPreference=0;AutoHDREnable=0;".to_owned()))
    );
    // The user chose another preference, or removed the pair: theirs wins (D10).
    assert_eq!(
        unset("GpuPreference=1;", HP, Some("GpuPreference=0;")),
        Unset::NotOurs
    );
    assert_eq!(unset("GpuPreference=0;", HP, None), Unset::NotOurs);
    assert_eq!(unset("AutoHDREnable=1;", HP, None), Unset::NotOurs);
    // The journal's old value is read without the grammar (a grammar tightened since the plan
    // must not make a drifted value Foreign): only its GpuPreference piece counts.
    assert_eq!(
        unset(
            "AutoHDREnable=0;GpuPreference=2;",
            HP,
            Some("AutoHDREnable=1; X = y;GpuPreference=0;")
        ),
        Unset::Rest(Some("AutoHDREnable=0;GpuPreference=0;".to_owned()))
    );
    assert_eq!(
        unset("AutoHDREnable=0;GpuPreference=2;", HP, Some("odd text")),
        Unset::Rest(Some("AutoHDREnable=0;".to_owned()))
    );
    // An old pair of another value is not guessed at.
    assert_eq!(
        unset("GpuPreference=2;", HP, Some("GpuPreference=7;")),
        Unset::Foreign
    );
}

/// Property: for every grammatical old value whose pair is missing or `0`,
/// `unset(set(old)) == old`, over a small generated corpus.
#[test]
fn unset_of_set_is_the_old_value() {
    let others = [
        "",
        "AutoHDREnable=1;",
        "SwapEffectUpgradeEnable=0;",
        "AutoHDREnable=0;SwapEffectUpgradeEnable=1;",
        "X_1=a.b-c;",
    ];
    let mut n = 0;
    for a in others {
        for b in others {
            for pair in ["", "GpuPreference=0;"] {
                let old = format!("{a}{pair}{b}");
                if parse(&old).is_err() {
                    continue; // empty, or a name twice
                }
                let new = set(Some(&old), HP).unwrap();
                assert_eq!(current(&parse(&new).unwrap()), Current::Digit(2));
                assert_eq!(unset(&new, HP, Some(&old)), Unset::Rest(Some(old.clone())));
                n += 1;
            }
        }
    }
    assert!(n > 20, "{n}");
}

#[test]
fn the_preference_on_the_wire() {
    assert_eq!(serde_json::to_string(&HP).unwrap(), r#""high_performance""#);
    assert!(serde_json::from_str::<GpuPref>(r#""power_saving""#).is_err());
    assert_eq!(HP.digit(), 2);
}
