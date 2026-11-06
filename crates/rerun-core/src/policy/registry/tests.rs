//! RP: the rules of `policy::registry` against the fake (ADR 0018, amendment P2-9).

use std::cell::Cell;
use std::thread::LocalKey;

use super::*;
use crate::sys::fake::FakeSystem;
use crate::sys::registry::{RegistryWrite, reg_type};

fn seg(s: &str) -> AsciiSeg {
    AsciiSeg::parse(s).unwrap()
}

fn game(vendor: &str, product: &str) -> Result<GameKey, RegPolicyError> {
    GameKey::new(AsciiSeg::parse(vendor)?, AsciiSeg::parse(product)?, vec![])
}

fn value(name: &str) -> AllowedValue {
    RegPolicy
        .check(
            &RegSlot::GameValue {
                key: game("Ubisoft", "AC").unwrap(),
                name: AsciiName::parse(name).unwrap(),
            },
            &[],
        )
        .unwrap()
}

fn hkcu(p: &str) -> RegKey {
    RegKey::new(Hive::CurrentUser, RegView::Native, p)
}

fn is_denied<T: fmt::Debug>(r: Result<T, RegPolicyError>) -> bool {
    matches!(r, Err(RegPolicyError::Denied { .. }))
}

/// The rule table (RP); a function so the controls K-R6 run the same checks.
fn rp_table() -> Result<(), String> {
    let fail = |what: &str| Err(format!("RP: {what}"));
    // The vendor deny list, folded; G1 adds Khronos.
    for v in [
        "Microsoft",
        "microsoft",
        "MICROSOFT",
        "Wow6432Node",
        "WOW6432NODE",
        "Classes",
        "Policies",
        "Clients",
        "RegisteredApplications",
        "AppDataLow",
        "Valve",
        "VALVE",
        "Rerun",
        "rerun",
        "Mythen Studios",
        "mythen studios",
        "Khronos",
        "KHRONOS",
    ] {
        if !is_denied(game(v, "Product")) {
            return fail(&format!("vendor {v} is denied"));
        }
    }
    if game("Ubisoft", "Assassin's Creed").is_err() {
        return fail("a plain vendor is allowed");
    }
    // Segment rules.
    if AsciiSeg::parse(&"a".repeat(64)).is_err() {
        return fail("64 characters are allowed");
    }
    for bad in [
        String::new(),
        "a".repeat(65),
        r"a\b".into(),
        " a".into(),
        "a ".into(),
        "ä".into(),
        "a\u{7}".into(),
        "a\tb".into(),
    ] {
        if AsciiSeg::parse(&bad).is_ok() {
            return fail(&format!("segment {bad:?} is refused"));
        }
    }
    let four = vec![seg("a"), seg("b"), seg("c"), seg("d")];
    let mut five = four.clone();
    five.push(seg("e"));
    if GameKey::new(seg("V"), seg("P"), four).is_err()
        || GameKey::new(seg("V"), seg("P"), five).is_ok()
    {
        return fail("at most 4 segments below the product");
    }
    // Value names: 0 to 128, printable ASCII, no `\ / : %` (G1).
    for ok in [String::new(), "a".repeat(128), "Lang".into()] {
        if AsciiName::parse(&ok).is_err() {
            return fail(&format!("name {ok:?} is allowed"));
        }
    }
    for bad in [
        "a".repeat(129),
        r"C:\Games\x\layer.json".into(),
        "a/b".into(),
        "a:b".into(),
        "%TEMP%".into(),
        "ä".into(),
        " a".into(),
    ] {
        if AsciiName::parse(&bad).is_ok() {
            return fail(&format!("name {bad:?} is refused"));
        }
    }
    // Types and limits of new values; REG_BINARY is not written (user decision).
    let v = value("Lang");
    let p = RegPolicy;
    for ok in [
        RegValue::Dword(1),
        RegValue::Qword(u64::MAX),
        RegValue::String("x".repeat(1_024)),
        RegValue::String(String::new()),
        RegValue::String("de-CH, mode 2 (fast)".into()),
    ] {
        if p.check_new(&v, &ok).is_err() {
            return fail(&format!("{ok} is allowed"));
        }
    }
    for bad in [
        RegValue::String("x".repeat(1_025)),
        RegValue::String("a\nb".into()),
        RegValue::String(r"C:\Games\x.dll".into()),
        RegValue::String("%APPDATA%".into()),
        RegValue::String("a/b".into()),
        RegValue::String("a:b".into()),
        // Best-fit characters an ANSI reader turns into `\ : % /`, bidi, format, non-ASCII.
        RegValue::String("C\u{FF1A}\u{FF3C}x".into()),
        RegValue::String("a\u{FF3C}b".into()),
        RegValue::String("\u{FF05}TEMP\u{FF05}".into()),
        RegValue::String("a\u{FF0F}b".into()),
        RegValue::String("a\u{2215}b".into()),
        RegValue::String("a\u{202E}b".into()),
        RegValue::String("a\u{2028}b".into()),
        RegValue::String("caf\u{E9}".into()),
        RegValue::Binary(vec![]),
        RegValue::Binary(vec![1; 16]),
        RegValue::ExpandString("x".into()),
        RegValue::MultiString(vec!["x".into()]),
        RegValue::decode(reg_type::REG_LINK, &[0x61, 0]),
        RegValue::decode(reg_type::REG_NONE, &[1]),
    ] {
        if !is_denied(p.check_new(&v, &bad)) {
            return fail(&format!("{bad} is refused"));
        }
    }
    Ok(())
}

#[test]
fn rp_the_rule_table_holds() {
    rp_table().unwrap();
}

/// K-R6: an unfolded deny list, or the content rule switched off, fails the table.
#[test]
fn rp_catches_an_unfolded_deny_list_or_a_missing_content_rule() {
    let knobs: [(&str, &'static LocalKey<Cell<bool>>, &str); 2] = [
        (
            "unfolded deny list",
            &KNOB_UNFOLDED_DENY,
            "vendor microsoft",
        ),
        ("no content rule", &KNOB_NO_CONTENT_RULE, "is refused"),
    ];
    for (what, knob, at) in knobs {
        knob.with(|k| k.set(true));
        let r = rp_table();
        knob.with(|k| k.set(false));
        let e = r.expect_err(what);
        assert!(e.contains(at), "{what}: {e}");
    }
}

#[test]
fn compat_layers_name_the_executable_in_its_root() {
    let roots = [
        RootPath::new(r"D:\Games\X").unwrap(),
        RootPath::new(r"e:/Lib/steamapps/common/Y").unwrap(),
    ];
    let slot = |root: u16, exe: &str| RegSlot::CompatLayers {
        root: RootIx(root),
        exe: RelPath::parse(exe).unwrap(),
    };
    let v = RegPolicy.check(&slot(0, r"bin\game.exe"), &roots).unwrap();
    assert_eq!(v.name(), r"D:\Games\X\bin\game.exe");
    assert_eq!(v.key().key(), &hkcu(LAYERS));
    let v = RegPolicy.check(&slot(1, "y.exe"), &roots).unwrap();
    assert_eq!(v.name(), r"E:\Lib\steamapps\common\Y\y.exe");
    assert!(!v.name().starts_with(r"\\?\"));
    assert_eq!(
        RegPolicy.check(&slot(2, "y.exe"), &roots),
        Err(RegPolicyError::UnknownRoot(2))
    );
    // New values wait for compat_layer (P2-11).
    assert!(matches!(
        RegPolicy.check_new(&v, &RegValue::String("~ WIN7RTM".into())),
        Err(RegPolicyError::Unsupported(_))
    ));
    // A value name longer than the registry allows is refused.
    assert!(exe_name_fits(&"a".repeat(MAX_VALUE_NAME_UTF16)).is_ok());
    assert!(is_denied(exe_name_fits(
        &"a".repeat(MAX_VALUE_NAME_UTF16 + 1)
    )));
}

#[test]
fn gpu_preference_is_reserved_and_hklm_needs_the_helper() {
    let slot = RegSlot::GpuPreference {
        root: RootIx(0),
        exe: RelPath::parse("g.exe").unwrap(),
    };
    let roots = [RootPath::new(r"D:\G").unwrap()];
    assert!(matches!(
        RegPolicy.check(&slot, &roots),
        Err(RegPolicyError::Reserved(_))
    ));
    assert!(matches!(
        AllowedKey::new(Hive::LocalMachine, r"SOFTWARE\Rerun", 1),
        Err(RegPolicyError::NeedsHelper(_))
    ));
}

/// `missing_keys` lists only the keys below the anchor, top-down; `create_key` and
/// `delete_empty_key` refuse a key at or above the anchor or outside the allowed key.
#[test]
fn the_writer_creates_and_deletes_only_below_the_anchor() {
    let cv = hkcu(r"Software\Microsoft\Windows NT\CurrentVersion");
    let sys = FakeSystem::builder().key(cv.clone()).build().unwrap();
    let w = RegPolicy.writer(&sys);
    let roots = [RootPath::new(r"D:\G").unwrap()];
    let layers = RegPolicy
        .check(
            &RegSlot::CompatLayers {
                root: RootIx(0),
                exe: RelPath::parse("g.exe").unwrap(),
            },
            &roots,
        )
        .unwrap();
    let k = layers.key();
    let missing = w.missing_keys(k).unwrap();
    assert_eq!(
        missing,
        [cv.join("AppCompatFlags"), cv.join(r"AppCompatFlags\Layers")]
    );
    for m in &missing {
        assert!(w.create_key(m, k).unwrap());
    }
    assert!(w.missing_keys(k).unwrap().is_empty());
    for bad in [
        cv.clone(),
        hkcu("Software"),
        hkcu(""),
        hkcu(r"Software\Other\X"),
    ] {
        assert_eq!(
            w.create_key(&bad, k).unwrap_err().kind,
            SysErrorKind::InvalidPath,
            "{bad}"
        );
        assert_eq!(
            w.delete_empty_key(&bad, k).unwrap_err().kind,
            SysErrorKind::InvalidPath,
            "{bad}"
        );
    }
    // A game key may be created from `<Vendor>` down.
    let g = value("Lang");
    assert_eq!(
        w.missing_keys(g.key()).unwrap(),
        [hkcu(r"Software\Ubisoft"), hkcu(r"Software\Ubisoft\AC")]
    );
    w.delete_empty_key(&cv.join(r"AppCompatFlags\Layers"), k)
        .unwrap();
    w.flush().unwrap();
}

/// `set` checks the new value again; `restore` writes back exactly what was there, also a
/// value no `set` may write, and deletes for `None`.
#[test]
fn set_checks_the_new_value_and_restore_does_not() {
    let key = hkcu(r"Software\Ubisoft\AC");
    let raw = RegValue::decode(reg_type::REG_BINARY, &[1, 2, 3]);
    let sys = FakeSystem::builder()
        .value(key.clone(), "Blob", raw.clone())
        .build()
        .unwrap();
    let w = RegPolicy.writer(&sys);
    let blob = value("Blob");
    assert!(matches!(
        w.set(&blob, Some(&raw), &RegValue::Binary(vec![9])),
        Err(RegWriteError::Policy(RegPolicyError::Denied { .. }))
    ));
    w.set(&blob, Some(&raw), &RegValue::Dword(7)).unwrap();
    assert_eq!(w.get(&blob).unwrap(), Some(RegValue::Dword(7)));
    w.restore(&blob, &RegValue::Dword(7), Some(&raw)).unwrap();
    assert_eq!(w.get(&blob).unwrap(), Some(raw.clone()));
    // A restore of a value someone changed meanwhile is refused.
    assert_eq!(
        w.restore(&blob, &RegValue::Dword(7), None)
            .unwrap_err()
            .kind,
        SysErrorKind::Mismatch
    );
    w.restore(&blob, &raw, None).unwrap();
    assert_eq!(w.get(&blob).unwrap(), None);
    assert_eq!(
        sys.fake_registry().key_state(&key).unwrap(),
        KeyState::Present {
            values: 0,
            subkeys: 0
        }
    );
}
