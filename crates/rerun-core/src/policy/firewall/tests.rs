use std::time::{Duration, Instant};

use super::*;
use crate::sys::System;
use crate::sys::fake::FakeSystem;
use crate::sys::firewall::{ACTION_ALLOW, DIR_IN};

fn id(s: &str) -> Id {
    Id::parse(s).unwrap()
}

fn txn() -> TxnId {
    "00000042-00ff00ff00ff00ff".parse().unwrap()
}

fn program() -> Program {
    let root = RootPath::new(r"D:\SteamLibrary\steamapps\common\Assassin's Creed").unwrap();
    Program::new(&root, &RelPath::parse("AssassinsCreed_Dx9.exe").unwrap()).unwrap()
}

fn ours(op: u16) -> FwRule {
    rule(
        &id("assassins-creed-dc"),
        &txn(),
        op,
        &program(),
        Direction::Out,
    )
}

#[test]
fn the_rule_has_rerun_s_form() {
    let r = ours(7);
    assert_eq!(
        r.name,
        "Rerun - assassins-creed-dc - 00000042-00ff00ff00ff00ff-007"
    );
    assert_eq!(
        r.description,
        "Added by Rerun for assassins-creed-dc; removed by rerun revert 00000042-00ff00ff00ff00ff"
    );
    assert_eq!(r.grouping, "Rerun");
    assert_eq!(
        r.program,
        r"D:\SteamLibrary\steamapps\common\Assassin's Creed\AssassinsCreed_Dx9.exe"
    );
    assert_eq!(
        (r.direction, r.action, r.profiles, r.protocol, r.enabled),
        (DIR_OUT, ACTION_BLOCK, PROFILES_ALL, PROTOCOL_ANY, true)
    );
    assert_eq!(r.rest, rest());
    assert!(r.name.is_ascii());
}

#[test]
fn rule_names_have_one_written_form() {
    let n = RuleName::derive(&id("lego-city-undercover"), &txn(), 3);
    let back = RuleName::parse(n.as_str()).unwrap();
    assert_eq!(back, n);
    assert_eq!(
        (back.topo().as_str(), back.txn(), back.op()),
        ("lego-city-undercover", txn(), 3)
    );
    let big = RuleName::derive(&id("a"), &txn(), u16::MAX);
    assert_eq!(RuleName::parse(big.as_str()), Some(big));
    for bad in [
        "Rerun - a - 00000042-00ff00ff00ff00ff-7",
        "Rerun - a - 00000042-00ff00ff00ff00ff-0007",
        "rerun - a - 00000042-00ff00ff00ff00ff-007",
        "Rerun - A - 00000042-00ff00ff00ff00ff-007",
        "Rerun - a - 00000042-00FF00FF00FF00FF-007",
        "Rerun - a - 0000042-00ff00ff00ff00ff-007",
        "Rerun - a - 00000042-00ff00ff00ff00ff-+07",
        "Rerun - a - 00000042-00ff00ff00ff00ff-65536",
        "Rerun - a -  00000042-00ff00ff00ff00ff-007",
        "Rerun - a - 00000042-00ff00ff00ff00ff-007 ",
        "Rerun - a - b - 00000042-00ff00ff00ff00ff-007",
        "Core Networking - DHCP",
        "",
    ] {
        assert_eq!(RuleName::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn programs_are_drive_paths_without_percent() {
    assert_eq!(
        Program::parse(r"C:\Games\X\game.EXE").unwrap().as_str(),
        r"C:\Games\X\game.EXE"
    );
    assert!(matches!(
        Program::parse(r"%SystemRoot%\System32\svchost.exe"),
        Err(ProgramError::Percent(_))
    ));
    assert!(matches!(
        Program::parse(r"C:\Games\100%\game.exe"),
        Err(ProgramError::Percent(_))
    ));
    for bad in [
        r"c:\Games\game.exe",
        r"C:/Games/game.exe",
        r"C:\Games\\game.exe",
        r"C:\Games\..\game.exe",
        r"\\server\share\game.exe",
        r"\\?\C:\Games\game.exe",
        r"C:\",
        r"C:game.exe",
        "C:\\Games\\\u{FFFD}.exe",
    ] {
        assert!(
            matches!(Program::parse(bad), Err(ProgramError::Form(_))),
            "{bad:?}"
        );
    }
    assert!(matches!(
        Program::parse(r"C:\Games\game.dll"),
        Err(ProgramError::NotExe(_))
    ));
    let max = format!(r"C:\{}.exe", "a".repeat(MAX_PROGRAM_CHARS - 7));
    assert_eq!(max.chars().count(), MAX_PROGRAM_CHARS);
    assert!(Program::parse(&max).is_ok());
    let long = format!(r"C:\{}.exe", "a".repeat(MAX_PROGRAM_CHARS - 6));
    assert!(matches!(
        Program::parse(&long),
        Err(ProgramError::TooLong(_))
    ));
    // From the plan's spelling, folded comparison (A4 S6 a).
    let p = program();
    assert!(p.names(&p.as_str().to_uppercase()));
    assert!(!p.names(r"D:\Other\AssassinsCreed_Dx9.exe"));
    // ASCII case only: U+0131 folds to `I` in Unicode, NTFS keeps the names apart.
    let dotless = Program::parse("C:\\Games\\gam\u{131}.exe").unwrap();
    assert!(!dotless.names(r"C:\Games\GAMI.EXE"));
    assert!(dotless.names("C:\\GAMES\\gam\u{131}.EXE"));
}

fn fw_with(rules: Vec<FwRule>) -> FakeSystem {
    let sys = FakeSystem::new();
    sys.fake_firewall().set_rules(rules);
    sys
}

fn foreign(name: &str) -> FwRule {
    FwRule {
        name: name.to_owned(),
        grouping: "@FirewallAPI.dll,-25000".to_owned(),
        direction: DIR_IN,
        action: ACTION_ALLOW,
        protocol: 17,
        enabled: true,
        ..FwRule::default()
    }
}

#[test]
fn observe_classifies_before_after_foreign() {
    let e = ours(1);
    let other = foreign("Core Networking - DHCP");
    // Before: no rule of that name.
    let sys = fw_with(vec![other.clone()]);
    assert_eq!(observe(sys.firewall(), &e).unwrap(), Observed::Before);
    // After: exactly one, every fact; the program only differs in case (S6 a).
    let mut cased = e.clone();
    cased.program = cased.program.to_lowercase();
    let sys = fw_with(vec![other.clone(), cased]);
    assert_eq!(observe(sys.firewall(), &e).unwrap(), Observed::After);
    // Foreign: each changed fact, a second rule, a name in another case.
    type Change = fn(&mut FwRule);
    let changes: [(&str, Change); 14] = [
        ("disabled", |r| r.enabled = false),
        ("another group", |r| r.grouping = "rerun".to_owned()),
        ("description", |r| r.description.push('!')),
        ("program", |r| {
            r.program = r"D:\Other\AssassinsCreed_Dx9.exe".to_owned()
        }),
        ("direction", |r| r.direction = DIR_IN),
        ("action", |r| r.action = ACTION_ALLOW),
        ("profiles", |r| r.profiles = 4),
        ("protocol", |r| r.protocol = 6),
        ("remote ports", |r| r.rest.remote_ports = "80".to_owned()),
        ("remote addresses", |r| {
            r.rest.remote_addresses = "LocalSubnet".to_owned();
        }),
        ("edge options", |r| r.rest.edge_options = Some(1)),
        ("no INetFwRule3", |r| r.rest.v3 = None),
        ("a package (S6 d)", |r| {
            if let Some(v3) = &mut r.rest.v3 {
                v3.package_id = "S-1-15-2-1".to_owned();
            }
        }),
        ("name case", |r| r.name = r.name.to_lowercase()),
    ];
    for (what, change) in changes {
        let mut r = e.clone();
        change(&mut r);
        let sys = fw_with(vec![r]);
        assert_eq!(
            observe(sys.firewall(), &e).unwrap(),
            Observed::Foreign,
            "{what}"
        );
    }
    let sys = fw_with(vec![e.clone(), e.clone()]);
    assert_eq!(
        observe(sys.firewall(), &e).unwrap(),
        Observed::Foreign,
        "two"
    );
    let mut folded_twin = e.clone();
    folded_twin.name = folded_twin.name.to_uppercase();
    let sys = fw_with(vec![e.clone(), folded_twin]);
    assert_eq!(
        observe(sys.firewall(), &e).unwrap(),
        Observed::Foreign,
        "a twin in another case counts as the same name"
    );
}

#[test]
fn observe_all_enumerates_once_and_errors_pass_through() {
    let batch: Vec<FwRule> = (0..8).map(ours).collect();
    let sys = fw_with(vec![batch[0].clone(), batch[3].clone(), batch[3].clone()]);
    let got = observe_all(sys.firewall(), &batch).unwrap();
    assert_eq!(got[0], Observed::After);
    assert_eq!(got[3], Observed::Foreign);
    assert!(
        got.iter()
            .enumerate()
            .all(|(i, o)| i == 0 || i == 3 || *o == Observed::Before)
    );
    assert_eq!(sys.fake_firewall().selects(), 1);
    assert_eq!(observe_all(sys.firewall(), &[]).unwrap(), Vec::new());
    assert_eq!(
        sys.fake_firewall().selects(),
        1,
        "no enumeration for nothing"
    );
    sys.fake_firewall()
        .fail_with(Some(crate::sys::SysErrorKind::AccessDenied));
    assert!(observe(sys.firewall(), &batch[0]).is_err());
}

/// A4 S11: one observation of a batch of 8 against 1,000 and 10,000 rules, with the policy's
/// own cost (folding every name) in a single enumeration. The fake has no COM cost; the real
/// per-rule cost is measured in `sys::win::tests::firewall` (ADR 0023 §6).
#[test]
fn observe_all_cost_with_1k_and_10k_rules() {
    let batch: Vec<FwRule> = (0..8).map(ours).collect();
    for n in [1_000usize, 10_000] {
        let mut rules: Vec<FwRule> = (0..n)
            .map(|i| foreign(&format!("Some Application {i} (TCP-In)")))
            .collect();
        rules.push(batch[2].clone());
        let sys = fw_with(rules);
        let t = Instant::now();
        let got = observe_all(sys.firewall(), &batch).unwrap();
        let took = t.elapsed();
        eprintln!("MEASURED S11 fake: {n} rules, a batch of 8 observed in {took:?}");
        assert_eq!(got[2], Observed::After);
        assert_eq!(sys.fake_firewall().selects(), 1);
        assert!(took < Duration::from_secs(5), "{n} rules took {took:?}");
    }
}

#[test]
fn orphans_are_rerun_rules_no_open_transaction_names() {
    let a = ours(0);
    let b = ours(1);
    let mut look_alike = foreign("Rerun - x - 00000001-0000000000000001-000");
    look_alike.grouping = String::new();
    let mut grouped = foreign("an administrator's rule");
    grouped.grouping = "RERUN".to_owned();
    let sys = fw_with(vec![
        a.clone(),
        foreign("Core Networking - DHCP"),
        b.clone(),
        look_alike.clone(),
        grouped.clone(),
    ]);
    let rerun = rerun_rules(sys.firewall()).unwrap();
    assert_eq!(
        rerun,
        vec![a.clone(), b.clone(), look_alike.clone(), grouped.clone()]
    );
    let owned = [RuleName::parse(&a.name).unwrap()];
    let left: Vec<&str> = orphans(&rerun, &owned)
        .into_iter()
        .map(|r| r.name.as_str())
        .collect();
    assert_eq!(left, [&b.name[..], &look_alike.name, &grouped.name]);
}

/// The helper's view of `sys` (an elevated fake token).
fn helper(sys: &FakeSystem) -> crate::sys::fake::FakeHelperSystem<'_> {
    crate::sys::fake::FakeHelperSystem::new(sys, crate::sys::fake::FakeHelperToken::new(true))
}

/// Security L3 of the P4-2d review (ADR 0023 §15): a firewall that stores a fact of an added rule
/// other than it was set (here the program in lower case beyond the drive, then a changed
/// description) makes the add's read-back fail; the undo still takes the helper's own adds back
/// (exactly one rule of the name, in group `Rerun`), so the batch ends `RolledBack` with every
/// rule gone, never `LeftOpen` with a `Foreign` rule under a rolled-back transaction.
#[test]
fn an_add_the_firewall_normalises_is_rolled_back_not_left_foreign() {
    let rules = [ours(1), ours(2)];
    for f in [
        (|r: &mut FwRule| r.description.push('.')) as fn(&mut FwRule),
        |r: &mut FwRule| r.profiles = 7,
        |r: &mut FwRule| r.program = format!("%SystemDrive%{}", &r.program[2..]),
    ] {
        let sys = fw_with(vec![foreign("Core Networking - DHCP")]);
        sys.fake_firewall().normalise_adds(Some(f));
        assert_eq!(add_all(&helper(&sys), &rules), Written::RolledBack);
        assert_eq!(
            sys.fake_firewall().rules(),
            vec![foreign("Core Networking - DHCP")]
        );
    }
    // A rule of the name in another group is not the helper's add: never removed (the race of
    // §6 with an administrator's rule of another group).
    let sys = fw_with(Vec::new());
    sys.fake_firewall()
        .normalise_adds(Some(|r: &mut FwRule| r.grouping = "Other".to_owned()));
    let w = add_all(&helper(&sys), &rules[..1]);
    assert_eq!(w, Written::LeftOpen(vec![Some(Observed::Foreign)]));
    assert_eq!(sys.fake_firewall().rules().len(), 1);
}

/// The undo removes a name only while exactly one rule holds it, with exactly that name, in
/// group `Rerun`: a second rule of the name (an administrator's, added between the count and the
/// undo, §6) or a case twin is never taken for the helper's own add.
#[test]
fn the_undo_takes_only_the_one_rule_of_the_exact_name() {
    let r = ours(1);
    assert!(own_add(&r, std::slice::from_ref(&r)));
    assert!(!own_add(&r, &[r.clone(), r.clone()]));
    assert!(!own_add(&r, &[]));
    let mut twin = r.clone();
    twin.name = twin.name.to_ascii_lowercase();
    assert!(!own_add(&r, &[twin]), "a case twin is not the exact name");
    let other_group = FwRule {
        grouping: "Other".to_owned(),
        ..r.clone()
    };
    assert!(!own_add(&r, &[other_group]));
    // Facts beyond name and group are not compared (L3).
    let changed = FwRule {
        description: "changed".to_owned(),
        profiles: 1,
        ..r.clone()
    };
    assert!(own_add(&r, &[changed]));
}

/// The firewall's own limit (P4-5b, measured: `Add` keeps 259 UTF-16 units, refuses 260): a
/// program within Rerun's 243 characters can still pass 259 units with characters outside the
/// BMP (two units each), and is refused with the length named.
#[test]
fn a_program_of_260_utf16_units_is_refused() {
    let astral = "\u{1D400}".repeat(20); // 20 characters, 40 units
    let path = |filler: usize| format!(r"C:\{astral}{}.exe", "a".repeat(filler));
    let ok = path(212);
    assert_eq!(ok.encode_utf16().count(), 259);
    assert!(ok.chars().count() <= MAX_PROGRAM_CHARS);
    Program::parse(&ok).unwrap();
    let long = path(213);
    assert_eq!(long.encode_utf16().count(), 260);
    assert!(long.chars().count() <= MAX_PROGRAM_CHARS);
    match Program::parse(&long) {
        Err(e @ ProgramError::FirewallLimit(_, 260)) => {
            assert!(e.to_string().contains("260 UTF-16 units"), "{e}");
        }
        other => panic!("{other:?}"),
    }
    // Plain ASCII never reaches the limit: Rerun's own bound comes first.
    const { assert!(MAX_PROGRAM_CHARS < MAX_PROGRAM_UTF16) };
}
