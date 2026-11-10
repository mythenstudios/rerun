//! The fake firewall (P4-5a, P4-5b): the read and write contracts, that they bite, and the
//! durability models.

use super::super::{FakeFirewall, FakeSystem};
use crate::sys::contract::{WriteFacts, firewall_read_contract, firewall_write_contract};
use crate::sys::firewall::{ACTION_BLOCK, DIR_OUT, FwSelection, PROFILES_ALL, PROTOCOL_ANY};
use crate::sys::{Firewall, FwRule, SysErrorKind, SysResult, System};

fn rule(name: &str, group: &str) -> FwRule {
    FwRule {
        name: name.to_owned(),
        grouping: group.to_owned(),
        direction: DIR_OUT,
        action: ACTION_BLOCK,
        profiles: PROFILES_ALL,
        protocol: PROTOCOL_ANY,
        enabled: true,
        ..FwRule::default()
    }
}

#[test]
fn fake_fulfils_firewall_read_contract() {
    let sys = FakeSystem::builder()
        .fw_rule(rule("Core Networking - DHCP", "@FirewallAPI.dll,-25000"))
        .fw_rule(rule("Rerun - x - 1", "Rerun"))
        .fw_rule(rule("Rerun - x - 1", "Rerun"))
        .fw_rule(rule("other", ""))
        .build()
        .unwrap();
    firewall_read_contract(sys.firewall()).unwrap();
    assert_eq!(
        sys.fake_firewall().selects(),
        4,
        "one count per enumeration"
    );
    let two = sys.firewall().select(&|n, _| n == "Rerun - x - 1").unwrap();
    assert_eq!((two.total, two.rules.len()), (4, 2), "duplicates of a name");
}

#[test]
fn the_fake_fails_on_request_and_changes_through_shared_access() {
    let fw = FakeFirewall::default();
    fw.push(rule("a", "g"));
    fw.fail_with(Some(SysErrorKind::AccessDenied));
    let e = fw.select(&|_, _| true).unwrap_err();
    assert_eq!(e.kind, SysErrorKind::AccessDenied);
    fw.fail_with(None);
    fw.edit(|r| r.name == "a", |r| r.enabled = false);
    assert!(!fw.select(&|_, _| true).unwrap().rules[0].enabled);
    fw.set_rules(Vec::new());
    assert_eq!(fw.rules(), Vec::new());
}

/// A firewall that breaks one rule of the contract.
struct Broken(u8, Vec<FwRule>);

impl Firewall for Broken {
    fn select(&self, keep: &dyn Fn(&str, &str) -> bool) -> SysResult<FwSelection> {
        let mut out = FwSelection {
            total: self.1.len(),
            rules: Vec::new(),
        };
        for r in &self.1 {
            let show = if self.0 == 1 { "renamed" } else { &r.name[..] };
            if keep(show, &r.grouping) || self.0 == 2 {
                out.rules.push(r.clone());
            }
        }
        if self.0 == 3 {
            out.total += 1;
        }
        if self.0 == 4 {
            out.rules.iter_mut().for_each(|r| r.direction = 7);
        }
        Ok(out)
    }
}

#[test]
fn the_firewall_contract_catches_a_broken_read() {
    let rules = vec![rule("a", "g"), rule("b", "h")];
    for (case, what) in [
        (1, "keep sees another name"),
        (2, "ignores keep"),
        (3, "total off by one"),
        (4, "an impossible direction"),
    ] {
        assert!(
            firewall_read_contract(&Broken(case, rules.clone())).is_err(),
            "{what}"
        );
    }
    assert!(firewall_read_contract(&Broken(0, rules)).is_ok());
    assert!(
        firewall_read_contract(&Broken(0, Vec::new())).is_err(),
        "no rule at all"
    );
}

#[test]
fn the_fake_bounds_texts_like_windows() {
    use crate::sys::firewall::MAX_TEXT_UTF16;
    let long = "x".repeat(MAX_TEXT_UTF16 + 1);
    let fw = FakeFirewall::default();
    let mut r = rule("a", "g");
    r.description = long.clone();
    fw.push(r);
    assert!(
        fw.select(&|_, _| false).is_ok(),
        "only kept rules are read fully"
    );
    let e = fw.select(&|_, _| true).unwrap_err();
    assert_eq!(e.kind, SysErrorKind::TooLarge);
    fw.set_rules(vec![rule(&long, "g")]);
    let e = fw.select(&|_, _| false).unwrap_err();
    assert_eq!(
        e.kind,
        SysErrorKind::TooLarge,
        "a name is read for every rule"
    );
}

/// The write contract against the fake (P4-5b): its `Remove` takes every rule of the name,
/// folded (also a Unicode case twin: `fold` upper-cases U+0131 to `I`), and a missing name is
/// no error (the worst case the design assumes, ADR 0023 §6; Windows' answer is the [SB]
/// measurement).
#[test]
fn fake_fulfils_firewall_write_contract() {
    let sys = FakeSystem::builder()
        .fw_rule(rule("Core Networking - DHCP", "@FirewallAPI.dll,-25000"))
        .build()
        .unwrap();
    let fw = sys.fake_firewall();
    let a = rule(
        "Rerun - contract-i - 00000001-0000000000000001-001",
        "Rerun",
    );
    let b = rule(
        "Rerun - contract-B - 00000001-0000000000000001-002",
        "Rerun",
    );
    let facts = firewall_write_contract(fw, fw, &a, &b).unwrap();
    assert_eq!(
        facts,
        WriteFacts {
            program_case_drift: false,
            takes_every_rule_of_the_name: true,
            case_remove_ok: true,
            ignores_case: true,
            unicode_twin_removes: true,
            missing_name_is_ok: true,
        }
    );
    assert_eq!(
        fw.rules(),
        vec![rule("Core Networking - DHCP", "@FirewallAPI.dll,-25000")]
    );
}

/// The write contract bites: a firewall that stores another fact than it was given fails W1,
/// and the contract still removes what it added; a program read back in another ASCII case only
/// is reported, not failed (it is how `policy::firewall` compares, review S2 of P4-5b); a setup
/// whose names are taken folded is refused.
#[test]
fn the_write_contract_catches_a_normalising_add() {
    let mut a = rule("Rerun - c-i - 00000001-0000000000000001-001", "Rerun");
    a.program = r"C:\Games\game.exe".to_owned();
    let b = rule("Rerun - C2 - 00000001-0000000000000001-002", "Rerun");
    let fw = FakeFirewall::default();
    fw.normalise_adds(Some(|r: &mut FwRule| r.description.push('.')));
    let e = firewall_write_contract(&fw, &fw, &a, &b).unwrap_err();
    assert!(e.starts_with("W1"), "{e}");
    assert!(
        fw.rules().is_empty(),
        "the contract cleans up after a failure"
    );
    let fw = FakeFirewall::default();
    fw.normalise_adds(Some(|r: &mut FwRule| r.program.make_ascii_uppercase()));
    let facts = firewall_write_contract(&fw, &fw, &a, &b).unwrap();
    assert!(facts.program_case_drift);
    assert!(fw.rules().is_empty());
    let fw = FakeFirewall::default();
    fw.push(rule(&a.name.to_ascii_uppercase(), "Other"));
    let e = firewall_write_contract(&fw, &fw, &a, &b).unwrap_err();
    assert!(e.contains("setup"), "{e}");
    assert_eq!(fw.rules().len(), 1, "a refused setup touches no rule");
}

/// The durability models (ADR 0023 §6, P4-5b): durable on return by default; lazy: the helper's
/// writes since the last flush are lost by a power loss, a test's own changes never.
#[test]
fn the_fake_firewall_models_durable_and_lazy_writes() {
    use crate::sys::FirewallWrite;
    let sys = FakeSystem::builder()
        .fw_rule(rule("fixture", ""))
        .build()
        .unwrap();
    let fw = sys.fake_firewall();
    let a = rule("Rerun - a - 1", "Rerun");
    let b = rule("Rerun - b - 1", "Rerun");
    let cut = || sys.power_loss(&std::collections::BTreeMap::new());
    #[expect(
        clippy::disallowed_methods,
        reason = "test: the fake's write side itself"
    )]
    let add = |r: &FwRule| fw.add(r).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test: the fake's write side itself"
    )]
    let remove = |n: &str| fw.remove_named(n).unwrap();
    add(&a);
    cut();
    assert_eq!(
        fw.rules(),
        vec![rule("fixture", ""), a.clone()],
        "durable on return"
    );
    fw.set_lazy(true);
    add(&b);
    remove(&a.name);
    fw.push(rule("admin", ""));
    cut();
    assert_eq!(
        fw.rules(),
        vec![rule("fixture", ""), a.clone(), rule("admin", "")],
        "lazy: the add is lost, the removed rule is back, the test's own push stays"
    );
    add(&b);
    fw.lazy_flush();
    remove(&b.name);
    cut();
    assert!(fw.rules().contains(&b), "flushed, then a lost remove");
}
