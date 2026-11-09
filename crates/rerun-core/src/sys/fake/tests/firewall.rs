//! The fake firewall (P4-5a): the read contract, and that the contract bites.

use super::super::{FakeFirewall, FakeSystem};
use crate::sys::contract::firewall_read_contract;
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
