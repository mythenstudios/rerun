//! Read contract of the firewall (ADR 0023 §8 outcome A, §14; P4-5a), against the fake and the
//! real Windows Firewall (read only: it never adds, changes or removes a rule); and the write
//! contract (P4-5b, [`firewall_write_contract`]), against the fake and, in the [SB] only, the
//! real firewall.
//!
//! - **F1** one call is one enumeration: `keep` sees every rule once, `total` counts them, and
//!   only the rules `keep` chose come back, in enumeration order.
//! - **F2** `keep` sees exactly the name and grouping the full facts carry.
//! - **F3** a selection by name or by grouping returns exactly the rules of that name or
//!   grouping of a full read, with the same facts (reads are repeatable).
//! - **F4** the facts are plausible: direction in or out, action block or allow, protocol 0 to
//!   256, no NUL in a text.
//!
//! The real collection may change between two calls (an installer adds a rule); the contract
//! assumes it does not during the few milliseconds of a run.

use std::cell::RefCell;

use super::{ContractResult, ensure, ok};
use crate::sys::firewall::{ACTION_ALLOW, ACTION_BLOCK, DIR_IN, DIR_OUT, FwRule, PROTOCOL_ANY};
use crate::sys::{Firewall, FirewallWrite};

fn texts(r: &FwRule) -> Vec<&str> {
    let mut t = vec![
        &r.name[..],
        &r.description,
        &r.grouping,
        &r.program,
        &r.rest.service,
        &r.rest.local_ports,
        &r.rest.remote_ports,
        &r.rest.local_addresses,
        &r.rest.remote_addresses,
        &r.rest.icmp_types,
        &r.rest.interface_types,
    ];
    if let Some(v3) = &r.rest.v3 {
        t.extend([
            &v3.package_id[..],
            &v3.user_owner,
            &v3.local_users,
            &v3.remote_users,
            &v3.remote_machines,
        ]);
    }
    t
}

/// Runs F1 to F4 (module docs). The firewall must hold at least one rule.
pub fn firewall_read_contract(fw: &dyn Firewall) -> ContractResult {
    // F1, F2.
    let seen = RefCell::new(Vec::new());
    let none = ok(
        fw.select(&|n, g| {
            seen.borrow_mut().push((n.to_owned(), g.to_owned()));
            false
        }),
        "select none",
    )?;
    let seen = seen.into_inner();
    ensure(none.rules.is_empty(), "keep = false returns no rule")?;
    ensure(none.total == seen.len(), "keep sees every rule once")?;
    ensure(none.total > 0, "the firewall holds at least one rule")?;
    let all = ok(fw.select(&|_, _| true), "select all")?;
    ensure(all.total == none.total, "two enumerations count alike")?;
    ensure(
        all.rules.len() == all.total,
        "keep = true returns every rule",
    )?;
    let pairs: Vec<(String, String)> = all
        .rules
        .iter()
        .map(|r| (r.name.clone(), r.grouping.clone()))
        .collect();
    ensure(
        pairs == seen,
        "keep sees the name and grouping of the full facts, in enumeration order",
    )?;
    // F3.
    let probe = &all.rules[all.rules.len() / 2];
    let by_name = ok(fw.select(&|n, _| n == probe.name), "select by name")?;
    let want: Vec<&FwRule> = all.rules.iter().filter(|r| r.name == probe.name).collect();
    ensure(
        by_name.rules.iter().collect::<Vec<_>>() == want,
        "a selection by name returns those rules with the same facts",
    )?;
    let by_group = ok(fw.select(&|_, g| g == probe.grouping), "select by grouping")?;
    let want: Vec<&FwRule> = all
        .rules
        .iter()
        .filter(|r| r.grouping == probe.grouping)
        .collect();
    ensure(
        by_group.rules.iter().collect::<Vec<_>>() == want,
        "a selection by grouping returns those rules with the same facts",
    )?;
    // F4.
    for r in &all.rules {
        ensure(
            [DIR_IN, DIR_OUT].contains(&r.direction),
            "direction is in or out",
        )?;
        ensure(
            [ACTION_BLOCK, ACTION_ALLOW].contains(&r.action),
            "action is block or allow",
        )?;
        ensure(
            (0..=PROTOCOL_ANY).contains(&r.protocol),
            "protocol is 0 to 256",
        )?;
        ensure(
            texts(r).iter().all(|t| !t.contains('\0')),
            "no NUL in a text",
        )?;
    }
    Ok(())
}

/// What the write contract saw of `INetFwRules::Remove` (measured on Windows by the [SB] write
/// contract; fixed in the fake).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoveFacts {
    /// `Remove(name)` with two rules of that name took both (B12 c, R10: the design assumes it
    /// does and counts first).
    pub takes_every_rule_of_the_name: bool,
    /// `Remove(name)` took a rule whose name differs from `name` in ASCII case only (A4 S6 c).
    pub ignores_case: bool,
    /// `Remove(name)` of a name no rule holds returned success.
    pub missing_name_is_ok: bool,
}

/// The write contract of the firewall (ADR 0023 §6, §14; P4-5b), against the fake and, in the
/// [SB] only, the real Windows Firewall (it adds and removes real rules).
///
/// - **W1** an added rule reads back with exactly the facts it was added with (one rule of its
///   name; every fact Rerun compares, A4 S6 d).
/// - **W2** two adds of one name are two rules (the firewall does not refuse a duplicate);
///   `Remove(name)` leaves no rule of that exact name ([`RemoveFacts`] says whether one call
///   took both, R10).
/// - **W3** `Remove` with the name in another ASCII case: measured ([`RemoveFacts`]); the rule
///   is removed by its exact name afterwards if it is still there.
/// - **W4** `Remove` of a name no rule holds: measured.
///
/// `a` and `b` are two rules of different names that no rule of the firewall holds (folded);
/// `b`'s name has an upper-case ASCII letter. Every rule the contract adds is removed again,
/// also when a case fails (by exact name).
///
/// # Errors
/// The first broken rule.
pub fn firewall_write_contract(
    fw: &dyn Firewall,
    w: &dyn FirewallWrite,
    a: &FwRule,
    b: &FwRule,
) -> Result<RemoveFacts, String> {
    let lower = b.name.to_ascii_lowercase();
    if lower == b.name || a.name.eq_ignore_ascii_case(&b.name) {
        return Err("setup: b's name needs an upper-case letter, a and b other names".into());
    }
    let r = write_cases(fw, w, a, b, &lower);
    // Clean up whatever the cases left, by exact name (twice: a duplicate may be left).
    for name in [&a.name, &a.name, &b.name] {
        #[expect(
            clippy::disallowed_methods,
            reason = "write contract: removes the rules the contract itself added"
        )]
        let _ = w.remove_named(name);
    }
    let left = ok(
        fw.select(&|n, _| n.eq_ignore_ascii_case(&a.name) || n.eq_ignore_ascii_case(&b.name)),
        "select after the clean-up",
    )?;
    ensure(left.rules.is_empty(), "the contract leaves no rule behind")?;
    r
}

/// The rules of exactly `name`.
fn named(fw: &dyn Firewall, name: &str) -> Result<Vec<FwRule>, String> {
    Ok(ok(fw.select(&|n, _| n == name), "select by name")?.rules)
}

fn write_cases(
    fw: &dyn Firewall,
    w: &dyn FirewallWrite,
    a: &FwRule,
    b: &FwRule,
    lower: &str,
) -> Result<RemoveFacts, String> {
    #[expect(
        clippy::disallowed_methods,
        reason = "write contract: the add under test"
    )]
    let add = |r: &FwRule| w.add(r);
    #[expect(
        clippy::disallowed_methods,
        reason = "write contract: the remove under test"
    )]
    let remove = |n: &str| w.remove_named(n);
    for r in [a, b] {
        ensure(named(fw, &r.name)?.is_empty(), "setup: the names are free")?;
    }
    // W1.
    ok(add(a), "add a")?;
    let got = named(fw, &a.name)?;
    if got.as_slice() != std::slice::from_ref(a) {
        return Err(format!(
            "W1: an added rule reads back with the facts it was added with:\n  set  {a:?}\n  read {got:?}"
        ));
    }
    // W2.
    ok(add(a), "add a again")?;
    ensure(
        named(fw, &a.name)?.len() == 2,
        "W2: a second add of one name is a second rule",
    )?;
    ok(remove(&a.name), "remove a")?;
    let left = named(fw, &a.name)?.len();
    let takes_every_rule_of_the_name = left == 0;
    if left == 1 {
        ok(remove(&a.name), "remove a, the second rule")?;
    }
    ensure(
        named(fw, &a.name)?.is_empty(),
        "W2: Remove leaves no rule of the exact name",
    )?;
    // W3.
    ok(add(b), "add b")?;
    ok(remove(lower), "remove b by its name in lower case")?;
    let ignores_case = named(fw, &b.name)?.is_empty();
    if !ignores_case {
        ok(remove(&b.name), "remove b by its exact name")?;
    }
    ensure(named(fw, &b.name)?.is_empty(), "W3: b removed")?;
    // W4.
    let missing_name_is_ok = remove(&b.name).is_ok();
    Ok(RemoveFacts {
        takes_every_rule_of_the_name,
        ignores_case,
        missing_name_is_ok,
    })
}
