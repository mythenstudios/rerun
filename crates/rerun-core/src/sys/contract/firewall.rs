//! Read contract of the firewall (ADR 0023 §8 outcome A, §14; P4-5a), against the fake and the
//! real Windows Firewall (read only: it never adds, changes or removes a rule).
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
use crate::sys::Firewall;
use crate::sys::firewall::{ACTION_ALLOW, ACTION_BLOCK, DIR_IN, DIR_OUT, FwRule, PROTOCOL_ANY};

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
