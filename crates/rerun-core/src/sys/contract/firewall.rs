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
use crate::fold::fold;
use crate::sys::firewall::{
    ACTION_ALLOW, ACTION_BLOCK, DIR_IN, DIR_OUT, FwRule, MAX_APPLICATION_NAME_UTF16, PROTOCOL_ANY,
};
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

/// What the write contract saw (measured on Windows by the [SB] write contract; fixed in the
/// fake). Every field is a measurement, none fails the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteFacts {
    /// W1: the program of the added rule read back in another ASCII case (every other fact
    /// exact). `policy::firewall` compares the program with ASCII case ignored, so this is
    /// drift Rerun tolerates, reported rather than failed (review S2 of P4-5b).
    pub program_case_drift: bool,
    /// W2: `Remove(name)` with two rules of that name took both (B12 c, R10: the design assumes
    /// it does and counts first).
    pub takes_every_rule_of_the_name: bool,
    /// W3: `Remove` with the name in lower case returned success.
    pub case_remove_ok: bool,
    /// W3: after that call no rule of the exact name was left (A4 S6 c).
    pub ignores_case: bool,
    /// W3b: `Remove` with every `i` of the name replaced by U+0131 (dotless i, which Unicode
    /// upper-cases to `I`) took the rule (security review 4 of P4-5b).
    pub unicode_twin_removes: bool,
    /// W4: `Remove(name)` of a name no rule holds returned success.
    pub missing_name_is_ok: bool,
}

/// The write contract of the firewall (ADR 0023 §6, §14; P4-5b), against the fake and, in the
/// [SB] only, the real Windows Firewall (it adds and removes real rules).
///
/// - **W1** an added rule reads back with the facts it was added with: one rule of its name,
///   every fact equal, the program equal with ASCII case ignored (as `policy::firewall`
///   compares it; a case-only difference is [`WriteFacts::program_case_drift`]).
/// - **W2** two adds of one name are two rules (the firewall does not refuse a duplicate);
///   `Remove(name)` leaves no rule of that exact name ([`WriteFacts`] says whether one call
///   took both, R10).
/// - **W3** `Remove` with the name in lower case: its result and the read-back are measured;
///   the rule is removed by its exact name afterwards if it is still there.
/// - **W3b** `Remove` with the name's `i` as U+0131: measured the same way.
/// - **W4** `Remove` of a name no rule holds: measured.
/// - **W5** an `ApplicationName` of 260 UTF-16 units is refused by `Add` and nothing is added
///   (measured on Windows in P4-5b; the fake refuses the same).
///
/// `a` and `b` are two rules of different names whose names no rule of the firewall holds,
/// compared folded; `a`'s name has an ASCII `i`, `b`'s an upper-case ASCII letter. Every rule
/// the contract adds is removed again, also when a case fails (by exact name).
///
/// # Errors
/// The first broken rule.
pub fn firewall_write_contract(
    fw: &dyn Firewall,
    w: &dyn FirewallWrite,
    a: &FwRule,
    b: &FwRule,
) -> Result<WriteFacts, String> {
    let lower = b.name.to_ascii_lowercase();
    if lower == b.name || !a.name.contains('i') || fold(&a.name) == fold(&b.name) {
        return Err(
            "setup: a's name needs an `i`, b's an upper-case letter, a and b other names".into(),
        );
    }
    // Before anything is added, so the clean-up below can only meet the contract's own rules.
    for r in [a, b] {
        let taken = ok(fw.select(&|n, _| fold(n) == fold(&r.name)), "select folded")?;
        ensure(taken.rules.is_empty(), "setup: the names are free (folded)")?;
    }
    let r = write_cases(fw, w, a, b, &lower);
    // Clean up whatever the cases left, by exact name (twice for a: a duplicate may be left).
    for name in [&a.name, &a.name, &b.name] {
        #[expect(
            clippy::disallowed_methods,
            reason = "write contract: removes the rules the contract itself added"
        )]
        let _ = w.remove_named(name);
    }
    let left = ok(
        fw.select(&|n, _| fold(n) == fold(&a.name) || fold(n) == fold(&b.name)),
        "select after the clean-up",
    )?;
    ensure(left.rules.is_empty(), "the contract leaves no rule behind")?;
    r
}

/// The rules of exactly `name`.
fn named(fw: &dyn Firewall, name: &str) -> Result<Vec<FwRule>, String> {
    Ok(ok(fw.select(&|n, _| n == name), "select by name")?.rules)
}

/// `got` is `want` with the program equal with ASCII case ignored: `Some(true)` for a
/// case-only drift of the program, `Some(false)` for exact, `None` otherwise.
fn same_facts(want: &FwRule, got: &FwRule) -> Option<bool> {
    let strip = |r: &FwRule| FwRule {
        program: String::new(),
        ..r.clone()
    };
    (strip(want) == strip(got) && want.program.eq_ignore_ascii_case(&got.program))
        .then(|| want.program != got.program)
}

fn write_cases(
    fw: &dyn Firewall,
    w: &dyn FirewallWrite,
    a: &FwRule,
    b: &FwRule,
    lower: &str,
) -> Result<WriteFacts, String> {
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
    // W1.
    ok(add(a), "add a")?;
    let got = named(fw, &a.name)?;
    let program_case_drift = match got.as_slice() {
        [one] => same_facts(a, one),
        _ => None,
    }
    .ok_or_else(|| {
        format!(
            "W1: an added rule reads back with the facts it was added with:\n  set  {a:?}\n  read {got:?}"
        )
    })?;
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
    // W3: the result is recorded, never propagated, and the read-back decides.
    ok(add(b), "add b")?;
    let case_remove_ok = remove(lower).is_ok();
    let ignores_case = named(fw, &b.name)?.is_empty();
    if !ignores_case {
        ok(remove(&b.name), "remove b by its exact name")?;
    }
    ensure(named(fw, &b.name)?.is_empty(), "W3: b removed")?;
    // W3b.
    ok(add(a), "add a for W3b")?;
    let twin = a.name.replace('i', "\u{131}");
    let _ = remove(&twin);
    let unicode_twin_removes = named(fw, &a.name)?.is_empty();
    if !unicode_twin_removes {
        ok(remove(&a.name), "remove a by its exact name after W3b")?;
    }
    ensure(named(fw, &a.name)?.is_empty(), "W3b: a removed")?;
    // W4.
    let missing_name_is_ok = remove(&b.name).is_ok();
    // W5: a program of 260 UTF-16 units is refused and leaves nothing.
    let long = FwRule {
        program: format!(r"C:\{}.exe", "p".repeat(MAX_APPLICATION_NAME_UTF16 + 1 - 7)),
        ..a.clone()
    };
    debug_assert_eq!(
        long.program.encode_utf16().count(),
        MAX_APPLICATION_NAME_UTF16 + 1
    );
    let refused = add(&long).is_err();
    let left = named(fw, &a.name)?;
    if !left.is_empty() {
        ok(remove(&a.name), "remove the long rule")?;
    }
    ensure(
        refused && left.is_empty(),
        "W5: an ApplicationName of 260 UTF-16 units is refused and nothing is added",
    )?;
    Ok(WriteFacts {
        program_case_drift,
        takes_every_rule_of_the_name,
        case_remove_ok,
        ignores_case,
        unicode_twin_removes,
        missing_name_is_ok,
    })
}
