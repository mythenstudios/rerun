//! Fake Windows Firewall, read side (ADR 0023 §14, P4-5a): the rules as data.
//!
//! The rule collection is a list in insertion order (the enumeration order), duplicates of a
//! name allowed as on Windows. Tests change it at any time through `&self` (an administrator
//! adding or changing a rule between two observations). Every [`Firewall::select`] is counted,
//! so a test can show that an observation enumerates once (A4 S11). The write side, its fault
//! sequence and the two durability models of ADR 0023 §6 come with P4-5b.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use crate::sys::firewall::{FwRule, FwSelection, MAX_RULES, MAX_TEXT_UTF16};
use crate::sys::{Firewall, SysError, SysErrorKind, SysResult};

/// The fake firewall: rules as data, an optional fixed error.
#[derive(Debug, Default)]
pub struct FakeFirewall {
    rules: Mutex<Vec<FwRule>>,
    error: Mutex<Option<SysErrorKind>>,
    selects: AtomicUsize,
}

impl FakeFirewall {
    /// Appends a rule (also one whose name another rule has).
    pub fn push(&self, rule: FwRule) {
        self.lock().push(rule);
    }

    /// Replaces every rule.
    pub fn set_rules(&self, rules: Vec<FwRule>) {
        *self.lock() = rules;
    }

    /// Changes every rule `pick` returns `true` for.
    pub fn edit(&self, pick: impl Fn(&FwRule) -> bool, change: impl Fn(&mut FwRule)) {
        self.lock().iter_mut().filter(|r| pick(r)).for_each(change);
    }

    /// Every rule, in enumeration order.
    pub fn rules(&self) -> Vec<FwRule> {
        self.lock().clone()
    }

    /// From now on [`Firewall::select`] fails with `kind` (`None`: works again).
    pub fn fail_with(&self, kind: Option<SysErrorKind>) {
        *self.error.lock().unwrap_or_else(PoisonError::into_inner) = kind;
    }

    /// How many enumerations ran.
    pub fn selects(&self) -> usize {
        self.selects.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<FwRule>> {
        self.rules.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Firewall for FakeFirewall {
    fn select(&self, keep: &dyn Fn(&str, &str) -> bool) -> SysResult<FwSelection> {
        self.selects.fetch_add(1, Ordering::Relaxed);
        if let Some(kind) = *self.error.lock().unwrap_or_else(PoisonError::into_inner) {
            return Err(SysError::new(kind, "firewall rules"));
        }
        let rules = self.lock();
        if rules.len() > MAX_RULES {
            return Err(SysError::too_large("firewall rules", MAX_RULES as u64));
        }
        // Like `sys::win`: name and grouping of every rule are read, every text of a kept rule.
        let too_long = || SysError::too_large("firewall rules: a text", MAX_TEXT_UTF16 as u64);
        let long = |t: &str| t.encode_utf16().count() > MAX_TEXT_UTF16;
        let mut out = FwSelection {
            total: rules.len(),
            rules: Vec::new(),
        };
        for r in rules.iter() {
            if long(&r.name) || long(&r.grouping) {
                return Err(too_long());
            }
            if keep(&r.name, &r.grouping) {
                if texts(r).any(long) {
                    return Err(too_long());
                }
                out.rules.push(r.clone());
            }
        }
        Ok(out)
    }
}

/// Every text field of a rule.
fn texts(r: &FwRule) -> impl Iterator<Item = &str> {
    let x = &r.rest;
    let v3 = x.v3.iter().flat_map(|v| {
        [
            &v.package_id[..],
            &v.user_owner,
            &v.local_users,
            &v.remote_users,
            &v.remote_machines,
        ]
    });
    [
        &r.description[..],
        &r.program,
        &x.service,
        &x.local_ports,
        &x.remote_ports,
        &x.local_addresses,
        &x.remote_addresses,
        &x.icmp_types,
        &x.interface_types,
    ]
    .into_iter()
    .chain(v3)
}
