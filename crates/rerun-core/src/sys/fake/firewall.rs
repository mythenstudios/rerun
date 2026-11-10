//! Fake Windows Firewall, read side (ADR 0023 §14, P4-5a): the rules as data.
//!
//! The rule collection is a list in insertion order (the enumeration order), duplicates of a
//! name allowed as on Windows. Tests change it at any time through `&self` (an administrator
//! adding or changing a rule between two observations). Every [`Firewall::select`] is counted,
//! so a test can show that an observation enumerates once (A4 S11). The write side (P4-2d) has one
//! armed fault ([`WriteFault`]) and the "durable on return" model; the lazy model of ADR 0023 §6
//! comes with the P4-5b write contract.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use crate::fold::fold;
use crate::sys::firewall::{FwRule, FwSelection, MAX_RULES, MAX_TEXT_UTF16};
use crate::sys::{Firewall, FirewallWrite, SysError, SysErrorKind, SysResult};

/// The fake firewall: rules as data, an optional fixed error, and the write side of the helper
/// (P4-2d) with one armed fault.
#[derive(Debug, Default)]
pub struct FakeFirewall {
    rules: Mutex<Vec<FwRule>>,
    error: Mutex<Option<SysErrorKind>>,
    fail_next: Mutex<usize>,
    selects: AtomicUsize,
    writes: AtomicUsize,
    fault: Mutex<Option<(usize, WriteFault)>>,
    crashed: AtomicBool,
}

/// What an armed fault of the write side does at its call (P4-2d).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFault {
    /// The write fails with this kind before it acts.
    Fail(SysErrorKind),
    /// The write acts, then the helper process crashes: every later call of the firewall
    /// fails until [`FakeFirewall::take_crash`] (the helper is gone; the service is not).
    CrashAfter,
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

    /// The next `n` enumerations fail with `AccessDenied` (a passing failure).
    pub fn fail_next(&self, n: usize) {
        *self
            .fail_next
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = n;
    }

    /// How many enumerations ran.
    pub fn selects(&self) -> usize {
        self.selects.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<FwRule>> {
        self.rules.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Arms `fault` for the `nth` (1-based) write from now on (the count starts again).
    pub fn fault_write(&self, nth: usize, fault: WriteFault) {
        self.writes.store(0, Ordering::Relaxed);
        *self.fault.lock().unwrap_or_else(PoisonError::into_inner) = Some((nth, fault));
    }

    /// How many writes ran since the last [`Self::fault_write`] (or ever).
    pub fn writes(&self) -> usize {
        self.writes.load(Ordering::Relaxed)
    }

    /// The helper crashed at an armed write (see [`WriteFault::CrashAfter`]); clears it, so the
    /// firewall answers again (the CLI's reads after the helper died).
    pub fn take_crash(&self) -> bool {
        self.crashed.swap(false, Ordering::Relaxed)
    }

    fn crashed_err() -> SysError {
        SysError::new(SysErrorKind::Other, "fake: helper crashed")
    }

    /// Counts a write and applies the armed fault: `Ok(true)` crash after it acts.
    fn enter_write(&self) -> SysResult<bool> {
        if self.crashed.load(Ordering::Relaxed) {
            return Err(Self::crashed_err());
        }
        let n = self.writes.fetch_add(1, Ordering::Relaxed) + 1;
        let mut f = self.fault.lock().unwrap_or_else(PoisonError::into_inner);
        match *f {
            Some((at, fault)) if at == n => {
                *f = None;
                match fault {
                    WriteFault::Fail(kind) => Err(SysError::new(
                        kind,
                        format!("fake: injected fault at firewall write #{n}"),
                    )),
                    WriteFault::CrashAfter => Ok(true),
                }
            }
            _ => Ok(false),
        }
    }
}

impl FirewallWrite for FakeFirewall {
    /// Appends the rule (durable on return, ADR 0023 §6: the assumed model; the lazy model
    /// follows with the P4-5b write contract).
    fn add(&self, rule: &FwRule) -> SysResult<()> {
        let crash = self.enter_write()?;
        self.lock().push(rule.clone());
        if crash {
            self.crashed.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Removes every rule whose name equals `name` folded (the worst case of ADR 0023 §6).
    fn remove_named(&self, name: &str) -> SysResult<()> {
        let crash = self.enter_write()?;
        let n = fold(name);
        self.lock().retain(|r| fold(&r.name) != n);
        if crash {
            self.crashed.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl Firewall for FakeFirewall {
    fn select(&self, keep: &dyn Fn(&str, &str) -> bool) -> SysResult<FwSelection> {
        self.selects.fetch_add(1, Ordering::Relaxed);
        if self.crashed.load(Ordering::Relaxed) {
            return Err(Self::crashed_err());
        }
        let once = {
            let mut n = self
                .fail_next
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let fail = *n > 0;
            *n = n.saturating_sub(1);
            fail
        };
        if once {
            return Err(SysError::new(SysErrorKind::AccessDenied, "firewall rules"));
        }
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
