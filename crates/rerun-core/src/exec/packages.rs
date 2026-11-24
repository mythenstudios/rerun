//! Which packages of the store are used, and their removal under the journal lock (P5-8b, ADR
//! 0025 amendment P5-8b). The rule is enforced here, not in a front end (as `exec::purge_seen`
//! of P5-6d); `pkg::store` lists and deletes and knows no journal.
//!
//! - **Used by** a transaction that is not forgotten, not closed and not empty (open or
//!   interrupted, applied, a cleanup pending, damaged with a head that decodes) and whose head
//!   names the package (`ContentRef::Package { id, version }`, any op, `Hold` included). The same
//!   reading of the head as `stack::slot_taken`. Forgotten transactions do not count: Rerun never
//!   reverts them, and their files in the game folder stay whatever happens to the package.
//! - **Unreadable** (user decision E3 a, fail closed): a transaction of that kind whose folder or
//!   head cannot be read or decoded may use any package, so while one exists no package is
//!   removed (it is listed with its reason; archives without a package and leftovers still go).
//! - **A revert never needs a package** (P5-8b finding 1): revert, rollback, rebind, forget and
//!   verify read only the journal's backups and the hashes in the ops; `packages\` is read only by
//!   the planner, the checks before an apply and the apply itself. Removing a package therefore
//!   never takes a recovery away.
//!
//! [`remove_packages`] takes `journal\lock`, then (in `pkg::store::remove`) `packages\.lock` and
//! `cache\lock`, in this fixed order and never waiting (`Busy`), so no two Rerun runs can hold
//! them crosswise; it reads the users again under the lock and refuses with nothing written
//! when a shown package is used now.

use std::collections::BTreeMap;

use crate::journal::{InstanceTag, Journal, JournalError, Listing, TxnId, TxnState, VerifyBackups};
use crate::pkg::store::{self, Removed, StoreError};
use crate::plan::ContentRef;
use crate::policy::root::AppDir;

use super::{ExecCtx, ExecError, Refusal, decode_head, standard_user};

/// Who uses which package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Users {
    /// The transactions whose head names a package (ID, version), oldest first.
    pub(crate) by: BTreeMap<(String, String), Vec<TxnId>>,
    /// Transactions that may use any package: not forgotten, not settled, and their head cannot
    /// be read (E3 a).
    pub(crate) unreadable: Vec<TxnId>,
}

impl Users {
    /// The transactions that use `id` at `version` (names compared as the file system does).
    pub(crate) fn of(&self, id: &str, version: &str) -> Vec<TxnId> {
        let mut out: Vec<TxnId> = self
            .by
            .iter()
            .filter(|((i, v), _)| i.eq_ignore_ascii_case(id) && v.eq_ignore_ascii_case(version))
            .flat_map(|(_, t)| t.iter().copied())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// The users of every package on one listing.
fn users_of(j: &Journal<'_>, l: &Listing) -> Users {
    let mut out = Users::default();
    for t in &l.txns {
        if t.forgotten {
            continue;
        }
        let Ok(v) = &t.view else {
            out.unreadable.push(t.id);
            continue;
        };
        if matches!(v.state, TxnState::Closed(_) | TxnState::Empty) {
            continue;
        }
        let plan = j
            .load(&t.id, VerifyBackups::Length)
            .ok()
            .and_then(|full| full.head)
            .and_then(|h| decode_head(&h).ok());
        let Some(plan) = plan else {
            out.unreadable.push(t.id);
            continue;
        };
        for op in &plan.ops {
            if let Some((_, ContentRef::Package { id, version, .. })) = op.package_file() {
                let users = out.by.entry((id.clone(), version.clone())).or_default();
                if !users.contains(&t.id) {
                    users.push(t.id);
                }
            }
        }
    }
    out
}

/// Who uses which package now (module docs), and the status of every transaction (live heads
/// only), from one listing of the journal, so a front end's lines and its locks agree. Reads only
/// and takes no lock; [`remove_packages`] decides again under the lock.
///
/// # Errors
/// The journal cannot be listed.
pub(crate) fn package_users_with_status(
    app: &AppDir<'_>,
) -> Result<(Users, super::Status), JournalError> {
    let j = Journal::new(app, InstanceTag::new());
    let l = j.list()?;
    Ok((
        users_of(&j, &l),
        super::status::status_listed(&j, app, &l, false),
    ))
}

/// Removes exactly `shown` (a preview's list) under `journal\lock` (module docs): a shown package
/// that a transaction uses now is `Refusal::PackageInUse`, and while a transaction cannot be read
/// any shown package is `Refusal::Blocked` (E3 a); both write nothing. Then
/// `pkg::store::remove` compares what is there with what was shown (`Refusal::StoreChanged`,
/// nothing written) and deletes.
///
/// # Errors
/// A refusal (nothing written), or the system layer.
pub(crate) fn remove_packages(
    cx: &ExecCtx<'_>,
    shown: &[store::Shown],
) -> Result<Removed, ExecError> {
    standard_user(cx.sys)?;
    let j = Journal::new(cx.app, cx.tag);
    let _lock = j.lock().map_err(Refusal::from)?;
    let listing = j.list().map_err(Refusal::from)?;
    let users = users_of(&j, &listing);
    // A version folder, and the archive of a package (security review S3: a package that was
    // only its archive may have been unpacked and applied since the preview).
    let packages = shown.iter().flat_map(|s| match s {
        store::Shown::Package(v) => vec![(v.id.as_str(), v.version.as_str())],
        store::Shown::Archive { owners, .. } => owners
            .iter()
            .map(|(i, v)| (i.as_str(), v.as_str()))
            .collect(),
        store::Shown::EmptyId(_) => Vec::new(),
    });
    for (id, version) in packages {
        if let Some(txn) = users.of(id, version).first() {
            return Err(Refusal::PackageInUse {
                package: crate::escape::text(&format!("{id}@{version}")).into_owned(),
                txn: *txn,
            }
            .into());
        }
        if let Some(txn) = users.unreadable.first() {
            return Err(Refusal::Blocked { txn: *txn }.into());
        }
    }
    store::remove(cx.sys, cx.app, shown).map_err(|e| match e {
        StoreError::Elevated => Refusal::Elevated.into(),
        StoreError::Changed => Refusal::StoreChanged.into(),
        StoreError::Busy => Refusal::StoreBusy.into(),
        StoreError::Root(r) => Refusal::Root(r).into(),
        StoreError::Sys(s) => ExecError::Sys(s),
    })
}
