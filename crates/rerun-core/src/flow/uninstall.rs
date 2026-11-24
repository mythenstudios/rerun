//! The uninstall check (P5-13b, ADR 0030): whether Rerun can be removed now. Reads only, creates
//! nothing (not even Rerun's folder), and runs behind [`super::guard`], so an elevated process
//! reads nothing (user decision E3).
//!
//! - Every transaction that is not settled (open, applied, reverting, cleanup pending, damaged,
//!   unreadable) blocks: the uninstall would delete the journal and the backups a revert needs
//!   (rule 2). Undo them in Rerun first, or forget them.
//! - Warnings, never blockers: the games Steam may still start through this install's
//!   `rerun-launch.exe` (a profile a transaction holds, forgotten ones included, or a launch
//!   result: the shim ran at that game's last recorded start; Rerun does not read Steam's
//!   settings, so it cannot see whether the option was removed since), forgotten transactions
//!   (their backups are in Rerun's folder), and Rerun's firewall rules no transaction of this
//!   account owns.

use std::collections::BTreeMap;

use crate::escape::Shown;
use crate::exec::launch_result::ProfileId;
use crate::exec::{self, OrphanRule, OrphansError, TxnStatus};
use crate::journal::{JournalError, TxnId};
use crate::policy::root::RootError;

use super::history::app_of;
use super::{DataFolder, Guarded, Heads, data_folder, head, journal, orphans, profile_id_of};

/// A game Steam may still start through `rerun-launch.exe` (a warning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchLeft {
    /// The profile ID (the `--profile` of the launch option).
    pub id: ProfileId,
    /// The Steam app, if a transaction of the journal names it with this profile.
    pub app_id: Option<u32>,
    /// The transaction whose applied profile op holds the profile, and whether it is forgotten.
    pub held: Option<(TxnId, bool)>,
    /// The last recorded start through the shim: its time (Unix seconds), or why its result
    /// cannot be read (escaped). `None`: no start recorded.
    pub last_start: Option<Result<u64, Shown<'static>>>,
}

/// Whether Rerun can be removed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallVerdict {
    /// Nothing is open.
    Clean,
    /// At least one transaction is not settled.
    OpenChanges,
}

/// What the uninstall check found.
#[derive(Debug)]
pub struct UninstallView {
    /// The journal with every head read (`None`: Rerun's folder does not exist).
    pub status: Option<exec::Status>,
    /// The games Steam may still start through `rerun-launch.exe`, by profile ID.
    pub launch_options: Vec<LaunchLeft>,
    /// The launch results could not be read (the list above may miss games).
    pub launch_unreadable: Option<RootError>,
    /// Rerun's firewall rules no transaction of this account owns (`None`: Rerun's folder does
    /// not exist, nothing to compare with).
    pub orphans: Option<Result<Vec<OrphanRule>, OrphansError>>,
    /// Rerun's folder: where it is and whether it exists.
    pub data: Result<DataFolder, RootError>,
}

impl UninstallView {
    /// The transactions that are not settled: each one blocks the uninstall.
    pub fn open(&self) -> Vec<&TxnStatus> {
        self.status
            .iter()
            .flat_map(|s| s.txns.iter())
            .filter(|t| !t.is_settled())
            .collect()
    }

    /// The forgotten transactions (their backups stay in Rerun's folder).
    pub fn forgotten(&self) -> usize {
        self.status
            .iter()
            .flat_map(|s| s.txns.iter())
            .filter(|t| t.is_forgotten())
            .count()
    }

    /// [`UninstallVerdict::OpenChanges`] if and only if a transaction is not settled.
    pub fn verdict(&self) -> UninstallVerdict {
        if self.open().is_empty() {
            UninstallVerdict::Clean
        } else {
            UninstallVerdict::OpenChanges
        }
    }
}

/// The uninstall check of the job `g` (module docs). Reads only.
///
/// # Errors
/// The journal cannot be read (fatal: nothing can be said about open changes).
pub fn uninstall_check(g: &Guarded<'_>) -> Result<UninstallView, JournalError> {
    let data = data_folder(g);
    let Some(app) = g.app() else {
        return Ok(UninstallView {
            status: None,
            launch_options: Vec::new(),
            launch_unreadable: None,
            orphans: None,
            data,
        });
    };
    let j = journal(app, Heads::All)?;
    // The Steam app of each profile, from every head that names one (newest wins).
    let mut apps: BTreeMap<[u8; 16], u32> = BTreeMap::new();
    for st in &j.status.txns {
        if let (Some(id), Some(a)) = (head(st).and_then(profile_id_of), app_of(st)) {
            apps.insert(id.0, a);
        }
    }
    // By profile ID, so the list is in a stable order.
    let mut left: BTreeMap<[u8; 16], LaunchLeft> = BTreeMap::new();
    fn slot<'m>(
        left: &'m mut BTreeMap<[u8; 16], LaunchLeft>,
        apps: &BTreeMap<[u8; 16], u32>,
        id: ProfileId,
    ) -> &'m mut LaunchLeft {
        left.entry(id.0).or_insert_with(|| LaunchLeft {
            id,
            app_id: apps.get(&id.0).copied(),
            held: None,
            last_start: None,
        })
    }
    for h in &j.holders {
        slot(&mut left, &apps, h.id).held = Some((h.txn, h.forgotten));
    }
    let mut launch_unreadable = None;
    match j.launch {
        Ok(Some(r)) => {
            for e in r.entries {
                slot(&mut left, &apps, e.id).last_start = Some(e.result.map(|r| r.unix_s));
            }
        }
        Ok(None) => {}
        Err(e) => launch_unreadable = Some(e),
    }
    let orphans = Some(orphans(g.env().sys, app));
    Ok(UninstallView {
        status: Some(j.status),
        launch_options: left.into_values().collect(),
        launch_unreadable,
        orphans,
        data,
    })
}
