//! What a Topo and its picks authorise elevated (ADR 0023 §5 steps 3, 5, 7; A4 S7). Pure.
//!
//! One derivation for both sides: the helper re-derives the add batch from the signed index
//! with it, and the CLI runs the same at `plan` and again before `begin` (non-elevated), so a
//! refusal of the helper can only mean that something changed in between or was tampered with
//! (else the user would click a UAC prompt for a batch that is refused, and the run would end
//! with a rollback, exit 4).
//!
//! [`derive_add`]: the Topo not retired; the picks resolved with the engine's pure rules
//! (`topo::resolve_picks`, no `when`); one [`Anchor`] per `firewall_rule` step of the picked
//! variants in pick and step order: the `match.exes` entry of exactly the step's spelling (the
//! program is derived from the entry, never from the step), which must carry a `sha256` (R6:
//! `sha1` alone never anchors anything elevated). At most [`MAX_BATCH_OPS`] anchors and no
//! executable twice (two rules for one program would make the batch's rule names ambiguous to
//! no gain).
//!
//! [`check_plan`] (A4 S7, the CLI): [`derive_add`], and a root whose volume cannot open by ID
//! (FAT, exFAT: no `FILE_SUPPORTS_OPEN_BY_FILE_ID`) or has no volume GUID path is refused in the
//! plan, never at the helper.

use super::MAX_BATCH_OPS;
use crate::catalog::model::{Sha256, Status, Topo, TopoStep};
use crate::fold::fold;
use crate::path::RelPath;
use crate::plan::Pick;
use crate::policy::firewall::Direction;
use crate::sys::fs::RootInfo;
use crate::topo::{EngineError, resolve_picks};

/// One elevated op a Topo authorises: a block rule for this executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The `match.exes` path, in the entry's spelling.
    pub exe: RelPath,
    /// Its signed SHA-256.
    pub sha256: [u8; 32],
    /// The step's direction.
    pub direction: Direction,
}

/// Why a Topo and its picks authorise no batch.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// The Topo is retired.
    #[error("Topo {0} is retired and offers no fixes")]
    Retired(String),
    /// The picks do not resolve.
    #[error(transparent)]
    Picks(#[from] EngineError),
    /// A `firewall_rule` step names no `match.exes` entry of its spelling.
    #[error("{0} is not an executable of the Topo's match.exes")]
    NotAnExe(RelPath),
    /// The entry has no `sha256` (or a `TODO`).
    #[error("{0} has no signed SHA-256: it cannot anchor an elevated op")]
    NoSha256(RelPath),
    /// More rules than one helper batch holds.
    #[error("the picked variants bring {0} firewall rules; one run holds at most 8")]
    TooMany(usize),
    /// Two rules for one executable.
    #[error("two firewall rules for {0}: pick one variant")]
    Duplicate(RelPath),
}

/// The add batch `topo` and `picks` authorise (module docs); empty if no picked variant has a
/// `firewall_rule` step.
///
/// # Errors
/// [`DeriveError`].
pub fn derive_add(topo: &Topo, picks: &[Pick]) -> Result<Vec<Anchor>, DeriveError> {
    if topo.status == Status::Retired {
        return Err(DeriveError::Retired(topo.id.to_string()));
    }
    let mut out: Vec<Anchor> = Vec::new();
    for (_, variant) in resolve_picks(topo, picks)? {
        for step in &variant.steps {
            let TopoStep::FirewallRule(f) = step else {
                continue;
            };
            let entry = topo
                .matches
                .exes
                .iter()
                .find(|e| e.path.same_spelling(&f.exe))
                .ok_or_else(|| DeriveError::NotAnExe(f.exe.clone()))?;
            let sha256 = entry
                .sha256
                .as_ref()
                .and_then(Sha256::bytes)
                .ok_or_else(|| DeriveError::NoSha256(entry.path.clone()))?;
            let folded = fold(entry.path.as_str());
            if out.iter().any(|a| fold(a.exe.as_str()) == folded) {
                return Err(DeriveError::Duplicate(entry.path.clone()));
            }
            out.push(Anchor {
                exe: entry.path.clone(),
                sha256: *sha256,
                direction: f.direction,
            });
        }
    }
    if out.len() > MAX_BATCH_OPS {
        return Err(DeriveError::TooMany(out.len()));
    }
    Ok(out)
}

/// Why the CLI refuses a plan with helper ops (A4 S7).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlanRefusal {
    /// The derivation the helper repeats.
    #[error(transparent)]
    Derive(#[from] DeriveError),
    /// The game folder's volume cannot be opened by ID, or has no volume GUID path.
    #[error(
        "the game folder's drive cannot be opened by identity (FAT or exFAT, or no volume GUID): \
         Rerun's firewall rules need an NTFS or ReFS drive"
    )]
    NoOpenById,
}

/// The CLI's check of a plan's helper ops (module docs).
///
/// # Errors
/// [`PlanRefusal`].
pub fn check_plan(
    topo: &Topo,
    picks: &[Pick],
    root: &RootInfo,
) -> Result<Vec<Anchor>, PlanRefusal> {
    let anchors = derive_add(topo, picks)?;
    if !anchors.is_empty() && !(root.supports_open_by_id && root.volume_guid.is_some()) {
        return Err(PlanRefusal::NoOpenById);
    }
    Ok(anchors)
}
