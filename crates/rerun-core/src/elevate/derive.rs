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
//! plan, never at the helper; so is an anchor whose executable is not there with its signed hash, and
//! a game where the anti-cheat rule applies (the facts `topo::read_game` read).

use super::MAX_BATCH_OPS;
use crate::catalog::model::{Sha256, Status, Topo, TopoStep};
use crate::fold::fold;
use crate::path::{RelPath, RootPath};
use crate::plan::Pick;
use crate::policy::firewall::{Direction, Program, ProgramError};
use crate::sys::fs::RootInfo;
use crate::topo::{EngineError, ExeState, GameFacts, anti_cheat_state, resolve_picks};

/// One elevated op a Topo authorises: a block rule for this executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The `match.exes` path, in the entry's spelling.
    pub exe: RelPath,
    /// The signed SHA-256 of every `match.exes` entry of exactly this spelling (two builds may
    /// share one path, P4-10 review S2): the file must hash to one of them.
    pub sha256: Vec<[u8; 32]>,
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
            // Every entry of exactly this spelling (two builds may share the path; the loader
            // requires a sha256 on each), so the build that matched is among them (P4-10 S2).
            let entries: Vec<_> = topo
                .matches
                .exes
                .iter()
                .filter(|e| e.path.same_spelling(&f.exe))
                .collect();
            let entry = entries
                .first()
                .ok_or_else(|| DeriveError::NotAnExe(f.exe.clone()))?;
            let sha256 = entries
                .iter()
                .map(|e| e.sha256.as_ref().and_then(Sha256::bytes).copied())
                .collect::<Option<Vec<[u8; 32]>>>()
                .ok_or_else(|| DeriveError::NoSha256(entry.path.clone()))?;
            let folded = fold(entry.path.as_str());
            if out.iter().any(|a| fold(a.exe.as_str()) == folded) {
                return Err(DeriveError::Duplicate(entry.path.clone()));
            }
            out.push(Anchor {
                exe: entry.path.clone(),
                sha256,
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
    /// The executable a rule names is not there with its signed SHA-256 (it need not be the
    /// main executable the Topo was matched by).
    #[error("{0} is not there with the SHA-256 the Topo signs: no firewall rule for it")]
    ExeMismatch(RelPath),
    /// The anti-cheat rule applies (E4): no firewall rule.
    #[error("anti-cheat found: no firewall rule for this game")]
    AntiCheat,
    /// The game folder's path cannot be a rule's program, or the program would be longer than
    /// the firewall takes (`policy::firewall::MAX_PROGRAM_UTF16`, measured in P4-5b).
    #[error("no firewall rule for this program: {0}")]
    Program(#[from] ProgramError),
    /// The game folder's canonical path is not a drive path Rerun can name.
    #[error("the game folder's path cannot be a firewall rule's program")]
    RootPath,
}

/// The CLI's check of a plan's helper ops (module docs): what the helper will check later, from
/// what the engine read of the game folder (`game`, `topo::read_game` of the same root): every
/// anchor's executable there with its hashes (`ExeState::Match`, which for an anchor includes the
/// signed SHA-256; also for an executable that is not the main one; never a file that matched only
/// as the build a live `laa_patch` changed, P4-10: the helper hashes the file itself and would
/// refuse it), and the anti-cheat rule not
/// enforced. The engine builds `Op::FirewallRule` from these anchors only (P4-2d).
///
/// # Errors
/// [`PlanRefusal`].
pub fn check_plan(
    topo: &Topo,
    picks: &[Pick],
    root: &RootInfo,
    game: &GameFacts,
) -> Result<Vec<Anchor>, PlanRefusal> {
    let anchors = derive_add(topo, picks)?;
    if anchors.is_empty() {
        return Ok(anchors);
    }
    if !(root.supports_open_by_id && root.volume_guid.is_some()) {
        return Err(PlanRefusal::NoOpenById);
    }
    if anti_cheat_state(topo, &game.anti_cheat).enforced() {
        return Err(PlanRefusal::AntiCheat);
    }
    // The program as the helper forms it (`Program::new` on the request's root path, which the
    // CLI takes from the same canonical path): refused here, before any prompt.
    let root_path =
        RootPath::from_final_path(&root.final_path).map_err(|_| PlanRefusal::RootPath)?;
    for a in &anchors {
        Program::new(&root_path, &a.exe)?;
    }
    for a in &anchors {
        let ok = game.exes.iter().any(|e| {
            e.path.same_spelling(&a.exe) && e.state == ExeState::Match && e.patched_by.is_none()
        });
        if !ok {
            return Err(PlanRefusal::ExeMismatch(a.exe.clone()));
        }
    }
    Ok(anchors)
}
