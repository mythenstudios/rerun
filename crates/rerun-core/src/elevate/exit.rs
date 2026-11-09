//! The helper's exit code (ADR 0023 §7): its only report. Pure.
//!
//! Layout of the `u32` (`GetExitCodeProcess`):
//!
//! | bits | field |
//! |---|---|
//! | 31..24 | [`MAGIC`] `0x52` |
//! | 23..20 | [`ExitClass`] |
//! | 19..16 | [`Reason`], 0 = none (exactly with [`ExitClass::Done`]) |
//! | 15..0 | 2 bits per op in request order, op 0 in bits 1..0 ([`OpResult`]) |
//!
//! Any other value (a crash's `NTSTATUS`, `STILL_ACTIVE`, a code of another program) does not
//! decode: [`HelperExit::from_code`] is strict (A4 N4). A decoded code is the helper's
//! statement only once the CLI's process checks of §7 hold (A4 S2, P4-2b).

use super::MAX_BATCH_OPS;

/// Bits 31..24 of every helper code: `R`.
pub const MAGIC: u32 = 0x52;

/// How the run ended (bits 23..20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    /// Every op done as reported; no reason.
    Done,
    /// Refused before any change (§5 steps 1 to 7, §3): every op `NotRun`.
    Refused,
    /// A failure after a change, and the helper's own rollback finished.
    RolledBack,
    /// A failure the helper could not roll back: the per-op results say what is left.
    LeftOpen,
}

impl ExitClass {
    const ALL: [Self; 4] = [Self::Done, Self::Refused, Self::RolledBack, Self::LeftOpen];

    const fn bits(self) -> u32 {
        match self {
            Self::Done => 0,
            Self::Refused => 1,
            Self::RolledBack => 2,
            Self::LeftOpen => 3,
        }
    }
}

/// Why the helper did not finish with `Done` (bits 19..16, values 1 to 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The arguments are not exactly the form of §3 step 5.
    Usage,
    /// The process is not elevated (§3 step 3).
    NotElevated,
    /// The running image is not the admin-only `Program Files\Rerun\rerun-helper.exe` (§3 step 4).
    ImageFolder,
    /// The request is from another build (§2, R12).
    Build,
    /// The request does not decode or breaks a form rule.
    Request,
    /// The index is missing, unsigned, below the seq floor or breaks a rule (§5 step 2).
    Index,
    /// The Topo or a variant is missing, retired or conflicting (§5 step 3).
    Topo,
    /// The game root does not open by its identity or is forbidden (§5 step 4).
    Root,
    /// A program is missing, linked or has another hash (§5 step 5).
    Program,
    /// An anti-cheat system was found (§5 step 6, E4).
    AntiCheat,
    /// The ops are not exactly the derived set (§5 step 7).
    Ops,
    /// A rule of the name already exists (§6).
    DuplicateName,
    /// The firewall call failed.
    Firewall,
    /// Anything else (a privilege that cannot be dropped, the token unreadable, …).
    Internal,
}

impl Reason {
    const ALL: [Self; 14] = [
        Self::Usage,
        Self::NotElevated,
        Self::ImageFolder,
        Self::Build,
        Self::Request,
        Self::Index,
        Self::Topo,
        Self::Root,
        Self::Program,
        Self::AntiCheat,
        Self::Ops,
        Self::DuplicateName,
        Self::Firewall,
        Self::Internal,
    ];

    const fn bits(self) -> u32 {
        match self {
            Self::Usage => 1,
            Self::NotElevated => 2,
            Self::ImageFolder => 3,
            Self::Build => 4,
            Self::Request => 5,
            Self::Index => 6,
            Self::Topo => 7,
            Self::Root => 8,
            Self::Program => 9,
            Self::AntiCheat => 10,
            Self::Ops => 11,
            Self::DuplicateName => 12,
            Self::Firewall => 13,
            Self::Internal => 14,
        }
    }
}

/// The helper's report for one op (2 bits each).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpResult {
    /// Not reached (and every slot beyond the batch).
    NotRun,
    /// The state before the op (nothing to do, or rolled back).
    Before,
    /// The op's target state.
    After,
    /// Something else; left untouched (ADR 0020 D10).
    Foreign,
}

impl OpResult {
    const ALL: [Self; 4] = [Self::NotRun, Self::Before, Self::After, Self::Foreign];

    const fn bits(self) -> u32 {
        match self {
            Self::NotRun => 0,
            Self::Before => 1,
            Self::After => 2,
            Self::Foreign => 3,
        }
    }
}

/// A decoded helper exit code (ADR 0023 §7, §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperExit {
    /// How the run ended.
    pub class: ExitClass,
    /// Why, `None` exactly with [`ExitClass::Done`].
    pub reason: Option<Reason>,
    /// One result per op in request order; slots beyond the batch are `NotRun`.
    pub ops: [OpResult; MAX_BATCH_OPS],
}

impl HelperExit {
    /// A refusal: nothing changed, every op `NotRun`.
    #[must_use]
    pub const fn refused(reason: Reason) -> Self {
        Self {
            class: ExitClass::Refused,
            reason: Some(reason),
            ops: [OpResult::NotRun; MAX_BATCH_OPS],
        }
    }

    /// The exit code (layout in the module docs).
    #[must_use]
    pub fn to_code(&self) -> u32 {
        let reason = self.reason.map_or(0, Reason::bits);
        let ops = self
            .ops
            .iter()
            .enumerate()
            .fold(0, |acc, (i, op)| acc | (op.bits() << (2 * i)));
        (MAGIC << 24) | (self.class.bits() << 20) | (reason << 16) | ops
    }

    /// Decodes `code` for a batch of `batch` ops (A4 N4, strict): the magic; a known class; a
    /// known reason, none exactly with `Done`; every slot from `batch` on `NotRun`; with
    /// `Done` every op of the batch reached (not `NotRun`); with `Refused` none (nothing
    /// changed before step 8, §5). `batch` above [`MAX_BATCH_OPS`] decodes nothing. Anything
    /// else is `None`: the run's outcome is unknown.
    #[must_use]
    pub fn from_code(code: u32, batch: usize) -> Option<Self> {
        if code >> 24 != MAGIC || batch > MAX_BATCH_OPS {
            return None;
        }
        let class = *ExitClass::ALL
            .iter()
            .find(|c| c.bits() == (code >> 20) & 0xF)?;
        let reason = match (code >> 16) & 0xF {
            0 => None,
            r => Some(*Reason::ALL.iter().find(|x| x.bits() == r)?),
        };
        let mut ops = [OpResult::NotRun; MAX_BATCH_OPS];
        for (i, op) in ops.iter_mut().enumerate() {
            let bits = (code >> (2 * i)) & 0b11;
            *op = *OpResult::ALL.iter().find(|o| o.bits() == bits)?;
        }
        let (used, unused) = ops.split_at(batch);
        let fits = (class == ExitClass::Done) == reason.is_none()
            && unused.iter().all(|o| *o == OpResult::NotRun)
            && match class {
                ExitClass::Done => used.iter().all(|o| *o != OpResult::NotRun),
                ExitClass::Refused => used.iter().all(|o| *o == OpResult::NotRun),
                ExitClass::RolledBack | ExitClass::LeftOpen => true,
            };
        fits.then_some(Self { class, reason, ops })
    }
}
