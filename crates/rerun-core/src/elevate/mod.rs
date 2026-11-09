//! The elevated helper's side of `rerun-core` (ADR 0023), and the parts of the CLI's side that
//! need no journal.
//!
//! - [`exit`]: the exit code (§7, strict decoding, A4 N4); [`judge`](mod@judge): is an exit code
//!   the helper's statement? (A4 S2); [`prompt`]: the UAC prompt state (§10, N7).
//! - [`request`]: the request file and the command line that names it (§4, §12, A4 S1).
//! - [`derive`]: what a Topo and its picks authorise elevated, the same derivation for the
//!   helper and the CLI's plan check (§5 steps 3, 5, 7; A4 S7).
//! - [`serve`](mod@serve): the helper's run, §3 and the validation chain of §5 (P4-2c; the
//!   firewall write side follows in P4-5b).
//! - [`client`]: the CLI's start of the helper for a written request and its process check
//!   (A4 S8); the request file and the journal records come with `exec` in P4-2d.
//!
//! `serve` never uses `exec`, `journal`, `hw`, `pkg`, `detect::steam`, `topo::when` or
//! `exec::standard_user` (§11); `crates/rerun-helper/tests/source_rules.rs` checks this folder.

pub mod client;
pub mod derive;
pub mod exit;
pub mod judge;
pub mod prompt;
pub mod request;
pub mod serve;

pub use derive::{Anchor, DeriveError, PlanRefusal, check_plan, derive_add};
pub use exit::{ExitClass, HelperExit, OpResult, Reason};
pub use judge::{Judged, judge};
pub use prompt::{PromptKind, PromptState};
pub use request::{
    AddOp, Body, DirRef, MAX_REQUEST_BYTES, REQUEST_FORMAT, RemoveOp, Request, RequestError,
    RequestName, RequestRef, RootRef, decode, encode,
};
pub use serve::serve;

/// At most this many ops in one helper batch (§5 step 1); the exit code has a 2-bit slot for
/// each.
pub const MAX_BATCH_OPS: usize = 8;

/// The lowest `seq` of a signed index the helper accepts for an add (§5 step 2): the `seq` of
/// the index shipped with this build (user decision E5). No index is shipped yet, so every
/// signed index counts (1 is the first `seq`); it rises with the first shipped index, so an
/// older signed index can no longer authorise a new rule.
pub const HELPER_MIN_SEQ: u64 = 1;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod chain_tests;
