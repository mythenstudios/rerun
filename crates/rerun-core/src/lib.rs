//! Rerun core.
//!
//! Phase 0 contains only the foundation:
//! - [`sys`]: the system layer (traits for file system, registry, CPU topology), plus
//!   `sys::fake` (in-memory) and the generic [`sys::snapshot`].
//! - [`policy`]: pure rules above `sys`, e.g. the confinement of paths to the
//!   game folder ([`policy::path::RelPath`]).
//!
//! See `docs/01-architecture.md` and ADR 0004.

pub mod policy;
pub mod sys;

/// Rerun version (from `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
