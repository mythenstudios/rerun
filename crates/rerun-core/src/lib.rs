//! Rerun core.
//!
//! - [`path`]: [`path::RelPath`] (relative, confined) and [`path::RootPath`] (absolute root),
//!   pure and without I/O.
//! - [`sys`]: the system layer (traits for file system, registry, CPU topology, known
//!   folders, GPU), plus
//!   `sys::fake` (in-memory) and the generic [`sys::snapshot`].
//! - [`policy`]: rules above `sys`, e.g. which roots may be opened.
//! - [`detect`]: detection of installed games (Steam files through the bounded VDF parser,
//!   ADR 0011).
//! - [`hw`]: hardware facts above `sys` (GPU architecture table, OS build, ADR 0015).
//!
//! See `docs/01-architecture.md`, ADR 0004, ADR 0007 and ADR 0011.

pub mod detect;
mod fold;
pub mod hw;
pub mod path;
pub mod policy;
pub mod sys;

/// Rerun version (from `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
