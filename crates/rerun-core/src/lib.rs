//! Rerun core.
//!
//! - [`path`]: [`path::RelPath`] (relative, confined) and [`path::RootPath`] (absolute root),
//!   pure and without I/O.
//! - [`sys`]: the system layer (traits for file system, registry, CPU topology), plus
//!   `sys::fake` (in-memory) and the generic [`sys::snapshot`].
//! - [`policy`]: rules above `sys`, e.g. which roots may be opened.
//!
//! See `docs/01-architecture.md`, ADR 0004 and ADR 0007.

mod fold;
pub mod path;
pub mod policy;
pub mod sys;

/// Rerun version (from `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
