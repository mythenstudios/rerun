//! Rerun core.
//!
//! - [`path`]: [`path::RelPath`] (relative, confined) and [`path::RootPath`] (absolute root),
//!   pure and without I/O.
//! - [`sys`]: the system layer (traits for file system, registry, CPU topology, known
//!   folders, GPU), plus, for tests only (feature `fake`), `sys::fake` (in-memory),
//!   `sys::contract` and `sys::snapshot` (state comparison of the round-trip tests).
//! - [`policy`]: rules above `sys`, e.g. which roots may be opened.
//! - [`detect`]: detection of installed games (Steam files through the bounded VDF parser,
//!   ADR 0011).
//! - [`escape`]: display of untrusted text ([`escape::text`], [`escape::path`], ADR 0016).
//! - [`hw`]: the system profile above `sys` (GPU, CPU, OS build, GPU architecture table,
//!   ADR 0015).
//!
//! See `docs/01-architecture.md`, ADR 0004, ADR 0007 and ADR 0011.

pub mod detect;
pub mod escape;
mod fold;
pub mod hw;
pub mod path;
pub mod policy;
pub mod sys;

/// Rerun version (from `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
