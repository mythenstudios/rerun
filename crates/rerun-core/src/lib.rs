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
//! - [`journal`]: the file-based journal below `AppDir` (ADR 0019).
//! - [`plan`]: plans, their one serialisation, hash, storage and preview (ADR 0020).
//! - [`prim`]: primitives as planners (`file_install`), ADR 0020.
//! - [`exec`]: apply, verify, revert and forget of plans with the journal (ADR 0020).
//! - [`catalog`]: the signed index and the typed Topos and packages (ADR 0024, ADR 0005).
//!
//! See `docs/01-architecture.md`, ADR 0004, ADR 0007 and ADR 0011.

pub mod catalog;
pub mod detect;
pub mod escape;
pub mod exec;
mod fold;
pub mod hw;
pub mod journal;
pub mod path;
pub mod plan;
pub mod policy;
pub mod prim;
pub mod sys;
mod wire;

/// Rerun version (from `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
