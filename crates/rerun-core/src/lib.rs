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
//! - [`topo`]: the Topo engine (P4-4): match, `when`, variants, anti-cheat rule, plan.
//! - [`elevate`]: the elevated helper's side (ADR 0023): its exit code and `serve`.
//! - [`pkg`]: packages: the download into the cache (ADR 0025).
//! - [`flow`]: the typed flows the CLI and the app share (ADR 0027): guards, index state,
//!   library, game, status; no text, never asks.
//!
//! See `docs/01-architecture.md`, ADR 0004, ADR 0007 and ADR 0011.

pub mod catalog;
pub mod detect;
pub mod elevate;
pub mod escape;
pub mod exec;
pub mod flow;
mod fold;
pub mod hw;
pub mod journal;
pub mod path;
pub mod pkg;
pub mod plan;
pub mod policy;
pub mod prim;
pub mod sys;
pub mod topo;
mod wire;

/// Rerun version (from `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The build ID (ADR 0023 §2, A4 S9): `<version>+<commit>` for a release or CI build that
/// sets `RERUN_BUILD_ID`, else `<version>+dev-<SHA-256 of the contract sources>` (`build.rs`,
/// `src/build_contract.rs`). A helper request carries the CLI's; the helper refuses another
/// (P4-2c). Not a security boundary: it catches a CLI and a helper of different builds.
pub const BUILD_ID: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("RERUN_BUILD_ID"));

#[cfg(test)]
mod build_contract;

#[cfg(test)]
mod build_id_tests;
