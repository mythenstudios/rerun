//! Shared data types for Rerun.
//!
//! This crate is deliberately small: `rerun-launch` and `rerun-cpu` depend on it and
//! must get by without heavy dependencies. `serde` is only available via the `serde` feature.
//! The CPU rule selection (`cpu::rule`) and the launch profile codec (`profile`) are shared by
//! the writer in `rerun-core` and the reader in `rerun-launch` (ADR 0022).

pub mod cpu;
pub mod profile;
