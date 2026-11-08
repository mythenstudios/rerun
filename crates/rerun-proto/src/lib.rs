//! Shared data types for Rerun.
//!
//! This crate is deliberately small: `rerun-launch` and `rerun-cpu` depend on it and
//! must get by without heavy dependencies. `serde` is only available via the `serde` feature.
//! The CPU rule selection (`cpu::rule`), the launch profile codec (`profile`) and the launch
//! result codec (`launch`) are shared by `rerun-core` and `rerun-launch` (ADR 0022).

pub mod cpu;
pub mod launch;
pub mod profile;
