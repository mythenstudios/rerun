//! Shared data types for Rerun.
//!
//! This crate is deliberately small: `rerun-launch` and `rerun-cpu` depend on it and
//! must get by without heavy dependencies. `serde` is only available via the `serde` feature.

pub mod cpu;
