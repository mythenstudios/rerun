//! Hardware facts (ADR 0015): the GPU architecture table ([`arch`]).
//!
//! `hw` sits above `sys` and only consumes it: no FFI, no `unsafe`, no serde.

pub mod arch;
