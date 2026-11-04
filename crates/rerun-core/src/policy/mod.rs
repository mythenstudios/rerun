//! Rules above the system layer (ADR 0004).
//!
//! `sys` executes, `policy` decides what is allowed. That way the same rules apply to the
//! fake and the real system, and the elevated helper revalidates through the same code.
//!
//! Phase 0: [`path`] (confinement to the game folder, purely lexical). Phase 2 adds the
//! check against reparse points via `sys::Fs`, phase 3 the registry allowlist.

pub mod path;
