//! Rules above the system layer (ADR 0004, ADR 0007).
//!
//! `sys` executes, `policy` decides what is allowed. That way the same rules apply to the
//! fake and the real system, and the elevated helper revalidates through the same code.
//!
//! - [`path`]: re-export of [`crate::path`] (lexical rules for relative paths and roots).
//! - `root` (next step): the only way to open a game or store folder.
//! - `registry` (phase 3): the registry allowlist.

/// Lexical path rules; see [`crate::path`].
pub mod path {
    pub use crate::path::{Anomaly, PathError, RelPath, RootPath, classify, is_deceptive};
}
