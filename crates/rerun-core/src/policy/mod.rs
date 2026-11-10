//! Rules above the system layer (ADR 0004, ADR 0007).
//!
//! `sys` executes, `policy` decides what is allowed. That way the same rules apply to the
//! fake and the real system, and the elevated helper revalidates through the same code.
//!
//! - [`path`]: re-export of [`crate::path`] (lexical rules for relative paths and roots).
//! - [`root`]: the only way to open a store or game folder; forbidden roots, root identity.
//! - [`firewall`]: Rerun's own firewall rules: the one rule form and their observation (ADR 0023
//!   §6, P4-5a).
//! - [`ini`]: the bounded INI editor (ADR 0021): dialect, `edit` and `unedit`.
//! - [`registry`]: the registry allowlist and the only way to the registry write side (ADR 0018).
//! - [`url`]: the URL rules of the loader and the downloader: form, provenance, redirects
//!   (docs/02, ADR 0024, ADR 0025).

pub mod firewall;
pub mod ini;
pub mod registry;
pub mod root;
pub mod url;

/// Lexical path rules; see [`crate::path`].
pub mod path {
    pub use crate::path::{Anomaly, PathError, RelPath, RootPath, classify, is_deceptive};
}
