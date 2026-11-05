//! Detection of installed games.
//!
//! - [`vdf`]: bounded parser for Valve KeyValues text files and the one reader that takes them
//!   from a store root (ADR 0011).
//! - [`steam`]: Steam. Typed views of `libraryfolders.vdf` and `appmanifest_*.acf`
//!   ([`steam::files`]); root discovery and library walking follow in step 12.

pub mod steam;
pub mod vdf;
