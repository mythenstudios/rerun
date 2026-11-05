//! Detection of installed games.
//!
//! - [`vdf`]: bounded parser for Valve KeyValues text files and the one reader that takes them
//!   from a store root (ADR 0011).
//! - [`steam`]: Steam (ADR 0012). [`steam::scan()`] finds the Steam root in the registry, its
//!   libraries and their apps, never failing as a whole; typed views of `libraryfolders.vdf`
//!   and `appmanifest_*.acf` in [`steam::files`].
//! - [`pe`]: bounded parser for executables (headers, machine, flags), ADR 0013.
//! - [`exe`]: executable candidates of a game folder (ADR 0014): the bounded walk.
//! - [`text`]: [`text::RawText`], untrusted text whose `Debug` shows only its length (ADR 0012;
//!   shared by every detector since ADR 0013, re-exported as `steam::RawText`).

pub mod exe;
pub mod pe;
pub mod steam;
pub mod text;
pub mod vdf;
