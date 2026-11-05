//! Steam detection (ADR 0012).
//!
//! - [`files`]: typed views of `libraryfolders.vdf` and `appmanifest_<appid>.acf` (ADR 0011).
//! - [`text`]: [`RawText`], untrusted text whose `Debug` shows only its length.
//! - [`state`]: [`StateFlags`] and the derived [`AppState`].
//! - [`issue`]: [`Issue`], what the scan reports instead of failing.
//! - [`root`]: the Steam root from the registry ([`RootSource`]).
//! - [`library`]: the library list, opening libraries through `policy::root` and reading their
//!   manifests ([`SteamLibrary`], [`SteamApp`]); game folders through
//!   [`SteamLibrary::open_game`].
//! - [`scan`](mod@scan): [`scan()`], the whole scan ([`SteamScan`]), never failing as a whole.

pub mod files;
pub mod issue;
pub mod library;
pub mod root;
pub mod scan;
pub mod state;
pub mod text;

#[cfg(test)]
mod testfx;

pub use issue::{BadValue, Issue, IssueKind, Location};
pub use library::{MAX_LIBRARIES, MAX_MANIFESTS, SteamApp, SteamLibrary};
pub use root::RootSource;
pub use scan::{SteamScan, scan};
pub use state::{AppState, StateFlags};
pub use text::RawText;
