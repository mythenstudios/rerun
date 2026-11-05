//! Steam detection (ADR 0012).
//!
//! - [`files`]: typed views of `libraryfolders.vdf` and `appmanifest_<appid>.acf` (ADR 0011).
//! - [`text`]: [`RawText`], untrusted text whose `Debug` shows only its length.
//! - [`state`]: [`StateFlags`] and the derived [`AppState`].
//! - [`issue`]: [`Issue`], what the scan reports instead of failing.
//! - [`root`]: the Steam root from the registry ([`RootSource`]).
//!
//! Opening libraries through `policy::root`, listing the manifests and opening game folders
//! follow in this step.

pub mod files;
pub mod issue;
pub mod root;
pub mod state;
pub mod text;

#[cfg(test)]
mod testfx;

pub use issue::{BadValue, Issue, IssueKind, Location};
pub use root::RootSource;
pub use state::{AppState, StateFlags};
pub use text::RawText;
