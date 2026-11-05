//! Steam detection (ADR 0012).
//!
//! - [`files`]: typed views of `libraryfolders.vdf` and `appmanifest_<appid>.acf` (ADR 0011).
//! - [`text`]: [`RawText`], untrusted text whose `Debug` shows only its length.
//! - [`state`]: [`StateFlags`] and the derived [`AppState`].
//!
//! Root discovery, opening libraries through `policy::root`, listing the manifests and opening
//! game folders follow in this step.

pub mod files;
pub mod state;
pub mod text;

pub use state::{AppState, StateFlags};
pub use text::RawText;
