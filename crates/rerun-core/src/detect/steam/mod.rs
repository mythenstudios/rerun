//! Steam detection.
//!
//! - [`files`]: typed views of `libraryfolders.vdf` and `appmanifest_<appid>.acf` (ADR 0011).
//!
//! Step 12 adds the Steam root discovery, opening libraries through `policy::root`, listing
//! the manifests and opening game folders.

pub mod files;
