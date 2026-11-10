//! Packages (ADR 0025): download into the cache (P4-6); extraction follows in P4-7.
//!
//! - [`download`]: which downloads a package of the signed index has ([`download::downloads`]),
//!   and [`download::fetch`], the one way a package archive reaches `<AppDir>\cache`: over
//!   [`Http`](crate::sys::Http), every redirect checked by `policy::url`, at most
//!   [`download::MAX_DOWNLOAD_BYTES`], hashed while it streams, kept only with the pinned
//!   SHA-256; non-elevated only.

pub mod download;

#[cfg(test)]
mod tests;
