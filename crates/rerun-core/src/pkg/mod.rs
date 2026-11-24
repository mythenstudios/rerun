//! Packages (ADR 0025): download into the cache (P4-6), extraction into the version folder
//! (P4-7).
//!
//! - [`download`]: which downloads a package of the signed index has ([`download::downloads`]),
//!   and [`download::fetch`], the one way a package archive reaches `<AppDir>\cache`: over
//!   [`Http`](crate::sys::Http), every redirect checked by `policy::url`, at most
//!   [`download::MAX_DOWNLOAD_BYTES`], hashed while it streams, kept only with the pinned
//!   SHA-256; non-elevated only.
//! - [`archive`]: Rerun's own bounded zip and tar.gz readers (inflate by `miniz_oxide`): the
//!   whole structure checked before any content, one name rule for every entry, only files and
//!   folders.
//! - [`extract`]: only the files a package names, each with its pinned SHA-256, from the cached
//!   archive (hashed again) into `<AppDir>\packages\<id>\<version>`; non-elevated only.
//! - [`store`]: the store listed (version folders, archives, leftovers, foreign entries) and
//!   exactly what a preview showed removed by file ID (P5-8b); whether a package is used is
//!   `exec::remove_packages`'s rule.

pub mod archive;
pub mod download;
pub mod extract;
pub mod store;

#[cfg(test)]
pub(crate) mod extract_tests;
#[cfg(test)]
mod tests;
