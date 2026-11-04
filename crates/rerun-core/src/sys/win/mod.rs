//! The real system layer on Windows (ADR 0004, ADR 0007, ADR 0008, ADR 0009).
//!
//! Phase 1 is **read-only**: [`WinFs`]/[`WinDir`] implement [`Fs`](crate::sys::Fs) and
//! [`Dir`](crate::sys::Dir); every write method returns `Unsupported`
//! ("sys::win is read-only in phase 1"). [`WinRegistry`] implements
//! [`Registry`](crate::sys::Registry), equally read-only. [`WinKnownFolders`] implements
//! [`KnownFolders`](crate::sys::KnownFolders). Topology and GPU follow in later steps of
//! phase 1; `WinSystem` (the [`System`](crate::sys::System) bundle) arrives once all of them
//! exist.
//!
//! Modules:
//! - `nt`: the only NT/Win32 file calls (`NtCreateFile` through exactly two wrappers,
//!   `NtQueryInformationFile`, `NtQueryDirectoryFile`, `GetFinalPathNameByHandleW`,
//!   `GetVolumeInformationByHandleW`, `DeviceIoControl`), handles as `OwnedHandle`.
//! - `token`: `user_writable` via `AccessCheck` against the non-elevated user's token.
//! - `shell`: the only calls to `SHGetKnownFolderPath` (with the process token, freed with
//!   `CoTaskMemFree`) and `GetSystemWindowsDirectoryW`.
//! - `reg`: the only registry calls (`RegOpenCurrentUser`, `RegOpenKeyExW`, `RegEnumKeyExW`,
//!   `RegQueryInfoKeyW`, `RegCloseKey`; values with `NtQueryValueKey`/`NtEnumerateValueKey`,
//!   because the Win32 value reads fix up strings), key handles as `OwnedKey`.
//! - `status`: `NTSTATUS`/Win32 code → `SysErrorKind`, for files and the registry (pure).
//! - `name`: single-segment check, L1 long-name check, `volume_path`, `open_dir` input rules,
//!   NT buffer decoding (pure).
//! - `reparse`: `REPARSE_DATA_BUFFER` parser (pure).
//! - `fs`: `WinFs`/`WinDir`, walk, classification, metadata; no `unsafe`.
//! - `known_folders`: `WinKnownFolders`, the source of each folder, `ProfileList` expansion;
//!   no `unsafe`, never the environment.
//! - `registry`: `WinRegistry`, input rules, limits, retries and enumeration restarts; no
//!   `unsafe`.
//!
//! `unsafe` lives only in `nt`, `token`, `reg` and `shell`. Path-based Win32 file APIs
//! (`CreateFileW`, `DeleteFileW`, `MoveFileExW`, `GetFileAttributesW`, …) and every
//! environment-based path source (`std::env::var`, `GetEnvironmentVariableW`,
//! `ExpandEnvironmentStringsW`, `SHGetFolderPathW`, `GetWindowsDirectoryW`, …) are banned in
//! `clippy.toml`, as is every registry API outside `reg` (legacy, ANSI, writes, hive loading,
//! predefined-key overrides, transactions).
//!
//! Test only: `testfx` (test root with the `docs/09-testing.md` safeguards, the `FsFixture`
//! for real Windows, the naive control `Fs`, the private app hive that is the `RegFixture`;
//! path-based calls, registry writes to that hive and `unsafe` FFI allowed there), `tests`
//! (smoke tests and the contract runners) and `bans` (every banned `windows-sys` and
//! `std::env` item of `clippy.toml` must resolve, else clippy fails).

mod fs;
mod known_folders;
mod name;
mod nt;
mod reg;
mod registry;
mod reparse;
mod shell;
mod status;
mod token;

#[cfg(test)]
mod bans;

#[cfg(test)]
mod testfx;

#[cfg(test)]
mod tests;

pub use fs::{WinDir, WinFs};
pub use known_folders::WinKnownFolders;
pub use registry::WinRegistry;
