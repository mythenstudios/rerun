//! The real system layer on Windows (ADR 0004, ADR 0007, ADR 0008, ADR 0009).
//!
//! Phase 1 is **read-only**: [`WinFs`]/[`WinDir`] implement [`Fs`](crate::sys::Fs) and
//! [`Dir`](crate::sys::Dir); every write method returns `Unsupported`
//! ("sys::win is read-only in phase 1"). [`WinKnownFolders`] implements
//! [`KnownFolders`](crate::sys::KnownFolders). Registry, topology and GPU follow in later
//! steps of phase 1; `WinSystem` (the [`System`](crate::sys::System) bundle) arrives once all
//! of them exist.
//!
//! Modules:
//! - `nt`: the only NT/Win32 file calls (`NtCreateFile` through exactly two wrappers,
//!   `NtQueryInformationFile`, `NtQueryDirectoryFile`, `GetFinalPathNameByHandleW`,
//!   `GetVolumeInformationByHandleW`, `DeviceIoControl`), handles as `OwnedHandle`.
//! - `token`: `user_writable` via `AccessCheck` against the non-elevated user's token.
//! - `shell`: the only calls to `SHGetKnownFolderPath` (with the process token, freed with
//!   `CoTaskMemFree`) and `GetSystemWindowsDirectoryW`.
//! - `status`: `NTSTATUS`/Win32 code → `SysErrorKind` (pure).
//! - `name`: single-segment check, L1 long-name check, `volume_path`, `open_dir` input rules,
//!   NT buffer decoding (pure).
//! - `reparse`: `REPARSE_DATA_BUFFER` parser (pure).
//! - `fs`: `WinFs`/`WinDir`, walk, classification, metadata; no `unsafe`.
//! - `known_folders`: `WinKnownFolders`, the source of each folder, `ProfileList` expansion;
//!   no `unsafe`, never the environment.
//!
//! `unsafe` lives only in `nt`, `token` and `shell`. Path-based Win32 file APIs
//! (`CreateFileW`, `DeleteFileW`, `MoveFileExW`, `GetFileAttributesW`, …) and every
//! environment-based path source (`std::env::var`, `GetEnvironmentVariableW`,
//! `ExpandEnvironmentStringsW`, `SHGetFolderPathW`, `GetWindowsDirectoryW`, …) are banned in
//! `clippy.toml`.
//!
//! Test only: `testfx` (test root with the `docs/09-testing.md` safeguards, the `FsFixture`
//! for real Windows, the naive control `Fs`, a read-only `HKLM` reader for
//! `WinKnownFolders`; path-based calls and `unsafe` FFI allowed there), `tests` (smoke tests
//! and the contract runners) and `bans` (every banned `windows-sys` and `std::env` item of
//! `clippy.toml` must resolve, else clippy fails).

mod fs;
mod known_folders;
mod name;
mod nt;
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
