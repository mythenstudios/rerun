//! The real system layer on Windows (ADR 0004, ADR 0007, ADR 0008).
//!
//! Phase 1 is **read-only**: [`WinFs`]/[`WinDir`] implement [`Fs`](crate::sys::Fs) and
//! [`Dir`](crate::sys::Dir); every write method returns `Unsupported`
//! ("sys::win is read-only in phase 1"). Registry, known folders, topology and GPU follow in
//! later steps of phase 1; `WinSystem` (the [`System`](crate::sys::System) bundle) arrives
//! once all of them exist.
//!
//! Modules:
//! - `nt`: the only NT/Win32 file calls (`NtCreateFile` through exactly two wrappers,
//!   `NtQueryInformationFile`, `NtQueryDirectoryFile`, `GetFinalPathNameByHandleW`,
//!   `GetVolumeInformationByHandleW`, `DeviceIoControl`), handles as `OwnedHandle`.
//! - `token`: `user_writable` via `AccessCheck` against the non-elevated user's token.
//! - `status`: `NTSTATUS`/Win32 code → `SysErrorKind` (pure).
//! - `name`: single-segment check, L1 long-name check, `volume_path`, `open_dir` input rules,
//!   NT buffer decoding (pure).
//! - `reparse`: `REPARSE_DATA_BUFFER` parser (pure).
//! - `fs`: `WinFs`/`WinDir`, walk, classification, metadata; no `unsafe`.
//!
//! `unsafe` lives only in `nt` and `token`. Path-based Win32 file APIs (`CreateFileW`,
//! `DeleteFileW`, `MoveFileExW`, `GetFileAttributesW`, …) are banned in `clippy.toml`.

mod fs;
mod name;
mod nt;
mod reparse;
mod status;
mod token;

#[cfg(test)]
mod tests;

pub use fs::{WinDir, WinFs};
