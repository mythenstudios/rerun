//! The real system layer on Windows (ADR 0004, ADR 0007, ADR 0008, ADR 0009).
//!
//! Phase 1 is **read-only**: [`WinFs`]/[`WinDir`] implement [`Fs`](crate::sys::Fs) and
//! [`Dir`](crate::sys::Dir); every write method returns `Unsupported`
//! ("sys::win is read-only in phase 1"). [`WinRegistry`] implements
//! [`Registry`](crate::sys::Registry), equally read-only. [`WinKnownFolders`] implements
//! [`KnownFolders`](crate::sys::KnownFolders), [`WinTopology`] implements
//! [`Topology`](crate::sys::Topology) (ADR 0010). The GPU follows in a later step of phase 1;
//! `WinSystem` (the [`System`](crate::sys::System) bundle) arrives once all of them exist.
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
//!   because the Win32 value reads fix up strings; `NtQueryKey` for key names), key handles
//!   as `OwnedKey`.
//! - `cpu`: the only calls to `GetSystemCpuSetInformation` (system-wide, `Process = NULL`) and
//!   `GetLogicalProcessorInformationEx(RelationAll)`: size query, `u64`-aligned buffer, at most
//!   4 retries, 1 MiB cap; the bytes go unchanged to `rerun_proto::cpu::CpuTopology::
//!   from_windows`.
//! - `topology`: `WinTopology`, error mapping; no `unsafe`.
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
//! `unsafe` lives only in `nt`, `token`, `reg`, `shell` and `cpu`. Path-based Win32 file APIs
//! (`CreateFileW`, `DeleteFileW`, `MoveFileExW`, `GetFileAttributesW`, …) and every
//! environment-based path source (`std::env::var`, `GetEnvironmentVariableW`,
//! `ExpandEnvironmentStringsW`, `SHGetFolderPathW`, `GetWindowsDirectoryW`, …) are banned in
//! `clippy.toml`, as is every registry API outside `reg` (legacy, ANSI, writes, hive loading,
//! predefined-key overrides, transactions), as are both topology APIs outside `cpu`, every other
//! processor-count source (`GetSystemInfo`, `GetLogicalProcessorInformation`, the processor
//! count APIs, `NtQuerySystemInformation`, `std::thread::available_parallelism`) and every
//! affinity and CPU Set setter until phase 3 (ADR 0010).
//!
//! Test only: `testfx` (test root with the `docs/09-testing.md` safeguards, the `FsFixture`
//! for real Windows, the naive control `Fs`, the private app hive that is the `RegFixture`;
//! path-based calls, registry writes to that hive and `unsafe` FFI allowed there), `tests`
//! (smoke tests and the contract runners) and `bans` (every banned `windows-sys` and
//! `std::env` item of `clippy.toml` must resolve, else clippy fails).

// A 32-bit (WOW64) process gets the x86 folders for `FOLDERID_ProgramFiles` and
// `FOLDERID_ProgramFilesCommon`, and the file system redirector moves `System32`; the forbidden
// list and the registry views assume a native 64-bit process. Only `rerun-cpu` (no dependency on
// `rerun-core`) is built for i686.
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "rerun-core's sys::win needs a 64-bit Windows target: a 32-bit process would see the x86 \
     Program Files folders and redirected system paths"
);

mod cpu;
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
mod topology;

#[cfg(test)]
mod bans;

#[cfg(test)]
mod testfx;

#[cfg(test)]
mod tests;

pub use fs::{WinDir, WinFs};
pub use known_folders::WinKnownFolders;
pub use registry::WinRegistry;
pub use topology::WinTopology;
