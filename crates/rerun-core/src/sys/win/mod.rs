//! The real system layer on Windows (ADR 0004, ADR 0007, ADR 0008, ADR 0009).
//!
//! [`WinFs`]/[`WinDir`] implement [`Fs`](crate::sys::Fs), [`Dir`](crate::sys::Dir) and
//! [`DirWrite`](crate::sys::DirWrite) (the write side of ADR 0017: the sequences of
//! `sys::seq` over the primitives in `fs::prim`). [`WinRegistry`] implements
//! [`Registry`](crate::sys::Registry) and [`RegistryWrite`](crate::sys::RegistryWrite) (the
//! sequences of `sys::seq::reg` over the primitives in `registry`, ADR 0018). [`WinKnownFolders`] implements
//! [`KnownFolders`](crate::sys::KnownFolders), [`WinTopology`] implements
//! [`Topology`](crate::sys::Topology) (ADR 0010), [`WinGpu`] implements
//! [`Gpu`](crate::sys::Gpu) (DXGI, ADR 0008 amendment), and [`WinSystem`] bundles them into
//! the real [`System`](crate::sys::System).
//!
//! Modules:
//! - `nt`: the only NT/Win32 file calls (`NtCreateFile` through exactly two calls, the
//!   absolute directory open and the relative one behind `open_relative` and
//!   `open_self_for_flush`,
//!   `NtQueryInformationFile`, `NtQueryDirectoryFile`, `NtSetInformationFile` through one
//!   wrapper with three classes, `NtFlushBuffersFileEx`, `GetFinalPathNameByHandleW`,
//!   `GetVolumeInformationByHandleW`, `DeviceIoControl`), handles as `OwnedHandle`.
//! - `token`: `user_writable` via `AccessCheck` against the non-elevated user's token, and
//!   `TokenElevation` for the registry write side (S2).
//! - `shell`: the only calls to `SHGetKnownFolderPath` (with the process token, freed with
//!   `CoTaskMemFree`) and `GetSystemWindowsDirectoryW`.
//! - `reg`: the only registry calls (`RegOpenCurrentUser`, `RegOpenKeyExW`, `RegEnumKeyExW`,
//!   `RegQueryInfoKeyW`, `RegCloseKey`; values with `NtQueryValueKey`/`NtEnumerateValueKey`,
//!   because the Win32 value reads fix up strings; `NtQueryKey` for key names and flags; the
//!   write side of ADR 0018: `RegOpenKeyExW`/`RegCreateKeyExW` of one segment with
//!   `REG_OPTION_OPEN_LINK`, `NtSetValueKey`, `NtDeleteValueKey`, `NtDeleteKey`, `RegFlushKey`),
//!   key handles as `OwnedKey`.
//! - `loader`: the only call to `SetDefaultDllDirectories` ([`restrict_dll_search`], ADR 0008,
//!   H2), the first statement of `rerun.exe`'s `main`; the only `LoadLibraryExW` (bare name,
//!   System32 only, never freed) and `GetProcAddress`.
//! - `cpu`: the only calls to `GetSystemCpuSetInformation` (system-wide, `Process = NULL`) and
//!   `GetLogicalProcessorInformationEx(RelationAll)`: size query, `u64`-aligned buffer, at most
//!   4 retries, 1 MiB cap; the bytes go unchanged to `rerun_proto::cpu::CpuTopology::
//!   from_windows`.
//! - `topology`: `WinTopology`, error mapping; no `unsafe`.
//! - `dxgi`: the only DXGI calls, a hand-written binding on `windows-sys` types (`windows-sys`
//!   has no DXGI): `DXGI_ADAPTER_DESC1`, vtable prefixes of `IDXGIFactory1`/`IDXGIAdapter1`
//!   (layout and slot tests against `dxgi.h`), a `Com` guard that releases on drop;
//!   `dxgi.dll` from System32 through `loader`, `CreateDXGIFactory1` cached, a fresh factory
//!   per enumeration, at most 64 adapters.
//! - `gpu`: `WinGpu`, name/LUID/driver-version mapping and error mapping; no `unsafe`.
//! - `system`: `WinSystem`; no `unsafe`.
//! - `status`: `NTSTATUS`/Win32 code → `SysErrorKind`, for files and the registry (pure).
//! - `name`: single-segment check, L1 long-name check, `volume_path`, `open_dir` input rules,
//!   NT buffer decoding (pure).
//! - `reparse`: `REPARSE_DATA_BUFFER` parser (pure).
//! - `fs`: `WinFs`/`WinDir`, walk, classification, metadata; `fs::prim` the write
//!   primitives (`PrimDir`, `PrimFile`, ADR 0017 A1); no `unsafe`.
//! - `known_folders`: `WinKnownFolders`, the source of each folder, `ProfileList` expansion;
//!   no `unsafe`, never the environment.
//! - `registry`: `WinRegistry`, input rules, limits, retries and enumeration restarts, and the
//!   write primitives of `sys::seq::reg` (`WinKey`, ADR 0018); no `unsafe`.
//!
//! `unsafe` lives only in `nt`, `token`, `reg`, `shell`, `cpu`, `loader` and `dxgi`. Path-based Win32 file APIs
//! (`CreateFileW`, `DeleteFileW`, `MoveFileExW`, `GetFileAttributesW`, …) and every
//! environment-based path source (`std::env::var`, `GetEnvironmentVariableW`,
//! `ExpandEnvironmentStringsW`, `SHGetFolderPathW`, `GetWindowsDirectoryW`, …) are banned in
//! `clippy.toml`, as is every registry API outside `reg` (legacy, ANSI, writes, hive loading,
//! predefined-key overrides, transactions), as are both topology APIs outside `cpu`, every other
//! processor-count source (`GetSystemInfo`, `GetLogicalProcessorInformation`, the processor
//! count APIs, `NtQuerySystemInformation`, `std::thread::available_parallelism`) and every
//! affinity and CPU Set setter until phase 3 (ADR 0010), and every DLL search path change and
//! dynamic load (`SetDefaultDllDirectories`, `SetDllDirectoryW`, `AddDllDirectory`,
//! `LoadLibrary*`, `GetProcAddress`) outside `loader`, every DXGI/DXCore/D3DKMT entry point
//! outside `dxgi` and every COM activation call until phase 3 (ADR 0008).
//!
//! Test only: `testfx` (test root with the `docs/09-testing.md` safeguards, the `FsFixture`
//! for real Windows, the naive control `Fs`, the private app hive that is the `RegFixture`,
//! where a module was loaded from, the `RtlGetVersion` cross-check of `hw::os` (ADR 0015);
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
mod dxgi;
mod fs;
mod gpu;
mod known_folders;
mod loader;
mod name;
mod nt;
mod reg;
mod registry;
mod reparse;
mod shell;
mod status;
mod system;
mod token;
mod topology;

#[cfg(test)]
mod bans;

#[cfg(test)]
mod testfx;

#[cfg(test)]
mod tests;

pub use fs::{WinDir, WinFs};
pub use gpu::WinGpu;
pub use known_folders::WinKnownFolders;
pub use loader::restrict_dll_search;
pub(crate) use registry::WinRegistry;
pub use system::WinSystem;
pub use topology::WinTopology;
