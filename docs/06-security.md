# 06 · Threat model

## What we protect

The user's system (files outside the game folder, registry, firewall, autostart) and the trust that Rerun only does what the preview shows.

## Attackers and scenarios

| # | Scenario | Countermeasure |
|---|---|---|
| 1 | Malicious Topo in the community repo | Purely declarative format, no execute primitive, launch options only as game arguments after `%command%`, INI values without line breaks/paths, download URLs bound to the original source, schema validation, review via PR, signed index |
| 2 | Compromised GitHub repo / index replaced | Ed25519 signature, key offline, public key in the binary |
| 3 | Upstream release replaced | Pinned SHA256 in the package, check before extraction |
| 4 | Path escape (`..`, absolute paths, junctions, ADS, UNC, `CON`, Unicode lookalikes) | `RelPath` and `RootPath` lexically strict; all file operations relative to a root handle opened by `policy::root`, never follow junctions or symlinks below the root, forbidden roots from known folders, never environment variables (Windows, Program Files itself, profile roots, other users' profiles, per-volume system folders; a root may neither lie in nor contain a protected folder; the list fails closed), no network or volume roots, a game folder from a store is opened handle-relative so a junction at game level is an anomaly, root identity re-checked before every apply and revert, hard links never changed in place, invalid names on disk reported and never touched (ADR 0007) |
| 5 | Zip Slip during extraction | Check every entry individually, never extract blindly |
| 6 | Registry abuse | Allowlist of keys, previous value to the Journal |
| 7 | TOCTOU between preview and elevation | The plan hash only catches accidents; the boundary is the helper's own re-validation: it treats the plan as untrusted, only writes into roots that only admins can write and that contain the topo's target exe with the signed hash, verifies index signature and package hashes itself, and opens its root by volume GUID path + file ID; root identity (volume serial + file ID) is checked on every apply and revert (ADR 0007). Helper process hardening: ADR 0008. DLL planting next to a Rerun executable (a user-writable install folder): every shipped executable is linked with `/DEPENDENTLOADFLAG:0x800` (static imports from System32 only) and restricts its DLL search path to System32 as the first statement of `main`, failing closed; tests check the built PE (ADR 0008 amendment 2026-11-05) |
| 8 | Wrong exe targeted (same name) | Identification via path + hash; IFEO with `FilterFullPath` |
| 9 | Revert deletes foreign/modified files | Delete only if the hash matches, otherwise ask |
| 10 | Crash in the middle of apply | Write-ahead Journal, revert also works with incomplete entries |
| 11 | Rerun itself perceived as malware | Code signing, no injection, IFEO opt-in only, transparent preview |

## Principles

- The GUI never runs elevated. Admin only in the helper, per apply, with a validated plan.
- Network only to the Topo index and package hosts from `packages/`. No telemetry.
- `unsafe` minimal, commented, encapsulated in `sys::win`, `rerun-launch` and `rerun-cpu`.
- Dependencies checked with `cargo deny` (licenses, advisories, crates.io only, no OpenSSL) in CI.
- **Policy boundary (ADR 0004):** `sys` executes, `policy` decides. Confinement (`policy::path::RelPath`) and the registry allowlist (from Phase 3 `policy::registry`) sit above `sys` and apply equally to the fake, the real system and the elevated helper.
- **No system access bypassing `sys`:** `clippy.toml` blocks `std::fs` write operations and `std::process::Command::new` (`disallowed_methods = deny`). Exceptions only with `#[allow(…, reason = "…")]` in `sys::win` and `rerun-launch`.
- **No path-based Win32 file APIs:** `clippy.toml` also blocks `CreateFileW`, `DeleteFileW`, `MoveFileExW`, `ReplaceFileW`, `CopyFile*`, `GetFileAttributesW`, `GetNamedSecurityInfoW`, `DefineDosDeviceW` and the other path-based file APIs of `windows-sys`, plus `NtOpenFile`. `NtCreateFile` is fenced to the two wrappers `sys::win::nt::{open_relative, open_absolute_dir}`, which fix the flags (`OBJ_DONT_REPARSE` and `FILE_OPEN_REPARSE_POINT` for every relative open, `FILE_OPEN` only, never `FILE_OPEN_FOR_BACKUP_INTENT`); ADR 0007, amendment "sys::win read side".
- **Registry only through `sys::win::reg`** (ADR 0009): `clippy.toml` blocks every other advapi32, ntdll and shlwapi registry call (writes, legacy and ANSI variants, reads that fix up or expand values, hive loading, predefined-key overrides, transactions, `NtOpenKey*` and the other bypasses), DACL writes by handle (`SetSecurityInfo`, `SetKernelObjectSecurity`, `NtSetSecurityObject`), and every environment-based path source including `GetTempPath*`. `sys/win/bans.rs` makes each `windows-sys` entry fail clippy if it does not resolve.
- **DLL loading** (ADR 0008 amendment 2026-11-05): the static imports of every shipped executable are an exact, tested allowlist (no graphics DLL, no dynamic CRT), no delay-load imports, no hand-written `extern` block, `#[link]` or `raw-dylib` anywhere (source rule test); dynamic loads only through `sys::win::loader` (System32, bare name); `LoadLibrary*`, `GetProcAddress` and every DLL search path call (`SetDefaultDllDirectories`, `SetDllDirectory*`, `AddDllDirectory`, `RemoveDllDirectory`) are `clippy.toml` bans outside it. GPU data only through the hand-written DXGI binding `sys::win::dxgi` (the `D3DKMT*` adapter APIs are banned), never in the elevated helper; COM activation (`CoCreateInstance*`, `CoGetClassObject`, `CoGetObject`, `CoInitialize*`) is banned until phase 3 gives it one wrapper with `CLSCTX_INPROC_SERVER` only.
- **CI supply chain:** GitHub Actions pinned by commit SHA, `permissions: contents: read`, toolchain pinned in `rust-toolchain.toml`, `Cargo.lock` committed and `--locked`.

## Allowed registry areas (initial list)

- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` (value = path of the game exe)
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` (only `PerfOptions\CpuPriorityClass`, `Debugger`, `UseFilter`, filter subkeys)
- Game-specific keys that are explicitly named in the Topo and approved in review
