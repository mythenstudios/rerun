# ADR 0008 · Win32 bindings

**Status:** accepted · 2026-11-04

## Context
Phase 1 needs NT file APIs (`NtCreateFile`), registry, CPU sets, version info and GPU enumeration. Phase 3 needs Job Objects, IFEO and the firewall COM interface (`INetFwPolicy2`). `rerun-launch` and `rerun-cpu` must stay small (ADR 0006). `windows-sys` 0.61 no longer contains COM interfaces such as DXGI.

## Decision
- **`windows-sys`** (Microsoft, MIT OR Apache-2.0, depends only on `windows-link`) for all plain Win32/NT functions in every crate, with only the features that are used.
- **`windows`** (Microsoft, MIT OR Apache-2.0) **only in `rerun-core`**, only for COM: DXGI now (`Win32_Graphics_Dxgi`), the firewall COM interface in Phase 3. It pulls about nine `windows-*` crates; acceptable for the core, not for `rerun-launch`/`rerun-cpu`.
- All `unsafe` stays in `sys::win` (and later `rerun-launch`, `rerun-cpu`), each block with a `// SAFETY:` comment. Handles are wrapped in `std::os::windows::io::OwnedHandle`; file I/O goes through `std::fs::File::from(OwnedHandle)`.

## Alternatives
- Hand-written COM vtables on `windows-sys`: no extra crates, but vtable order and reference counting become our risk.
- `D3DKMTEnumAdapters2`/`D3DKMTQueryAdapterInfo` via `windows-sys` for the GPU: no COM, but a less common WDK thunk API; does not help with the firewall in Phase 3.

### Hardening of the elevated helper (from the security review, H2)
`windows`/`windows-sys` import DLLs directly; a DLL that is not a KnownDLL (such as `dxgi.dll`) would first be loaded from the application directory. If that directory is user-writable (Tauri's default per-user install under `%LOCALAPPDATA%\Programs`), malware could plant a DLL or replace the executable and get elevated code execution. Therefore:
- Every Rerun executable is linked with `/DEPENDENTLOADFLAG:0x800` (load dependencies from System32 only) and calls `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` first thing.
- The elevated code path uses no COM/DXGI; GPU code is only reachable from non-elevated commands (delay-loaded or in a separate binary, decided in Phase 3).
- At startup the helper refuses to run if its own image directory is writable by any principal other than SYSTEM, Administrators or TrustedInstaller. Elevated features therefore require a per-machine install (Phase 5).
- The helper removes `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege` and `SeDebugPrivilege` from its token at startup.
- COM in the elevated helper uses `CLSCTX_INPROC_SERVER` only (Windows ignores per-user COM registrations for elevated processes).

## Consequences
- `cargo deny` covers the extra crates; the CI dependency check for `rerun-launch` stays (`windows-sys` and `rerun-proto` only).
- `windows-core` pulls the proc-macro crates `windows-implement`/`windows-interface` plus `syn`/`quote`, i.e. code that runs at build time. `windows` features are kept minimal; duplicate `windows-sys`/`windows-targets` versions are watched in `cargo deny` (bans: `multiple-versions = "warn"`).
