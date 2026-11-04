# ADR 0008 · Win32 bindings

**Status:** accepted · 2026-11-04 · amended 2026-11-05 (DLL hardening)

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

## Amendment 2026-11-05: DLL hardening of the shipped executables (H2, implemented)

H2 is implemented now (phase 1, step 10) instead of with the helper, so that no shipped binary ever loads a DLL from its own folder, before the first DLL that is not a KnownDLL (`dxgi.dll`) is loaded.

- **Link flag.** The `build.rs` of `rerun-cli` and `rerun-launch` emits `cargo::rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800` when `CARGO_CFG_TARGET_ENV == "msvc"`. The linker writes `0x800` (`LOAD_LIBRARY_SEARCH_SYSTEM32`) into `IMAGE_LOAD_CONFIG_DIRECTORY64::DependentLoadFlags` (offset `0x4E`, winnt.h); the loader then resolves the image's static imports from System32 only (KnownDLLs and API sets are unaffected). Not set for `rerun-cpu` (a DLL loaded into a game; its imports are `kernel32` only, and a DLL's flag would only govern its own static imports) and not for `rerun-workbench` (not shipped). The Tauri app gets the same `build.rs` line in phase 5.
- **Search path.** The first statement of `main` in `rerun` is `rerun_core::sys::win::restrict_dll_search()` (`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`); `rerun-launch` has its own copy of the one call (`src/dll.rs`, it does not depend on `rerun-core`; `windows-sys` with `Win32_System_LibraryLoader` only, ADR 0006 already allows the crate). If the call fails, the binary exits non-zero (fail closed). This removes the application directory, the current directory and `PATH` from every later `LoadLibrary*` of the process, including loads Windows makes on Rerun's behalf.
- **Tests.** `crates/rerun-cli/tests/hardening.rs` and `crates/rerun-launch/tests/hardening.rs` read the built binary (`CARGO_BIN_EXE_*`) with a minimal bounds-checked PE32+ reader (`tests/support/pe_min.rs`, included with `#[path]`; step 13 replaces it with `detect::pe`): `DependentLoadFlags == 0x800`, no static import of `dxgi.dll`, `d3d*`, `dxcore.dll`, `vcruntime*`, `msvcp*`, `ucrtbase*` or `api-ms-win-crt-*`, an empty delay-import table; and the binary runs past the restriction. Found on 2026-11-05 (debug and release, x64): both binaries import only `kernel32.dll`, `ntdll.dll` and `api-ms-win-core-synch-l1-2-0.dll`.
- **Bans** (`clippy.toml`, checked by `sys/win/bans.rs`): `LoadLibraryA`/`W`, `LoadLibraryExA`/`W`, `LoadPackagedLibrary` and `GetProcAddress` outside `sys::win::loader`; `SetDefaultDllDirectories`, `SetDllDirectoryW`/`A`, `AddDllDirectory` and `RemoveDllDirectory` outside `loader::restrict_dll_search` (and `rerun-launch`'s copy).
- **Phase 5 (Tauri app).** `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` also removes the application directory for the app. `WebView2Loader.dll`, which Tauri/wry loads from next to the exe by default, would then not be found: the app must link the WebView2 loader statically (wry's static-loader option) or add exactly its own install directory with `AddDllDirectory` after checking that it is not user-writable (per-machine install). Decided in phase 5; the ban on `AddDllDirectory` makes that a reviewed exception.

### Alternatives (hardening)
- **Delay-load `dxgi.dll`** (`/DELAYLOAD`): keeps the `windows` crate's static style, but the delay-load helper resolves through the same search path and adds a delay-import table the elevated helper must never have; an explicit `LoadLibraryExW(…, LOAD_LIBRARY_SEARCH_SYSTEM32)` is narrower and visible.
- **Only `SetDefaultDllDirectories`, no link flag:** the static imports are resolved before `main` runs, so a planted DLL that shadows a non-KnownDLL import would load anyway.
- **Only the link flag:** covers the static imports, not `LoadLibrary*` calls made later by Windows components (COM, shell, drivers' user-mode parts).

