# ADR 0007 · File operations relative to a root handle

**Status:** proposed · 2026-11-04 · **must be decided before `sys::win` (Phase 1/2)**

## Context
The Phase 0 security review (finding 3) shows: `sys::Fs` takes an absolute `&Path` per call. The check ("no reparse point in the path") and the operation resolve the path separately (TOCTOU). If a Steam library is located in a folder writable by the user (`D:\SteamLibrary`), malware in the user context can replace a subfolder with a junction to `C:\Windows\System32` between the check and the elevated helper's `CreateFileW` (also via Object Manager symlinks). Result: elevated arbitrary file write (scenarios 4, 7 in `06-security.md`).

In addition, the current contract forbids reparse points anywhere in the path. Legitimate roots via junctions (moved library, OneDrive) would fail.

## Proposal
- **Open the root, then work relatively:** `GameRoot` is opened once as a handle and canonicalized via `GetFinalPathNameByHandleW`. All operations go through `NtCreateFile` with `RootDirectory` = handle of the parent folder, component by component with `FILE_OPEN_REPARSE_POINT` or `OBJ_DONT_REPARSE`; afterwards check the final path against the root.
- **Reparse points above the root allowed, below it never.**
- **System folders forbidden as root** (`%windir%`, `%ProgramFiles%\WindowsApps`, profile folder roots …), checked on the canonical path.
- **Writing in the game folder not elevated** if the folder is writable by the user. The helper gets only what really needs admin.
- **Type `CheckedPath`**, which only `policy` can create (root handle + `RelPath`). `Fs` methods for the game folder take `&CheckedPath`, not `&Path`. Absolute paths remain only for Rerun's own folders (`%LOCALAPPDATA%\Rerun`).
- `sys::win` works internally with `\\?\` paths. Names from `read_dir` that are not valid `RelPath` segments (`d3d9.dll.`, `CON`, `x `) are reported as an anomaly and never touched silently (review finding 9).

## Open questions
- Trait shape: split `Fs` (`GameFs` relative, `AppFs` absolute) or one `Fs` with `CheckedPath`?
- How does `sys::fake` replicate handles and the replacement of a folder by a junction between two calls (test for the TOCTOU scenario)?
- Behavior for game folders under `Program Files` (not user-writable, helper required).

## Consequences
- Changes the `Fs` signatures from ADR 0004 before primitives build on them. Therefore decide before Phase 1 `sys::win`, with a security review.
