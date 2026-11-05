# ADR 0006 · Release build

**Status:** accepted · 2026-11-04

## Context
`rerun-cpu.asi` runs in old 32- and 64-bit game processes, `rerun-launch.exe` is started by Steam and should stay < 1 MB. Neither may depend on an installed VC++ Redistributable.

## Decision
- `+crt-static` for `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` (`.cargo/config.toml`).
- Release profile: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `debug = "line-tables-only"` (the PDB is not shipped); `opt-level = "s"` for `rerun-launch` and `rerun-cpu`.
- Cargo cannot change the extension: the artifact `rerun_cpu.dll` is copied to `dist/<arch>/rerun-cpu.asi` in the CI step. A packaging script follows with Phase 5/6.
- Toolchain pinned in `rust-toolchain.toml`, MSRV = pinned version. Updates deliberately via commit.

## Consequences
- A panic terminates the process immediately, including the GUI. This is acceptable because the Journal works write-ahead.
- CI checks the size and allowed dependencies of `rerun-launch`, always built with `-p` (otherwise feature unification pulls in `rerun-proto/serde`). The dependency check covers normal dependencies only (`cargo tree -e normal`): since ADR 0013 `rerun-core` is a dev-dependency of `rerun-launch` for its hardening test, which never reaches the shipped binary (the size build with `-p` does not build dev-dependencies).
