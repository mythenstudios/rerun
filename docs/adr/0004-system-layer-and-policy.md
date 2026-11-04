# ADR 0004 · System layer and policy boundary

**Status:** accepted · 2026-11-04

## Context
Primitives must be testable against a fake system (`docs/09-testing.md`) and may touch the real system only in allowed ways (core rules 2–4). It was open how the traits are shaped and where confinement and the allowlist are checked.

## Decision
- `rerun-core::sys` defines `System` with `Fs`, `Registry`, `Topology` (Phase 0), `Firewall` and `Process` from Phase 3. All traits take `&self`, are `Send + Sync` and object-safe; primitives receive `&dyn System`.
- **No `Steam` trait.** Steam is domain logic (`detect::steam`) on top of `Registry`, `Fs` and `Process`.
- `sys` is "dumb and honest": absolute paths, no confinement, no allowlist. **Confinement and the allowlist live in `rerun-core::policy`** and thus apply identically to the fake, the real system and the elevated helper.
- `Fs` never follows reparse points; `metadata` reports them, all other operations through them result in `ReparsePoint`. No `create_dir_all`, `Registry::create_key` requires an existing parent key: every created folder/key is recorded individually in the Journal.
- `sys::snapshot` is generic over `&dyn System` and ignores timestamps. It serves the round-trip tests and later the folder comparison after a revert.
- `sys::contract` contains contract tests that run against `fake` and (from Phase 1/2, in Windows Sandbox) against `win`.
- `clippy.toml` blocks `std::fs` write operations and `std::process::Command::new` via `disallowed_methods`; exceptions only via `#[allow(…, reason = "…")]`.

## Consequences
- The fake replicates Win32 semantics (case-insensitive with preserved casing, error kinds). Known deviations are listed in `sys/fake/fs.rs`.
- The policy check for reparse points in the real folder (`resolve_confined`) comes in Phase 2, the registry allowlist (`policy::registry`) in Phase 3.
- A new system access means: trait method + fake + contract test, never a direct call.
