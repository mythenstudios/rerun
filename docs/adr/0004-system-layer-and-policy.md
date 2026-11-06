# ADR 0004 · System layer and policy boundary

**Status:** accepted · 2026-11-04

## Context
Primitives must be testable against a fake system (`docs/09-testing.md`) and may touch the real system only in allowed ways (core rules 2–4). It was open how the traits are shaped and where confinement and the allowlist are checked.

## Decision
- `rerun-core::sys` defines `System` with `Fs`, `Registry`, `Topology` (Phase 0), `Firewall` and `Process` from Phase 3. All traits take `&self`, are `Send + Sync` and object-safe; primitives receive `&dyn System`.
- **No `Steam` trait.** Steam is domain logic (`detect::steam`) on top of `Registry`, `Fs` and `Process`.
- `sys` is "dumb and honest": absolute paths, no confinement, no allowlist. **Confinement and the allowlist live in `rerun-core::policy`** and thus apply identically to the fake, the real system and the elevated helper.
- `Fs` never follows reparse points; `metadata` reports them, all other operations through them result in `ReparsePoint`. No `create_dir_all`, `Registry::create_key` requires an existing parent key: every created folder/key is recorded individually in the Journal.
- `sys::snapshot` ignores timestamps and serves the round-trip tests. **Amended 2026-11-06 (P2-5, user decision E4):** it is test code like `sys::contract` and `sys::fake` (`cfg(any(test, feature = "fake"))`), takes root handles (`SnapRoot`) and `&dyn Registry` instead of `&dyn System` and absolute paths, and runs against `sys::win` as well; a folder comparison after a revert in the product would be a new decision.
- `sys::contract` contains contract tests that run against `fake` and (from Phase 1/2, in Windows Sandbox) against `win`.
- `clippy.toml` blocks `std::fs` write operations and `std::process::Command::new` via `disallowed_methods`; exceptions only via `#[allow(…, reason = "…")]`.

## Consequences
- The fake replicates Win32 semantics (case-insensitive with preserved casing, error kinds). Known deviations are listed in `sys/fake/fs.rs`.
- The policy check for reparse points in the real folder (`resolve_confined`) comes in Phase 2, the registry allowlist (`policy::registry`) in Phase 3.
- A new system access means: trait method + fake + contract test, never a direct call.
- ADR 0007 replaces the `Fs` signatures described here: file operations now go through `Dir` relative to a root handle opened by `policy::root`.

## Amendment · 2026-11-05 (phase 2 plan)
- The `resolve_confined` check of the "Consequences" above is superseded by ADR 0007: every component below a root is opened relative to its parent handle and a reparse point is never followed, so no separate confinement check of a resolved path exists or is needed.
- `policy::registry` moves from phase 3 to **phase 2** (audit A1 B2): `registry_set` and `compat_layer` ship in phase 2 and must not write without the allowlist (core rule 4). Its shape, `HKCU` only, and the split of `Registry` into a read trait and `RegistryWrite`: ADR 0018.
- Writing is a capability: `Dir` reads, `DirWrite` and `FileGuard` write (ADR 0017); only `GameDir` and `AppDir` hand out a write handle.
