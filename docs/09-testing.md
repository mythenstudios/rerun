# 09 · Testing

## Levels

1. **Unit** – pure logic (parsers, CPU selection, `when` evaluation, plan building). Fast, without a system.
2. **Primitive against `sys::fake`** – round trip, idempotence, crash, tampering, path escape. Required for every primitive.
3. **Windows Sandbox** – real Win32 calls (registry, firewall, IFEO, Job Objects) in a disposable environment. Tests with `#[ignore]`, script `scripts/sandbox-test.wsb`.
4. **Real hardware, manual** – launch games, post-launch check, revert, folder comparison.

## Round-trip contract

```
before = sys::snapshot::snapshot(&sys, &scope)
plan → apply → verify == Ok
revert
assert_eq!(snapshot(&sys, &scope), before)   // on mismatch: before.diff(&after)
```

"Identical" means: existence, kind, casing, content (SHA-256), length, attributes (read-only, hidden, system), hard link count, reparse tag and link target; for the registry: keys, value names, value type and value. Names that fail `policy::path::classify`, entries of case-sensitive directories and names that fold to the same key are recorded as anomalies (metadata only, never opened). Cloud placeholders are recorded without a hash (no hydration), the attributes of a scope root itself are not captured, and nesting deeper than 64 directories is an error. Each scope directory is opened once by absolute path and walked through `Dir` handles (ADR 0007). **Timestamps and file IDs do not count** (restored backups have a new mtime and ID). An empty key is different from a missing one. `snapshot` is generic over `&dyn System` and also runs in the sandbox.

`scope` covers the game folder (hashes), affected registry keys, firewall rules with the Rerun prefix, IFEO keys, Steam launch option.

## Contract tests of the system layer

`rerun_core::sys::contract` checks the semantics of the traits against `sys::fake` and `sys::win`.

- **File system contract on real Windows runs in CI and locally** in a fresh temporary directory under `target/` (decided 2026-11-04). It creates its own junctions there (no admin needed) and touches nothing outside that directory: no registry, no firewall, no game folders. File symlinks need Developer Mode or admin; those cases skip with a message when the privilege is missing. Required safeguards:
  1. The test root is created new and uniquely named under the canonical `target/` directory. The test canonicalizes it and panics unless it is inside `target/`, on a local fixed drive, not a reparse point and not under a cloud/OneDrive tag.
  2. Junction targets stay inside the test root. The escape target is a sibling `outside/` folder with a canary file whose content is asserted unchanged.
  3. Cleanup only after re-checking (1), handle-based and never following links.
  4. Locally the test skips when the process is elevated. On GitHub-hosted runners (admin, ephemeral VM) it runs.
  5. No registry, `%TEMP%` or home-directory paths. The test-only root constructor is gated (`cfg(test)`/`fake` feature) and does not bypass the forbidden-root checks for anything else.
- **Known folders and GPU contracts** (`known_folders_contract`, `gpu_contract`) only read, so they run against `sys::win` in CI and locally. The fake sets the known folders with `FakeSystemBuilder::known_folder`, creates their directories with `windows_layout()` and adds adapters with `gpu()`; its default has no adapter, which no real machine reports.
- **Registry, firewall, IFEO and anything outside the temp directory** run only in Windows Sandbox as `#[ignore]` tests.
- **TOCTOU:** the fake has test hooks that run between two path components of an operation, so a test can swap a directory for a junction mid-operation (ADR 0007). On `sys::win` the swap between two calls is tested. If the fake deviates from the real system, the contract is extended first, then the fake is adjusted. Known, deliberate deviations are listed in `sys/fake/fs.rs`.
- **`policy::root`** (`policy/root/tests.rs`, fake only): every forbidden-list entry with its exact reason, component-wise matching, relocated and junctioned known folders, fail-closed resolution (each missing folder, files, shares, short names), a junction at `steamapps`, `common` or the game level, a swap to a junction mid-walk (hook on the game segment) with a canary in an admin-only folder, swap after open, and identity mismatch after a folder is replaced.

The fake layer is available to other crates via the `fake` feature of `rerun-core`.

## Schema and parity tests

`crates/rerun-core/tests/schema.rs` checks: schemas against the metaschema, shared `$defs` identical, all `topos/` and `packages/` valid, file name = `id`, package references resolvable, `TODO` ⇒ `draft`, `tests/fixtures/schema/valid/*` valid and **every** file in `tests/fixtures/schema/invalid/*` invalid (a comment in the first line states the reason). Whether an invalid fixture fails for the right reason: `RERUN_SHOW_SCHEMA_ERRORS=1 cargo test -p rerun-core --test schema -- --nocapture`.

Parity: `tests/fixtures/paths.json` runs against `RelPath::parse` **and** `$defs/relPath`; both must decide the same way.

## CPU fixtures

See `03-cpu-topology.md`. Every rule against every fixture; expected masks as snapshot tests.

## Manual test matrix (continuously extended)

| Game | Store | Checks | Hardware | Status |
|---|---|---|---|---|
| Far Cry 2 | Steam | core limit, `direct` | 5950X / RX 9070 XT | open |
| Assassin's Creed DC | Steam | Ubisoft chain, `watch`, EaglePatch + ASI Loader, revert | 5950X / RX 9070 XT | open |
| LEGO City Undercover | Steam | Special K local, slot conflict with DXVK | 5950X / RX 9070 XT | open |
| a DirectDraw game | GOG | dgVoodoo 2 / dxwrapper, heuristic | 5950X / RX 9070 XT | open |

## Rules

- No test modifies the real system outside the sandbox.
- Bugs: failing test first, then the fix.
- Fixtures are data, not code generators. **Exception:** PE test files are built by a small builder in test code (`tests/support`), because third-party binaries must not be committed and hand-written binary fixtures cannot be reviewed.
