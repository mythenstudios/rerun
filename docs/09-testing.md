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

"Identical" means: existence, kind, casing, content (SHA-256), length and read-only flag; for the registry: keys, value names, value type and value. **Timestamps do not count** (restored backups have a new mtime). An empty key is different from a missing one. `snapshot` is generic over `&dyn System` and also runs in the sandbox.

`scope` covers the game folder (hashes), affected registry keys, firewall rules with the Rerun prefix, IFEO keys, Steam launch option.

## Contract tests of the system layer

`rerun_core::sys::contract` (`fs_contract`, `registry_contract`, `topology_contract`) checks the semantics of the traits. Today against `sys::fake`, from Phase 1/2 as `#[ignore]` tests in Windows Sandbox against `sys::win`. If the fake deviates from the real system, the contract is extended first, then the fake is adjusted. Known, deliberate deviations are listed in `sys/fake/fs.rs`.

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
- Fixtures are data, not code generators.
