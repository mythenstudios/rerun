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

"Identical" means: existence, kind, casing, content (SHA-256), length, attributes (read-only, hidden, system), hard link count, reparse tag and link target; for the registry: keys, value names, value type and value. Names that fail `policy::path::classify`, entries of case-sensitive directories and names that fold to the same key are recorded as anomalies (metadata only, never opened). Restricted entries (their DACL denies the current user every open, `Metadata.restricted`) are recorded from the listing with kind, length, attributes, reparse tag and the restricted flag; never opened, hashed or descended into, and their unknown link count does not count. Cloud placeholders are recorded without a hash (no hydration), the attributes of a scope root itself are not captured, and nesting deeper than 64 directories is an error. Each scope directory is opened once by absolute path and walked through `Dir` handles (ADR 0007). **Timestamps and file IDs do not count** (restored backups have a new mtime and ID). An empty key is different from a missing one. `snapshot` is generic over `&dyn System` and also runs in the sandbox.

`scope` covers the game folder (hashes), affected registry keys, firewall rules with the Rerun prefix, IFEO keys, Steam launch option.

## Contract tests of the system layer

`rerun_core::sys::contract` checks the semantics of the traits against `sys::fake` and `sys::win`.

- **File system contract on real Windows runs in CI and locally** in a fresh temporary directory under `target/` (decided 2026-11-04). It creates its own junctions there (no admin needed) and touches nothing outside that directory: no registry, no firewall, no game folders. File symlinks need Developer Mode or admin; those cases skip with a message when the privilege is missing. Required safeguards:
  1. The test root is created new and uniquely named under the canonical `target/` directory. The test canonicalizes it and panics unless it is inside `target/`, on a local fixed drive, not a reparse point and not under a cloud/OneDrive tag.
  2. Junction targets stay inside the test root. The escape target is a sibling `outside/` folder with a canary file whose content is asserted unchanged.
  3. Cleanup only after re-checking (1), handle-based and never following links.
  4. Locally the test skips when the process is elevated. On GitHub-hosted runners (admin, ephemeral VM) it runs. Extension (decided 2026-11-04): fixtures that change the machine beyond the test root (mount point, `subst`, `SetFileShortNameW`) run only there (`GITHUB_ACTIONS=true`), never locally, and are undone by a drop guard.
  5. No registry, `%TEMP%` or home-directory paths. The test-only root constructor is gated (`cfg(test)`/`fake` feature) and does not bypass the forbidden-root checks for anything else.
- **Contract split and fixture-based setup.** The file system contracts are split by side. The read side (`fs_read_contract`, `fs_link_read_contract`, `fs_volume_contract`, `fs_race_contract`) takes `&dyn Fs` and uses only `Fs::open_dir` and the reading methods of `Dir` (`info`, `open_dir`, `metadata`, `open_read`, `read`, `read_dir`); it runs against `sys::fake` and `sys::win` (read-only in phase 1). The write side (`fs_write_contract`, `fs_link_write_contract`) exercises the writing methods and runs against the fake only until `sys::win` can write (phase 2). Everything a read contract needs on disk, and every attacker move, goes through an `FsFixture` (std::fs and raw calls in test code; `FakeFs` implements it for the fake): directories, files, junctions, directory and file symlinks, hard links, renames, case-sensitive directories, mounted volumes, `subst`, 8.3 short names, WOF compression, restricted DACLs (`FsFixture::restricted`: the current user is denied every access, the runner can still restore and remove the entry). The runner owns cleanup; a contract needs a fresh, empty work directory and the read contracts never delete anything.
- **Skips are observable.** A case the fixture cannot set up (no symlink privilege, no second volume, 8.3 names disabled, no WOF) returns `Ok(false)` / `Ok(None)` from the fixture. The contract skips it and returns the case names as `Skipped` (`Result<Vec<&'static str>, String>`), so the runner can tell a pass from a pass-by-skipping. The fake test runners assert the exact skip list (the fake has no 8.3 names, no WOF and no `subst`). On GitHub runners (`GITHUB_ACTIONS=true`) a skip is a test failure, except `mount_volume` (no second volume), `short_name` (8.3 names disabled) and `wof_compress` (not supported), which are warnings.
- **What the read contracts pin down.** `Fs::open_dir` accepts only drive-absolute input (`X:\…`, `\\?\X:\…`, `/` as `\`); `.`, `..`, UNC, device and volume-GUID paths, relative paths and stream paths are `InvalidPath`. A reparse point where a directory is expected, including a file symlink, is `ReparsePoint`, never `InvalidPath`. The matrix of link kinds (junction, directory symlink, file symlink, mount point) × position (`steamapps`, `common`, `Game`) is refused everywhere, with the right tag on `metadata` of the link. After every relative open the last segment of the normalized name must equal the requested one, so an 8.3 short name finds nothing (`NotFound`). A volume mounted in a folder reports an empty `volume_path` and its own serial when opened by absolute path and is a `MOUNT_POINT` surrogate below a root; a substituted drive shows the real location in `final_path` with the identity of the target. A restricted file or directory is listed by `read_dir` and described identically by `metadata` (`restricted`, `links: None`, length and attributes from the listing, own file ID), while `open_read`, `read`, `open_dir`, `read_dir` on it, walks through it and `Fs::open_dir` of it are `AccessDenied`.
- **Race harness (M-b).** `fs_race_contract(fs, fx, work, budget)`: a flipper thread swaps directories for junctions to an outside folder by path (renames at the first, middle and last of three directory levels) while the main thread probes through the root handle (`read`, `metadata`, `read_dir`, `open_dir` and reads through the sub handle). No result that comes back `Ok` may contain the canary's content, file ID or name `canary-only.txt`; allowed are `ReparsePoint`, `NotFound` (gap between two renames) and the real file's content. The assertion has to be able to fail: against the fake a fixture whose "junction" is a plain copy must be caught (`the_race_contract_catches_a_leaking_swap`). Against `sys::win` (commit with the real run) a test-only naive implementation (check `symlink_metadata` per prefix, `yield_now`, then read by full path) must be caught within 30 s, otherwise the test fails with "harness lost its teeth"; the safe implementation then runs for `max(5 s, 10 × time-to-catch-naive)`. The fake runs the contract with a short budget as a sanity check; its deterministic step hooks remain the precise TOCTOU tests.
- **Fixtures that change the machine (mount point, `subst`, 8.3 short names) run only on GitHub runners** (`GITHUB_ACTIONS=true`), never locally (decided 2026-11-04). This extends safeguard 4: locally these fixtures report "not available" and their cases skip. Each one is undone by a drop guard (unmount, `subst /d`, no lasting short name), also on panic.
- **Known folders and GPU contracts** (`known_folders_contract`, `gpu_contract`) only read, so they run against `sys::win` in CI and locally. The fake sets the known folders with `FakeSystemBuilder::known_folder`, creates their directories with `windows_layout()` and adds adapters with `gpu()`; its default has no adapter, which no real machine reports.
- **Registry, firewall, IFEO and anything outside the temp directory** run only in Windows Sandbox as `#[ignore]` tests.
- **TOCTOU:** the fake has test hooks that run between two path components of an operation, so a test can swap a directory for a junction mid-operation (ADR 0007). On `sys::win` the swap between two calls is tested. If the fake deviates from the real system, the contract is extended first, then the fake is adjusted. Known, deliberate deviations are listed in `sys/fake/fs.rs`.
- **`policy::root`** (`policy/root/tests.rs`, fake only): every forbidden-list entry with its exact reason, component-wise matching, relocated and junctioned known folders, fail-closed resolution (each missing folder, files, shares, short names), a junction at `steamapps`, `common` or the game level, a swap to a junction mid-walk (hook on the game segment) with a canary in an admin-only folder, swap after open, and identity mismatch after a folder is replaced.

The fake layer is available to other crates via the `fake` feature of `rerun-core`. CI fails if a shipped crate (`rerun-cli`, later the app) enables it (`cargo tree` feature check). Absolute file access is a `clippy.toml` `disallowed-methods` error outside `policy::root::open_abs` and `sys::snapshot::snapshot`; contract and test code opt out per module with `#![expect(clippy::disallowed_methods, reason = ...)]`, so a stale exception warns.

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

Not covered by the automated file system contracts; check by hand on a real machine until a fixture exists:

| Case | Checks / why manual | Status |
|---|---|---|
| Mount point, `subst` and 8.3 short-name fixtures locally | run only on GitHub runners by decision (they change the machine); locally their cases skip | by design |
| Junction, symlink and mount point on a network share or ReFS/exFAT volume | no fixture for these volumes | open |
| Game folder compressed with CompactGUI (WOF) | `metadata` reports tag `0x80000017`, `open_read` returns the uncompressed bytes (hash equals an uncompressed copy); the fixture compresses a synthetic file only | open |
| OneDrive folder with online-only and locally available files | online-only file: `open_read` is `Unsupported` and no download starts; available file reads normally; folder tag allowlisted | open |
| Volume mounted in a folder without a drive letter | `info().volume_path` is empty for the mount folder, `final_path` behaviour of `GetFinalPathNameByHandleW` recorded | open |
| FAT32 / exFAT USB drive | `fs_kind`, L1 check via `FileNameInformation` fallback, `info()` fails if `FileNormalizedNameInformation` is unsupported (documented, fail closed) | open |
| Elevated process (UAC, admin user) | `user_writable` answers for the linked non-elevated token: `false` for `C:\Program Files`, `true` for a folder in the own profile | open |
| Hard-linked file | `FileNormalizedNameInformation` on a second link reports that link's name, so L1 accepts both names | passes (`sys::win` smoke test, NTFS) |

## Rules

- No test modifies the real system outside the sandbox.
- Bugs: failing test first, then the fix.
- Fixtures are data, not code generators. **Exception:** PE test files are built by a small builder in test code (`tests/support`), because third-party binaries must not be committed and hand-written binary fixtures cannot be reviewed.
