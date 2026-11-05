# ADR 0020 · Plans, operations and primitives

**Status:** accepted (decided by the user) · 2026-11-05 · replaces the `Primitive` trait of `docs/01-architecture.md`; builds on ADR 0017, ADR 0018, ADR 0019

## Context
`docs/01-architecture.md` gave every primitive its own `plan`, `apply`, `verify` and `revert` over `&dyn System` (audit A1 nit: not over root types). The four phase 2 primitives (`file_install`, `registry_set`, `compat_layer`, `ini_set`) share a handful of effects: create a directory, create or replace a file, create a key, set a value. Each effect needs the same guard, intermediate phases, journal records, crash and power-loss tests (ADR 0017, ADR 0019); per primitive they would be written and tested four times. Phase 2 also needs an input before the Topo engine exists (phase 4), a plan hash that binds preview and apply, and rules for a revert that meets changed state.

## Decision

### Primitives are planners, effects are op kinds (user decision D9)
A primitive turns its spec into ops; `exec` applies, verifies and reverts op kinds. The round-trip test `apply → verify → revert → snapshot identical` stays mandatory **per primitive** (`docs/09-testing.md`); the crash, power-loss and tamper tests run per op kind.
```rust
// prim: durable spec types (serde, deny_unknown_fields) and one planner each
pub enum Step { FileInstall(FileInstallSpec), RegistrySet(RegistrySetSpec),
                CompatLayer(CompatLayerSpec), IniSet(IniSetSpec) }
pub struct PlanCtx<'a> { pub game: &'a GameDir<'a>, pub app: &'a AppDir<'a>,
                         pub sys: &'a dyn System, pub reg: &'a RegPolicy }  // reads only
pub fn plan(steps: &[Step], ctx: &PlanCtx<'_>) -> Result<Plan, PlanError>;

// plan
pub struct Plan { pub format: u32, pub roots: Vec<PlanRoot>, pub ops: Vec<Op> }   // format 1
pub struct PlanRoot { pub kind: RootKind, pub path: RootPath, pub id: RootId,
                      pub origin: PlanOrigin, pub main_exe: Option<RelPath> }
pub enum RootKind { Game }                    // `UserData` reserved (D6, phase 4)
pub enum PlanOrigin { Steam { store: RootPath, store_id: RootId, app_id: u32, installdir: RelPath },
                      Manual }
pub struct RootIx(pub u16);                   // index into `roots`, one per file op (condition S4)
pub enum Op {
    CreateDir   { root: RootIx, path: RelPath },
    CreateFile  { root: RootIx, path: RelPath, content: ContentRef, attrs: Attrs },
    ReplaceFile { root: RootIx, path: RelPath, old: FileState, content: ContentRef, attrs: Attrs },
    CreateKey   { slot: RegSlot, key: RegKey },
    SetValue    { slot: RegSlot, old: Option<RegValue>, new: RegValue },
    IniValue    { root: RootIx, path: RelPath, old_file: FileState, section: String, key: String,
                  old: Option<String>, new: String },
    TokenList   { slot: RegSlot, old: Option<RegValue>, add: Vec<String> },
}
pub struct FileState { pub sha256: [u8; 32], pub len: u64, pub attrs: Attrs }
pub enum ContentRef { Package { id: String, version: String, file: RelPath, sha256: [u8; 32], len: u64 } }
pub struct PlanHash(pub [u8; 32]);

// exec
pub enum Observed { Before, After, Drifted, Foreign }
// `fr`: roots are reopened through policy::root (StoreDir::open / game, GameDir::open_manual)
pub fn apply(sys: &dyn System, fr: &ForbiddenRoots, app: &AppDir<'_>, plan: &PlanHash) -> Result<TxnId, ApplyError>;
pub fn verify(sys: &dyn System, fr: &ForbiddenRoots, app: &AppDir<'_>, txn: &TxnId) -> Result<Vec<(usize, Observed)>, ExecError>;
pub fn revert(sys: &dyn System, fr: &ForbiddenRoots, app: &AppDir<'_>, txn: &TxnId, rebind: bool) -> Result<RevertReport, ExecError>;
pub fn forget(app: &AppDir<'_>, txn: &TxnId) -> Result<(), ExecError>;
```
- Ops whose old and new state are equal are not emitted (the same hash and attributes, the same value, a token already present). A plan without ops is "nothing to do" and starts no transaction.
- Every missing directory is its own `CreateDir`, every missing key its own `CreateKey` (ADR 0004). There is no delete op in phase 2: deleting is only ever a revert.
- `roots[]` with an index per op lets a plan span several roots and keeps room for `UserData` (D6) without a format change.
- An op that needs admin (an `HKLM` slot, a root the user cannot write) is marked `NeedsHelper` by the planner; phase 2 refuses such a plan, phase 3 sends that part to the helper. A non-elevated `AccessDenied` never escalates (ADR 0007).

### Plan hash
- `rerun plan` serialises the plan **once**; those bytes are the preview's source, are stored as `<AppDir>\plans\<hash>.json` and become `head.json` of the transaction (ADR 0019). `PlanHash` is SHA-256 over exactly these bytes. Nothing is serialised again for hashing.
- Head types use `BTreeMap` only, never `HashMap`; `RootId` (serial and file ID), every SHA-256 and every byte string (`REG_BINARY`, `Raw` data) are lower-case hex strings (no JSON number above 2^53); `format` is part of the hashed bytes.
- `apply` takes the hash the preview showed, reads the stored bytes (bounded), refuses unless their hash matches, then parses them as untrusted input. The hash binds what was previewed to what is applied and catches accidents; it is not a security boundary, the re-checks below are.

### Preview
Every op is shown before anything happens (core rule 5): root and path, key and value name, old and new value, content source and hash, attributes, and once per plan what a revert does not restore (ADR 0017, D3). Every untrusted field reaches output only as `escape::Shown` (condition S9; ADR 0016): `escape::path` for paths and value names, `escape::text` for values, INI sections and keys.

### Apply
In this order, all before `head.json` is written (ADR 0019): take the lock; check the hash; reopen every root through `policy::root` and `ensure_id`; for a Steam root re-read the app state, and refuse `UpdatePending` and `NotInstalled` (ADR 0012); **the game must be closed** (user decision D4): `users()` of every existing file-op target and of each root's main executable must be empty, else `Busy` with "<exe> is in use; close the game and try again later"; check stacking (ADR 0019); re-observe every op's old state (guard hash, value read) and refuse with `Mismatch` ("changed since the preview; plan again") on any difference. Then op by op (ADR 0019 write order), `verify` (every op must observe `After`), flushes, `Applied`. Any failure after the first change rolls back at once (ADR 0019, B-2). Revert checks D4 and the Steam state the same way.

### Observing and reverting
Each op kind observes its object on disk, never trusting a record alone:
- `Before`: as before the op. `After`: exactly as the op left it. `Drifted` (semantic ops only): the surrounding content changed, Rerun's own part is still exactly as it set it. `Foreign`: anything else.
- `After` is reverted, `Before` needs nothing, `Drifted` gets a semantic revert, `Foreign` is **never overwritten or deleted** (user decision D10, replacing "otherwise ask" in `docs/06-security.md` and `docs/02-topo-format.md`): the op stays unresolved, its backup stays in the journal, `status` names the backup's location, and `forget` closes the transaction after a preview.

| Op | `After` / revert |
|---|---|
| `CreateDir` | exists with the file ID from `Done`, empty / `remove_dir` by that ID; not empty or another ID: `Foreign` |
| `CreateFile` | content hash, one link / guard + `delete(expected)`; a user-edited file (a `config` file) is `Foreign` |
| `ReplaceFile` | new hash / guard + `replace(expected new, backup, old attributes)`; old hash is `Before` |
| `CreateKey` | exists, no values or subkeys / `delete_empty_key`; with content `Foreign` |
| `SetValue` | value equals `new` / set `old`, or delete it if there was none; equals `old`: `Before` |
| `IniValue` | file hash as written / restore the backup bytes; otherwise our key still has `new`: `Drifted`, set the key back to `old` (or remove it) in the current content and keep everything else; our key changed: `Foreign` |
| `TokenList` | value as written / restore `old`; otherwise our tokens still present: `Drifted`, remove only them (delete the value if nothing is left and there was none before); a token removed: `Foreign` |

For `ini_set` the semantic revert is the normal path, not an exception: games rewrite their INI files on every start, so `After` rarely holds by the time of a revert. The INI editor changes only the value span (line endings, encoding and every other byte kept), so a semantic revert of an unchanged file gives exactly the old bytes; the round-trip test pins that. A semantic revert writes through `FileGuard::replace` with the hash just observed as the expected one.

### Rebind (user decision D5)
After a moved Steam library or a reinstall, a revert meets `IdentityMismatch`. `rerun revert <txn> --rebind` binds the transaction to the new folder only if all hold: the recorded root cannot be opened any more; the Steam scan finds the app's install folder in exactly one library; every op of that root observes `Before` or `After` there (no `Foreign`); and the user confirms a preview showing the old and the new folder and identity. A `Rebind` record is written first. Manual roots are never rebound. Otherwise the transaction stays as it is and only `forget` closes it.

### Input until the Topo engine (user decision D7)
`rerun plan <steps.json>` reads a JSON step file: a throwaway envelope (`format: 1`, the game as a Steam app ID or a folder, `steps`) around **durable step objects**: each step is an object with exactly one key, deserialised into the spec types above with `deny_unknown_fields`. `registry_set`, `compat_layer` and `ini_set` are the Topo step objects of phase 4 and enter `schema/topo.schema.json` with their primitive (ADR 0005); `file_install` is what a Topo `package` step expands to (the package's files with their hashes) and is not a Topo step itself. The file is read through `policy::root` (its folder opened read-only by absolute path, the file a single segment), at most 1 MiB with a bounded read; every path field is parsed as `RelPath`, hashes follow `docs/02-topo-format.md`. No YAML at run time before phase 4.

### First primitive: `file_install` (user decision D11)
Sources are files below `<AppDir>\packages\<id>\<version>\` (`id` and `version` with the rules of `docs/02-topo-format.md`), each with a fixed SHA-256 in the step. In phase 2 only test fixtures are placed there (tests, the sandbox script); downloads, slots, `requires` and reference counting are phase 4. The planner emits `CreateDir` per missing parent, `CreateFile` for an absent target and `ReplaceFile` (old state from a guard) for an existing one; a source is opened sharing read only and is hashed while it is streamed into the temp file (ADR 0017). Audit A2 runs after this primitive.

### Moved
- `UserData` roots (`Documents`, `My Games`) to phase 4 (user decision D6: OneDrive placeholders and redirection need their own rules); the plan format already has `roots[]` with a kind.
- `gpu_preference` to phase 4 with `gpu.hybrid` and `gpu.integrated` (user decision D8; slot reserved, ADR 0018).
- The UAC VirtualStore warning (ADR 0007 "Open for Phase 2") to phase 3.

### CLI
`rerun plan <steps.json> [--dry-run]` (preview and `PlanHash`; without `--dry-run` the plan is stored), `rerun apply <plan-hash>`, `rerun revert <txn> [--rebind]`, `rerun status` (transactions with their state, unresolved ops, pending cleanups, backup locations), `rerun forget <txn>`. `apply`, `revert` and `forget` take the journal lock; `plan` and `status` do not. Output rules of ADR 0016.

## Alternatives
- **The per-primitive trait of `docs/01`:** four copies of the guard, phase, journal and crash logic; planners without a system are pure and cheap to test.
- **Hashing a re-serialised `Plan`:** serde output and map order are not stable across versions; a byte change would make an approved plan unappliable, or worse, a different plan hash the same.
- **Asking on revert** (the former "otherwise ask"): a dialog at revert time invites "overwrite" and destroys the user's or a mod manager's change; `forget` is explicit and keeps the backup until then.
- **Automatic rebind by app ID or name:** could attach a journal to a different folder.
- **YAML input in phase 2:** a run-time YAML parser before the loader rules of phase 4 exist (ADR 0005, ADR 0015 open point).
- **Restoring the INI backup whenever it matches, else refusing:** fails on nearly every game that rewrites its INI on start.

## Consequences
- `rerun-core` modules: `prim` (spec types and planners), `plan` (`Plan`, `Op`, `PlanHash`, storage), `exec` (apply, verify, revert, forget, `Observed`), `journal` (ADR 0019). `serde` with `derive` becomes a direct dependency of `rerun-core` (already in `Cargo.lock` through `serde_json` and `rerun-proto`), justified in its commit.
- `docs/01-architecture.md` (modules, primitives), `docs/02-topo-format.md` (`config: true`, `package`), `docs/03b-gpu-display.md` and `docs/08-roadmap.md` (`gpu_preference` in phase 4), `docs/06-security.md` (scenarios 6, 9, 10, 14) and `docs/09-testing.md` follow in the same commit.
- Core rules: rule 4 (no op kind runs code; content only from pinned hashes; roots and registry slots through policy), rule 5 (preview from the stored bytes), rule 2 (`Observed`, D10, LIFO), rule 6 (`NeedsHelper` refused in phase 2).

## Open points
- Exit codes of the new commands (refused before any change vs. rolled back vs. left open): fixed with the CLI step.
- The INI editor's accepted encodings and syntax (UTF-8, ANSI, UTF-16 with BOM; comments, duplicate keys, keys outside a section): P2-12, failing closed on anything ambiguous.
- `compat_layer` token list: P2-11 (ADR 0018).
