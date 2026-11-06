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

## Amendment (P2-8, 2026-11-06; decided by the user after a senior-dev cross-check)

### Wire form of format 1 (`rerun-core::plan`)
- `{"format":1,"roots":[…],"ops":[…]}` exactly as `serde_json::to_vec` writes it: no whitespace, fields in declaration order, `deny_unknown_fields` everywhere, no maps. Enums are externally tagged in `snake_case` (`{"create_file":{…}}`; a unit variant is its name, `"origin":"manual"`). A SHA-256 is 64 lower-case hex digits, a `RootId` the string `<16 hex>-<32 hex>`, `Attrs` `{"readonly":…,"hidden":…,"system":…}`, paths are strings with `\` (`RelPath::parse` and `RootPath::new` again on read). Lengths are JSON numbers (at most 2 GiB).
- `ContentRef::Package` carries `config` (the step's `config: true`, shown by the preview), so the preview needs nothing but the plan.
- **One form:** `decode` checks `format` first (another value is `PlanError::Format`), parses strictly, and accepts the bytes only if re-encoding the result gives the same bytes; so `/`, a lower-case drive letter, whitespace or another field order is refused (`NotOneForm`), not normalised. Then the bounds of `encode`: at most 128 ops, 8 KiB per op serialised, 1 MiB per plan, 16 roots (no root listed twice, a Steam app ID ≥ 1), every `RootIx` inside `roots`, one op per object (root index and folded path), package ID and version by `docs/02-topo-format.md` and a valid segment, contents and old files at most 2 GiB, old files at most 4 GiB together, no `ReplaceFile` whose new hash equals the old one (ADR 0017 A2).
- `store` writes `plans\<hash>.json` with `create_new` and flushes `plans\`; the same bytes again are `Ok`, other bytes under the name are `HashMismatch`. `load` reads at most 1 MiB and refuses bytes that do not hash to the name.
- **Objects** (stacking, ADR 0019 B-2): `(RootId, folded path, created directory?)` per op; two overlap if equal, or if one is a directory an op creates and the other lies below it. Root identity, not the root index or app ID, so two Steam apps sharing one install folder overlap. Two different roots of which one lies inside the other (a manual root inside a Steam install folder) overlap as a whole, whatever the paths (fail closed, review S2).

### `file_install` and the planner context
`PlanCtx { game, app, steam_app, main_exe }` (no `sys`: the planner reads through the `GameDir` and `AppDir` handles; `RegPolicy` joins with P2-9). A Steam root needs its app ID, a manual one has none. Same content is no op whatever its attributes (senior-dev B1); new files get no R/H/S; refusals as in `docs/02-topo-format.md` and `prim::file_install`.
- **Name spelling (audit A2-B1; ADR 0017 D3: the case of a name is part of "exact").** The planner writes every existing segment of a target in its stored spelling (`Dir::stored_name`, `FileNameInformation` on an attribute-only handle, as the guard), whatever the step says: a replace names its target as the folder holds it. A segment the plan creates keeps the spelling of the first step that creates it; a new file keeps the step's. `exec` compares the guard's name (`FileGuard::name`) with the plan's last segment exactly (`RelPath::same_spelling`: `==` on a `RelPath` folds) in the old-state check and again on the apply's guard before backup and intent; another spelling is `Mismatch`. So the planned spelling is the one the file had when it was applied, and a recovery that renames `X.old` or `Yi.old` back in phase B renames onto it (before: onto the step's spelling, a silent snapshot difference at 4 of 217 crash points). A target found in another spelling after the apply (someone renamed it, case only) is not the planned object: the observation of a replace counts it as "other" in `S0` and every `Si`, so `verify` and the revert report it `Foreign` and leave it as the user named it (review S1); the restore checks the spelling on its own guard again (`Mismatch`). Existing ancestors are only opened, never renamed; their spelling in the plan is for the preview.

### `exec` (P2-8)
```rust
pub struct ExecCtx<'a> { pub sys: &'a dyn System, pub fr: &'a ForbiddenRoots, pub app: &'a AppDir<'a>, pub tag: InstanceTag }
pub enum Outcome { Nothing, Applied(TxnId) }
pub fn apply(cx: &ExecCtx, h: &PlanHash) -> Result<Outcome, ApplyError>;   // Refused | RolledBack | LeftOpen
pub fn verify(cx: &ExecCtx, t: &TxnId) -> Result<Vec<(u16, Observed)>, ExecError>; // read only, no lock
pub fn revert(cx: &ExecCtx, t: &TxnId) -> Result<RevertReport, ExecError>;  // also recovery; rebind with the CLI
pub fn forget(cx: &ExecCtx, t: &TxnId) -> Result<(), ExecError>;
```
- **Apply.** Nothing is written before `begin`: the stored plan (bounded, hash) is decoded; no ops is `Outcome::Nothing` (no lock, no transaction). Then the lock and the listing (stacking only there, below); every root reopened and checked by identity (a Steam root through its store, `app_manifest` with the plan's install folder and `Installed`, else `Refusal::Steam`); `!user_writable` is `NeedsHelper`; `users()` of every existing target and main executable (`Busy`); every created object still missing, every replaced file's guard holding exactly `old` (hash, length, R/H/S, one link), every source still hashing to its content (`Mismatch { op }`). Then `begin`; per op the order of ADR 0019, a replace checking the guard against `old` and asking `users()` on the guard again before backup and intent (senior-dev conditions 5 and 8); every op observed `After`; the touched game folders flushed (after every guard is dropped); `Applied`. A failure after `begin` runs the revert loop on the same writer and closes `RolledBack`; a failure between `begin` and the first intent leaves nothing to revert (closed `RolledBack`, or `Empty` if even that failed, which blocks nothing). A rollback that fails or meets a foreign op is `LeftOpen`.
- **Stacking on the listing** (only `list` sees a duplicate `seq`): a forgotten, closed or empty transaction blocks nothing; a `view` error, a damaged one without a usable head, a head whose hash differs from the listing's on its one `load` (condition 6) or that `decode` refuses (more than 128 ops included) is `Blocked` for every apply and for the revert of every earlier transaction; an open one, an applied one with any `RevertIntent` (condition 3) and a damaged one with a usable head have their head's objects open (`Interrupted` on overlap); an applied one is stackable. Revert is LIFO: a later open or applied transaction on an overlapping object is `Later`.
- **Revert = recovery = rollback**: the lock, the listing (the own entry must not be damaged), `resume`, `decode(w.head())` (the bytes read under the lock; refused: only `forget`), records that fit the head (an intent per existing op, temp names and backups by op kind, a replace's `BackupRef` equal to its `old`: else `Blocked`), LIFO, roots, Steam, `users()` of the intended targets; then newest op first: observe, `RevertIntent` (a temp name only when a restore starts, B2), act, flush the op's game folder (always, ADR 0019 amendment P2-8: a durable `RevertDone` must have a durable change and a durable undo of a failed sequence), `RevertDone`. With a restore, a `.old` holding `h0` is deleted only after the restore succeeded (review S1), so a damaged backup never costs the last copy of the old content. A foreign op gets `RevertIntent` and `RevertDone { Foreign }` and the lower ops are still reverted (**user decision D3, R1**); the transaction stays open, `RevertReport::closed` is `None`, only `forget` closes it. `verify` is the read-only preview of what a revert will meet (rule 5).
- **Observation** (every hash on a guard; a link count other than 1, other R/H/S, a restricted entry or a reparse point is "other"):
  - `CreateDir`: missing → `Before`; empty with `Done.file_id` → `After`, removed by that ID; otherwise `Foreign`. Without `Done` (**user decision D1**): the in-process rollback uses the call's result (an ID from `create_dir`; `AlreadyExists` from `create_dir` or `create_new` is foreign, never removed: condition 4); the recovery removes an empty directory by the ID it finds then, not empty is `Foreign`. `verify` counts a created folder holding only the targets of the plan's later ops as empty.
  - `CreateFile` (`X`): target missing → `Before`, `X` deleted; target `h1` → `After`, deleted with `h1` expected, `X` left; anything else `Foreign`, `X` deleted unless the target holds `h1`.
  - `ReplaceFile` (**senior-dev B2**): `S0 = (X, h0 → h1)` and one `Si = (Yi, h1 → h0)` per `RevertIntent` with a temp name. The newest `Si` whose `Yi` or `Yi.old` exists decides, else `S0`, by the table of ADR 0017 A3 for its direction: `S0` phase A or B → `Before` (B renames `X.old` back with `h0` expected), C or D → `After` (C deletes `X.old` with `h0` expected) and restore; `Si` phase A or B → `After` (B renames `Yi.old` back with `h1` expected) and a new restore, C or D → `Before`. A `X.old` holding `h0` next to a target holding `h0` after a restore was intended (or with `Done.old_left`) is the pending cleanup of step 8, not foreign. Once some `Si` decides, every earlier sequence completed (the ordered log of the folder's volume), so `X` and older `Yj` are no temp files of Rerun any more; a `.old` of them holding the expected hash is still cleaned up. Restore: `users()` on the guard, then `replace(h1, backup_reader(k), NewFile { Y, old R/H/S, sha256: BackupRef.sha256, max_len: BackupRef.len })`: the backup is checked while it is written, never before (TOCTOU). A step 8 that fails gets one more try on a fresh guard; still `Busy` (mapped) leaves `Y.old` as a pending cleanup named in the report (open point below).
- **Forget** (**user decision D2**): an empty, open or applied transaction (by the listing) is resumed and closed `Forgotten`; a damaged one, or one whose view is an error, gets the marker `journal\<txn>.forgotten` (ADR 0019 amendment). Backups stay.

### Open points (P2-8)
- A `.old` left mapped after a revert (`RevertDone.old_left`) is not cleaned up by a later run yet (cleaning up other transactions' `.old`, phase 5); the report names it.
- `main_exe` is `None` for a manual root without a chosen executable (then only the targets are asked); fixed with the CLI step.

## Amendment (P2-9, 2026-11-06; decided by the user after a senior-dev cross-check; conditions for P2-10)
- **Op form of registry slots (M2):** a registry op names a `RegSlot` whose executable is `{ root: RootIx, exe: RelPath }`, never a free-form path; `RegPolicy::check` builds the value name from `Plan::roots[root].path` (parsed again) on plan, apply and revert (ADR 0018 amendment P2-9).
- **6a, `CreateKey` without an identity proof (user decision a):** like D1 for directories: recovery deletes an **empty** key at the path of a `CreateKey` intent without `Done`; a key with values or subkeys is `Foreign`. P2-10 conditions: `Done` is written only for `create_key == true`; `false` (the key existed) is `Mismatch` and a rollback, never a delete (with a test); `verify` counts a key holding only later targets of the same plan as empty; the preview and `status` treat a game that fills the key or value later as the normal case (`Foreign`, then `forget`). Rest risk: `docs/06-security.md`, scenario 10.
- **6b, revert when a root does not open (user decision d, senior-dev):** the planner orders every registry op after every file op; `revert` opens roots lazily per op; a file op whose root does not open (for whatever reason) halts the revert **without a record**: the transaction stays open and resumable, and a rebind (D5) stays possible. Implemented in P2-10 (`exec`).
- **Op budget:** `SetValue { old }` cannot carry an old value of up to 1 MiB inside the 8 KiB op budget: the head holds `old: Option<ValueState { kind, len, sha256 }>` (small old values inline up to a limit), the bytes go to `Intent.before` or `op-NNNN.bin`; the preview shows kind, length and hash. `RegistryWrite::set(expected: Option<&RegValue>)` serves both (P2-10).
- **`create_key` errors (review S5):** after a failure past the create (its flags), the key may exist; `exec` treats an `Err` as "observe", never as foreign and never as "not created".
- **`RegWriter::delete_empty_key`** also deletes an empty key that existed before Rerun: `exec` deletes only keys it created itself (`Done` written after `create_key == true`), with a test.
- **Deserialising a `RegSlot`** (plan or journal) goes through `AsciiSeg::parse`, `AsciiName::parse` and `GameKey::new`, never through raw fields, so a manipulated journal cannot name a key the rules refuse.

## Amendment (P2-10a, 2026-11-06; decided by the user after a senior-dev cross-check)

### Dispatch by target (audit A2 should-item 3)
`Op::target() -> Target` replaces `Op::root()`/`Op::path()`: `Target::File { root, path, dir }` now, `Key` and `Value` with the registry op kinds (P2-10b). Every generic path matches on it: objects (`Object` is an enum by target, `root_path` always set) and "one op per object" in `plan`; in `exec` apply, observe, act, the record check, the game-closed check and the flushes (`Touched`: the game folders now, the hives with P2-10b; `flush_all` before `Applied`, `flush_for` the op's domain before each `RevertDone`). `exec::file` is the file domain behind it, unchanged; the revert loop stays one for every domain. The flush knobs of J6 are named by domain and place (`Flush::GameBeforeApplied`, `Flush::GameBeforeRevertDone`).

### Revert when a root does not open (user decisions 6b-d and E3)
An apply still needs every root open (`Roots::all`). A revert and `verify` open each root on its own (`Roots::each`) and sort it:
- **Open:** reopened and checked by identity. If the current user cannot write it (or its volume lacks POSIX semantics), its file ops cannot run; D4 still asks it (read access suffices).
- **Absent:** a manual folder whose path is not found; a Steam app without manifest, installed in another folder or not installed (the halt names which: `Refusal::SteamGone` or `Steam { NotInstalled }`). Extending E3's wording: a Steam library whose path is not found, and an app whose manifest says installed while its folder is not found. Only a `NotFound` of the open itself counts: `policy::root` reports a folder that changes while it is opened (`Dir::info` failing after the open, the `common` entry swapped) as `Busy` (review S-1). D4 does not ask an absent root, its file ops cannot run.
- **Undecided:** everything else (`UpdatePending`, a manifest that cannot be read now, `IdentityMismatch` (a rebind, D5, may bind it), busy (also the swap races above), access denied, a reparse point, forbidden). The revert is refused before any change.

D4 runs on the open roots (targets and `main_exe`; a missing `main_exe` is fine in a revert), and `Busy` refuses before any change. Then, newest op first, a file op whose root cannot run file ops **halts** the revert without a record (`Halt { op, root, why }`): `RevertReport { closed: None, halted: Some(..) }`, also at the first op (`Ok`, review N4). The transaction stays open and resumable, and a rebind stays possible. The halt is decided again on every run, so the revert goes on once the folder itself is back or the update has finished. A reinstall makes a new folder with a new identity: `IdentityMismatch`, undecided, refused until a rebind (D5). `verify` returns `Verified { ops, halted }`: newest op first; missing are the ops below the halt and the cleanly reverted ops of a root that cannot run file ops, while an op whose revert left it `Foreign` there is shown `Foreign` as recorded (security N-5). From P2-10b on, `check` refuses at encode and decode (the journal head is untrusted) any registry op before a file op, so a halt always comes after every registry op is reverted. The control K-R9 (every root opened eagerly, as before) fails H4.

### `verify` of a created directory (review S3)
`verify` observes newest op first, as a revert does, and hands each observation (`Seen`, with its actions) to the earlier ops. A created directory counts as gone what the later ops remove or never made: a target observed `After` or `Before`, and every temp name a later op deletes (`DeleteTmp`, review S-a). A later target observed `Foreign` stays, so the directories above it are `Foreign` too, as the revert will find them. Before, `verify` called them `After` (T2 changed accordingly), and called a folder holding only a later op's temp name `Foreign` while the revert closed it.

### The main executable and write access (user decision E2, review M1, S1; audit A2 should-item 8)
- A `main_exe` that is given must be a plain file of its root (not missing, not a folder, link or other reparse point, not restricted), checked by the planner (`PlanError::Step`) and again by the apply (`Refusal::MainExe`, before anything is written), since D4 would otherwise ask nothing about it. A revert tolerates a missing one. A file plan may still have none (its targets are asked; open point P2-8).
- Registry ops (P2-10b) need at least one root and a `main_exe` for every root: `check` refuses other plans on encode and decode, and the planner refuses a registry step without one. The hook is `Target::needs_main_exe` (false for files), so both rules apply as soon as the registry targets exist.
- Write access only for a root that file ops target (S1), in the planner and in the apply; D4 needs read access only, so a root without file ops may be read-only to the user.

### Checklist for P2-10b (from the P2-10a reviews)
- `check` refuses a registry op before a file op, on encode and decode (the head is untrusted; the planner's order alone is not the guarantee). **Done (P2-10b, `plan::check`, test P7).**
- S2: `writable()` (elevated) in the revert too, after `game_closed` and before `revert_loop`, for plans with registry ops.
- N2: a `CompatLayers` slot is refused in `check` until P2-11. **Done (P2-10b, `plan::allowed`, test P7).**
- P-tests: a registry plan with `roots: []` and one without `main_exe` refused, also on decode. **Done (P2-10b, test P7).**
- `records_fit` compares `Before::Inline`/`Bin` exactly with the planned old value of a `SetValue`.

## Amendment (P2-10b, 2026-11-06; plan `P2-10` with the user decisions E1 to E3 and the senior-dev conditions)

### Registry op kinds in format 1
```rust
pub enum Op { /* file op kinds */
    CreateKey { slot: RegSlot, segs: u8 },   // the slot's key cut to `segs` segments below HKCU
    SetValue  { slot: RegSlot, old: Option<ValueState>, new: NewValue } }
pub enum NewValue { Dword(u32), Qword(u64), Sz(String) }   // {"dword":1} | {"qword":"<decimal>"} | {"sz":"…"}
pub struct ValueState { pub kind: u32, pub len: u32, pub sha256: [u8; 32], pub data: Option<Vec<u8>> }
pub const OLD_INLINE: usize = 1 << 10;      // `data` (hex) exactly when len <= OLD_INLINE: preview only
pub enum Target<'a> { File { .. }, Key { slot: &'a RegSlot, segs: u8 }, Value { slot: &'a RegSlot } }
pub(crate) enum Object { File { .. }, Key { key: RegKey, created: bool }, Value { key: RegKey, name: String } }
```
- A slot is written as `{"game_value":{"vendor":…,"product":…,"rest":[…],"name":…}}` (`compat_layers`/`gpu_preference` with `root` and `exe`) and read back through `AsciiSeg::parse`, `AsciiName::parse`, `GameKey::new` and `RelPath::parse` (ADR 0018 amendment P2-10b). `CreateKey` names its key by `segs` (`AllowedKey::cut`: below the anchor, at most the slot's key), so no key outside the slot can be expressed. `qword` is a decimal string (no JSON number above 2^53), without sign or leading zero.
- The old value of a `SetValue` is its type, length and SHA-256; its bytes ride along only up to 1 KiB, for the preview. The revert's source is always the journal (`Intent.before`, inline up to 16 KiB, else `op-NNNN.bin`). The worst case (the longest slot, 1 KiB of old data, a `REG_SZ` of 1,024 characters that each need escaping) is 4,833 bytes, inside the 8 KiB op budget (test P8).
- **`check` (encode and decode alike; the head is untrusted):** every slot passes `RegPolicy::check` with the plan's root paths (a `CompatLayers` slot is refused until P2-11, review N2; `GpuPreference` stays reserved), every new value `RegPolicy::check_new` (`PlanError::Registry`); every registry op comes after every file op (so a revert that halts at a file op has reverted every registry op, 6b-d); one op per key and per value (folded); `segs` within the slot; a `CreateKey` before every key and value below it; an old value with length at most 1 MiB, inline bytes exactly up to 1 KiB with the length and hash they claim, not equal to the new value, and absent in a key the plan creates; a plan with registry ops has at least one root and a `main_exe` for each (E2, review M1).
- **Objects:** a created key holds every key and value below it; a value is its key plus the folded name; a file and a registry object never overlap. `Object::of` fails closed: a slot the policy refuses is `Blocked`, never a missing object.
- **Preview:** the key (`HKCU\…`), the value name (`(default)` for `""`), the old value (numbers and strings decoded from the inline bytes, strings through `escape::text`; anything else by type, length and SHA-256; `missing`), a type change marked, the new value; once per plan with registry ops the note that a game filling the key or changing the value later (also with another type, review S4) is left as it is and closed with `forget`, and that a revert does not restore the last-write times of keys. This is the one place where old registry data reaches output (review N6; ADR 0016 output rules apply).
