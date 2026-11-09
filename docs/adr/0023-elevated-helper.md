# ADR 0023 · Elevated helper

**Status:** Proposed — audit A4 pending · 2026-11-09 · phase 4, step P4-1 · builds on ADR 0007 ("Elevation"), ADR 0008 (H2), ADR 0019, ADR 0020 (amendment P4-4), ADR 0024

## Context
Core rule 6: the GUI and the CLI never run elevated; whatever needs administrator rights goes as a plan to a short-lived elevated helper. Phase 4 needs it for one thing only: Rerun's own outbound block rule for one game executable (`firewall_rule`, user requirement of 2026-11-08). The user decided the scope (plan P4, E1 = "0"): in phase 4 the helper can **only add and remove Rerun's own Windows Firewall rules**; no admin-only roots, no `HKLM`, no file writes (moved to phase 6 with a helper-owned backup store). E3 a: only for an executable of a signed Topo whose SHA-256 the helper checks itself. E4 "a+": with an anti-cheat system detected, `firewall_rule` is refused, and the helper checks that again.

What makes the helper hard is not the firewall call but the boundary. Everything the helper could take from its caller (the request, the plan, the journal, the stored index, the game folder) lives in places any process of the same user can change (`docs/06-security.md` #7, #14). A UAC click must therefore never give same-user malware more than "a Rerun block rule for an executable a signed Topo names". Revert must work without any of today's data (condition R1): an index may be retired, a game moved or patched.

This ADR fixes the design. Per senior-dev condition B11/R7 **no signature or grammar below enters `plan`, `sys`, `journal` or `elevate` code before A4**; they live here. A scaffold binary with its hardening and source-rule tests is allowed.

## Decision

### 1. What the helper may do (phase 4)
| Capability | Phase 4 | Condition |
|---|---|---|
| Add a firewall rule | yes | exactly the rule form of §6, program = an executable of a signed Topo variant with a `firewall_rule` step, SHA-256 checked by the helper on its own handle, no anti-cheat found, root not forbidden |
| Remove a firewall rule | yes | Rerun's name form, group `Rerun`, exactly one rule of that name, every fact as recorded (§5, R1, R10) |
| Change or remove any other rule, profiles, default policy, firewall on/off | never | |
| Files, folders, registry (also read), journal, network, GPU, `hw`, archives, Steam files | never | source rule, import and content tests (§14) |

### 2. Process model
- One binary, `crates/rerun-helper` → `rerun-helper.exe`, `#![windows_subsystem = "windows"]` (no console window: an elevated process cannot attach to the user's console), manifest `asInvoker` (elevation comes from the `runas` verb; a non-elevated start reaches the helper's own refusal, which the hardening tests use). No output at all; the result is the exit code (§7).
- Started **at most once per `apply` or `revert` run**, only when the run has helper ops to change (a revert whose helper ops all observe `Before` starts none). `plan`, `status`, `verify`, `forget` never start it. It lives for the duration of one batch (milliseconds to seconds). Core rule 1 holds.
- **Installed only at `<FOLDERID_ProgramFiles>\Rerun\rerun-helper.exe`** (known folder, never the environment, never next to the CLI). Until the installer (phase 5) the developer copies it once by hand as administrator (docs/09), CI copies it as `runneradmin`.
- **CLI pre-check before UAC** (`policy::root::helper_image`): `Rerun` and `rerun-helper.exe` opened handle-relative below the known folder, neither a reparse point, the file a plain single-link file, and the security descriptor of **both** the folder and the file admin-only (the ADR 0007 rule: owner SYSTEM, Administrators or TrustedInstaller; no ACE granting write, delete, `WRITE_DAC` or `WRITE_OWNER` to any other SID). Otherwise `Refusal::HelperUnsafe` before the lock: "the helper is not installed safely" (exit 3), no UAC dialog. This is what stops "the user confirms a UAC dialog for a replaced `rerun-helper.exe`": H2 inside the helper only protects a genuine helper from planted DLLs. Because both objects are admin-only, the check is not a TOCTOU window for the same user. `plan` runs the same check and shows a warning, never an error.
- Start: `ShellExecuteExW`, verb `runas`, the canonical image path from the pre-check, `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI`, the console window as owner; wait without timeout (a UAC dialog may wait for the user); `GetExitCodeProcess`. `ERROR_CANCELLED` is `HelperRun::Declined`. No handle inheritance across elevation, hence no pipe. `ShellExecuteExW` gets the one reviewed exception to its ban in `sys::win::elevation` (the shim's exception stays separate).
- **Build ID (R12):** `rerun_core::BUILD_ID` = `CARGO_PKG_VERSION` + `+` + `RERUN_BUILD_ID` (the commit, set by CI and the release build; `dev` otherwise). The request carries the CLI's; the helper refuses any other (`Refused(Build)`). It catches a CLI and a helper of different builds deriving rule names or request fields differently; it is no security boundary (the request is untrusted anyway).

### 3. Hardening at start (fixed order, each step fail closed)
1. `restrict_dll_search()` (ADR 0008; the binary is linked with `/DEPENDENTLOADFLAG:0x800`).
2. Remove `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeDebugPrivilege` (`SE_PRIVILEGE_REMOVED`) and every other privilege except `SeChangeNotifyPrivilege` (stricter than H2; the firewall needs none, measured in P4-5).
3. Must be elevated (`TokenElevation`), else `Refused(NotElevated)`.
4. Own image check (H2): `<FOLDERID_ProgramFiles>\Rerun` resolved by the helper itself, folder and file admin-only as in §2, and the running image (`ProcessImageFileNameWin32`, compared folded with the canonical path of the opened file, same volume serial and file ID) is that file; else `Refused(ImageFolder)`.
5. Arguments: exactly `--request <absolute path> --sha256 <64 lower-case hex>`; anything else `Refused(Usage)`.
6. COM: `CoInitializeEx(COINIT_MULTITHREADED)`, activation only through the one wrapper `sys::win::com::create_inproc` (`CLSCTX_INPROC_SERVER`; elevated processes ignore per-user COM registrations).

### 4. Transport (lead decision L2)
- The CLI writes, under the journal lock, `<AppDir>\elevate\<txn>-<n>.req` (`AppSub::Elevate`, `create_new`, flushed), JSON, at most `MAX_REQUEST_BYTES` = 64 KiB, and passes its absolute path and SHA-256. The CLI deletes it after the run; a leftover after a crash is Rerun's own state, never read again.
- The helper reads it like `policy::root::read_input` (folder by absolute path, read side; the file one plain segment, no reparse point, bounded), compares the SHA-256 with the argument (accidents only), checks `format` first, then `deny_unknown_fields` everywhere. A same-user process can swap the file between write and read: that is why §5 trusts nothing in it.
- **Back:** only the exit code (§7). The helper never writes anything into a folder the user can write (an elevated write there is an attack surface) and writes no file at all in phase 4.
- **Over-the-shoulder elevation (B12 a):** a standard user who types an administrator's password gets a helper running as *that* account, with another `LocalAppData` and `HKCU`. Hence absolute paths in the request and no known folder of the helper's account for the user's data. The administrator's token can read the user's profile (default ACL). The helper resolves its own `ForbiddenRoots` (ADR 0007 amendment): the user's profile then counts as another user's, so a game root inside it is refused (stricter, intended). Nothing of the helper uses `HKCU`.

### 5. Validation: the helper trusts nothing from its caller
The request names; the helper derives. Two modes, both closed lists of ops.

**Add (apply)** — every step fail closed, nothing changed before step 8:
1. `build`, `format`, at most `MAX_BATCH_OPS` = 8 ops, op indices unique, every op an `AddOp`.
2. **Index:** `<index_dir>\<hex(source.index)>.json` and `.sig` read like the request (at most `MAX_INDEX_BYTES`); SHA-256 of the bytes equals `source.index`; signature under `catalog::key::trusted_keys()` (release slots only: no retired key admits a new elevated change, a revoked one never); `seq` ≥ `HELPER_MIN_SEQ`, a constant of the build (the seq of the index shipped with it, E5). The pointer `current.json` is never read (user-writable). Then the form rules of ADR 0024 (`Rules::Release`).
3. **Topo and variants:** the Topo `source.topo` with `rev == source.rev`, not retired; the picks resolved with the engine's pure rules (one variant per issue, at most 32, conflicts within the pick). `when` is **not** evaluated (the helper builds no system profile, `docs/06-security.md` "System profile").
4. **Root:** opened by volume GUID path + 128-bit file ID from the request (`NtCreateFile` with `FILE_OPEN_BY_FILE_ID` relative to the volume handle, ADR 0007 "Elevation", condition R4; never `OpenFileById`, never a drive-letter path, so a per-session drive letter or `subst` cannot redirect it). It must be a directory, not a surrogate, with the request's volume serial; its canonical path (from the handle) must equal the request's `path` (folded) and pass the helper's own `ForbiddenRoots`. The root need **not** be admin-only: nothing is written into it, and a block rule names a path, it grants nothing.
5. **Program:** every `firewall_rule` step of the picked variants names one entry of the Topo's `match.exes` that carries a `sha256` (R6: `sha1` alone never anchors anything elevated). The helper opens that `RelPath` handle-relative below the root (ADR 0007 walk, no reparse point, single link), hashes it with SHA-256 on that handle (bounded like `--hashes`), and requires the signed value.
6. **Anti-cheat (E4):** `detect::exe::anti_cheat` on the helper's own root handle, `topo::anti_cheat_state` with the Topo's `dead` release; anything found (or unreadable) → `Refused(AntiCheat)`.
7. **The ops must be exactly the derived set:** the helper derives one `FwRule` per `firewall_rule` step (`policy::firewall::rule`, §6, name from Topo ID, `txn`, op index) and requires the request's ops to name the same programs in the same order; any difference → `Refused(Ops)`. So the request can choose *which* signed data, never *what* follows from it.
8. Execute (§6), newest-added first rollback of its own adds on any failure → `RolledBack`.

**Remove (revert and rollback, condition R1)** — never reads an index, never asks a `seq` floor, never opens the game folder or hashes an executable; it works after the game was uninstalled, patched or moved and after a key rotation:
1. `build`, `format`, at most 8 ops, every op a `RemoveOp`.
2. Per op the helper forms the expected rule from the request (`topo`, `txn`, op index, the program path recorded in the head) with the same `policy::firewall::rule`; a name that does not parse as Rerun's form is `Refused(Request)`.
3. Per op (§6): no rule of that name → `Before` (nothing to do); exactly one, in group `Rerun`, every fact equal → remove it; anything else (two or more, another group, a fact changed, disabled) → `Foreign`, untouched (ADR 0020 D10).
- What a forged remove request can reach: Rerun-named rules in group `Rerun` whose facts it states exactly. Only an administrator can create rules, so such a rule is Rerun's own or an administrator's imitation of one. The worst case is that a Rerun block rule disappears: the effect of the user's own revert. Accepted (A4 question 3).

### 6. The rule form and the firewall domain
- **One form** (`policy::firewall::rule`, used by planner, preview, helper and observation alike): name `Rerun - <topo-id> - <txn>-<op:03>` (`<txn>` = `%08u-%016x`, ADR 0019; ASCII only; refines the P4-5 sketch: the full transaction ID keeps names unique across users and journals, condition R10); group `Rerun`; description `Added by Rerun for <topo-id>; removed by rerun revert <txn>`; direction out; action block; all profiles (`NET_FW_PROFILE2_ALL`); protocol any (256); program = the root's canonical path + the `match.exes` path; every other field (ports, addresses, interface types, service, edge traversal) at its default; enabled. Whether the firewall returns every fact exactly as set is a P4-5 write-contract measurement; a fact it normalises is compared in its normalised form, documented there (ADR 0020 X table only if something cannot be compared).
- **Add:** count rules of that name (enumeration over `INetFwRules::get__NewEnum` / `IEnumVARIANT`, because `Item(name)` returns only the first): must be 0, else `Refused(DuplicateName)` → then `Add` → enumerate again: exactly one, every fact equal, else `Foreign` and the helper's rollback.
- **Remove (R10, B12 c):** `INetFwRules::Remove(name)` removes **every** rule of that name (to be confirmed by the P4-5 contract; the design assumes the worst). Hence the count right before: exactly one and ours, then `Remove`, then enumerate again: none. A same-named rule an administrator adds between the count and `Remove` is removed too (needs admin; accepted, A4 question 6).
- **Never touched:** other rules, profiles, default policy, `FirewallEnabled`. The preview warns (lead decision L11) when the Windows Firewall is off in an active profile, or local rules are overridden by Group Policy (`LocalPolicyModifyState`): the rule would have no effect. Third-party firewalls are not detected in phase 4.
- **Durability:** the firewall service persists rules in the `SYSTEM` hive; no flush is available to the helper. The fake models two variants (§14): "durable on return" (assumed) and "lost until a lazy flush". Under the second, a power loss right after a revert can bring a removed rule back under a closed transaction; `rerun status` then lists Rerun-group rules that no open transaction owns (read side, §8), and a candidate X row goes to ADR 0020 with P4-5 (A4 question 7).

### 7. Exit code (`HelperExit` ⇄ `u32`)
`bits 31..24` = `0x52` (magic), `23..20` class (`Done`, `Refused`, `RolledBack`, `LeftOpen`), `19..16` reason (`Usage`, `NotElevated`, `ImageFolder`, `Build`, `Request`, `Index`, `Topo`, `Root`, `Program`, `AntiCheat`, `Ops`, `DuplicateName`, `Firewall`, `Internal`), `15..0` = 2 bits per op in request order (`NotRun`, `Before`, `After`, `Foreign`). Any other value (a crash's NTSTATUS, `STILL_ACTIVE`) is `Unknown`. The exit code of an elevated process cannot be set by a same-user process; it is the helper's statement, which the CLI compares with its own observation where it can (§8).

### 8. Observation (B12 b: is the firewall readable without admin?)
To be measured read-only (P4 condition R9; not yet in docs/09). Both outcomes are designed; the code takes the measured one, and the other stays documented here.
- **A · readable** (expected): `sys::Firewall` (read side) is part of every `System`. After the helper exits, the CLI observes every batch op itself with `policy::firewall::observe` and writes `Done(k)` only if **both** its observation and the helper's per-op report say `After`. `verify`, `status`, the revert preview and the decision "does this revert need the helper at all" observe non-elevated. `CLI_IMPORTS` grows by `ole32.dll` and `oleaut32.dll` (review).
- **B · not readable:** the helper's per-op report is the only observation. `Done(k)` is written when the report says `After` (exit class `Done` or `LeftOpen`); `verify`/`status` show firewall ops as "not observable without administrator rights"; every revert with an un-reverted helper op starts the helper. A read-only helper mode is **not** added (it would be a second UAC prompt, R3). The CLI needs no COM.
- In both: a disagreement (A) or an `Unknown` exit leaves the batch ops without `Done`, the transaction open (exit 5), and `rerun revert <txn>` resolves it with one helper run. Never a second helper run in the same CLI run.

### 9. Journal: one owner, the batch last (R3, D11 a)
- **One journal, one writer: the CLI**, holding `journal\lock` (share 0) for the whole run including the helper. The journal stays user-writable (ADR 0019); the helper never reads it, never gets its path, and trusts nothing derived from it: every remove request is checked against the live rule (§5), every add against the signed index.
- **Plan order:** helper ops are the **last** ops of a plan (planner and `exec` check; `Rules::Current` and `Rules::Recorded`). Apply: profile (op 0, B8 fence) → file ops → registry ops → helper ops. Revert is newest first, so the helper batch is reverted **first**. Each direction starts at most one helper: never a second UAC prompt (R3).
- **New records** (additive to format 1; the grammar machine of ADR 0019 shared by reader and writer):
  - `HelperBatch { first, last, request: Digest }` replaces the `Intent`s of ops `first..=last`: allowed once, before `Applied`, after every earlier intent is done, `first` = the number of intents so far, at most 8 ops. Then `Done(k)` for `k = first..=last` in order, then `Applied`. `exec` checks that the batch ends at the head's last op and that every op in it is a helper op.
  - `RevertBatch { first, last, request: Option<Digest> }` replaces the `RevertIntent`s of a batch: allowed when every op above `last` has its `RevertDone`; repeatable until the first `RevertDone(last)`; then `RevertDone(k)` for `k = last` down to `first`. `request: None` when no helper is started (every op observed `Before`).
  - `Done` and `RevertDone` of a helper op carry no file ID, no temp name, no `old_left` (`records_fit`).
- **Flush order with a batch:** every flush site that ADR 0019 places before `Applied` (game folders, `HKCU`) moves **before `HelperBatch`**, so that after the helper only `Done` records and `Applied` remain: a failure after the batch never needs a rollback through a second helper run. `HelperBatch` and `RevertBatch` flush the transaction folder (two new flush sites, J6).
- **Apply outcomes:** helper `Done` and observed `After` → `Done(k)`…, `Applied` (exit 0). `Declined`, `Refused` or `RolledBack` with every op observed `Before` → `RevertBatch { request: None }`, `RevertDone(k, Before)`…, then the normal rollback of the earlier ops → `Closed { RolledBack }` (exit 4; the reason in the report: "administrator approval declined", "the installed helper is from another build" …). This replaces "UAC declined → exit 3" of the earlier P4-2 draft: with the batch last, earlier ops have changed and were rolled back. A plan of helper ops only gives exit 4 as well (a record was written). Anything else (`LeftOpen`, `Unknown`, a disagreement) → transaction open, exit 5.
- **Revert outcomes:** helper ops observed first; only if one is not `Before` is the helper started. `Declined` leaves the `RevertBatch` and every op as it was (exit 5, "nothing was reverted; run the revert again to be asked again"); the rest of the transaction is not reverted in that run (LIFO).
- **Stacking:** the object of a helper op is its rule name; names are unique per transaction and op, so helper ops never overlap. A firewall op is no file op of its root: a root that is gone or rebound does not halt it, and a rebind does not change its recorded program path.
- **`forget`** of a transaction with a rule `After` leaves the rule; the preview names it and says it can be removed in Windows Defender Firewall (group `Rerun`) (X11 unchanged).

### 10. No click boundary (R11, B12 e)
The CLI reads (read only, `Registry::get`, native view) `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` `EnableLUA`, `ConsentPromptBehaviorAdmin`, `ConsentPromptBehaviorUser`, and its token's elevation type, into `PromptState`:
| State | When | Behaviour |
|---|---|---|
| `Consent` / `Credentials` | UAC on, the matching behaviour value 1 to 5 (admin) or 1/3 (standard user) | normal; the UAC dialog is the click boundary |
| `NoPrompt` | UAC on, administrator in approval mode, `ConsentPromptBehaviorAdmin = 0` (measured on the CI runner) | allowed; the preview says: "Windows will not ask for administrator approval on this PC: your confirmation here is the only one" |
| `Denied` | standard user, `ConsentPromptBehaviorUser = 0` | refused before the lock (exit 3): Windows denies elevation for standard users |
| `UacOff` | `EnableLUA = 0` | refused before the lock (exit 3): an administrator's CLI is elevated and refused anyway (P2-13 E3), a standard user cannot elevate |
| `Unknown` | a value missing, of another type or unreadable | treated as `NoPrompt` (the boundary is not assumed) |
With `NoPrompt` the CLI's preview confirmation (the console question, or the caller's explicit `--yes`) is the only boundary. Decided: `--yes` stays allowed. Refusing it would protect nothing: on such a machine any same-user process elevates silently without Rerun. The helper's re-validation (§5) is unchanged in every state, so what can be done is the same; only who agreed differs. Tests: §14 [F] matrix and the [SB] runner, which has `NoPrompt`.

### 11. The helper's system: no GPU, nothing it does not use
- `WinHelperSystem` (`sys::win::helper`) implements `System` so that `policy::root`, `catalog` and `detect::exe` work unchanged, and `HelperSystem` for the write side. It holds: the file system read side and `open_by_id`, known folders, the firewall read and write side, its token. `gpu()` is `NoGpu` (every call `Unsupported`, no reference to `sys::win::dxgi` or `loader`), `topology()` `NoTopology`, `registry()` and `registry_write()` refuse everything (no registry in phase 4), `elevation()` refuses (no nested elevation). It never constructs `WinSystem` or `WinGpu`.
- `elevate::serve` is the helper's only entry into `rerun-core`; it does not use `exec`, `journal`, `hw`, `pkg`, `detect::steam`, `topo::when` or `exec::standard_user` (that stays for CLI and GUI, A3 7 e).

### 12. Signatures (draft for A4; not in code before A4, B11)
```rust
// rerun-core::sys
pub trait System { /* … */ fn firewall(&self) -> &dyn Firewall; fn elevation(&self) -> &dyn Elevation; }
pub trait HelperSystem: System {                       // only WinHelperSystem and the fake's helper view
    fn firewall_write(&self) -> &dyn FirewallWrite;   // clippy.toml: only policy::firewall
    fn token(&self) -> &dyn HelperToken;
}
pub trait Firewall: Send + Sync {                       // read side; outcome B: Unsupported non-elevated
    fn rules_named(&self, name: &str) -> SysResult<Vec<FwRule>>; // every rule of exactly that name
    fn group_names(&self, group: &str) -> SysResult<Vec<String>>; // orphan listing (§6)
    fn state(&self) -> SysResult<FwState>;              // enabled per profile, current profiles, GP override
}
pub trait FirewallWrite: Send + Sync {
    fn add(&self, rule: &FwRule) -> SysResult<()>;
    fn remove_named(&self, name: &str) -> SysResult<()>; // INetFwRules::Remove: every rule of that name
}
pub struct FwRule { pub name: String, pub description: String, pub grouping: String,
    pub program: Option<String>, pub direction: FwDir, pub action: FwAction, pub profiles: u32,
    pub protocol: i32, pub enabled: bool, pub rest: FwRest /* ports, addresses, interfaces, service, edge */ }
pub trait Elevation: Send + Sync {                      // CLI side
    fn prompt(&self) -> SysResult<PromptState>;
    fn run_helper(&self, image: &RootPath, request: &RootPath, sha256: &[u8; 32]) -> SysResult<HelperRun>;
}
pub enum HelperRun { Exited(u32), Declined }
pub trait HelperToken: Send + Sync {
    fn is_elevated(&self) -> SysResult<bool>; fn drop_privileges(&self) -> SysResult<()>;
    fn own_image(&self) -> SysResult<(RootPath, RootId)>;
}
// Fs: fn open_by_id(&self, volume: &VolumeGuid, id: &FileId128) -> SysResult<Box<dyn Dir>>; // policy::root only
// Dir: fn sd_facts(&self, entry: Option<&RelPath>) -> SysResult<SdFacts>; RootInfo gains volume_guid.

// rerun-core::policy
pub fn root::helper_image(sys: &dyn System) -> Result<RootPath, RootError>;           // §2 pre-check
pub fn root::open_by_id(sys: &dyn System, fr: &ForbiddenRoots, r: &RootRef) -> Result<GameDir<'_>, RootError>;
pub struct firewall::RuleName(String);                  // parse / derive(topo, txn, op)
pub fn firewall::rule(topo: &TopoId, txn: &TxnId, op: u16, program: &ExePath) -> FwRule;
pub enum firewall::Observed { Absent, Ours, Foreign }
pub fn firewall::observe(fw: &dyn Firewall, expected: &FwRule) -> SysResult<firewall::Observed>;
pub fn firewall::add(sys: &dyn HelperSystem, rule: &FwRule) -> Result<(), FwError>;
pub fn firewall::remove(sys: &dyn HelperSystem, expected: &FwRule) -> Result<firewall::Observed, FwError>;

// rerun-core::plan (format 1, additive)
Op::FirewallRule { root: RootIx, program: RelPath }     // helper op; needs Plan.source (L8); last in the plan

// rerun-core::journal (format 1, additive)
Record::HelperBatch { first: u16, last: u16, request: Digest }
Record::RevertBatch { first: u16, last: u16, request: Option<Digest> }

// rerun-core::elevate
pub const REQUEST_FORMAT: u32 = 1; pub const MAX_REQUEST_BYTES: u64 = 64 << 10; pub const MAX_BATCH_OPS: usize = 8;
pub const BUILD_ID: &str; pub const HELPER_MIN_SEQ: u64;
pub struct Request { pub format: u32, pub build: String, pub txn: TxnId, pub body: Body }
pub enum Body {
    Add { source: PlanSource, index_dir: RootPath, root: RootRef, ops: Vec<AddOp> },
    Remove { topo: TopoId, ops: Vec<RemoveOp> },
}
pub struct RootRef { pub volume: VolumeGuid, pub file_id: FileId128, pub serial: u64, pub path: RootPath }
pub struct AddOp { pub op: u16, pub program: RelPath }
pub struct RemoveOp { pub op: u16, pub program: ExePath } // canonical path as in the head
pub fn encode(r: &Request) -> Vec<u8>; pub fn decode(b: &[u8]) -> Result<Request, RequestError>;
pub struct HelperExit { pub class: ExitClass, pub reason: Reason, pub ops: [OpResult; MAX_BATCH_OPS] }
impl HelperExit { pub fn to_code(&self) -> u32; pub fn from_code(c: u32) -> Option<Self>; }
pub fn serve(sys: &dyn HelperSystem, args: &[OsString]) -> HelperExit;

// rerun-core::exec (CLI side, crate-internal)
fn run_batch(cx: &ExecCtx<'_>, w: &mut TxnWriter, b: Batch) -> Result<BatchOutcome, ApplyError>;
fn revert_batch(cx: &ExecCtx<'_>, w: &mut RevertWriter, b: Batch) -> Result<BatchOutcome, ExecError>;
```
A test-only helper op (`Op::TestNoop`, the request body `TestNoop`) exists **only under `cfg(test)`** (B11/R7) for the two-process fake before `firewall_rule` exists; it is never in a wire format of a non-test build (a release decoder refuses it as an unknown variant, tested).

### 13. Dependencies
- **No new crate.** The firewall COM interfaces are bound by hand on `windows-sys` (P3 decision D12 a; the ADR 0008 re-evaluation of the `windows` crate ends here: it would bring about nine crates and build-time proc macros for some twenty methods). Bound: `IUnknown`, `IDispatch` (slots as untyped placeholders), `INetFwPolicy2`, `INetFwRules`, `INetFwRule`, `IEnumVARIANT`; slots and IIDs from `netfw.h`/`oaidl.h` pinned by `offset_of!` and GUID-byte tests like DXGI. `BSTR` and `VARIANT` with guards (`SysFreeString`, `VariantClear`). New `windows-sys` features (exact list in the commits): COM, variant/OLE automation, `Win32_NetworkManagement_WindowsFirewall` (CLSID, IIDs, `NET_FW_*` constants), `Win32_UI_Shell` (already used). If the binding grows beyond about 600 lines, `windows` is re-evaluated (P4 risk R4).
- `HELPER_IMPORTS` (exact allowlist, ADR 0008 style): `kernel32`, `ntdll`, `api-ms-win-core-synch-l1-2-0`, `advapi32`, `shell32`, `combase`, `ole32`, `oleaut32`, plus whatever `std` brings, found on the built binary and reviewed. Never `dxgi.dll`, `d3d*`, `dxcore.dll`, the dynamic CRT; empty delay-import table; `DependentLoadFlags == 0x800`.

### 14. Tests
- **[F] two-process fake.** `FakeSystem` gets a firewall domain (P2-9 template: `fail_at`, crash, the two durability models of §6) and an origin per call (`Cli`, `Helper`). The fake `Elevation::run_helper` calls `serve` in-process with a `HelperSystem` view of the same world (elevated token, admin-only folders by fake security descriptors, optionally another account's known folders for over-the-shoulder). Scripted: `Declined`, a crash of either side after every call, a power loss over all domains at every cut, an `Unknown` exit. Matrices: every step of CLI × helper; each property of §8/§9 (no `Done` without agreement, no second helper run, batch last, LIFO). Tamper per field of the request, of the index file (bytes, signature, other signed index, revoked or retired key, seq below the floor), of the root (another file ID, a junction, a forbidden root, the user's profile under over-the-shoulder), of the program (other hash, sha1 only, link), anti-cheat markers, duplicate names, a forged remove request (other group, changed fact, two rules). `PromptState` × `--yes`/console matrix with the preview lines. Journal J1–J9 extended for `HelperBatch`/`RevertBatch` (grammar, room rule, two new flush sites in J6).
- **Hardening of the built binary** (`crates/rerun-helper/tests/hardening.rs`, docs/08 acceptance): `HELPER_IMPORTS` on DLL level; a **test-only** reader of import function names in `tests/support` (product `detect::pe` stays without function names, ADR 0013) refuses `LoadLibrary*` unless `std` brings it (then a named, reviewed exception); a **content test** finds neither `dxgi.dll` (ASCII or UTF-16LE, case-insensitive) nor `CreateDXGIFactory1`; the **control** is the existing binary of `crates/rerun-core/tests/win_gpu_restricted.rs`, which links `WinGpu` and must fail the same content test (B9). Source rule test: no `WinGpu`, `WinSystem`, `hw::`, `journal::`, `exec::`, `pkg::`, `detect::steam`, `topo::when` in `crates/rerun-helper` and `elevate::serve`. The binary started non-elevated exits `Refused(NotElevated)` after step 2 of §3.
- **[SB] CI sandbox** (`runneradmin` elevated, `rerunci` standard): the helper copied to `C:\Program Files\Rerun\`, started directly elevated with crafted requests: each refusal code; image folder with a `Users` write ACE → `ImageFolder`; started from `target\` → `ImageFolder`; `drop_privileges` checked by a test in an elevated test process (token read back). P4-5: the firewall write contract only there (add, read back every fact, duplicates, `Remove` with two same-named rules: B12 c), the read side as `rerunci` (B12 b if not measured before). The runner has `NoPrompt` (docs/09): if a filtered `runneradmin` process can be started there, the full CLI → `runas` → helper path runs without a dialog (measured; else skipped with a warning).
- **[DEV] hand test** (few steps, instructions in the window title, the script checks itself): the real UAC dialog. P4-2: a `#[ignore]` test behind `RERUN_DEV_UAC=1` starts the installed helper through the real `Elevation` with a request for an unknown Topo: decline → `Declined`; accept → `Refused(Topo)`, nothing changed. P4-5: `rerun apply` of a `firewall_rule` plan on a test Topo signed with the test key build (never a game, only after the user's explicit "apply"): rule visible in `wf.msc`, revert removes it, one prompt each.

### 15. Cuts after A4 (each one review, one follow-up commit)
1. **P4-2a** `rerun-helper` scaffold: §3 hardening, exit `Refused(Usage)`; `HELPER_IMPORTS`, content test with control, source rule (allowed before A4).
2. **P4-2b** `elevate` codec, `HelperExit`, `serve` with the validation chain (§5 steps 1–7) and the `TestNoop` body under `cfg(test)`; `WinHelperSystem`, `NoGpu`; `open_by_id`, `sd_facts`, `helper_image`; `sys::win::elevation`, `PromptState`.
3. **P4-2c** journal records and grammar, `exec` batch with flush order, two-process fake, crash/power/tamper matrices, CLI preview lines and exit codes; clippy bans of the P3 acceptance nits as their own commit.
4. **P4-5a** firewall read side (COM binding, fake domain, contracts), B12 b result here and in docs/09.
5. **P4-5b** `FirewallWrite`, `policy::firewall`, `prim::firewall_rule`, `Op::FirewallRule`, helper add/remove, round trip `apply → verify → revert → snapshot identical` (snapshot scope: group `Rerun` and every rule of a planned name).

## Alternatives
- **Request on the command line** instead of a file: no file and no TOCTOU on it, but the 32,767-character limit leaves no room for the phase 6 file ops, and the UAC details and every process listing would show it. Not now; reconsider if the file causes trouble.
- **A named pipe or a result file back:** no handle survives the elevation boundary; a pipe needs a server, an ACL and a protocol; a result file means an elevated write into a user-writable folder. The exit code carries all phase 4 needs.
- **Helper batch first** (the earlier L3): a declined prompt would change nothing (exit 3), but a revert (LIFO) would then reach the helper ops last, after the user's files, and a failure in between would need a second prompt. R3 keeps one prompt per direction.
- **Revert through the signed index** (as for files in phase 6): a retired index or a moved game would make a rule unremovable; a rule carries every fact needed to recognise it (R1).
- **A Steam check in the helper** (B12 f, "only roots Steam detected"): Steam's files are user-writable, so it adds no trust; the signed SHA-256 (E3) is stricter and needs no VDF parser elevated.
- **`windows` crate for COM:** see §13.
- **Refusing `--yes` without a prompt:** see §10.
- **A read-only helper run for observation** (outcome B): a second prompt per run, against R3.

## Consequences
- New crate `rerun-helper`, new module `rerun-core::elevate`, `policy::firewall`, `sys::win::{elevation, helper, firewall, com}`, `sys::fake` firewall domain and helper view. `rerun-launch` is unaffected.
- **Amendments with the cuts:** ADR 0007 (`open_by_id`, `sd_facts`, `volume_guid`; a firewall-only helper writes into no root, so the admin-only rule of "Elevation" applies from phase 6); ADR 0008 (`HELPER_IMPORTS`, the COM wrapper and its ban exceptions, firewall COM by hand, `ShellExecuteExW` exception, `CLI_IMPORTS` + `ole32`/`oleaut32` in outcome A); ADR 0019 (`HelperBatch`, `RevertBatch`, flush order, flush sites); ADR 0020 (`Op::FirewallRule`, helper ops last, X row candidate for §6 durability, `NeedsHelper` now served); ADR 0024 (the helper reads `<sha>.json` from the user's `index` folder by hash with `trusted_keys()` and `HELPER_MIN_SEQ`; a firewall remove reads no index); ADR 0016 (exit 4 for a declined prompt, the `NoPrompt` line).
- docs/01 (`elevate` → `rerun-helper`, primitive table), docs/02 (`firewall_rule` step, P4-5), docs/06 (#7 rewritten to §5; new rows: helper request, firewall rules; "Principles" COM wrapper), docs/08 (helper acceptance unchanged in substance, plus R1 wording), docs/09 (two-process matrix, SB-H cases, B12 b result, [DEV] steps, helper installation by hand).
- Core rules: 1 (one short run per command), 2 (write-ahead `HelperBatch`, LIFO, R1 remove by facts), 3 (no injection; COM in-proc of a system DLL only), 4 (only signed data authorises an add), 5 (the preview shows rule, program, direction, group and the prompt state), 6 (admin only for the batch, the GUI and CLI never elevated).

## Questions for audit A4
1. **TOCTOU:** does §5 hold with nothing trusted from request, index folder, journal, plan and game folder? Is "the request chooses *which* signed data" (another signed variant, an older signed index ≥ `HELPER_MIN_SEQ`, another non-forbidden root with a matching exe) an acceptable residual?
2. **Helper replacement:** is the CLI pre-check (admin-only folder and file, no reparse) plus H2 enough before code signing (phase 5, "unknown publisher" dialog)? Do per-session drive letters (`DefineDosDevice`) matter for the path passed to `ShellExecuteExW` (win32-systems)?
3. **Remove without an index (R1):** acceptable that a forged remove request can delete Rerun-group rules whose facts it states?
4. **Journal across two processes:** are `HelperBatch`/`RevertBatch`, "flushes before the batch", "`Done` only when both agree", exit 4 on a declined apply and exit 5 on a declined revert complete and right?
5. **B12 b:** is outcome B (the helper's report as the only observation) acceptable, or must Rerun refuse `firewall_rule` if the firewall is not readable non-elevated?
6. **R10:** count-then-`Remove` with the race named in §6; enough?
7. **Durability:** no flush for firewall rules; is the orphan listing in `status` plus an X row enough if the lazy model is real?
8. **`NoPrompt`:** agree that `--yes` stays allowed (§10)?
9. **Hardening and tests:** privileges, image check, COM `CLSCTX_INPROC_SERVER`, content test with the `win_gpu_restricted` control (B9); `FILE_OPEN_BY_FILE_ID` with 8 vs 16-byte IDs on NTFS/ReFS (win32-systems); what must be [DEV] beyond the dialog?
10. **Build ID:** is `version + commit` (`dev` locally) enough, or should a dev build carry more?
