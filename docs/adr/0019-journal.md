# ADR 0019 · Journal

**Status:** accepted (decided by the user) · 2026-11-05 · amended 2026-11-05, P2-3 plan (see "Amendment" at the end) · replaces the SQLite journal of `docs/01-architecture.md`, introduces `AppDir` (ADR 0007), closes audit A1 should-item 6 and the plan review's design blockers B-1 and B-2

## Context
Core rule 2: every change is reversible, the journal is written before the change, a revert restores the state before the first change exactly, also after a crash. `docs/01-architecture.md` planned SQLite (`rusqlite`) at `%LOCALAPPDATA%\Rerun\journal.db`. Audit A1 (should-item 6) found that at odds with ADR 0007: SQLite opens by path, creates temporary files through `GetTempPathW` (banned, ADR 0009), adds C code and needs its own allowlist entry. The plan review raised two design blockers: **B-1** a plan touches two volumes (journal on `C:`, game on `D:`) whose writes the OS does not order; **B-2** what happens on an in-process failure, and when two transactions touch the same object.

Spike P2-1 (throwaway; observed on Windows 11 build 26300, NTFS, standard user): a directory can be flushed without admin by re-opening it with an empty name relative to its `Dir` handle with `FILE_ADD_FILE | SYNCHRONIZE` and `FILE_DIRECTORY_FILE` (no path needed; read access is `ACCESS_DENIED` for a flush); `NtFlushBuffersFileEx` on a directory accepts flags 0, `NO_SYNC` and `DATA_SYNC_ONLY`, not `FLUSH_DATA_ONLY`. Measured: a 1 MiB file 3.8 ms, a directory 2.3 ms the first time and 63 µs after, a renamed temp file 0.7 ms. Whether a flushed rename survives a power loss is **undocumented** (NTFS commits its log up to the flushed LSN).

## Decision

### File-based, under `AppDir` (user decision D2)
- `policy::root::AppDir` is the third root kind: `<LocalAppData>\Rerun`. `LocalAppData` comes from `KnownFolders` (process token, never the environment, ADR 0009) and is opened by absolute path through `open_abs` like a store root (a redirection above it is followed); its canonical path must pass `RootPath` (drive letter, no network) and not be a volume root, and its volume must support POSIX delete and rename (ADR 0017). `Rerun` and everything below it are opened handle-relative and created one directory at a time if missing; a reparse point there is `RootError::Reparse`, never followed. `AppDir` is not checked against `ForbiddenRoots`, whose `LocalAppData\Rerun` entry exists to keep game and store roots out of it.
- **Not SQLite:** a C library and a build-time C compiler in the shipped binary, path-based opens and temp files outside ADR 0007, a WAL and shared-memory file beside the database, and a binary format a user cannot read when recovery is needed. A journal of small immutable files fits the handle API, the fake (crash and power-loss injection) and the untrusted reader below.

```
<LocalAppData>\Rerun\
  journal\
    lock                       held with share 0 by apply, revert, forget (and their recovery)
    <seq>-<tag>\               one transaction: 8-digit sequence, instance tag in hex
      head.json                the plan, byte-identical to what was previewed (PlanHash, ADR 0020)
      0001.json 0002.json …    records, numbered without gaps
      0003.bin …               backup of the old content, belongs to record 0003
  plans\<plan-hash>.json       plans written by `rerun plan` (ADR 0020)
  packages\<id>\<version>\     local package files (ADR 0020, D11)
```
- **Immutable files.** Every journal file is written once with `create_new` (temp name, write, flush, rename without replace, ADR 0017) and never rewritten, so a record is complete or absent. A transaction's state is the replay of its records. Record kinds: `Intent { op, tmp, before, backup }`, `Done { op, after }`, `Cleanup { op, name }` (a `.old` still mapped, ADR 0017), `Applied` (the closing record of an apply), `RevertIntent { op }`, `RevertDone { op, observed }`, `Rebind { root, old, new }` (ADR 0020, D5) and `Closed { RolledBack | Reverted | Forgotten }`.
- **Backups before the intent.** For a replace or delete of an existing file, the old content is streamed from the `FileGuard` into `NNNN.bin` (ADR 0017), the file is opened again, hashed and compared with the guard's hash, and only then is the `Intent` naming it (file, SHA-256, length) written. Old registry values larger than 16 KiB go to a `.bin` the same way.
- **Damaged.** A gap in the numbering, an unparsable or oversized record, an unknown `format`, or a backup whose hash differs from its intent makes the transaction `Damaged`: listed by `status`, never acted on automatically; only `forget` (with preview) closes it.

### Budgets (condition S1)
`head.json` at most 1 MiB; one op at most 8 KiB serialized (checked when the plan is built), so a plan has at most 128 ops; a record at most 64 KiB; an old registry value inline only up to 16 KiB (hex in the record), up to `MAX_VALUE_BYTES` (1 MiB, ADR 0009) in a `.bin`; at most 1,024 records per transaction; backups at most 2 GiB per file and 4 GiB per transaction (condition S6). The reader enforces every limit with bounded reads (`read_limited`, P2-2) before parsing.

### Write order and durability (B-1)
Per op: guard and backup (above) → `Intent`, flushed, and the transaction directory flushed → the change (ADR 0017: the new file is flushed before its renames) → `Done`. After the last op, before `Applied`: flush every affected parent directory (`DirWrite::flush`, the empty-name re-open above) and `RegFlushKey` every changed key (ADR 0018); a flush failure is an apply error and triggers the rollback. Then `Applied`, flushed. A revert or rollback follows the same order (`RevertIntent`, change, `RevertDone`, flushes, `Closed`).

So the intent is on disk before its change starts, and every change is on disk before the transaction counts as applied, on whichever volumes they live. Nothing orders writes between `C:` and `D:` beyond these flushes, so after a power loss any op after the last durable `Done` may be in any of its intermediate states; recovery therefore never trusts a record alone, it observes each op on disk (the phases of ADR 0017, `Observed` of ADR 0020). This is **best effort**: that the flushes run without admin is observed, that a flushed rename is durable is not documented. The test is the fake's power loss (`FakeFs::power_loss`, model in the amendment below, which replaces the "drops every change not yet flushed" reading): a test cuts power at every step boundary of a plan spanning two volumes, at every cut of each volume's log (`docs/09-testing.md`).

### Lock
`journal\lock` is opened (created on first use, never deleted) with `FILE_READ_DATA` and share 0 by `apply`, `revert` and `forget` for their whole run; a second one gets `Busy` ("another Rerun is applying or reverting"). The kernel releases it when the process ends, also on a crash. `status`, `plan`, `scan` and `system` take no lock: `status` reads immutable files and shows a transaction without a closing record as "open (in progress or interrupted)".

### Stacking (B-2)
Objects are a file or directory as `(RootId, folded RelPath)`, a registry value as `(folded RegKey, folded name)` and a key as its folded `RegKey`; an object below a directory a transaction created counts as touching that directory. An **open** transaction has an `Intent` but neither `Applied` nor `Closed`; an **active** one is `Applied` and not closed.
- No apply touches an object of an open transaction: "transaction N is interrupted; revert it first".
- Applies may stack on objects of active transactions; the plan's old state is then the earlier transaction's new state.
- Revert is LIFO per object: reverting T is refused while a later active transaction touches an object of T, and the message names it. Objects are identified by root identity, not by app ID, so two Steam apps sharing one install folder (seen on the developer machine, ADR 0012 amendment) are covered.

### Failures
- **In-process failure (B-2):** after the first `Intent`, any error makes `exec` roll back at once, newest op first, with `RevertIntent`/`RevertDone` records, then `Closed { RolledBack }`. If the rollback itself fails (a file became `Busy`), the transaction stays open, `status` shows it and the user reverts it later. Checks that need no change (identity, `users()`, Steam state, old hashes) run before `head.json` is written.
- **Recovery only on an explicit command:** Rerun never repairs anything on start (core rules 1 and 5). An interrupted transaction is reverted by `rerun revert <txn>`, with a preview built from what is observed on disk.

### The journal is untrusted input
Any process of the user can change, delete or plant files under `LocalAppData`. The reader bounds every read, parses with `deny_unknown_fields` and checks `format`; paths are parsed again as `RelPath`, roots are re-opened through `policy::root` and checked by `RootId` (a mismatch is `IdentityMismatch`, ADR 0020 D5), registry locations pass `RegPolicy::check` again (ADR 0018), and a backup is used only if its hash equals its intent. A tampered journal can therefore make Rerun do no more than a plan could, in places the user can write anyway: forget a change, or "restore" content the same user could have written directly. The elevated helper (phase 3) never reads the journal.

### Names
Transaction directories are `<seq>-<tag>`: `seq` is one more than the highest existing (taken under the lock), so LIFO has a total order; `tag` is the instance tag. Temp names are `.rerun-<tag>-<n>.tmp` (`TmpName`, ADR 0017). The instance tag is 64 bits from `std::hash::RandomState` (keys seeded from the OS random generator once per thread, varied per instance), hashed with the process ID and the start time: no new dependency (`getrandom`, `rand`) for a value that only has to avoid collisions between instances and runs. It is no secret (the journal is readable) and nothing relies on it being unpredictable: `create_new` catches every collision.

### Format
`head.json` and every record carry `format: 1`; the reader refuses any other value. A later format reads the older ones or ships with a migration plan; journal files are never rewritten in place.

## Alternatives
- **SQLite:** see above.
- **One append-only log file:** a torn last record after a crash, partial-write detection with checksums, and a rewrite to compact it; immutable files are torn-free by construction.
- **Rewriting a state file per step:** two copies of the truth during the rewrite, and a lost update on a crash.
- **Backups beside the game files (`.bak`):** inside a folder that Steam's file check, mod managers and the user change; outside the reach of the lock and the reader rules.
- **Automatic recovery on start:** acts without a preview (rule 5) and on every start (rule 1).
- **No flush, trusting the order of writes:** not guaranteed across volumes.

## Consequences
- New `rerun-core::journal` (P2-7) and `policy::root::AppDir` (P2-6). `KnownFolder::LocalAppData` is already resolved; `Documents` and other user folders wait for the `UserData` root kind (phase 4, user decision D6), with their own list instead of the forbidden list (A1 should-item 10).
- Tests: `docs/09-testing.md` (crash, power-loss and tamper matrix). Phase 2 acceptance includes the Windows Sandbox run.
- `rerun-launch` (phase 3) reads its profiles from `<LocalAppData>\Rerun\profiles`; the profiles are written by `apply` and journaled like any other file.
- Core rules: no background process (no recovery service, no start-up repair), rule 2 (write-ahead, exact backups, LIFO), rule 5 (recovery with preview).

## Open points
- Retention of closed transactions (only `.bin` files are removed when a transaction closes; heads and records stay as the log). Decide with the app's log screen (phase 5).
- The power-loss VM run (journal on `C:`, game on `D:`) is a manual case (`docs/09-testing.md`); it can show the absence of a problem, not prove durability.

## Amendment (amended 2026-11-05, P2-3 plan; decided by the user after a senior-dev cross-check)

### Power-loss model of the fake (user decision D-1)
"Drops every change not yet flushed" leaves open what a flush covers, and dropping all unflushed changes together never separates two renames of one replace, so phase B (ADR 0017) would never come out of a power loss. The fake models a volume like NTFS's ordered log instead:
- Each volume has one ordered log of metadata changes: create, rename (it touches the source and the target directory), delete, attribute change, link change, create and remove of a directory. File content is not in the log.
- Flushing a file makes its content durable and the volume's log durable up to the last change that touched that file. Flushing a directory makes the log durable up to the last change that touched an entry in it or the directory itself. Because the log is ordered, every earlier change on that volume becomes durable with it, whatever it touched.
- A power loss keeps the durable part and **any prefix** of the rest, chosen per volume independently; the tests enumerate every cut on every volume at every step boundary. Cut 0 is the original sentence (every unflushed change dropped). Content written but not flushed is lost: the file reads as its last flushed content, or empty if it was never flushed (a simplification; NTFS may show zeros).
- Across volumes nothing is ordered except by the flushes of "Write order and durability". A test passes if, for every cut, recovery finds each op `Before` or `After` (ADR 0017 amendment, A3), never `Foreign`, and never loses a backup whose intent is durable.
This is still a model of best-effort durability, not a proof; the manual VM case stays.

In the fake (P2-3): `FakeFs::sync_all()` makes everything so far durable (a clean shutdown, used at the end of a setup), `FakeFs::pending(drive)` counts the changes of a volume a power loss could drop, `FakeFs::power_loss(&keep)` keeps the durable part plus `keep[drive]` more changes per volume (default 0) and undoes the rest newest first. The log holds Rerun's changes through the write primitives (create of `<tmp>`, a lock file or a directory, rename, attribute change, a POSIX delete completing when its handle closes). A fixture or attacker change is another program that flushed: it is durable itself and makes the log of its volume durable up to that moment, so the undo of a power loss never meets a change it did not log; an undo that collides anyway is a model error and panics. A volume mounted in a folder shares the log of the drive it is mounted on (a deviation; such volumes are only read in the tests). Tests (`sys/fake/tests.rs`): for replace, `create_new`, delete, `create_dir` and `remove_dir`, a power loss after every primitive call and at every cut recovers by the A3 tables to `Before` or `After`, never `Foreign`, and a replace reaches all four phases A to D, B included, also by the cuts after the completed replace alone (a power loss keeps any prefix of the unflushed log, not only all or nothing); the flush rules of `create_new` (step 5 makes `<tmp>` durable, the rename only the folder flush; unflushed content reads as the last flushed); on two volumes, a flush of `C:` before the change on `D:` keeps the order for every pair of cuts, and without it some pair keeps the change but loses the intent.

### Crash model of the fake
A crash stops the process after a primitive call (ADR 0017 amendment, A1): every later call of the crashed process fails, so no rollback runs. A restart closes the handles Rerun held, by origin (not by process ID): pending POSIX deletes on them complete and the journal lock is released; handles and image mappings of other processes (fixture holds) stay. Fixture and attacker helpers are never blocked by the crash flag. A power loss is a crash plus the cut above, and drops every hold and mapping.

### Lock
`journal\lock` is taken with `DirWrite::lock` (ADR 0017 amendment, A7); it is part of the write contract, so `sys::win` must pass it unchanged in P2-4.
