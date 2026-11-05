# ADR 0017 · File write side

**Status:** accepted (decided by the user) · 2026-11-05 · amends ADR 0007 ("Other rules", "Implementation"), closes audit A1 B1 and should-items 1, 2, 3, 8, 9 · amended 2026-11-05, P2-3 plan (see "Amendment" at the end; it takes precedence where the two differ)

## Context
Phase 2 writes into game folders (`file_install`, `ini_set`) and into Rerun's own folder (journal, ADR 0019). The phase 1 `Dir` trait already has writing methods, but audit A1 found them unfit for that:
- **B1:** `Dir::replace` and `Dir::remove_file` take no expected content. Hash and action are separate opens, so a file changed between them is overwritten or deleted (core rule 2).
- `replace` keeps only read-only; hidden and system are lost. A hard-linked target (a mod manager such as Vortex deploys by hard link) is silently split from its other links. `create_new` writes under the final name, so a crash leaves a torn file. `StoreDir::dir()` hands out a writable `&dyn Dir` although stores are never written. `STATUS_DELETE_PENDING` maps to `NotFound` and `STATUS_CANNOT_DELETE` to `AccessDenied`, which hides "in use, retry".

A throwaway Win32 spike (P2-1, not committed) settled the facts this ADR relies on. Everything marked "observed" was observed on Windows 11 build 26300, NTFS, as a standard user; behaviour marked "undocumented" is not promised by Microsoft and is never the only safeguard.

## Decision

### Capabilities: `Dir` reads, `DirWrite` writes
```rust
pub trait Fs: Send + Sync {
    fn open_dir(&self, abs: &Path) -> SysResult<Box<dyn Dir + '_>>;
    fn open_dir_write(&self, abs: &Path, cap: &WriteCap) -> SysResult<Box<dyn DirWrite + '_>>;
}
pub struct WriteCap(()); // zero-sized; constructor pub(crate), called only in policy::root

pub trait Dir: Send + Sync + fmt::Debug {           // read side, unchanged plus `users`
    fn info(&self) -> SysResult<RootInfo>;
    fn open_dir(&self, p: &RelPath) -> SysResult<Box<dyn Dir + '_>>;
    fn metadata(&self, p: &RelPath) -> SysResult<Option<Metadata>>;
    fn open_read(&self, p: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>>;
    fn read(&self, p: &RelPath) -> SysResult<Vec<u8>>;                     // provided
    fn read_limited(&self, p: &RelPath, max_len: u64) -> SysResult<Vec<u8>>; // provided, ADR 0011
    fn read_dir(&self, p: Option<&RelPath>) -> SysResult<Vec<DirEntry>>;   // provided, unbounded
    fn read_dir_limited(&self, p: Option<&RelPath>, max_entries: usize)
        -> SysResult<Vec<DirEntry>>;                                        // ADR 0012
    fn users(&self, p: &RelPath) -> SysResult<Vec<u32>>; // attribute-only handle, see "users"
}

pub trait DirWrite: Dir {
    fn open_dir_write(&self, p: &RelPath) -> SysResult<Box<dyn DirWrite + '_>>;
    // `name`: exactly one segment, a direct child of this handle (`InvalidPath` otherwise)
    fn guard(&self, name: &RelPath) -> SysResult<Box<dyn FileGuard + '_>>;
    fn create_new(&self, name: &RelPath, src: &mut dyn Read, new: &NewFile) -> SysResult<Written>;
    fn create_dir(&self, name: &RelPath) -> SysResult<u128>;            // file ID of the new directory
    fn remove_dir(&self, name: &RelPath, expected_id: u128) -> SysResult<()>; // empty, by handle
    fn flush(&self) -> SysResult<()>;                                   // this directory (ADR 0019)
}

pub trait FileGuard: Send + fmt::Debug {
    fn metadata(&self) -> SysResult<Metadata>;           // on the guard handle
    fn sha256(&mut self) -> SysResult<[u8; 32]>;         // streamed once, then cached
    fn reader(&mut self) -> SysResult<Box<dyn Read + '_>>; // from offset 0, for backups
    fn users(&self) -> SysResult<Vec<u32>>;              // queried on the guard handle itself
    fn replace(self: Box<Self>, expected: &[u8; 32], src: &mut dyn Read, new: &NewFile)
        -> SysResult<Replaced>;
    fn delete(self: Box<Self>, expected: &[u8; 32]) -> SysResult<()>;
    fn rename_to(self: Box<Self>, name: &RelPath) -> SysResult<()>; // recovery only, never replaces
}

pub struct NewFile { pub tmp: TmpName, pub attrs: Attrs, pub sha256: [u8; 32], pub max_len: u64 }
pub struct Written { pub sha256: [u8; 32], pub len: u64, pub file_id: u128 }
pub struct Replaced { pub new: Written, pub old_left: Option<TmpName> } // `.old` still mapped
pub struct TmpName(String); // `.rerun-<instance tag>-<n>.tmp`, chosen and journaled by ADR 0019
```
- `Fs::open_dir` returns `Box<dyn Dir>`; a write handle comes only from `Fs::open_dir_write`, which takes a `WriteCap`: a zero-sized token whose constructor is crate-internal and is called only in `policy::root`, so code outside `rerun-core` (CLI, app) cannot obtain a write handle at all. `Fs::open_dir_write`, `WriteCap::new` and `GameDir::dir_write` are `clippy.toml` bans; their callers (`policy::root`, later `exec` and `journal`) carry an `#[expect]`. There is one handle type in `sys::win` (a `Dir` handle already shares read, write and delete). The split is a capability in the types: `StoreDir::dir()` and `GameDir::dir()` return `&dyn Dir`; the writable handle of a `GameDir` and of the new `AppDir` (ADR 0019) is `pub(crate)` and reached only by `exec` and `journal` (ADR 0020). `Fs::open_dir` stays a `clippy.toml` ban outside `policy::root` and `sys::snapshot`.
- `Dir::replace`, `Dir::remove_file`, `Dir::rename`, `Dir::set_readonly` and the old `Dir::create_new`/`create_dir`/`remove_dir` leave the trait. Every write names a direct child of a write handle: the parent is the handle that is checked, renamed into and flushed, never a path resolved again.

### `FileGuard`: check and act on one handle
- Opened relative to the parent handle with `DELETE | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_ATTRIBUTES`, share `FILE_SHARE_READ` only. Observed while a guard is held: another open for write, for delete, or for read without `FILE_SHARE_DELETE` fails with `SHARING_VIOLATION`; read with `FILE_SHARE_DELETE` and attribute-only opens succeed. So the content cannot change and the file cannot be renamed or deleted by anyone else; the hash taken on the guard is the hash of what `replace` and `delete` act on.
- On open the guard refuses: not a plain file (`AccessDenied`), a reparse point (`ReparsePoint`), a case-sensitive parent (`Unsupported`), a link count other than 1 on the guard handle (`Linked`, user decision D1: a hard-linked target is "managed by a mod manager (hard link)", never replaced or deleted, also not on revert).
- `replace` and `delete` take the expected SHA-256 and compare it with the guard's hash first; a difference is the new kind `Mismatch` and nothing is touched.
- **Name re-check.** Before each rename and before the delete, `FileNameInformation` of the guard must still be the parent's volume path plus the expected name (folded); otherwise `Busy`, nothing renamed. Observed: the guard sees a rename by another process at once (`FileNameInformation` about 2.5 µs); while any handle below a folder is open, renaming an ancestor of it is `ACCESS_DENIED` (undocumented, an extra safeguard only; confirmed for every kind of handle by contract case R3, see A5).

### Replace sequence (as observed)
1. Guard on the target; checks above; hash equals `expected` (else `Mismatch`).
2. Create `<tmp>` next to it, `FILE_CREATE`, share 0, relative to the parent handle (a second `FILE_CREATE` of the name is `OBJECT_NAME_COLLISION`: `AlreadyExists`).
3. Stream `src` into `<tmp>`, hashing; at most `max_len` bytes. A hash other than `new.sha256` deletes `<tmp>` and is `Mismatch`.
4. Set the attributes (`FileBasicInformation`) on the `<tmp>` handle **after the last write**: observed, a write sets `ARCHIVE` again (`0x7` became `0x27`), and a new file starts as `0x20`.
5. Flush `<tmp>`.
6. Rename the guard to `<tmp>.old` (`FileRenameInformationEx`, no replace flag, single-segment name, `RootDirectory` = parent handle).
7. Rename `<tmp>` onto the stored spelling of the target name, without `REPLACE_IF_EXISTS` (observed to work although `<tmp>` may carry R/H/S). If someone created the name in the window between 6 and 7 (observed: others see `OBJECT_NAME_NOT_FOUND` there), the rename fails with `OBJECT_NAME_COLLISION` → `Busy`; `<tmp>` is deleted (observed to work), the intruder and `<tmp>.old` stay, and the op is `Foreign` (below).
8. POSIX delete of `<tmp>.old` through the guard: `FileDispositionInformationEx` with `DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE`; the name goes when the guard closes. Observed for an image-mapped file (a running exe or loaded DLL without an open handle): steps 1 to 7 succeed and this delete is `STATUS_CANNOT_DELETE` (also with `FORCE_IMAGE_SECTION_CHECK`). That is success with pending cleanup: `Replaced::old_left` names it, the journal records it (ADR 0019), and a later apply, revert or recovery deletes it with the old hash as the expected one.

`create_new` is the same without the guard: `<tmp>` `FILE_CREATE` share 0, write, attributes, flush, rename onto the name without replace (an existing name is `AlreadyExists` before step 2; a collision only at the rename is `Busy`), so a crash never leaves a torn file under the final name. `delete` is step 8 on the guard of the file itself.

### Intermediate states and recovery (condition S2)
(The table below is replaced by the complete tables in "Amendment", A3.) The journal records `<tmp>`, the old hash `h0` and the new hash `h1` before step 2 (ADR 0019). Recovery and in-process rollback decide from what is on disk, checking every hash on a guard, never from the record alone:

| Phase | On disk | Rule |
|---|---|---|
| A | `<tmp>`, target = `h0`, no `.old` | delete `<tmp>`; the op is `Before` |
| B | `<tmp>` and `.old` = `h0`, target name missing | rename `.old` back onto the target name (never delete `.old`), then delete `<tmp>`; `Before` |
| C | target = `h1` and `.old` = `h0` | delete `.old` (pending cleanup); `After` |
| D | target = `h1` only | `After` |

Any other combination (a target with neither hash, a `.old` without `h0`, an intruder at the target name in phase B) is `Foreign` (ADR 0020): apart from our `<tmp>`, nothing is deleted or renamed, and the names are reported (the backup of the old content stays in the journal). `<tmp>` is deleted without a hash check: it is our journaled name, created with share 0. Each phase has a crash test (`Fault::CrashAfter`, `docs/09-testing.md`).

### Renames
Only by handle, only a single segment relative to a checked `Dir` handle, never with replace. Observed: a rename target name containing `\` is resolved by the kernel and **follows junctions** (`OBJ_DONT_REPARSE` does not apply to it), `..\x` is `OBJECT_NAME_INVALID`; so `sys::win` re-asserts the single segment. Every open handle on the target folder must share write, else `SHARING_VIOLATION` (observed; Rerun's own `Dir` handles share it): a third party holding the game folder without `FILE_SHARE_WRITE` makes every rename `Busy`. The parent handle needs no access right of its own for a rename (observed); the folder's DACL decides.

### POSIX semantics are required (condition S7)
Observed: a legacy delete (`FileDispositionInformation`) with a reader still open keeps the name, and every open or create of it is `STATUS_DELETE_PENDING` until the reader closes; a POSIX delete frees the name at once (the open reader keeps the file in `\$Extend\$Deleted`). The write side therefore uses only POSIX deletes and renames. A volume without `FILE_SUPPORTS_POSIX_UNLINK_RENAME` (`0x400`, `RootInfo::supports_posix_rename`, from `GetVolumeInformationByHandleW`) gets no write handle: `GameDir`/`AppDir` refuse writing with `Unsupported` ("volume without POSIX delete and rename (FAT, exFAT)"), and `sys::win` checks again per operation. FAT and exFAT could not be tested (every local volume is NTFS); a manual case covers it.

### `users()`
`FileProcessIdsUsingFileInformation` (class 47) on a handle with `FILE_READ_ATTRIBUTES`, which no share mode blocks. Observed: it reports open handles, image sections and views (also without a handle), data mappings and the running process of an exe; the querying handle itself is not counted, a second handle of the same process is (so `FileGuard::users` queries on the guard). About 6 ms per call, so only the targets of a plan's file ops and each root's main executable are asked (user decision D4, ADR 0020). It is a check at a moment, not a lock; the guard's share mode and the `.old` rule above cover what starts afterwards.

### What "exact" means (user decision D3)
A revert restores what `sys::snapshot` compares: existence, kind, name and its case, content (SHA-256), length, the attributes read-only, hidden and system, the link count, reparse tag and link target; for the registry ADR 0018. Not restored and not compared: timestamps, file IDs, DACL and owner, alternate data streams, 8.3 names, extended attributes, compression and EFS state, and `ARCHIVE` with every other attribute. `ARCHIVE` is excluded because the system sets it on every write (observed above): any later write by the game or the user changes it, and backup tools reset it, so pinning it would make reverts fail for no effect on the game. R/H/S are set on the new file in step 4 (A1 should-item 1).

### Backups (condition S6)
A backup is streamed from `FileGuard::reader` into the journal with `create_new` (ADR 0019), never read into memory; `NewFile::max_len` caps it at 2 GiB per file (the hash limit of ADR 0014), the journal caps a transaction at 4 GiB. Larger targets are refused at plan time and again on the guard.

### Error kinds
- New `SysErrorKind::Mismatch`: an expected hash or file ID differs. Nothing was changed.
- `Busy` is defined as "transient or concurrent, a retry may succeed": `SHARING_VIOLATION`, `OBJECT_NAME_COLLISION` on a rename, `STATUS_DELETE_PENDING` (was `NotFound`), `STATUS_CANNOT_DELETE` (was `AccessDenied`; the write side always passes `IGNORE_READONLY_ATTRIBUTE`, so the remaining observed cause is an image section, "in use"), and a name that changed under a held handle.
- `OBJECT_NAME_COLLISION` on a create stays `AlreadyExists`.
- Every `SysError` keeps its `NTSTATUS` (`SysError::ntstatus`): Win32 code 5 is ambiguous (observed for both `ACCESS_DENIED` and `CANNOT_DELETE`), the status is not.

### Implementation (`sys::win`)
- `NtCreateFile` stays behind `nt::{open_relative, open_absolute_dir}`; `open_relative` gains the guard access, the `FILE_CREATE` create of `<tmp>` and new directories (share 0), and the directory re-open for flushing (empty name relative to the `Dir` handle, `FILE_ADD_FILE | SYNCHRONIZE`, `FILE_DIRECTORY_FILE`: observed to work without admin and without a path; read access is `ACCESS_DENIED` for a flush). Never `FILE_OPEN_FOR_BACKUP_INTENT`, never `FILE_OVERWRITE*`.
- `NtSetInformationFile` only in one `nt` wrapper with three classes: `FileRenameInformationEx` (65, flags 0), `FileDispositionInformationEx` (64, `0x1 | 0x2 | 0x10`), `FileBasicInformation` (attributes of a new file). `NtFlushBuffersFileEx`/`FlushFileBuffers` only in `nt`; both join the `clippy.toml` bans elsewhere.
- Writes in case-sensitive folders stay `Unsupported`.

## Alternatives
- **Expected hash on path operations** (`replace(p, expect_old, …)`, `remove_file_if`): still two opens, so the check and the act stay separate unless the share mode is held between them, which is the guard.
- **Writing in place** (truncate and write): a crash leaves a torn file, a hard link is changed for every name, and a mapped image refuses `GENERIC_WRITE` anyway (observed).
- **`ReplaceFileW`:** path-based (banned), merges ACLs, streams and attributes by its own rules, follows reparse points in the path.
- **Rename with `REPLACE_IF_EXISTS`:** would overwrite a name an intruder created in the window; without it the collision is detected.
- **Legacy delete:** leaves `DELETE_PENDING` names behind (observed), which break the next create.
- **A FAT/exFAT fallback** (legacy delete and rename): the same `DELETE_PENDING` problem and no atomic replace; old games on a FAT stick are rare. `Unsupported` is honest.
- **Comparing `ARCHIVE`:** see "What exact means".

## Consequences
- `sys::fs`: `DirWrite`, `FileGuard`, `NewFile`, `Written`, `Replaced`, `TmpName`; `Dir::users`. `SysErrorKind::Mismatch`; `status.rs` maps `DELETE_PENDING` and `CANNOT_DELETE` to `Busy`, the rename wrapper maps a collision to `Busy`. P2-2 does the trait split, P2-3 the fake, P2-4 `sys::win`.
  - **P2-2 done (2026-11-05):** the split as sketched above (after review: `Fs::open_dir` read-only, `Fs::open_dir_write` with `WriteCap`; deviation from the first sketch: `read_dir_limited` is the required listing method and `read_dir`, `read`, `read_limited` are provided); the review moved the write capability out of `Fs::open_dir`, which first returned `Box<dyn DirWrite>`). `StoreDir::dir()`/`GameDir::dir()` return `&dyn Dir`, a `StoreDir` has no write accessor (it keeps its write-capable handle only to open its game folders), and `GameDir::dir_write()` (crate-internal) refuses a volume without POSIX delete and rename with `Unsupported` as of opening. `DirWrite::open_dir_write` is an open, not a write: it is implemented in both `sys::fake` and `sys::win` (the same walk as `Dir::open_dir`; `StoreDir::game` needs it), every other `DirWrite` method returns `Unsupported` and no `FileGuard` exists yet. `Dir::users` is implemented in `sys::win` (attribute-only handle relative to the parent, plain files only: a directory is `AccessDenied`, a reparse point `ReparsePoint`); the fake reports no users until its share model. `TmpName::new` writes the instance tag as exactly 16 lowercase hex digits and `TmpName::parse` accepts only that shape (a bijection; `tag()` for the journal); recovery compares the journaled name folded and never adopts a temp name found in a listing. `SysErrorKind::TooLarge` errors keep the path as `target` and carry the bound in `SysError::limit`. The phase 1 write contracts and the fake's path-based write methods were removed with the old API.
- The fake gets share modes and image sections (`FsFixture::hold_open`, `FsFixture::mapped_image`), faults on primitive calls (`FakeFs::fail_at(call, nth, kind)`, `FakeFs::fault(call, nth, Fault::CrashAfter)`) and a power loss (`FakeFs::power_loss`, ADR 0019); `fs_write_contract` runs against the fake and, under `target/` in a `TestRoot`, against `sys::win`, plus a writing race contract (`docs/09-testing.md`). The P2-3 items below give the final names.
  - **P2-3, share model:** `FsFixture::hold_open(p, Access, Share) -> Held` (fake and `WinFixture`), `contract::share_conflict` (the `IoCheckShareAccess` rule the fake uses), `FakeFs::hold_open_as(pid, …)` for other process IDs, `FakeFs::rename_ignoring_shares` (fake only, defence-in-depth tests). The fake records every handle that stays open (`Dir` handles, `open_read` readers, holds), checks new opens and fixture moves against them and reports real `users`.
  - **P2-3, `sys::seq`:** the crate-internal module `sys::seq` holds `create_new`, `create_dir`, `remove_dir`, `flush` and `lock` over the primitive traits `PrimDir` (`support`, `lookup`, `create_tmp`, `open_lock`, `create_dir`, `open_dir_delete`, `rename`, `flush`) and `PrimFile` (`state` → `HeldState`, `write`, `set_attrs`, `flush`, `posix_delete`); the guard adds its primitives with the guard. Every name a primitive takes is a `seq::Seg`, a `RelPath` of exactly one segment, so the segment rules of `crate::path` (no `:`, no `.`/`..`, no device name, no trailing dot or space) are checked once for fake and win: no stream or ADS name can reach a primitive. `DirWrite::lock` and the marker trait `FileLock` exist (A7). The fake implements the primitives (`sys/fake/fs/prim.rs`); its step hook fires before each one with `FsOp::Write` and `StepEvent::call: Some(Prim::…)`. Every write method, also `replace`, `delete` and `rename_to` on a guard, first asks the narrow primitive `support()` (case sensitivity of the directory, POSIX support of its volume; not the full `Dir::info`): `Unsupported` for either, also `flush` and `lock`. `PrimDir::rename` needs `DELETE` on the renamed handle (the fake refuses a lock handle with `AccessDenied`). Before `<tmp>` is renamed onto its name (`create_new` and step 7), its link count must still be 1 (`Linked`; share 0 does not stop another program from adding a hard link, see A4), otherwise it is discarded (and in a replace the guard goes back, A2); only our name of it goes. `remove_dir` of a file is `InvalidPath`. `fs_write_contract` runs against the fake; its `sys::win` runner is `#[ignore]`d until P2-4.
  - **P2-3, guard:** `sys::seq::Guard` is the one `FileGuard` (`seq::guard`, replace, delete, `rename_to`); new primitives `PrimDir::volume_name` and `open_guard`, `PrimFile::name`, `read_at` and `users`. Re-checks (A4) run before step 6, before the undo rename, before step 8, before `delete` and before `rename_to`; `guard` also refuses a file that is not at the full volume path of the directory plus the name once opened (`Busy`; comparing the last segment alone would miss a move to another folder under the same name). The fixture gained `FsFixture::remove` and `FsFixture::set_attrs` (another program's delete and attribute change). `fs_link_write_contract` (L1–L3) joins `fs_write_contract`; both `sys::win` runners are `#[ignore]`d until P2-4. A rename of `.old` by someone else between step 7 and step 8 (possible only with the fake-only `rename_ignoring_shares`) ends as success with `old_left`, by A2, not as `Busy`.
  - **P2-3, image sections and delete-pending:** `FsFixture::mapped_image(p)` and `FsFixture::delete_pending(p)` (both `Ok(None)` in `WinFixture` until P2-4: a mapped image needs a valid PE in the test root, a delete-pending file a legacy delete with a second handle). Fake: `FakeFs::map_image_as(pid, abs)` (reported by `users`, renames work, a delete or an open for write is `Busy`, never counts for the ancestor rule since that was not observed) and `FakeFs::delete_pending(abs)` (A6: every open `Busy`, listings skip it, the name goes when the hold drops).
  - **P2-3, faults and crashes:** the fault unit is a call of Rerun: a primitive (`Prim::…`) or a read-side call (`Prim::ReadSide(FsOp)`, also `Fs::open_dir`). `FakeFs::fault(call, nth, Fault)` with `Fault::Fail(kind)` (the call fails before it acts) or `Fault::CrashAfter` (the call acts, then every later call of Rerun fails with `Other` until `FakeFs::restart`; a read-side call crashes before it acts); `fail_at(call, nth, kind)`, `clear_faults`, `fault_fired`, `record_calls`/`take_calls`, `crashed`. `restart` closes Rerun's handles by origin (pending POSIX deletes complete, a lock is released, old `Dir` handles and guards are stale with `Other`) and keeps other programs' holds and image sections. The fault state belongs to `FakeFs` only. A crash inside step 8 is a failed step 8, so `replace` returns success with `old_left` there (A2). After a crash no step hook fires; calls made from inside a hook (the hook plays another program) are neither counted, recorded nor faulted, but fail after a crash.
  - **P2-3, a folder held for delete (observed 2026-11-05, Windows 11 build 26300):** another program holding the folder with `DELETE` access and share read+write+delete or read+write does not block a rename into it or within it (`MoveFileExW`, POSIX rename) nor a create: the target-directory open of a rename does not ask for delete. Contract case W18b requires `create_new` and replace to work there; the fake already behaves so.
  - **P2-3, power loss:** the ordered per-volume log of ADR 0019 (amendment) in the fake (`sys/fake/fs/durable.rs`): `FakeFs::sync_all`, `pending(drive)`, `power_loss(&keep)`. `PrimFile::flush` and `PrimDir::flush` carry the durability; every cut of every replace, `create_new`, delete, `create_dir` and `remove_dir` lands in a row of A3 with `Before` or `After`.
- `sys::snapshot` (P2-5, A1 should-item 5): runs against `sys::win` as well, takes root handles (`GameDir`, `AppDir`) instead of absolute `Scope.dirs`, caps the depth of a registry walk, records lossy registry names as anomalies (ADR 0018). A snapshot meeting `Busy` fails; reverts run only with the game closed (D4), so a game holding its files does not occur in a round trip.
- ADR 0007's "Replace", "Revert" and hard-link rules are refined here; its "Packages copied from Rerun's cache" rule is the `NewFile::sha256` check in step 3.
- Core rules: no background process, no injection; rule 2 is the reason for the guard, the phases and D1.

## Open points
- Whether `windows-sys` 0.61 has `FILE_RENAME_INFORMATION_EX` and `FILE_DISPOSITION_INFORMATION_EX`; if not, `#[repr(C)]` copies in `sys::win::nt` with a layout test against the documented offsets (P2-4).
- Durability of a rename after a flush is undocumented (NTFS commits its log up to the flushed LSN); ADR 0019 treats it as best effort.
- Manual checks on a FAT32/exFAT stick (`Unsupported`), with a game running (`users()` blocks before the first write), and with a third party holding the game folder without `FILE_SHARE_WRITE` (`Busy`): `docs/09-testing.md`.

## Amendment (amended 2026-11-05, P2-3 plan; decided by the user after a senior-dev cross-check)

### A1 · One sequence, written once (user decision D-4)
The replace, `create_new`, delete, `remove_dir` and lock sequences (the checks on open, steps 1 to 8, the undo of A2, the cleanup of `<tmp>`, the re-checks of A4, the handling of step 8) live once, in a crate-internal module of `sys` (`sys::seq`), generic over a small primitive trait. `sys::fake` and `sys::win` implement only the primitives: open a guard, read on it, create `<tmp>` (`FILE_CREATE`, share 0), write, set attributes, flush a file, rename a held handle to a single segment of its parent without replace, POSIX delete on a held handle, query a held handle (name, link count, attributes, kind), create a directory, open a directory for deleting, flush a directory, open-or-create a lock file. `FileGuard` has one implementation, in `sys::seq`. The fake injects faults, crashes and power loss at the primitive layer, so the failure paths that ship in `sys::win` are the ones the fake tests exercise. `sys::win` keeps the rules that belong to one call (single-segment re-assertion, status mapping, `IGNORE_READONLY_ATTRIBUTE`) inside its primitives.

### A2 · Failures inside a sequence (user decision D-2)
`<tmp>` is created with share 0 and its handle is held until step 7, which renames that handle; cleaning up `<tmp>` is a POSIX delete on the held handle, never a re-open, so no hash is needed and nobody can swap it.
- Steps 2 to 5 fail: delete `<tmp>`, return the error. Nothing else changed.
- Step 6 fails (also a failed re-check, A4): nothing renamed; delete `<tmp>`, return the error.
- Step 7 fails: rename the guard (now `<tmp>.old`) back onto the stored name **on the same handle**, without replace, after the re-checks of A4; delete `<tmp>`; return the step-7 error. The backup state is never unguarded in between. If the undo rename fails too (an intruder holds the name: `Busy`), `<tmp>` is still deleted and the step-7 error is returned; the disk is in phase B or `Foreign` and recovery decides (A3).
- Step 8 fails for any reason (`STATUS_CANNOT_DELETE`, a failed re-check, anything else): the replace succeeded; `Ok` with `Replaced::old_left`, pending cleanup as before.
- `FileGuard::delete` (step 8 alone): any failure is an error and nothing was deleted (`STATUS_CANNOT_DELETE` stays `Busy`).
- `replace` refuses `new.sha256 == expected` with `Unsupported` ("content unchanged"): with equal hashes the phases below cannot be told apart. Planners never emit such a replace (same content with other R/H/S is not a replace; no op kind of phase 2 changes attributes only).

### A3 · Phase tables (replaces the table in "Intermediate states and recovery")
Every hash is taken on a guard (link count 1, else that entry counts as "other"). `X` is the journaled `<tmp>`. One rule for `X` in every table: **`X` is deleted if and only if the target does not hold the new content**; then it can only be ours (or planted under our journaled name, which deleting harms no one). Where the target holds the new content, our `<tmp>` was renamed away, so a file at `X` is not ours: it is left and reported. Attributes and link count beyond the hash are judged by `Observed` (ADR 0020), which may turn a phase's `After` into `Foreign`.

Replace (`h0` old, `h1` new, `h0 != h1` by A2):

| Target | `.old` | Phase | Action | Result |
|---|---|---|---|---|
| `h0` | absent | A | delete `X` | `Before` |
| absent | `h0` | B | rename `.old` back onto the target name (never delete it), delete `X` | `Before` |
| `h1` | `h0` | C | delete `.old` (expected `h0`); `X` left, reported | `After` |
| `h1` | absent | D | `X` left, reported | `After` |
| `h0` | present (any content) | — | delete `X`; nothing else | `Foreign` |
| absent | absent | — | delete `X` | `Foreign` |
| absent | not `h0` | — | delete `X` | `Foreign` |
| other (an intruder) | any | — | delete `X` | `Foreign` |
| `h1` | not `h0` | — | `X` left | `Foreign` |

`create_new` (`h1` new): target absent → delete `X`, `Before`; target `h1` → `X` left and reported, `After`; target other → delete `X`, `Foreign`.
`delete` (`h0` old): target `h0` → `Before`; absent → `After`; other → `Foreign`.
Under the power-loss model of ADR 0019 (amendment) every cut of these sequences lands in a row with result `Before` or `After`; `Foreign` arises only from someone else's change.

### A4 · Re-checks on the guard
The guard's share mode does not cover `FILE_WRITE_ATTRIBUTES` (no data access) and probably not `CreateHardLinkW` (`FileLinkInformation` on a handle without data access); contract cases pin what another process can do while a guard is held. So before step 6, before the undo rename of A2 and before step 8 (and before `delete`), the guard re-checks on its own handle: the name (`Busy`, as before), the link count is still 1 (`Linked`), and read-only, hidden and system are those it saw when it was opened (`Mismatch`). A failure there is handled by A2.

### A5 · Ancestor renames
Line 68 ("while any handle below a folder is open") and `docs/09-testing.md` (race harness: "a handle opened without `FILE_SHARE_DELETE`") disagreed. P2-3 adds a read-contract case that holds each handle kind below a folder (a `Dir` handle, an `open_read` reader, a fixture hold with and without share-delete, an attribute-only query) and renames an ancestor through the fixture; it runs on the developer machine and on the CI runner, requires the observed outcome on both (user decision D-3), and this paragraph and line 68 are corrected with the result in that commit. Principle: the fake is never stricter than Windows. Fake tests that rename an ancestor of an open handle and turn out to be refused move to a fake-only rename that ignores share modes, kept as defence-in-depth tests.

**Result (observed 2026-11-05, Windows 11 build 26300, NTFS, standard user; contract case R3, `ancestor_renames`).** Line 68 is right, `docs/09-testing.md` was too narrow (corrected). While any handle is open strictly below a folder, renaming that folder or any of its ancestors (one, two and three levels up) is `ACCESS_DENIED`, with `MoveFileExW` and with a POSIX rename (`FileRenameInfoEx`, as `std::fs::rename` does) alike. Access and share mode do not matter; observed for:

| Handle below the folder | Access | Share | Ancestor rename |
|---|---|---|---|
| `Dir` handle (directory) | list, traverse, read attributes | read, write, delete | `ACCESS_DENIED` |
| `open_read` reader (file) | `GENERIC_READ` | read | `ACCESS_DENIED` |
| hold, file or directory | read data | read and delete | `ACCESS_DENIED` |
| hold, file | read data | read, write and delete | `ACCESS_DENIED` |
| hold, file | read data | none | `ACCESS_DENIED` |
| hold, file or directory | read attributes only | all, or none | `ACCESS_DENIED` |
| guard (file) | `DELETE`, read data, read attributes | read | `ACCESS_DENIED` |

A handle on the folder itself does not block renaming that folder (its `final_path` follows). The contract requires `AccessDenied` for the kinds of the table on both runners (the guard in the write contract, W22). The fake records every handle that stays open, also an attribute-only fixture hold, and refuses the rename of any folder with such a handle below it; the two `policy::root` tests that renamed an ancestor of an open store or game handle now use `FakeFs::rename_ignoring_shares`.

Observed in the same probe: a walk through a folder held with share 0 is not blocked (`sys::win` opens the components of a walk attribute-only, which no share mode blocks), only opening or listing that folder itself is `Busy` (contract case R4); while a guard is held, another program can add a hard link to the file (`CreateHardLinkW`) and change its attributes (an open with `FILE_WRITE_ATTRIBUTES`, then read-only set): both succeed, so the re-checks of A4 are needed (contract case S2).

### A6 · `DELETE_PENDING` on the read side
A name in legacy delete-pending state cannot be opened at all, not even attribute-only. `metadata`, `open_read`, `read`, `users`, `open_dir`, `guard`, `lock` and the existence check of `create_new` return `Busy`; `read_dir` skips such an entry like one that vanished between the listing and its reopen (it is being removed). The fake models the state (fixture `delete_pending`); `sys::win` maps `STATUS_DELETE_PENDING` and `STATUS_CANNOT_DELETE` to `Busy` (P2-4, keeping the status in `SysError::ntstatus`) and skips a delete-pending entry in `read_dir` by its status.

### A7 · Lock files (journal lock, ADR 0019)
`DirWrite::lock(name) -> SysResult<Box<dyn FileLock + '_>>`: opens or creates (`FILE_OPEN_IF`) the plain file `name` directly under its final name (it stays empty and its content never matters, so no `<tmp>`), `FILE_READ_DATA | SYNCHRONIZE`, share 0, never following a reparse point (`ReparsePoint`); a directory is `AccessDenied`, a link count other than 1 `Linked`; any other open of it, by Rerun or anyone, is `Busy` until the `FileLock` drops; the kernel releases it when the process ends. `FileLock` is a marker trait (`Send + Debug`). Part of the fake and the write contract in P2-3, `sys::win` in P2-4 (`Unsupported` until then).

### A8 · Names in tests
The fake's fixture and fault names (`hold_open`, `mapped_image`, `delete_pending`, faults on primitive calls, crash and power loss) are fixed by the P2-3 commits that introduce them; each such commit updates "Consequences" above and `docs/09-testing.md` to the final names.
