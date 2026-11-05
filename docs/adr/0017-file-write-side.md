# ADR 0017 · File write side

**Status:** accepted (decided by the user) · 2026-11-05 · amends ADR 0007 ("Other rules", "Implementation"), closes audit A1 B1 and should-items 1, 2, 3, 8, 9

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
- **Name re-check.** Before each rename and before the delete, `FileNameInformation` of the guard must still be the parent's volume path plus the expected name (folded); otherwise `Busy`, nothing renamed. Observed: the guard sees a rename by another process at once (`FileNameInformation` about 2.5 µs); while any handle below a folder is open, renaming an ancestor of it is `ACCESS_DENIED` (undocumented, an extra safeguard only).

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
The journal records `<tmp>`, the old hash `h0` and the new hash `h1` before step 2 (ADR 0019). Recovery and in-process rollback decide from what is on disk, checking every hash on a guard, never from the record alone:

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
- The fake gets share modes and an image-mapped flag (`FsFixture::hold_open`, `map_image`), `fail_at(op, nth, kind)`, `Fault::CrashAfter(step)` and `Fault::PowerLoss` (ADR 0019); `fs_write_contract` runs against the fake and, under `target/` in a `TestRoot`, against `sys::win`, plus a writing race contract (`docs/09-testing.md`).
- `sys::snapshot` (P2-5, A1 should-item 5): runs against `sys::win` as well, takes root handles (`GameDir`, `AppDir`) instead of absolute `Scope.dirs`, caps the depth of a registry walk, records lossy registry names as anomalies (ADR 0018). A snapshot meeting `Busy` fails; reverts run only with the game closed (D4), so a game holding its files does not occur in a round trip.
- ADR 0007's "Replace", "Revert" and hard-link rules are refined here; its "Packages copied from Rerun's cache" rule is the `NewFile::sha256` check in step 3.
- Core rules: no background process, no injection; rule 2 is the reason for the guard, the phases and D1.

## Open points
- Whether `windows-sys` 0.61 has `FILE_RENAME_INFORMATION_EX` and `FILE_DISPOSITION_INFORMATION_EX`; if not, `#[repr(C)]` copies in `sys::win::nt` with a layout test against the documented offsets (P2-4).
- Durability of a rename after a flush is undocumented (NTFS commits its log up to the flushed LSN); ADR 0019 treats it as best effort.
- Manual checks on a FAT32/exFAT stick (`Unsupported`), with a game running (`users()` blocks before the first write), and with a third party holding the game folder without `FILE_SHARE_WRITE` (`Busy`): `docs/09-testing.md`.
