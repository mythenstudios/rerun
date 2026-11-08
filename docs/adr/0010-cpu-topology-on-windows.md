# ADR 0010 · CPU topology on Windows

**Status:** accepted · 2026-11-04 · extends ADR 0004, ADR 0006, ADR 0008

## Context
Phase 1 reads the real CPU topology (`sys::Topology`, acceptance: the 5950X is 2 L3 groups × 8 cores × 2 threads). Phase 3 turns CPU rules into CPU Sets (`SetProcessDefaultCpuSets`, needs CPU Set IDs) and hard affinity (Job Object, per-group `GROUP_AFFINITY` masks, needs group + index). `docs/03-cpu-topology.md` puts `CpuTopology` into `rerun-proto` so that `rerun-launch` can compute on the spot, i.e. read the live topology at launch: CPU Set IDs are runtime values and a stored profile can be stale (BIOS SMT toggle, CPU swap).

Windows reports the topology twice. `GetSystemCpuSetInformation` gives per logical processor the CPU Set `Id`, `Group`, `LogicalProcessorIndex`, `CoreIndex`, `LastLevelCacheIndex`, `NumaNodeIndex`, `EfficiencyClass` and flags (`Parked`, `Allocated`, `AllocatedToTargetProcess`, `RealTime`). `CoreIndex`, `LastLevelCacheIndex` and `NumaNodeIndex` are group-relative bytes: in practice the index of the first logical processor of the core or cache in that group. A cache shared across two groups (a large single-L3 Xeon split into two groups) therefore has two different raw values. `GetLogicalProcessorInformationEx` gives cores (`RelationProcessorCore`, with efficiency class), caches with level, type, size and group masks (`RelationCache`, `GroupCount` since Windows 11), and groups (`RelationGroup`). The fixtures so far store the raw `CoreIndex`/`LastLevelCacheIndex` values and are built from datasheets.

## Decision

### Data model (`rerun-proto::cpu`)
```rust
pub struct LogicalCpu {
    pub cpu_set_id: u32,       // SYSTEM_CPU_SET_INFORMATION.CpuSet.Id
    pub group: u16,            // processor group
    pub index: u8,             // index within the group, < 64
    pub core: u32,             // dense core number
    pub llc: u32,              // dense last-level-cache number, index into `llcs`
    pub efficiency_class: u8,  // higher = more powerful
}
pub struct Llc { pub level: u8, pub size: u64 }
pub struct CpuTopology { pub cpus: Vec<LogicalCpu>, pub llcs: Vec<Llc> }
```
- `numa` is dropped: no rule uses it, and its raw value is group-relative as well. It comes back (dense, like `llc`) with the first rule that needs it.
- `llc_sizes: BTreeMap<u32, u64>` becomes `llcs: Vec<Llc>`, indexed by the dense `llc`. `level` tells an L3 from an L2 that is the last level (LP E-cores), which the UI and the presets need.
- Everything in `LogicalCpu` is needed by `rerun-launch`; nothing is core-only.

### Dense numbering
`cpus` is sorted by `(group, index)`. Cores are numbered `0, 1, …` in the order in which they first appear in `cpus`; LLCs likewise. The numbers are a pure function of the partition: two machines with the same shape give the same `CpuTopology` apart from `cpu_set_id`, and raw Windows indices never leave the parser. `CpuTopology::validate` checks: non-empty; strictly sorted by `(group, index)`; `index < 64`; unique `cpu_set_id`; `core` and `llc` dense in first-appearance order; the threads of one core share group, LLC and efficiency class; `llcs.len()` equals the number of LLCs, each with `size > 0` and `level` in `1..=4`. Fixtures, the fake and the parser output all go through it.

### Sources and authority
- **CPU Sets** are authoritative for `cpu_set_id`, the set of `(group, index)` and the flags. Queried for the system (`Process = NULL`), never filtered by Rerun's own process affinity: the topology is a machine property; what a launched process may use is phase 3.
- **`GetLogicalProcessorInformationEx(RelationAll)`**, one call, is authoritative for core membership, LLC membership (per logical processor the highest-level unified or data cache whose group masks contain it), LLC level and size, and the active groups. `GroupCount == 0` in a cache record counts as 1. Unknown relationship types (die, module, NUMA, package) are skipped by `Size`.
- **Consistency, fail closed:** the two sets of `(group, index)` are equal and match the active masks of `RelationGroup`; the core partition from `(Group, CoreIndex)` equals the one from `RelationProcessorCore`; the LLC partition from `(Group, LastLevelCacheIndex)` equals the GLPI LLC partition intersected with each group; the efficiency class of every thread equals its core's. Any mismatch is an error naming the check, never a best-effort topology: a wrong topology means an affinity across CCDs that the user was promised not to get.
- **Flags:** CPU Sets with `RealTime` or `Allocated` are not available to a game and are left out of `cpus` (after the consistency checks); dense numbering runs afterwards. `Parked` (power state, changes between calls), `SchedulingClass`, `AllocationTag` and `NumaNodeIndex` are ignored.

### Parser in `rerun-proto`, FFI per binary
- The parser is pure, safe Rust without dependencies in `rerun-proto::cpu::parse`: `CpuTopology::from_windows(cpu_sets: &[u8], processor_info: &[u8])`. It reads fields by offset from byte slices (no casts, no alignment needs), in the layout a **64-bit** process receives (`KAFFINITY` is 8 bytes). Bounds: each buffer at most 1 MiB (`rerun_proto::cpu::parse::MAX_BUFFER`, also the FFI cap); every record header must fit, `Size` must be non-zero, at least the 8-byte header and the minimum for its type and fit in the returned length, and the type is read from the record itself; at most 4,096 logical processors. The parser is pointer-width neutral, but its input is always the x64 layout: every FFI that feeds `from_windows` (now `sys::win`, which has a `compile_error!` for non-64-bit targets; the `rerun-launch` copy in phase 3) must refuse to build or run as a non-64-bit process (`compile_error!` or a runtime `Unsupported`), because a WOW64 process receives a different layout. `rerun-cpu` (32-bit, phase 6) does not use it; how it gets its selection is decided in phase 6.
- The FFI is one module per binary: `rerun-core::sys::win::cpu` now (the only callers of `GetSystemCpuSetInformation` and `GetLogicalProcessorInformationEx`), a copy of the same two calls in `rerun-launch` in phase 3. Size query, then a `u64`-aligned buffer, retried at most 4 times on `ERROR_INSUFFICIENT_BUFFER`, capped at 1 MiB (`Unsupported` beyond); only the returned length is passed to the parser. A layout test compares the parser's offsets with `offset_of!` on the `windows-sys` structs.
- Banned in `clippy.toml` (checked by `sys/win/bans.rs`): both source APIs outside `sys::win::cpu`; `GetLogicalProcessorInformation` (group 0 only), `GetSystemInfo`/`GetNativeSystemInfo` and `GetActiveProcessorCount`/`GetMaximumProcessorCount`/`GetActiveProcessorGroupCount`/`GetMaximumProcessorGroupCount` (per group or not the topology); `NtQuerySystemInformation`/`ZwQuerySystemInformation` (undocumented source); the affinity, CPU Set and NUMA readers (`GetProcessAffinityMask`, `GetProcessGroupAffinity`, `GetThreadGroupAffinity`, `GetProcessDefaultCpuSets`, `GetProcessDefaultCpuSetMasks`, `GetThreadSelectedCpuSets`, `GetThreadSelectedCpuSetMasks`, `GetNumaNodeProcessorMask`, `GetNumaNodeProcessorMaskEx`, `GetNumaProcessorNode`, `GetNumaProcessorNodeEx`: the process's view or a partial one, not the topology); every affinity and CPU Set setter (`SetProcessAffinityMask`, `SetThreadAffinityMask`, `SetThreadGroupAffinity`, `SetProcessDefaultCpuSets`, `SetProcessDefaultCpuSetMasks`, `SetThreadSelectedCpuSets`, `SetThreadSelectedCpuSetMasks`, `SetThreadIdealProcessor`, `SetThreadIdealProcessorEx`, `SetProcessAffinityUpdateMode`, `NtSetInformationThread`/`ZwSetInformationThread`, `UpdateProcThreadAttribute` (group affinity, ideal processor at creation), `ReleaseExclusiveCpuSets`) and `SetInformationJobObject` (Job Object affinity and CPU limits) until phase 3 gives them one wrapper; the remaining process creation APIs (`CreateProcessAsUserA`, `CreateProcessWithLogonW`, `CreateProcessWithTokenW`, `ShellExecuteA`/`W`, `ShellExecuteExA`/`W`; processes only through `sys::Process`); `std::thread::available_parallelism` (limited by the process affinity).

### Fixtures
- A real machine is stored **raw**: `<cpu>.raw.json` holds the bytes of both calls as hex (fixed 32-byte lines), a hand-written `description` (CPU model, Windows build) and `format: 1`; next to it `<cpu>.json` is the expected parsed `CpuTopology`. A test parses the raw file and compares, so a parser regression shows on real bytes. The raw dump contains no identifying data (indices, masks, cache geometry, volatile park flags). Exception found on the first dump (5950X, 2026-11-05): `SchedulingClass` carries the firmware's preferred-core ranking, which differs per chip sample. The dump writer therefore zeroes every CPU Set byte the parser does not read (an allowlist: bytes 20 to `Size` of each record) and checks that the scrubbed bytes parse to the same topology; a test checks those bytes are zero in every committed dump.
- The dump is written by an `#[ignore]` test against real Windows into `target/cpu-dump.json`; `rerun system` (phase 1, step 16) may expose the same later.
- Machines without a dump stay parsed-only fixtures (`CpuTopology` JSON, validated); parser edge cases are built as byte records by a small builder in the `rerun-proto` tests (like the PE builder exception in `docs/09-testing.md`).
- `CpuTopology` is not a persisted format (no journal, no topo field). If a launch profile ever stores it, that profile carries the version.

## Alternatives
- **Raw indices in the model** (as before): group-relative values need `(group, core)` pairs everywhere and split an LLC that spans groups; fixtures would encode Windows quirks.
- **CPU Sets only:** no cache sizes (X3D rule), no cross-group LLC.
- **GLPI only:** no CPU Set IDs, no reserved flags.
- **Parser in `rerun-core`, `rerun-launch` gets precomputed IDs/masks:** no parser in the shim, but stale after hardware or BIOS changes, against `docs/03-cpu-topology.md`.
- **Best effort on inconsistency:** keeps `rerun system` working on odd VMs, but can silently produce a wrong affinity.
- **Parsed-only fixture for the 5950X:** the parser would never run on real bytes in CI.

## Consequences
- Fixtures migrate (`cpu_set_id`, dense `core`/`llc`, `llcs`, no `numa`); old-shape JSON is rejected (`deny_unknown_fields`, missing field).
- `rerun-proto` grows by the parser (no dependency, no `unsafe`); the `rerun-launch` size budget is unaffected.
- `sys::win` gains `cpu` (FFI, `unsafe`) and `topology` (`WinTopology`, no `unsafe`); `TestWinSystem` uses `WinTopology`. `topology_contract` takes `&dyn Topology` and runs against the fake and real Windows (CI and locally, read-only).
- A VM or machine whose two APIs disagree gets no topology (an error with the failed check) until the case is understood; CPU rules are then unavailable, detection otherwise continues.

## Amendment P3-1b (2026-11-08): the wrapper module of `rerun-launch`
The setter bans have their one exception in `crates/rerun-launch/src/win/launch.rs` (ADR 0022): one call site each of `CreateProcessW`, `SetInformationJobObject` (extended limit flags and `JobObjectGroupInformationEx`), `UpdateProcThreadAttribute` (the job list only), `SetProcessDefaultCpuSets`, `ShellExecuteExW` and `CoInitializeEx` (740 fallback), plus the reader `GetThreadGroupAffinity` for the read-back of the suspended child's initial thread (not a topology source). Each carries `#[expect(clippy::disallowed_methods, reason)]`. `SetPriorityClass` and `AssignProcessToJobObject` are banned as well (review of P3-1b), with the same module as their only possible exception. The copy of the two topology calls is `crates/rerun-launch/src/win/cpu.rs`, compiled for 64-bit targets only; a 32-bit shim reports the topology as unsupported at run time instead of a `compile_error!`, so the CI's i686 clippy run still builds it.
