# 03 · CPU topology and affinity

## Principle

Topos speak in **rules**, not in thread numbers. Rerun reads the topology from Windows at launch and translates the rule to the CPU at hand. A CPU database is needed only for genuine exceptions.

## Data source

Two Windows calls, parsed together (ADR 0010):

- `GetSystemCpuSetInformation` (system-wide, `Process = NULL`): per logical processor the CPU Set `Id`, `Group`, `LogicalProcessorIndex`, `CoreIndex`, `LastLevelCacheIndex`, `EfficiencyClass` and the flags. Authoritative for the CPU Set ID, the set of `(group, index)` and the flags.
- `GetLogicalProcessorInformationEx(RelationAll)`, one call: cores (`RelationProcessorCore`), caches with level, type, size and group masks (`RelationCache`), active groups (`RelationGroup`). Authoritative for core and LLC membership (per logical processor the highest-level unified or data cache that contains it), LLC level and size. Other relationships (die, module, NUMA, package) are skipped.

The two must agree: same `(group, index)` as the active group masks, the same core partition, the same LLC partition (per group), the same efficiency class per thread. Any mismatch is an error naming the failed check, never a best-effort topology. CPU Sets with `RealTime` or `Allocated` are not available to a game and are left out; `Parked`, `SchedulingClass`, `AllocationTag` and `NumaNodeIndex` are ignored.

From this the following is built (in `rerun-proto::cpu`, so that `rerun-launch` can read the live topology at launch; `CpuTopology` instead of `Topology`, to avoid colliding with the trait `sys::Topology`):

```rust
pub struct LogicalCpu {
    pub cpu_set_id: u32,       // CPU Set ID, for SetProcessDefaultCpuSets (runtime value)
    pub group: u16,            // processor group
    pub index: u8,             // index within the group, < 64
    pub core: u32,             // dense core number (SMT siblings share it)
    pub llc: u32,              // dense last-level-cache number, index into `llcs`
    pub efficiency_class: u8,  // higher = stronger
}
pub struct Llc { pub level: u8, pub size: u64 }
pub struct CpuTopology { pub cpus: Vec<LogicalCpu>, pub llcs: Vec<Llc> }
```

`cpus` is sorted by `(group, index)`; cores and LLCs are numbered `0, 1, …` in the order in which they first appear. Raw Windows indices (`CoreIndex`, `LastLevelCacheIndex`, group-relative) never leave the parser, and an LLC shared across two groups is one `llc`. `CpuTopology::validate` checks: non-empty and at most 4,096 entries; strictly sorted; `index < 64`; unique `cpu_set_id`; dense `core`/`llc`; the threads of one core share group, LLC and efficiency class; one `Llc` per `llc`, `size > 0`, `level` in `1..=4`. The parser output, the fake and every fixture go through it.

### Parser

`CpuTopology::from_windows(cpu_sets, processor_info)` in `rerun-proto::cpu::parse`: pure, safe Rust without dependencies, reading fields by offset from the byte slices in the layout of a 64-bit process (`KAFFINITY` = 8 bytes). Every record header must fit, `Size` must be non-zero, at least the minimum of its type (with its variable mask array) and fit in the returned length. `GroupCount == 0` in a cache record (reserved before Windows 11) counts as 1. Mask bits of inactive processors are ignored.

| Structure (64-bit) | Offsets used |
|---|---|
| `SYSTEM_CPU_SET_INFORMATION` (32 bytes, minimum 20) | `Size` 0, `Type` 4, `Id` 8, `Group` 12, `LogicalProcessorIndex` 14, `CoreIndex` 15, `LastLevelCacheIndex` 16, `EfficiencyClass` 18, `AllFlags` 19 |
| `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` | `Relationship` 0, `Size` 4, union 8 |
| `PROCESSOR_RELATIONSHIP` (from record start) | `EfficiencyClass` 9, `GroupCount` 30, `GroupMask[]` 32 |
| `CACHE_RELATIONSHIP` (from record start) | `Level` 8, `CacheSize` 12, `Type` 16, `GroupCount` 38, `GroupMasks[]` 40 |
| `GROUP_RELATIONSHIP` (from record start) | `ActiveGroupCount` 10, `GroupInfo[]` 32 (48 bytes each: `ActiveProcessorCount` 1, `ActiveProcessorMask` 40) |
| `GROUP_AFFINITY` (16 bytes) | `Mask` 0, `Group` 8 |

The FFI lives in one module per binary: `rerun-core::sys::win::cpu` now, a copy of the same two calls in `rerun-launch` in phase 3. A layout test there compares these offsets with `offset_of!` on the `windows-sys` structures.

## Cases

| Case | Detection | Rule effect |
|---|---|---|
| SMT | several `LogicalCpu` with the same `core` | `smt: off` → one thread per core |
| Multiple CCDs (Ryzen 9, Threadripper) | several `llc` groups | `single_l3: true` → all threads from one group |
| X3D with 2 CCDs | `llcs` sizes unequal | `prefer_l3: largest` → V-Cache CCD |
| Intel hybrid (P/E) | several `efficiency_class` | `prefer: performance` → highest class |
| LP E-cores (Core Ultra) | lowest class, own LLC with `level: 2` | never for games, unless explicit |
| > 64 threads | several groups | mask per group; game in one group |
| 32-bit game | PE header x86 | select at most 32 logical processors |

## Selection algorithm (order)

1. Candidates = all logical CPUs of group 0 (or of the largest group).
2. `prefer: performance` → only the highest `efficiency_class`.
3. `prefer_l3: largest` → L3 group with the largest cache; otherwise with `single_l3` the L3 group with the most candidates.
4. `smt: off` → only the first thread per `core`.
5. 32-bit → truncate to 32.
6. `max_threads` → the first N (cores before SMT siblings).
7. Empty result → rule too strict, error with explanation instead of a silent fallback.

## Pitfalls

- **Core count ≠ affinity.** `GetSystemInfo().dwNumberOfProcessors` stays the same, no matter which mask is set. Games that count this way and crash with too many cores need `inproc` with `report_cores`.
- **Hard vs. soft.** Affinity (`SetProcessAffinityMask`, Job Object) is hard. CPU Sets (`SetProcessDefaultCpuSets`) are a preference; often better on hybrid CPUs because Thread Director can keep working. Default: hard.
- **Games that set affinity themselves.** Only `hold` (set again) or `inproc` (hook) helps.

## UI

Thread tiles grouped by topology: one row per L3 group or core type, SMT siblings as a pair, V-Cache CCD marked. Presets are generated from the detected system ("P-cores only" only on hybrid, "V-Cache CCD only" only on X3D with 2 CCDs).

## Test fixtures

`tests/fixtures/cpu/` (see its `README.md`). A real machine is stored **raw**: `<cpu>.raw.json` (format 1) holds the bytes of both calls as hex, next to it `<cpu>.json` is the expected parsed `CpuTopology`; a test parses the raw file and compares. Machines without a dump are parsed-only fixtures (`CpuTopology` JSON, validated). Parser edge cases are byte records built in the `rerun-proto` tests.

Planned: `ryzen9-5950x.json` (2 CCD, 32 T; built from the datasheet, a raw dump replaces it), `ryzen9-7950x3d.json`, `i9-14900k.json`, `core-ultra-9-285k.json`, `core-ultra-7-155h.json` (LP-E), `threadripper-7980x.json` (>64), `i5-6600.json` (4 cores, no SMT).
