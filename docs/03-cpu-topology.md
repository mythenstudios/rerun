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

The FFI lives in one module per binary: `rerun-core::sys::win::cpu` now (size query, `u64`-aligned buffer, at most 4 retries on `ERROR_INSUFFICIENT_BUFFER`, 1 MiB cap, only the returned length goes to the parser), a copy of the same two calls in `rerun-launch` in phase 3. `sys::win::WinTopology` reads both on every call. A layout test compares these offsets with `offset_of!` on the `windows-sys` structures (all equal, 2026-11-05). Banned in `clippy.toml`: both calls outside `sys::win::cpu`, every other processor-count source (`GetSystemInfo`, `GetNativeSystemInfo`, `GetLogicalProcessorInformation`, `Get{Active,Maximum}Processor{,Group}Count`, `NtQuerySystemInformation`, `std::thread::available_parallelism`) and every affinity, CPU Set and Job Object limit setter until phase 3.

## Cases

| Case | Detection | Rule effect |
|---|---|---|
| SMT | several `LogicalCpu` with the same `core` | `smt: off` → one thread per core |
| Multiple CCDs (Ryzen 9, Threadripper) | several `llc` groups | `single_l3: true` → all threads from one group |
| X3D with 2 CCDs | `llcs` sizes unequal | `prefer_l3: largest` → V-Cache CCD |
| Intel hybrid (P/E) | several `efficiency_class` | `prefer: performance` → highest class |
| LP E-cores (Core Ultra) | own LLC with a lower `level` (L2 as last level); the class alone may not tell them from E-cores | never for games: step 1 drops them, no rule selects them |
| > 64 threads | several groups | the game stays in one group (step 1); the mask is per group |
| 32-bit game | PE header x86 | only indices below 32 of the group (step 2) |
| Zen 2 CCX (Ryzen 3000) | two `llc` groups of 4 cores per CCD | `single_l3: true` → 4 cores, not 8; never infer the group size from the product name |
| X3D with V-Cache on both CCDs (9950X3D2) | several `llc` groups, **equal** sizes | `prefer_l3: largest` → tie → same as `single_l3` (see step 4) |
| Hybrid without SMT (Arrow Lake, Lunar Lake, Panther Lake) | several `efficiency_class`, one thread per `core` | `smt: off` is a no-op, not an error |
| Compact cores (Zen 5c, later Zen 6c) | own `llc` group with a smaller size; efficiency class still to be verified | `single_l3` → the cluster with more threads (Zen 5c); `prefer_l3: largest` → full-size cores |
| Intel with several compute tiles (Nova Lake-S, unreleased) | several `llc` groups on one Intel package | treated exactly like dual-CCD Ryzen: `single_l3` keeps a game on one tile |

## Selection algorithm (order)

`rerun_proto::cpu::rule::select(topology, rule, bitness)` (ADR 0022), pure, on the live topology at every start:

1. **Group.** Candidates = the logical CPUs of the group with the most logical CPUs; on a tie the lowest group number (a machine with one group: group 0). Within it, every LLC whose `level` is below the highest `level` in the group drops out: LP E-cores sit on their own L2 as last level next to an L3, and no rule ever selects them. A machine whose LLCs all have the same level (e.g. an old CPU with two L2s and no L3) keeps them all.
2. **32-bit.** For an x86 game only indices `< 32` stay. A WOW64 process holds every affinity mask as a 32-bit value, so a bit at index 32 or higher is invisible to the game and lost when it reads and sets its own mask (ADR 0022, B6). The limit comes before the L3 step, so the L3 choice only sees processors the game can address. Nothing left → error (`bitness`).
3. **`prefer: performance`** → only the highest `efficiency_class` among the candidates.
4. **`prefer_l3: largest`** → the LLC with the largest size, then the most candidates, then the lowest `llc` number. **`single_l3`** alone → the LLC with the most candidates, then the largest size, then the lowest `llc` number. Candidates here are the threads left before the SMT step (so SMT siblings count). Either way exactly one LLC: a rule with `single_l3` or `prefer_l3` never spreads a game across tied LLCs (9950X3D2, plain dual-CCD parts, two Nova Lake tiles). Without either, all LLCs left after step 3 stay. The number of cores per LLC is always read, never assumed (4 on Zen 2, 8 on Zen 3–5, up to 12 on Zen 6, 16 on Zen 6c).
5. **`smt: off`** → only the first thread (lowest index) of each `core`.
6. **`max_threads: N`** → the first `N` in the order "the first thread of every core, then the second thread of every core, …", each by index: cores before SMT siblings. On the 5950X, `max_threads: 8` with `single_l3` gives 8 cores × 1 thread on CCD 0 with `smt` on or off.
7. **Empty result** → error naming the step that emptied the candidates (`bitness`, or `max_threads: 0`), never a silent fallback. Steps 1, 3, 4 and 5 cannot empty a non-empty candidate set.

The result is one group, a mask within it, the CPU Set IDs of the same processors and "`threads` of `of`" (`of` = all logical processors of the machine). Golden snapshot of every fixture × a rule table × both bitnesses: `tests/fixtures/cpu/select.golden`; properties (subset of the group, one group, no LLC below the top level, x86 below index 32, one LLC with `single_l3`/`prefer_l3`, `max_threads` a prefix) on every fixture and on random topologies.

## Coverage by CPU family (as of 2026-11-05)

Rerun keeps no model list; every row below is handled by the rules above. The table records what each family looks like to the parser, so fixtures and tests can target the differences. "Unreleased" rows come from announcements and leaks and must be re-checked against a real dump before they are treated as fact.

| Family | Status | What the parser sees | Notes |
|---|---|---|---|
| Intel Core 6th–11th gen | released | one `llc`, one efficiency class, SMT on most SKUs | fixture `i5-6600.json` (no SMT) |
| Intel Core 12th–14th gen (Alder/Raptor Lake) | released | one `llc`, two classes, SMT on P-cores only | |
| Core Ultra 100 (Meteor Lake, mobile) | released | three core types; LP-E on the SoC tile with their own `llc` (level 2) | |
| Core Ultra 200S/HX (Arrow Lake, incl. 200K Plus) | released | two classes, no SMT, one `llc` | 200H/U add two LP-E cores |
| Core Ultra 200V (Lunar Lake) | released | 4 P + 4 LP-E, no SMT; LP-E cluster outside the P-core ring | |
| Core Ultra Series 3 (Panther Lake, mobile) | released (CES 2026) | 4P + 4LP-E or 4P + 8E + 4LP-E; LP-E use the same core design as the E-cores on a separate power island | **the efficiency class alone may not separate E from LP-E**; the `llc` must. Verify with a dump. |
| Core Ultra 400 (Nova Lake-S, desktop) | unreleased (announced/leaked, H2 2026 or later) | up to 16P + 32E + 4LP-E on two compute tiles, each with its own large LLC | first Intel desktop part with several L3 groups |
| Ryzen 1000/2000 (Zen, Zen+) | released | CCX of 4 cores with their own L3 | Zen+ is the oldest officially supported by Windows 11 |
| Ryzen 3000 (Zen 2) | released | per CCD two CCX of 4 cores, 16 MB L3 each | |
| Ryzen 5000/7000/9000 (Zen 3–5) | released | per CCD one group of 8 cores, 32 MB L3; Ryzen 9 has two | fixture `ryzen9-5950x` (real dump) |
| X3D, one CCD (5800X3D, 7800X3D, 9800X3D) | released | one `llc` | |
| X3D, two CCDs, V-Cache on one (7900X3D, 7950X3D, 9900X3D, 9950X3D) | released | two `llc`, unequal sizes | see pitfall on AMD's driver |
| X3D, V-Cache on both CCDs (9950X3D2 Dual Edition) | released (April 2026) | two `llc`, equal sizes (96 MB each) | tie-break in step 3 |
| Ryzen AI 300 (Strix Point) | released | Zen 5 and Zen 5c clusters with different L3 sizes | efficiency class to be verified |
| Ryzen AI Max (Strix Halo) | released | two Zen 5 CCDs, like desktop Ryzen 9 | |
| Zen 6 desktop/mobile | unreleased (late 2026 to 2027) | CCD with up to 12 cores and 48 MB L3, up to two CCDs; Zen 6c up to 16 per CCD | the reason group sizes are never assumed |
| Threadripper, EPYC, Xeon | released | many `llc` groups, more than 64 threads, several processor groups | |
| Windows on ARM (Snapdragon X) | out of scope for v1 | — | `tested_on: [arm64]` in the Topo format |

## Pitfalls

- **Core count ≠ affinity.** `GetSystemInfo().dwNumberOfProcessors` stays the same, no matter which mask is set. Games that count this way and crash with too many cores need `inproc` with `report_cores`.
- **Hard vs. soft.** Affinity (Job Object group affinity, `SetProcessAffinityMask`) is hard. CPU Sets (`SetProcessDefaultCpuSets`) are a preference; often better on hybrid CPUs because Thread Director can keep working. Default: hard.
- **Games that set affinity themselves.** Only `hold` (set again) or `inproc` (hook) helps.
- **Vendor schedulers already at work.** On dual-CCD X3D parts with V-Cache on one CCD, AMD's chipset driver parks the other CCD for games it recognises (via Game Bar); on Intel hybrid parts Thread Director steers threads. Rerun's rule must agree with them (`prefer_l3: largest` picks the same CCD the driver keeps awake) and never fight them. Parked state is ignored by the parser on purpose; the post-launch check reports what the game actually got.

## UI

Thread tiles grouped by topology: one row per L3 group or core type, SMT siblings as a pair, V-Cache CCD marked. Presets are generated from the detected system ("P-cores only" only on hybrid, "V-Cache CCD only" only on X3D with 2 CCDs).

## Test fixtures

`tests/fixtures/cpu/` (see its `README.md`). A real machine is stored **raw**: `<cpu>.raw.json` (format 1) holds the bytes of both calls as hex, next to it `<cpu>.json` is the expected parsed `CpuTopology`; a test parses the raw file and compares. Machines without a dump are parsed-only fixtures (`CpuTopology` JSON, validated). Parser edge cases are byte records built in the `rerun-proto` tests.

Present: `ryzen9-5950x.raw.json` + `ryzen9-5950x.json` (2 CCD, 32 T, real dump, Windows 11 build 26300), and built from datasheets or announcements (the README lists the assumptions each one makes until a dump exists): `i5-6600.json`, `ryzen9-7950x3d.json`, `ryzen9-9950x3d2.json` (equal V-Cache, tie-break), `ryzen7-3700x.json` (Zen 2, two CCX per CCD), `ryzen-ai-9-hx370.json` (Zen 5 + Zen 5c), `i9-14900k.json`, `core-ultra-9-285k.json`, `core-ultra-7-155h.json` (LP-E), `core-ultra-7-258v.json` (Lunar Lake, LP-E), `core-ultra-x9-388h.json` (Panther Lake, E and LP-E in one class), `threadripper-7980x.json` (two groups of 64). Synthetic, until real hardware exists: `nova-lake-2tile.json` (two compute tiles), `zen6-12c.json` (12 cores per CCD).

## Sources (checked 2026-11-05)

- Panther Lake configurations and LP-E design: heise online, "Panther Lake notebook processor" (heise.de/-10748523); PCWorld, "Intel launches Core Ultra Series 3" (pcworld.com/article/3023764).
- Nova Lake-S tiles and bLLC (leaks, unreleased): Tom's Hardware and TweakTown reports on the 52/44/28/24-core bLLC configurations.
- Zen 2 CCX layout and Zen 6 CCD (12 cores, 48 MB L3, unreleased): Wccftech, "Zen 6 Olympic Ridge" core configurations.
- 9950X3D2 Dual Edition (V-Cache on both CCDs, 96 MB L3 each, April 2026): StorageReview and HotHardware reviews.
