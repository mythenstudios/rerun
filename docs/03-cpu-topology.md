# 03 · CPU topology and affinity

## Principle

Topos speak in **rules**, not in thread numbers. Rerun reads the topology from Windows at launch and translates the rule to the CPU at hand. A CPU database is needed only for genuine exceptions.

## Data source

- `GetLogicalProcessorInformationEx` (`RelationProcessorCore`, `RelationCache`, `RelationNumaNode`, `RelationGroup`)
- `GetSystemCpuSetInformation`: per logical processor `CoreIndex`, `EfficiencyClass`, `LastLevelCacheIndex`, `NumaNodeIndex`, `Group`, `LogicalProcessorIndex`

From this the following is built (in `rerun-proto::cpu`, so that `rerun-launch` and `rerun-cpu` can compute on the spot; `CpuTopology` instead of `Topology`, to avoid colliding with the trait `sys::Topology`):

```rust
pub struct LogicalCpu {
    pub group: u16, pub index: u8,      // processor group + index within it
    pub core: u32,                      // physical core (SMT siblings share it)
    pub efficiency_class: u8,           // higher = stronger
    pub llc: u32,                       // L3 group (≈ CCD/CCX)
    pub numa: u32,
}
pub struct CpuTopology { pub cpus: Vec<LogicalCpu>, pub llc_sizes: BTreeMap<u32, u64> }
```

## Cases

| Case | Detection | Rule effect |
|---|---|---|
| SMT | several `LogicalCpu` with the same `core` | `smt: off` → one thread per core |
| Multiple CCDs (Ryzen 9, Threadripper) | several `llc` groups | `single_l3: true` → all threads from one group |
| X3D with 2 CCDs | `llc_sizes` unequal | `prefer_l3: largest` → V-Cache CCD |
| Intel hybrid (P/E) | several `efficiency_class` | `prefer: performance` → highest class |
| LP E-cores (Core Ultra) | lowest class, own/no L3 group | never for games, unless explicit |
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

`tests/fixtures/cpu/`: `ryzen9-5950x.json` (2 CCD, 32 T), `ryzen9-7950x3d.json`, `i9-14900k.json`, `core-ultra-9-285k.json`, `core-ultra-7-155h.json` (LP-E), `threadripper-7980x.json` (>64), `i5-6600.json` (4 cores, no SMT).
