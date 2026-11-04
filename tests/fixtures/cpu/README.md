# CPU fixtures

Serialized `rerun_proto::cpu::CpuTopology` (JSON). Values follow the Windows semantics of
`GetSystemCpuSetInformation`:

- `core` = `CoreIndex`, i.e. the index of the first logical processor of the core (SMT siblings share it).
- `llc` = `LastLevelCacheIndex`, i.e. the index of the first logical processor of the L3 group.
- `efficiency_class` = `EfficiencyClass` (AMD without hybrid cores: 0 everywhere).
- `llc_sizes` in bytes.

| File | System | State |
|---|---|---|
| `ryzen9-5950x.json` | 2 CCDs × 8 cores × 2 threads, 32 MiB L3 each | Built from the datasheet. **Phase 1:** compare with a real dump. |
| `i5-6600.json` | 4 cores, no SMT, 6 MiB L3 | Built from the datasheet. |

The remaining fixtures listed in `docs/03-cpu-topology.md` arrive in phase 3 together with the selection algorithm.
