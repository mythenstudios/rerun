# CPU fixtures

Serialized `rerun_proto::cpu::CpuTopology` (JSON, ADR 0010). Every fixture must pass `CpuTopology::validate`:

- `cpus` sorted by `(group, index)`; `cpu_set_id` is the CPU Set ID (Windows: `0x100 + n` on a single-group machine).
- `core` and `llc` are **dense** numbers `0, 1, …` in the order in which they first appear in `cpus`, never the raw Windows `CoreIndex`/`LastLevelCacheIndex`. SMT siblings share `core`.
- `llcs[llc]` holds `level` (3 for an L3, 2 where the L2 is the last level) and `size` in bytes.
- `efficiency_class`: higher = more powerful (AMD without hybrid cores: 0 everywhere).

A real machine is stored **raw** as `<cpu>.raw.json` next to its expected parsed `<cpu>.json`:

```json
{
  "format": 1,
  "description": "CPU model, Windows build",
  "cpu_sets": ["<hex, 32 bytes per line>", "..."],
  "processor_info": ["<hex, 32 bytes per line>", "..."]
}
```

`cpu_sets` are the bytes of `GetSystemCpuSetInformation(Process = NULL)`, `processor_info` those of `GetLogicalProcessorInformationEx(RelationAll)`, 64-bit layout, exactly the returned length. `rerun-core/tests/cpu_fixtures.rs` parses every raw file and compares with the JSON. The raw bytes contain no identifying data (indices, masks, cache geometry, flags).

| File | System | Source |
|---|---|---|
| `ryzen9-5950x.json` | 2 CCDs × 8 cores × 2 threads, 32 MiB L3 each | Built from the datasheet. **Phase 1:** replaced by a real dump. |
| `i5-6600.json` | 4 cores, no SMT, 6 MiB L3 | Built from the datasheet. |

The remaining fixtures listed in `docs/03-cpu-topology.md` arrive in phase 3 together with the selection algorithm.
