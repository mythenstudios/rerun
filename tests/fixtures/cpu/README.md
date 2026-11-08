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

`cpu_sets` are the bytes of `GetSystemCpuSetInformation(Process = NULL)`, `processor_info` those of `GetLogicalProcessorInformationEx(RelationAll)`, 64-bit layout, exactly the returned length. `rerun-core/tests/cpu_fixtures.rs` parses every raw file and compares with the JSON. The raw bytes contain no identifying data (indices, masks, cache geometry, flags): the dump test (`dump_cpu_topology`, see `docs/09-testing.md`) zeroes every CPU Set byte the parser does not read (bytes 20 to `Size` of each record: `SchedulingClass`, which Windows fills from the chip's preferred-core ranking and which differs per sample, `AllocationTag`, reserved bytes), and `cpu_fixtures.rs` checks that every committed dump has them zero. New dump: `cargo test -p rerun-core --lib dump_cpu_topology -- --ignored`, then copy `target/cpu-dump.json` to `<cpu>.raw.json` with a real description and `target/cpu-dump.parsed.json` to `<cpu>.json` after checking the shape by hand.

| File | System | Source |
|---|---|---|
| `ryzen9-5950x.raw.json`, `ryzen9-5950x.json` | 2 CCDs × 8 cores × 2 threads, 32 MiB L3 each, CPU Set IDs `0x100`–`0x11F` | Real dump, Windows 11 build 26300.9711 (2026-11-05). |
| `i5-6600.json` | 4 cores, no SMT, 6 MiB L3 | Built from the datasheet. |
| `ryzen9-7950x3d.json` | 2 CCDs × 8 cores × 2 threads; CCD 0 96 MiB L3 (V-Cache), CCD 1 32 MiB | Built from the datasheet. |
| `ryzen9-9950x3d2.json` | 2 CCDs × 8 cores × 2 threads, 96 MiB L3 each | Built from reviews (docs/03 sources). |
| `ryzen7-3700x.json` | 1 CCD, 2 CCX × 4 cores × 2 threads, 16 MiB L3 each | Built from the datasheet. |
| `ryzen-ai-9-hx370.json` | 4 Zen 5 cores × 2 threads on 16 MiB L3, then 8 Zen 5c cores × 2 threads on 8 MiB L3, one efficiency class | Built from the datasheet; the class (0 for both) is an assumption until a dump. |
| `i9-14900k.json` | 8 P-cores × 2 threads (class 1), then 16 E-cores (class 0), one 36 MiB L3 | Built from the datasheet. |
| `core-ultra-9-285k.json` | 8 P-cores (class 1), then 16 E-cores (class 0), no SMT, one 36 MiB L3 | Built from the datasheet; enumeration order (P first) is an assumption until a dump. |
| `core-ultra-7-155h.json` | 6 P-cores × 2 threads (class 2), 8 E-cores (class 1) on a 24 MiB L3; 2 LP E-cores (class 0) with a 2 MiB L2 as last level | Built from the datasheet; classes and order are assumptions until a dump. |
| `core-ultra-7-258v.json` | Lunar Lake: 4 P-cores (class 1) on a 12 MiB L3; 4 LP E-cores (class 0) with a 4 MiB L2 as last level | Built from the datasheet; classes are an assumption until a dump. |
| `core-ultra-x9-388h.json` | Panther Lake: 4 P-cores (class 1), 8 E-cores (class 0) on an 18 MiB L3; 4 LP E-cores (class 0, the same class as the E-cores) with a 4 MiB L2 as last level | Built from announcements (docs/03 sources); E and LP E in one class on purpose, the case where only the LLC separates them. |
| `threadripper-7980x.json` | 8 CCDs × 8 cores × 2 threads, 32 MiB L3 each; two processor groups of 64 (CCD 0–3, CCD 4–7) | Built from the datasheet; the group split is an assumption until a dump. |
| `nova-lake-2tile.json` | **Synthetic.** 2 compute tiles of 8 P-cores (class 1) + 16 E-cores (class 0) on a 36 MiB L3 each; 4 LP E-cores (class 0) with a 4 MiB L2 | Unreleased; shape from leaks (docs/03 sources), sizes invented. |
| `zen6-12c.json` | **Synthetic.** 2 CCDs × 12 cores × 2 threads, 48 MiB L3 each | Unreleased; shape from leaks (docs/03 sources). |

Every fixture except the real dump uses CPU Set IDs `0x100 + n` in `(group, index)` order and puts the threads of a core next to each other; a dump replaces the fixture when the hardware is available.

`select.golden` is the snapshot of the CPU rule selection on every fixture (ADR 0022): `crates/rerun-core/tests/cpu_select.rs` compares it and, on a difference, writes the new snapshot to `target/cpu-select.golden` for review. A new fixture therefore needs a reviewed snapshot in the same commit.
