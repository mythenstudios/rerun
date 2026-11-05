# 03b · GPU and display

## Principle

The CPU tells Windows its own layout, so Rerun needs no CPU list (`03-cpu-topology.md`). The GPU does not: DXGI reports IDs, memory and a driver version, but not the generation. Rerun therefore derives `gpu.arch` from a **data table of PCI device IDs** that ships inside the signed Topo index, not in the code. A new GPU generation then arrives with the next index update, without a new Rerun release. Until the index exists (phase 4), a small built-in copy of the table is compiled in, bound to `data/gpu-arch.yaml` by a test (ADR 0015).

Display properties (refresh rate, resolution, aspect ratio, HDR) belong to the same profile: for old games they often matter more than the GPU itself.

## Data source

Already in place (ADR 0008 amendment, `sys::Gpu`): `GpuAdapter` per DXGI adapter with `name`, `vendor_id`, `device_id`, `subsys_id`, `revision`, `luid`, `dedicated_video_memory`, `shared_system_memory`, `software`, `umd_version`. Found on the developer machine: `AMD Radeon RX 9070 XT` (`0x1002`/`0x7550`, 16 GiB) and `Microsoft Basic Render Driver` (software).

Still open, each needs a decision before it is used:

- **Vulkan version per adapter** (chooses the DXVK version, see below). Either estimated from the arch table (no new DLL) or queried from `vulkan-1.dll` and matched to the DXGI adapter by LUID. Start with the table; an ADR decides the query when DXVK packages land (phase 4).
- **Display**: refresh rate, resolution, HDR state per monitor (`QueryDisplayConfig`). Phase to be decided.

## Profile

Step 15 (ADR 0015, `rerun-core::hw`):

```rust
pub struct GpuProfile {
    pub adapters: Vec<GpuEntry>,  // hardware adapters only, DXGI order; software adapters
}                                 // and vendor 0x1414 dropped; primary() = the first one
pub struct GpuEntry {
    pub adapter: GpuAdapter,      // raw DXGI data: name, IDs, memory, driver (umd_version)
    pub vendor: GpuVendor,        // Amd | Nvidia | Intel | Other(u32)
    pub arch: GpuArch,            // Known(identifier) from the table, or Unknown
    pub integrated: Option<bool>, // from the table entry, not guessed from VRAM; None if unknown
}                                 // vram_mb(): from adapter.dedicated_video_memory
```

Target, added later:

- `GpuProfile::hybrid` (an integrated and a discrete adapter are both present) and a game adapter chosen per game (see "Which adapter"): with `gpu_preference` (phase 2). Until then conditions use `primary()`.
- `GpuEntry::vulkan` (table estimate until a query exists) and `GpuEntry::dx9` (`Native | D3d9On12 | Unknown`, from the table entry): with the keys that use them. The table carries both fields from step 15 on.

`when` keys (extends `02-topo-format.md`; evaluated against the conditions adapter: `primary()` in step 15, the game adapter once `gpu_preference` exists):

| Key | Values | Note | Since |
|---|---|---|---|
| `gpu.vendor` | `amd`, `nvidia`, `intel`; `other` later (additive) | from `vendor_id`; until `other` exists, any other vendor matches none | step 15 |
| `gpu.arch` | identifiers declared in the table (`archs`) | `unknown` is a profile state, not a value: an unknown device matches no list | step 15 |
| `gpu.integrated` | bool | | phase 2 |
| `gpu.hybrid` | bool | system-wide | phase 2 |
| `gpu.vram_mb` | number, compared with `gt`/`lt` | | later |
| `gpu.vulkan` | `"1.1"`, `"1.3"`, … | estimate until queried | phase 4 |
| `gpu.dx9` | `native`, `d3d9on12` | Intel only differs | later |
| `display.refresh_hz` | number | highest refresh rate of the primary display | later |
| `display.aspect` | `"16:9"`, `"16:10"`, `"21:9"`, `"32:9"` | | later |
| `display.hdr` | bool | | later |

Driver versions are **not** a `when` key in v1: their format differs per vendor, and for old games a driver update is not a fix.

### Which adapter

The game adapter is the one the game will actually use: on a hybrid system the high-performance adapter once Rerun applies `gpu_preference` (below) or recommends it; otherwise the first hardware adapter in DXGI order, which drives the primary display. The LUID changes with every reboot and is never stored in a profile or the journal.

Step 15 implements only the second half: conditions use `primary()`, the first hardware adapter in DXGI order (software adapters and vendor `0x1414` skipped; CI runners report the Basic Render Driver without the software flag). That is the order Rerun's own process sees; Windows' per-app preference belongs to the game's executable and can pick another adapter on a hybrid system, so the per-game choice comes with `gpu_preference`.

## Architecture identifiers (as of 2026-11-05)

Status "unreleased" is based on reports and leaks; such rows get table entries only once real device IDs are public.

| Vendor | `gpu.arch` | Products (examples) | Status | Notes for fixes |
|---|---|---|---|---|
| AMD | `terascale` | Radeon HD 2000–6000 | legacy | no Vulkan: no DXVK |
| AMD | `gcn1`–`gcn4` | HD 7000, R7/R9 200/300, RX 400/500 (Polaris) | legacy | |
| AMD | `vega` | RX Vega, Radeon VII; Vega iGPUs of Ryzen APUs up to Ryzen 5000 | legacy | id kept from the existing Topo example |
| AMD | `rdna1` | RX 5000 | released | separate maintenance driver branch since 25.10.2 |
| AMD | `rdna2` | RX 6000; Ryzen 6000 iGPU, Ryzen 7000/9000 desktop iGPU, Steam Deck | released | same maintenance branch as RDNA 1 |
| AMD | `rdna3` | RX 7000; Ryzen 7040/8040 iGPU (780M) | released | |
| AMD | `rdna3_5` | Ryzen AI 300 (890M), Ryzen AI Max (Strix Halo) | released | integrated only |
| AMD | `rdna4` | RX 9000 (9070 XT: `0x7550`, developer machine) | released | |
| AMD | `rdna5` | next Radeon generation | unreleased (mid to late 2027) | |
| NVIDIA | `tesla`, `fermi` | GeForce 8000–500 | legacy | no DXVK 2 |
| NVIDIA | `kepler` | GTX 600/700 (most) | legacy, last driver branch 470 | DXVK 2 unsupported: **DXVK 1.10.3** |
| NVIDIA | `maxwell`, `pascal`, `volta` | GTX 750/900, GTX 10, Titan V | legacy, last driver branch 580 | |
| NVIDIA | `turing` | RTX 20, GTX 16 | released | |
| NVIDIA | `ampere` | RTX 30 | released | |
| NVIDIA | `ada` | RTX 40 | released | |
| NVIDIA | `blackwell` | RTX 50 | released | a Super refresh is rumoured, unconfirmed |
| NVIDIA | `rubin` | RTX 60 | unreleased (late 2027 or later) | |
| Intel | `gen9` | HD/UHD 500/600 (Skylake to Comet Lake) | legacy | native D3D9 |
| Intel | `gen11` | Iris Plus (Ice Lake) | legacy | native D3D9 |
| Intel | `xe_lp` | Iris Xe (Tiger Lake), UHD 700 (Rocket/Alder/Raptor Lake) | released | **D3D9 path per device entry**: 11th gen native, 12th gen and newer via D3D9On12 |
| Intel | `xe_hpg` | Arc A-series (Alchemist); Meteor Lake Arc iGPU (Xe-LPG) | released | D3D9On12 |
| Intel | `xe2` | Arc B580/B570 (Battlemage); Lunar Lake Arc 140V | released | D3D9On12 |
| Intel | `xe3` | Panther Lake (Core Ultra Series 3) iGPU | released | D3D9On12 (to verify) |
| Intel | `xe3p`, `xe4` | discrete Celestial reportedly cancelled; Xe4 "Druid" | unreleased | |
| Microsoft | — | Basic Render Driver | — | dropped from the profile (software flag or vendor `0x1414`) |
| Qualcomm | — | Adreno (Windows on ARM) | — | out of scope for v1 |

### The table

`data/gpu-arch.yaml` (next to `topos/` and `packages/`), validated against `schema/gpu-arch.schema.json`. Step 15 ships it as a small built-in copy checked against the YAML (ADR 0015); from phase 4 it travels in the signed index and replaces the built-in copy wholesale.

```yaml
format: 1
archs:                       # every identifier a Topo may name, unreleased ones included
  - { id: rdna4, vendor: 0x1002 }
  - { id: rdna5, vendor: 0x1002 }
  # … all identifiers of the table above
entries:
  - vendor: 0x1002
    arch: rdna4
    integrated: false
    vulkan: "1.4"            # "1.<minor>" estimate from the vendor's published support, or none
    dx9: native              # native | d3d9on12
    device_ids: [0x7550]     # explicit IDs
    # device_ranges: [{ from: …, to: … }]   inclusive ranges, only as a source states them
    source: "developer machine dump, 2026-11-05 (ADR 0008)"
```

- Identifiers: `^[a-z][a-z0-9_]{0,31}$`, never `unknown`; the schemas list no values, so a new generation needs no release. A Topo may only name declared identifiers.
- Each `(vendor, device)` is covered at most once; revision and subsystem IDs are not keys. Full validation rules and limits: ADR 0015.
- Device IDs come from public sources (vendor documentation, driver INF files, the PCI ID Repository). Check each source's licence before importing in bulk (`05-sources-policy.md`, "Reference data").
- Intel ties the D3D9 path to the CPU generation, not the GPU family, so `dx9` is per entry, never per arch.
- An unknown ID gives the profile state `GpuArch::Unknown` (never a value a Topo can name). `hw` logs nothing; from step 16 `rerun system` and later the UI say "GPU generation unknown, update the index". Topos with `gpu.arch` conditions then do not match; vendor conditions still do.

## Cases

| Problem | Detection | Fix (building block) |
|---|---|---|
| Game runs on the integrated GPU | `gpu.hybrid` | **new primitive `gpu_preference`** (below) |
| Old game washed out or wrong colours under Auto HDR | `display.hdr` | same primitive, `AutoHDREnable=0` |
| Game crashes or refuses with "too much" video memory | `gpu.vram_mb` above a Topo threshold | wrapper option that reports less memory (package `options`) |
| Game refuses an unknown GPU | Topo knowledge | wrapper option that reports another vendor/device ID |
| DXVK cannot run | `gpu.arch` `kepler` or older, `gpu.vulkan` below `1.3` | DXVK 1.10.3 instead of 2.x, or a D3D9 wrapper (dgVoodoo 2, dxwrapper) |
| DX9 game misbehaves on Intel | `gpu.dx9: d3d9on12` | separate variant (e.g. DXVK), verified per game |
| Physics or game speed broken above 60 Hz | `display.refresh_hz` | frame cap through a wrapper or Special K; Rerun does not change the monitor mode |
| Stretched image or HUD | `display.aspect` | widescreen/HUD fix packages |
| GPU-vendor-only effects (GPU PhysX on AMD/Intel) | `gpu.vendor` | information only; existing third-party launch options (e.g. a ZLUDA wrapper) are detected and never overwritten (`HANDOFF.md`, phase 3) |
| Driver no longer maintained | arch table | information only, never offered as a fix |

### Primitive `gpu_preference` (phase 2, registry write side)

- Key `HKCU\Software\Microsoft\DirectX\UserGpuPreferences`, value name = full path of the game exe, `REG_SZ`. The same value Windows writes from Settings > Display > Graphics.
- Content is a list of `Key=Value;` pairs: `GpuPreference` `0` (let Windows decide), `1` (power saving), `2` (high performance), plus other keys Windows may store, such as `AutoHDREnable`. The primitive **parses and merges**: it changes only its own key and keeps all others. Revert restores the exact original string, or deletes the value if there was none.
- Takes effect at the next start of the game; Rerun refuses to apply while the exe is running.
- Whether OpenGL and Vulkan games follow this setting depends on the driver: verify per API on a hybrid machine before a Topo relies on it; vendor control panels stay out of scope.
- Allowlist entry in `06-security.md`: this key, value names that are canonical paths of a detected game exe only.

### DXVK on Windows

The DXVK authors state they do not and cannot officially support Windows. Every DXVK variant in a Topo therefore starts as `unverified` and only becomes `verified` after a test on the stated hardware. Version choice by GPU:

- DXVK 2.7 and later: a driver with Vulkan 1.3 and the required features.
- Kepler and older: DXVK 1.10.3 (needs Vulkan 1.1).

## Test fixtures

Target, not yet in place (step 15 builds its adapters inline in `hw/tests.rs`): `tests/fixtures/gpu/`, adapter lists as JSON (as `GpuAdapter` stores them): developer machine (`rdna4` + Basic Render Driver, from the real dump), hybrid laptop (`xe_lp` + `ampere`), APU only (`rdna3` 780M), Arc A-series with an 11th-gen iGPU (D3D9On12 on the Arc), Kepler desktop (DXVK 1.10.3 path), unknown device ID, two identical discrete cards (LUID distinguishes them). Apart from the developer machine, device IDs in tests are synthetic and mapped by a test-only table; they never become shipped data (ADR 0015).

## Open decisions

Decided for phase 1, step 15 (2026-11-05):

- **`when` keys in step 15:** only the five keys of `02-topo-format.md`: `gpu.vendor`, `gpu.arch`, `cpu.threads`, `cpu.hybrid`, `os.build`.
- **Arch table now:** the schema of `gpu-arch.yaml` with all fields above (including `integrated` and `dx9`), and only a few entries, each with a source: the developer machine's RX 9070 XT (`0x1002`/`0x7550`) and what the test fixtures need. The full table follows later.
- **`unknown`** is a profile value only: it never matches a `gpu.arch` list.
- **Profile extras:** VRAM and `integrated` go into the profile so that `rerun system` can show them; they are **not** `when` keys yet.
- **Adapter for conditions:** the first hardware adapter in DXGI order; software adapters (and the Microsoft Basic Render Driver) are skipped. The per-game choice under "Which adapter" comes with `gpu_preference`.

Amendments, approved 2026-11-05 (details in ADR 0015):

- **Shipped entries:** only `0x1002`/`0x7550` → `rdna4`. Entries for tests are synthetic and live in test code only; every shipped ID needs its own real source.
- **Declared identifiers:** the table declares every identifier above in `archs`; a Topo may only use declared ones. `unknown` is forbidden as a Topo value.
- **Location and runtime:** `data/gpu-arch.yaml` with `schema/gpu-arch.schema.json`; step 15 uses a built-in copy checked against the YAML by a test, the YAML loader comes with the index (phase 4).
- **Adapter filter:** vendor `0x1414` is dropped as well (CI shows the Basic Render Driver without the software flag). `integrated` is `Option<bool>`: unknown without a table entry.
- **Missing facts:** a fact that could not be read makes its condition `Unknown`, never preselected or applied automatically; an unknown device ID and a missing adapter make it `No`.
- **`gpu.vendor: other`:** deferred, additive later.

Scheduled later:

- `gpu.hybrid` and `gpu.integrated` as `when` keys: with the `gpu_preference` primitive (phase 2).
- `gpu.vulkan`: with the DXVK packages (phase 4).
- `display.*`: a separate step, once a Topo needs it.

Still open:

- Vulkan query vs. table estimate (ADR in phase 4).
- Display API and phase.
- Whether `gpu_preference` should support picking a specific adapter on multi-GPU desktops (not in v1).
- Whether the built-in table stays as an offline fallback once the index carries the table (decide by phase 4). Either way the pairing rule of ADR 0015 holds: a Topo is evaluated against exactly the table it was validated with, the two tables are never mixed.

## Sources (checked 2026-11-05)

- `UserGpuPreferences` values (0 let Windows decide, 1 power saving, 2 high performance) and the `AutoHDREnable` key: Microsoft Q&A; Kapil Arya, "Set Graphics Preference for Apps in Windows 11".
- NVIDIA: driver branch 580 is the last for Maxwell, Pascal and Volta (Tom's Hardware, TechPowerUp, 2025); branch 470 was the last for Kepler.
- AMD: RDNA 1 and 2 on a separate maintenance branch from Adrenalin 25.10.2, with continued game support per AMD's clarification (HotHardware, Tom's Hardware, TweakTown).
- Intel: 12th-gen iGPUs and Arc have no native D3D9 and use D3D9On12; 11th gen and older are native (Intel support statement via Tom's Hardware, PC Gamer, Windows Central). Discrete Xe3P gaming GPUs reportedly cancelled (Tom's Hardware, TweakTown).
- Next generations: RDNA 5 mid to late 2027 (HotHardware, Wccftech); RTX 60 "Rubin" late 2027 or later (Tom's Hardware, PC-Welt).
- DXVK driver requirements and Windows support statement: DXVK wiki "Driver support" (github.com/doitsujin/dxvk/wiki/Driver-support).
