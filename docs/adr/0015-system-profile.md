# ADR 0015 · System profile and GPU architecture table

**Status:** accepted · 2026-11-05 · extends ADR 0005, ADR 0008, ADR 0009, ADR 0010

## Context
Phase 1 step 15 builds the system profile: the facts that the five `when` keys of `docs/02-topo-format.md` (`gpu.vendor`, `gpu.arch`, `cpu.threads`, `cpu.hybrid`, `os.build`) are evaluated against in phase 4, and what `rerun system` shows (step 16). The raw sources exist: `sys::Gpu` (DXGI adapters with raw PCI IDs, ADR 0008 amendment), `sys::Topology` (`CpuTopology`, ADR 0010) and the read-only `sys::Registry` (ADR 0009). Missing are a mapping from PCI device IDs to a GPU architecture (a GPU does not report its generation, `docs/03b-gpu-display.md`), the OS build, the rule which adapter counts, and what a missing fact means for a condition.

Findings:
- Developer machine: `AMD Radeon RX 9070 XT` (`0x1002`/`0x7550`) and `Microsoft Basic Render Driver` (`0x1414`, software flag). The CI runners report the Basic Render Driver **without** the software flag.
- `docs/03b-gpu-display.md` names architectures with `_` (`rdna3_5`, `xe_lp`, `xe_hpg`); the `when.gpu.arch` pattern of the Topo schema (`^[a-z0-9]+$`) refuses them. No Topo uses `gpu.arch` yet (one schema fixture: `rdna2`).
- Everything read is untrusted: IDs and names come from the driver, the OS build from an `HKLM` value (admin-writable).

## Decision

### Scope
Step 15 serves only the five keys above. VRAM and `integrated` are in the profile for `rerun system` only; they are not `when` keys. Further GPU and display keys are scheduled in `docs/03b-gpu-display.md` ("Open decisions"); `gpu.vendor: other` is deferred (an additive schema change).

### Layers
- New module `rerun-core::hw`, above `sys`, a consumer only: no new `System` part, no new FFI, no `unsafe`, no new dependency. No serde on the profile types in step 15 (`rerun system` prints them; a persisted or JSON form, e.g. the app's `system_profile` command, is decided when it is needed).
- `read` never fails as a whole: GPU, CPU and OS are read independently, each a `Result`.

```rust
pub fn read(sys: &dyn System, table: Option<&GpuArchTable>) -> SystemProfile;

pub struct SystemProfile {
    pub gpu: Result<GpuProfile, ProfileError>,
    pub cpu: Result<CpuTopology, ProfileError>,
    pub os: Result<OsBuild, ProfileError>,
    // private: whether an arch table was given (see "Facts")
}
impl SystemProfile {
    pub fn gpu_vendor(&self) -> VendorFact;
    pub fn gpu_arch(&self) -> ArchFact;
    pub fn cpu_threads(&self) -> Fact<u32>;
    pub fn cpu_hybrid(&self) -> Fact<bool>;
    pub fn os_build(&self) -> Fact<u32>;
}

pub struct GpuProfile { pub adapters: Vec<GpuEntry> } // hardware adapters only, DXGI order
impl GpuProfile {
    pub(crate) fn new(adapters: Vec<GpuAdapter>, table: Option<&GpuArchTable>) -> Self;
    pub fn primary(&self) -> Option<&GpuEntry>; // the first one
}

pub struct GpuEntry {
    pub adapter: GpuAdapter,      // raw DXGI data (sys::gpu)
    pub vendor: GpuVendor,
    pub arch: GpuArch,
    pub integrated: Option<bool>, // from the table entry; None without one
}
impl GpuEntry {
    pub(crate) fn new(adapter: GpuAdapter, table: Option<&GpuArchTable>) -> Self;
    pub fn vram_mb(&self) -> u64; // dedicated_video_memory / 2^20, rounded down
}

pub enum GpuVendor { Amd, Nvidia, Intel, Other(u32) } // 0x1002, 0x10DE, 0x8086, else
impl GpuVendor { pub fn from_id(vendor_id: u32) -> Self; pub fn id(self) -> u32; }
pub enum GpuArch { Known(ArchId), Unknown }
pub struct ArchId(String); // ArchId::new(&str) -> Result<ArchId, ArchIdError>
pub struct OsBuild { pub build: u32, pub ubr: Option<u32> }

pub enum VendorFact { Unavailable, NoAdapter, Known(GpuVendor) }
pub enum ArchFact { Unavailable, NoAdapter, Unknown, Known(ArchId) }
pub enum Fact<T> { Known(T), Unavailable }

pub enum ProfileSource { Gpu, CpuTopology, CurrentBuildNumber }
pub enum ProfileError {
    Sys(ProfileSource, SysError),
    Missing(ProfileSource),
    Malformed(ProfileSource),
}
impl ProfileError { pub fn origin(&self) -> ProfileSource; } // not `source`: Error::source

// crate-internal until step 16 needs more: hw::gpu::read(&dyn Gpu, Option<&GpuArchTable>),
// hw::os::read(&dyn Registry), hw::os::current_version_key() and the value-name constants.
```

`ProfileError` names the source (`GPU`, `CPU topology`, `CurrentBuildNumber`, its `Display` prefix) and the kind, never raw registry or driver content.

### Adapters
- `GpuProfile::adapters` holds hardware adapters only, in DXGI order: an adapter with `software` set **or** vendor `0x1414` (Microsoft) is dropped, because CI shows the Basic Render Driver without the flag.
- The **conditions adapter** is `primary()`, the first remaining adapter. This is the order Rerun's own process sees; Windows' per-app GPU preference belongs to the game's executable and can choose another adapter on a hybrid system. The per-game choice comes with the `gpu_preference` primitive (phase 2, `docs/03b-gpu-display.md`, "Which adapter").
- `vendor` from `vendor_id`; `arch` and `integrated` from the table by `(vendor_id, device_id)`; no entry gives `Unknown` and `None`. `revision` and `subsys_id` are never consulted.

### Facts
| Accessor | Derived from | Without data |
|---|---|---|
| `gpu_vendor` | `primary().vendor` | `gpu` is `Err`: `Unavailable`; no hardware adapter: `NoAdapter` |
| `gpu_arch` | `primary().arch` | `gpu` is `Err`: `Unavailable`; no hardware adapter: `NoAdapter`; no table given: `Unavailable`; no table entry: `Unknown` |
| `cpu_threads` | `CpuTopology::logical_count()` | `cpu` is `Err`: `Unavailable` |
| `cpu_hybrid` | more than one `efficiency_class` in `CpuTopology::cpus` | `cpu` is `Err`: `Unavailable` |
| `os_build` | `OsBuild::build` | `os` is `Err`: `Unavailable` |

The checks run in the order of the "Without data" column.

### CPU
- `cpu.threads` is the system-wide count of logical processors available to games: CPU Sets flagged `RealTime` or `Allocated` are excluded (ADR 0010); never Rerun's own process affinity. On a machine with more than 64 logical processors a game that asks `GetSystemInfo` sees only its processor group; `cpu.threads` stays the system count.
- `cpu.hybrid` means "Windows reports more than one efficiency class", not "Intel P/E-cores". The 5950X has one class. Whether Zen 5c parts (Strix Point) report a second class is unverified and stays open; no guess.

### OS build
- Source: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` in `RegView::Native`, through the existing read-only `Registry::get` (ADR 0009).
- `CurrentBuildNumber` must be `RegValue::String` of ASCII digits only, without a leading zero, at least 1, fitting `u32`; anything else is `Malformed` (also `Dword`, `Raw`, surrounding spaces), an absent value `Missing`. A missing `CurrentVersion` key is a read error, `Sys(CurrentBuildNumber, NotFound)`, like a denied one (`AccessDenied`).
- `UBR` (`RegValue::Dword`) becomes `OsBuild::ubr` for display only and is never compared; absent, another type or a read error give `None` and never fail `os`.
- Banned everywhere (`clippy.toml`, checked by `sys/win/bans.rs`): `GetVersion`, `GetVersionExA`/`W`, `VerifyVersionInfoA`/`W`, `VerSetConditionMask`, `RtlGetVersion`, `RtlVerifyVersionInfo`. A read-only test on real Windows in `sys::win::testfx` cross-checks `build` against `RtlGetVersion`; the one call is `testfx::rtl_build_number`, under its own `#[expect(clippy::disallowed_methods)]`.

### GPU architecture table
**Source of truth** `data/gpu-arch.yaml` (a new top-level directory next to `topos/` and `packages/`; under `topos/` it would break `all_topos_are_valid`), schema `schema/gpu-arch.schema.json`. Format 1:
- `format: 1`; `archs: [{ id, vendor }]` declares **every** identifier of the table in `docs/03b-gpu-display.md`, unreleased ones included; `entries: [{ vendor, arch, integrated, vulkan, dx9, device_ids, device_ranges, source }]` with `vulkan` `"1.<minor>"` or `none`, `dx9` `native` or `d3d9on12`, `device_ids: [int]`, `device_ranges: [{ from, to }]` (inclusive).
- `ArchId`: pattern `^[a-z][a-z0-9_]{0,31}$` and not `unknown`. In both schemas the same `$defs/archId` (`allOf: [{ pattern }, { not: { const: "unknown" } }]`), used by `when.gpu.arch.items` of `topo.schema.json` and by `gpu-arch.schema.json`; checked identical by the shared-definitions test (ADR 0005). No schema enumerates the values: a new architecture arrives with the index, without a release.

**Validation** (`GpuArchTable::new`; the schema checks what it can express):
- arch ids unique; every `entry.arch` declared, and its vendor equal to the declared one;
- vendors only `0x1002`, `0x10DE`, `0x8086`;
- device IDs and range bounds `0..=0xFFFF`, `from <= to`;
- at most 1,024 items per entry (an ID or a range counts 1), at least one; at most 256 archs and 4,096 entries; at most 3 × 65,536 items in the whole table (`MAX_TOTAL_ITEMS`: a valid table covers each device once, so it cannot have more), checked before the lookup index is allocated;
- `vulkan` minor at most 99 (the schema's `"1.<0-99>"`);
- any double coverage of one `(vendor, device)` is an error, even with the same arch; checked over sorted intervals, never by expanding ranges;
- `source` 1 to 200 characters, no control characters, no bidi controls (`sys::gpu::is_bidi_control`);
- `revision` and `subsys` are deliberately not keys.

`TableError { at: Table | Arch(index) | Entry(index), kind }` names positions and kinds (an overlap both entries), never content.

```rust
pub struct GpuArchTable { /* archs, entries, per-vendor sorted intervals */ }
impl GpuArchTable {
    pub fn new(archs: Vec<ArchDecl>, entries: Vec<ArchEntry>) -> Result<Self, TableError>;
    pub fn builtin() -> Result<&'static GpuArchTable, TableError>; // built once through `new`
    pub fn archs(&self) -> &[ArchDecl];
    pub fn entries(&self) -> &[ArchEntry];
    pub fn arch(&self, id: &ArchId) -> Option<&ArchDecl>;
    pub fn declares(&self, id: &ArchId) -> bool;
    pub fn lookup(&self, vendor_id: u32, device_id: u32) -> Option<&ArchEntry>;
}
pub struct VkVersion { pub minor: u8 } // 1.<minor>, minor <= 99
pub struct ArchDecl { pub id: ArchId, pub vendor: u32 }
pub struct ArchEntry {
    pub vendor: u32,
    pub arch: ArchId,
    pub integrated: bool,
    pub vulkan: Option<VkVersion>, // None = `none`
    pub dx9: Dx9Path,              // Native | D3d9On12
    pub device_ids: Vec<u32>,
    pub device_ranges: Vec<DeviceRange>, // { from, to }, inclusive
    pub source: String,
}
```

**Runtime in step 15:** `new` is serde-free; `builtin()` builds from a small Rust `const` mirror of the YAML. A test parses `data/gpu-arch.yaml` with the existing dev-dependencies (`serde-saphyr` with the strict options of ADR 0005 and a `Budget` with zero anchors and aliases, `jsonschema`), validates it against the schema and through `new`, and requires equality with `builtin()`. The YAML stays the single source; the mirror is acceptable only while the table is small: the full table before phase 4 reopens this decision. The runtime YAML loader (`from_yaml`) comes in phase 4 with the index.

**Pairing:** a Topo is evaluated against exactly the table it was validated with. The built-in and the index table are never mixed; the index table replaces the built-in one wholesale.

**Shipped data in step 15:** one entry, `0x1002`/`0x7550` → `rdna4`, `integrated: false`, `dx9: native`, `vulkan: "1.4"` (`docs/03b-gpu-display.md`), source `developer machine dump, 2026-11-05 (ADR 0008)`. Test entries are synthetic and live in test code only. Every shipped ID needs its own real source (`docs/05-sources-policy.md`, "Reference data").

### Evaluation semantics (implemented in phase 4, fixed now)
- Each key gives `Yes`, `No` or `Unknown`. A `when` is the Kleene AND of its keys: any `No` → `No`, else any `Unknown` → `Unknown`, else `Yes`. An empty `when` is `Yes`.
- `Unavailable` → `Unknown`. `NoAdapter` → `No`. `ArchFact::Unknown` → `No` for any list. `GpuVendor::Other` → `No` for `gpu.vendor`.
- Several comparison operators in one object are ANDed (a range); comparisons are in `i64`.
- `Unknown` is never preselected and never applied automatically; the UI shows why.
- The phase 4 loader rejects a Topo whose `gpu.arch` names an identifier its paired table does not declare (a load error, not a silent `No`).
- `when` is never authorisation. The elevated helper never builds a profile and never evaluates `when`; it checks the plan, not the hardware.

## Alternatives
- **`RtlGetVersion` (an `Os` part of `System`):** its fields come from the PEB, which compatibility shims bend; it needs new FFI and a new trait, and has no `UBR`. **Both sources with a consistency check:** two answers and no rule which wins; the cross-check stays a test. **`KUSER_SHARED_DATA`:** an undocumented fixed address read with `unsafe`.
- **A Rust enum of architectures:** every new generation would need a release, against the principle of `docs/03b-gpu-display.md`.
- **An enum of arch values in the schemas:** the same, and a second list next to `archs`; the loader checks Topos against the declared ids instead.
- **Runtime `serde-saphyr` now:** a YAML parser in the binary for one entry; typed `u32` in `serde-saphyr` 2.1.0 also accepts forms the schema refuses (see open points).
- **`build.rs` code generation from the YAML:** a YAML parser running at build time for a table the mirror covers.
- **JSON instead of YAML:** Topos and packages are YAML (ADR 0005); hex IDs (`0x7550`) are readable in YAML only.
- **Adapter matching over any adapter, all adapters or the one with most VRAM:** "any" fires discrete-GPU fixes on a laptop's iGPU, "all" never matches a hybrid system, VRAM is a guess (shared memory blurs it). **`EnumAdapterByGpuPreference` (`IDXGIFactory6`):** a new binding, and it returns Windows' global high-performance choice, still not the game's per-app setting.
- **`unknown` as a Topo value:** would make "no data" a rule; an unknown device is an index update.
- **One untagged list of IDs and ranges** (`devices: [0x7550, { from, to }]`): mixed types need untagged deserialisation (vague errors, accepts more than intended) and `oneOf` in the schema; two typed lists are plain.

## Consequences
- `schema/topo.schema.json`: `when.gpu.arch.items` becomes `$defs/archId` (adds `_`, requires a leading letter, at most 32 characters, refuses `unknown`). Format 1 is unreleased and no Topo uses `gpu.arch`, so no migration. New `schema/gpu-arch.schema.json` and `data/gpu-arch.yaml`, with valid and invalid fixtures.
- `clippy.toml` and `bans.rs` gain the version APIs; `docs/06-security.md` (registry read, untrusted IDs, helper never evaluates `when`) and `docs/09-testing.md` (table validation, fake-based profile tests, the Windows cross-check) are updated in the commits that implement them.
- The doc comment of `CpuTopology::is_hybrid` ("Intel P/E-cores") is aligned with the efficiency-class meaning.
- Core rules: everything is read-only and in-process (no background process, nothing to revert, no injection, no elevation); the table is declarative data, not code; its sources follow `docs/05-sources-policy.md`.

## Open points
- **Phase 4 YAML loader:** typed `u32` in `serde-saphyr` 2.1.0 accepts quoted `"0x1002"`, `0o17`, `4_098` and `!!int`, while the schema refuses `"0x1002"`. The loader needs a strict integer visitor and fixtures for these forms, and it must refuse float forms as well (`30032.0`, `1e3`): JSON Schema 2020-12 counts `30032.0` as an integer, so the schema accepts it (fixture `gpu-arch-device-float.yaml`, listed as schema-valid and refused by the strict test conversion). No amendment of ADR 0005 now.
- Whether the built-in table stays as an offline fallback after phase 4: decided by phase 4.
- Efficiency classes of Zen 5c (Strix Point): verify on hardware or a dump before a Topo relies on `cpu.hybrid` for AMD.
- **Closed by ADR 0016:** adapter names (driver) and table `source` texts are shown through `rerun_core::escape::text`, which also escapes what `new` lets pass (U+2028/U+2029, U+200B, U+FEFF, tag characters).
- Phase 3: a source-rule test that the elevated helper's code never references `hw::` (it never builds a profile or evaluates `when`).
- Phase 4: the pairing rule must hold by construction: the Topo loader and `hw::read` get the same table instance from one index object. The profile only records whether a table was given, not which one.
- Licence check of each bulk source (vendor INF files and documentation, Mesa under MIT, the PCI ID Repository under BSD-3-Clause with a notice) before the full table is imported.

## Amendment 2026-11-05: `gpu_preference` in phase 4
User decision D8 of the phase 2 plan: the `gpu_preference` primitive and with it the per-game adapter, `gpu.hybrid` and `gpu.integrated` move from phase 2 to phase 4. "Phase 2" in "Adapters" above now reads "phase 4"; until then the conditions adapter stays `primary()`. The registry slot is reserved (ADR 0018), `docs/03b-gpu-display.md` is updated.

## Amendment P4-4 (2026-11-09): the evaluation is built
`rerun_core::topo::when::eval` implements "Evaluation semantics" above unchanged: one `Tri` per key, the Kleene AND, an empty or missing `when` is yes. The Topo engine (ADR 0020 amendment P4-4) shows the result per issue in its report, refuses an explicit pick whose `when` is no and plans one whose `when` is unknown only on that explicit pick, with a warning; nothing is preselected.
- **Undeclared `gpu.arch`:** the engine refuses the whole Topo when an issue names an identifier the paired table does not declare (`EngineError::UndeclaredArch`), before it evaluates anything.
- **Pairing:** until the index carries an architecture table, the CLI reads the profile with the built-in table and gives the engine the same instance (`topo::Facts::table`); without a table `gpu.arch` is unknown and no undeclared check runs. The pairing by construction from one index object comes with the index table.
- **Tests:** `topo/tests.rs` TW: each key yes, no and unknown on fake profiles (RX 9070 XT with the 5950X topology and build 26100; adapters failing; no adapter; an unknown device; no table), ranges, and the AND table.
