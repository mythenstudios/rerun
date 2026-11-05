//! Golden tests of `rerun system` (ADR 0016, `docs/09-testing.md`, "CLI"). Everything renders
//! through `Out`, so the last-resort net is checked to never fire.
//!
//! Apart from the developer machine's `0x1002`/`0x7550` (the built-in table's one entry),
//! device IDs here are synthetic.

use std::io;

use rerun_core::hw::arch::{TableError, TableErrorKind, TablePos};
use rerun_core::hw::{
    self, ArchId, GpuArch, GpuArchTable, GpuEntry, GpuProfile, GpuVendor, SystemProfile,
};
use rerun_core::sys::fake::{FakeSystem, FakeSystemBuilder};
use rerun_core::sys::registry::{Hive, RegKey, RegValue, RegView};
use rerun_core::sys::{GpuAdapter, SysErrorKind};
use rerun_proto::cpu::{CpuTopology, Llc, LogicalCpu};

use super::{render, system};
use crate::cli::Exit;
use crate::out::Out;
use crate::out::tests::Failing;

const RYZEN_5950X: &str = include_str!("../../../../tests/fixtures/cpu/ryzen9-5950x.json");
const I5_6600: &str = include_str!("../../../../tests/fixtures/cpu/i5-6600.json");

fn adapter(name: &str, vendor_id: u32, device_id: u32, vram: u64, software: bool) -> GpuAdapter {
    GpuAdapter {
        name: name.to_owned(),
        vendor_id,
        device_id,
        dedicated_video_memory: vram,
        software,
        ..GpuAdapter::default()
    }
}

/// The developer machine's discrete card, as `dump_gpu_adapters` reported it.
fn rx_9070_xt() -> GpuAdapter {
    adapter("AMD Radeon RX 9070 XT", 0x1002, 0x7550, 16 << 30, false)
}

fn basic_render_driver() -> GpuAdapter {
    adapter("Microsoft Basic Render Driver", 0x1414, 0x8c, 0, true)
}

fn table() -> &'static GpuArchTable {
    GpuArchTable::builtin().unwrap()
}

/// The developer machine's shape: RX 9070 XT and the Basic Render Driver, the 5950X, a build
/// with `UBR`.
fn dev_machine() -> FakeSystemBuilder {
    FakeSystem::builder()
        .gpu(rx_9070_xt())
        .gpu(basic_render_driver())
        .topology_json(RYZEN_5950X)
        .os_build(26300, Some(9711))
}

fn read(b: FakeSystemBuilder, table: Option<&GpuArchTable>) -> SystemProfile {
    hw::read(&b.build().unwrap(), table)
}

fn shown(p: &SystemProfile, table_error: Option<&TableError>) -> String {
    let mut out = Out::new(Vec::new());
    out.lines(&render(p, table_error)).unwrap();
    String::from_utf8(out.into_inner()).unwrap()
}

const DEV_CPU: &str = "\
CPU
  2 L3 groups x 8 cores x 2 threads (16 cores, 32 threads)
  L3 group 0: 32 MiB, 8 cores x 2 threads, cores 0-7
  L3 group 1: 32 MiB, 8 cores x 2 threads, cores 8-15
  efficiency class 0: 16 cores, 32 threads
  hybrid: no (1 efficiency class)
";

const CONDITIONS: &str = "Conditions (the facts Topo `when` keys are evaluated against)\n";

#[test]
fn the_developer_machine() {
    let p = read(dev_machine(), Some(table()));
    let expected = format!(
        "\
GPU
  adapter 1 (conditions adapter): AMD Radeon RX 9070 XT
    AMD, PCI 0x1002:0x7550, 16384 MiB VRAM, integrated: no, architecture: rdna4

{DEV_CPU}
OS
  Windows build 26300.9711

{CONDITIONS}  gpu.vendor: amd
  gpu.arch: rdna4
  cpu.threads: 32
  cpu.hybrid: false
  os.build: 26300
"
    );
    assert_eq!(shown(&p, None), expected);
}

#[test]
fn system_prints_the_profile_and_exits_0() {
    let sys = dev_machine().build().unwrap();
    let (mut out, mut err) = (Out::new(Vec::new()), Out::new(Vec::new()));
    assert_eq!(system(&sys, &mut out, &mut err), Exit::Report);
    let expected = shown(&hw::read(&sys, Some(table())), None);
    assert_eq!(String::from_utf8(out.into_inner()).unwrap(), expected);
    assert!(err.into_inner().is_empty());
}

#[test]
fn system_on_a_closed_pipe_exits_0_and_on_a_write_error_1() {
    let sys = dev_machine().build().unwrap();
    for (kind, exit, stderr) in [
        (io::ErrorKind::BrokenPipe, Exit::Report, ""),
        (
            io::ErrorKind::PermissionDenied,
            Exit::Fatal,
            "rerun: cannot write the output: permission denied\n",
        ),
    ] {
        let mut out = Out::new(Failing {
            kind,
            ok: 2,
            written: Vec::new(),
        });
        let mut err = Out::new(Vec::new());
        assert_eq!(system(&sys, &mut out, &mut err), exit);
        assert_eq!(String::from_utf8(err.into_inner()).unwrap(), stderr);
        assert_eq!(
            String::from_utf8(out.into_inner().written).unwrap(),
            "GPU\n  adapter 1 (conditions adapter): AMD Radeon RX 9070 XT\n"
        );
    }
}

/// An entry as `hw` builds it.
fn entry(a: GpuAdapter, arch: Option<&str>, integrated: Option<bool>) -> GpuEntry {
    GpuEntry {
        vendor: GpuVendor::from_id(a.vendor_id),
        arch: arch.map_or(GpuArch::Unknown, |id| {
            GpuArch::Known(ArchId::new(id).unwrap())
        }),
        integrated,
        adapter: a,
    }
}

/// The GPU block and the two GPU conditions of `p`.
fn gpu_part(p: &SystemProfile, table_error: Option<&TableError>) -> (String, String) {
    let all = shown(p, table_error);
    let gpu = all.split("\n\n").next().unwrap().to_owned();
    let conditions: Vec<&str> = all.lines().filter(|l| l.starts_with("  gpu.")).collect();
    (gpu, conditions.join("\n"))
}

#[test]
fn two_hardware_adapters_mark_the_conditions_adapter_and_add_the_note() {
    let mut p = read(dev_machine(), Some(table()));
    p.gpu = Ok(GpuProfile {
        adapters: vec![
            entry(
                adapter("Synthetic iGPU", 0x8086, 0x0F01, 128 << 20, false),
                None,
                None,
            ),
            entry(rx_9070_xt(), Some("rdna4"), Some(false)),
        ],
    });
    let (gpu, conditions) = gpu_part(&p, None);
    assert_eq!(
        gpu,
        "\
GPU
  adapter 1 (conditions adapter): Synthetic iGPU
    Intel, PCI 0x8086:0x0f01, 128 MiB VRAM, integrated: unknown, architecture: unknown \
(0x8086:0x0f01 not in the table)
  adapter 2: AMD Radeon RX 9070 XT
    AMD, PCI 0x1002:0x7550, 16384 MiB VRAM, integrated: no, architecture: rdna4
  note: conditions use the first hardware adapter in DXGI order; a game's GPU preference \
may choose another"
    );
    assert_eq!(
        conditions,
        "  gpu.vendor: intel\n  gpu.arch: unknown (matches no value)"
    );
}

#[test]
fn an_integrated_adapter_from_the_table_and_another_vendor() {
    let mut p = read(dev_machine(), Some(table()));
    p.gpu = Ok(GpuProfile {
        adapters: vec![entry(
            adapter("Synthetic Adreno", 0x5143, 0x0001, 0, false),
            Some("xe2"),
            Some(true),
        )],
    });
    let (gpu, conditions) = gpu_part(&p, None);
    assert_eq!(
        gpu,
        "\
GPU
  adapter 1 (conditions adapter): Synthetic Adreno
    vendor 0x5143, PCI 0x5143:0x0001, 0 MiB VRAM, integrated: yes, architecture: xe2"
    );
    assert_eq!(
        conditions,
        "  gpu.vendor: other (vendor 0x5143, matches no value)\n  gpu.arch: xe2"
    );
}

#[test]
fn no_hardware_adapter() {
    let p = read(
        FakeSystem::builder()
            .gpu(basic_render_driver())
            .gpu(adapter(
                "Microsoft Basic Render Driver",
                0x1414,
                0x8c,
                0,
                false,
            ))
            .topology_json(RYZEN_5950X)
            .os_build(26300, Some(9711)),
        Some(table()),
    );
    let (gpu, conditions) = gpu_part(&p, None);
    assert_eq!(
        gpu,
        "GPU\n  no hardware adapter (software adapters are not counted)"
    );
    assert_eq!(
        conditions,
        "  gpu.vendor: no hardware adapter (matches no value)\n  \
         gpu.arch: no hardware adapter (matches no value)"
    );
}

#[test]
fn the_adapters_could_not_be_read() {
    let p = read(
        FakeSystem::builder()
            .gpu_error(SysErrorKind::AccessDenied)
            .topology_json(RYZEN_5950X)
            .os_build(26300, Some(9711)),
        Some(table()),
    );
    let (gpu, conditions) = gpu_part(&p, None);
    assert_eq!(
        gpu,
        "GPU\n  could not read the graphics adapters: GPU: access denied: gpu adapters"
    );
    assert_eq!(
        conditions,
        "  gpu.vendor: unavailable (a condition on it is unknown)\n  \
         gpu.arch: unavailable (a condition on it is unknown)"
    );
}

#[test]
fn an_invalid_table_makes_every_architecture_unavailable() {
    // `hw::read` without a table, as `system` does when `builtin()` fails.
    let p = read(dev_machine(), None);
    let e = TableError {
        at: TablePos::Entry(0),
        kind: TableErrorKind::Overlap { other: 0 },
    };
    let (gpu, conditions) = gpu_part(&p, Some(&e));
    assert_eq!(
        gpu,
        "\
GPU
  the built-in GPU architecture table is invalid, no architecture is available: gpu arch \
table: entries[0]: a device is also covered by entries[0]
  adapter 1 (conditions adapter): AMD Radeon RX 9070 XT
    AMD, PCI 0x1002:0x7550, 16384 MiB VRAM, integrated: unknown, architecture: unavailable \
(no valid architecture table)"
    );
    assert_eq!(
        conditions,
        "  gpu.vendor: amd\n  gpu.arch: unavailable (a condition on it is unknown)"
    );
}

#[test]
fn a_hostile_adapter_name_is_escaped() {
    let mut p = read(dev_machine(), Some(table()));
    let name = "Evil\u{1b}]0;title\u{7}\u{202E}GPU\u{E0041}\u{2028}x";
    p.gpu = Ok(GpuProfile {
        adapters: vec![entry(
            adapter(name, 0x1002, 0x7550, 16 << 30, false),
            Some("rdna4"),
            Some(false),
        )],
    });
    let (gpu, _) = gpu_part(&p, None);
    assert_eq!(
        gpu.lines().nth(1).unwrap(),
        r#"  adapter 1 (conditions adapter): "Evil\u{1b}]0;title\u{7}\u{202e}GPU\u{e0041}\u{2028}x""#
    );
    // A full-width or right-to-left name is legitimate and stays readable.
    p.gpu = Ok(GpuProfile {
        adapters: vec![entry(
            adapter("Ｒａｄｅｏｎ שלום", 0x1002, 0x7550, 0, false),
            None,
            None,
        )],
    });
    let (gpu, _) = gpu_part(&p, None);
    assert_eq!(
        gpu.lines().nth(1).unwrap(),
        "  adapter 1 (conditions adapter): Ｒａｄｅｏｎ שלום"
    );
}

#[test]
fn a_four_core_cpu_without_smt() {
    let p = read(dev_machine().topology_json(I5_6600), Some(table()));
    let all = shown(&p, None);
    let cpu = all.split("\n\n").nth(1).unwrap();
    assert_eq!(
        cpu,
        "\
CPU
  1 L3 group x 4 cores x 1 thread (4 cores, 4 threads)
  L3 group 0: 6 MiB, 4 cores x 1 thread, cores 0-3
  efficiency class 0: 4 cores, 4 threads
  hybrid: no (1 efficiency class)"
    );
    assert!(
        all.contains("  cpu.threads: 4\n  cpu.hybrid: false\n"),
        "{all}"
    );
}

/// A synthetic hybrid part: 2 P-cores with SMT (class 1), 4 E-cores (class 0), one L3.
fn hybrid() -> CpuTopology {
    let mut cpus = Vec::new();
    let mut index = 0u8;
    for (core, threads, class) in [
        (0, 2, 1),
        (1, 2, 1),
        (2, 1, 0),
        (3, 1, 0),
        (4, 1, 0),
        (5, 1, 0),
    ] {
        for _ in 0..threads {
            cpus.push(LogicalCpu {
                cpu_set_id: 0x100 + u32::from(index),
                group: 0,
                index,
                core,
                llc: 0,
                efficiency_class: class,
            });
            index += 1;
        }
    }
    let t = CpuTopology {
        cpus,
        llcs: vec![Llc {
            level: 3,
            size: 12 << 20,
        }],
    };
    t.validate().unwrap();
    t
}

#[test]
fn a_hybrid_cpu() {
    let p = read(dev_machine().topology(hybrid()), Some(table()));
    let all = shown(&p, None);
    let cpu = all.split("\n\n").nth(1).unwrap();
    assert_eq!(
        cpu,
        "\
CPU
  1 L3 group, 6 cores, 8 threads (not uniform)
  L3 group 0: 12 MiB, 6 cores, 8 threads, cores 0-5
  efficiency class 0: 4 cores, 4 threads
  efficiency class 1: 2 cores, 4 threads
  hybrid: yes (2 efficiency classes)"
    );
    assert!(
        all.contains("  cpu.threads: 8\n  cpu.hybrid: true\n"),
        "{all}"
    );
}

#[test]
fn groups_of_different_sizes_and_levels() {
    // Two groups: 4 cores with SMT under an L3, 2 cores under an L2 (last level).
    let mut cpus = Vec::new();
    let mut index = 0u8;
    for (core, threads, llc) in [
        (0, 2, 0),
        (1, 2, 0),
        (2, 2, 0),
        (3, 2, 0),
        (4, 1, 1),
        (5, 1, 1),
    ] {
        for _ in 0..threads {
            cpus.push(LogicalCpu {
                cpu_set_id: 0x100 + u32::from(index),
                group: 0,
                index,
                core,
                llc,
                efficiency_class: 0,
            });
            index += 1;
        }
    }
    let t = CpuTopology {
        cpus,
        llcs: vec![
            Llc {
                level: 3,
                size: 16 << 20,
            },
            Llc {
                level: 2,
                size: 2 << 20,
            },
        ],
    };
    t.validate().unwrap();
    let p = read(dev_machine().topology(t), Some(table()));
    let all = shown(&p, None);
    assert_eq!(
        all.split("\n\n").nth(1).unwrap(),
        "\
CPU
  2 last-level cache groups, 6 cores, 10 threads (not uniform)
  L3 group 0: 16 MiB, 4 cores x 2 threads, cores 0-3
  L2 group 1: 2 MiB, 2 cores x 1 thread, cores 4-5
  efficiency class 0: 6 cores, 10 threads
  hybrid: no (1 efficiency class)"
    );
}

#[test]
fn the_topology_could_not_be_read() {
    let p = read(
        FakeSystem::builder()
            .gpu(rx_9070_xt())
            .os_build(26300, Some(9711)),
        Some(table()),
    );
    let all = shown(&p, None);
    assert_eq!(
        all.split("\n\n").nth(1).unwrap(),
        "CPU\n  could not read the CPU topology: CPU topology: unsupported: fake topology: none \
         configured (FakeSystemBuilder::topology)"
    );
    assert!(
        all.contains(
            "  cpu.threads: unavailable (a condition on it is unknown)\n  \
             cpu.hybrid: unavailable (a condition on it is unknown)\n"
        ),
        "{all}"
    );
}

fn os_block(b: FakeSystemBuilder) -> (String, String) {
    let all = shown(&read(b, Some(table())), None);
    let os = all.split("\n\n").nth(2).unwrap().to_owned();
    let build = all.lines().last().unwrap().to_owned();
    (os, build)
}

#[test]
fn the_build_without_ubr_and_unreadable() {
    let base = || {
        FakeSystem::builder()
            .gpu(rx_9070_xt())
            .topology_json(RYZEN_5950X)
    };
    assert_eq!(
        os_block(base().os_build(22631, None)),
        (
            "OS\n  Windows build 22631 (update revision unknown)".to_owned(),
            "  os.build: 22631".to_owned()
        )
    );
    let key = RegKey::new(
        Hive::LocalMachine,
        RegView::Native,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    );
    let unavailable = "  os.build: unavailable (a condition on it is unknown)".to_owned();
    assert_eq!(
        os_block(base().value(
            key.clone(),
            "CurrentBuildNumber",
            RegValue::String("26300\u{1b}[2J".to_owned())
        )),
        (
            "OS\n  could not read the Windows build: CurrentBuildNumber: malformed".to_owned(),
            unavailable.clone()
        )
    );
    assert_eq!(
        os_block(base().key(key)),
        (
            "OS\n  could not read the Windows build: CurrentBuildNumber: missing".to_owned(),
            unavailable
        )
    );
}
