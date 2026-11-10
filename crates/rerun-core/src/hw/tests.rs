//! The system profile against the fake system.
//!
//! Apart from the developer machine's `0x1002`/`0x7550`, every device ID here is synthetic and
//! mapped by [`synthetic_table`], which lives in test code only (ADR 0015).

use rerun_proto::cpu::{CpuTopology, Llc, LogicalCpu};

use super::arch::{ArchDecl, ArchEntry, DeviceRange, Dx9Path, VkVersion};
use super::*;
use crate::sys::fake::FakeSystem;
use crate::sys::{GpuAdapter, SysErrorKind};

const RYZEN_5950X: &str = include_str!("../../../../tests/fixtures/cpu/ryzen9-5950x.json");
const I5_6600: &str = include_str!("../../../../tests/fixtures/cpu/i5-6600.json");

fn id(s: &str) -> ArchId {
    ArchId::new(s).unwrap()
}

fn adapter(name: &str, vendor_id: u32, device_id: u32, vram: u64) -> GpuAdapter {
    GpuAdapter {
        name: name.to_owned(),
        vendor_id,
        device_id,
        dedicated_video_memory: vram,
        ..GpuAdapter::default()
    }
}

/// The developer machine's discrete card, as `dump_gpu_adapters` reported it.
fn rx_9070_xt() -> GpuAdapter {
    GpuAdapter {
        subsys_id: 0x2410_1EAE,
        revision: 0xC0,
        luid: 0x1_0000_ABCD,
        ..adapter("AMD Radeon RX 9070 XT", 0x1002, 0x7550, 16 << 30)
    }
}

/// Microsoft Basic Render Driver, with or without the software flag (CI lists both).
fn basic_render_driver(software: bool) -> GpuAdapter {
    GpuAdapter {
        software,
        ..adapter("Microsoft Basic Render Driver", 0x1414, 0x8c, 0)
    }
}

/// SYNTHETIC test-only table: invented device IDs, never shipped data.
pub(crate) fn synthetic_table() -> GpuArchTable {
    let entry = |vendor, arch: &str, integrated, ids: &[u32], ranges: &[(u32, u32)]| ArchEntry {
        vendor,
        arch: id(arch),
        integrated,
        vulkan: Some(VkVersion { minor: 3 }),
        dx9: if integrated {
            Dx9Path::D3d9On12
        } else {
            Dx9Path::Native
        },
        device_ids: ids.to_vec(),
        device_ranges: ranges
            .iter()
            .map(|&(from, to)| DeviceRange { from, to })
            .collect(),
        source: "synthetic test entry".to_owned(),
    };
    GpuArchTable::new(
        vec![
            ArchDecl {
                id: id("rdna4"),
                vendor: 0x1002,
            },
            ArchDecl {
                id: id("ada"),
                vendor: 0x10DE,
            },
            ArchDecl {
                id: id("xe_lp"),
                vendor: 0x8086,
            },
        ],
        vec![
            entry(0x1002, "rdna4", false, &[0x7550], &[]),
            entry(0x10DE, "ada", false, &[], &[(0xA000, 0xA0FF)]),
            entry(0x8086, "xe_lp", true, &[0xB001], &[]),
        ],
    )
    .unwrap()
}

/// The developer machine: 5950X, RX 9070 XT and the Basic Render Driver, build 26300.
fn dev_machine() -> FakeSystem {
    FakeSystem::builder()
        .topology_json(RYZEN_5950X)
        .gpu(rx_9070_xt())
        .gpu(basic_render_driver(true))
        .os_build(26300, Some(7019))
        .build()
        .unwrap()
}

#[test]
fn developer_machine() {
    let p = read(&dev_machine(), Some(GpuArchTable::builtin().unwrap()));
    assert_eq!(p.gpu_facts()[0].vendor, VendorFact::Known(GpuVendor::Amd));
    assert_eq!(p.gpu_facts()[0].arch, ArchFact::Known(id("rdna4")));
    assert_eq!(p.cpu_threads(), Fact::Known(32));
    assert_eq!(p.cpu_hybrid(), Fact::Known(false));
    assert_eq!(p.os_build(), Fact::Known(26300));
    assert_eq!(
        p.os,
        Ok(OsBuild {
            build: 26300,
            ubr: Some(7019)
        })
    );
    let gpu = p.gpu.as_ref().unwrap();
    assert_eq!(gpu.adapters.len(), 1, "the Basic Render Driver is dropped");
    let primary = gpu.primary().unwrap();
    assert_eq!(primary.adapter, rx_9070_xt());
    assert_eq!(primary.vram_mb(), 16384);
    assert_eq!(primary.integrated, Some(false));
    assert_eq!(primary.arch, GpuArch::Known(id("rdna4")));
}

/// A GitHub runner: the Basic Render Driver twice, once without the software flag.
#[test]
fn ci_runner_has_no_hardware_adapter() {
    let sys = FakeSystem::builder()
        .gpu(basic_render_driver(false))
        .gpu(basic_render_driver(true))
        .build()
        .unwrap();
    let p = read(&sys, Some(GpuArchTable::builtin().unwrap()));
    assert_eq!(p.gpu.as_ref().unwrap().adapters, Vec::new());
    assert_eq!(p.gpu_facts()[0].vendor, VendorFact::NoAdapter);
    assert_eq!(p.gpu_facts()[0].arch, ArchFact::NoAdapter);
    // No adapter at all (the fake's default) is the same.
    let p = read(&FakeSystem::new(), Some(GpuArchTable::builtin().unwrap()));
    assert_eq!(p.gpu_facts()[0].vendor, VendorFact::NoAdapter);
}

#[test]
fn software_adapters_of_any_vendor_are_dropped() {
    let soft_amd = GpuAdapter {
        software: true,
        ..rx_9070_xt()
    };
    let sys = FakeSystem::builder()
        .gpu(soft_amd)
        .gpu(adapter("synthetic", 0x10DE, 0xA010, 8 << 30))
        .build()
        .unwrap();
    let p = read(&sys, Some(&synthetic_table()));
    assert_eq!(
        p.gpu_facts()[0].vendor,
        VendorFact::Known(GpuVendor::Nvidia)
    );
    assert_eq!(p.gpu_facts()[0].arch, ArchFact::Known(id("ada")));
}

#[test]
fn a_gpu_error_makes_both_gpu_facts_unavailable() {
    let sys = FakeSystem::builder()
        .gpu(rx_9070_xt())
        .gpu_error(SysErrorKind::Unsupported)
        .topology_json(RYZEN_5950X)
        .os_build(26300, None)
        .build()
        .unwrap();
    // Checked before the missing table and before the adapters.
    for table in [Some(GpuArchTable::builtin().unwrap()), None] {
        let p = read(&sys, table);
        assert_eq!(p.gpu_facts()[0].vendor, VendorFact::Unavailable);
        assert_eq!(p.gpu_facts()[0].arch, ArchFact::Unavailable);
        let e = p.gpu.as_ref().unwrap_err();
        assert!(
            matches!(e, ProfileError::Sys(ProfileSource::Gpu, s) if s.kind == SysErrorKind::Unsupported),
            "{e:?}"
        );
        assert!(e.to_string().starts_with("GPU: "), "{e}");
        // The other parts are read anyway.
        assert_eq!(p.cpu_threads(), Fact::Known(32));
        assert_eq!(p.os_build(), Fact::Known(26300));
    }
}

#[test]
fn without_a_table_the_arch_is_unavailable_and_the_vendor_known() {
    let p = read(&dev_machine(), None);
    assert_eq!(p.gpu_facts()[0].vendor, VendorFact::Known(GpuVendor::Amd));
    assert_eq!(p.gpu_facts()[0].arch, ArchFact::Unavailable);
    let primary = p.gpu.as_ref().unwrap().primary().unwrap();
    assert_eq!(primary.arch, GpuArch::Unknown);
    assert_eq!(primary.integrated, None);
    // No adapter is checked before the missing table.
    let p = read(&FakeSystem::new(), None);
    assert_eq!(p.gpu_facts()[0].arch, ArchFact::NoAdapter);
}

#[test]
fn an_unknown_device_is_unknown_with_integrated_none() {
    let sys = FakeSystem::builder()
        .gpu(adapter("synthetic unknown", 0x1002, 0x7551, 4 << 30))
        .build()
        .unwrap();
    let p = read(&sys, Some(GpuArchTable::builtin().unwrap()));
    assert_eq!(p.gpu_facts()[0].vendor, VendorFact::Known(GpuVendor::Amd));
    assert_eq!(p.gpu_facts()[0].arch, ArchFact::Unknown);
    let primary = p.gpu.as_ref().unwrap().primary().unwrap();
    assert_eq!(primary.arch, GpuArch::Unknown);
    assert_eq!(primary.integrated, None);
}

/// Revision and subsystem IDs are never consulted.
#[test]
fn revision_and_subsystem_do_not_matter() {
    for (revision, subsys_id) in [(0, 0), (0xFF, 0xFFFF_FFFF), (0xC1, 0x1234_5678)] {
        let sys = FakeSystem::builder()
            .gpu(GpuAdapter {
                revision,
                subsys_id,
                ..rx_9070_xt()
            })
            .build()
            .unwrap();
        let p = read(&sys, Some(GpuArchTable::builtin().unwrap()));
        assert_eq!(p.gpu_facts()[0].arch, ArchFact::Known(id("rdna4")));
    }
}

/// A laptop: DXGI lists the iGPU first. The order is kept; `gpu_vendor`/`gpu_arch` are the
/// first adapter's, `gpu_facts` has one entry per adapter (P4-11) and the system is hybrid.
#[test]
fn igpu_before_dgpu_keeps_the_dxgi_order() {
    let sys = FakeSystem::builder()
        .gpu(adapter("synthetic iGPU", 0x8086, 0xB001, 128 << 20))
        .gpu(basic_render_driver(true))
        .gpu(adapter("synthetic dGPU", 0x10DE, 0xA0FF, 8 << 30))
        .build()
        .unwrap();
    let table = synthetic_table();
    let p = read(&sys, Some(&table));
    let gpu = p.gpu.as_ref().unwrap();
    let names: Vec<&str> = gpu
        .adapters
        .iter()
        .map(|e| e.adapter.name.as_str())
        .collect();
    assert_eq!(names, ["synthetic iGPU", "synthetic dGPU"]);
    assert_eq!(gpu.adapters[0].integrated, Some(true));
    assert_eq!(gpu.adapters[0].vram_mb(), 128);
    assert_eq!(gpu.adapters[1].integrated, Some(false));
    assert_eq!(gpu.adapters[1].arch, GpuArch::Known(id("ada")));
    assert_eq!(p.gpu_facts()[0].vendor, VendorFact::Known(GpuVendor::Intel));
    assert_eq!(p.gpu_facts()[0].arch, ArchFact::Known(id("xe_lp")));
    assert_eq!(
        p.gpu_facts(),
        vec![
            GpuFacts {
                vendor: VendorFact::Known(GpuVendor::Intel),
                arch: ArchFact::Known(id("xe_lp")),
                integrated: IntegratedFact::Known(true),
            },
            GpuFacts {
                vendor: VendorFact::Known(GpuVendor::Nvidia),
                arch: ArchFact::Known(id("ada")),
                integrated: IntegratedFact::Known(false),
            },
        ]
    );
    assert!(gpu.hybrid());
    assert_eq!(p.gpu_hybrid(), Fact::Known(true));
}

/// `gpu.hybrid` (P4-11, E-G1 c): at least two hardware adapters; the Basic Render Driver does
/// not count; a failed read is unavailable. `gpu_facts` is never empty.
#[test]
fn gpu_hybrid_counts_hardware_adapters_and_facts_are_never_empty() {
    let p = read(&dev_machine(), Some(&synthetic_table()));
    assert_eq!(p.gpu_hybrid(), Fact::Known(false));
    assert_eq!(p.gpu_facts().len(), 1);
    assert_eq!(p.gpu_facts()[0].integrated, IntegratedFact::Known(false));

    let ci = FakeSystem::builder()
        .gpu(basic_render_driver(false))
        .gpu(basic_render_driver(true))
        .build()
        .unwrap();
    let p = read(&ci, Some(&synthetic_table()));
    assert_eq!(p.gpu_hybrid(), Fact::Known(false));
    assert_eq!(
        p.gpu_facts(),
        vec![GpuFacts {
            vendor: VendorFact::NoAdapter,
            arch: ArchFact::NoAdapter,
            integrated: IntegratedFact::NoAdapter,
        }]
    );

    let broken = FakeSystem::builder()
        .gpu_error(SysErrorKind::Unsupported)
        .build()
        .unwrap();
    let p = read(&broken, Some(&synthetic_table()));
    assert_eq!(p.gpu_hybrid(), Fact::Unavailable);
    assert_eq!(
        p.gpu_facts(),
        vec![GpuFacts {
            vendor: VendorFact::Unavailable,
            arch: ArchFact::Unavailable,
            integrated: IntegratedFact::Unavailable,
        }]
    );

    // Two identical discrete cards are hybrid as well (two hardware adapters).
    let twins = FakeSystem::builder()
        .gpu(rx_9070_xt())
        .gpu(rx_9070_xt())
        .build()
        .unwrap();
    let p = read(&twins, Some(&synthetic_table()));
    assert_eq!(p.gpu_hybrid(), Fact::Known(true));
    assert_eq!(p.gpu_facts().len(), 2);

    // Without a table `integrated` is unavailable; with one but no entry it is unknown.
    let unknown = FakeSystem::builder()
        .gpu(adapter("synthetic unknown", 0x1002, 0x7551, 0))
        .build()
        .unwrap();
    let p = read(&unknown, None);
    assert_eq!(p.gpu_facts()[0].integrated, IntegratedFact::Unavailable);
    let p = read(&unknown, Some(&synthetic_table()));
    assert_eq!(p.gpu_facts()[0].integrated, IntegratedFact::Unknown);
}

#[test]
fn another_vendor_is_other() {
    // Qualcomm Adreno (Windows on ARM), out of scope for v1.
    let sys = FakeSystem::builder()
        .gpu(adapter("synthetic Adreno", 0x5143, 0x0C36, 0))
        .build()
        .unwrap();
    let p = read(&sys, Some(&synthetic_table()));
    assert_eq!(
        p.gpu_facts()[0].vendor,
        VendorFact::Known(GpuVendor::Other(0x5143))
    );
    assert_eq!(p.gpu_facts()[0].arch, ArchFact::Unknown);
    assert_eq!(GpuVendor::Other(0x5143).to_string(), "vendor 0x5143");
}

#[test]
fn vendor_ids() {
    for (vid, v, shown) in [
        (0x1002, GpuVendor::Amd, "AMD"),
        (0x10DE, GpuVendor::Nvidia, "NVIDIA"),
        (0x8086, GpuVendor::Intel, "Intel"),
        (0x1414, GpuVendor::Other(0x1414), "vendor 0x1414"),
        (0, GpuVendor::Other(0), "vendor 0x0000"),
    ] {
        assert_eq!(GpuVendor::from_id(vid), v);
        assert_eq!(v.id(), vid);
        assert_eq!(v.to_string(), shown);
    }
}

#[test]
fn vram_is_rounded_down_to_mib() {
    let entry = |bytes| GpuEntry::new(adapter("x", 0x1002, 1, bytes), None);
    assert_eq!(entry(0).vram_mb(), 0);
    assert_eq!(entry((1 << 20) - 1).vram_mb(), 0);
    assert_eq!(entry(3 << 19).vram_mb(), 1);
    assert_eq!(entry(u64::MAX).vram_mb(), u64::MAX >> 20);
}

#[test]
fn i5_6600_has_four_threads_and_is_not_hybrid() {
    let sys = FakeSystem::builder()
        .topology_json(I5_6600)
        .build()
        .unwrap();
    let p = read(&sys, None);
    assert_eq!(p.cpu_threads(), Fact::Known(4));
    assert_eq!(p.cpu_hybrid(), Fact::Known(false));
}

/// Two efficiency classes: hybrid, whatever the vendor.
#[test]
fn an_inline_hybrid_topology_is_hybrid() {
    let cpu = |index: u8, core: u32, llc: u32, efficiency_class: u8| LogicalCpu {
        cpu_set_id: 0x100 + u32::from(index),
        group: 0,
        index,
        core,
        llc,
        efficiency_class,
    };
    let topology = CpuTopology {
        // A P-core with two threads, then two E-cores sharing an L2 as the last level.
        cpus: vec![
            cpu(0, 0, 0, 1),
            cpu(1, 0, 0, 1),
            cpu(2, 1, 1, 0),
            cpu(3, 2, 1, 0),
        ],
        llcs: vec![
            Llc {
                level: 3,
                size: 12 << 20,
            },
            Llc {
                level: 2,
                size: 2 << 20,
            },
        ],
    };
    let sys = FakeSystem::builder().topology(topology).build().unwrap();
    let p = read(&sys, None);
    assert_eq!(p.cpu_threads(), Fact::Known(4));
    assert_eq!(p.cpu_hybrid(), Fact::Known(true));
}

/// Each part fails alone; the others are still read.
#[test]
fn parts_are_independent() {
    // No topology, no OS values, the developer machine's GPU.
    let sys = FakeSystem::builder().gpu(rx_9070_xt()).build().unwrap();
    let p = read(&sys, Some(GpuArchTable::builtin().unwrap()));
    assert_eq!(p.gpu_facts()[0].arch, ArchFact::Known(id("rdna4")));
    assert_eq!(p.cpu_threads(), Fact::Unavailable);
    assert_eq!(p.cpu_hybrid(), Fact::Unavailable);
    assert_eq!(p.os_build(), Fact::Unavailable);
    let cpu = p.cpu.as_ref().unwrap_err();
    assert_eq!(cpu.origin(), ProfileSource::CpuTopology);
    assert!(cpu.to_string().starts_with("CPU topology: "), "{cpu}");
    assert_eq!(
        p.os.as_ref().unwrap_err().origin(),
        ProfileSource::CurrentBuildNumber
    );

    // A malformed build alone.
    let sys = FakeSystem::builder()
        .topology_json(RYZEN_5950X)
        .value(
            os::current_version_key(),
            os::BUILD_VALUE,
            crate::sys::registry::RegValue::Dword(26300),
        )
        .gpu(rx_9070_xt())
        .build()
        .unwrap();
    let p = read(&sys, Some(GpuArchTable::builtin().unwrap()));
    assert_eq!(
        p.os,
        Err(ProfileError::Malformed(ProfileSource::CurrentBuildNumber))
    );
    assert_eq!(p.os_build(), Fact::Unavailable);
    assert_eq!(p.cpu_threads(), Fact::Known(32));
    assert_eq!(p.gpu_facts()[0].vendor, VendorFact::Known(GpuVendor::Amd));
}

/// A profile read with a table equals one read again: no hidden state.
#[test]
fn reading_twice_gives_the_same_profile() {
    let sys = dev_machine();
    let table = GpuArchTable::builtin().unwrap();
    assert_eq!(read(&sys, Some(table)), read(&sys, Some(table)));
    assert_ne!(read(&sys, Some(table)), read(&sys, None));
}
