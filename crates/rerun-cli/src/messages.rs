//! Every user-facing string of `rerun` (ADR 0016), English only in phase 1.
//!
//! One [`Message`] is one output line. Parameters are named; counts are parameters (so Fluent
//! plurals can follow) and a sentence is never assembled from other messages. Static text is
//! ASCII; untrusted fields enter only as [`Shown`], which only `rerun_core::escape` creates.
//! Untrusted text stands last on its line where possible, so a name cannot pose as a marker.

use std::fmt;
use std::io;

use rerun_core::escape::Shown;
use rerun_core::hw::GpuVendor;

/// A section heading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Heading {
    /// Graphics adapters.
    Gpu,
    /// CPU topology.
    Cpu,
    /// Windows build.
    Os,
    /// The facts of the `when` keys.
    Conditions,
}

/// The architecture of one adapter as shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchText<'a> {
    /// From the table.
    Known(Shown<'a>),
    /// The table has no entry for the device.
    Unknown {
        /// PCI vendor ID.
        vendor_id: u32,
        /// PCI device ID.
        device_id: u32,
    },
    /// No valid table.
    Unavailable,
}

/// The value of one `when` key as shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactText<'a> {
    /// A vendor.
    Vendor(GpuVendor),
    /// An architecture identifier.
    Arch(Shown<'a>),
    /// A number.
    Number(u32),
    /// A boolean.
    Bool(bool),
    /// No hardware adapter: matches no value.
    NoAdapter,
    /// The table has no entry for the conditions adapter: matches no value.
    Unknown,
    /// Could not be read: a condition on it is unknown.
    Unavailable,
}

/// The cache level of a group of logical processors: `Some(3)` for L3, `None` when the groups
/// of one CPU are of different levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheLevel(pub Option<u8>);

/// One line of output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message<'a> {
    /// An empty line between sections.
    Blank,
    /// A section heading.
    Heading(Heading),

    // ---------- rerun system: GPU ----------
    /// The adapters could not be read.
    GpuUnreadable {
        /// The error (source and kind).
        error: Shown<'a>,
    },
    /// No hardware adapter.
    NoHardwareAdapter,
    /// The built-in architecture table failed validation.
    ArchTableInvalid {
        /// The error (position and kind).
        error: Shown<'a>,
    },
    /// A hardware adapter, numbered from 1 in DXGI order.
    Adapter {
        /// Position in DXGI order, from 1.
        number: usize,
        /// The conditions adapter.
        conditions: bool,
        /// Name from the driver.
        name: Shown<'a>,
    },
    /// The facts of the adapter above.
    AdapterFacts {
        /// Vendor.
        vendor: GpuVendor,
        /// PCI vendor ID.
        vendor_id: u32,
        /// PCI device ID.
        device_id: u32,
        /// Dedicated video memory in MiB.
        vram_mb: u64,
        /// From the table; `None` without an entry.
        integrated: Option<bool>,
        /// The architecture.
        arch: ArchText<'a>,
    },
    /// More than one hardware adapter.
    SeveralAdapters,

    // ---------- rerun system: CPU ----------
    /// The topology could not be read.
    CpuUnreadable {
        /// The error.
        error: Shown<'a>,
    },
    /// Every group has the same number of cores with the same number of threads each.
    CpuUniform {
        /// The cache level of the groups.
        level: CacheLevel,
        /// Number of groups.
        groups: usize,
        /// Cores per group.
        cores: usize,
        /// Threads per core.
        threads: usize,
        /// Cores in total.
        total_cores: usize,
        /// Threads in total.
        total_threads: usize,
    },
    /// Groups of different shapes.
    CpuMixed {
        /// The cache level of the groups.
        level: CacheLevel,
        /// Number of groups.
        groups: usize,
        /// Cores in total.
        total_cores: usize,
        /// Threads in total.
        total_threads: usize,
    },
    /// One group of logical processors sharing a last-level cache.
    CacheGroup {
        /// Its cache level.
        level: CacheLevel,
        /// Its number (dense, from 0).
        index: u32,
        /// Cache size in bytes.
        size: u64,
        /// Cores.
        cores: usize,
        /// Threads per core if equal for every core.
        per_core: Option<usize>,
        /// Threads.
        threads: usize,
        /// Core numbers as inclusive ranges.
        core_ranges: Vec<(u32, u32)>,
    },
    /// One efficiency class.
    EfficiencyClass {
        /// The class (higher is more powerful).
        class: u8,
        /// Cores.
        cores: usize,
        /// Threads.
        threads: usize,
    },
    /// Whether the CPU counts as hybrid.
    Hybrid {
        /// More than one efficiency class.
        hybrid: bool,
        /// Number of efficiency classes.
        classes: usize,
    },

    // ---------- rerun system: OS ----------
    /// The Windows build.
    OsBuild {
        /// Build number.
        build: u32,
        /// Update build revision.
        ubr: Option<u32>,
    },
    /// The build could not be read.
    OsUnreadable {
        /// The error.
        error: Shown<'a>,
    },

    // ---------- rerun system: conditions ----------
    /// One `when` key and its fact.
    Condition {
        /// The key (`gpu.vendor`, …).
        key: &'static str,
        /// The fact.
        value: FactText<'a>,
    },

    // ---------- errors (stderr) ----------
    /// `restrict_dll_search` failed.
    DllSearch {
        /// The error.
        error: Shown<'a>,
    },
    /// `WinSystem::new` failed.
    SystemUnavailable {
        /// The error.
        error: Shown<'a>,
    },
    /// Not on Windows.
    #[cfg(not(windows))]
    WindowsOnly,
    /// Writing the report failed.
    WriteFailed {
        /// The kind of the I/O error.
        kind: io::ErrorKind,
    },
}

/// `n` with the singular or plural noun.
struct Count<'s>(usize, &'s str, &'s str);

impl fmt::Display for Count<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(n, one, other) = *self;
        write!(f, "{n} {}", if n == 1 { one } else { other })
    }
}

fn cores(n: usize) -> Count<'static> {
    Count(n, "core", "cores")
}

fn threads(n: usize) -> Count<'static> {
    Count(n, "thread", "threads")
}

impl fmt::Display for CacheLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(level) => write!(f, "L{level}"),
            None => f.write_str("last-level cache"),
        }
    }
}

/// Bytes as MiB when whole, else KiB.
struct Size(u64);

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        if b >= 1 << 20 && b.is_multiple_of(1 << 20) {
            write!(f, "{} MiB", b >> 20)
        } else if b.is_multiple_of(1 << 10) {
            write!(f, "{} KiB", b >> 10)
        } else {
            write!(f, "{b} bytes")
        }
    }
}

/// Inclusive ranges as `0-7, 9`.
struct Ranges<'r>(&'r [(u32, u32)]);

impl fmt::Display for Ranges<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, &(from, to)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            if from == to {
                write!(f, "{from}")?;
            } else {
                write!(f, "{from}-{to}")?;
            }
        }
        Ok(())
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

impl fmt::Display for Heading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Gpu => "GPU",
            Self::Cpu => "CPU",
            Self::Os => "OS",
            Self::Conditions => "Conditions (the facts Topo `when` keys are evaluated against)",
        })
    }
}

impl fmt::Display for ArchText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(id) => write!(f, "{id}"),
            Self::Unknown {
                vendor_id,
                device_id,
            } => write!(
                f,
                "unknown ({vendor_id:#06x}:{device_id:#06x} not in the table)"
            ),
            Self::Unavailable => f.write_str("unavailable (no valid architecture table)"),
        }
    }
}

impl fmt::Display for FactText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vendor(GpuVendor::Amd) => f.write_str("amd"),
            Self::Vendor(GpuVendor::Nvidia) => f.write_str("nvidia"),
            Self::Vendor(GpuVendor::Intel) => f.write_str("intel"),
            Self::Vendor(GpuVendor::Other(id)) => {
                write!(f, "other (vendor {id:#06x}, matches no value)")
            }
            Self::Arch(id) => write!(f, "{id}"),
            Self::Number(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::NoAdapter => f.write_str("no hardware adapter (matches no value)"),
            Self::Unknown => f.write_str("unknown (matches no value)"),
            Self::Unavailable => f.write_str("unavailable (a condition on it is unknown)"),
        }
    }
}

impl fmt::Display for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blank => Ok(()),
            Self::Heading(h) => write!(f, "{h}"),

            Self::GpuUnreadable { error } => {
                write!(f, "  could not read the graphics adapters: {error}")
            }
            Self::NoHardwareAdapter => {
                f.write_str("  no hardware adapter (software adapters are not counted)")
            }
            Self::ArchTableInvalid { error } => write!(
                f,
                "  the built-in GPU architecture table is invalid, no architecture is \
                 available: {error}"
            ),
            Self::Adapter {
                number,
                conditions,
                name,
            } => {
                if *conditions {
                    write!(f, "  adapter {number} (conditions adapter): {name}")
                } else {
                    write!(f, "  adapter {number}: {name}")
                }
            }
            Self::AdapterFacts {
                vendor,
                vendor_id,
                device_id,
                vram_mb,
                integrated,
                arch,
            } => {
                let integrated = integrated.map_or("unknown", yes_no);
                write!(
                    f,
                    "    {vendor}, PCI {vendor_id:#06x}:{device_id:#06x}, {vram_mb} MiB VRAM, \
                     integrated: {integrated}, architecture: {arch}"
                )
            }
            Self::SeveralAdapters => f.write_str(
                "  note: conditions use the first hardware adapter in DXGI order; a game's GPU \
                 preference may choose another",
            ),

            Self::CpuUnreadable { error } => {
                write!(f, "  could not read the CPU topology: {error}")
            }
            Self::CpuUniform {
                level,
                groups,
                cores: c,
                threads: t,
                total_cores,
                total_threads,
            } => write!(
                f,
                "  {} x {} x {} ({}, {})",
                Count(
                    *groups,
                    &format!("{level} group"),
                    &format!("{level} groups")
                ),
                cores(*c),
                threads(*t),
                cores(*total_cores),
                threads(*total_threads),
            ),
            Self::CpuMixed {
                level,
                groups,
                total_cores,
                total_threads,
            } => write!(
                f,
                "  {}, {}, {} (not uniform)",
                Count(
                    *groups,
                    &format!("{level} group"),
                    &format!("{level} groups")
                ),
                cores(*total_cores),
                threads(*total_threads),
            ),
            Self::CacheGroup {
                level,
                index,
                size,
                cores: c,
                per_core,
                threads: t,
                core_ranges,
            } => {
                write!(f, "  {level} group {index}: {}, ", Size(*size))?;
                match per_core {
                    Some(p) => write!(f, "{} x {}", cores(*c), threads(*p))?,
                    None => write!(f, "{}, {}", cores(*c), threads(*t))?,
                }
                write!(f, ", cores {}", Ranges(core_ranges))
            }
            Self::EfficiencyClass {
                class,
                cores: c,
                threads: t,
            } => write!(
                f,
                "  efficiency class {class}: {}, {}",
                cores(*c),
                threads(*t)
            ),
            Self::Hybrid { hybrid, classes } => write!(
                f,
                "  hybrid: {} ({})",
                yes_no(*hybrid),
                Count(*classes, "efficiency class", "efficiency classes")
            ),

            Self::OsBuild { build, ubr } => match ubr {
                Some(ubr) => write!(f, "  Windows build {build}.{ubr}"),
                None => write!(f, "  Windows build {build} (update revision unknown)"),
            },
            Self::OsUnreadable { error } => {
                write!(f, "  could not read the Windows build: {error}")
            }

            Self::Condition { key, value } => write!(f, "  {key}: {value}"),

            Self::DllSearch { error } => write!(
                f,
                "rerun: cannot restrict the DLL search path to System32: {error}"
            ),
            Self::SystemUnavailable { error } => {
                write!(f, "rerun: cannot open the system layer: {error}")
            }
            #[cfg(not(windows))]
            Self::WindowsOnly => f.write_str("rerun: runs on Windows only"),
            Self::WriteFailed { kind } => write!(f, "rerun: cannot write the output: {kind}"),
        }
    }
}
