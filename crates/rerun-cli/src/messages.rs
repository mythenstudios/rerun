//! Every user-facing string of `rerun` (ADR 0016), English only (German with Fluent in phase
//! 5). The phase 2 commands have their lines in `txn` ([`TxnMsg`]), the launch results of
//! `rerun status` in `launch` ([`LaunchMsg`]).
//!
//! One [`Message`] is one output line. Parameters are named; counts are parameters (so Fluent
//! plurals can follow) and a sentence is never assembled from other messages. Static text is
//! ASCII; untrusted fields enter only as [`Shown`], which only `rerun_core::escape` creates.
//! Untrusted text stands last on its line where possible, so a name cannot pose as a marker.

mod helper;
mod index;
mod launch;
mod package;
mod profile;
mod topo;
mod txn;

use std::fmt;
use std::io;

use rerun_core::detect::exe::{ApiReport, Hashes};
use rerun_core::detect::pe::Machine;
use rerun_core::detect::steam::{AppState, RootSource};
use rerun_core::escape::Shown;
use rerun_core::hw::GpuVendor;

pub use helper::HelperMsg;
pub use index::IndexMsg;
pub use launch::{LaunchMsg, Utc};
pub use package::{FetchedHow, PackageMsg, UnpackedHow};
#[cfg(test)]
pub(crate) use profile::size as size_text;
pub use profile::{ProfileMsg, ranges};
pub use topo::TopoMsg;
pub use txn::{At, OpRef, OpText, SteamWhy, StepText, TxnMsg, TxnText};

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

/// Why the CPU summary is not one `groups x cores x threads` product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotUniform {
    /// The groups have different numbers of cores.
    GroupSizes,
    /// The cores have different numbers of threads (hybrid parts, SMT on some cores only).
    ThreadsPerCore,
}

/// The hashes of one executable as shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashText<'a> {
    /// Hashed.
    Done(&'a Hashes),
    /// Skipped or failed: the core's text, escaped (a failure may name a file).
    NotDone(Shown<'a>),
}

/// Why a game has no main executable, derived from its candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoneReason {
    /// The walk found no executable.
    NoExecutable,
    /// Executables, but none with the role "game".
    NoGameExecutable {
        /// Executables found.
        found: usize,
    },
    /// Every game executable failed to open or parse.
    AllFailed {
        /// Game executables.
        games: usize,
    },
}

/// The counts at the end of `rerun scan`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanCounts {
    /// Libraries.
    pub libraries: usize,
    /// Apps listed.
    pub apps: usize,
    /// Of these installed (scanned).
    pub installed: usize,
    /// Update pending (not opened).
    pub pending: usize,
    /// Not installed (not opened).
    pub not_installed: usize,
    /// Games with one main executable.
    pub one: usize,
    /// Games with a tie.
    pub tied: usize,
    /// Games without a main executable (or whose folder did not open).
    pub none: usize,
    /// Issue lines.
    pub issues: usize,
}

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
    /// A hardware adapter, numbered from 0 in DXGI order.
    Adapter {
        /// Position in DXGI order, from 0.
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
        /// What differs.
        why: NotUniform,
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

    // ---------- rerun scan ----------
    /// Steam's root came from this registry candidate (library 0 below is the root).
    SteamFound {
        /// The candidate.
        source: RootSource,
    },
    /// No usable registry candidate.
    SteamNotFound,
    /// An issue of the Steam scan.
    SteamIssue {
        /// Location and kind.
        issue: Shown<'a>,
    },
    /// A library.
    Library {
        /// Its number (0 is the Steam root).
        index: usize,
        /// Its path.
        path: Shown<'a>,
    },
    /// The label of the library above.
    LibraryLabel {
        /// The label as written.
        label: Shown<'a>,
    },
    /// An app of the library above.
    App {
        /// Steam app ID.
        app_id: u32,
        /// Its state; only installed apps are opened.
        state: AppState,
        /// Its name as written.
        name: Shown<'a>,
    },
    /// The install folder of the app above.
    InstallFolder {
        /// `installdir`.
        folder: Shown<'a>,
    },
    /// The game folder could not be opened.
    GameNotOpened {
        /// The error.
        error: Shown<'a>,
    },
    /// Exactly one main executable.
    MainOne {
        /// Relative to the game folder.
        path: Shown<'a>,
    },
    /// Several executables share the best rank; none is picked.
    MainTied {
        /// How many.
        count: usize,
    },
    /// One executable of a tie.
    TiedExe {
        /// Relative to the game folder.
        path: Shown<'a>,
    },
    /// No main executable.
    MainNone {
        /// Why.
        reason: NoneReason,
    },
    /// Machine, API and the numeric version of the executable above.
    ExeFacts {
        /// Machine.
        machine: Machine,
        /// `IMAGE_FILE_LARGE_ADDRESS_AWARE` (shown for x86 only).
        large_address_aware: bool,
        /// The graphics API with its evidence.
        api: &'a ApiReport,
        /// The file version from the fixed part of the version resource.
        version: Option<[u16; 4]>,
    },
    /// The hashes of the executable above (`--hashes`).
    ExeHashes(HashText<'a>),
    /// The walk of the game folder did not list everything.
    WalkIncomplete {
        /// Folders not entered because they lie deeper than `max_depth`.
        depth_cut: usize,
        /// The depth limit.
        max_depth: usize,
        /// A limit stopped the walk (see its issue line).
        stopped: bool,
    },
    /// An issue of the game scan.
    GameIssue {
        /// Location and kind.
        issue: Shown<'a>,
    },
    /// An anti-cheat marker in the game folder (P4-4): the Topo engine refuses file and
    /// firewall fixes and `watch` for this game and warns for the others.
    GameAntiCheat {
        /// The system.
        system: &'static str,
        /// The marker found.
        path: Shown<'a>,
    },
    /// An anti-cheat marker that could not be asked (treated like a find).
    GameAntiCheatUnreadable {
        /// The marker path.
        path: Shown<'a>,
    },
    /// A requested app ID that no library holds.
    AppNotFound {
        /// The app ID.
        app_id: u32,
    },
    /// The counts.
    Summary(ScanCounts),
    /// The closing hint.
    Hints,

    // ---------- errors and warnings (stderr) ----------
    /// `--hashes` is slow.
    HashesWarning,
    /// The install folder of `rerun.exe` is unknown.
    CurrentExe {
        /// The error.
        error: Shown<'a>,
    },
    /// The forbidden roots could not be resolved: no scan.
    ForbiddenRoots {
        /// The error.
        error: Shown<'a>,
    },
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
    /// A line of the phase 2 commands.
    Txn(TxnMsg<'a>),
    /// A line of the launch results in `rerun status` (P3-2).
    Launch(LaunchMsg<'a>),
    /// A line about a launch profile (P3-3d).
    Profile(ProfileMsg<'a>),
    /// A line about the signed index (ADR 0024).
    Index(IndexMsg<'a>),
    /// The elevated helper and its firewall rules (P4-2d).
    Helper(HelperMsg<'a>),
    /// A line of the Topo engine (P4-4).
    Topo(TopoMsg<'a>),
    /// A line about a package download (P4-6).
    Package(PackageMsg<'a>),
    /// A usage error, formatted by Rerun (security review N5): the user's own value only
    /// through `escape::text`, last on the line.
    Usage {
        /// What is wrong (Rerun's words).
        what: &'static str,
        /// The expected form, from Rerun's own value parser.
        why: Option<Shown<'a>>,
        /// The value or argument concerned.
        value: Option<Shown<'a>>,
    },
    /// Where to look after a usage error.
    UsageHelp,
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

impl fmt::Display for NotUniform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GroupSizes => "groups of different sizes",
            Self::ThreadsPerCore => "threads per core differ",
        })
    }
}

impl fmt::Display for NoneReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoExecutable => f.write_str("no executable found"),
            Self::NoGameExecutable { found } => write!(
                f,
                "no game executable among {}",
                Count(*found, "executable", "executables")
            ),
            Self::AllFailed { games } => write!(
                f,
                "{} failed to open or parse",
                Count(*games, "game executable", "game executables")
            ),
        }
    }
}

/// A machine as shown.
struct MachineText(Machine);

impl fmt::Display for MachineText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Machine::X86 => f.write_str("x86"),
            Machine::X64 => f.write_str("x64"),
            Machine::Arm64 => f.write_str("arm64"),
            Machine::Other(m) => write!(f, "machine {m:#06x}"),
        }
    }
}

impl fmt::Display for ScanCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Summary: {}, {} ({} installed, {} update pending, {} not installed); main \
             executable: {} found, {}, {} without; {}",
            Count(self.libraries, "library", "libraries"),
            Count(self.apps, "app", "apps"),
            self.installed,
            self.pending,
            self.not_installed,
            self.one,
            Count(self.tied, "tie", "ties"),
            self.none,
            Count(self.issues, "issue", "issues"),
        )
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
                why,
                level,
                groups,
                total_cores,
                total_threads,
            } => write!(
                f,
                "  {}, {}, {} ({})",
                Count(
                    *groups,
                    &format!("{level} group"),
                    &format!("{level} groups")
                ),
                cores(*total_cores),
                threads(*total_threads),
                why,
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

            Self::SteamFound { source } => write!(f, "Steam: found through {source}"),
            Self::SteamNotFound => f.write_str("Steam: not found"),
            Self::SteamIssue { issue } => write!(f, "  issue: {issue}"),
            Self::Library { index, path } => write!(f, "library {index}: {path}"),
            Self::LibraryLabel { label } => write!(f, "  label: {label}"),
            Self::App {
                app_id,
                state,
                name,
            } => match state {
                AppState::Installed => write!(f, "  app {app_id} (installed): {name}"),
                AppState::UpdatePending => {
                    write!(f, "  app {app_id} (update pending; not opened): {name}")
                }
                AppState::NotInstalled => {
                    write!(f, "  app {app_id} (not installed; not opened): {name}")
                }
            },
            Self::InstallFolder { folder } => write!(f, "    install folder: {folder}"),
            Self::GameNotOpened { error } => {
                write!(f, "    issue: game folder not opened: {error}")
            }
            Self::MainOne { path } => write!(f, "    main executable: {path}"),
            Self::MainTied { count } => write!(
                f,
                "    main executable: a tie between {count} executables, none picked"
            ),
            Self::TiedExe { path } => write!(f, "    tied: {path}"),
            Self::MainNone { reason } => write!(f, "    main executable: none ({reason})"),
            Self::ExeFacts {
                machine,
                large_address_aware,
                api,
                version,
            } => {
                write!(f, "      {}", MachineText(*machine))?;
                if *machine == Machine::X86 {
                    let laa = if *large_address_aware {
                        "large address aware"
                    } else {
                        "not large address aware"
                    };
                    write!(f, " ({laa})")?;
                }
                write!(f, ", API {api}, ")?;
                match version {
                    Some([a, b, c, d]) => write!(f, "version {a}.{b}.{c}.{d}"),
                    None => f.write_str("no version"),
                }
            }
            Self::ExeHashes(HashText::Done(h)) => write!(
                f,
                "      SHA-1 {}, SHA-256 {} ({} bytes)",
                h.sha1, h.sha256, h.len
            ),
            Self::ExeHashes(HashText::NotDone(text)) => write!(f, "      hashes: {text}"),
            Self::WalkIncomplete {
                depth_cut,
                max_depth,
                stopped,
            } => {
                f.write_str("    walk: ")?;
                if *depth_cut > 0 {
                    write!(
                        f,
                        "{} deeper than {max_depth} levels not listed",
                        Count(*depth_cut, "folder", "folders")
                    )?;
                    if *stopped {
                        f.write_str("; ")?;
                    }
                }
                if *stopped {
                    f.write_str("stopped at a limit")?;
                }
                f.write_str(" (the list of executables may be incomplete)")
            }
            Self::GameIssue { issue } => write!(f, "    issue: {issue}"),
            Self::GameAntiCheat { system, path } => {
                write!(f, "    anti-cheat: {system} at {path}")
            }
            Self::GameAntiCheatUnreadable { path } => {
                write!(f, "    anti-cheat: cannot check {path} (counted as found)")
            }
            Self::AppNotFound { app_id } => write!(f, "app {app_id}: not found in any library"),
            Self::Summary(counts) => write!(f, "{counts}"),
            Self::Hints => {
                f.write_str("Roles and APIs are hints from names and imports, not verdicts.")
            }

            Self::HashesWarning => f.write_str(
                "warning: --hashes reads every game executable in full; can take minutes on a \
                 cold cache",
            ),
            Self::CurrentExe { error } => {
                write!(f, "rerun: cannot find its own install folder: {error}")
            }
            Self::ForbiddenRoots { error } => write!(
                f,
                "rerun: cannot resolve the folders that must never be scanned: {error}"
            ),

            Self::DllSearch { error } => write!(
                f,
                "rerun: cannot restrict the DLL search path to System32: {error}"
            ),
            Self::SystemUnavailable { error } => {
                write!(f, "rerun: cannot open the system layer: {error}")
            }
            #[cfg(not(windows))]
            Self::WindowsOnly => f.write_str("rerun: runs on Windows only"),
            Self::Txn(m) => write!(f, "{m}"),
            Self::Launch(m) => write!(f, "{m}"),
            Self::Profile(m) => write!(f, "{m}"),
            Self::Index(m) => write!(f, "{m}"),
            Self::Helper(m) => write!(f, "{m}"),
            Self::Topo(m) => write!(f, "{m}"),
            Self::Package(m) => write!(f, "{m}"),
            Self::Usage { what, why, value } => {
                write!(f, "rerun: {what}")?;
                if let Some(why) = why {
                    write!(f, " ({why})")?;
                }
                match value {
                    Some(v) => write!(f, ": {v}"),
                    None => Ok(()),
                }
            }
            Self::UsageHelp => f.write_str(
                "rerun --help lists the commands, rerun <command> --help their arguments",
            ),
            Self::WriteFailed { kind } => write!(f, "rerun: cannot write the output: {kind}"),
        }
    }
}
