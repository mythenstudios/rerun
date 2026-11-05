//! GPU architecture table (ADR 0015, `docs/03b-gpu-display.md`).
//!
//! A GPU does not report its generation, so Rerun maps the PCI `(vendor, device)` pair to an
//! architecture identifier through a data table. The source of truth is `data/gpu-arch.yaml`
//! (schema `schema/gpu-arch.schema.json`); step 15 compiles in a small mirror of it
//! ([`GpuArchTable::builtin`]), and a test requires the two to be equal. From phase 4 the table
//! travels in the signed index and replaces the built-in one wholesale; a Topo is evaluated
//! against exactly the table it was validated with.
//!
//! [`GpuArchTable::new`] is the only constructor and checks every rule of ADR 0015, also those
//! the schema cannot express (unique identifiers, declared architectures with a matching
//! vendor, no `(vendor, device)` covered twice). It is serde-free; table data is untrusted, so
//! sizes are bounded before anything is sorted, ranges are never expanded, and a
//! [`TableError`] names positions and kinds, never content.

use std::cmp::Ordering;
use std::fmt;
use std::sync::OnceLock;

use crate::sys::gpu::is_bidi_control;

/// PCI vendor ID of AMD.
pub const VENDOR_AMD: u32 = 0x1002;
/// PCI vendor ID of NVIDIA.
pub const VENDOR_NVIDIA: u32 = 0x10DE;
/// PCI vendor ID of Intel.
pub const VENDOR_INTEL: u32 = 0x8086;
/// The vendors a table may name.
pub const VENDORS: [u32; 3] = [VENDOR_AMD, VENDOR_NVIDIA, VENDOR_INTEL];

/// Most declared architectures.
pub const MAX_ARCHS: usize = 256;
/// Most entries.
pub const MAX_ENTRIES: usize = 4096;
/// Most device IDs plus ranges in one entry (an ID or a range counts 1).
pub const MAX_ITEMS: usize = 1024;
/// Highest PCI device ID (and range bound).
pub const MAX_DEVICE_ID: u32 = 0xFFFF;
/// Longest architecture identifier, in characters (all ASCII).
pub const MAX_ARCH_ID_LEN: usize = 32;
/// Longest `source`, in characters.
pub const MAX_SOURCE_CHARS: usize = 200;

/// The value an identifier may never have: an unknown device is a profile state.
const RESERVED_ARCH_ID: &str = "unknown";

// ---------- ArchId ----------

/// An architecture identifier: `^[a-z][a-z0-9_]{0,31}$`, never `unknown` (the same rule as
/// `$defs/archId` of both schemas; a parity test runs the same cases through both).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArchId(String);

/// Why a string is no [`ArchId`]. Never carries the string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ArchIdError {
    /// The empty string.
    #[error("architecture identifier is empty")]
    Empty,
    /// More than [`MAX_ARCH_ID_LEN`] characters.
    #[error("architecture identifier is longer than {MAX_ARCH_ID_LEN} characters")]
    TooLong,
    /// The first character is no lowercase ASCII letter.
    #[error("architecture identifier does not start with a lowercase letter")]
    FirstNotLetter,
    /// A character other than a lowercase ASCII letter, digit or `_`.
    #[error("architecture identifier contains a character other than a-z, 0-9 or _")]
    BadChar,
    /// `unknown`, a profile state and never a value.
    #[error("architecture identifier \"unknown\" is reserved")]
    Reserved,
}

impl ArchId {
    /// Checks `s` against the identifier rule.
    pub fn new(s: &str) -> Result<Self, ArchIdError> {
        let mut chars = s.chars();
        let first = chars.next().ok_or(ArchIdError::Empty)?;
        if !first.is_ascii_lowercase() {
            return Err(ArchIdError::FirstNotLetter);
        }
        if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(ArchIdError::BadChar);
        }
        // All ASCII from here on: bytes are characters.
        if s.len() > MAX_ARCH_ID_LEN {
            return Err(ArchIdError::TooLong);
        }
        if s == RESERVED_ARCH_ID {
            return Err(ArchIdError::Reserved);
        }
        Ok(Self(s.to_owned()))
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------- Table data ----------

/// A declared architecture: an identifier a Topo may name, and its vendor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArchDecl {
    /// Identifier.
    pub id: ArchId,
    /// PCI vendor ID, one of [`VENDORS`].
    pub vendor: u32,
}

/// The highest Vulkan version a vendor states for a group of devices: `1.<minor>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VkVersion {
    /// Minor version (the major version is always 1).
    pub minor: u8,
}

impl fmt::Display for VkVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "1.{}", self.minor)
    }
}

/// How Direct3D 9 runs on a group of devices. Intel ties it to the CPU generation, so it is
/// per entry, never per architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dx9Path {
    /// A native D3D9 driver.
    Native,
    /// The D3D9On12 mapping layer.
    D3d9On12,
}

impl fmt::Display for Dx9Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::D3d9On12 => "d3d9on12",
        })
    }
}

/// An inclusive range of device IDs, only as a source states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceRange {
    /// First device ID.
    pub from: u32,
    /// Last device ID (inclusive).
    pub to: u32,
}

/// One group of devices of one architecture. Revision and subsystem IDs are deliberately not
/// keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArchEntry {
    /// PCI vendor ID, one of [`VENDORS`], equal to the declared vendor of `arch`.
    pub vendor: u32,
    /// Architecture, declared in the table.
    pub arch: ArchId,
    /// An integrated GPU (from the source, not guessed from memory).
    pub integrated: bool,
    /// Highest Vulkan version, `None` for none.
    pub vulkan: Option<VkVersion>,
    /// D3D9 path.
    pub dx9: Dx9Path,
    /// Explicit device IDs.
    pub device_ids: Vec<u32>,
    /// Inclusive device ID ranges.
    pub device_ranges: Vec<DeviceRange>,
    /// Where the IDs come from.
    pub source: String,
}

// ---------- Errors ----------

/// Where a [`TableError`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TablePos {
    /// The table as a whole.
    Table,
    /// `archs[index]`.
    Arch(usize),
    /// `entries[index]`.
    Entry(usize),
}

impl fmt::Display for TablePos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Table => f.write_str("gpu arch table"),
            Self::Arch(i) => write!(f, "gpu arch table: archs[{i}]"),
            Self::Entry(i) => write!(f, "gpu arch table: entries[{i}]"),
        }
    }
}

/// What is wrong. Never carries table content (no identifier, ID or source text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TableErrorKind {
    /// More than [`MAX_ARCHS`] architectures.
    TooManyArchs,
    /// More than [`MAX_ENTRIES`] entries.
    TooManyEntries,
    /// An identifier breaks the identifier rule (the built-in mirror only; elsewhere an
    /// [`ArchId`] is checked when it is made).
    BadArchId(ArchIdError),
    /// A vendor other than AMD, NVIDIA and Intel.
    BadVendor,
    /// The identifier is declared before, at `archs[first]`.
    DuplicateArch {
        /// Index of the first declaration.
        first: usize,
    },
    /// The entry's architecture is not declared.
    UndeclaredArch,
    /// The entry's vendor differs from the declared vendor of its architecture.
    ArchVendorMismatch {
        /// Index of the declaration in `archs`.
        arch: usize,
    },
    /// Neither a device ID nor a range.
    NoDevices,
    /// More than [`MAX_ITEMS`] device IDs and ranges together.
    TooManyDevices,
    /// A device ID or range bound above [`MAX_DEVICE_ID`].
    DeviceOutOfRange,
    /// A range with `from > to`.
    RangeReversed,
    /// `source` is empty or longer than [`MAX_SOURCE_CHARS`] characters.
    SourceLength,
    /// `source` contains a control character.
    SourceControl,
    /// `source` contains a bidirectional formatting character.
    SourceBidi,
    /// A `(vendor, device)` this entry covers is covered by `entries[other]` as well (or twice
    /// by this entry, then `other` is its own index). Reported at the later entry.
    Overlap {
        /// Index of the other entry.
        other: usize,
    },
}

impl fmt::Display for TableErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyArchs => write!(f, "more than {MAX_ARCHS} architectures"),
            Self::TooManyEntries => write!(f, "more than {MAX_ENTRIES} entries"),
            Self::BadArchId(e) => write!(f, "{e}"),
            Self::BadVendor => f.write_str("vendor is not AMD, NVIDIA or Intel"),
            Self::DuplicateArch { first } => {
                write!(f, "architecture already declared at archs[{first}]")
            }
            Self::UndeclaredArch => f.write_str("architecture is not declared"),
            Self::ArchVendorMismatch { arch } => {
                write!(f, "vendor differs from the declaration at archs[{arch}]")
            }
            Self::NoDevices => f.write_str("no device IDs and no device ranges"),
            Self::TooManyDevices => {
                write!(f, "more than {MAX_ITEMS} device IDs and ranges")
            }
            Self::DeviceOutOfRange => write!(f, "device ID above {MAX_DEVICE_ID:#06x}"),
            Self::RangeReversed => f.write_str("device range with from > to"),
            Self::SourceLength => {
                write!(
                    f,
                    "source is empty or longer than {MAX_SOURCE_CHARS} characters"
                )
            }
            Self::SourceControl => f.write_str("source contains a control character"),
            Self::SourceBidi => f.write_str("source contains a bidi control character"),
            Self::Overlap { other } => {
                write!(f, "a device is also covered by entries[{other}]")
            }
        }
    }
}

/// A rule of ADR 0015 the table breaks: where and what, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{at}: {kind}")]
pub struct TableError {
    /// Position.
    pub at: TablePos,
    /// Kind.
    pub kind: TableErrorKind,
}

impl TableError {
    fn new(at: TablePos, kind: TableErrorKind) -> Self {
        Self { at, kind }
    }
}

// ---------- Table ----------

/// A covered device interval, the lookup index. Sorted by `(vendor, from)`, never
/// overlapping once [`GpuArchTable::new`] succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Interval {
    vendor: u32,
    from: u32,
    to: u32,
    entry: usize,
}

/// A validated GPU architecture table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuArchTable {
    archs: Vec<ArchDecl>,
    entries: Vec<ArchEntry>,
    intervals: Vec<Interval>,
}

impl GpuArchTable {
    /// Checks every rule of ADR 0015 and builds the lookup index. Sizes are checked before
    /// anything else; overlaps are found over sorted intervals, ranges are never expanded.
    pub fn new(archs: Vec<ArchDecl>, entries: Vec<ArchEntry>) -> Result<Self, TableError> {
        if archs.len() > MAX_ARCHS {
            return Err(TableError::new(
                TablePos::Table,
                TableErrorKind::TooManyArchs,
            ));
        }
        if entries.len() > MAX_ENTRIES {
            return Err(TableError::new(
                TablePos::Table,
                TableErrorKind::TooManyEntries,
            ));
        }
        for (i, a) in archs.iter().enumerate() {
            let at = TablePos::Arch(i);
            if !VENDORS.contains(&a.vendor) {
                return Err(TableError::new(at, TableErrorKind::BadVendor));
            }
            if let Some(first) = archs[..i].iter().position(|b| b.id == a.id) {
                return Err(TableError::new(at, TableErrorKind::DuplicateArch { first }));
            }
        }
        let mut intervals = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            check_entry(&archs, e).map_err(|kind| TableError::new(TablePos::Entry(i), kind))?;
            intervals.extend(e.device_ids.iter().map(|&d| Interval {
                vendor: e.vendor,
                from: d,
                to: d,
                entry: i,
            }));
            intervals.extend(e.device_ranges.iter().map(|r| Interval {
                vendor: e.vendor,
                from: r.from,
                to: r.to,
                entry: i,
            }));
        }
        intervals.sort_unstable_by_key(|v| (v.vendor, v.from, v.to, v.entry));
        if let Some((a, b)) = first_overlap(&intervals) {
            let (earlier, later) = (a.min(b), a.max(b));
            return Err(TableError::new(
                TablePos::Entry(later),
                TableErrorKind::Overlap { other: earlier },
            ));
        }
        Ok(Self {
            archs,
            entries,
            intervals,
        })
    }

    /// The table compiled into this binary, a mirror of `data/gpu-arch.yaml` (a test requires
    /// both to be equal), built once through [`GpuArchTable::new`].
    pub fn builtin() -> Result<&'static GpuArchTable, TableError> {
        static BUILTIN: OnceLock<Result<GpuArchTable, TableError>> = OnceLock::new();
        BUILTIN
            .get_or_init(|| from_mirror(BUILTIN_ARCHS, BUILTIN_ENTRIES))
            .as_ref()
            .map_err(|e| *e)
    }

    /// The declared architectures, in table order.
    pub fn archs(&self) -> &[ArchDecl] {
        &self.archs
    }

    /// The entries, in table order.
    pub fn entries(&self) -> &[ArchEntry] {
        &self.entries
    }

    /// The declaration of `id`, if the table declares it.
    pub fn arch(&self, id: &ArchId) -> Option<&ArchDecl> {
        self.archs.iter().find(|a| a.id == *id)
    }

    /// Does the table declare `id`? A Topo may only name declared identifiers.
    pub fn declares(&self, id: &ArchId) -> bool {
        self.arch(id).is_some()
    }

    /// The entry covering `(vendor_id, device_id)`; `None` for an unknown device. Revision and
    /// subsystem IDs are never consulted.
    pub fn lookup(&self, vendor_id: u32, device_id: u32) -> Option<&ArchEntry> {
        let key = (vendor_id, device_id);
        let after = self
            .intervals
            .partition_point(|v| (v.vendor, v.from).cmp(&key) != Ordering::Greater);
        let candidate = self.intervals.get(after.checked_sub(1)?)?;
        (candidate.vendor == vendor_id && device_id <= candidate.to)
            .then(|| self.entries.get(candidate.entry))
            .flatten()
    }
}

/// The rules for one entry, in a fixed order.
fn check_entry(archs: &[ArchDecl], e: &ArchEntry) -> Result<(), TableErrorKind> {
    if !VENDORS.contains(&e.vendor) {
        return Err(TableErrorKind::BadVendor);
    }
    let arch = archs
        .iter()
        .position(|a| a.id == e.arch)
        .ok_or(TableErrorKind::UndeclaredArch)?;
    if archs.get(arch).is_some_and(|a| a.vendor != e.vendor) {
        return Err(TableErrorKind::ArchVendorMismatch { arch });
    }
    let items = e.device_ids.len().saturating_add(e.device_ranges.len());
    if items == 0 {
        return Err(TableErrorKind::NoDevices);
    }
    if items > MAX_ITEMS {
        return Err(TableErrorKind::TooManyDevices);
    }
    let bounds = e
        .device_ids
        .iter()
        .chain(e.device_ranges.iter().flat_map(|r| [&r.from, &r.to]));
    if bounds.into_iter().any(|&d| d > MAX_DEVICE_ID) {
        return Err(TableErrorKind::DeviceOutOfRange);
    }
    if e.device_ranges.iter().any(|r| r.from > r.to) {
        return Err(TableErrorKind::RangeReversed);
    }
    check_source(&e.source)
}

fn check_source(s: &str) -> Result<(), TableErrorKind> {
    let n = s.chars().count();
    if n == 0 || n > MAX_SOURCE_CHARS {
        return Err(TableErrorKind::SourceLength);
    }
    if s.chars().any(char::is_control) {
        return Err(TableErrorKind::SourceControl);
    }
    if s.chars().any(is_bidi_control) {
        return Err(TableErrorKind::SourceBidi);
    }
    Ok(())
}

/// The entries of the first two intervals (sorted by `(vendor, from, …)`) that share a device.
/// Until the first overlap, the intervals of one vendor are disjoint and ascending, so the
/// previous interval is the one reaching furthest.
fn first_overlap(sorted: &[Interval]) -> Option<(usize, usize)> {
    sorted.windows(2).find_map(|w| match w {
        [prev, cur] if prev.vendor == cur.vendor && cur.from <= prev.to => {
            Some((prev.entry, cur.entry))
        }
        _ => None,
    })
}

// ---------- Built-in mirror of data/gpu-arch.yaml ----------

/// One entry of the built-in mirror, as plain constant data.
struct MirrorEntry {
    vendor: u32,
    arch: &'static str,
    integrated: bool,
    vulkan: Option<u8>,
    dx9: Dx9Path,
    device_ids: &'static [u32],
    device_ranges: &'static [(u32, u32)],
    source: &'static str,
}

/// `archs` of `data/gpu-arch.yaml`, in file order.
const BUILTIN_ARCHS: &[(&str, u32)] = &[
    ("terascale", VENDOR_AMD),
    ("gcn1", VENDOR_AMD),
    ("gcn2", VENDOR_AMD),
    ("gcn3", VENDOR_AMD),
    ("gcn4", VENDOR_AMD),
    ("vega", VENDOR_AMD),
    ("rdna1", VENDOR_AMD),
    ("rdna2", VENDOR_AMD),
    ("rdna3", VENDOR_AMD),
    ("rdna3_5", VENDOR_AMD),
    ("rdna4", VENDOR_AMD),
    ("rdna5", VENDOR_AMD),
    ("tesla", VENDOR_NVIDIA),
    ("fermi", VENDOR_NVIDIA),
    ("kepler", VENDOR_NVIDIA),
    ("maxwell", VENDOR_NVIDIA),
    ("pascal", VENDOR_NVIDIA),
    ("volta", VENDOR_NVIDIA),
    ("turing", VENDOR_NVIDIA),
    ("ampere", VENDOR_NVIDIA),
    ("ada", VENDOR_NVIDIA),
    ("blackwell", VENDOR_NVIDIA),
    ("rubin", VENDOR_NVIDIA),
    ("gen9", VENDOR_INTEL),
    ("gen11", VENDOR_INTEL),
    ("xe_lp", VENDOR_INTEL),
    ("xe_hpg", VENDOR_INTEL),
    ("xe2", VENDOR_INTEL),
    ("xe3", VENDOR_INTEL),
    ("xe3p", VENDOR_INTEL),
    ("xe4", VENDOR_INTEL),
];

/// `entries` of `data/gpu-arch.yaml`, in file order. Every shipped ID needs its own real
/// source (`docs/05-sources-policy.md`); test entries live in test code only.
const BUILTIN_ENTRIES: &[MirrorEntry] = &[MirrorEntry {
    vendor: VENDOR_AMD,
    arch: "rdna4",
    integrated: false,
    vulkan: Some(4),
    dx9: Dx9Path::Native,
    device_ids: &[0x7550],
    device_ranges: &[],
    source: "developer machine dump, 2026-11-05 (ADR 0008)",
}];

fn from_mirror(archs: &[(&str, u32)], entries: &[MirrorEntry]) -> Result<GpuArchTable, TableError> {
    let archs = archs
        .iter()
        .enumerate()
        .map(|(i, &(id, vendor))| {
            ArchId::new(id)
                .map(|id| ArchDecl { id, vendor })
                .map_err(|e| TableError::new(TablePos::Arch(i), TableErrorKind::BadArchId(e)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let entries = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let arch = ArchId::new(e.arch).map_err(|err| {
                TableError::new(TablePos::Entry(i), TableErrorKind::BadArchId(err))
            })?;
            Ok(ArchEntry {
                vendor: e.vendor,
                arch,
                integrated: e.integrated,
                vulkan: e.vulkan.map(|minor| VkVersion { minor }),
                dx9: e.dx9,
                device_ids: e.device_ids.to_vec(),
                device_ranges: e
                    .device_ranges
                    .iter()
                    .map(|&(from, to)| DeviceRange { from, to })
                    .collect(),
                source: e.source.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, TableError>>()?;
    GpuArchTable::new(archs, entries)
}

#[cfg(test)]
mod tests;
