//! `when` against the system profile (ADR 0015, "Evaluation semantics", built in P4-4).
//!
//! Each key is yes, no or unknown; a `when` is the Kleene AND of its keys (any no → no, else
//! any unknown → unknown, else yes); an empty or missing `when` is yes. `Unavailable` is
//! unknown; no hardware adapter is no; a device the architecture table does not know is no for
//! any list; a vendor other than AMD, NVIDIA and Intel is no. `when` selects suggestions and is
//! never authorisation.
//!
//! The GPU keys `gpu.vendor`, `gpu.arch` and `gpu.integrated` form one block, checked on each
//! hardware adapter (P4-11, user decision E-G2 d): the block is yes when it is yes on every
//! adapter, no when it is no on every adapter, else unknown; then it is ANDed with the other
//! keys. With one adapter this is the per-key AND of before. `gpu.hybrid` is system-wide.

use crate::catalog::model::{Compare, Vendor, When};
use crate::hw::{ArchFact, Fact, GpuFacts, GpuVendor, IntegratedFact, SystemProfile, VendorFact};

/// A three-valued result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    /// Holds.
    Yes,
    /// Does not hold.
    No,
    /// A fact could not be read.
    Unknown,
}

impl Tri {
    /// Kleene AND.
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Yes,
        }
    }

    fn of(b: bool) -> Self {
        if b { Self::Yes } else { Self::No }
    }

    /// `yes`, `no`, `unknown`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Unknown => "unknown",
        }
    }
}

/// Every given bound of `c` holds for `v`.
fn compare(c: &Compare, v: i64) -> bool {
    c.gt.is_none_or(|x| v > x)
        && c.gte.is_none_or(|x| v >= x)
        && c.lt.is_none_or(|x| v < x)
        && c.lte.is_none_or(|x| v <= x)
        && c.eq.is_none_or(|x| v == x)
}

fn number(f: Fact<u32>, c: &Compare) -> Tri {
    match f {
        Fact::Known(n) => Tri::of(compare(c, i64::from(n))),
        Fact::Unavailable => Tri::Unknown,
    }
}

/// `w` has a key of the GPU block (`gpu.vendor`, `gpu.arch`, `gpu.integrated`).
pub fn has_gpu_block(w: &When) -> bool {
    w.gpu_vendor.is_some() || w.gpu_arch.is_some() || w.gpu_integrated.is_some()
}

/// The GPU block on one adapter's facts.
fn on_adapter(w: &When, f: &GpuFacts) -> Tri {
    let mut r = Tri::Yes;
    if let Some(v) = w.gpu_vendor {
        r = r.and(match f.vendor {
            VendorFact::Unavailable => Tri::Unknown,
            VendorFact::NoAdapter => Tri::No,
            VendorFact::Known(g) => Tri::of(matches!(
                (v, g),
                (Vendor::Amd, GpuVendor::Amd)
                    | (Vendor::Nvidia, GpuVendor::Nvidia)
                    | (Vendor::Intel, GpuVendor::Intel)
            )),
        });
    }
    if let Some(list) = &w.gpu_arch {
        r = r.and(match &f.arch {
            ArchFact::Unavailable => Tri::Unknown,
            ArchFact::NoAdapter | ArchFact::Unknown => Tri::No,
            ArchFact::Known(id) => Tri::of(list.iter().any(|a| a.id() == id)),
        });
    }
    if let Some(i) = w.gpu_integrated {
        r = r.and(match f.integrated {
            IntegratedFact::Unavailable => Tri::Unknown,
            IntegratedFact::NoAdapter | IntegratedFact::Unknown => Tri::No,
            IntegratedFact::Known(b) => Tri::of(b == i),
        });
    }
    r
}

/// The GPU block over every adapter (module docs).
fn gpu_block(w: &When, p: &SystemProfile) -> Tri {
    let each: Vec<Tri> = p.gpu_facts().iter().map(|f| on_adapter(w, f)).collect();
    if each.iter().all(|t| *t == Tri::Yes) {
        Tri::Yes
    } else if each.iter().all(|t| *t == Tri::No) {
        Tri::No
    } else {
        Tri::Unknown
    }
}

fn flag(f: Fact<bool>, want: bool) -> Tri {
    match f {
        Fact::Known(b) => Tri::of(b == want),
        Fact::Unavailable => Tri::Unknown,
    }
}

/// The `when` of an issue (`None`: all systems).
pub fn eval(when: Option<&When>, p: &SystemProfile) -> Tri {
    let Some(w) = when else {
        return Tri::Yes;
    };
    let mut r = Tri::Yes;
    if has_gpu_block(w) {
        r = r.and(gpu_block(w, p));
    }
    if let Some(h) = w.gpu_hybrid {
        r = r.and(flag(p.gpu_hybrid(), h));
    }
    if let Some(c) = &w.cpu_threads {
        r = r.and(number(p.cpu_threads(), c));
    }
    if let Some(h) = w.cpu_hybrid {
        r = r.and(flag(p.cpu_hybrid(), h));
    }
    if let Some(c) = &w.os_build {
        r = r.and(number(p.os_build(), c));
    }
    r
}
