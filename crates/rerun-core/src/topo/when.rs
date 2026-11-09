//! `when` against the system profile (ADR 0015, "Evaluation semantics", built in P4-4).
//!
//! Each key is yes, no or unknown; a `when` is the Kleene AND of its keys (any no → no, else
//! any unknown → unknown, else yes); an empty or missing `when` is yes. `Unavailable` is
//! unknown; no hardware adapter is no; a device the architecture table does not know is no for
//! any list; a vendor other than AMD, NVIDIA and Intel is no. `when` selects suggestions and is
//! never authorisation.

use crate::catalog::model::{Compare, Vendor, When};
use crate::hw::{ArchFact, Fact, GpuVendor, SystemProfile, VendorFact};

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

/// The `when` of an issue (`None`: all systems).
pub fn eval(when: Option<&When>, p: &SystemProfile) -> Tri {
    let Some(w) = when else {
        return Tri::Yes;
    };
    let mut r = Tri::Yes;
    if let Some(v) = w.gpu_vendor {
        r = r.and(match p.gpu_vendor() {
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
        r = r.and(match p.gpu_arch() {
            ArchFact::Unavailable => Tri::Unknown,
            ArchFact::NoAdapter | ArchFact::Unknown => Tri::No,
            ArchFact::Known(id) => Tri::of(list.iter().any(|a| *a.id() == id)),
        });
    }
    if let Some(c) = &w.cpu_threads {
        r = r.and(number(p.cpu_threads(), c));
    }
    if let Some(h) = w.cpu_hybrid {
        r = r.and(match p.cpu_hybrid() {
            Fact::Known(b) => Tri::of(b == h),
            Fact::Unavailable => Tri::Unknown,
        });
    }
    if let Some(c) = &w.os_build {
        r = r.and(number(p.os_build(), c));
    }
    r
}
