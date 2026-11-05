//! `rerun system` (ADR 0016): the system profile (ADR 0015) in four blocks, GPU, CPU, OS and
//! Conditions. Read-only; rendering is pure.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use rerun_core::escape;
use rerun_core::hw::arch::TableError;
use rerun_core::hw::{
    self, ArchFact, Fact, GpuArch, GpuArchTable, GpuProfile, ProfileError, SystemProfile,
    VendorFact,
};
use rerun_core::sys::System;
use rerun_proto::cpu::CpuTopology;

use crate::cli::Exit;
use crate::messages::{ArchText, CacheLevel, FactText, Heading, Message};
use crate::out::{Out, failed};

/// Reads the profile with the built-in architecture table and prints it. Exit 0 also when a
/// part could not be read; 1 only for a write error other than a closed pipe.
pub fn system<W: Write, E: Write>(sys: &dyn System, out: &mut Out<W>, err: &mut Out<E>) -> Exit {
    let table = GpuArchTable::builtin();
    let profile = hw::read(sys, table.as_ref().ok().copied());
    let lines = render(&profile, table.as_ref().err());
    match out.lines(&lines).and_then(|()| out.flush()) {
        Ok(()) => Exit::Report,
        Err(e) => failed(err, e),
    }
}

/// The profile as lines. `table_error`: the built-in table failed validation (every
/// architecture is then unavailable).
pub fn render<'a>(p: &'a SystemProfile, table_error: Option<&TableError>) -> Vec<Message<'a>> {
    let mut m = vec![Message::Heading(Heading::Gpu)];
    gpu(&mut m, &p.gpu, table_error);
    m.push(Message::Blank);
    m.push(Message::Heading(Heading::Cpu));
    match &p.cpu {
        Ok(t) => cpu(&mut m, t),
        Err(e) => m.push(Message::CpuUnreadable { error: error(e) }),
    }
    m.push(Message::Blank);
    m.push(Message::Heading(Heading::Os));
    m.push(match &p.os {
        Ok(b) => Message::OsBuild {
            build: b.build,
            ubr: b.ubr,
        },
        Err(e) => Message::OsUnreadable { error: error(e) },
    });
    m.push(Message::Blank);
    m.push(Message::Heading(Heading::Conditions));
    conditions(&mut m, p);
    m
}

/// A profile error for display (source and kind; a system error's target is already escaped,
/// `text` is the second line of defence).
fn error(e: &ProfileError) -> escape::Shown<'static> {
    owned(&e.to_string())
}

/// `escape::text` of a computed string, owned.
fn owned(s: &str) -> escape::Shown<'static> {
    escape::text(s).into_owned()
}

fn gpu<'a>(
    m: &mut Vec<Message<'a>>,
    gpu: &'a Result<GpuProfile, ProfileError>,
    table_error: Option<&TableError>,
) {
    if let Some(e) = table_error {
        m.push(Message::ArchTableInvalid {
            error: owned(&e.to_string()),
        });
    }
    let g = match gpu {
        Err(e) => {
            m.push(Message::GpuUnreadable { error: error(e) });
            return;
        }
        Ok(g) => g,
    };
    if g.adapters.is_empty() {
        m.push(Message::NoHardwareAdapter);
        return;
    }
    for (i, a) in g.adapters.iter().enumerate() {
        m.push(Message::Adapter {
            number: i + 1,
            conditions: i == 0,
            name: escape::text(&a.adapter.name),
        });
        let arch = match (&a.arch, table_error) {
            (_, Some(_)) => ArchText::Unavailable,
            (GpuArch::Known(id), None) => ArchText::Known(escape::text(id.as_str())),
            (GpuArch::Unknown, None) => ArchText::Unknown {
                vendor_id: a.adapter.vendor_id,
                device_id: a.adapter.device_id,
            },
        };
        m.push(Message::AdapterFacts {
            vendor: a.vendor,
            vendor_id: a.adapter.vendor_id,
            device_id: a.adapter.device_id,
            vram_mb: a.vram_mb(),
            integrated: a.integrated,
            arch,
        });
    }
    if g.adapters.len() > 1 {
        m.push(Message::SeveralAdapters);
    }
}

/// One last-level cache group: core → threads.
struct Group {
    level: Option<u8>,
    size: u64,
    cores: BTreeMap<u32, usize>,
}

impl Group {
    fn threads(&self) -> usize {
        self.cores.values().sum()
    }

    /// Threads per core if every core has the same number.
    fn per_core(&self) -> Option<usize> {
        let mut v = self.cores.values();
        let first = *v.next()?;
        v.all(|t| *t == first).then_some(first)
    }
}

/// Sorted numbers as inclusive ranges.
fn ranges(nums: impl IntoIterator<Item = u32>) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for n in nums {
        match out.last_mut() {
            Some((_, to)) if to.checked_add(1) == Some(n) => *to = n,
            _ => out.push((n, n)),
        }
    }
    out
}

fn cpu(m: &mut Vec<Message<'_>>, t: &CpuTopology) {
    let mut groups: BTreeMap<u32, Group> = BTreeMap::new();
    let mut classes: BTreeMap<u8, (BTreeSet<u32>, usize)> = BTreeMap::new();
    for c in &t.cpus {
        let llc = t.llcs.get(usize::try_from(c.llc).unwrap_or(usize::MAX));
        let g = groups.entry(c.llc).or_insert_with(|| Group {
            level: llc.map(|l| l.level),
            size: llc.map_or(0, |l| l.size),
            cores: BTreeMap::new(),
        });
        *g.cores.entry(c.core).or_default() += 1;
        let class = classes.entry(c.efficiency_class).or_default();
        class.0.insert(c.core);
        class.1 += 1;
    }
    let levels: BTreeSet<Option<u8>> = groups.values().map(|g| g.level).collect();
    let level = CacheLevel(match levels.into_iter().collect::<Vec<_>>().as_slice() {
        [one] => *one,
        _ => None,
    });
    let shapes: BTreeSet<(usize, Option<usize>)> = groups
        .values()
        .map(|g| (g.cores.len(), g.per_core()))
        .collect();
    let (total_cores, total_threads) = (t.core_count(), t.logical_count());
    m.push(match shapes.into_iter().collect::<Vec<_>>().as_slice() {
        [(cores, Some(threads))] => Message::CpuUniform {
            level,
            groups: groups.len(),
            cores: *cores,
            threads: *threads,
            total_cores,
            total_threads,
        },
        _ => Message::CpuMixed {
            level,
            groups: groups.len(),
            total_cores,
            total_threads,
        },
    });
    for (index, g) in &groups {
        m.push(Message::CacheGroup {
            level: CacheLevel(g.level),
            index: *index,
            size: g.size,
            cores: g.cores.len(),
            per_core: g.per_core(),
            threads: g.threads(),
            core_ranges: ranges(g.cores.keys().copied()),
        });
    }
    for (class, (cores, threads)) in &classes {
        m.push(Message::EfficiencyClass {
            class: *class,
            cores: cores.len(),
            threads: *threads,
        });
    }
    m.push(Message::Hybrid {
        hybrid: t.is_hybrid(),
        classes: classes.len(),
    });
}

fn conditions<'a>(m: &mut Vec<Message<'a>>, p: &'a SystemProfile) {
    let vendor = match p.gpu_vendor() {
        VendorFact::Known(v) => FactText::Vendor(v),
        VendorFact::NoAdapter => FactText::NoAdapter,
        VendorFact::Unavailable => FactText::Unavailable,
    };
    let arch = match p.gpu_arch() {
        ArchFact::Known(id) => FactText::Arch(owned(id.as_str())),
        ArchFact::Unknown => FactText::Unknown,
        ArchFact::NoAdapter => FactText::NoAdapter,
        ArchFact::Unavailable => FactText::Unavailable,
    };
    let number = |f: Fact<u32>| match f {
        Fact::Known(n) => FactText::Number(n),
        Fact::Unavailable => FactText::Unavailable,
    };
    let hybrid = match p.cpu_hybrid() {
        Fact::Known(b) => FactText::Bool(b),
        Fact::Unavailable => FactText::Unavailable,
    };
    for (key, value) in [
        ("gpu.vendor", vendor),
        ("gpu.arch", arch),
        ("cpu.threads", number(p.cpu_threads())),
        ("cpu.hybrid", hybrid),
        ("os.build", number(p.os_build())),
    ] {
        m.push(Message::Condition { key, value });
    }
}

#[cfg(test)]
mod tests;
