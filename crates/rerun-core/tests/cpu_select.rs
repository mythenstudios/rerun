//! CPU rule selection on every topology fixture (`docs/03-cpu-topology.md`, ADR 0022):
//! a snapshot of every fixture x rule x bitness (`tests/fixtures/cpu/select.golden`), the
//! hand-checked cases of docs/03, and the properties on every fixture.
//!
//! A changed selection fails `every_fixture_matches_the_golden_selection` and writes the new
//! snapshot to `target/cpu-select.golden`; check it line by line, then copy it over the
//! committed file.

#![expect(
    clippy::disallowed_methods,
    reason = "reads repository fixtures (tests/fixtures/cpu), writes only below target/"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use rerun_proto::cpu::CpuTopology;
use rerun_proto::cpu::rule::{
    Bitness, CpuRule, Mode, Prefer, PreferL3, SelectError, X86_INDEX_LIMIT, select,
};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cpu")
}

/// Every parsed fixture (`*.json` without `.raw.json`), sorted by name, without `.json`.
fn fixtures() -> Vec<(String, CpuTopology)> {
    let mut out: Vec<(String, CpuTopology)> = fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| !p.to_string_lossy().ends_with(".raw.json"))
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            let t: CpuTopology = serde_json::from_str(&fs::read_to_string(&p).unwrap())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            (name, t)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn base() -> CpuRule {
    CpuRule {
        max_threads: None,
        prefer: Prefer::Any,
        single_l3: false,
        prefer_l3: None,
        smt: true,
        mode: Mode::Hard,
    }
}

/// The rule table of the snapshot.
fn rules() -> Vec<(&'static str, CpuRule)> {
    let b = base();
    vec![
        ("all", b),
        (
            "perf",
            CpuRule {
                prefer: Prefer::Performance,
                ..b
            },
        ),
        (
            "single_l3",
            CpuRule {
                single_l3: true,
                ..b
            },
        ),
        (
            "largest_l3",
            CpuRule {
                prefer_l3: Some(PreferL3::Largest),
                ..b
            },
        ),
        ("smt_off", CpuRule { smt: false, ..b }),
        (
            "perf_largest_l3_smt_off",
            CpuRule {
                prefer: Prefer::Performance,
                prefer_l3: Some(PreferL3::Largest),
                smt: false,
                ..b
            },
        ),
        (
            "max8_single_l3",
            CpuRule {
                max_threads: Some(8),
                single_l3: true,
                ..b
            },
        ),
        (
            "max8_single_l3_smt_off",
            CpuRule {
                max_threads: Some(8),
                single_l3: true,
                smt: false,
                ..b
            },
        ),
        (
            "max4",
            CpuRule {
                max_threads: Some(4),
                ..b
            },
        ),
    ]
}

const BITNESS: [(Bitness, &str); 2] = [(Bitness::X86, "x86"), (Bitness::X64, "x64")];

fn snapshot() -> String {
    let mut out = String::from(
        "# CPU rule selection per fixture, rule and bitness (crates/rerun-core/tests/cpu_select.rs).\n\
         # fixture rule bitness: group mask threads/of, or the step that emptied the candidates\n",
    );
    for (name, t) in fixtures() {
        for (rname, r) in rules() {
            for (b, bname) in BITNESS {
                let result = match select(&t, &r, b) {
                    Ok(s) => format!(
                        "group={} mask=0x{:016x} threads={}/{}",
                        s.group, s.mask, s.threads, s.of
                    ),
                    Err(SelectError::Empty { after }) => format!("empty after {}", after.name()),
                    Err(e) => panic!("{name}: {e}"),
                };
                writeln!(out, "{name} {rname} {bname}: {result}").unwrap();
            }
        }
    }
    out
}

#[test]
fn every_fixture_matches_the_golden_selection() {
    let actual = snapshot();
    let golden = fs::read_to_string(dir().join("select.golden")).unwrap_or_default();
    if actual != golden {
        let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/cpu-select.golden");
        fs::write(&out, &actual).unwrap();
        panic!(
            "the selection changed; the new snapshot is in {}: check it, then copy it to \
             tests/fixtures/cpu/select.golden",
            out.display()
        );
    }
}

fn topology(name: &str) -> CpuTopology {
    fixtures()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no fixture {name}"))
        .1
}

fn rule(name: &str) -> CpuRule {
    rules().into_iter().find(|(n, _)| *n == name).unwrap().1
}

/// The cases docs/03 and ADR 0022 name, checked by hand (independent of the snapshot).
#[test]
fn the_documented_cases() {
    let even = |n: u8| (0..n).step_by(2).fold(0u64, |m, i| m | 1 << i);
    for (fixture, r, b, group, mask) in [
        // B5: 8 cores x 1 thread on CCD 0, with and without SMT.
        ("ryzen9-5950x", "max8_single_l3", Bitness::X64, 0, even(16)),
        (
            "ryzen9-5950x",
            "max8_single_l3_smt_off",
            Bitness::X64,
            0,
            even(16),
        ),
        ("ryzen9-5950x", "single_l3", Bitness::X64, 0, 0xFFFF),
        // V-Cache CCD (CCD 0 on the 7950X3D); the other CCD has equal count, smaller cache.
        ("ryzen9-7950x3d", "largest_l3", Bitness::X64, 0, 0xFFFF),
        ("ryzen9-7950x3d", "single_l3", Bitness::X64, 0, 0xFFFF),
        // Equal V-Cache on both CCDs: the lowest LLC, never both.
        ("ryzen9-9950x3d2", "largest_l3", Bitness::X64, 0, 0xFFFF),
        // Zen 2: one CCX of 4 cores, not the CCD.
        ("ryzen7-3700x", "single_l3", Bitness::X64, 0, 0xFF),
        // Zen 5 cluster over Zen 5c (larger L3, fewer candidates).
        ("ryzen-ai-9-hx370", "largest_l3", Bitness::X64, 0, 0xFF),
        (
            "ryzen-ai-9-hx370",
            "single_l3",
            Bitness::X64,
            0,
            0xFFFF << 8,
        ),
        // P-cores; E-cores share the L3.
        ("i9-14900k", "perf", Bitness::X64, 0, 0xFFFF),
        ("core-ultra-9-285k", "perf", Bitness::X64, 0, 0xFF),
        // LP E-cores (own L2 as last level) never, even with `prefer: any`.
        ("core-ultra-7-155h", "all", Bitness::X64, 0, 0xF_FFFF),
        ("core-ultra-7-258v", "all", Bitness::X64, 0, 0xF),
        ("core-ultra-x9-388h", "all", Bitness::X64, 0, 0xFFF),
        ("core-ultra-x9-388h", "perf", Bitness::X64, 0, 0xF),
        // Two compute tiles: one tile, never both; LP E-cores never.
        ("nova-lake-2tile", "single_l3", Bitness::X64, 0, 0xFF_FFFF),
        ("nova-lake-2tile", "all", Bitness::X64, 0, 0xFFFF_FFFF_FFFF),
        // 12 cores per CCD are read, not assumed.
        ("zen6-12c", "single_l3", Bitness::X64, 0, 0xFF_FFFF),
        // Two groups of 64: group 0; a 32-bit game gets indices 0..32 (CCD 0 and 1).
        ("threadripper-7980x", "all", Bitness::X64, 0, u64::MAX),
        ("threadripper-7980x", "all", Bitness::X86, 0, 0xFFFF_FFFF),
        ("threadripper-7980x", "single_l3", Bitness::X86, 0, 0xFFFF),
        ("i5-6600", "smt_off", Bitness::X86, 0, 0xF),
    ] {
        let s = select(&topology(fixture), &rule(r), b).unwrap();
        assert_eq!((s.group, s.mask), (group, mask), "{fixture} {r} {b:?}");
    }
}

/// The properties of docs/03 on every fixture and rule, both bitnesses.
#[test]
fn every_fixture_keeps_the_properties() {
    let fixtures = fixtures();
    assert!(fixtures.len() >= 14, "only {} fixtures", fixtures.len());
    for (name, t) in &fixtures {
        for (rname, r) in rules() {
            for (b, _) in BITNESS {
                let s = select(t, &r, b).unwrap_or_else(|e| panic!("{name} {rname}: {e}"));
                let chosen: Vec<_> = t
                    .cpus
                    .iter()
                    .filter(|c| c.group == s.group && s.mask & (1 << c.index) != 0)
                    .collect();
                assert_eq!(chosen.len(), usize::from(s.threads), "{name} {rname}");
                assert_eq!(s.cpu_set_ids.len(), chosen.len());
                let top = t
                    .cpus
                    .iter()
                    .filter(|c| c.group == s.group)
                    .map(|c| t.llcs[usize::try_from(c.llc).unwrap()].level)
                    .max()
                    .unwrap();
                for c in &chosen {
                    assert_eq!(t.llcs[usize::try_from(c.llc).unwrap()].level, top, "{name}");
                    if b == Bitness::X86 {
                        assert!(c.index < X86_INDEX_LIMIT, "{name} {rname}");
                    }
                }
                let llcs: BTreeSet<u32> = chosen.iter().map(|c| c.llc).collect();
                if r.single_l3 || r.prefer_l3.is_some() {
                    assert_eq!(llcs.len(), 1, "{name} {rname}: spread across LLCs");
                }
                if let Some(max) = r.max_threads {
                    assert!(s.threads <= max);
                }
                if !r.smt {
                    let cores: BTreeSet<u32> = chosen.iter().map(|c| c.core).collect();
                    assert_eq!(cores.len(), chosen.len(), "{name} {rname}");
                }
            }
        }
    }
}
