//! CPU fixtures (ADR 0010, `tests/fixtures/cpu/README.md`): every raw dump parses to its
//! expected JSON, every fixture validates, and mutated dumps never panic the parser.

#![expect(
    clippy::disallowed_methods,
    reason = "reads repository fixtures (tests/fixtures/cpu), never game folders"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::fs;
use std::path::{Path, PathBuf};

use rerun_proto::cpu::CpuTopology;
use serde_json::Value;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cpu")
}

/// All `*.json` fixtures, sorted, as `(file name, content)`.
fn fixtures() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, fs::read_to_string(&p).unwrap())
        })
        .collect();
    out.sort();
    out
}

/// A raw dump: the bytes of both calls.
struct Raw {
    cpu_sets: Vec<u8>,
    processor_info: Vec<u8>,
}

fn hex(name: &str, field: &str, lines: &Value) -> Vec<u8> {
    let lines = lines
        .as_array()
        .unwrap_or_else(|| panic!("{name}: {field} is not an array"));
    let mut out = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        let s = line
            .as_str()
            .unwrap_or_else(|| panic!("{name}: {field}[{n}] is not a string"));
        let last = n + 1 == lines.len();
        assert!(
            s.len() == 64 || (last && !s.is_empty() && s.len() < 64 && s.len() % 2 == 0),
            "{name}: {field}[{n}] must be 32 bytes (the last line 1 to 32)"
        );
        for k in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[k..k + 2], 16)
                .unwrap_or_else(|e| panic!("{name}: {field}[{n}]: {e}"));
            out.push(byte);
        }
        assert_eq!(s, s.to_ascii_lowercase(), "{name}: {field}[{n}] lower case");
    }
    out
}

fn raw(name: &str, json: &str) -> Raw {
    let v: Value = serde_json::from_str(json).unwrap_or_else(|e| panic!("{name}: {e}"));
    let obj = v.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["cpu_sets", "description", "format", "processor_info"],
        "{name}: fields"
    );
    assert_eq!(v["format"], 1, "{name}: format");
    let description = v["description"].as_str().unwrap_or_default();
    assert!(
        !description.is_empty() && !description.contains("TODO"),
        "{name}: description (CPU model, Windows build)"
    );
    Raw {
        cpu_sets: hex(name, "cpu_sets", &v["cpu_sets"]),
        processor_info: hex(name, "processor_info", &v["processor_info"]),
    }
}

fn raws() -> Vec<(String, Raw)> {
    fixtures()
        .into_iter()
        .filter(|(n, _)| n.ends_with(".raw.json"))
        .map(|(n, j)| {
            let r = raw(&n, &j);
            (n, r)
        })
        .collect()
}

#[test]
fn every_raw_dump_parses_to_its_expected_topology() {
    let raws = raws();
    assert!(!raws.is_empty(), "no raw dump in {}", dir().display());
    for (name, r) in raws {
        let parsed = CpuTopology::from_windows(&r.cpu_sets, &r.processor_info)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let expected_name = name.replace(".raw.json", ".json");
        let expected = fs::read_to_string(dir().join(&expected_name))
            .unwrap_or_else(|e| panic!("{expected_name}: {e}"));
        let expected: CpuTopology = serde_json::from_str(&expected).unwrap();
        assert_eq!(parsed, expected, "{name} → {expected_name}");
    }
}

#[test]
fn every_parsed_fixture_validates() {
    let mut n = 0;
    for (name, json) in fixtures() {
        if name.ends_with(".raw.json") {
            continue;
        }
        let t: CpuTopology = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{name}: {e}"));
        t.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
        n += 1;
    }
    assert!(n >= 2, "only {n} parsed fixtures");
}

#[test]
fn the_ryzen_9_5950x_dump_is_2_l3_by_8_cores_by_2_threads() {
    let r = raw(
        "ryzen9-5950x.raw.json",
        &fs::read_to_string(dir().join("ryzen9-5950x.raw.json")).unwrap(),
    );
    let t = CpuTopology::from_windows(&r.cpu_sets, &r.processor_info).unwrap();
    assert_eq!(t.logical_count(), 32);
    assert_eq!(t.core_count(), 16);
    assert_eq!(t.llc_count(), 2);
    assert!(t.llcs.iter().all(|l| l.level == 3 && l.size == 32 << 20));
    for c in &t.cpus {
        assert_eq!(c.group, 0);
        assert_eq!(c.efficiency_class, 0);
        assert_eq!(c.core, u32::from(c.index / 2));
        assert_eq!(c.llc, u32::from(c.index / 16));
    }
}

/// xorshift64*, so the loop is the same on every machine (no proptest dependency).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

#[test]
fn mutated_real_dumps_never_panic() {
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    for (name, r) in raws() {
        let mut parsed = 0;
        for _ in 0..5_000 {
            let mut s = r.cpu_sets.clone();
            let mut i = r.processor_info.clone();
            for _ in 0..=rng.below(3) {
                let buf = if rng.below(2) == 0 { &mut s } else { &mut i };
                if buf.is_empty() {
                    continue;
                }
                match rng.below(3) {
                    0 => {
                        let at = rng.below(buf.len());
                        buf[at] = rng.byte();
                    }
                    1 => {
                        let at = rng.below(buf.len());
                        buf[at] = u8::try_from(rng.below(4)).unwrap();
                    }
                    _ => {
                        let at = rng.below(buf.len() + 1);
                        buf.truncate(at);
                    }
                }
            }
            if let Ok(t) = CpuTopology::from_windows(&s, &i) {
                assert_eq!(t.validate(), Ok(()), "{name}");
                parsed += 1;
            }
        }
        assert!(parsed > 0, "{name}: no mutation parsed");
    }
}
