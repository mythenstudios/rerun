//! Tests of the GPU architecture table. Every device ID here except the developer machine's
//! `0x1002`/`0x7550` is synthetic (ADR 0015): test tables never become shipped data.

use super::*;

const AMD: u32 = VENDOR_AMD;
const NVIDIA: u32 = VENDOR_NVIDIA;
const INTEL: u32 = VENDOR_INTEL;

fn id(s: &str) -> ArchId {
    ArchId::new(s).unwrap()
}

fn decl(s: &str, vendor: u32) -> ArchDecl {
    ArchDecl { id: id(s), vendor }
}

/// A synthetic entry; `ranges` as `(from, to)`.
fn entry(vendor: u32, arch: &str, ids: &[u32], ranges: &[(u32, u32)]) -> ArchEntry {
    ArchEntry {
        vendor,
        arch: id(arch),
        integrated: false,
        vulkan: Some(VkVersion { minor: 3 }),
        dx9: Dx9Path::Native,
        device_ids: ids.to_vec(),
        device_ranges: ranges
            .iter()
            .map(|&(from, to)| DeviceRange { from, to })
            .collect(),
        source: "synthetic test entry".to_owned(),
    }
}

/// Three synthetic architectures, one per vendor.
fn archs() -> Vec<ArchDecl> {
    vec![decl("aa", AMD), decl("nn", NVIDIA), decl("ii", INTEL)]
}

fn err(archs: Vec<ArchDecl>, entries: Vec<ArchEntry>) -> TableError {
    GpuArchTable::new(archs, entries).unwrap_err()
}

fn at_entry(i: usize, kind: TableErrorKind) -> TableError {
    TableError {
        at: TablePos::Entry(i),
        kind,
    }
}

// ---------- Built-in table ----------

#[test]
fn builtin_maps_the_developer_machine() {
    let t = GpuArchTable::builtin().unwrap();
    assert!(
        std::ptr::eq(t, GpuArchTable::builtin().unwrap()),
        "built once"
    );
    let e = t.lookup(0x1002, 0x7550).unwrap();
    assert_eq!(e.arch.as_str(), "rdna4");
    assert!(!e.integrated);
    assert_eq!(e.vulkan, Some(VkVersion { minor: 4 }));
    assert_eq!(e.vulkan.unwrap().to_string(), "1.4");
    assert_eq!(e.dx9, Dx9Path::Native);
    assert_eq!(e.source, "developer machine dump, 2026-11-05 (ADR 0008)");
    assert_eq!(t.entries().len(), 1);
    // Neighbours, another vendor and the Basic Render Driver are unknown.
    assert_eq!(t.lookup(0x1002, 0x754F), None);
    assert_eq!(t.lookup(0x1002, 0x7551), None);
    assert_eq!(t.lookup(0x10DE, 0x7550), None);
    assert_eq!(t.lookup(0x1414, 0x8c), None);
    // Every identifier of 03b is declared with its vendor; `rdna3_5` among them.
    assert_eq!(t.archs().len(), 31);
    assert!(t.declares(&id("rdna3_5")));
    assert!(t.declares(&id("xe_hpg")));
    assert!(!t.declares(&id("rdna6")));
    assert_eq!(t.arch(&id("kepler")).map(|a| a.vendor), Some(NVIDIA));
    assert_eq!(t.arch(&id("xe2")).map(|a| a.vendor), Some(INTEL));
}

#[test]
fn a_broken_mirror_is_an_error_at_its_position() {
    let bad_arch = from_mirror(&[("aa", AMD), ("Bad", AMD)], &[]).unwrap_err();
    assert_eq!(
        bad_arch,
        TableError {
            at: TablePos::Arch(1),
            kind: TableErrorKind::BadArchId(ArchIdError::FirstNotLetter),
        }
    );
    let bad_entry = from_mirror(
        &[("aa", AMD)],
        &[MirrorEntry {
            vendor: AMD,
            arch: "unknown",
            integrated: true,
            vulkan: None,
            dx9: Dx9Path::D3d9On12,
            device_ids: &[1],
            device_ranges: &[],
            source: "synthetic",
        }],
    )
    .unwrap_err();
    assert_eq!(
        bad_entry,
        at_entry(0, TableErrorKind::BadArchId(ArchIdError::Reserved))
    );
    // A mirror that parses still goes through `new`.
    let overlap = from_mirror(
        &[("aa", AMD)],
        &[
            MirrorEntry {
                vendor: AMD,
                arch: "aa",
                integrated: true,
                vulkan: None,
                dx9: Dx9Path::D3d9On12,
                device_ids: &[5],
                device_ranges: &[],
                source: "synthetic",
            },
            MirrorEntry {
                vendor: AMD,
                arch: "aa",
                integrated: true,
                vulkan: None,
                dx9: Dx9Path::D3d9On12,
                device_ids: &[],
                device_ranges: &[(1, 9)],
                source: "synthetic",
            },
        ],
    )
    .unwrap_err();
    assert_eq!(overlap, at_entry(1, TableErrorKind::Overlap { other: 0 }));
}

// ---------- ArchId ----------

#[test]
fn arch_id_rule() {
    for ok in [
        "a",
        "rdna4",
        "rdna3_5",
        "xe_hpg",
        "gen11",
        "a_",
        "unknown_",
        "unknowns",
        "a234567890123456789012345678901_",
    ] {
        assert_eq!(ArchId::new(ok).map(|a| a.to_string()), Ok(ok.to_owned()));
    }
    for (bad, e) in [
        ("", ArchIdError::Empty),
        ("unknown", ArchIdError::Reserved),
        ("Rdna4", ArchIdError::FirstNotLetter),
        ("4rdna", ArchIdError::FirstNotLetter),
        ("_rdna", ArchIdError::FirstNotLetter),
        ("ärdna", ArchIdError::FirstNotLetter),
        ("rDna", ArchIdError::BadChar),
        ("rdna-4", ArchIdError::BadChar),
        ("rdna 4", ArchIdError::BadChar),
        ("rdna4 ", ArchIdError::BadChar),
        ("rdna4\n", ArchIdError::BadChar),
        ("rdnä", ArchIdError::BadChar),
        ("rdna\u{202E}", ArchIdError::BadChar),
        ("a2345678901234567890123456789012x", ArchIdError::TooLong),
    ] {
        assert_eq!(ArchId::new(bad), Err(e), "{bad:?}");
    }
}

#[test]
fn arch_id_errors_never_show_the_identifier() {
    for bad in [
        "SECRETX",
        "secret-x",
        "secret_secret_secret_secret_secret",
        "unknown",
    ] {
        let msg = ArchId::new(bad).unwrap_err().to_string();
        assert!(!msg.contains("ecret"), "{msg}");
    }
}

// ---------- Validation rules ----------

#[test]
fn a_valid_table_is_accepted() {
    let t = GpuArchTable::new(
        archs(),
        vec![
            entry(
                AMD,
                "aa",
                &[0x0000, 0xFFFF],
                &[(0x1000, 0x1000), (0x1001, 0x10FF)],
            ),
            // The same device IDs at another vendor are another device.
            entry(NVIDIA, "nn", &[0x0000, 0x1000], &[(0x2000, 0x2FFF)]),
            entry(INTEL, "ii", &[], &[(0, MAX_DEVICE_ID)]),
        ],
    )
    .unwrap();
    assert_eq!(t.archs().len(), 3);
    assert_eq!(t.entries().len(), 3);
    // An empty table is valid as well.
    assert!(GpuArchTable::new(Vec::new(), Vec::new()).is_ok());
}

#[test]
fn table_size_limits() {
    let many_archs = |n: usize| {
        (0..n)
            .map(|i| decl(&format!("a{i}"), AMD))
            .collect::<Vec<_>>()
    };
    assert!(GpuArchTable::new(many_archs(MAX_ARCHS), Vec::new()).is_ok());
    assert_eq!(
        err(many_archs(MAX_ARCHS + 1), Vec::new()),
        TableError {
            at: TablePos::Table,
            kind: TableErrorKind::TooManyArchs
        }
    );

    let many_entries = |n: u32| {
        (0..n)
            .map(|d| entry(AMD, "aa", &[d], &[]))
            .collect::<Vec<_>>()
    };
    assert!(GpuArchTable::new(archs(), many_entries(4096)).is_ok());
    // Checked before any entry: the 4,097 entries are not looked at.
    let mut over = many_entries(4097);
    over[0].vendor = 0x1414;
    assert_eq!(
        err(archs(), over),
        TableError {
            at: TablePos::Table,
            kind: TableErrorKind::TooManyEntries
        }
    );
}

#[test]
fn items_per_entry_limits() {
    let ids: Vec<u32> = (0..512).collect();
    let ranges: Vec<(u32, u32)> = (0..512).map(|i| (1000 + 2 * i, 1000 + 2 * i)).collect();
    assert!(GpuArchTable::new(archs(), vec![entry(AMD, "aa", &ids, &ranges)]).is_ok());
    let more: Vec<(u32, u32)> = (0..513).map(|i| (1000 + 2 * i, 1000 + 2 * i)).collect();
    assert_eq!(
        err(archs(), vec![entry(AMD, "aa", &ids, &more)]),
        at_entry(0, TableErrorKind::TooManyDevices)
    );
    let all_ids: Vec<u32> = (0..1025).collect();
    assert_eq!(
        err(archs(), vec![entry(AMD, "aa", &all_ids, &[])]),
        at_entry(0, TableErrorKind::TooManyDevices)
    );
    assert_eq!(
        err(archs(), vec![entry(AMD, "aa", &[], &[])]),
        at_entry(0, TableErrorKind::NoDevices)
    );
}

#[test]
fn device_bounds() {
    assert!(GpuArchTable::new(archs(), vec![entry(AMD, "aa", &[0, 0xFFFF], &[])]).is_ok());
    for (ids, ranges) in [
        (&[0x1_0000][..], &[][..]),
        (&[u32::MAX][..], &[][..]),
        (&[][..], &[(0xFF00, 0x1_0000)][..]),
        (&[][..], &[(0x1_0000, 0x1_0001)][..]),
        (&[][..], &[(0, u32::MAX)][..]),
    ] {
        assert_eq!(
            err(archs(), vec![entry(AMD, "aa", ids, ranges)]),
            at_entry(0, TableErrorKind::DeviceOutOfRange),
            "{ids:?} {ranges:?}"
        );
    }
    // A range of one device is fine, a reversed one is not.
    assert!(GpuArchTable::new(archs(), vec![entry(AMD, "aa", &[], &[(7, 7)])]).is_ok());
    assert_eq!(
        err(archs(), vec![entry(AMD, "aa", &[], &[(8, 7)])]),
        at_entry(0, TableErrorKind::RangeReversed)
    );
}

#[test]
fn vendor_whitelist() {
    for vendor in [0x1414, 0, 0x5143, 0x1002_0000, u32::MAX] {
        assert_eq!(
            err(vec![decl("aa", AMD), decl("xx", vendor)], Vec::new()),
            TableError {
                at: TablePos::Arch(1),
                kind: TableErrorKind::BadVendor
            }
        );
        assert_eq!(
            err(archs(), vec![entry(vendor, "aa", &[1], &[])]),
            at_entry(0, TableErrorKind::BadVendor)
        );
    }
}

#[test]
fn entries_name_a_declared_arch_of_their_vendor() {
    assert_eq!(
        err(
            archs(),
            vec![entry(AMD, "aa", &[1], &[]), entry(AMD, "zz", &[2], &[])]
        ),
        at_entry(1, TableErrorKind::UndeclaredArch)
    );
    assert_eq!(
        err(archs(), vec![entry(NVIDIA, "aa", &[1], &[])]),
        at_entry(0, TableErrorKind::ArchVendorMismatch { arch: 0 })
    );
    assert_eq!(
        err(archs(), vec![entry(AMD, "ii", &[1], &[])]),
        at_entry(0, TableErrorKind::ArchVendorMismatch { arch: 2 })
    );
}

#[test]
fn arch_ids_are_unique() {
    assert_eq!(
        err(
            vec![decl("aa", AMD), decl("nn", NVIDIA), decl("aa", AMD)],
            Vec::new()
        ),
        TableError {
            at: TablePos::Arch(2),
            kind: TableErrorKind::DuplicateArch { first: 0 }
        }
    );
    // Also with another vendor.
    assert_eq!(
        err(vec![decl("aa", AMD), decl("aa", INTEL)], Vec::new()),
        TableError {
            at: TablePos::Arch(1),
            kind: TableErrorKind::DuplicateArch { first: 0 }
        }
    );
}

#[test]
fn source_rules() {
    let with_source = |s: &str| {
        let mut e = entry(AMD, "aa", &[1], &[]);
        s.clone_into(&mut e.source);
        GpuArchTable::new(archs(), vec![e]).map(|_| ())
    };
    assert_eq!(with_source("x"), Ok(()));
    assert_eq!(with_source(&"ä".repeat(MAX_SOURCE_CHARS)), Ok(()));
    // Not a control or bidi character: accepted, like the schema pattern.
    assert_eq!(with_source("zero\u{200B}width"), Ok(()));
    for (s, kind) in [
        ("", TableErrorKind::SourceLength),
        (
            &"a".repeat(MAX_SOURCE_CHARS + 1),
            TableErrorKind::SourceLength,
        ),
        ("line\nbreak", TableErrorKind::SourceControl),
        ("tab\there", TableErrorKind::SourceControl),
        ("nul\0", TableErrorKind::SourceControl),
        ("del\u{7F}", TableErrorKind::SourceControl),
        ("c1\u{85}", TableErrorKind::SourceControl),
        ("rlo\u{202E}", TableErrorKind::SourceBidi),
        ("alm\u{061C}", TableErrorKind::SourceBidi),
        ("lri\u{2066}", TableErrorKind::SourceBidi),
        ("lrm\u{200E}", TableErrorKind::SourceBidi),
    ] {
        assert_eq!(with_source(s).unwrap_err(), at_entry(0, kind), "{s:?}");
    }
}

// ---------- Overlap ----------

#[test]
fn any_double_coverage_is_an_error() {
    let two = |a: ArchEntry, b: ArchEntry| err(archs(), vec![a, b]);
    let overlap = |i, other| at_entry(i, TableErrorKind::Overlap { other });
    // The same ID twice, also with the same architecture.
    assert_eq!(
        two(entry(AMD, "aa", &[5], &[]), entry(AMD, "aa", &[5], &[])),
        overlap(1, 0)
    );
    // An ID inside a range, either order.
    assert_eq!(
        two(
            entry(AMD, "aa", &[5], &[]),
            entry(AMD, "aa", &[], &[(1, 9)])
        ),
        overlap(1, 0)
    );
    assert_eq!(
        two(
            entry(AMD, "aa", &[], &[(1, 9)]),
            entry(AMD, "aa", &[9], &[])
        ),
        overlap(1, 0)
    );
    // Ranges touching at one bound, and one range inside another.
    assert_eq!(
        two(
            entry(AMD, "aa", &[], &[(1, 9)]),
            entry(AMD, "aa", &[], &[(9, 20)])
        ),
        overlap(1, 0)
    );
    assert_eq!(
        two(
            entry(AMD, "aa", &[], &[(0, 0xFFFF)]),
            entry(AMD, "aa", &[], &[(0x7000, 0x7001)])
        ),
        overlap(1, 0)
    );
    // Within one entry: an ID twice, an ID in its own range, two of its ranges.
    assert_eq!(
        err(archs(), vec![entry(AMD, "aa", &[3, 3], &[])]),
        overlap(0, 0)
    );
    assert_eq!(
        err(archs(), vec![entry(AMD, "aa", &[3], &[(0, 4)])]),
        overlap(0, 0)
    );
    assert_eq!(
        err(archs(), vec![entry(AMD, "aa", &[], &[(0, 4), (4, 4)])]),
        overlap(0, 0)
    );
    // Reported at the later entry, naming the earlier, however they sort.
    assert_eq!(
        err(
            archs(),
            vec![
                entry(AMD, "aa", &[0x50], &[]),
                entry(AMD, "aa", &[0x10], &[]),
                entry(AMD, "aa", &[], &[(0x40, 0x60)]),
            ]
        ),
        overlap(2, 0)
    );
    // A long range that overlaps an interval far behind it in sort order.
    assert_eq!(
        err(
            archs(),
            vec![
                entry(AMD, "aa", &[], &[(0, 0x1000)]),
                entry(AMD, "aa", &[0x10, 0x20, 0x30], &[]),
            ]
        ),
        overlap(1, 0)
    );
}

#[test]
fn adjacent_ranges_and_other_vendors_do_not_overlap() {
    assert!(
        GpuArchTable::new(
            archs(),
            vec![
                entry(AMD, "aa", &[], &[(0, 9)]),
                entry(AMD, "aa", &[10], &[(11, 0xFFFF)]),
                entry(NVIDIA, "nn", &[], &[(0, 0xFFFF)]),
                entry(INTEL, "ii", &[5], &[]),
            ]
        )
        .is_ok()
    );
}

/// Every device of every vendor, as 3 × 64 entries of 1,024 IDs (the item limit): valid, and
/// every lookup hits its entry. Overlap detection sorts these intervals, it never expands.
#[test]
fn a_full_table_maps_every_device() {
    let mut entries = Vec::new();
    for (vendor, arch) in [(AMD, "aa"), (NVIDIA, "nn"), (INTEL, "ii")] {
        for block in 0..64u32 {
            let ids: Vec<u32> = (block * 1024..(block + 1) * 1024).rev().collect();
            entries.push(entry(vendor, arch, &ids, &[]));
        }
    }
    let t = GpuArchTable::new(archs(), entries).unwrap();
    for (vi, vendor) in [AMD, NVIDIA, INTEL].into_iter().enumerate() {
        for device in (0..=MAX_DEVICE_ID).step_by(97).chain([0, MAX_DEVICE_ID]) {
            let e = t.lookup(vendor, device).unwrap();
            let block = usize::try_from(device / 1024).unwrap();
            assert!(std::ptr::eq(e, &t.entries()[vi * 64 + block]));
        }
        assert_eq!(t.lookup(vendor, MAX_DEVICE_ID + 1), None);
    }
}

// ---------- Lookup ----------

#[test]
fn lookup_respects_bounds_and_vendor() {
    let t = GpuArchTable::new(
        archs(),
        vec![
            entry(AMD, "aa", &[0x20], &[(0x100, 0x1FF)]),
            entry(NVIDIA, "nn", &[0x150], &[]),
        ],
    )
    .unwrap();
    let arch = |v, d| t.lookup(v, d).map(|e| e.arch.as_str());
    assert_eq!(arch(AMD, 0x20), Some("aa"));
    assert_eq!(arch(AMD, 0x1F), None);
    assert_eq!(arch(AMD, 0x21), None);
    assert_eq!(arch(AMD, 0xFF), None);
    assert_eq!(arch(AMD, 0x100), Some("aa"));
    assert_eq!(arch(AMD, 0x150), Some("aa"));
    assert_eq!(arch(AMD, 0x1FF), Some("aa"));
    assert_eq!(arch(AMD, 0x200), None);
    assert_eq!(arch(NVIDIA, 0x150), Some("nn"));
    assert_eq!(arch(NVIDIA, 0x100), None);
    assert_eq!(arch(INTEL, 0x150), None);
    assert_eq!(arch(0, 0), None);
    assert_eq!(arch(u32::MAX, u32::MAX), None);
    assert_eq!(arch(AMD, 0x1_0020), None);
    assert_eq!(arch(AMD, u32::MAX), None);
}

// ---------- Errors ----------

#[test]
fn table_errors_name_position_and_kind_never_content() {
    let marked = |source: &str| {
        let mut e = entry(AMD, "secretarch", &[1], &[]);
        source.clone_into(&mut e.source);
        e
    };
    let secret_archs = vec![decl("secretarch", AMD), decl("secretother", NVIDIA)];
    let cases = [
        err(secret_archs.clone(), vec![marked("SECRET\n")]),
        err(secret_archs.clone(), vec![marked("SECRET\u{202E}")]),
        err(secret_archs.clone(), vec![marked(&"SECRET".repeat(40))]),
        err(
            secret_archs.clone(),
            vec![marked("SECRET"), marked("SECRET")],
        ),
        err(
            vec![decl("secretarch", AMD), decl("secretarch", AMD)],
            Vec::new(),
        ),
        err(archs(), vec![marked("SECRET")]),
        err(secret_archs.clone(), {
            let mut e = marked("SECRET");
            e.vendor = NVIDIA;
            vec![e]
        }),
        err(secret_archs, {
            let mut e = marked("SECRET");
            e.device_ids = vec![0x1_2345];
            vec![e]
        }),
    ];
    let expected = [
        "gpu arch table: entries[0]: source contains a control character",
        "gpu arch table: entries[0]: source contains a bidi control character",
        "gpu arch table: entries[0]: source is empty or longer than 200 characters",
        "gpu arch table: entries[1]: a device is also covered by entries[0]",
        "gpu arch table: archs[1]: architecture already declared at archs[0]",
        "gpu arch table: entries[0]: architecture is not declared",
        "gpu arch table: entries[0]: vendor differs from the declaration at archs[0]",
        "gpu arch table: entries[0]: device ID above 0xffff",
    ];
    for (e, want) in cases.iter().zip(expected) {
        let msg = e.to_string();
        assert_eq!(msg, want);
        assert!(!msg.to_lowercase().contains("secret"), "{msg}");
        assert!(!msg.contains("12345"), "{msg}");
    }
}

// ---------- Model and mutation ----------

/// Deterministic xorshift (no `proptest`, docs/09-testing.md).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u32) -> u32 {
        u32::try_from(self.next() % u64::from(n.max(1))).unwrap()
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let len = u32::try_from(items.len()).unwrap();
        &items[usize::try_from(self.below(len)).unwrap()]
    }
}

/// Random tables that break no rule except perhaps the overlap rule, over a small device range:
/// `new` succeeds exactly when a brute-force count finds no device covered twice, and then
/// every lookup equals the brute-force answer.
#[test]
fn overlap_detection_matches_a_brute_force_model() {
    const DOMAIN: u32 = 48;
    let vendors = [(AMD, "aa"), (NVIDIA, "nn")];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut accepted, mut refused) = (0, 0);
    for _ in 0..3000 {
        let entries: Vec<ArchEntry> = (0..=rng.below(4))
            .map(|_| {
                let &(vendor, arch) = rng.pick(&vendors);
                let ids: Vec<u32> = (0..rng.below(3)).map(|_| rng.below(DOMAIN)).collect();
                let mut ranges = Vec::new();
                for _ in 0..rng.below(3) {
                    let from = rng.below(DOMAIN);
                    ranges.push((from, from + rng.below(6)));
                }
                if ids.is_empty() && ranges.is_empty() {
                    entry(vendor, arch, &[rng.below(DOMAIN)], &[])
                } else {
                    entry(vendor, arch, &ids, &ranges)
                }
            })
            .collect();
        // Brute force over the small domain.
        let mut cover: Vec<Vec<Vec<usize>>> = vec![vec![Vec::new(); 64]; 2];
        for (i, e) in entries.iter().enumerate() {
            let v = usize::from(e.vendor == NVIDIA);
            let devices = e
                .device_ids
                .iter()
                .map(|&d| (d, d))
                .chain(e.device_ranges.iter().map(|r| (r.from, r.to)))
                .flat_map(|(a, b)| a..=b);
            for d in devices {
                cover[v][usize::try_from(d).unwrap()].push(i);
            }
        }
        let double = cover.iter().flatten().any(|c| c.len() > 1);
        match GpuArchTable::new(archs(), entries) {
            Ok(t) => {
                accepted += 1;
                assert!(!double, "an overlap was accepted");
                for (v, &(vendor, _)) in vendors.iter().enumerate() {
                    for d in 0..64u32 {
                        let want = cover[v][usize::try_from(d).unwrap()]
                            .first()
                            .map(|&i| &t.entries()[i]);
                        assert_eq!(t.lookup(vendor, d), want, "vendor {vendor:#x} device {d}");
                    }
                }
            }
            Err(e) => {
                refused += 1;
                assert!(double, "refused without an overlap: {e}");
                let TableErrorKind::Overlap { other } = e.kind else {
                    panic!("not an overlap: {e}");
                };
                let TablePos::Entry(at) = e.at else {
                    panic!("not at an entry: {e}");
                };
                assert!(other <= at);
                // The two named entries really share a device.
                assert!(
                    cover.iter().flatten().any(|c| c.contains(&at)
                        && c.contains(&other)
                        && (at != other || c.iter().filter(|&&i| i == at).count() > 1)),
                    "entries {other} and {at} share no device"
                );
            }
        }
    }
    assert!(accepted > 300 && refused > 300, "{accepted} / {refused}");
}

/// Wild input never panics, and an accepted table keeps its promises.
#[test]
fn mutated_tables_never_panic() {
    let ids = ["aa", "nn", "ii", "zz", "a_1"];
    let vendors = [AMD, NVIDIA, INTEL, 0x1414, 0, u32::MAX];
    let sources = ["ok", "", "a\nb", "x\u{202E}", "fine source"];
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let (mut ok, mut failed) = (0, 0);
    for _ in 0..5000 {
        let archs: Vec<ArchDecl> = (0..rng.below(5))
            .map(|_| decl(rng.pick(&ids), *rng.pick(&vendors)))
            .collect();
        let wild = |rng: &mut Rng| match rng.below(4) {
            0 => u32::try_from(rng.next() >> 32).unwrap(),
            1 => MAX_DEVICE_ID + rng.below(3),
            _ => rng.below(0x40),
        };
        let entries: Vec<ArchEntry> = (0..rng.below(5))
            .map(|_| {
                let mut e = entry(AMD, "aa", &[], &[]);
                e.vendor = *rng.pick(&vendors);
                e.arch = id(rng.pick(&ids));
                e.device_ids = (0..rng.below(4)).map(|_| wild(&mut rng)).collect();
                e.device_ranges = (0..rng.below(3))
                    .map(|_| DeviceRange {
                        from: wild(&mut rng),
                        to: wild(&mut rng),
                    })
                    .collect();
                (*rng.pick(&sources)).clone_into(&mut e.source);
                e
            })
            .collect();
        match GpuArchTable::new(archs, entries) {
            Ok(t) => {
                ok += 1;
                for (i, e) in t.entries().iter().enumerate() {
                    assert!(t.declares(&e.arch));
                    for &d in &e.device_ids {
                        assert!(std::ptr::eq(
                            t.lookup(e.vendor, d).unwrap(),
                            &t.entries()[i]
                        ));
                    }
                    for r in &e.device_ranges {
                        for d in [r.from, r.to] {
                            assert!(std::ptr::eq(
                                t.lookup(e.vendor, d).unwrap(),
                                &t.entries()[i]
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                failed += 1;
                assert!(!e.to_string().is_empty());
            }
        }
    }
    assert!(ok > 50 && failed > 1000, "{ok} / {failed}");
}
