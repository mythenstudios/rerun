//! Extraction into the version folder (ADR 0025 part 2) against the fake: only the named files,
//! each with its pinned hash, nothing outside `packages\<id>\<version>`, and a refused archive
//! leaves no file at all.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::extract::{ExtractError, How, Unpacked, extract, extract_with, layout, source_path};

fn extract_limited(
    sys: &FakeSystem,
    app: &AppDir<'_>,
    p: &Package,
    limits: &Limits,
) -> Result<Vec<Unpacked>, ExtractError> {
    let mut done = Vec::new();
    extract_with(sys, app, p, limits, &mut done).map(|()| done)
}
use crate::catalog::model::{
    Arch, ArchList, Asset, Hex, Id, Package, PackageFile, PackageSource, Status, Tier,
};
use crate::path::RelPath;
use crate::pkg::archive::testfx::{TarEntry, ZipEntry, tar_gz, zip};
use crate::pkg::archive::{ArchiveError, Limits};
use crate::pkg::download::cache_name;
use crate::policy::root::{AppDir, Create};
use crate::sys::Dir;
use crate::sys::fake::{FakeSystem, Fault, Prim};
use crate::sys::fs::EntryKind;

pub(crate) const LAD: &str = r"C:\Users\Player\AppData\Local";
const CACHE: &str = r"C:\Users\Player\AppData\Local\Rerun\cache";
pub(crate) const REPO: &str = "https://github.com/owner/fix-pack";

pub(crate) fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

/// A package file entry.
pub(crate) fn file(from: &str, to: &str, data: &[u8]) -> PackageFile {
    PackageFile {
        from: rel(from),
        to: rel(to),
        sha256: Hex::new(sha(data)),
        config: false,
        arch: None,
        api: None,
    }
}

/// A package with one download `fix-pack-1.0.<ext>` of `archive`.
pub(crate) fn package(ext: &str, archive: &[u8], files: Vec<PackageFile>) -> Package {
    Package {
        format: 1,
        id: Id::parse("fix-pack").unwrap(),
        name: "Fix pack".into(),
        status: Status::Active,
        tier: Tier::Established,
        source: PackageSource {
            repo: Some(REPO.into()),
            page: None,
            release: Some(format!("{REPO}/releases/download/v1.0/fix-pack-1.0.{ext}")),
        },
        version: "1.0".into(),
        sha256: Some(Hex::new(sha(archive))),
        assets: None,
        license: "MIT".into(),
        arch: ArchList::List(vec![Arch::X86, Arch::X64]),
        apis: None,
        slots: vec![],
        slots_by_api: None,
        requires: vec![],
        requires_gpu: vec![],
        supports_exe_sha1: vec![],
        files,
        options: Default::default(),
    }
}

/// A package with one zip asset per architecture.
pub(crate) fn assets_package(x86: &[u8], x64: &[u8], files: Vec<PackageFile>) -> Package {
    let mut p = package("zip", b"", files);
    p.source.release = None;
    p.sha256 = None;
    p.assets = Some(vec![
        Asset {
            arch: Arch::X86,
            url: format!("{REPO}/releases/download/v1.0/fix-pack.zip"),
            sha256: Hex::new(sha(x86)),
        },
        Asset {
            arch: Arch::X64,
            url: format!("{REPO}/releases/download/v1.0/fix-pack_x64.zip"),
            sha256: Hex::new(sha(x64)),
        },
    ]);
    p
}

fn sys() -> FakeSystem {
    FakeSystem::builder().dir(LAD).build().unwrap()
}

fn app(sys: &FakeSystem) -> AppDir<'_> {
    AppDir::open(sys, Create::IfMissing).unwrap().unwrap()
}

/// Puts `archive` into the cache under its hash (as `download::fetch` would).
pub(crate) fn cache(sys: &FakeSystem, archive: &[u8]) {
    let p = format!(r"{CACHE}\{}", cache_name(&sha(archive)));
    let _ = sys.fake_fs().remove_abs(Path::new(&p));
    sys.fake_fs().put_file(Path::new(&p), archive).unwrap();
    sys.sync_all();
}

/// Every path below `dir`, folders with a trailing `\`, sorted.
fn tree(dir: &dyn Dir) -> Vec<String> {
    let mut out = Vec::new();
    let mut todo: Vec<Option<RelPath>> = vec![None];
    while let Some(p) = todo.pop() {
        for e in dir.read_dir(p.as_ref()).unwrap() {
            let here = match &p {
                None => RelPath::from_segment(&e.name).unwrap(),
                Some(p) => p.child(&e.name).unwrap(),
            };
            if e.meta.kind == EntryKind::Dir {
                out.push(format!(r"{}\", here.as_str()));
                todo.push(Some(here));
            } else {
                out.push(here.as_str().to_owned());
            }
        }
    }
    out.sort();
    out
}

/// Every path below Rerun's folder except the cache entries.
fn app_tree(sys: &FakeSystem) -> Vec<String> {
    let a = app(sys);
    tree(a.dir())
        .into_iter()
        .filter(|p| !p.starts_with(r"cache\") || p == r"cache\")
        .collect()
}

fn read(sys: &FakeSystem, rel_below_version: &str) -> Vec<u8> {
    let a = app(sys);
    a.dir()
        .read(&rel(&format!(r"packages\fix-pack\1.0\{rel_below_version}")))
        .unwrap()
}

fn hows(v: &[Unpacked]) -> Vec<(String, How)> {
    v.iter()
        .map(|u| (u.dest.as_str().to_owned(), u.how))
        .collect()
}

/// What an empty version folder looks like in Rerun's folder.
const EMPTY: &[&str] = &[
    r"cache\",
    r"packages\",
    r"packages\.lock",
    r"packages\fix-pack\",
    r"packages\fix-pack\1.0\",
];

fn with_empty(extra: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = EMPTY.iter().chain(extra).map(|s| (*s).to_owned()).collect();
    v.sort();
    v
}

#[test]
fn only_the_named_files_of_a_zip_are_extracted() {
    let z = zip(&[
        ZipEntry::dir("bin/"),
        ZipEntry::file("bin/d3d9.dll", b"the d3d9"),
        ZipEntry::stored("readme.txt", b"not asked for"),
        ZipEntry::file("bin/other.dll", b"not asked for"),
        ZipEntry::file("cfg/fix.ini", b"[fix]"),
    ]);
    let p = package(
        "zip",
        &z,
        vec![
            file("bin/d3d9.dll", "d3d9.dll", b"the d3d9"),
            file("cfg/fix.ini", "scripts/fix.ini", b"[fix]"),
        ],
    );
    let sys = sys();
    cache(&sys, &z);
    let got = extract(&sys, &app(&sys), &p).unwrap();
    assert_eq!(
        hows(&got),
        [
            (r"bin\d3d9.dll".to_owned(), How::Extracted),
            (r"cfg\fix.ini".to_owned(), How::Extracted)
        ]
    );
    assert_eq!(
        app_tree(&sys),
        with_empty(&[
            r"packages\fix-pack\1.0\bin\",
            r"packages\fix-pack\1.0\bin\d3d9.dll",
            r"packages\fix-pack\1.0\cfg\",
            r"packages\fix-pack\1.0\cfg\fix.ini",
        ])
    );
    assert_eq!(read(&sys, r"bin\d3d9.dll"), b"the d3d9");

    // Again: hashed on a guard, the archive not even needed.
    let a = app(&sys);
    let cache_dir = format!(r"{CACHE}\{}", cache_name(&sha(&z)));
    sys.fake_fs().remove_abs(Path::new(&cache_dir)).unwrap();
    let again = extract(&sys, &a, &p).unwrap();
    assert!(again.iter().all(|u| u.how == How::Present), "{again:?}");

    // A changed file is extracted again over the old one (the archive is needed then).
    drop(a);
    let f = format!(r"{LAD}\Rerun\packages\fix-pack\1.0\bin\d3d9.dll");
    sys.fake_fs().remove_abs(Path::new(&f)).unwrap();
    sys.fake_fs().put_file(Path::new(&f), b"changed").unwrap();
    assert_eq!(
        extract(&sys, &app(&sys), &p).unwrap_err(),
        ExtractError::NotCached {
            id: "fix-pack".into()
        }
    );
    cache(&sys, &z);
    let fixed = extract(&sys, &app(&sys), &p).unwrap();
    assert_eq!(
        hows(&fixed),
        [
            (r"cfg\fix.ini".to_owned(), How::Present),
            (r"bin\d3d9.dll".to_owned(), How::Extracted)
        ]
    );
    assert_eq!(read(&sys, r"bin\d3d9.dll"), b"the d3d9");
}

#[test]
fn a_tar_gz_is_extracted_in_one_pass() {
    let t = tar_gz(&[
        TarEntry::dir("dxvk-9.9/"),
        TarEntry::file("dxvk-9.9/x32/d3d9.dll", b"32-bit d3d9"),
        TarEntry::file("dxvk-9.9/x32/dxgi.dll", b"32-bit dxgi"),
        TarEntry::file("dxvk-9.9/x64/d3d9.dll", b"64-bit d3d9"),
    ]);
    let p = package(
        "tar.gz",
        &t,
        vec![
            file("dxvk-9.9/x64/d3d9.dll", "d3d9.dll", b"64-bit d3d9"),
            file("dxvk-9.9/x32/d3d9.dll", "d3d9.dll", b"32-bit d3d9"),
        ],
    );
    let sys = sys();
    cache(&sys, &t);
    extract(&sys, &app(&sys), &p).unwrap();
    assert_eq!(
        app_tree(&sys),
        with_empty(&[
            r"packages\fix-pack\1.0\dxvk-9.9\",
            r"packages\fix-pack\1.0\dxvk-9.9\x32\",
            r"packages\fix-pack\1.0\dxvk-9.9\x32\d3d9.dll",
            r"packages\fix-pack\1.0\dxvk-9.9\x64\",
            r"packages\fix-pack\1.0\dxvk-9.9\x64\d3d9.dll",
        ])
    );
    assert_eq!(read(&sys, r"dxvk-9.9\x64\d3d9.dll"), b"64-bit d3d9");
}

#[test]
fn an_assets_package_puts_each_build_below_its_architecture() {
    let x86 = zip(&[
        ZipEntry::file("dinput8.dll", b"loader x86"),
        ZipEntry::file("readme.txt", b"same text"),
    ]);
    let x64 = zip(&[
        ZipEntry::file("dinput8.dll", b"loader x64"),
        ZipEntry::file("readme.txt", b"same text"),
    ]);
    let mut a86 = file("dinput8.dll", "dinput8.dll", b"loader x86");
    a86.arch = Some(vec![Arch::X86]);
    let mut a64 = file("dinput8.dll", "dinput8.dll", b"loader x64");
    a64.arch = Some(vec![Arch::X64]);
    let both = file("readme.txt", "scripts/readme.txt", b"same text");
    let p = assets_package(&x86, &x64, vec![a86.clone(), a64.clone(), both.clone()]);
    assert_eq!(
        source_path(&p, &a86, Arch::X86),
        Some(rel(r"x86\dinput8.dll"))
    );
    assert_eq!(source_path(&p, &a86, Arch::X64), None);
    assert_eq!(
        source_path(&p, &both, Arch::X64),
        Some(rel(r"x64\readme.txt"))
    );
    let sys = sys();
    cache(&sys, &x86);
    cache(&sys, &x64);
    extract(&sys, &app(&sys), &p).unwrap();
    assert_eq!(
        app_tree(&sys),
        with_empty(&[
            r"packages\fix-pack\1.0\x64\",
            r"packages\fix-pack\1.0\x64\dinput8.dll",
            r"packages\fix-pack\1.0\x64\readme.txt",
            r"packages\fix-pack\1.0\x86\",
            r"packages\fix-pack\1.0\x86\dinput8.dll",
            r"packages\fix-pack\1.0\x86\readme.txt",
        ])
    );
    assert_eq!(read(&sys, r"x64\dinput8.dll"), b"loader x64");
    // One place, two hashes: refused before anything is touched.
    let mut wrong = both.clone();
    wrong.sha256 = Hex::new([1; 32]);
    let p = assets_package(&x86, &x64, vec![both, wrong]);
    assert!(matches!(layout(&p), Err(ExtractError::Layout { .. })));
}

/// Refused archives (the zip-slip corpus through the product path): the error, and nothing
/// below Rerun's folder but the empty version folder.
#[test]
fn a_refused_archive_writes_nothing() {
    let slip = |name: &str| {
        let mut e = ZipEntry::file(name, b"evil");
        e.flags = 0x0800;
        zip(&[ZipEntry::file("good.dll", b"good"), e])
    };
    let mut link = ZipEntry::file("good.dll", b"target");
    link.made_by = 0x0314;
    link.attrs = 0o120_777 << 16;
    let mut bad_crc = ZipEntry::file("good.dll", b"good");
    bad_crc.crc = Some(1);
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("zip", slip("../../../../evil.dll"), "BadName"),
        ("zip", slip("..\\evil.dll"), "BadName"),
        ("zip", slip("/evil.dll"), "BadName"),
        ("zip", slip("C:/evil.dll"), "BadName"),
        ("zip", slip("//host/share/evil.dll"), "BadName"),
        ("zip", slip("good.dll:evil"), "BadName"),
        ("zip", slip("CON.dll"), "BadName"),
        ("zip", slip("\u{ff0e}\u{ff0e}/evil.dll"), "BadName"),
        ("zip", slip("GOOD.DLL"), "Duplicate"),
        ("zip", zip(&[link]), "Special"),
        ("zip", zip(&[bad_crc]), "Crc"),
        (
            "tar.gz",
            tar_gz(&[
                TarEntry::file("good.dll", b"good"),
                TarEntry::typed("evil.dll", b'2'),
            ]),
            "Special",
        ),
        (
            "tar.gz",
            tar_gz(&[
                TarEntry::file("good.dll", b"good"),
                TarEntry::file("../evil.dll", b"evil"),
            ]),
            "BadName",
        ),
    ];
    for (ext, archive, want) in cases {
        let p = package(ext, &archive, vec![file("good.dll", "good.dll", b"good")]);
        let sys = sys();
        cache(&sys, &archive);
        let e = extract(&sys, &app(&sys), &p).unwrap_err();
        let ExtractError::Archive { error, .. } = &e else {
            panic!("{want}: {e:?}");
        };
        assert!(format!("{error:?}").starts_with(want), "{want}: {error:?}");
        assert_eq!(app_tree(&sys), with_empty(&[]), "{want}");
    }
}

#[test]
fn a_file_without_its_pinned_hash_is_not_kept() {
    let z = zip(&[ZipEntry::file("good.dll", b"other content")]);
    let p = package("zip", &z, vec![file("good.dll", "good.dll", b"good")]);
    let sys = sys();
    cache(&sys, &z);
    assert_eq!(
        extract(&sys, &app(&sys), &p).unwrap_err(),
        ExtractError::Mismatch {
            id: "fix-pack".into(),
            file: "good.dll".into()
        }
    );
    assert_eq!(app_tree(&sys), with_empty(&[]));
}

#[test]
fn names_must_match_exactly_and_formats_are_fixed() {
    let z = zip(&[ZipEntry::file("Good.dll", b"good")]);
    let p = package("zip", &z, vec![file("good.dll", "good.dll", b"good")]);
    let sys = sys();
    cache(&sys, &z);
    assert_eq!(
        extract(&sys, &app(&sys), &p).unwrap_err(),
        ExtractError::Archive {
            id: "fix-pack".into(),
            error: ArchiveError::NotFound {
                name: "good.dll".into(),
                other_case: true
            }
        }
    );
    // The download names a format Rerun does not read.
    let p = package("7z", &z, vec![file("good.dll", "good.dll", b"good")]);
    assert!(matches!(
        extract(&sys, &app(&sys), &p),
        Err(ExtractError::Format { .. })
    ));
    // A zip named .tar.gz.
    let p = package("tar.gz", &z, vec![file("good.dll", "good.dll", b"good")]);
    assert_eq!(
        extract(&sys, &app(&sys), &p).unwrap_err(),
        ExtractError::Archive {
            id: "fix-pack".into(),
            error: ArchiveError::NotFormat("tar.gz (gzip)")
        }
    );
}

#[test]
fn the_cached_archive_is_hashed_again() {
    let z = zip(&[ZipEntry::file("good.dll", b"good")]);
    let p = package("zip", &z, vec![file("good.dll", "good.dll", b"good")]);
    let sys = sys();
    // Another content under the archive's name.
    let name = format!(r"{CACHE}\{}", cache_name(&sha(&z)));
    sys.fake_fs()
        .put_file(Path::new(&name), b"swapped")
        .unwrap();
    assert_eq!(
        extract(&sys, &app(&sys), &p).unwrap_err(),
        ExtractError::CacheChanged {
            id: "fix-pack".into()
        }
    );
    assert_eq!(app_tree(&sys), with_empty(&[]));
}

#[test]
fn links_in_the_version_folder_are_refused_and_limits_hold() {
    let z = zip(&[ZipEntry::file("bin/good.dll", b"good")]);
    let p = package("zip", &z, vec![file("bin/good.dll", "good.dll", b"good")]);
    // A junction where a folder of the version folder belongs.
    let sys = FakeSystem::builder()
        .dir(LAD)
        .dir(r"D:\Elsewhere")
        .junction(
            format!(r"{LAD}\Rerun\packages\fix-pack\1.0\bin"),
            r"D:\Elsewhere",
        )
        .build()
        .unwrap();
    cache(&sys, &z);
    assert!(matches!(
        extract(&sys, &app(&sys), &p),
        Err(ExtractError::Entry { .. })
    ));
    // The archive limits are the caller's.
    let sys = self::sys();
    cache(&sys, &z);
    let small = Limits {
        max_entry_bytes: 3,
        ..Limits::DEFAULT
    };
    assert!(matches!(
        extract_limited(&sys, &app(&sys), &p, &small),
        Err(ExtractError::Archive {
            error: ArchiveError::TooLarge(_),
            ..
        })
    ));
}

#[test]
fn an_interrupted_extraction_leaves_a_temp_file_the_next_run_removes() {
    let z = zip(&[ZipEntry::file("good.dll", b"good")]);
    let p = package("zip", &z, vec![file("good.dll", "good.dll", b"good")]);
    let sys = sys();
    cache(&sys, &z);
    let a = app(&sys);
    sys.fake_fs().fault(Prim::Write, 1, Fault::CrashAfter);
    assert!(extract(&sys, &a, &p).is_err());
    drop(a);
    sys.fake_fs().restart();
    sys.fake_fs().clear_faults();
    let left = app_tree(&sys);
    assert!(
        left.iter()
            .any(|n| n.starts_with(r"packages\fix-pack\1.0\.rerun-")),
        "{left:?}"
    );
    extract(&sys, &app(&sys), &p).unwrap();
    assert_eq!(
        app_tree(&sys),
        with_empty(&[r"packages\fix-pack\1.0\good.dll"])
    );
}

#[test]
fn an_elevated_process_extracts_nothing() {
    let z = zip(&[ZipEntry::file("good.dll", b"good")]);
    let p = package("zip", &z, vec![file("good.dll", "good.dll", b"good")]);
    let sys = sys();
    cache(&sys, &z);
    let a = app(&sys);
    sys.fake_registry().set_elevated(true);
    assert_eq!(extract(&sys, &a, &p), Err(ExtractError::Elevated));
}
