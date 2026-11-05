//! `scan_game` and `inspect_exe` against `sys::fake` with synthetic images (ADR 0014). Every
//! folder, file and string is invented.

use std::path::Path;

use super::{Candidate, ExeError, GameExes, Main, Options, inspect_exe, scan_game};
use crate::detect::exe::api::{ApiVerdict, Basis, Engine, GraphicsApi};
use crate::detect::exe::role::Role;
use crate::detect::exe::{ExeIssueKind, ExeLimits};
use crate::detect::pe::layout as l;
use crate::detect::pe::testfx::{self, Builder, string_table, version_info};
use crate::detect::pe::{LegacyFormat, Limits, Machine, PeErrorKind, PeReadError};
use crate::path::RelPath;
use crate::policy::root::{ForbiddenRoots, GameDir};
use crate::sys::SysErrorKind;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const GAME: &str = r"D:\Games\Invented Game";

fn base() -> FakeSystemBuilder {
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(GAME)
}

fn at(path: &str) -> String {
    format!(r"{GAME}\{path}")
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn game(sys: &FakeSystem) -> GameDir<'_> {
    let fr = ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap();
    GameDir::open_manual(sys, &fr, Path::new(GAME)).unwrap()
}

fn options() -> Options {
    Options {
        name_hint: Some(rel("Invented Game")),
        ..Options::default()
    }
}

fn scan(sys: &FakeSystem) -> GameExes {
    scan_game(&game(sys), &options())
}

/// An x64 GUI executable importing `imports`.
fn exe(imports: &[&str]) -> Vec<u8> {
    let mut b = Builder::x64();
    b.imports = Some(imports.iter().map(|n| n.as_bytes().to_vec()).collect());
    b.build().bytes
}

/// An x86 GUI executable importing `imports`.
fn exe32(imports: &[&str]) -> Vec<u8> {
    let mut b = Builder::x86();
    b.imports = Some(imports.iter().map(|n| n.as_bytes().to_vec()).collect());
    b.build().bytes
}

fn find<'r>(r: &'r GameExes, path: &str) -> &'r Candidate {
    r.candidates
        .iter()
        .find(|c| c.path == rel(path))
        .unwrap_or_else(|| panic!("no candidate {path}"))
}

fn order(r: &GameExes) -> Vec<&str> {
    r.candidates.iter().map(|c| c.path.as_str()).collect()
}

fn verdict(c: &Candidate) -> &ApiVerdict {
    &c.facts.as_ref().unwrap().api.verdict
}

#[test]
fn a_whole_game_folder() {
    let mut dll = Builder::x64();
    dll.characteristics |= l::FILE_DLL;
    dll.imports = Some(vec![b"d3d9.dll".to_vec()]);
    let sys = base()
        .file(
            at(r"Binaries\Win64\Invented-Win64-Shipping.exe"),
            exe(&["KERNEL32.dll", "d3d11.dll", "d3d9.dll", "dxgi.dll"]),
        )
        .file(at("InventedLauncher.exe"), exe32(&["d3d9.dll"]))
        .file(at("UnityCrashHandler64.exe"), exe(&["KERNEL32.dll"]))
        .file(at("Setup.exe"), exe(&[]))
        .file(at(r"_CommonRedist\vcredist_x64.exe"), exe(&[]))
        .file(at("helper.exe"), dll.build().bytes)
        .file(at("dos.exe"), testfx::dos_exe())
        .file(at("broken.exe"), b"SECRETMARKER, no executable".to_vec())
        .build()
        .unwrap();
    let r = scan(&sys);
    assert_eq!(
        order(&r),
        [
            r"Binaries\Win64\Invented-Win64-Shipping.exe",
            "InventedLauncher.exe",
            "Setup.exe",
            "UnityCrashHandler64.exe",
            "helper.exe",
            "dos.exe",
            "broken.exe",
        ]
    );
    assert_eq!(r.main, Main::One(0));
    let main = &r.candidates[0];
    assert_eq!(main.role, Role::Game);
    assert_eq!(main.depth, 2);
    assert_eq!(
        verdict(main),
        &ApiVerdict::One {
            api: GraphicsApi::D3d11,
            basis: Basis::HighestD3d
        }
    );
    let facts = main.facts.as_ref().unwrap();
    assert_eq!(facts.info.headers.machine, Machine::X64);
    assert_eq!(facts.api.to_string(), "d3d11 (also d3d9)");
    assert!(facts.bytes_read <= Limits::DEFAULT.max_read_bytes);

    let launcher = find(&r, "InventedLauncher.exe");
    assert_eq!(launcher.role, Role::Launcher);
    assert_eq!(
        launcher.facts.as_ref().unwrap().info.headers.machine,
        Machine::X86
    );
    assert_eq!(find(&r, "Setup.exe").role, Role::Installer);
    assert_eq!(
        find(&r, "UnityCrashHandler64.exe").role,
        Role::CrashReporter
    );
    assert_eq!(find(&r, "helper.exe").role, Role::NotAnApp);
    let dos = find(&r, "dos.exe");
    assert_eq!(dos.role, Role::Legacy(LegacyFormat::Dos));
    assert!(dos.facts.is_err());
    // A broken file keeps its name role and its error, and ranks last.
    let broken = find(&r, "broken.exe");
    assert_eq!(broken.role, Role::Game);
    assert!(matches!(
        &broken.facts,
        Err(ExeError::Pe(PeReadError::Parse { file, error }))
            if *file == rel("broken.exe") && error.kind == PeErrorKind::NotExecutable
    ));

    assert_eq!(r.stats.skipped_dirs, [rel("_CommonRedist")]);
    assert!(r.stats.complete);
    assert!(r.issues.is_empty(), "{:?}", r.issues);
}

#[test]
fn engines_and_managed_images() {
    let mut managed = Builder::x86();
    managed.dirs = vec![(l::DIR_COM_DESCRIPTOR, testfx::DATA_RVA, 0x48)];
    managed.imports = Some(vec![b"mscoree.dll".to_vec()]);
    let sys = base()
        .file(at("Invented.exe"), exe(&["UnityPlayer.dll"]))
        .file(at("FFLauncher.exe"), managed.build().bytes)
        .build()
        .unwrap();
    let r = scan(&sys);
    assert_eq!(r.main, Main::One(0));
    assert_eq!(
        verdict(&r.candidates[0]),
        &ApiVerdict::RendererInDll(Engine::Unity)
    );
    assert_eq!(r.candidates[0].similarity, 1);
    let launcher = find(&r, "FFLauncher.exe");
    assert_eq!(launcher.role, Role::Launcher);
    assert_eq!(verdict(launcher), &ApiVerdict::Managed);
}

#[test]
fn two_game_executables_are_tied() {
    let sys = base()
        .file(at("Invented_Dx9.exe"), exe32(&["d3d9.dll"]))
        .file(at("Invented_Dx10.exe"), exe32(&["d3d10.dll", "dxgi.dll"]))
        .file(at("InventedLauncher.exe"), exe32(&["d3d9.dll"]))
        .build()
        .unwrap();
    let r = scan_game(&game(&sys), &Options::default());
    assert_eq!(r.main, Main::Tied(vec![0, 1]));
    assert_eq!(
        order(&r),
        [
            "Invented_Dx10.exe",
            "Invented_Dx9.exe",
            "InventedLauncher.exe"
        ]
    );
}

#[test]
fn no_main_without_a_parsed_game_executable() {
    let sys = base()
        .file(at("InventedLauncher.exe"), exe(&["d3d11.dll"]))
        .file(at("InventedConfig.exe"), exe(&["d3d9.dll"]))
        .file(at("game.exe"), b"MZ".to_vec())
        .build()
        .unwrap();
    let r = scan_game(&game(&sys), &Options::default());
    assert_eq!(r.main, Main::None);
    assert_eq!(r.candidates[0].role, Role::Launcher);
    assert_eq!(r.candidates[2].path, rel("game.exe"));

    let sys = base().build().unwrap();
    let r = scan(&sys);
    assert_eq!(r.main, Main::None);
    assert!(r.candidates.is_empty());
    assert!(r.stats.complete);
}

#[test]
fn inspect_exe_reaches_paths_the_walk_does_not() {
    let deep = r"a\b\c\d\e\Invented.exe";
    let sys = base()
        .file(at(deep), exe(&["opengl32.dll", "glu32.dll"]))
        .build()
        .unwrap();
    let g = game(&sys);
    assert!(scan_game(&g, &options()).candidates.is_empty());
    let facts = inspect_exe(&g, &rel(deep), &Limits::DEFAULT, None).unwrap();
    assert_eq!(
        facts.api.verdict,
        ApiVerdict::One {
            api: GraphicsApi::Opengl,
            basis: Basis::Only
        }
    );
    match inspect_exe(&g, &rel("missing.exe"), &Limits::DEFAULT, None) {
        Err(ExeError::Pe(PeReadError::Open { source, .. })) => {
            assert_eq!(source.kind, SysErrorKind::NotFound);
        }
        other => panic!("expected Open, got {other:?}"),
    }
}

#[test]
fn the_result_outlives_the_game_folder() {
    fn owned<T: 'static>(t: T) -> T {
        t
    }
    let sys = base()
        .file(at("Invented.exe"), exe(&["d3d9.dll"]))
        .build()
        .unwrap();
    let r = {
        let g = game(&sys);
        owned(scan_game(&g, &options()))
    };
    assert_eq!(r.main, Main::One(0));
    assert_eq!(r.candidates[0].similarity, 1);
}

#[test]
fn the_walk_limits_apply() {
    let sys = (0..4)
        .fold(base(), |b, i| b.file(at(&format!("g{i}.exe")), exe(&[])))
        .build()
        .unwrap();
    let limits = ExeLimits {
        max_exes: 2,
        ..ExeLimits::DEFAULT
    };
    let r = scan_game(
        &game(&sys),
        &Options {
            limits,
            ..options()
        },
    );
    assert_eq!(order(&r), ["g0.exe", "g1.exe"]);
    assert_eq!(
        r.issues[0].kind,
        ExeIssueKind::TooManyExes { found: 4, max: 2 }
    );
}

#[test]
fn no_content_reaches_the_output() {
    let blob = version_info(
        vec![string_table(
            "040904b0",
            &[
                ("CompanyName", "SECRETMARKER company"),
                ("FileDescription", "SECRETMARKER \u{1b}[31m description"),
                ("ProductName", "SECRETMARKER\u{202E}gnp.exe"),
            ],
        )],
        Some((0x0409, 0x04B0)),
    )
    .encode();
    let mut b = Builder::x64().with_version(blob);
    b.imports = Some(vec![b"d3d9.dll".to_vec()]);
    let sys = base()
        .file(at("Invented.exe"), b.build().bytes)
        .file(at("broken.exe"), b"MZ SECRETMARKER".to_vec())
        .raw_file(GAME, "evil\u{202E}\u{1b}[31m.exe", exe(&[]))
        .raw_file(GAME, "SECRETMARKER.exe.", exe(&[]))
        .build()
        .unwrap();
    let r = scan(&sys);
    // The marker was really read.
    let v = r.candidates[0]
        .facts
        .as_ref()
        .unwrap()
        .info
        .version
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap();
    assert!(
        v.strings
            .company_name
            .as_ref()
            .unwrap()
            .as_raw_str()
            .contains("SECRETMARKER")
    );
    for shown in [format!("{r:?}"), format!("{r:#?}")] {
        assert!(!shown.contains("SECRETMARKER company"), "{shown}");
        assert!(
            !shown.contains('\u{1b}') && !shown.contains('\u{202E}'),
            "{shown}"
        );
    }
    assert_eq!(r.issues.len(), 2, "{:?}", r.issues);
    for issue in &r.issues {
        let shown = format!("{issue} / {issue:?}");
        assert!(
            !shown.contains('\u{1b}') && !shown.contains('\u{202E}'),
            "{shown}"
        );
        assert!(shown.starts_with("game folder: anomalous name "), "{shown}");
    }
    let e = r
        .candidates
        .iter()
        .find_map(|c| c.facts.as_ref().err())
        .unwrap();
    assert!(!format!("{e} / {e:?}").contains("SECRETMARKER"));
}

// ---------- Hashes ----------

use std::io::{Cursor, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::inspect_pe;
use crate::detect::exe::{HashError, HashLimits, HashOutcome, HashSkip, Hashes};
use crate::detect::pe::Pe;
use crate::sys::fake::{FakeFs, FsOp, StepEvent};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn hashes(c: &Candidate) -> &HashOutcome {
    &c.facts.as_ref().unwrap().hashes
}

fn hashing() -> Options {
    Options {
        hashes: true,
        ..options()
    }
}

/// A reader over an image that counts the bytes it served.
struct Counted {
    data: Cursor<Vec<u8>>,
    served: Arc<AtomicU64>,
}

impl std::io::Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.data.read(buf)?;
        self.served
            .fetch_add(u64::try_from(n).unwrap(), Ordering::SeqCst);
        Ok(n)
    }
}

impl std::io::Seek for Counted {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.data.seek(to)
    }
}

/// An image with a large tail the parser never reads.
fn padded() -> Vec<u8> {
    let mut bytes = exe(&["d3d9.dll"]);
    bytes.resize(bytes.len() + (3 << 20), 0xA5);
    bytes
}

fn counted(bytes: &[u8]) -> (Counted, Arc<AtomicU64>) {
    let served = Arc::new(AtomicU64::new(0));
    let reader = Counted {
        data: Cursor::new(bytes.to_vec()),
        served: Arc::clone(&served),
    };
    (reader, served)
}

#[test]
fn without_hashes_nothing_beyond_the_parser_is_read() {
    let bytes = padded();
    let len = u64::try_from(bytes.len()).unwrap();
    let (reader, served) = counted(&bytes);
    let pe = Pe::parse(reader, &Limits::DEFAULT).unwrap();
    let (facts, _) = inspect_pe(pe, &rel("game.exe"), None, None).unwrap();
    assert_eq!(facts.hashes, HashOutcome::NotRequested);
    let n = served.load(Ordering::SeqCst);
    assert!(n <= facts.bytes_read, "{n} > {}", facts.bytes_read);
    assert!(n < len / 2);

    // With hashes: the same handle, read once more from 0 to its end.
    let (reader, served) = counted(&bytes);
    let pe = Pe::parse(reader, &Limits::DEFAULT).unwrap();
    let (facts, hashed) =
        inspect_pe(pe, &rel("game.exe"), Some(&HashLimits::DEFAULT), None).unwrap();
    let HashOutcome::Done(h) = &facts.hashes else {
        panic!("expected hashes, got {:?}", facts.hashes);
    };
    assert_eq!(h.len, len);
    assert_eq!(hashed, len);
    assert_eq!(h.sha1, hex(&Sha1::digest(&bytes)));
    assert_eq!(h.sha256, hex(&Sha256::digest(&bytes)));
    assert!(served.load(Ordering::SeqCst) <= facts.bytes_read + h.len);

    // A scan without `--hashes`: every parsed candidate says so.
    let sys = base()
        .file(at("Invented.exe"), bytes)
        .file(at("InventedLauncher.exe"), exe(&[]))
        .build()
        .unwrap();
    let r = scan(&sys);
    for c in &r.candidates {
        assert_eq!(hashes(c), &HashOutcome::NotRequested, "{}", c.path);
    }
}

#[test]
fn inspect_exe_hashes_the_file_it_parsed() {
    let bytes = padded();
    let len = u64::try_from(bytes.len()).unwrap();
    let file = rel(r"bin\Invented.exe");
    let sys = base()
        .file(at(r"bin\Invented.exe"), bytes.clone())
        .build()
        .unwrap();
    let g = game(&sys);
    let facts = inspect_exe(&g, &file, &Limits::DEFAULT, Some(&HashLimits::DEFAULT)).unwrap();
    assert_eq!(
        facts.hashes,
        HashOutcome::Done(Hashes {
            len,
            sha1: hex(&Sha1::digest(&bytes)),
            sha256: hex(&Sha256::digest(&bytes)),
        })
    );
    // The per-file limit: exactly the length is hashed, one byte less is too large.
    let exact = HashLimits {
        max_file_bytes: len,
        ..HashLimits::DEFAULT
    };
    let at_limit = inspect_exe(&g, &file, &Limits::DEFAULT, Some(&exact)).unwrap();
    assert!(matches!(at_limit.hashes, HashOutcome::Done(_)));
    let under = HashLimits {
        max_file_bytes: len - 1,
        ..HashLimits::DEFAULT
    };
    let over = inspect_exe(&g, &file, &Limits::DEFAULT, Some(&under)).unwrap();
    assert_eq!(
        over.hashes,
        HashOutcome::Skipped(HashSkip::TooLarge { max: len - 1 })
    );
}

#[test]
fn only_parsed_game_candidates_are_hashed_in_rank_order() {
    let main = exe(&["d3d11.dll"]);
    let sys = base()
        .file(at(r"bin\Invented.exe"), main.clone())
        .file(at("Invented_Dx9.exe"), exe(&["d3d9.dll", "d3d8.dll"]))
        .file(at("Other.exe"), exe(&[]))
        .file(at("InventedLauncher.exe"), exe(&["d3d9.dll"]))
        .file(at("UnityCrashHandler64.exe"), exe(&[]))
        .file(at("broken.exe"), b"not an executable".to_vec())
        .build()
        .unwrap();
    let limits = ExeLimits {
        hash: HashLimits {
            max_files: 2,
            ..HashLimits::DEFAULT
        },
        ..ExeLimits::DEFAULT
    };
    let r = scan_game(
        &game(&sys),
        &Options {
            limits,
            ..hashing()
        },
    );
    assert_eq!(
        order(&r),
        [
            r"bin\Invented.exe",
            "Invented_Dx9.exe",
            "Other.exe",
            "InventedLauncher.exe",
            "UnityCrashHandler64.exe",
            "broken.exe"
        ]
    );
    let HashOutcome::Done(h) = hashes(&r.candidates[0]) else {
        panic!("{:?}", hashes(&r.candidates[0]));
    };
    assert_eq!(h.sha256, hex(&Sha256::digest(&main)));
    assert!(matches!(hashes(&r.candidates[1]), HashOutcome::Done(_)));
    assert_eq!(
        hashes(&r.candidates[2]),
        &HashOutcome::Skipped(HashSkip::TooManyFiles { max: 2 })
    );
    for c in &r.candidates[3..5] {
        assert_eq!(
            hashes(c),
            &HashOutcome::Skipped(HashSkip::NotGame),
            "{}",
            c.path
        );
    }
    // A candidate that failed has no hashes, only its error.
    assert!(r.candidates[5].facts.is_err());
}

#[test]
fn the_game_budget_and_the_file_limit_skip_by_the_listed_length() {
    let big = padded();
    let small = exe(&["d3d9.dll"]);
    let big_len = u64::try_from(big.len()).unwrap();
    let small_len = u64::try_from(small.len()).unwrap();
    let sys = base()
        .file(at("Invented.exe"), big)
        .file(at("Invented_Dx9.exe"), padded())
        .file(at("Other.exe"), small)
        .build()
        .unwrap();
    // The budget fits the first file and the small one, not the second big one.
    let budget = big_len + small_len;
    let limits = ExeLimits {
        hash: HashLimits {
            max_game_bytes: budget,
            ..HashLimits::DEFAULT
        },
        ..ExeLimits::DEFAULT
    };
    let r = scan_game(
        &game(&sys),
        &Options {
            limits,
            ..hashing()
        },
    );
    assert_eq!(order(&r), ["Invented.exe", "Invented_Dx9.exe", "Other.exe"]);
    assert!(matches!(hashes(&r.candidates[0]), HashOutcome::Done(h) if h.len == big_len));
    assert_eq!(
        hashes(&r.candidates[1]),
        &HashOutcome::Skipped(HashSkip::GameBudget { max: budget })
    );
    assert!(matches!(hashes(&r.candidates[2]), HashOutcome::Done(h) if h.len == small_len));

    // The per-file limit by the listed length: never read.
    let limits = ExeLimits {
        hash: HashLimits {
            max_file_bytes: big_len - 1,
            ..HashLimits::DEFAULT
        },
        ..ExeLimits::DEFAULT
    };
    let r = scan_game(
        &game(&sys),
        &Options {
            limits,
            ..hashing()
        },
    );
    for c in &r.candidates[..2] {
        assert_eq!(
            hashes(c),
            &HashOutcome::Skipped(HashSkip::TooLarge { max: big_len - 1 }),
            "{}",
            c.path
        );
    }
    assert!(matches!(hashes(&r.candidates[2]), HashOutcome::Done(_)));
}

/// Replaces `file` (one segment, in the game folder) with `with` when it is opened for
/// reading the `nth` time (from 1).
fn replace_on_open(fs: &FakeFs, file: &'static str, nth: usize, with: Vec<u8>) {
    let opens = AtomicUsize::new(0);
    fs.on_step(move |fs: &FakeFs, ev: &StepEvent| {
        if ev.op == FsOp::OpenRead
            && ev.name == file
            && opens.fetch_add(1, Ordering::SeqCst) + 1 == nth
        {
            fs.put_file(Path::new(&at(file)), &with).unwrap();
        }
    });
}

#[test]
fn a_file_replaced_between_the_two_inspections_is_not_hashed() {
    let sys = base()
        .file(at("Invented.exe"), exe(&["d3d9.dll"]))
        .build()
        .unwrap();
    replace_on_open(sys.fake_fs(), "Invented.exe", 2, exe(&["opengl32.dll"]));
    let r = scan_game(&game(&sys), &hashing());
    sys.fake_fs().clear_on_step();
    let c = &r.candidates[0];
    assert_eq!(hashes(c), &HashOutcome::Failed(HashError::Changed));
    // The first facts stay.
    assert_eq!(
        verdict(c),
        &ApiVerdict::One {
            api: GraphicsApi::D3d9,
            basis: Basis::Only
        }
    );

    let sys = base()
        .file(at("Invented.exe"), exe(&["d3d9.dll"]))
        .build()
        .unwrap();
    replace_on_open(sys.fake_fs(), "Invented.exe", 2, b"gone".to_vec());
    let r = scan_game(&game(&sys), &hashing());
    sys.fake_fs().clear_on_step();
    let outcome = hashes(&r.candidates[0]);
    let HashOutcome::Failed(HashError::Inspect(e)) = outcome else {
        panic!("{outcome:?}");
    };
    assert!(
        matches!(**e, ExeError::Pe(PeReadError::Parse { .. })),
        "{e}"
    );
    assert_eq!(outcome.to_string(), format!("failed: {e}"));
}

/// Replaces each `(file, with)` (one segment, in the game folder) when that file is opened for
/// reading the second time (the first is the inspection, the second the one that hashes).
fn replace_each_on_second_open(fs: &FakeFs, files: Vec<(&'static str, Vec<u8>)>) {
    let opens: Vec<AtomicUsize> = files.iter().map(|_| AtomicUsize::new(0)).collect();
    fs.on_step(move |fs: &FakeFs, ev: &StepEvent| {
        if ev.op != FsOp::OpenRead {
            return;
        }
        for ((file, with), n) in files.iter().zip(&opens) {
            if ev.name == *file && n.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                fs.put_file(Path::new(&at(file)), with).unwrap();
            }
        }
    });
}

/// `exe(imports)` with `extra` bytes of overlay appended (the parser never reads it, so the
/// facts stay the same).
fn with_overlay(imports: &[&str], extra: usize) -> Vec<u8> {
    let mut bytes = exe(imports);
    bytes.resize(bytes.len() + extra, 0x5A);
    bytes
}

#[test]
fn changed_files_cost_only_parser_reads() {
    // Two game executables are replaced by large, different ones before they are hashed;
    // a third, unchanged one fills the budget.
    let third = with_overlay(&["d3d9.dll"], 1 << 20);
    let third_len = u64::try_from(third.len()).unwrap();
    let sys = base()
        .file(at("Invented.exe"), exe(&["d3d11.dll"]))
        .file(at("Invented_A.exe"), exe(&["d3d10.dll"]))
        .file(at("Invented_B.exe"), third)
        .build()
        .unwrap();
    let big = with_overlay(&["opengl32.dll"], 8 << 20);
    replace_each_on_second_open(
        sys.fake_fs(),
        vec![("Invented.exe", big.clone()), ("Invented_A.exe", big)],
    );
    let chunk = 4096;
    let limits = ExeLimits {
        hash: HashLimits {
            max_game_bytes: third_len,
            chunk_bytes: chunk,
            ..HashLimits::DEFAULT
        },
        ..ExeLimits::DEFAULT
    };
    let before = sys.fake_fs().bytes_served();
    let r = scan_game(
        &game(&sys),
        &Options {
            limits,
            ..hashing()
        },
    );
    let served = sys.fake_fs().bytes_served() - before;
    sys.fake_fs().clear_on_step();
    assert_eq!(
        order(&r),
        ["Invented.exe", "Invented_A.exe", "Invented_B.exe"]
    );
    assert_eq!(
        hashes(&r.candidates[0]),
        &HashOutcome::Failed(HashError::Changed)
    );
    assert_eq!(
        hashes(&r.candidates[1]),
        &HashOutcome::Failed(HashError::Changed)
    );
    assert!(matches!(hashes(&r.candidates[2]), HashOutcome::Done(h) if h.len == third_len));
    // Two parser passes over three files (each at most the parser budget), plus the game
    // budget plus one chunk per hashed file; hashing the replaced 8 MiB files would exceed it.
    let parser = 2 * 3 * Limits::DEFAULT.max_read_bytes;
    let bound = parser + third_len + 3 * u64::try_from(chunk).unwrap();
    assert!(served <= bound, "{served} > {bound}");
}

#[test]
fn a_file_that_grew_hits_the_game_budget_and_later_ones_are_skipped() {
    // The listing says small; before hashing, an overlay is appended (same facts). The
    // remaining game budget caps the read: `GameBudget`, and nothing is left for the next.
    let first = exe(&["d3d11.dll"]);
    let first_len = u64::try_from(first.len()).unwrap();
    let sys = base()
        .file(at("Invented.exe"), first)
        .file(at("Invented_A.exe"), exe(&["d3d9.dll"]))
        .build()
        .unwrap();
    replace_each_on_second_open(
        sys.fake_fs(),
        vec![("Invented.exe", with_overlay(&["d3d11.dll"], 1 << 20))],
    );
    let budget = first_len + 100;
    let limits = ExeLimits {
        hash: HashLimits {
            max_game_bytes: budget,
            chunk_bytes: 4096,
            ..HashLimits::DEFAULT
        },
        ..ExeLimits::DEFAULT
    };
    let before = sys.fake_fs().bytes_served();
    let r = scan_game(
        &game(&sys),
        &Options {
            limits,
            ..hashing()
        },
    );
    let served = sys.fake_fs().bytes_served() - before;
    sys.fake_fs().clear_on_step();
    assert_eq!(order(&r), ["Invented.exe", "Invented_A.exe"]);
    assert_eq!(
        hashes(&r.candidates[0]),
        &HashOutcome::Skipped(HashSkip::GameBudget { max: budget })
    );
    assert_eq!(
        hashes(&r.candidates[1]),
        &HashOutcome::Skipped(HashSkip::GameBudget { max: budget })
    );
    let bound = 2 * 2 * Limits::DEFAULT.max_read_bytes + budget + 4096;
    assert!(served <= bound, "{served} > {bound}");
}

// ---------- Regressions from the developer-machine dump (shapes only, invented names) ----------

/// An x86 image with `imports`, `subsystem`, and optionally the CLR directory.
fn image32(imports: &[&str], subsystem: u16, managed: bool) -> Vec<u8> {
    let mut b = Builder::x86();
    b.subsystem = subsystem;
    b.imports = Some(imports.iter().map(|n| n.as_bytes().to_vec()).collect());
    if managed {
        b.dirs = vec![(l::DIR_COM_DESCRIPTOR, testfx::DATA_RVA, 0x48)];
    }
    b.build().bytes
}

fn hinted_scan(sys: &FakeSystem, hint: &str) -> GameExes {
    scan_game(
        &game(sys),
        &Options {
            name_hint: Some(rel(hint)),
            ..Options::default()
        },
    )
}

#[test]
fn a_console_shader_worker_never_beats_the_gui_executables() {
    // A console shader compile worker with a helper-only import, a GUI start app without
    // graphics imports, a renamed launcher with Direct3D 9 and a .NET backup launcher.
    let gui = l::SUBSYSTEM_WINDOWS_GUI;
    let sys = base()
        .file(
            at(r"Binaries\InvShaderCompileWorker.exe"),
            image32(&["d3dx10_43.dll"], l::SUBSYSTEM_WINDOWS_CUI, false),
        )
        .file(at(r"Binaries\InvStartApp.exe"), image32(&[], gui, false))
        .file(
            at(r"Binaries\InvLauncher.exe"),
            image32(&["d3d9.dll"], gui, false),
        )
        .file(
            at(r"Binaries\InvLauncher_BackUP.exe"),
            image32(&["mscoree.dll"], gui, true),
        )
        .build()
        .unwrap();
    let r = hinted_scan(&sys, "Invented Asylum");
    assert_eq!(r.main, Main::One(0));
    assert_eq!(r.candidates[0].path, rel(r"Binaries\InvStartApp.exe"));
    assert_eq!(
        find(&r, r"Binaries\InvShaderCompileWorker.exe").role,
        Role::Helper
    );
    assert_eq!(find(&r, r"Binaries\InvLauncher.exe").role, Role::Launcher);
    assert_eq!(
        find(&r, r"Binaries\InvLauncher_BackUP.exe").role,
        Role::Launcher
    );
}

#[test]
fn the_folder_name_contained_in_the_stem_beats_a_managed_tool() {
    // A .NET log viewer deep in a tools folder against the game without graphics imports,
    // whose stem is contained in the install folder name.
    let gui = l::SUBSYSTEM_WINDOWS_GUI;
    let sys = base()
        .file(
            at(r"tools\logview\logview_viewer.exe"),
            image32(&["mscoree.dll"], gui, true),
        )
        .file(
            at(r"bin\win32_release\Invented2.exe"),
            image32(&[], gui, false),
        )
        .build()
        .unwrap();
    let r = hinted_scan(&sys, "Fortress Invented 2");
    assert_eq!(r.main, Main::One(0));
    let main = &r.candidates[0];
    assert_eq!(main.path, rel(r"bin\win32_release\Invented2.exe"));
    assert_eq!(main.similarity, 1);
    assert_eq!(verdict(main), &ApiVerdict::None);
    assert_eq!(verdict(&r.candidates[1]), &ApiVerdict::Managed);
}

#[test]
fn a_launcher_without_the_word_ties_with_the_game() {
    // Accepted (review of step 14): two GUI executables without graphics imports and without
    // similarity to the folder name are tied.
    let gui = l::SUBSYSTEM_WINDOWS_GUI;
    let sys = base()
        .file(at("Inv5_Enhanced.exe"), image32(&[], gui, false))
        .file(at("PlayInv5.exe"), image32(&[], gui, false))
        .build()
        .unwrap();
    let r = hinted_scan(&sys, "Grand Invented Five");
    assert_eq!(r.main, Main::Tied(vec![0, 1]));
    assert_eq!(order(&r), ["Inv5_Enhanced.exe", "PlayInv5.exe"]);
}

#[test]
fn a_launcher_named_after_the_folder_stays_a_launcher() {
    let gui = l::SUBSYSTEM_WINDOWS_GUI;
    let sys = base()
        .file(at("Invented4.exe"), image32(&["d3d11.dll"], gui, false))
        .file(
            at("Invented4Launcher.exe"),
            image32(&["d3d9.dll"], gui, false),
        )
        .build()
        .unwrap();
    let r = hinted_scan(&sys, "Invented 4");
    assert_eq!(r.main, Main::One(0));
    assert_eq!(r.candidates[0].path, rel("Invented4.exe"));
    assert_eq!(r.candidates[0].similarity, 2);
    assert_eq!(find(&r, "Invented4Launcher.exe").role, Role::Launcher);
}
