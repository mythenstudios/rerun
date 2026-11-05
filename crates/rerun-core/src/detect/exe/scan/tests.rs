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
    let facts = inspect_exe(&g, &rel(deep), &Limits::DEFAULT).unwrap();
    assert_eq!(
        facts.api.verdict,
        ApiVerdict::One {
            api: GraphicsApi::Opengl,
            basis: Basis::Only
        }
    );
    match inspect_exe(&g, &rel("missing.exe"), &Limits::DEFAULT) {
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
