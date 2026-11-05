//! Tests of `rerun scan` (ADR 0016, `docs/09-testing.md`, "CLI"): golden strings of the pure
//! render functions on directly built values, and in-process end-to-end cases against the fake
//! system layer with synthetic executables from `tests/support/pe_image.rs`. Everything
//! renders through `Out`, so the last-resort net is checked to never fire. Every path, name and
//! app ID is invented.

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rerun_core::detect::exe::{
    ApiEvidence, ApiReport, ApiVerdict, Basis, Candidate, ExeError, ExeFacts, ExeIssue,
    ExeIssueKind, GameExes, GraphicsApi, HashError, HashOutcome, HashSkip, Hashes, Main, Role,
    WalkStats,
};
use rerun_core::detect::pe::{
    FixedFileInfo, Headers, Machine, PeError, PeErrorKind, PeFormat, PeInfo, PeReadError,
    VersionInfo,
};
use rerun_core::detect::steam::{self, RawText, RootSource, StateFlags, SteamApp};
use rerun_core::path::{Anomaly, RelPath};
use rerun_core::policy::root::ForbiddenRoots;
use rerun_core::sys::KnownFolder;
use rerun_core::sys::fake::{FakeSystem, FakeSystemBuilder, FsOp};
use rerun_core::sys::registry::RegValue;

#[path = "../../../../tests/support/pe_image.rs"]
mod pe_image;

use super::{render_app, render_game, render_summary, scan};
use crate::cli::Exit;
use crate::messages::{Message, ScanCounts};
use crate::out::Out;
use crate::out::tests::Failing;

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn shown(ms: &[Message<'_>]) -> String {
    let mut out = Out::new(Vec::new());
    out.lines(ms).unwrap();
    String::from_utf8(out.into_inner()).unwrap()
}

// ---------- Rendering, on directly built values ----------

fn app(app_id: u32, name: &str, dir: &str, flags: u32) -> SteamApp {
    SteamApp {
        app_id,
        name: RawText::new(name),
        install_dir: rel(dir),
        state_flags: StateFlags::new(flags),
        manifest: rel(&format!(r"steamapps\appmanifest_{app_id}.acf")),
    }
}

fn one(api: GraphicsApi) -> ApiReport {
    ApiReport {
        verdict: ApiVerdict::One {
            api,
            basis: Basis::Only,
        },
        evidence: ApiEvidence::default(),
    }
}

fn facts(machine: Machine, api: ApiReport, version: Option<[u16; 4]>) -> ExeFacts {
    let format = if machine == Machine::X86 {
        PeFormat::Pe32
    } else {
        PeFormat::Pe32Plus
    };
    ExeFacts {
        info: PeInfo {
            headers: Headers {
                machine,
                format,
                characteristics: 0x0102,
                subsystem: 2,
                dll_characteristics: 0,
                image_base: 0x40_0000,
                size_of_headers: 0x400,
                section_count: 4,
                managed: false,
            },
            imports: Vec::new(),
            delay_imports: Vec::new(),
            version: Ok(version.map(|v| VersionInfo {
                fixed: Some(FixedFileInfo {
                    file_version: v,
                    product_version: [9, 9, 9, 9],
                    file_flags_mask: 0,
                    file_flags: 0,
                    file_os: 0,
                    file_type: 1,
                    file_subtype: 0,
                }),
                ..VersionInfo::default()
            })),
        },
        api,
        bytes_read: 4096,
        hashes: HashOutcome::NotRequested,
    }
}

fn cand(path: &str, role: Role, facts: Result<ExeFacts, ExeError>) -> Candidate {
    Candidate {
        path: rel(path),
        depth: 0,
        listed_len: 1 << 20,
        similarity: 0,
        role,
        facts,
    }
}

fn exes(candidates: Vec<Candidate>, main: Main, issues: Vec<ExeIssue>) -> GameExes {
    GameExes {
        stats: WalkStats {
            complete: true,
            listed_dirs: 1,
            entries: candidates.len(),
            exes_found: candidates.len(),
            depth_cut: 0,
            skipped_dirs: Vec::new(),
        },
        candidates,
        main,
        issues,
    }
}

fn parse_error(file: &str) -> ExeError {
    ExeError::Pe(PeReadError::Parse {
        file: rel(file),
        error: PeError {
            kind: PeErrorKind::Truncated,
            offset: Some(0x3c),
        },
    })
}

#[test]
fn one_main_executable_with_machine_api_and_version() {
    let a = app(220, "Half-Life 2", "Half-Life 2", 4);
    let e = exes(
        vec![
            cand(
                r"bin\hl2.exe",
                Role::Game,
                Ok(facts(
                    Machine::X86,
                    one(GraphicsApi::D3d9),
                    Some([1, 0, 0, 1]),
                )),
            ),
            cand(
                "launcher.exe",
                Role::Launcher,
                Err(parse_error("launcher.exe")),
            ),
        ],
        Main::One(0),
        Vec::new(),
    );
    assert_eq!(
        shown(&render_game(&a, &e)),
        "  app 220 (installed): Half-Life 2
    install folder: Half-Life 2
    main executable: bin\\hl2.exe
      x86 (not large address aware), API d3d9, version 1.0.0.1
"
    );
}

#[test]
fn a_tie_lists_every_tied_executable_and_picks_none() {
    let a = app(15_100, "Fixture Creed", "Fixture Creed", 4);
    let mut d3d10 = one(GraphicsApi::D3d10);
    d3d10.evidence.imports.core.insert(GraphicsApi::D3d10);
    d3d10.evidence.imports.core.insert(GraphicsApi::D3d9);
    d3d10.verdict = ApiVerdict::One {
        api: GraphicsApi::D3d10,
        basis: Basis::HighestD3d,
    };
    let e = exes(
        vec![
            cand(
                "Fixture_Dx10.exe",
                Role::Game,
                Ok(facts(Machine::X86, d3d10, Some([1, 2, 0, 0]))),
            ),
            cand(
                "Fixture_Dx9.exe",
                Role::Game,
                Ok(facts(Machine::X86, one(GraphicsApi::D3d9), None)),
            ),
        ],
        Main::Tied(vec![0, 1]),
        Vec::new(),
    );
    assert_eq!(
        shown(&render_game(&a, &e)),
        "  app 15100 (installed): Fixture Creed
    install folder: Fixture Creed
    main executable: a tie between 2 executables, none picked
    tied: Fixture_Dx10.exe
      x86 (not large address aware), API d3d10 (also d3d9), version 1.2.0.0
    tied: Fixture_Dx9.exe
      x86 (not large address aware), API d3d9, no version
"
    );
}

#[test]
fn none_with_each_reason() {
    let a = app(7, "Fixture Tool", "Fixture Tool", 4);
    let head = "  app 7 (installed): Fixture Tool\n    install folder: Fixture Tool\n";
    let cases = [
        (
            exes(Vec::new(), Main::None, Vec::new()),
            "    main executable: none (no executable found)\n",
        ),
        (
            exes(
                vec![cand(
                    "launcher.exe",
                    Role::Launcher,
                    Ok(facts(Machine::X64, one(GraphicsApi::D3d11), None)),
                )],
                Main::None,
                Vec::new(),
            ),
            "    main executable: none (no game executable among 1 executable)\n",
        ),
        (
            exes(
                vec![
                    cand("game.exe", Role::Game, Err(parse_error("game.exe"))),
                    cand("game2.exe", Role::Game, Err(parse_error("game2.exe"))),
                    cand("setup.exe", Role::Installer, Err(parse_error("setup.exe"))),
                ],
                Main::None,
                Vec::new(),
            ),
            "    main executable: none (2 game executables failed to open or parse)
    issue: game.exe: file ends inside a structure at offset 0x3c
    issue: game2.exe: file ends inside a structure at offset 0x3c
",
        ),
    ];
    for (e, tail) in cases {
        assert_eq!(shown(&render_game(&a, &e)), format!("{head}{tail}"));
    }
}

#[test]
fn hashes_done_and_skipped() {
    let a = app(1, "Fixture", "Fixture", 4);
    let mut done = facts(Machine::X64, one(GraphicsApi::Vulkan), None);
    done.hashes = HashOutcome::Done(Hashes {
        len: 3,
        sha1: "A9993E364706816ABA3E25717850C26C9CD0D89D".to_owned(),
        sha256: "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD".to_owned(),
    });
    let mut skipped = facts(Machine::Arm64, one(GraphicsApi::D3d12), None);
    skipped.hashes = HashOutcome::Skipped(HashSkip::TooLarge { max: 1024 });
    let e = exes(
        vec![
            cand("a.exe", Role::Game, Ok(done)),
            cand("b.exe", Role::Game, Ok(skipped)),
        ],
        Main::Tied(vec![0, 1]),
        Vec::new(),
    );
    let text = shown(&render_game(&a, &e));
    assert!(
        text.contains(
            "    tied: a.exe
      x64, API vulkan, no version
      SHA-1 A9993E364706816ABA3E25717850C26C9CD0D89D, SHA-256 \
             BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD (3 bytes)
    tied: b.exe
      arm64, API d3d12, no version
      hashes: skipped: larger than 1024 bytes
"
        ),
        "{text}"
    );
}

#[test]
fn a_failed_hash_names_its_file_escaped() {
    // A tag character is no control character and no `is_deceptive` one: a valid RelPath.
    let hostile = "game\u{E0041}.exe";
    assert!(RelPath::parse(hostile).is_ok());
    let a = app(1, "Fixture", "Fixture", 4);
    let mut f = facts(Machine::X64, one(GraphicsApi::D3d11), None);
    f.hashes = HashOutcome::Failed(HashError::Inspect(Box::new(parse_error(hostile))));
    let e = exes(
        vec![cand("ok.exe", Role::Game, Ok(f))],
        Main::One(0),
        Vec::new(),
    );
    let text = shown(&render_game(&a, &e));
    assert!(
        text.ends_with(
            "      hashes: \"failed: game\\u{e0041}.exe: file ends inside a structure at offset \
             0x3c\"\n"
        ),
        "{text}"
    );
}

#[test]
fn failed_game_executables_are_issues_whatever_the_main_executable() {
    let a = app(2, "Fixture", "Fixture", 4);
    let e = exes(
        vec![
            cand(
                "game.exe",
                Role::Game,
                Ok(facts(Machine::X64, one(GraphicsApi::D3d11), None)),
            ),
            cand(
                "game_dx12.exe",
                Role::Game,
                Err(parse_error("game_dx12.exe")),
            ),
            cand("setup.exe", Role::Installer, Err(parse_error("setup.exe"))),
        ],
        Main::One(0),
        Vec::new(),
    );
    assert_eq!(
        shown(&render_game(&a, &e)),
        "  app 2 (installed): Fixture
    install folder: Fixture
    main executable: game.exe
      x64, API d3d11, no version
    issue: game_dx12.exe: file ends inside a structure at offset 0x3c
"
    );
    let mut counts = ScanCounts::default();
    super::tally(&mut counts, &e);
    assert_eq!((counts.one, counts.issues), (1, 1));
}

#[test]
fn an_incomplete_walk_is_one_line() {
    let a = app(3, "Fixture", "Fixture", 4);
    let mut e = exes(Vec::new(), Main::None, Vec::new());
    e.stats.depth_cut = 2;
    let head = "  app 3 (installed): Fixture
    install folder: Fixture
    main executable: none (no executable found)
";
    assert_eq!(
        shown(&render_game(&a, &e)),
        format!(
            "{head}    walk: 2 folders deeper than 3 levels not listed (the list of executables \
             may be incomplete)\n"
        )
    );
    e.stats.complete = false;
    e.stats.depth_cut = 1;
    assert_eq!(
        shown(&render_game(&a, &e)),
        format!(
            "{head}    walk: 1 folder deeper than 3 levels not listed; stopped at a limit (the \
             list of executables may be incomplete)\n"
        )
    );
    e.stats.depth_cut = 0;
    assert!(
        shown(&render_game(&a, &e)).ends_with(
            "    walk: stopped at a limit (the list of executables may be incomplete)\n"
        )
    );
}

#[test]
fn no_walk_line_when_a_main_executable_was_found() {
    let a = app(4, "Fixture", "Fixture", 4);
    let game = || {
        cand(
            "game.exe",
            Role::Game,
            Ok(facts(Machine::X64, one(GraphicsApi::D3d11), None)),
        )
    };
    for main in [Main::One(0), Main::Tied(vec![0, 1])] {
        let mut e = exes(vec![game(), game()], main, Vec::new());
        e.stats.depth_cut = 5;
        e.stats.complete = false;
        let text = shown(&render_game(&a, &e));
        assert!(!text.contains("    walk: "), "{text}");
    }
}

#[test]
fn an_empty_or_blank_label_is_no_line() {
    let lib = rerun_core::path::RootPath::new(r"D:\SteamLibrary").unwrap();
    let head = "library 1: D:\\SteamLibrary\n";
    for label in ["", "   "] {
        let label = RawText::new(label);
        assert_eq!(shown(&super::render_library(1, &lib, Some(&label))), head);
    }
    assert_eq!(shown(&super::render_library(1, &lib, None)), head);
    // A tab is escaped, so the label is quoted and shown.
    let tab = RawText::new("\t");
    assert_eq!(
        shown(&super::render_library(1, &lib, Some(&tab))),
        format!("{head}  label: \"\\t\"\n")
    );
    let games = RawText::new("Games");
    assert_eq!(
        shown(&super::render_library(1, &lib, Some(&games))),
        format!("{head}  label: Games\n")
    );
}

#[test]
fn apps_that_are_not_opened_show_their_state() {
    assert_eq!(
        shown(&render_app(&app(
            3,
            "Fixture Pending",
            "Fixture Pending",
            4 | 2
        ))),
        "  app 3 (update pending; not opened): Fixture Pending\n"
    );
    assert_eq!(
        shown(&render_app(&app(
            4,
            "Fixture Partial",
            "Fixture Partial",
            1026
        ))),
        "  app 4 (not installed; not opened): Fixture Partial\n"
    );
}

#[test]
fn the_summary_and_the_hint() {
    let counts = ScanCounts {
        libraries: 2,
        apps: 5,
        installed: 3,
        pending: 1,
        not_installed: 1,
        one: 1,
        tied: 1,
        none: 1,
        issues: 4,
    };
    assert_eq!(
        shown(&render_summary(counts)),
        "
Summary: 2 libraries, 5 apps (3 installed, 1 update pending, 1 not installed); main executable: \
1 found, 1 tie, 1 without; 4 issues
Roles and APIs are hints from names and imports, not verdicts.
"
    );
    let single = ScanCounts {
        libraries: 1,
        apps: 1,
        issues: 1,
        tied: 2,
        ..ScanCounts::default()
    };
    assert!(shown(&render_summary(single)).contains(
        "Summary: 1 library, 1 app (0 installed, 0 update pending, 0 not installed); main \
             executable: 0 found, 2 ties, 0 without; 1 issue"
    ));
}

#[test]
fn untrusted_fields_are_escaped() {
    let hostile = "Evil\u{1b}[2J\u{202E}Name\u{2028}\u{E0041}\u{E007F}";
    let a = app(9, hostile, "Fixture", 4 | 2);
    assert_eq!(
        shown(&render_app(&a)),
        "  app 9 (update pending; not opened): \"Evil\\u{1b}[2J\\u{202e}Name\\u{2028}\\u{e0041}\\u{e007f}\"\n"
    );
    let label = RawText::new(hostile);
    let lib = rerun_core::path::RootPath::new(r"D:\SteamLibrary").unwrap();
    assert_eq!(
        shown(&super::render_library(1, &lib, Some(&label))),
        "library 1: D:\\SteamLibrary\n  label: \"Evil\\u{1b}[2J\\u{202e}Name\\u{2028}\\u{e0041}\\u{e007f}\"\n"
    );
    // An anomalous file name in a walk issue: escaped by the core ({:?}) and again by the
    // output (the whole issue text).
    let issue = ExeIssue {
        at: Some(rel("bin")),
        kind: ExeIssueKind::Anomaly(Anomaly {
            name: hostile.to_owned(),
            reason: "forbidden character",
        }),
    };
    let e = exes(Vec::new(), Main::None, vec![issue]);
    let text = shown(&render_game(&app(9, "Fixture", "Fixture", 4), &e));
    let line = text.lines().last().unwrap();
    assert!(line.starts_with("    issue: "), "{text}");
    assert!(!line.chars().any(|c| c.is_control()), "{line:?}");
    assert!(
        !line.contains('\u{202E}') && !line.contains('\u{E0041}'),
        "{line:?}"
    );
}

// ---------- End to end, against the fake system layer ----------

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const STEAM: &str = r"C:\Program Files (x86)\Steam";
const LIB: &str = r"D:\SteamLibrary";
/// A SteamID-shaped account value in every manifest; it must appear nowhere.
const LAST_OWNER: &str = "76500000000000001";
/// Content of the refused manifests; it must appear nowhere.
const MARK: &str = "SECRETMARKER";

fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

fn library_folders(libs: &[(&str, &str)]) -> String {
    let mut out = String::from("\"libraryfolders\"\n{\n");
    for (i, (path, label)) in libs.iter().enumerate() {
        out.push_str(&format!(
            "\t\"{i}\"\n\t{{\n\t\t\"path\"\t\t{}\n\t\t\"label\"\t\t{}\n\t}}\n",
            q(path),
            q(label)
        ));
    }
    out.push_str("}\n");
    out
}

fn acf(app_id: u32, name: &str, install_dir: &str, flags: u32) -> String {
    format!(
        "\"AppState\"\n{{\n\t\"appid\"\t\t\"{app_id}\"\n\t\"name\"\t\t{}\n\t\"StateFlags\"\t\t\"{flags}\"\n\t\"installdir\"\t\t{}\n\t\"LastOwner\"\t\t\"{LAST_OWNER}\"\n}}\n",
        q(name),
        q(install_dir)
    )
}

trait Fixture: Sized {
    fn file_in(self, folder: &str, rel: &str, content: &[u8]) -> Self;

    fn manifest(self, library: &str, app_id: u32, content: &str) -> Self {
        self.file_in(
            library,
            &format!(r"steamapps\appmanifest_{app_id}.acf"),
            content.as_bytes(),
        )
    }

    /// A manifest and a game folder with `exes` (name, image).
    fn game(
        self,
        library: &str,
        app_id: u32,
        name: &str,
        dir: &str,
        flags: u32,
        exes: &[(&str, Vec<u8>)],
    ) -> Self {
        let mut b = self.manifest(library, app_id, &acf(app_id, name, dir, flags));
        for (exe, image) in exes {
            b = b.file_in(library, &format!(r"steamapps\common\{dir}\{exe}"), image);
        }
        b
    }
}

impl Fixture for FakeSystemBuilder {
    fn file_in(self, folder: &str, rel: &str, content: &[u8]) -> Self {
        self.file(Path::new(folder).join(rel), content.to_vec())
    }
}

fn x86_d3d9() -> Vec<u8> {
    pe_image::image_for(pe_image::I386, &["kernel32.dll", "d3d9.dll"], &[], 0)
}

fn x64_d3d11() -> Vec<u8> {
    pe_image::image_for(
        pe_image::AMD64,
        &["kernel32.dll", "dxgi.dll", "d3d11.dll"],
        &[],
        0,
    )
}

/// The fake Windows layout with Rerun's install folder.
fn base() -> FakeSystemBuilder {
    FakeSystem::builder().windows_layout().dir(INSTALL)
}

/// Steam with two libraries: two good games, an app Steam is updating, one not installed,
/// and the malicious manifests of ADR 0016.
fn steam() -> FakeSystemBuilder {
    let hostile = "Evil\u{1b}]0;title\u{7}\u{202E}Name\u{E0041}";
    let nested = format!(
        "\"AppState\"\n{{\n\t\"name\"\t\"{MARK}\"\n{}{}}}\n",
        "\"a\" {\n".repeat(20),
        "}\n".repeat(20)
    );
    let huge = acf(1_000_006, &MARK.repeat(100_000), "Huge Game", 4);
    assert!(huge.len() > 1 << 20);
    base()
        .value(
            RootSource::CurrentUser.key(),
            RootSource::CurrentUser.value_name(),
            RegValue::String(STEAM.to_owned()),
        )
        .file_in(
            STEAM,
            r"steamapps\libraryfolders.vdf",
            library_folders(&[(STEAM, ""), (LIB, &format!("Games{hostile}"))]).as_bytes(),
        )
        .game(
            STEAM,
            1_000_001,
            "Fixture Game",
            "Fixture Game",
            4,
            &[
                ("FixtureGame.exe", x86_d3d9()),
                ("launcher.exe", x86_d3d9()),
            ],
        )
        .game(
            LIB,
            1_000_002,
            hostile,
            "Evil Game",
            4,
            &[("evil.exe", x64_d3d11())],
        )
        .game(
            LIB,
            1_000_003,
            "Fixture Pending",
            "Pending Game",
            4 | 2,
            &[("pending.exe", x86_d3d9())],
        )
        .game(
            LIB,
            1_000_004,
            "Fixture Partial",
            "Partial Game",
            1026,
            &[("partial.exe", x86_d3d9())],
        )
        // Malicious manifests: `..` as installdir, over 1 MiB, nested too deep, a missing
        // required field. Each with a game folder that must never be opened.
        .manifest(LIB, 1_000_005, &acf(1_000_005, MARK, "..", 4))
        .manifest(LIB, 1_000_006, &huge)
        .file_in(LIB, r"steamapps\common\Huge Game\huge.exe", &x86_d3d9())
        .manifest(LIB, 1_000_007, &nested)
        .manifest(
            LIB,
            1_000_008,
            &acf(1_000_008, MARK, "Missing Game", 4).replace("\"installdir\"", "\"other\""),
        )
        .file_in(
            LIB,
            r"steamapps\common\Missing Game\missing.exe",
            &x86_d3d9(),
        )
}

struct Run {
    exit: Exit,
    stdout: String,
    stderr: String,
    /// Names of every directory component the scan opened (read or write capability).
    opened: Vec<String>,
}

fn run(sys: &FakeSystem, app_ids: &[u32], hashes: bool) -> Run {
    let opened = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&opened);
    sys.fake_fs().on_step(move |_, ev| {
        if matches!(ev.op, FsOp::OpenDir | FsOp::OpenDirWrite)
            && let Ok(mut v) = seen.lock()
        {
            v.push(ev.name.clone());
        }
    });
    let (mut out, mut err) = (Out::new(Vec::new()), Out::new(Vec::new()));
    let exit = scan(sys, Path::new(INSTALL), app_ids, hashes, &mut out, &mut err);
    sys.fake_fs().clear_on_step();
    let opened = opened.lock().unwrap().clone();
    Run {
        exit,
        stdout: String::from_utf8(out.into_inner()).unwrap(),
        stderr: String::from_utf8(err.into_inner()).unwrap(),
        opened,
    }
}

const FULL: &str = r#"Steam: found through HKCU\Software\Valve\Steam SteamPath
  issue: library D:\SteamLibrary, steamapps entry "appmanifest_1000005.acf": anomalous name "..": '.' or '..' segment
  issue: library D:\SteamLibrary, steamapps entry "appmanifest_1000006.acf": steamapps\appmanifest_1000006.acf: too large: steamapps\appmanifest_1000006.acf, more than 1048576 bytes
  issue: library D:\SteamLibrary, steamapps entry "appmanifest_1000007.acf": steamapps\appmanifest_1000007.acf: nesting deeper than 16 at byte 130 (line 19, column 5)
  issue: library D:\SteamLibrary, steamapps entry "appmanifest_1000008.acf": "installdir" missing in the object at byte 0

library 0: C:\Program Files (x86)\Steam
  app 1000001 (installed): Fixture Game
    install folder: Fixture Game
    main executable: FixtureGame.exe
      x86 (large address aware), API d3d9, no version

library 1: D:\SteamLibrary
  label: "GamesEvil\u{1b}]0;title\u{7}\u{202e}Name\u{e0041}"
  app 1000002 (installed): "Evil\u{1b}]0;title\u{7}\u{202e}Name\u{e0041}"
    install folder: Evil Game
    main executable: evil.exe
      x64, API d3d11, no version
  app 1000003 (update pending; not opened): Fixture Pending
  app 1000004 (not installed; not opened): Fixture Partial

Summary: 2 libraries, 4 apps (2 installed, 1 update pending, 1 not installed); main executable: 2 found, 0 ties, 0 without; 4 issues
Roles and APIs are hints from names and imports, not verdicts.
"#;

#[test]
fn a_steam_installation_with_malicious_manifests() {
    let sys = steam().build().unwrap();
    let r = run(&sys, &[], false);
    assert_eq!(r.exit, Exit::Report);
    assert_eq!(r.stderr, "");
    assert_eq!(r.stdout, FULL);
    // Never file content, never the account field.
    for s in [&r.stdout, &r.stderr] {
        assert!(!s.contains(MARK), "{s}");
        assert!(!s.contains(LAST_OWNER), "{s}");
    }
    // The game folders of apps that are not installed, being updated or refused are never
    // opened; the two installed games are.
    for dir in [
        "Pending Game",
        "Partial Game",
        "Huge Game",
        "Missing Game",
        "..",
    ] {
        assert!(!r.opened.iter().any(|n| n == dir), "{dir}: {:?}", r.opened);
    }
    for dir in ["Fixture Game", "Evil Game"] {
        assert!(r.opened.iter().any(|n| n == dir), "{dir}: {:?}", r.opened);
    }
}

#[test]
fn the_account_field_is_in_no_scan_result() {
    let sys = steam().build().unwrap();
    let fr = ForbiddenRoots::resolve(&sys, Path::new(INSTALL)).unwrap();
    let s = steam::scan(&sys, &fr);
    let mut debug = format!("{s:?}");
    for lib in &s.libraries {
        for app in lib.apps() {
            if let Ok(game) = lib.open_game(&fr, app.app_id) {
                let exes = rerun_core::detect::exe::scan_game(&game, &Default::default());
                debug.push_str(&format!("{exes:?}"));
            }
        }
    }
    assert!(debug.contains("1000002"), "{debug}");
    assert!(!debug.contains(LAST_OWNER), "{debug}");
    assert!(!debug.contains(MARK), "{debug}");
}

#[test]
fn requested_app_ids_filter_and_unknown_ones_are_reported() {
    let sys = steam().build().unwrap();
    let r = run(&sys, &[1_000_002, 42, 1_000_003, 42], false);
    assert_eq!(r.exit, Exit::Report);
    let tail = r.stdout.split("library 1:").nth(1).unwrap();
    assert_eq!(
        tail,
        r#" D:\SteamLibrary
  label: "GamesEvil\u{1b}]0;title\u{7}\u{202e}Name\u{e0041}"
  app 1000002 (installed): "Evil\u{1b}]0;title\u{7}\u{202e}Name\u{e0041}"
    install folder: Evil Game
    main executable: evil.exe
      x64, API d3d11, no version
  app 1000003 (update pending; not opened): Fixture Pending

app 42: not found in any library

Summary: 2 libraries, 2 apps (1 installed, 1 update pending, 0 not installed); main executable: 1 found, 0 ties, 0 without; 4 issues
Roles and APIs are hints from names and imports, not verdicts.
"#
    );
    assert!(!r.stdout.contains("app 1000001"), "{}", r.stdout);
    assert!(
        !r.opened.iter().any(|n| n == "Fixture Game"),
        "{:?}",
        r.opened
    );
}

#[test]
fn hashes_warn_on_stderr_and_hash_the_main_executable() {
    let sys = steam().build().unwrap();
    let r = run(&sys, &[1_000_001], true);
    assert_eq!(r.exit, Exit::Report);
    assert_eq!(
        r.stderr,
        "warning: --hashes reads every game executable in full; can take minutes on a cold \
         cache\n"
    );
    let line = r
        .stdout
        .lines()
        .find(|l| l.starts_with("      SHA-1 "))
        .unwrap_or_else(|| panic!("{}", r.stdout));
    let hex = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
    };
    let sha1 = &line[12..52];
    assert!(hex(sha1) && sha1.len() == 40, "{line}");
    assert!(line.contains(", SHA-256 "), "{line}");
    assert!(line.ends_with(" (1024 bytes)"), "{line}");
}

#[test]
fn steam_not_installed_is_a_report_with_exit_0() {
    let sys = base().build().unwrap();
    let r = run(&sys, &[], false);
    assert_eq!(r.exit, Exit::Report);
    assert_eq!(
        r.stdout,
        "Steam: not found

Summary: 0 libraries, 0 apps (0 installed, 0 update pending, 0 not installed); main executable: \
0 found, 0 ties, 0 without; 0 issues
Roles and APIs are hints from names and imports, not verdicts.
"
    );
}

#[test]
fn unresolvable_forbidden_roots_exit_1_without_a_report() {
    let sys = steam()
        .without_known_folder(KnownFolder::ProgramData)
        .build()
        .unwrap();
    let r = run(&sys, &[], true);
    assert_eq!(r.exit, Exit::Fatal);
    assert_eq!(r.stdout, "");
    let lines: Vec<&str> = r.stderr.lines().collect();
    assert_eq!(lines.len(), 2, "{}", r.stderr);
    assert!(lines[0].starts_with("warning: --hashes"), "{}", r.stderr);
    assert!(
        lines[1].starts_with("rerun: cannot resolve the folders that must never be scanned: "),
        "{}",
        r.stderr
    );
    assert!(r.opened.is_empty(), "{:?}", r.opened);
}

#[test]
fn a_closed_pipe_ends_the_scan_silently() {
    let sys = steam().build().unwrap();
    for (kind, exit) in [
        (io::ErrorKind::BrokenPipe, Exit::Report),
        (io::ErrorKind::PermissionDenied, Exit::Fatal),
    ] {
        let mut out = Out::new(Failing {
            kind,
            ok: 3,
            written: Vec::new(),
        });
        let mut err = Out::new(Vec::new());
        assert_eq!(
            scan(&sys, Path::new(INSTALL), &[], false, &mut out, &mut err),
            exit
        );
        let err = String::from_utf8(err.into_inner()).unwrap();
        assert_eq!(err.is_empty(), exit == Exit::Report, "{err}");
    }
}

#[test]
fn an_installed_app_without_its_folder_is_one_issue() {
    let sys = base()
        .value(
            RootSource::CurrentUser.key(),
            RootSource::CurrentUser.value_name(),
            RegValue::String(STEAM.to_owned()),
        )
        .manifest(
            STEAM,
            1_000_009,
            &acf(1_000_009, "Fixture Soundtrack", "Fixture Soundtrack", 4),
        )
        .build()
        .unwrap();
    let r = run(&sys, &[], false);
    assert_eq!(r.exit, Exit::Report);
    // The second issue is the missing library file (a Steam issue above the libraries).
    let steam_issues = r.stdout.lines().filter(|l| l.starts_with("  issue: "));
    assert_eq!(steam_issues.count(), 1, "{}", r.stdout);
    let body = r.stdout.split("library 0:").nth(1).unwrap();
    assert_eq!(
        body,
        r#" C:\Program Files (x86)\Steam
  app 1000009 (installed): Fixture Soundtrack
    install folder: Fixture Soundtrack
    issue: game folder not opened: not found: steamapps\common\Fixture Soundtrack

Summary: 1 library, 1 app (1 installed, 0 update pending, 0 not installed); main executable: 0 found, 0 ties, 1 without; 2 issues
Roles and APIs are hints from names and imports, not verdicts.
"#
    );
}
