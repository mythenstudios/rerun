use super::{SteamScan, scan};
use crate::detect::steam::AppState;
use crate::detect::steam::issue::{BadValue, Issue, IssueKind, Location};
use crate::detect::steam::root::RootSource;
use crate::detect::steam::testfx::{STEAM, SteamFixture, acf, base, fr, library_folders};
use crate::path::{RelPath, RootPath};
use crate::policy::root::{GameOrigin, RootError};
use crate::sys::SysErrorKind;
use crate::sys::registry::{RegValue, reg_type};

const LIB: &str = r"D:\SteamLibrary";
const LIB2: &str = r"E:\Steam Library";

fn rp(s: &str) -> RootPath {
    RootPath::new(s).unwrap()
}

/// `(library path, app IDs)` of a scan.
fn shape(scan: &SteamScan<'_>) -> Vec<(RootPath, Vec<u32>)> {
    scan.libraries
        .iter()
        .map(|l| {
            (
                l.path().clone(),
                l.apps().iter().map(|a| a.app_id).collect(),
            )
        })
        .collect()
}

/// Steam in its usual folder with one more library, as Steam writes it.
fn installed() -> crate::sys::fake::FakeSystemBuilder {
    base()
        .candidate_path(RootSource::CurrentUser, "c:/program files (x86)/steam")
        .candidate_path(RootSource::Machine32, STEAM)
        .library_file(STEAM, &library_folders(&[(STEAM, ""), (LIB, "Games")]))
        .app(STEAM, 228_980, "Fixture Redist", "Fixture Redist")
        .app(LIB, 1_000_001, "Fixture Game", "Fixture Game")
        .app(LIB, 1_000_002, "Fixture Other", "Fixture Other")
}

#[test]
fn steam_not_installed_is_an_empty_scan_without_issues() {
    let sys = base().build().unwrap();
    let fr = fr(&sys);
    let s = scan(&sys, &fr);
    assert_eq!(s.root, None);
    assert!(s.libraries.is_empty());
    assert_eq!(s.issues, []);
}

#[test]
fn a_full_installation() {
    let sys = installed()
        .file_in(
            LIB,
            r"steamapps\appmanifest_1000003.acf",
            &acf(1_000_003, "Fixture Updating", "Fixture Updating", 4 | 2),
        )
        .build()
        .unwrap();
    let fr = fr(&sys);
    let s = scan(&sys, &fr);
    assert_eq!(s.issues, []);
    assert_eq!(s.root, Some(RootSource::CurrentUser));
    assert_eq!(
        shape(&s),
        [
            (rp(STEAM), vec![228_980]),
            (rp(LIB), vec![1_000_001, 1_000_002, 1_000_003]),
        ]
    );
    let lib = &s.libraries[1];
    assert_eq!(lib.label().map(|l| l.as_raw_str()), Some("Games"));
    assert_eq!(s.libraries[0].label(), None);
    let states: Vec<AppState> = lib.apps().iter().map(|a| a.state()).collect();
    assert_eq!(
        states,
        [
            AppState::Installed,
            AppState::Installed,
            AppState::UpdatePending
        ]
    );

    // The game folder, handle-relative to its library.
    let game = lib.open_game(&fr, 1_000_001).unwrap();
    assert_eq!(
        game.path(),
        &rp(r"D:\SteamLibrary\steamapps\common\Fixture Game")
    );
    assert!(matches!(
        game.origin(),
        GameOrigin::Store { store, installdir, .. }
            if *store == rp(LIB) && *installdir == RelPath::parse("Fixture Game").unwrap()
    ));
    let exe = RelPath::parse("game.exe").unwrap();
    assert_eq!(game.dir().read(&exe).unwrap(), b"MZ");

    // An app of another library, an unknown ID, and an app without its folder.
    for id in [228_980, 42] {
        assert!(
            matches!(lib.open_game(&fr, id), Err(RootError::Sys(e)) if e.kind == SysErrorKind::NotFound),
            "{id}"
        );
    }
    assert!(matches!(
        lib.open_game(&fr, 1_000_003),
        Err(RootError::Sys(e)) if e.kind == SysErrorKind::NotFound
    ));
}

#[test]
fn a_junction_at_the_game_folder_is_refused_by_open_game() {
    let sys = installed()
        .file_in(
            LIB,
            r"steamapps\appmanifest_1000004.acf",
            &acf(1_000_004, "Linked", "Linked", 4),
        )
        .junction(format!(r"{LIB}\steamapps\common\Linked"), r"C:\Windows")
        .build()
        .unwrap();
    let fr = fr(&sys);
    let s = scan(&sys, &fr);
    assert_eq!(s.issues, []);
    assert!(matches!(
        s.libraries[1].open_game(&fr, 1_000_004),
        Err(RootError::Reparse { .. })
    ));
}

#[test]
fn a_disagreeing_root_is_not_scanned() {
    let sys = installed()
        .candidate_path(RootSource::Machine32, r"D:\Old Steam")
        .app(r"D:\Old Steam", 7, "Old", "Old")
        .build()
        .unwrap();
    let fr = fr(&sys);
    let s = scan(&sys, &fr);
    assert_eq!(shape(&s).len(), 2);
    assert!(s.libraries.iter().all(|l| l.app(7).is_none()));
    assert_eq!(s.issues.len(), 1, "{:?}", s.issues);
    assert_eq!(s.issues[0].at, Location::Registry(RootSource::Machine32));
    assert!(matches!(s.issues[0].kind, IssueKind::RootsDisagree { .. }));
}

#[test]
fn duplicate_app_ids_keep_every_copy_and_each_names_another_library() {
    let sys = installed()
        .library_file(
            STEAM,
            &library_folders(&[(STEAM, ""), (LIB, ""), (LIB2, "")]),
        )
        .app(STEAM, 1_000_001, "Copy A", "Copy A")
        .app(LIB2, 1_000_001, "Copy C", "Copy C")
        .app(LIB2, 1_000_002, "Copy D", "Copy D")
        .build()
        .unwrap();
    let fr = fr(&sys);
    let s = scan(&sys, &fr);
    assert_eq!(
        shape(&s),
        [
            (rp(STEAM), vec![228_980, 1_000_001]),
            (rp(LIB), vec![1_000_001, 1_000_002]),
            (rp(LIB2), vec![1_000_001, 1_000_002]),
        ]
    );
    let dup = |lib: &str, id: u32, other: &str, more: usize| Issue {
        at: Location::Manifest {
            library: rp(lib),
            name: format!("appmanifest_{id}.acf"),
        },
        kind: IssueKind::DuplicateApp {
            app_id: id,
            other: rp(other),
            more,
        },
    };
    assert_eq!(
        s.issues,
        [
            dup(STEAM, 1_000_001, LIB, 1),
            dup(LIB, 1_000_001, STEAM, 1),
            dup(LIB, 1_000_002, LIB2, 0),
            dup(LIB2, 1_000_001, STEAM, 1),
            dup(LIB2, 1_000_002, LIB, 0),
        ]
    );
    assert_eq!(
        s.issues[0].to_string(),
        r#"library C:\Program Files (x86)\Steam, steamapps entry "appmanifest_1000001.acf": app 1000001 is also in library D:\SteamLibrary and 1 more library"#
    );
    assert_eq!(
        s.issues[2].to_string(),
        r#"library D:\SteamLibrary, steamapps entry "appmanifest_1000002.acf": app 1000002 is also in library E:\Steam Library"#
    );
    // Each copy opens its own folder.
    let a = s.libraries[0].open_game(&fr, 1_000_001).unwrap();
    let b = s.libraries[1].open_game(&fr, 1_000_001).unwrap();
    assert_ne!(a.id(), b.id());
}

#[test]
fn nothing_read_from_files_or_the_registry_appears_in_the_output() {
    const MARK: &str = "SECRETMARKER";
    let labelled =
        library_folders(&[(STEAM, MARK), (LIB, MARK)]).replace("\"-1\"", &format!("\"{MARK}\""));
    let sys = installed()
        // Registry: a value that is refused.
        .candidate(
            RootSource::MachineNative,
            RegValue::ExpandString(format!(r"%{MARK}%\Steam")),
        )
        // A raw REG_SZ with a NUL in the middle, holding the marker on both sides.
        .raw_value(
            RootSource::Machine32.key(),
            RootSource::Machine32.value_name(),
            reg_type::REG_SZ,
            &utf16_with_nul(&format!(r"C:\{MARK}"), MARK),
        )
        .library_file(STEAM, &labelled)
        // Names of good apps, and fields that are ignored.
        .app(LIB, 1_000_005, MARK, "Marked")
        .file_in(
            LIB,
            r"steamapps\appmanifest_1000006.acf",
            &acf(1_000_006, MARK, "Universe", 4).replace("\"1\"", &format!("\"{MARK}\"")),
        )
        // Refused manifests whose content holds the marker.
        .file_in(
            LIB,
            r"steamapps\appmanifest_1000007.acf",
            &acf(1_000_008, MARK, "Mismatch", 4),
        )
        .file_in(
            LIB,
            r"steamapps\appmanifest_1000009.acf",
            &format!("\"AppState\" {{ \"name\" \"{MARK}\" #include \"{MARK}\" }}"),
        )
        .file_in(
            LIB,
            r"steamapps\appmanifest_1000010.acf",
            &format!("\"AppState\" {{ \"name\" \"{MARK}\" \"installdir\" \"{MARK}\" }}"),
        )
        .file_in(
            LIB,
            r"steamapps\appmanifest_1000011.acf",
            &format!("\"AppState\" {{ \"appid\" \"{MARK}\" \"name\" \"{MARK}\" \"installdir\" \"x\" \"StateFlags\" \"4\" }}"),
        )
        // A duplicate whose name holds the marker.
        .app(STEAM, 1_000_005, MARK, "Marked Too")
        .build()
        .unwrap();
    let fr = fr(&sys);
    let s = scan(&sys, &fr);
    // The marker really was read.
    assert_eq!(
        s.libraries[1].app(1_000_005).map(|a| a.name.as_raw_str()),
        Some(MARK)
    );
    assert_eq!(s.libraries[1].label().map(|l| l.as_raw_str()), Some(MARK));
    let kinds: Vec<&IssueKind> = s.issues.iter().map(|i| &i.kind).collect();
    assert!(kinds.contains(&&IssueKind::RegistryValue(BadValue::Unexpanded)));
    assert!(kinds.contains(&&IssueKind::RegistryValue(BadValue::InvalidString)));
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, IssueKind::AppIdMismatch { .. }))
    );
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, IssueKind::DuplicateApp { .. }))
    );
    assert!(
        kinds
            .iter()
            .filter(|k| matches!(k, IssueKind::VdfRead(_) | IssueKind::View(_)))
            .count()
            == 3
    );

    assert_no_marker(&s, MARK);

    // Library files refused by the parser and by the view, and a raw REG_SZ of odd length,
    // each holding the marker.
    let refused_files = [
        format!(
            "\"libraryfolders\" {{ \"0\" {{ \"label\" \"{MARK}\" \"path\" \"x\" }} #base \"{MARK}\" }}"
        ),
        format!(
            "\"libraryfolders\" {{ \"0\" {{ \"label\" \"{MARK}\" \"label\" \"{MARK}\" \"path\" \"{MARK}\" }} }}"
        ),
    ];
    for (i, content) in refused_files.iter().enumerate() {
        let mut odd = utf16_with_nul(MARK, MARK);
        odd.push(0x41);
        let sys = installed()
            .library_file(STEAM, content)
            .raw_value(
                RootSource::MachineNative.key(),
                RootSource::MachineNative.value_name(),
                reg_type::REG_SZ,
                &odd,
            )
            .build()
            .unwrap();
        let roots = crate::detect::steam::testfx::fr(&sys);
        let s = scan(&sys, &roots);
        let file_issue = s
            .issues
            .iter()
            .find(|i| matches!(i.at, Location::LibraryFile { .. }))
            .unwrap_or_else(|| panic!("{i}: {:?}", s.issues));
        let expected_parse = i == 0;
        assert_eq!(
            matches!(file_issue.kind, IssueKind::VdfRead(_)),
            expected_parse,
            "{file_issue:?}"
        );
        assert_eq!(
            matches!(file_issue.kind, IssueKind::View(_)),
            !expected_parse,
            "{file_issue:?}"
        );
        assert!(
            s.issues
                .iter()
                .any(|i| i.kind == IssueKind::RegistryValue(BadValue::InvalidString)),
            "{:?}",
            s.issues
        );
        assert_no_marker(&s, MARK);
    }
}

/// `a`, a NUL, `b`, a NUL, as UTF-16LE bytes: a raw `REG_SZ` with a NUL inside.
fn utf16_with_nul(a: &str, b: &str) -> Vec<u8> {
    a.encode_utf16()
        .chain([0])
        .chain(b.encode_utf16())
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Neither `{:?}`/`{:#?}` of the scan nor `Display`/`Debug` of any issue contains `mark`.
fn assert_no_marker(s: &SteamScan<'_>, mark: &str) {
    let shown = format!("{s:?}\n{s:#?}");
    assert!(!shown.contains(mark), "{shown}");
    for i in &s.issues {
        let shown = format!("{i}\n{i:?}\n{i:#?}");
        assert!(!shown.contains(mark), "{shown}");
        assert!(!i.to_string().is_empty());
    }
}

#[test]
fn every_issue_has_a_location_and_a_message() {
    // A messy installation: one of each kind of problem the scan reports.
    let sys = installed()
        .candidate(RootSource::MachineNative, RegValue::Dword(1))
        .library_file(
            STEAM,
            &library_folders(&[(STEAM, ""), (LIB, ""), (r"C:\Windows", ""), (LIB2, "")]),
        )
        .file_in(LIB, r"steamapps\appmanifest_01.acf", "")
        .dir(format!(r"{LIB}\steamapps\appmanifest_5.acf"))
        .file_in(
            LIB,
            r"steamapps\appmanifest_6.acf",
            &acf(6, "Six", r"..\..\Windows", 4),
        )
        .case_sensitive_dir(format!(r"{LIB2}\steamapps"))
        .build()
        .unwrap();
    let fr = fr(&sys);
    let s = scan(&sys, &fr);
    let lines: Vec<String> = s.issues.iter().map(ToString::to_string).collect();
    assert_eq!(lines.len(), 6, "{lines:#?}");
    let expected = [
        r"HKLM\SOFTWARE\Valve\Steam InstallPath (native view): registry type 4, not a string",
        r"C:\Program Files (x86)\Steam\steamapps\libraryfolders.vdf, library entry 2: C:\Windows is forbidden: is Windows",
        r"library D:\SteamLibrary, steamapps entry ",
        r"library D:\SteamLibrary, steamapps entry ",
        r"library D:\SteamLibrary, steamapps entry ",
        r"library E:\Steam Library: steamapps is case-sensitive; no apps read",
    ];
    for (line, start) in lines.iter().zip(expected) {
        assert!(
            line.starts_with(start),
            "{line}\n  does not start with\n{start}"
        );
    }
}

/// Scans the Steam installation of this machine through `WinSystem` (the test binary's folder
/// stands in for Rerun's install folder) and opens every app's game folder. Read-only: writes
/// no file, no registry value, nothing under `target/`. Prints app names and labels only as
/// their length and install folders only escaped; never run in CI, never commit the output.
/// Run by hand: `cargo test -p rerun-core --lib dump_steam_scan -- --ignored --nocapture`.
#[cfg(windows)]
#[test]
#[ignore = "reads this machine's Steam installation; run by hand, never in CI"]
fn dump_steam_scan() {
    use std::io::Write;
    use std::time::Instant;

    use crate::detect::steam::RawText;
    use crate::policy::root::ForbiddenRoots;
    use crate::sys::win::WinSystem;

    // Not captured by `cargo test` (like `sys::win::testfx::note`).
    let note = |msg: &str| {
        let _ = writeln!(std::io::stderr(), "{msg}");
    };
    let sys = WinSystem::new().unwrap_or_else(|e| panic!("{e}"));
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("current_exe: {e}"));
    let install = exe
        .parent()
        .unwrap_or_else(|| panic!("the test binary has no folder"));
    let fr = ForbiddenRoots::resolve(&sys, install).unwrap_or_else(|e| panic!("{e}"));

    let started = Instant::now();
    let s = scan(&sys, &fr);
    let took = started.elapsed();

    note(&format!(
        "steam root from: {}",
        s.root.map_or_else(|| "none".to_owned(), |r| r.to_string())
    ));
    let mut apps = 0;
    for (i, lib) in s.libraries.iter().enumerate() {
        note(&format!(
            "library {i}: {} (id {}), label {} bytes, {} apps",
            lib.path(),
            lib.id(),
            lib.label().map_or(0, RawText::len),
            lib.apps().len()
        ));
        for app in lib.apps() {
            apps += 1;
            let game = match lib.open_game(&fr, app.app_id) {
                Ok(g) => format!("game folder ok (id {})", g.id()),
                Err(e) => format!("game folder: {e}"),
            };
            note(&format!(
                "  app {} {} (flags {:#x}), name {} bytes, installdir {:?}: {game}",
                app.app_id,
                app.state(),
                app.state_flags.bits(),
                app.name.len(),
                app.install_dir.as_str()
            ));
        }
    }
    for issue in &s.issues {
        note(&format!("issue: {issue}"));
    }
    note(&format!(
        "steam: {} libraries, {apps} apps, {} issues, scan took {took:?}",
        s.libraries.len(),
        s.issues.len()
    ));
}
