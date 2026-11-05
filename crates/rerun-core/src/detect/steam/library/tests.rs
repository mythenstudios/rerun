use std::path::Path;

use super::{MAX_LIBRARIES, MAX_MANIFESTS, SteamLibrary, apps, libraries, manifest_id};
use crate::detect::steam::issue::{Issue, IssueKind, Location};
use crate::detect::steam::testfx::{
    STEAM, SteamFixture, acf, base, fr, legacy_folders, library_folders,
};
use crate::detect::steam::{AppState, StateFlags};
use crate::detect::vdf::VdfReadError;
use crate::path::{RelPath, RootPath};
use crate::policy::root::{Forbidden, RootError, StoreDir};
use crate::sys::SysErrorKind;
use crate::sys::fake::FakeSystem;
use crate::sys::fs::{EntryKind, tag};

const LIB: &str = r"D:\SteamLibrary";
const LIB2: &str = r"E:\Games\Steam Library";

fn rp(s: &str) -> RootPath {
    RootPath::new(s).unwrap()
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

/// One library as the tests compare it: path, label and app IDs.
#[derive(Debug, PartialEq, Eq)]
struct Shown {
    path: RootPath,
    label: Option<String>,
    apps: Vec<u32>,
}

fn shown(lib: &SteamLibrary<'_>) -> Shown {
    Shown {
        path: lib.path().clone(),
        label: lib.label().map(|l| l.as_raw_str().to_owned()),
        apps: lib.apps().iter().map(|a| a.app_id).collect(),
    }
}

fn lib(path: &str, label: Option<&str>, apps: &[u32]) -> Shown {
    Shown {
        path: rp(path),
        label: label.map(str::to_owned),
        apps: apps.to_vec(),
    }
}

/// The libraries of the Steam root `root` and the issues.
fn run_at(sys: &FakeSystem, root: &str) -> (Vec<Shown>, Vec<Issue>) {
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(root)).unwrap();
    let mut issues = Vec::new();
    let libs = libraries(sys, &fr, store, &mut issues);
    (libs.iter().map(shown).collect(), issues)
}

fn run(sys: &FakeSystem) -> (Vec<Shown>, Vec<Issue>) {
    run_at(sys, STEAM)
}

fn file_at(file: &str) -> Location {
    Location::LibraryFile {
        root: rp(STEAM),
        file: rel(file),
    }
}

fn entry_at(index: usize) -> Location {
    Location::LibraryEntry {
        root: rp(STEAM),
        file: rel(r"steamapps\libraryfolders.vdf"),
        index,
    }
}

fn manifest_at(library: &str, name: &str) -> Location {
    Location::Manifest {
        library: rp(library),
        name: name.to_owned(),
    }
}

fn root_err(issue: &Issue) -> &RootError {
    match &issue.kind {
        IssueKind::Root(e) => e.as_ref(),
        other => panic!("expected Root, got {other:?}"),
    }
}

fn sys_kind(issue: &Issue) -> SysErrorKind {
    match &issue.kind {
        IssueKind::Sys(e) => e.kind,
        IssueKind::VdfRead(VdfReadError::Open { source, .. }) => source.kind,
        other => panic!("expected a system error, got {other:?}"),
    }
}

// ---------- Library list ----------

#[test]
fn the_current_format_lists_the_root_again_and_it_is_deduplicated_silently() {
    let sys = base()
        .dir(LIB)
        .dir(LIB2)
        .library_file(
            STEAM,
            &library_folders(&[(STEAM, ""), (LIB, "Fast SSD"), (LIB2, "")]),
        )
        .app(STEAM, 10, "Ten", "Ten")
        .app(LIB, 20, "Twenty", "Twenty")
        .build()
        .unwrap();
    let (libs, issues) = run(&sys);
    assert_eq!(
        libs,
        [
            lib(STEAM, None, &[10]),
            lib(LIB, Some("Fast SSD"), &[20]),
            // No steamapps: no apps and an issue.
            lib(LIB2, Some(""), &[]),
        ]
    );
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(issues[0].at, Location::Library(rp(LIB2)));
    assert_eq!(sys_kind(&issues[0]), SysErrorKind::NotFound);
}

#[test]
fn the_format_before_2021_does_not_list_the_root_and_it_is_library_0_anyway() {
    let sys = base()
        .dir(r"D:\Lib\steamapps")
        .library_file(STEAM, &legacy_folders(&[r"D:\Lib"]))
        .dir(format!(r"{STEAM}\steamapps"))
        .build()
        .unwrap();
    assert_eq!(
        run(&sys),
        (
            vec![lib(STEAM, None, &[]), lib(r"D:\Lib", None, &[])],
            vec![]
        )
    );
}

#[test]
fn the_config_file_is_read_only_if_the_steamapps_file_is_not_found() {
    // The file is missing, then the whole `steamapps` folder.
    for with_steamapps in [true, false] {
        let mut b = base().dir(LIB).file_in(
            STEAM,
            r"config\libraryfolders.vdf",
            &library_folders(&[(LIB, "")]),
        );
        if with_steamapps {
            b = b.dir(format!(r"{STEAM}\steamapps"));
        }
        let sys = b.dir(format!(r"{LIB}\steamapps")).build().unwrap();
        let (libs, issues) = run(&sys);
        assert_eq!(
            libs,
            [lib(STEAM, None, &[]), lib(LIB, Some(""), &[])],
            "{with_steamapps}"
        );
        // Only the root's missing steamapps is reported, never the missing library file.
        let expected = usize::from(!with_steamapps);
        assert_eq!(issues.len(), expected, "{issues:?}");
    }
}

#[test]
fn a_damaged_or_locked_steamapps_file_is_an_issue_and_never_falls_back() {
    let config = library_folders(&[(LIB, "")]);
    // A parse error, a view error, a directory, a restricted file, a file symlink.
    let cases: Vec<(&str, FakeSystem)> = vec![
        (
            "parse",
            base()
                .library_file(STEAM, "\"libraryfolders\" { #include \"x\" }")
                .build()
                .unwrap(),
        ),
        (
            "view",
            base()
                .library_file(STEAM, "\"libraryfolders\" { \"0\" { \"label\" \"x\" } }")
                .build()
                .unwrap(),
        ),
        (
            "directory",
            base()
                .dir(format!(r"{STEAM}\steamapps\libraryfolders.vdf"))
                .build()
                .unwrap(),
        ),
        (
            "restricted",
            base()
                .library_file(STEAM, &config)
                .restricted(format!(r"{STEAM}\steamapps\libraryfolders.vdf"))
                .build()
                .unwrap(),
        ),
        (
            "symlink",
            base()
                .dir(format!(r"{STEAM}\steamapps"))
                .file_symlink(
                    format!(r"{STEAM}\steamapps\libraryfolders.vdf"),
                    r"C:\Elsewhere\libraryfolders.vdf",
                )
                .file(
                    r"C:\Elsewhere\libraryfolders.vdf",
                    config.clone().into_bytes(),
                )
                .build()
                .unwrap(),
        ),
    ];
    for (what, sys) in cases {
        // The config file would list another library: it must never be used.
        sys.fake_fs()
            .put_file(
                &Path::new(STEAM).join(r"config\libraryfolders.vdf"),
                config.as_bytes(),
            )
            .unwrap();
        sys.fake_fs().mkdir_all(Path::new(LIB)).unwrap();
        let (libs, issues) = run(&sys);
        assert_eq!(libs.len(), 1, "{what}: {libs:?}");
        assert_eq!(libs[0].path, rp(STEAM), "{what}");
        let file_issue = issues
            .iter()
            .find(|i| matches!(i.at, Location::LibraryFile { .. }))
            .unwrap_or_else(|| panic!("{what}: {issues:?}"));
        assert_eq!(
            file_issue.at,
            file_at(r"steamapps\libraryfolders.vdf"),
            "{what}"
        );
        match (what, &file_issue.kind) {
            ("parse", IssueKind::VdfRead(VdfReadError::Parse { .. }))
            | ("view", IssueKind::View(_)) => {}
            ("directory" | "restricted", _) => {
                assert_eq!(sys_kind(file_issue), SysErrorKind::AccessDenied, "{what}");
            }
            ("symlink", _) => {
                assert_eq!(sys_kind(file_issue), SysErrorKind::ReparsePoint, "{what}");
            }
            (_, other) => panic!("{what}: {other:?}"),
        }
    }
}

#[test]
fn neither_file_is_library_0_with_one_issue() {
    let sys = base().dir(format!(r"{STEAM}\steamapps")).build().unwrap();
    let (libs, issues) = run(&sys);
    assert_eq!(libs, [lib(STEAM, None, &[])]);
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(issues[0].at, file_at(r"steamapps\libraryfolders.vdf"));
    assert_eq!(sys_kind(&issues[0]), SysErrorKind::NotFound);
}

#[test]
fn a_damaged_config_file_is_reported_with_its_own_name() {
    let sys = base()
        .dir(format!(r"{STEAM}\steamapps"))
        .file_in(STEAM, r"config\libraryfolders.vdf", "{")
        .build()
        .unwrap();
    let (libs, issues) = run(&sys);
    assert_eq!(libs, [lib(STEAM, None, &[])]);
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(issues[0].at, file_at(r"config\libraryfolders.vdf"));
    assert!(matches!(
        issues[0].kind,
        IssueKind::VdfRead(VdfReadError::Parse { .. })
    ));
}

#[test]
fn the_two_files_are_never_merged() {
    let sys = base()
        .dir(format!(r"{LIB}\steamapps"))
        .dir(format!(r"{LIB2}\steamapps"))
        .dir(format!(r"{STEAM}\steamapps"))
        .library_file(STEAM, &library_folders(&[(LIB, "")]))
        .file_in(
            STEAM,
            r"config\libraryfolders.vdf",
            &library_folders(&[(LIB2, "")]),
        )
        .build()
        .unwrap();
    assert_eq!(
        run(&sys),
        (vec![lib(STEAM, None, &[]), lib(LIB, Some(""), &[])], vec![])
    );
}

#[test]
fn a_refused_library_is_an_issue_and_the_others_go_on() {
    let sys = base()
        .dir(format!(r"{LIB}\steamapps"))
        .dir(format!(r"{STEAM}\steamapps"))
        .mounted_volume(r"F:\Mounted")
        .library_file(
            STEAM,
            &library_folders(&[
                (STEAM, ""),
                (r"C:\Windows\System32", ""),
                (r"\\nas\games\SteamLibrary", ""),
                (r"G:\Gone", ""),
                ("relative", ""),
                ("", ""),
                (r"F:\Mounted", ""),
                (LIB, "last"),
            ]),
        )
        .build()
        .unwrap();
    let (libs, issues) = run(&sys);
    assert_eq!(libs, [lib(STEAM, None, &[]), lib(LIB, Some("last"), &[])]);
    let at: Vec<&Location> = issues.iter().map(|i| &i.at).collect();
    assert_eq!(
        at,
        [
            &entry_at(1),
            &entry_at(2),
            &entry_at(3),
            &entry_at(4),
            &entry_at(5),
            &entry_at(6)
        ]
    );
    assert!(matches!(
        root_err(&issues[0]),
        RootError::Forbidden {
            reason: Forbidden::Inside(_),
            ..
        }
    ));
    for i in [1, 3, 4] {
        assert!(
            matches!(root_err(&issues[i]), RootError::InvalidPath(_)),
            "{i}"
        );
    }
    assert!(matches!(root_err(&issues[2]), RootError::Sys(e) if e.kind == SysErrorKind::NotFound));
    assert!(matches!(
        root_err(&issues[5]),
        RootError::Forbidden {
            reason: Forbidden::VolumeRoot,
            ..
        }
    ));
    assert_eq!(
        issues[2].to_string(),
        r"C:\Program Files (x86)\Steam\steamapps\libraryfolders.vdf, library entry 3: not found: G:\Gone"
    );
}

#[test]
fn libraries_are_deduplicated_by_identity_first_occurrence_wins() {
    // A junction to a library, the same library spelled differently, and the root again.
    let sys = base()
        .dir(format!(r"{LIB}\steamapps"))
        .dir(format!(r"{STEAM}\steamapps"))
        .junction(r"C:\LibLink", LIB)
        .library_file(
            STEAM,
            &library_folders(&[
                (r"C:\LibLink", "via junction"),
                (STEAM, "root"),
                ("d:/steamlibrary/", "spelled"),
                (LIB, "plain"),
            ]),
        )
        .build()
        .unwrap();
    assert_eq!(
        run(&sys),
        (
            vec![lib(STEAM, None, &[]), lib(LIB, Some("via junction"), &[])],
            vec![]
        )
    );
}

#[test]
fn at_most_256_libraries_are_listed() {
    let at_limit: Vec<(&str, &str)> = vec![(LIB, ""); MAX_LIBRARIES];
    let sys = base()
        .dir(format!(r"{LIB}\steamapps"))
        .dir(format!(r"{STEAM}\steamapps"))
        .library_file(STEAM, &library_folders(&at_limit))
        .build()
        .unwrap();
    assert_eq!(
        run(&sys),
        (vec![lib(STEAM, None, &[]), lib(LIB, Some(""), &[])], vec![])
    );

    let over: Vec<(&str, &str)> = vec![(LIB, ""); MAX_LIBRARIES + 1];
    let sys = base()
        .dir(format!(r"{LIB}\steamapps"))
        .dir(format!(r"{STEAM}\steamapps"))
        .library_file(STEAM, &library_folders(&over))
        .build()
        .unwrap();
    let (libs, issues) = run(&sys);
    assert_eq!(libs, [lib(STEAM, None, &[])]);
    assert_eq!(
        issues,
        [Issue {
            at: file_at(r"steamapps\libraryfolders.vdf"),
            kind: IssueKind::TooManyLibraries {
                count: 257,
                max: 256
            },
        }]
    );
}

// ---------- steamapps ----------

#[test]
fn a_missing_junctioned_restricted_or_case_sensitive_steamapps_has_no_apps() {
    let manifest = acf(10, "Ten", "Ten", 4);
    let cases: Vec<(&str, FakeSystem)> = vec![
        ("missing", base().dir(LIB).build().unwrap()),
        (
            "junction",
            base()
                .file_in(r"D:\Moved", "appmanifest_10.acf", &manifest)
                .junction(format!(r"{LIB}\steamapps"), r"D:\Moved")
                .build()
                .unwrap(),
        ),
        (
            "restricted",
            base()
                .file_in(LIB, r"steamapps\appmanifest_10.acf", &manifest)
                .restricted(format!(r"{LIB}\steamapps"))
                .build()
                .unwrap(),
        ),
        (
            "case-sensitive",
            base()
                .case_sensitive_dir(format!(r"{LIB}\steamapps"))
                .file_in(LIB, r"steamapps\appmanifest_10.acf", &manifest)
                .build()
                .unwrap(),
        ),
    ];
    for (what, sys) in cases {
        let (libs, issues) = run_at(&sys, LIB);
        // The library itself has no library file (it is not a Steam root here): skip that one.
        let issues: Vec<&Issue> = issues
            .iter()
            .filter(|i| i.at == Location::Library(rp(LIB)))
            .collect();
        assert_eq!(libs, [lib(LIB, None, &[])], "{what}");
        assert_eq!(issues.len(), 1, "{what}: {issues:?}");
        match what {
            "missing" => assert_eq!(sys_kind(issues[0]), SysErrorKind::NotFound),
            "junction" => assert_eq!(sys_kind(issues[0]), SysErrorKind::ReparsePoint),
            "restricted" => assert_eq!(sys_kind(issues[0]), SysErrorKind::AccessDenied),
            _ => assert_eq!(issues[0].kind, IssueKind::CaseSensitiveSteamapps),
        }
    }
}

// ---------- Manifests ----------

/// The apps of `LIB` with the given limit, and the issues (without the library file's).
fn apps_of(sys: &FakeSystem, max: usize) -> (Vec<super::SteamApp>, Vec<Issue>) {
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(LIB)).unwrap();
    let mut issues = Vec::new();
    let apps = apps(&store, max, &mut issues);
    (apps, issues)
}

#[test]
fn manifest_names() {
    assert_eq!(manifest_id("appmanifest_10.acf"), Some("10"));
    assert_eq!(manifest_id("AppManifest_10.ACF"), Some("10"));
    assert_eq!(manifest_id("appmanifest_.acf"), Some(""));
    assert_eq!(manifest_id("appmanifest_x.y.acf"), Some("x.y"));
    for other in [
        "appmanifest.acf",
        "appmanifest_10.acf.tmp",
        "appmanifest_10.vdf",
        "xappmanifest_10.acf",
        "libraryfolders.vdf",
        "appmanifest_10.ac",
        "",
        "ä",
        "appmanifest_1ä.acf\u{0}",
        // Kelvin sign: not an ASCII `k`, so no case folding.
        "appmanifest_1.\u{212A}cf",
    ] {
        assert_eq!(manifest_id(other), None, "{other:?}");
    }
}

#[test]
fn apps_are_read_sorted_and_other_names_ignored() {
    let sys = base()
        .file_in(
            LIB,
            r"steamapps\appmanifest_300.acf",
            &acf(300, "Three", "Three", 4),
        )
        .file_in(
            LIB,
            r"steamapps\APPMANIFEST_20.ACF",
            &acf(20, "Two", "Two", 6),
        )
        .file_in(
            LIB,
            r"steamapps\appmanifest_1000001.acf",
            &acf(1_000_001, "One", "One", 0),
        )
        .file_in(LIB, r"steamapps\appmanifest_5.acf.tmp", "garbage")
        .file_in(LIB, r"steamapps\libraryfolders.vdf", "garbage")
        .file_in(LIB, r"steamapps\workshop\appworkshop_5.acf", "garbage")
        .dir(format!(r"{LIB}\steamapps\common"))
        .build()
        .unwrap();
    let (apps, issues) = apps_of(&sys, MAX_MANIFESTS);
    assert_eq!(issues, []);
    let got: Vec<(u32, &str, &str, AppState, &str)> = apps
        .iter()
        .map(|a| {
            (
                a.app_id,
                a.name.as_raw_str(),
                a.install_dir.as_str(),
                a.state(),
                a.manifest.as_str(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                20,
                "Two",
                "Two",
                AppState::UpdatePending,
                r"steamapps\APPMANIFEST_20.ACF"
            ),
            (
                300,
                "Three",
                "Three",
                AppState::Installed,
                r"steamapps\appmanifest_300.acf"
            ),
            (
                1_000_001,
                "One",
                "One",
                AppState::NotInstalled,
                r"steamapps\appmanifest_1000001.acf"
            ),
        ]
    );
    assert_eq!(apps[0].state_flags, StateFlags::new(6));
}

#[test]
fn a_bad_app_id_in_the_name_is_an_issue_and_the_file_is_not_read() {
    let names = [
        "appmanifest_.acf",
        "appmanifest_0.acf",
        "appmanifest_01.acf",
        "appmanifest_+1.acf",
        "appmanifest_1a.acf",
        "appmanifest_ 1.acf",
        "appmanifest_4294967296.acf",
        "appmanifest_12345678901.acf",
        "appmanifest_\u{FF11}.acf",
    ];
    let mut b = base().dir(format!(r"{LIB}\steamapps"));
    for n in names {
        // Valid content: only the name decides.
        b = b.raw_file(
            format!(r"{LIB}\steamapps"),
            n,
            acf(1, "N", "D", 4).into_bytes(),
        );
    }
    let sys = b.build().unwrap();
    let (apps, issues) = apps_of(&sys, MAX_MANIFESTS);
    assert_eq!(apps, []);
    let mut got: Vec<(String, IssueKind)> = issues
        .into_iter()
        .map(|i| match i.at {
            Location::Manifest { name, .. } => (name, i.kind),
            other => panic!("{other:?}"),
        })
        .collect();
    got.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected: Vec<(String, IssueKind)> = names
        .iter()
        .map(|n| ((*n).to_owned(), IssueKind::ManifestName))
        .collect();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(got, expected);
}

#[test]
fn a_manifest_that_is_not_a_plain_file_is_never_opened() {
    let sys = base()
        .dir(format!(r"{LIB}\steamapps\appmanifest_1.acf"))
        .file_symlink(format!(r"{LIB}\steamapps\appmanifest_2.acf"), r"C:\x.acf")
        .junction(format!(r"{LIB}\steamapps\appmanifest_3.acf"), r"C:\")
        .file_in(
            LIB,
            r"steamapps\appmanifest_4.acf",
            &acf(4, "Four", "Four", 4),
        )
        .restricted(format!(r"{LIB}\steamapps\appmanifest_4.acf"))
        .tagged_file(
            format!(r"{LIB}\steamapps\appmanifest_5.acf"),
            acf(5, "Five", "Five", 4).into_bytes(),
            tag::APPEXECLINK,
        )
        // An allowlisted data tag is a plain file.
        .tagged_file(
            format!(r"{LIB}\steamapps\appmanifest_6.acf"),
            acf(6, "Six", "Six", 4).into_bytes(),
            tag::WOF,
        )
        .build()
        .unwrap();
    let (apps, issues) = apps_of(&sys, MAX_MANIFESTS);
    assert_eq!(apps.iter().map(|a| a.app_id).collect::<Vec<_>>(), [6]);
    let mut got: Vec<(String, IssueKind)> = issues
        .into_iter()
        .map(|i| match i.at {
            Location::Manifest { name, .. } => (name, i.kind),
            other => panic!("{other:?}"),
        })
        .collect();
    got.sort_by(|a, b| a.0.cmp(&b.0));
    let entry = |kind, restricted| IssueKind::ManifestEntry { kind, restricted };
    assert_eq!(
        got,
        [
            ("appmanifest_1.acf".into(), entry(EntryKind::Dir, false)),
            ("appmanifest_2.acf".into(), entry(EntryKind::Reparse, false)),
            ("appmanifest_3.acf".into(), entry(EntryKind::Reparse, false)),
            ("appmanifest_4.acf".into(), entry(EntryKind::File, true)),
            ("appmanifest_5.acf".into(), entry(EntryKind::Reparse, false)),
        ]
    );
}

#[test]
fn the_manifest_must_agree_with_its_name_and_name_a_valid_install_folder() {
    let mut b = base()
        .file_in(
            LIB,
            r"steamapps\appmanifest_7.acf",
            &acf(8, "Eight", "Eight", 4),
        )
        .file_in(
            LIB,
            r"steamapps\appmanifest_9.acf",
            &acf(9, "Nine", "Nine", 4),
        );
    let bad_dirs = [
        r"..\..\Windows",
        "a/b",
        "..",
        "CON",
        "x.",
        "",
        "C:",
        "PROGRA~1",
        "a\u{202E}b",
    ];
    for (i, d) in bad_dirs.iter().enumerate() {
        let id = 100 + u32::try_from(i).unwrap();
        b = b.file_in(
            LIB,
            &format!(r"steamapps\appmanifest_{id}.acf"),
            &acf(id, "Bad", d, 4),
        );
    }
    let sys = b.build().unwrap();
    let (apps, issues) = apps_of(&sys, MAX_MANIFESTS);
    assert_eq!(apps.iter().map(|a| a.app_id).collect::<Vec<_>>(), [9]);
    assert_eq!(issues.len(), 1 + bad_dirs.len(), "{issues:?}");
    let mismatch = issues
        .iter()
        .find(|i| i.at == manifest_at(LIB, "appmanifest_7.acf"))
        .unwrap();
    assert_eq!(
        mismatch.kind,
        IssueKind::AppIdMismatch {
            file: 7,
            manifest: 8
        }
    );
    assert_eq!(
        mismatch.to_string(),
        r#"library D:\SteamLibrary, steamapps entry "appmanifest_7.acf": file name says app 7, the manifest says app 8; app dropped"#
    );
    for i in issues.iter().filter(|i| i.at != mismatch.at) {
        assert!(matches!(i.kind, IssueKind::Anomaly(_)), "{i:?}");
    }
}

#[test]
fn a_broken_manifest_is_an_issue_and_the_others_go_on() {
    let sys = base()
        .file_in(LIB, r"steamapps\appmanifest_1.acf", "\"AppState\" {")
        .file_in(
            LIB,
            r"steamapps\appmanifest_2.acf",
            "\"AppState\" { \"appid\" \"2\" }",
        )
        .file_in(
            LIB,
            r"steamapps\appmanifest_3.acf",
            &"x".repeat((1 << 20) + 1),
        )
        .file_in(
            LIB,
            r"steamapps\appmanifest_4.acf",
            &acf(4, "Four", "Four", 4),
        )
        .build()
        .unwrap();
    let (apps, issues) = apps_of(&sys, MAX_MANIFESTS);
    assert_eq!(apps.iter().map(|a| a.app_id).collect::<Vec<_>>(), [4]);
    assert_eq!(issues.len(), 3, "{issues:?}");
    for i in &issues {
        assert!(
            matches!(
                i.kind,
                IssueKind::VdfRead(VdfReadError::Parse { .. }) | IssueKind::View(_)
            ),
            "{i:?}"
        );
    }
}

#[test]
fn at_most_max_manifests_and_never_a_partial_list() {
    let sys = base()
        .file_in(LIB, r"steamapps\appmanifest_1.acf", &acf(1, "A", "A", 4))
        .file_in(LIB, r"steamapps\appmanifest_2.acf", &acf(2, "B", "B", 4))
        // Bad names and non-files count: the limit is on names, before anything is opened.
        .file_in(LIB, r"steamapps\appmanifest_0.acf", "")
        .dir(format!(r"{LIB}\steamapps\appmanifest_3.acf"))
        .file_in(LIB, r"steamapps\other.acf", "")
        .build()
        .unwrap();
    let (apps, issues) = apps_of(&sys, 4);
    assert_eq!(apps.len(), 2);
    assert_eq!(issues.len(), 2, "{issues:?}");

    let (apps, issues) = apps_of(&sys, 3);
    assert_eq!(apps, []);
    assert_eq!(
        issues,
        [Issue {
            at: Location::Library(rp(LIB)),
            kind: IssueKind::TooManyManifests { count: 4, max: 3 },
        }]
    );
}

#[test]
fn the_shipped_manifest_limit_refuses_one_more_without_reading_any() {
    let mut b = base().dir(format!(r"{LIB}\steamapps"));
    for id in 1..=MAX_MANIFESTS + 1 {
        // Unparsable content: reading even one would add an issue.
        b = b.file_in(LIB, &format!(r"steamapps\appmanifest_{id}.acf"), "{");
    }
    let sys = b.build().unwrap();
    let (apps, issues) = apps_of(&sys, MAX_MANIFESTS);
    assert_eq!(apps, []);
    assert_eq!(
        issues,
        [Issue {
            at: Location::Library(rp(LIB)),
            kind: IssueKind::TooManyManifests {
                count: 16_385,
                max: 16_384
            },
        }]
    );
}
