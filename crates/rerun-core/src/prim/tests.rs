//! T9: the `file_install` planner against the fake (P2-8, C2). The fixtures are shared with
//! the `exec` tests.

use std::path::Path;

use super::{FileEntry, FileInstallSpec, PlanCtx, Step, plan};
use crate::path::RelPath;
use crate::plan::tests::sha;
use crate::plan::{ContentRef, FileState, Op, Plan, PlanError, PlanOrigin, RootIx};
use crate::policy::root::{AppDir, Create, ForbiddenRoots, GameDir, StoreDir};
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::fs::{Attrs, tag};

pub(crate) const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
pub(crate) const PKG: &str = r"C:\Users\Player\AppData\Local\Rerun\packages\fix-pack\1.0.2";
pub(crate) const GAME: &str = r"D:\Games\G";
pub(crate) const STEAM_LIB: &str = r"D:\SteamLibrary";
pub(crate) const STEAM_GAME: &str = r"D:\SteamLibrary\steamapps\common\G";

pub(crate) fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

/// The fake Windows layout, `HKCU\Software`, Rerun's install folder and the game folder [`GAME`] with its main
/// executable `game.exe` (a plan names it, and it must be a file there, audit A2 should-item
/// 8).
pub(crate) fn builder() -> FakeSystemBuilder {
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(GAME)
        .file(format!(r"{GAME}\game.exe"), b"MZ".to_vec())
        .key(crate::sys::registry::RegKey::new(
            crate::sys::registry::Hive::CurrentUser,
            crate::sys::registry::RegView::Native,
            "Software",
        ))
}

pub(crate) fn fr(sys: &FakeSystem) -> ForbiddenRoots {
    ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap_or_else(|e| panic!("{e}"))
}

pub(crate) fn app(sys: &FakeSystem) -> AppDir<'_> {
    AppDir::open(sys, Create::IfMissing).unwrap().unwrap()
}

/// A package file `from` with `data` and its target `to`.
pub(crate) fn entry(from: &str, to: &str, data: &[u8]) -> FileEntry {
    FileEntry {
        from: rel(from),
        to: rel(to),
        sha256: sha(data),
        config: false,
    }
}

pub(crate) fn spec(files: Vec<FileEntry>) -> FileInstallSpec {
    FileInstallSpec {
        package: "fix-pack".to_owned(),
        version: "1.0.2".to_owned(),
        files,
    }
}

/// Plans `spec` for the manual game folder [`GAME`].
pub(crate) fn plan_manual(sys: &FakeSystem, s: &FileInstallSpec) -> Result<Plan, PlanError> {
    let fr = fr(sys);
    let game = GameDir::open_manual(sys, &fr, Path::new(GAME)).unwrap();
    let app = app(sys);
    let main = rel("game.exe");
    plan(
        &[Step::FileInstall(s.clone())],
        &PlanCtx {
            game: &game,
            app: Some(&app),
            steam_app: None,
            main_exe: Some(&main),
            reg: crate::policy::registry::RegPolicy.reader(sys),
        },
    )
}

fn pkg(name: &str) -> String {
    format!(r"{PKG}\{name}")
}

fn game(name: &str) -> String {
    format!(r"{GAME}\{name}")
}

fn content(from: &str, data: &[u8], config: bool) -> ContentRef {
    ContentRef::Package {
        id: "fix-pack".to_owned(),
        version: "1.0.2".to_owned(),
        file: rel(from),
        sha256: sha(data),
        len: u64::try_from(data.len()).unwrap(),
        config,
    }
}

#[test]
fn t9_plans_folders_top_down_new_files_and_replaces() {
    let rh = Attrs {
        readonly: true,
        hidden: true,
        system: false,
    };
    let sys = builder()
        .file(pkg(r"bin\d3d9.dll"), b"new d3d9".to_vec())
        .file(pkg("x.ini"), b"[x]".to_vec())
        .file(pkg("y.txt"), b"y".to_vec())
        .file(pkg("same.txt"), b"same".to_vec())
        .file(game("d3d9.dll"), b"old d3d9".to_vec())
        .readonly_file(game("same.txt"), b"same".to_vec())
        .dir(game("existing"))
        .build()
        .unwrap();
    sys.fake_fs()
        .set_attrs(Path::new(&game("d3d9.dll")), rh)
        .unwrap();
    let mut ini = entry("x.ini", r"mods\a\x.ini", b"[x]");
    ini.config = true;
    let s = spec(vec![
        entry(r"bin\d3d9.dll", "D3D9.dll", b"new d3d9"),
        ini,
        entry("y.txt", r"MODS\a\y.txt", b"y"),
        entry("same.txt", "same.txt", b"same"),
        entry("y.txt", r"EXISTING\New\y.txt", b"y"),
        entry("y.txt", r"existing\new\z.txt", b"y"),
    ]);
    let p = plan_manual(&sys, &s).unwrap();
    assert_eq!(p.roots.len(), 1);
    assert_eq!(p.roots[0].origin, PlanOrigin::Manual);
    assert_eq!(p.roots[0].main_exe, Some(rel("game.exe")));
    let root = RootIx(0);
    assert_eq!(
        p.ops,
        vec![
            Op::ReplaceFile {
                root,
                path: rel("d3d9.dll"),
                old: FileState {
                    sha256: sha(b"old d3d9"),
                    len: 8,
                    attrs: rh,
                },
                content: content(r"bin\d3d9.dll", b"new d3d9", false),
                attrs: Attrs::default(),
            },
            Op::CreateDir {
                root,
                path: rel("mods"),
            },
            Op::CreateDir {
                root,
                path: rel(r"mods\a"),
            },
            Op::CreateFile {
                root,
                path: rel(r"mods\a\x.ini"),
                content: content("x.ini", b"[x]", true),
                attrs: Attrs::default(),
            },
            Op::CreateFile {
                root,
                path: rel(r"mods\a\y.txt"),
                content: content("y.txt", b"y", false),
                attrs: Attrs::default(),
            },
            Op::CreateDir {
                root,
                path: rel(r"existing\New"),
            },
            Op::CreateFile {
                root,
                path: rel(r"existing\New\y.txt"),
                content: content("y.txt", b"y", false),
                attrs: Attrs::default(),
            },
            Op::CreateFile {
                root,
                path: rel(r"existing\New\z.txt"),
                content: content("y.txt", b"y", false),
                attrs: Attrs::default(),
            },
        ],
        "B1: same.txt has the content already (other attributes): no op"
    );
    // A2-B1 (`==` on a path folds, so the spelling is compared on its own): an existing
    // segment in its stored spelling whatever the step says, a segment the plan creates in
    // the spelling of the first step that creates it, a new file as the step spells it.
    let spelled: Vec<&str> = p
        .ops
        .iter()
        .filter_map(|o| match o.target() {
            crate::plan::Target::File { path, .. } => Some(path.as_str()),
            crate::plan::Target::Key { .. } | crate::plan::Target::Value { .. } => None,
        })
        .collect();
    assert_eq!(
        spelled,
        [
            "d3d9.dll",
            "mods",
            r"mods\a",
            r"mods\a\x.ini",
            r"mods\a\y.txt",
            r"existing\New",
            r"existing\New\y.txt",
            r"existing\New\z.txt",
        ]
    );
    // Planning again gives the same bytes.
    assert_eq!(
        plan_manual(&sys, &s).unwrap().encode().unwrap(),
        p.encode().unwrap()
    );
    // A spec without files: a plan without ops.
    let empty = plan_manual(&sys, &spec(Vec::new())).unwrap();
    assert!(empty.ops.is_empty());
}

#[test]
fn t9_a_steam_root_needs_its_app_and_a_manual_root_has_none() {
    let sys = builder()
        .file(format!(r"{STEAM_GAME}\game.exe"), b"MZ".to_vec())
        .build()
        .unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let game = store.game(&fr, "G").unwrap();
    let app = app(&sys);
    let ctx = |steam_app| PlanCtx {
        game: &game,
        app: Some(&app),
        steam_app,
        main_exe: None,
        reg: crate::policy::registry::RegPolicy.reader(&sys),
    };
    let p = plan(&[], &ctx(Some(220))).unwrap();
    assert!(matches!(
        &p.roots[0].origin,
        PlanOrigin::Steam { app_id: 220, installdir, store: s, .. }
            if installdir.as_str() == "G" && s == store.path()
    ));
    for bad in [None, Some(0)] {
        assert!(matches!(plan(&[], &ctx(bad)), Err(PlanError::Step(_))));
    }
    let manual = GameDir::open_manual(&sys, &fr, Path::new(GAME)).unwrap();
    let c = PlanCtx {
        game: &manual,
        app: Some(&app),
        steam_app: Some(220),
        main_exe: None,
        reg: crate::policy::registry::RegPolicy.reader(&sys),
    };
    assert!(matches!(plan(&[], &c), Err(PlanError::Step(_))));
}

#[test]
fn t9_refusals() {
    type Setup = fn(FakeSystemBuilder) -> FakeSystemBuilder;
    let ok = entry("a.dll", "a.dll", b"a");
    let base: Setup = |b| b.file(pkg("a.dll"), b"a".to_vec());
    let cases: Vec<(&str, Setup, Vec<FileEntry>, &str)> = vec![
        (
            "no package",
            |b| b,
            vec![ok.clone()],
            "not in Rerun's packages",
        ),
        (
            "source missing",
            base,
            vec![entry("b.dll", "b.dll", b"b")],
            "missing",
        ),
        (
            "source hash",
            base,
            vec![entry("a.dll", "a.dll", b"other")],
            "SHA-256",
        ),
        (
            "source is a folder",
            |b| b.dir(pkg("a.dll")),
            vec![ok.clone()],
            "is a folder",
        ),
        (
            "source link",
            |b| b.file_symlink(pkg("a.dll"), r"C:\x"),
            vec![ok.clone()],
            "link",
        ),
        (
            "source below a junction",
            |b| {
                b.file(r"C:\elsewhere\a.dll", b"a".to_vec())
                    .junction(pkg("sub"), r"C:\elsewhere")
            },
            vec![entry(r"sub\a.dll", "a.dll", b"a")],
            "reparse",
        ),
        (
            "source restricted",
            |b| b.file(pkg("a.dll"), b"a".to_vec()).restricted(pkg("a.dll")),
            vec![ok.clone()],
            "current user",
        ),
        (
            "target twice",
            base,
            vec![ok.clone(), entry("a.dll", "A.DLL", b"a")],
            "twice",
        ),
        (
            "target below another",
            base,
            vec![ok.clone(), entry("a.dll", r"a.dll\b.dll", b"a")],
            "twice or an ancestor",
        ),
        (
            "target is a folder",
            |b| b.file(pkg("a.dll"), b"a".to_vec()).dir(game("a.dll")),
            vec![ok.clone()],
            "is a folder",
        ),
        (
            "target hard-linked",
            |b| {
                b.file(pkg("a.dll"), b"a".to_vec())
                    .file(game("a.dll"), b"x".to_vec())
                    .hardlink(game("a.dll"), game("b.dll"))
            },
            vec![ok.clone()],
            "hard-linked",
        ),
        (
            "target link",
            |b| {
                b.file(pkg("a.dll"), b"a".to_vec())
                    .file_symlink(game("a.dll"), "x")
            },
            vec![ok.clone()],
            "link",
        ),
        (
            "target cloud placeholder",
            |b| {
                b.file(pkg("a.dll"), b"a".to_vec()).tagged_file(
                    game("a.dll"),
                    b"x".to_vec(),
                    tag::CLOUD,
                )
            },
            vec![ok.clone()],
            "cloud",
        ),
        (
            "target restricted",
            |b| {
                b.file(pkg("a.dll"), b"a".to_vec())
                    .file(game("a.dll"), b"x".to_vec())
                    .restricted(game("a.dll"))
            },
            vec![ok.clone()],
            "current user",
        ),
        (
            "a file on the way",
            |b| {
                b.file(pkg("a.dll"), b"a".to_vec())
                    .file(game("sub"), b"x".to_vec())
            },
            vec![entry("a.dll", r"sub\a.dll", b"a")],
            "not a plain folder",
        ),
        (
            "a junction on the way",
            |b| {
                b.file(pkg("a.dll"), b"a".to_vec())
                    .junction(game("sub"), r"C:\x")
            },
            vec![entry("a.dll", r"sub\a.dll", b"a")],
            "not a plain folder",
        ),
        (
            "case-sensitive on the way",
            |b| {
                b.file(pkg("a.dll"), b"a".to_vec())
                    .case_sensitive_dir(game("sub"))
            },
            vec![entry("a.dll", r"sub\a.dll", b"a")],
            "case-sensitive",
        ),
    ];
    for (what, setup, files, want) in cases {
        let sys = setup(builder()).build().unwrap();
        let e = plan_manual(&sys, &spec(files)).expect_err(what).to_string();
        assert!(e.contains(want), "{what}: {e}");
    }
    // A2 should-item 8: the main executable is restricted, missing, a folder or a link.
    type Exe = fn(&FakeSystem);
    let exes: [(&str, Exe); 4] = [
        // Security N-3: D4 could not ask it.
        ("restricted", |s| {
            s.fake_fs()
                .set_restricted(Path::new(&game("game.exe")), true)
                .unwrap();
        }),
        ("missing", |s| {
            s.fake_fs()
                .remove_abs(Path::new(&game("game.exe")))
                .unwrap();
        }),
        ("a folder", |s| {
            s.fake_fs()
                .remove_abs(Path::new(&game("game.exe")))
                .unwrap();
            s.fake_fs().mkdir_all(Path::new(&game("game.exe"))).unwrap();
        }),
        ("a link", |s| {
            s.fake_fs()
                .remove_abs(Path::new(&game("game.exe")))
                .unwrap();
            s.fake_fs()
                .put_link(Path::new(&game("game.exe")), tag::SYMLINK, r"C:\x.exe")
                .unwrap();
        }),
    ];
    for (what, make) in exes {
        let sys = base(builder()).build().unwrap();
        make(&sys);
        let e = plan_manual(&sys, &spec(vec![ok.clone()]))
            .expect_err(what)
            .to_string();
        assert!(
            e.contains(r"the main executable game.exe is not a file"),
            "{what}: {e}"
        );
    }
    // Package names.
    let sys = base(builder()).build().unwrap();
    for (id, version) in [("Fix", "1"), ("fix", "1..2"), ("fix", ".1"), ("con", "1")] {
        let mut s = spec(vec![ok.clone()]);
        s.package = id.to_owned();
        s.version = version.to_owned();
        let e = plan_manual(&sys, &s).expect_err(id).to_string();
        assert!(e.contains("package ID"), "{id} {version}: {e}");
    }
    // The game folder needs the helper.
    let sys = base(builder()).build().unwrap();
    sys.fake_fs()
        .set_user_writable(Path::new(GAME), false)
        .unwrap();
    assert!(matches!(
        plan_manual(&sys, &spec(vec![ok.clone()])),
        Err(PlanError::NeedsHelper)
    ));
    // S1: only a plan with file ops needs write access (D4 reads); here every file is there
    // with its content, so the plan is empty and no helper is needed.
    sys_put_file(&sys, &game("a.dll"), b"a");
    let p = plan_manual(&sys, &spec(vec![ok.clone()])).unwrap();
    assert!(p.ops.is_empty(), "{:?}", p.ops);
    // 129 ops.
    let sys = base(builder()).build().unwrap();
    let many: Vec<FileEntry> = (0..129)
        .map(|i| entry("a.dll", &format!("f{i}.dll"), b"a"))
        .collect();
    assert!(matches!(
        plan_manual(&sys, &spec(many)),
        Err(PlanError::TooManyOps { n: 129, .. })
    ));
}

#[test]
fn t9_backups_over_4_gib_are_refused() {
    let sys = builder().build().unwrap();
    let mut p = plan_manual(&sys, &spec(Vec::new())).unwrap();
    p.ops = (0..3u8)
        .map(|i| Op::ReplaceFile {
            root: RootIx(0),
            path: rel(&format!("f{i}")),
            old: FileState {
                sha256: [i; 32],
                len: 2 << 30,
                attrs: Attrs::default(),
            },
            content: content("a", b"a", false),
            attrs: Attrs::default(),
        })
        .collect();
    let e = p.encode().unwrap_err().to_string();
    assert!(e.contains("4 GiB"), "{e}");
    p.ops.truncate(2);
    p.encode().unwrap();
}

/// Puts a fixture file (another program's write).
fn sys_put_file(sys: &FakeSystem, abs: &str, data: &[u8]) {
    sys.fake_fs().put_file(Path::new(abs), data).unwrap();
}
