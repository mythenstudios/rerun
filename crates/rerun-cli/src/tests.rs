//! In-process end-to-end tests of the phase 2 commands (P2-13, `docs/09-testing.md`, "CLI"):
//! the command line parsed by clap, run against the fake system layer with in-memory stdout and
//! stderr and a fake console. Never the real machine. Everything renders through `Out`, so the
//! last-resort net is checked to never fire. Test IDs C1 to C12 (the plan's E1 to E12, renamed
//! so they do not collide with the user decisions E1 to E7).

use std::io::{self, Write};
use std::path::Path;

use clap::Parser;

use rerun_core::journal::{InstanceTag, Journal};
use rerun_core::policy::root::{AppDir, Create};
use rerun_core::sys::System;
use rerun_core::sys::fake::{FakeSystem, FakeSystemBuilder, Prim};
use rerun_core::sys::registry::{Hive, RegKey, RegValue, RegView};
use rerun_core::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};

use crate::cli::{Cli, Exit};
use crate::confirm::{Answer, Confirm};
use crate::host::Host;
use crate::messages::Message;
use crate::out::Out;
use crate::out::tests::Failing;
use crate::run;

pub const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
pub const LAD: &str = r"C:\Users\Player\AppData\Local";
pub const RERUN: &str = r"C:\Users\Player\AppData\Local\Rerun";
pub const GAME: &str = r"D:\Games\G";
pub const STEPS: &str = r"D:\Work\steps.json";

pub const OLD: &[u8] = b"old d3d9 of the game";
pub const NEW: &[u8] = b"new d3d9 of the package";
pub const N: &[u8] = b"new.dll of the package";
const NEW_SHA: &str = "392019b0f5e6d29623d477a56357f39b4d21d5b7cc080fda0f3bde7033906419";
const N_SHA: &str = "0acdc09cbd66b723e0afcc433aaf095b0197716bff469db14357d555032cb30e";
pub const INI_TEXT: &[u8] = b"[Display]\r\nWidth=1280\r\nHeight=720\r\n";

fn pkg(name: &str) -> String {
    format!(r"{RERUN}\packages\fix-pack\1.0.2\{name}")
}

pub fn game(name: &str) -> String {
    format!(r"{GAME}\{name}")
}

fn hkcu(p: &str) -> RegKey {
    RegKey::new(Hive::CurrentUser, RegView::Native, p)
}

/// The fake Windows layout, `HKCU\Software`, Rerun's install folder and the game folder with
/// its main executable, a file a package replaces and an INI file. No `Rerun` folder.
pub fn bare() -> FakeSystemBuilder {
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(GAME)
        .file(game("game.exe"), b"MZ".to_vec())
        .file(game("d3d9.dll"), OLD.to_vec())
        .file(game("game.ini"), INI_TEXT.to_vec())
        .key(hkcu("Software"))
}

/// [`bare`] with a local package (so `Rerun\packages` exists).
pub fn with_package() -> FakeSystemBuilder {
    bare()
        .file(pkg("d3d9.dll"), NEW.to_vec())
        .file(pkg("new.dll"), N.to_vec())
}

/// The three steps of the round trip: a package (a replace, a new folder and file), two
/// registry values, an INI key.
pub fn all_steps() -> String {
    format!(
        r#"{{"format":1,"game":{{"folder":"D:\\Games\\G"}},"main_exe":"game.exe","steps":[{{"file_install":{{"package":"fix-pack","version":"1.0.2","files":[{{"from":"d3d9.dll","to":"d3d9.dll","sha256":"{NEW_SHA}"}},{{"from":"new.dll","to":"mods\\new.dll","sha256":"{N_SHA}"}}]}}}},{{"registry_set":{{"key":"HKCU\\Software\\Vendor\\Game","values":[{{"name":"Width","dword":1920}},{{"name":"Lang","sz":"en"}}]}}}},{{"ini_set":{{"file":"game.ini","values":[{{"section":"Display","key":"Width","value":"1920"}}]}}}}]}}"#
    )
}

/// One file of a package: `new.dll` into the game folder.
pub fn file_steps() -> String {
    format!(
        r#"{{"format":1,"game":{{"folder":"D:\\Games\\G"}},"main_exe":"game.exe","steps":[{{"file_install":{{"package":"fix-pack","version":"1.0.2","files":[{{"from":"new.dll","to":"new.dll","sha256":"{N_SHA}"}}]}}}}]}}"#
    )
}

/// Registry and INI only (no package: runs without Rerun's folder).
pub fn no_package_steps() -> String {
    r#"{"format":1,"game":{"folder":"D:\\Games\\G"},"main_exe":"game.exe","steps":[{"registry_set":{"key":"HKCU\\Software\\Vendor\\Game","values":[{"name":"Width","dword":1920}]}},{"ini_set":{"file":"game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}]}"#.to_owned()
}

/// Writes the step file.
pub fn put_steps(sys: &FakeSystem, json: &str) {
    sys.fake_fs()
        .put_file(Path::new(STEPS), json.as_bytes())
        .unwrap();
}

pub fn build(b: FakeSystemBuilder, steps: &str) -> FakeSystem {
    let sys = b.file(STEPS, steps.as_bytes().to_vec()).build().unwrap();
    sys.fake_fs().sync_all();
    sys
}

/// A fake console.
pub struct FakeConfirm {
    pub answer: Answer,
    pub asked: Vec<String>,
}

impl Confirm for FakeConfirm {
    fn ask(&mut self, q: &Message<'_>) -> Answer {
        self.asked.push(q.to_string());
        self.answer
    }
}

/// What one command printed and returned.
pub struct Ran {
    pub exit: Exit,
    pub stdout: String,
    pub stderr: String,
    pub asked: Vec<String>,
}

/// Runs `rerun <args>` with `answer` from the console and stdout into `w`.
pub fn run_to<W: Write>(sys: &FakeSystem, args: &[&str], answer: Answer, w: W) -> (Ran, W) {
    let cli = Cli::try_parse_from(std::iter::once("rerun").chain(args.iter().copied()))
        .unwrap_or_else(|e| panic!("{args:?}: {e}"));
    let mut c = FakeConfirm {
        answer,
        asked: Vec::new(),
    };
    let mut host = Host {
        sys,
        install: Ok(INSTALL.into()),
        confirm: &mut c,
    };
    let (mut out, mut err) = (Out::new(w), Out::new(Vec::new()));
    let exit = run(&mut host, cli.command, &mut out, &mut err);
    let ran = Ran {
        exit,
        stdout: String::new(),
        stderr: String::from_utf8(err.into_inner()).unwrap(),
        asked: c.asked,
    };
    (ran, out.into_inner())
}

/// Runs `rerun <args>` with `answer` from the console.
pub fn cli(sys: &FakeSystem, args: &[&str], answer: Answer) -> Ran {
    let (mut ran, out) = run_to(sys, args, answer, Vec::new());
    ran.stdout = String::from_utf8(out).unwrap();
    ran
}

/// `rerun <args>` that must exit with `exit`.
pub fn expect(sys: &FakeSystem, args: &[&str], answer: Answer, exit: Exit) -> Ran {
    let r = cli(sys, args, answer);
    assert_eq!(
        r.exit, exit,
        "{args:?}\nstdout:\n{}\nstderr:\n{}",
        r.stdout, r.stderr
    );
    r
}

/// The value after `prefix` on the line that starts with it.
pub fn after<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("no line {prefix:?} in:\n{text}"))
}

/// The plan hash of a `plan` run.
pub fn hash_of(r: &Ran) -> String {
    after(&r.stdout, "apply with: rerun apply ").to_owned()
}

/// The transaction of an `apply` run.
pub fn txn_of(r: &Ran) -> String {
    after(&r.stdout, "revert with: rerun revert ").to_owned()
}

/// Opens an absolute folder of the fake for a snapshot.
fn snap_dirs(sys: &FakeSystem, dirs: &[&str]) -> Snapshot {
    #[expect(
        clippy::disallowed_methods,
        reason = "test: snapshot fixture folders of the fake"
    )]
    let handles: Vec<_> = dirs
        .iter()
        .map(|d| sys.fs().open_dir(Path::new(d)).unwrap())
        .collect();
    snapshot(
        sys.registry(),
        &Scope {
            dirs: handles
                .iter()
                .zip(dirs)
                .map(|(h, d)| SnapRoot::new(&**h, *d))
                .collect(),
            keys: vec![hkcu("Software")],
        },
    )
    .unwrap()
}

/// The game folder and `HKCU\Software`.
pub fn snap_game(sys: &FakeSystem) -> Snapshot {
    snap_dirs(sys, &[GAME])
}

/// The game folder, all of `LocalAppData` (Rerun's folder in it) and `HKCU\Software`.
pub fn snap_all(sys: &FakeSystem) -> Snapshot {
    snap_dirs(sys, &[GAME, LAD])
}

pub fn same(a: &Snapshot, b: &Snapshot) {
    assert!(a == b, "not identical: {:#?}", a.diff(b));
}

fn rerun_exists(sys: &FakeSystem) -> bool {
    AppDir::open(sys, Create::Never).unwrap().is_some()
}

fn journal_exists(sys: &FakeSystem) -> bool {
    #[expect(clippy::disallowed_methods, reason = "test: look into the fake")]
    let r = sys.fs().open_dir(Path::new(&format!(r"{RERUN}\journal")));
    r.is_ok()
}

// ---------- C1: plan stores what it shows ----------

#[test]
fn c1_plan_stores_the_bytes_it_shows_under_their_hash() {
    let sys = build(with_package(), &all_steps());
    let before = snap_game(&sys);
    let p = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    let hash = hash_of(&p);
    assert!(
        p.stdout
            .contains(&format!("plan {hash} stored: 8 changes\n")),
        "{}",
        p.stdout
    );
    #[expect(clippy::disallowed_methods, reason = "test: look into the fake")]
    let plans = sys
        .fs()
        .open_dir(Path::new(&format!(r"{RERUN}\plans")))
        .unwrap();
    let names: Vec<String> = plans
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec![format!("{hash}.json")]);
    assert!(p.asked.is_empty() && p.stderr.is_empty(), "{}", p.stderr);
    same(&before, &snap_game(&sys));
    assert!(!journal_exists(&sys), "plan takes no lock");
    // Planned again: the same bytes, stored once.
    let again = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    assert_eq!(hash_of(&again), hash);
}

#[test]
fn c1_apply_applies_the_stored_plan() {
    let sys = build(with_package(), &all_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    let a = expect(&sys, &["apply", &hash], Answer::Yes, Exit::Report);
    assert_eq!(a.asked, vec!["Apply these 8 changes? [y/N]".to_owned()]);
    assert!(
        a.stdout
            .starts_with(&format!("plan {hash}: 8 changes\nroot 0: D:\\Games\\G\n")),
        "{}",
        a.stdout
    );
    let txn = txn_of(&a);
    assert!(a.stdout.ends_with(&format!(
        "applied as transaction {txn}\nrevert with: rerun revert {txn}\n"
    )));
    assert_eq!(
        sys.registry()
            .get(&hkcu(r"Software\Vendor\Game"), "Width")
            .unwrap(),
        Some(RegValue::Dword(1920))
    );
    #[expect(clippy::disallowed_methods, reason = "test: look into the fake")]
    let g = sys.fs().open_dir(Path::new(GAME)).unwrap();
    assert_eq!(
        g.read(&rerun_core::path::RelPath::parse("d3d9.dll").unwrap())
            .unwrap(),
        NEW
    );
}

// ---------- C2: plan --dry-run writes nothing ----------

#[test]
fn c2_plan_dry_run_creates_nothing() {
    let sys = build(bare(), &no_package_steps());
    let before = snap_all(&sys);
    assert!(!rerun_exists(&sys));
    let p = expect(
        &sys,
        &["plan", STEPS, "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        p.stdout.contains("(dry run, not stored): 4 changes\n"),
        "{}",
        p.stdout
    );
    assert!(!p.stdout.contains("apply with"));
    same(&before, &snap_all(&sys));
    assert!(!rerun_exists(&sys), "no Rerun folder (review S6)");
    // A package step without Rerun's folder: no local packages, refused.
    put_steps(&sys, &file_steps());
    let before = snap_all(&sys);
    let p = expect(
        &sys,
        &["plan", STEPS, "--dry-run"],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        p.stderr.contains("is not in Rerun's packages folder"),
        "{}",
        p.stderr
    );
    same(&before, &snap_all(&sys));
    // Without --dry-run the folder is created right before the plan is stored.
    put_steps(&sys, &no_package_steps());
    expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    assert!(rerun_exists(&sys));
    assert!(!journal_exists(&sys), "plan takes no lock");
}

// ---------- C3: apply --dry-run writes nothing ----------

#[test]
fn c3_apply_dry_run_writes_nothing_and_refuses_alike() {
    let sys = build(with_package(), &all_steps());
    let p = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    let hash = hash_of(&p);
    let before = snap_all(&sys);
    let d = expect(
        &sys,
        &["apply", &hash, "--dry-run"],
        Answer::Yes,
        Exit::Report,
    );
    assert!(d.asked.is_empty(), "a dry run asks nothing");
    assert!(
        d.stdout
            .ends_with("dry run: every check passed; nothing was written\n"),
        "{}",
        d.stdout
    );
    same(&before, &snap_all(&sys));
    assert!(!journal_exists(&sys), "no journal folder, no lock");
    // The game runs: the dry run refuses as the apply does.
    let image = sys
        .fake_fs()
        .map_image_as(4242, Path::new(&game("game.exe")))
        .unwrap();
    let d = expect(
        &sys,
        &["apply", &hash, "--dry-run"],
        Answer::Yes,
        Exit::Refused,
    );
    let a = expect(&sys, &["apply", &hash, "--yes"], Answer::Yes, Exit::Refused);
    assert_eq!(d.stderr, a.stderr);
    assert!(a.stderr.contains("game.exe is in use"), "{}", a.stderr);
    drop(image);
}

// ---------- C4: the confirmation ----------

#[test]
fn c4_no_and_no_console_change_nothing() {
    let sys = build(with_package(), &file_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    let before = snap_all(&sys);
    let n = expect(&sys, &["apply", &hash], Answer::No, Exit::Refused);
    assert_eq!(n.asked, vec!["Apply this change? [y/N]".to_owned()]);
    assert_eq!(n.stderr, "nothing done\n");
    let c = expect(&sys, &["apply", &hash], Answer::NoConsole, Exit::Usage);
    assert!(c.stderr.contains("pass --yes"), "{}", c.stderr);
    same(&before, &snap_all(&sys));
    // A refusal of the checks is not asked about.
    let image = sys
        .fake_fs()
        .map_image_as(4242, Path::new(&game("game.exe")))
        .unwrap();
    let r = expect(&sys, &["apply", &hash], Answer::Yes, Exit::Refused);
    assert!(r.asked.is_empty());
    drop(image);
}

// ---------- C5: the plan hash ----------

#[test]
fn c5_a_changed_or_unknown_plan_is_refused() {
    let sys = build(with_package(), &file_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    let file = format!(r"{RERUN}\plans\{hash}.json");
    sys.fake_fs().remove_abs(Path::new(&file)).unwrap();
    sys.fake_fs().put_file(Path::new(&file), b"{}").unwrap();
    let r = expect(&sys, &["apply", &hash, "--yes"], Answer::Yes, Exit::Refused);
    assert!(
        r.stderr.contains("was changed; run plan again"),
        "{}",
        r.stderr
    );
    let unknown = "0".repeat(64);
    let r = expect(
        &sys,
        &["apply", &unknown, "--yes"],
        Answer::Yes,
        Exit::Refused,
    );
    assert!(r.stderr.contains("no stored plan"), "{}", r.stderr);
    assert!(!journal_exists(&sys));
    // Upper case is no plan hash: a usage error before any system access.
    assert!(Cli::try_parse_from(["rerun", "apply", &hash.to_uppercase()]).is_err());
}

// ---------- C6: refusals ----------

#[test]
fn c6_refusals_change_nothing() {
    // The game runs (an image of the main executable mapped).
    let sys = build(with_package(), &all_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    let before = snap_all(&sys);
    let image = sys
        .fake_fs()
        .map_image_as(4242, Path::new(&game("game.exe")))
        .unwrap();
    expect(&sys, &["apply", &hash, "--yes"], Answer::Yes, Exit::Refused);
    drop(image);
    same(&before, &snap_all(&sys));
    // Another Rerun holds the journal lock.
    {
        let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
        let j = Journal::new(&app, InstanceTag::fixed(7));
        drop(j.lock().unwrap());
        let locked = snap_all(&sys);
        let held = j.lock().unwrap();
        let r = expect(&sys, &["apply", &hash, "--yes"], Answer::Yes, Exit::Refused);
        assert!(
            r.stderr.contains("another Rerun is applying"),
            "{}",
            r.stderr
        );
        let d = expect(
            &sys,
            &["apply", &hash, "--dry-run"],
            Answer::Yes,
            Exit::Refused,
        );
        assert_eq!(d.stderr, r.stderr);
        drop(held);
        same(&locked, &snap_all(&sys));
    }
}

#[test]
fn c6_elevated_plan_and_apply_are_refused() {
    let sys = build(with_package(), &file_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    let before = snap_all(&sys);
    sys.fake_registry().set_elevated(true);
    for args in [
        &["plan", STEPS][..],
        &["plan", STEPS, "--dry-run"],
        &["apply", &hash, "--yes"],
        &["apply", &hash, "--dry-run"],
    ] {
        let r = expect(&sys, args, Answer::Yes, Exit::Refused);
        assert!(r.stdout.is_empty(), "{args:?}: {}", r.stdout);
        assert!(
            r.stderr.contains("runs as administrator") && r.stderr.contains("with UAC turned off"),
            "{args:?}: {}",
            r.stderr
        );
    }
    same(&before, &snap_all(&sys));
}

// ---------- C7: rolled back ----------

#[test]
fn c7_a_failed_apply_rolls_back() {
    let sys = build(with_package(), &all_steps());
    let before = snap_game(&sys);
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    sys.fake_fs().clear_faults();
    sys.fake_fs()
        .fail_at(Prim::CreateTmp, 4, rerun_core::sys::SysErrorKind::Other);
    let r = expect(
        &sys,
        &["apply", &hash, "--yes"],
        Answer::No,
        Exit::RolledBack,
    );
    assert!(
        r.stderr
            .contains("the apply failed and was rolled back; nothing changed"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("  cause: "), "{}", r.stderr);
    sys.fake_fs().clear_faults();
    same(&before, &snap_game(&sys));
}

// ---------- C10: the step file ----------

#[test]
fn c10_step_file_problems_are_refused_without_their_content() {
    let sys = build(with_package(), &file_steps());
    let secret = "SECRET\u{1b}[2J";
    let cases: Vec<(String, &str)> = vec![
        (" ".repeat((1 << 20) + 1), "too large (limit 1048576)"),
        (
            file_steps().replace(r#""format":1,"#, &format!(r#""format":1,"{secret}":1,"#)),
            "the step file is not valid",
        ),
        (
            file_steps().replace(r#""format":1"#, r#""format":2"#),
            "step file format 2 is not supported",
        ),
        (
            file_steps().replace(r#""main_exe":"game.exe","#, ""),
            "a field is unknown, missing",
        ),
        (format!("{secret} not json"), "not valid JSON"),
    ];
    for (json, want) in cases {
        put_steps(&sys, &json);
        let r = expect(
            &sys,
            &["plan", STEPS, "--dry-run"],
            Answer::No,
            Exit::Refused,
        );
        assert!(r.stderr.contains(want), "{want}: {}", r.stderr);
        assert!(
            !r.stderr.contains("SECRET") && r.stdout.is_empty(),
            "{}",
            r.stderr
        );
    }
    // A link as the step file, a share, a file on a drive root.
    sys.fake_fs()
        .put_link(
            Path::new(r"D:\Work\link.json"),
            rerun_core::sys::fs::tag::SYMLINK,
            STEPS,
        )
        .unwrap();
    for (path, want) in [
        (r"D:\Work\link.json", "not a plain file"),
        (r"\\server\share\steps.json", "invalid path"),
        (r"D:\steps.json", "directly on a drive root"),
    ] {
        let r = expect(
            &sys,
            &["plan", path, "--dry-run"],
            Answer::No,
            Exit::Refused,
        );
        assert!(r.stderr.contains(want), "{path}: {}", r.stderr);
    }
    // A missing main executable.
    put_steps(&sys, &file_steps().replace("game.exe", "nope.exe"));
    let r = expect(
        &sys,
        &["plan", STEPS, "--dry-run"],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        r.stderr
            .contains("the main executable nope.exe is not a file"),
        "{}",
        r.stderr
    );
}

// ---------- C11: a preview that did not arrive ----------

#[test]
fn c11_a_closed_pipe_before_the_change_changes_nothing() {
    let sys = build(with_package(), &file_steps());
    let before = snap_all(&sys);
    let (r, _) = run_to(
        &sys,
        &["plan", STEPS],
        Answer::Yes,
        Failing {
            kind: io::ErrorKind::BrokenPipe,
            ok: 2,
            written: Vec::new(),
        },
    );
    assert_eq!(r.exit, Exit::Refused);
    same(&before, &snap_all(&sys));
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    let before = snap_all(&sys);
    let (r, _) = run_to(
        &sys,
        &["apply", &hash, "--yes"],
        Answer::Yes,
        Failing {
            kind: io::ErrorKind::BrokenPipe,
            ok: 3,
            written: Vec::new(),
        },
    );
    assert_eq!(r.exit, Exit::Refused);
    assert!(r.stderr.is_empty(), "silent: {}", r.stderr);
    same(&before, &snap_all(&sys));
    assert!(!journal_exists(&sys));
    // Any other write error before the change is fatal, and changes nothing either.
    let (r, _) = run_to(
        &sys,
        &["apply", &hash, "--yes"],
        Answer::Yes,
        Failing {
            kind: io::ErrorKind::PermissionDenied,
            ok: 0,
            written: Vec::new(),
        },
    );
    assert_eq!(r.exit, Exit::Fatal);
    assert!(!journal_exists(&sys));
}

// ---------- the last-resort net with hostile text ----------

#[test]
fn hostile_text_in_errors_is_escaped() {
    let sys = build(with_package(), &file_steps());
    let r = expect(
        &sys,
        &["plan", "D:\\Work\\evil\u{202E}\u{1b}.json", "--dry-run"],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        !r.stderr.contains('\u{1b}') && !r.stderr.contains('\u{202E}'),
        "{}",
        r.stderr
    );
    assert!(
        r.stderr.contains(r"\u{202e}") || r.stderr.contains(r"\u{1b}"),
        "{}",
        r.stderr
    );
}
