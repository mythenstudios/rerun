//! In-process end-to-end tests of the phase 2 commands (P2-13, `docs/09-testing.md`, "CLI"):
//! the command line parsed by clap, run against the fake system layer with in-memory stdout and
//! stderr and a fake console. Never the real machine. Everything renders through `Out`, so the
//! last-resort net is checked to never fire. Test IDs C1 to C12 (the plan's E1 to E12, renamed
//! so they do not collide with the user decisions E1 to E7).

use std::io::{self, Write};
use std::path::Path;

use clap::Parser;

use rerun_core::detect::steam::RootSource;
use rerun_core::journal::{InstanceTag, Journal};
use rerun_core::policy::root::{AppDir, Create};
use rerun_core::sys::System;
use rerun_core::sys::fake::{FakeSystem, FakeSystemBuilder, Fault, Prim, RegPrim};
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
const STEAM: &str = r"C:\Program Files (x86)\Steam";
const LIB: &str = r"D:\SteamLibrary";

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

/// Plans `steps` and applies the plan with `--yes`: the transaction.
pub fn applied(sys: &FakeSystem) -> String {
    let p = expect(sys, &["plan", STEPS], Answer::No, Exit::Report);
    let a = expect(
        sys,
        &["apply", &hash_of(&p), "--yes"],
        Answer::No,
        Exit::Report,
    );
    txn_of(&a)
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

// ---------- C1: the round trip ----------

#[test]
fn c1_plan_apply_status_revert_status_round_trip() {
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
    // The hash names the stored file.
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

    let a = expect(&sys, &["apply", &hash], Answer::Yes, Exit::Report);
    assert_eq!(a.asked, vec!["Apply these 8 changes? [y/N]".to_owned()]);
    let txn = txn_of(&a);
    assert!(
        a.stdout
            .contains(&format!("applied as transaction {txn}\n"))
    );
    assert_eq!(
        sys.registry()
            .get(&hkcu(r"Software\Vendor\Game"), "Width")
            .unwrap(),
        Some(RegValue::Dword(1920))
    );

    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout
            .starts_with(&format!("transaction {txn}: applied\n")),
        "{}",
        s.stdout
    );
    assert!(
        s.stdout
            .contains(&format!("  revert with: rerun revert {txn}\n"))
    );
    assert!(
        s.stdout
            .contains(r"    backup (20 bytes): C:\Users\Player\AppData\Local\Rerun\journal\")
    );
    assert!(
        s.stdout
            .contains("1 transaction: 1 not closed, 0 closed, 0 forgotten\n"),
        "{}",
        s.stdout
    );

    let r = expect(&sys, &["revert", &txn, "--yes"], Answer::No, Exit::Report);
    assert!(r.asked.is_empty());
    assert!(
        r.stdout
            .contains(&format!("transaction {txn} reverted and closed\n")),
        "{}",
        r.stdout
    );
    same(&before, &snap_game(&sys));

    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert_eq!(
        s.stdout,
        "1 transaction: 0 not closed, 1 closed, 0 forgotten (rerun status --all lists the closed ones)\n"
    );
    let s = expect(&sys, &["status", "--all"], Answer::No, Exit::Report);
    assert!(
        s.stdout
            .starts_with(&format!("transaction {txn}: reverted\n")),
        "{}",
        s.stdout
    );
    // A second revert: already closed.
    let r = expect(&sys, &["revert", &txn, "--yes"], Answer::No, Exit::Report);
    assert!(
        r.stdout.contains("is already closed (reverted)"),
        "{}",
        r.stdout
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

// ---------- C3: apply --dry-run and revert --dry-run write nothing ----------

#[test]
fn c3_dry_runs_write_nothing_and_refuse_alike() {
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
    // revert --dry-run of an applied transaction.
    let txn = txn_of(&expect(
        &sys,
        &["apply", &hash, "--yes"],
        Answer::No,
        Exit::Report,
    ));
    let before = snap_all(&sys);
    let r = expect(
        &sys,
        &["revert", &txn, "--dry-run"],
        Answer::Yes,
        Exit::Report,
    );
    assert!(r.asked.is_empty());
    assert!(
        r.stdout.contains("on disk now, newest op first:\n"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains("  op 0, will be undone: replace file in root 0: d3d9.dll\n"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.ends_with("dry run: nothing was written\n"));
    same(&before, &snap_all(&sys));
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
    let txn = txn_of(&expect(&sys, &["apply", &hash], Answer::Yes, Exit::Report));
    // revert and forget ask too.
    let before = snap_all(&sys);
    let r = expect(&sys, &["revert", &txn], Answer::No, Exit::Refused);
    assert_eq!(r.asked, vec!["Revert this op? [y/N]".to_owned()]);
    let f = expect(&sys, &["forget", &txn], Answer::NoConsole, Exit::Usage);
    assert_eq!(f.asked, vec![format!("Forget transaction {txn}? [y/N]")]);
    same(&before, &snap_all(&sys));
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

/// P3-2: `rerun status` shows the launch results after the journal; a broken file is one line,
/// never an abort; nothing is written.
#[test]
fn status_shows_the_last_start_per_launch_profile() {
    let ok = "rerun-result 1\nprofile=0123456789abcdef0123456789abcdef\ntime=1762600000\nrule=applied\ncpu=hard:8:32\npriority=none\ncheck=ok\nstart=created\nended=none\n";
    let launch = format!(r"{RERUN}\launch");
    let sys = build(
        bare()
            .file(
                format!(r"{launch}\0123456789abcdef0123456789abcdef.result"),
                ok.as_bytes().to_vec(),
            )
            .file(
                format!(r"{launch}\ffffffffffffffffffffffffffffffff.result"),
                b"rerun-result 1\nprofile=\x1b[2J\n".to_vec(),
            ),
        &no_package_steps(),
    );
    let before = snap_all(&sys);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert_eq!(
        s.stdout,
        "no transactions\n\nlast start per launch profile (rerun-launch):\n  \
         0123456789abcdef0123456789abcdef, 2025-11-08 11:06:40 UTC: ok, verified: 8 of 32 \
         threads (hard)\n  ffffffffffffffffffffffffffffffff: unreadable: launch result line 2: \
         control character\n"
    );
    assert!(s.stderr.is_empty(), "{}", s.stderr);
    same(&before, &snap_all(&sys));
    // Elevated: still shown (read only).
    sys.fake_registry().set_elevated(true);
    let e = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert_eq!(e.stdout, s.stdout);
}

#[test]
fn c6_elevated_only_status_runs() {
    let sys = build(with_package(), &file_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    let txn = txn_of(&expect(
        &sys,
        &["apply", &hash, "--yes"],
        Answer::No,
        Exit::Report,
    ));
    let before = snap_all(&sys);
    sys.fake_registry().set_elevated(true);
    for args in [
        &["plan", STEPS][..],
        &["plan", STEPS, "--dry-run"],
        &["apply", &hash, "--yes"],
        &["apply", &hash, "--dry-run"],
        &["revert", &txn, "--yes"],
        &["revert", &txn, "--dry-run"],
        &["forget", &txn, "--yes"],
    ] {
        let r = expect(&sys, args, Answer::Yes, Exit::Refused);
        assert!(r.stdout.is_empty(), "{args:?}: {}", r.stdout);
        assert!(
            r.stderr.contains("runs as administrator") && r.stderr.contains("with UAC turned off"),
            "{args:?}: {}",
            r.stderr
        );
    }
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(s.stdout.contains(&format!("transaction {txn}: applied")));
    same(&before, &snap_all(&sys));
}

#[test]
fn c6_steam_updating_damaged_interrupted_and_later() {
    // Steam is updating the app: plan refuses.
    let steam_steps = format!(
        r#"{{"format":1,"game":{{"steam":220}},"main_exe":"game.exe","steps":[{{"file_install":{{"package":"fix-pack","version":"1.0.2","files":[{{"from":"new.dll","to":"new.dll","sha256":"{N_SHA}"}}]}}}}]}}"#
    );
    let lib_vdf = format!(
        "\"libraryfolders\"\n{{\n\t\"0\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n\t\"1\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n}}\n",
        STEAM.replace('\\', r"\\"),
        LIB.replace('\\', r"\\")
    );
    let acf = |flags: u32| {
        format!(
            "\"AppState\"\n{{\n\t\"appid\"\t\t\"220\"\n\t\"name\"\t\t\"G\"\n\t\"StateFlags\"\t\t\"{flags}\"\n\t\"installdir\"\t\t\"G\"\n}}\n"
        )
    };
    let manifest = format!(r"{LIB}\steamapps\appmanifest_220.acf");
    let steam = with_package()
        .value(
            RootSource::CurrentUser.key(),
            RootSource::CurrentUser.value_name(),
            RegValue::String(STEAM.to_owned()),
        )
        .file(
            format!(r"{STEAM}\steamapps\libraryfolders.vdf"),
            lib_vdf.into_bytes(),
        )
        .file(manifest.clone(), acf(4 | 2).into_bytes())
        .file(
            format!(r"{LIB}\steamapps\common\G\game.exe"),
            b"MZ".to_vec(),
        );
    let sys = build(steam, &steam_steps);
    let r = expect(&sys, &["plan", STEPS], Answer::No, Exit::Refused);
    assert!(
        r.stderr.contains("Steam app 220 is being updated by Steam"),
        "{}",
        r.stderr
    );
    sys.fake_fs().remove_abs(Path::new(&manifest)).unwrap();
    sys.fake_fs()
        .put_file(Path::new(&manifest), acf(4).as_bytes())
        .unwrap();
    let p = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    assert!(
        p.stdout
            .contains(r"  Steam app 220, library: D:\SteamLibrary"),
        "{}",
        p.stdout
    );
    let hash = hash_of(&p);
    // Steam starts an update between plan and apply.
    sys.fake_fs().remove_abs(Path::new(&manifest)).unwrap();
    sys.fake_fs()
        .put_file(Path::new(&manifest), acf(4 | 2).as_bytes())
        .unwrap();
    let r = expect(&sys, &["apply", &hash, "--yes"], Answer::Yes, Exit::Refused);
    assert!(
        r.stderr.contains("Steam app 220 is updating"),
        "{}",
        r.stderr
    );

    // Interrupted: an apply that crashed after its first change blocks a plan on its objects.
    let sys = build(with_package(), &file_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    sys.fake_fs().clear_faults();
    sys.fake_fs().fault(Prim::Rename, 3, Fault::CrashAfter);
    let crashed = cli(&sys, &["apply", &hash, "--yes"], Answer::Yes);
    assert_ne!(crashed.exit, Exit::Report, "{}", crashed.stderr);
    sys.fake_fs().restart();
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    let open = after(&s.stdout, "transaction ")
        .split(':')
        .next()
        .unwrap()
        .to_owned();
    assert!(
        s.stdout.contains(": open (in progress or interrupted)\n"),
        "{}",
        s.stdout
    );
    let r = expect(&sys, &["apply", &hash, "--yes"], Answer::Yes, Exit::Refused);
    assert!(
        r.stderr.contains(&format!(
            "transaction {open} is interrupted; revert it first"
        )),
        "{}",
        r.stderr
    );
    // The revert finishes it (a recovery).
    expect(&sys, &["revert", &open, "--yes"], Answer::No, Exit::Report);

    // Later: a later transaction on the same file blocks the revert of the earlier one.
    let sys = build(bare(), &ini_steps("Width", "1920"));
    let t1 = applied(&sys);
    put_steps(&sys, &ini_steps("Height", "1080"));
    let t2 = applied(&sys);
    let r = expect(&sys, &["revert", &t1, "--yes"], Answer::Yes, Exit::Refused);
    assert!(
        r.stderr
            .contains(&format!("transaction {t2} changed the same files later")),
        "{}",
        r.stderr
    );

    // Damaged with a usable head (review S-A/S-d): a record planted after a valid prefix. It
    // blocks an apply on its objects and the revert of an earlier transaction on them, with
    // one text; an apply on other objects goes on.
    let sys = build(with_package(), &ini_steps("Width", "1920"));
    let t0 = applied(&sys);
    put_steps(&sys, &ini_steps("Height", "1080"));
    let t1 = applied(&sys);
    sys.fake_fs()
        .put_file(
            Path::new(&format!(r"{RERUN}\journal\{t1}\0004.json")),
            b"{}",
        )
        .unwrap();
    let damaged = format!(
        "rerun: transaction {t1} is damaged; rerun status shows what it left; only rerun \
         forget {t1} closes it\n"
    );
    put_steps(&sys, &ini_steps("Width", "800"));
    let r = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    let hash = hash_of(&r);
    let r = expect(&sys, &["apply", &hash, "--yes"], Answer::Yes, Exit::Refused);
    assert_eq!(r.stderr, damaged);
    let r = expect(&sys, &["revert", &t0, "--yes"], Answer::Yes, Exit::Refused);
    assert_eq!(r.stderr, damaged);
    assert!(r.asked.is_empty() && r.stdout.is_empty(), "{}", r.stdout);
    let r = expect(&sys, &["revert", &t1, "--yes"], Answer::Yes, Exit::Refused);
    assert_eq!(r.stderr, damaged);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains(&format!(
            "transaction {t1}: damaged: record 4 cannot be parsed\n"
        )),
        "{}",
        s.stdout
    );
    assert!(
        s.stdout
            .contains("op 0, applied: edit ini in root 0: game.ini"),
        "{}",
        s.stdout
    );
    put_steps(&sys, &file_steps());
    applied(&sys);
    expect(&sys, &["forget", &t1, "--yes"], Answer::No, Exit::Report);
    // Forgotten, it blocks nothing any more: the earlier one reverts (its key only).
    expect(&sys, &["revert", &t0, "--yes"], Answer::No, Exit::Report);

    // A head no record confirms (another head.json): blocks every apply; revert refuses,
    // forget closes it with a marker.
    let sys = build(with_package(), &file_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    let t = applied(&sys);
    let head = format!(r"{RERUN}\journal\{t}\head.json");
    sys.fake_fs().remove_abs(Path::new(&head)).unwrap();
    sys.fake_fs().put_file(Path::new(&head), b"{}").unwrap();
    let damaged = format!(
        "rerun: transaction {t} is damaged; rerun status shows what it left; only rerun \
         forget {t} closes it\n"
    );
    let r = expect(&sys, &["apply", &hash, "--yes"], Answer::Yes, Exit::Refused);
    assert_eq!(r.stderr, damaged);
    let r = expect(&sys, &["revert", &t, "--yes"], Answer::Yes, Exit::Refused);
    assert_eq!(r.stderr, damaged);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains(&format!("transaction {t}: damaged: ")),
        "{}",
        s.stdout
    );
    assert!(s.stdout.contains("only forget closes it"), "{}", s.stdout);
    expect(&sys, &["forget", &t, "--yes"], Answer::No, Exit::Report);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains(&format!("transaction {t}: forgotten\n")),
        "{}",
        s.stdout
    );
    assert!(s.stdout.contains("  its backups stay in: "), "{}", s.stdout);
}
// ---------- C7: rolled back and left open ----------

#[test]
fn c7_a_failed_apply_rolls_back_or_stays_open() {
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
    let s = expect(&sys, &["status", "--all"], Answer::No, Exit::Report);
    assert!(s.stdout.contains(": rolled back\n"), "{}", s.stdout);

    // The rollback fails too: open, revert finishes it.
    // A registry value fails; the rollback cannot remove the folder the apply created.
    sys.fake_registry()
        .fail_at(RegPrim::SetValue, 1, rerun_core::sys::SysErrorKind::Other);
    for n in 1..=4 {
        sys.fake_fs().fail_at(
            Prim::OpenDirDelete,
            n,
            rerun_core::sys::SysErrorKind::AccessDenied,
        );
    }
    let r = expect(&sys, &["apply", &hash, "--yes"], Answer::No, Exit::Open);
    sys.fake_fs().clear_faults();
    let open = after(&r.stderr, "rerun status shows it; rerun revert ")
        .trim_end_matches(" finishes it")
        .to_owned();
    assert!(
        r.stderr.contains(&format!("transaction {open} stays open")),
        "{}",
        r.stderr
    );
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains(&format!("transaction {open}: open")),
        "{}",
        s.stdout
    );
    expect(&sys, &["revert", &open, "--yes"], Answer::No, Exit::Report);
    same(&before, &snap_game(&sys));
}

// ---------- C8: foreign, forget ----------

#[test]
fn c8_a_file_changed_after_the_apply_is_left_and_forget_closes() {
    let sys = build(with_package(), &all_steps());
    let txn = applied(&sys);
    // The user replaces the patched d3d9.dll.
    let fx = sys.fake_fs();
    fx.remove_abs(Path::new(&game("d3d9.dll"))).unwrap();
    fx.put_file(Path::new(&game("d3d9.dll")), b"the user's own")
        .unwrap();
    fx.sync_all();
    let r = expect(&sys, &["revert", &txn, "--yes"], Answer::No, Exit::Open);
    assert!(
        r.stdout
            .contains("  op 0: left as found (changed by someone else)\n"),
        "{}",
        r.stdout
    );
    let bin = format!(r"{RERUN}\journal\{txn}\op-0000.bin");
    assert!(
        r.stdout
            .contains(&format!("    backup (20 bytes): {bin}\n")),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains(&format!("rerun forget {txn} closes it (backups stay)"))
    );
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains("forget closes it: rerun forget"),
        "{}",
        s.stdout
    );
    // The forget preview names the backup and what forget does not do.
    let game_now = snap_game(&sys);
    let f = expect(&sys, &["forget", &txn], Answer::Yes, Exit::Report);
    assert!(
        f.stdout
            .contains(&format!("    backup (20 bytes): {bin}\n")),
        "{}",
        f.stdout
    );
    assert!(
        f.stdout
            .contains("Forget changes nothing in the game folder or the registry.\n")
    );
    assert!(!f.stdout.contains("finishes this cleanly"), "{}", f.stdout);
    assert!(f.stdout.contains(&format!("transaction {txn} forgotten\n")));
    same(&game_now, &snap_game(&sys));
    #[expect(clippy::disallowed_methods, reason = "test: look into the fake")]
    let jd = sys
        .fs()
        .open_dir(Path::new(&format!(r"{RERUN}\journal\{txn}")))
        .unwrap();
    assert!(
        jd.read_dir(None)
            .unwrap()
            .iter()
            .any(|e| e.name == "op-0000.bin"),
        "the backup stays"
    );
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout
            .contains(&format!("transaction {txn}: forgotten\n")),
        "{}",
        s.stdout
    );
    assert!(
        s.stdout
            .contains(&format!("    backup (20 bytes): {bin}\n")),
        "{}",
        s.stdout
    );
    let f = expect(&sys, &["forget", &txn, "--yes"], Answer::No, Exit::Report);
    assert!(f.stdout.contains("is already forgotten"));
    let r = expect(&sys, &["revert", &txn, "--yes"], Answer::No, Exit::Refused);
    assert!(r.stderr.contains("was forgotten"), "{}", r.stderr);
}

#[test]
fn c8_forget_of_a_clean_transaction_says_revert_finishes_it() {
    let sys = build(with_package(), &file_steps());
    let txn = applied(&sys);
    let f = expect(&sys, &["forget", &txn], Answer::No, Exit::Refused);
    assert!(
        f.stdout
            .contains(&format!("rerun revert {txn} finishes this cleanly")),
        "{}",
        f.stdout
    );
    assert!(f.stdout.contains("the change stays\n"), "{}", f.stdout);
}

// ---------- C9: a halt ----------

#[test]
fn c9_a_game_folder_gone_halts_the_revert_until_it_is_back() {
    let sys = build(with_package(), &all_steps());
    let before = snap_game(&sys);
    let txn = applied(&sys);
    sys.rename_abs(GAME, r"D:\Games\Away").unwrap();
    let r = expect(&sys, &["revert", &txn, "--yes"], Answer::No, Exit::Open);
    assert!(r.stdout.contains("the revert stops at op "), "{}", r.stdout);
    assert!(
        r.stdout.contains("goes on once the folder is back"),
        "{}",
        r.stdout
    );
    sys.rename_abs(r"D:\Games\Away", GAME).unwrap();
    expect(&sys, &["revert", &txn, "--yes"], Answer::No, Exit::Report);
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
        (
            r"\\server\share\steps.json",
            "on a network share is not read",
        ),
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

// ---------- status without Rerun's folder ----------

#[test]
fn status_without_rerun_s_folder_and_unknown_transactions() {
    let sys = build(bare(), &no_package_steps());
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert_eq!(s.stdout, "no transactions\n");
    assert!(!rerun_exists(&sys));
    let t = "00000009-00000000000000ab";
    let r = expect(&sys, &["revert", t, "--yes"], Answer::No, Exit::Refused);
    assert!(r.stderr.contains("Rerun has no folder yet"), "{}", r.stderr);
    expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    let r = expect(&sys, &["forget", t, "--yes"], Answer::No, Exit::Refused);
    assert!(
        r.stderr.contains(&format!("transaction {t} not found")),
        "{}",
        r.stderr
    );
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert_eq!(s.stdout, "no transactions\n");
}

/// One INI key of `game.ini` as the only step.
fn ini_steps(key: &str, value: &str) -> String {
    format!(
        r#"{{"format":1,"game":{{"folder":"D:\\Games\\G"}},"main_exe":"game.exe","steps":[{{"ini_set":{{"file":"game.ini","values":[{{"section":"Display","key":"{key}","value":"{value}"}}]}}}}]}}"#
    )
}

// ---------- C3/C4: revert runs every check before its preview and question ----------

#[test]
fn c4_revert_checks_before_its_preview_and_question() {
    let sys = build(bare(), &ini_steps("Width", "1920"));
    let t0 = applied(&sys);
    put_steps(&sys, &ini_steps("Height", "1080"));
    let t1 = applied(&sys);
    // A later transaction on the same file: the dry run refuses as the revert would.
    let r = expect(
        &sys,
        &["revert", &t0, "--dry-run"],
        Answer::Yes,
        Exit::Refused,
    );
    assert!(r.stdout.is_empty() && r.asked.is_empty(), "{}", r.stdout);
    assert!(
        r.stderr
            .contains(&format!("transaction {t1} changed the same files later")),
        "{}",
        r.stderr
    );
    // The game runs: refused before any preview or question.
    let image = sys
        .fake_fs()
        .map_image_as(4242, Path::new(&game("game.exe")))
        .unwrap();
    let before = snap_all(&sys);
    for args in [&["revert", &t1][..], &["revert", &t1, "--dry-run"]] {
        let r = expect(&sys, args, Answer::Yes, Exit::Refused);
        assert!(r.stdout.is_empty() && r.asked.is_empty(), "{}", r.stdout);
        assert!(r.stderr.contains("game.exe is in use"), "{}", r.stderr);
    }
    drop(image);
    same(&before, &snap_all(&sys));
}

#[test]
fn c4_an_empty_transaction_is_closed_without_a_question() {
    let sys = build(with_package(), &file_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    // A crash right after the head was written: a transaction with its head only.
    sys.fake_fs().clear_faults();
    sys.fake_fs()
        .fault(Prim::Rename, 1, rerun_core::sys::fake::Fault::CrashAfter);
    let crashed = cli(&sys, &["apply", &hash, "--yes"], Answer::Yes);
    assert_ne!(crashed.exit, Exit::Report);
    sys.fake_fs().restart();
    let s = expect(&sys, &["status", "--all"], Answer::No, Exit::Report);
    let t = after(&s.stdout, "transaction ")
        .split(':')
        .next()
        .unwrap()
        .to_owned();
    assert!(
        s.stdout.contains(": empty (it changed nothing)\n"),
        "{}",
        s.stdout
    );
    let d = expect(&sys, &["revert", &t, "--dry-run"], Answer::No, Exit::Report);
    assert!(
        d.stdout.contains(&format!(
            "transaction {t} changed nothing; rerun revert {t} only closes it\n"
        )),
        "{}",
        d.stdout
    );
    assert!(!d.stdout.contains("Revert"), "{}", d.stdout);
    let r = expect(&sys, &["revert", &t], Answer::No, Exit::Report);
    assert!(r.asked.is_empty(), "no question for an empty transaction");
    assert!(
        r.stdout
            .contains(&format!("transaction {t} reverted and closed\n")),
        "{}",
        r.stdout
    );
}

// ---------- C-RB: rerun revert --rebind (P2-14b) ----------

/// The library the rebind tests move to.
const LIB_E: &str = r"E:\SteamLibrary";

/// `libraryfolders.vdf` listing the Steam folder and `libs`.
fn lib_vdf(libs: &[&str]) -> String {
    let mut out = String::from("\"libraryfolders\"\n{\n");
    for (i, p) in std::iter::once(STEAM)
        .chain(libs.iter().copied())
        .enumerate()
    {
        out.push_str(&format!(
            "\t\"{i}\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n",
            p.replace('\\', r"\\")
        ));
    }
    out.push_str("}\n");
    out
}

fn lib_file() -> String {
    format!(r"{STEAM}\steamapps\libraryfolders.vdf")
}

/// Steam with app 220 in `G` of [`LIB`], and steps for it: a new file in a new folder and a
/// registry value.
fn steam_rebind() -> FakeSystem {
    let steps = format!(
        r#"{{"format":1,"game":{{"steam":220}},"main_exe":"game.exe","steps":[{{"file_install":{{"package":"fix-pack","version":"1.0.2","files":[{{"from":"new.dll","to":"mods\\new.dll","sha256":"{N_SHA}"}}]}}}},{{"registry_set":{{"key":"HKCU\\Software\\Vendor\\Game","values":[{{"name":"Width","dword":1920}}]}}}}]}}"#
    );
    let acf = "\"AppState\"\n{\n\t\"appid\"\t\t\"220\"\n\t\"name\"\t\t\"G\"\n\t\"StateFlags\"\t\t\"4\"\n\t\"installdir\"\t\t\"G\"\n}\n";
    let b = with_package()
        .value(
            RootSource::CurrentUser.key(),
            RootSource::CurrentUser.value_name(),
            RegValue::String(STEAM.to_owned()),
        )
        .file(lib_file(), lib_vdf(&[LIB]).into_bytes())
        .file(
            format!(r"{LIB}\steamapps\appmanifest_220.acf"),
            acf.as_bytes().to_vec(),
        )
        .file(
            format!(r"{LIB}\steamapps\common\G\game.exe"),
            b"MZ".to_vec(),
        );
    build(b, &steps)
}

/// Copies the tree `from` to `to` (new file IDs, as Steam copies to another volume).
fn copy_tree(sys: &FakeSystem, from: &str, to: &str) {
    use rerun_core::path::RelPath;
    let fx = sys.fake_fs();
    fx.mkdir_all(Path::new(to)).unwrap();
    #[expect(clippy::disallowed_methods, reason = "test: copy a fixture tree")]
    let d = sys.fs().open_dir(Path::new(from)).unwrap();
    for e in d.read_dir(None).unwrap() {
        let name = RelPath::parse(&e.name).unwrap();
        let (src, dst) = (format!(r"{from}\{}", e.name), format!(r"{to}\{}", e.name));
        match d.metadata(&name).unwrap().unwrap().kind {
            rerun_core::sys::fs::EntryKind::Dir => copy_tree(sys, &src, &dst),
            _ => fx
                .put_file(Path::new(&dst), &d.read(&name).unwrap())
                .unwrap(),
        }
    }
}

/// Removes the tree `abs`.
fn remove_tree(sys: &FakeSystem, abs: &str) {
    use rerun_core::path::RelPath;
    let entries: Vec<(String, bool)> = {
        #[expect(clippy::disallowed_methods, reason = "test: remove a fixture tree")]
        let d = sys.fs().open_dir(Path::new(abs)).unwrap();
        d.read_dir(None)
            .unwrap()
            .into_iter()
            .map(|e| {
                let dir = d
                    .metadata(&RelPath::parse(&e.name).unwrap())
                    .unwrap()
                    .unwrap()
                    .kind
                    == rerun_core::sys::fs::EntryKind::Dir;
                (e.name, dir)
            })
            .collect()
    };
    for (n, dir) in entries {
        let p = format!(r"{abs}\{n}");
        if dir {
            remove_tree(sys, &p);
        } else {
            sys.fake_fs().remove_abs(Path::new(&p)).unwrap();
        }
    }
    sys.fake_fs().remove_abs(Path::new(abs)).unwrap();
}

/// Steam moves the library to `E:` (a copy, the source removed, the list rewritten).
fn move_library(sys: &FakeSystem) {
    copy_tree(sys, LIB, LIB_E);
    remove_tree(sys, LIB);
    let fx = sys.fake_fs();
    fx.remove_abs(Path::new(&lib_file())).unwrap();
    fx.put_file(Path::new(&lib_file()), lib_vdf(&[LIB_E]).as_bytes())
        .unwrap();
    sys.fake_fs().sync_all();
}

/// C-RB1: apply, the library moved, the revert halts with the hint, `--rebind --dry-run` shows
/// the rebind and writes nothing, `--rebind` at a console binds and reverts.
#[test]
fn c_rb1_a_moved_library_is_rebound_through_the_cli() {
    let sys = steam_rebind();
    let t = applied(&sys);
    move_library(&sys);
    let r = expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Open);
    assert!(
        r.stdout.contains(&format!(
            "rerun revert {t} --rebind shows the folder Steam lists now"
        )),
        "{}",
        r.stdout
    );
    let before = snap_dirs(&sys, &[LAD, LIB_E]);
    let r = expect(
        &sys,
        &["revert", &t, "--rebind", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    let game_e = format!(r"{LIB_E}\steamapps\common\G");
    for want in [
        "rebind of root 0:".to_owned(),
        "bound now (identity ".to_owned(),
        format!(r"): {LIB}\steamapps\common\G"),
        "does not open:".to_owned(),
        "the folder Steam lists now (identity ".to_owned(),
        format!("): {game_e}"),
        format!("    in library: {LIB_E}"),
        format!(
            r"a folder the plan created, found there and not provably Rerun's (removed only if empty): {game_e}\mods"
        ),
        "what the revert does there:".to_owned(),
        "Registry changes are reverted where Rerun made them".to_owned(),
        "Only the folder bound now is reverted; a copy of the game elsewhere".to_owned(),
        "The binding is permanent".to_owned(),
        "dry run: nothing was written".to_owned(),
    ] {
        assert!(r.stdout.contains(&want), "{want:?} in:\n{}", r.stdout);
    }
    assert!(r.asked.is_empty());
    same(&before, &snap_dirs(&sys, &[LAD, LIB_E]));
    let r = expect(&sys, &["revert", &t, "--rebind"], Answer::Yes, Exit::Report);
    assert!(
        r.asked
            .iter()
            .any(|q| q.starts_with(&format!("Bind transaction {t} to this folder"))),
        "{:?}",
        r.asked
    );
    assert!(
        r.stdout
            .contains(&format!("transaction {t} reverted and closed")),
        "{}",
        r.stdout
    );
    #[expect(clippy::disallowed_methods, reason = "test: look into the fake")]
    let gone = sys
        .fs()
        .open_dir(Path::new(&format!(r"{game_e}\mods")))
        .is_err();
    assert!(gone, "the created folder is removed");
}

/// C-RB2 to C-RB5: no at the question (3, no record), no console (2, never `--yes`),
/// `--rebind --yes` a usage error, `--rebind` without need (3).
#[test]
fn c_rb2_the_question_the_console_and_refusals() {
    let sys = steam_rebind();
    let t = applied(&sys);
    // Not needed: nothing moved.
    let r = expect(
        &sys,
        &["revert", &t, "--rebind"],
        Answer::Yes,
        Exit::Refused,
    );
    assert!(r.stderr.contains("opens as recorded"), "{}", r.stderr);
    move_library(&sys);
    let before = snap_dirs(&sys, &[LAD, LIB_E]);
    let r = expect(&sys, &["revert", &t, "--rebind"], Answer::No, Exit::Refused);
    assert_eq!(r.asked.len(), 1, "{:?}", r.asked);
    same(&before, &snap_dirs(&sys, &[LAD, LIB_E]));
    let r = expect(
        &sys,
        &["revert", &t, "--rebind"],
        Answer::NoConsole,
        Exit::Usage,
    );
    assert!(
        r.stderr.contains("--yes is not accepted with --rebind"),
        "{}",
        r.stderr
    );
    same(&before, &snap_dirs(&sys, &[LAD, LIB_E]));
    let e = Cli::try_parse_from(["rerun", "revert", &t, "--rebind", "--yes"])
        .err()
        .map(|e| e.kind());
    assert_eq!(e, Some(clap::error::ErrorKind::ArgumentConflict));
}

/// C-RB6: a reinstall at the same path: the revert is refused with the hint that names
/// `--rebind`; a rebind left open by a crash right after its record shows in `status`, and
/// `--rebind` again reverts it as it is ("already bound").
#[test]
fn c_rb6_the_hint_the_status_line_and_already_bound() {
    let sys = steam_rebind();
    let t = applied(&sys);
    let game = format!(r"{LIB}\steamapps\common\G");
    copy_tree(&sys, &game, r"D:\Tmp\G");
    remove_tree(&sys, &game);
    copy_tree(&sys, r"D:\Tmp\G", &game);
    sys.fake_fs().sync_all();
    let r = expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Refused);
    assert!(
        r.stderr.contains(&format!(
            "rerun revert {t} --rebind shows the folder Steam lists"
        )),
        "{}",
        r.stderr
    );
    // The first flush of the run is the rebind's record (the checks write nothing).
    sys.fake_fs().clear_faults();
    sys.fake_fs().fault(Prim::FlushDir, 1, Fault::CrashAfter);
    let r = cli(&sys, &["revert", &t, "--rebind"], Answer::Yes);
    assert_eq!(r.exit, Exit::Open, "{}\n{}", r.stdout, r.stderr);
    sys.fake_fs().restart();
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains("  root 0 rebound (identity ") && s.stdout.contains(&game),
        "{}",
        s.stdout
    );
    let r = expect(&sys, &["revert", &t, "--rebind"], Answer::Yes, Exit::Report);
    assert!(
        r.stdout.contains(&format!("already bound to: {game}")),
        "{}",
        r.stdout
    );
    // One question: the plain revert's (security review nit N1).
    assert_eq!(r.asked.len(), 1, "{:?}", r.asked);
    assert!(
        r.stdout
            .contains(&format!("transaction {t} reverted and closed")),
        "{}",
        r.stdout
    );
}

/// C-RB7 (review S3, N3): a rebind whose record may not be on disk (a crash right after its
/// rename) exits 5 with "may be bound"; one whose record is on disk although its call failed
/// (its flush) exits 5 and says the transaction is bound now.
#[test]
fn c_rb7_a_failed_rebind_says_whether_the_transaction_is_bound() {
    for (call, fault, want) in [
        (
            Prim::Rename,
            Fault::CrashAfter,
            "may be bound to the new folder although the command failed",
        ),
        (
            Prim::FlushDir,
            Fault::Fail(rerun_core::sys::SysErrorKind::Other),
            "is bound to the new folder now",
        ),
    ] {
        let sys = steam_rebind();
        let t = applied(&sys);
        move_library(&sys);
        sys.fake_fs().clear_faults();
        // The first rename and flush of the run are the rebind record's.
        sys.fake_fs().fault(call, 1, fault);
        let r = cli(&sys, &["revert", &t, "--rebind"], Answer::Yes);
        assert_eq!(r.exit, Exit::Open, "{}\n{}", r.stdout, r.stderr);
        assert!(r.stderr.contains(want), "{want:?} in:\n{}", r.stderr);
        sys.fake_fs().clear_faults();
        sys.fake_fs().restart();
    }
}

// ---------- C-CL: a pending cleanup (P2-15) ----------

/// One replace: `d3d9.dll` from the package.
fn replace_steps() -> String {
    format!(
        r#"{{"format":1,"game":{{"folder":"D:\\Games\\G"}},"main_exe":"game.exe","steps":[{{"file_install":{{"package":"fix-pack","version":"1.0.2","files":[{{"from":"d3d9.dll","to":"d3d9.dll","sha256":"{NEW_SHA}"}}]}}}}]}}"#
    )
}

/// The images mapped by [`map_olds`].
type Held = std::sync::Arc<std::sync::Mutex<Vec<(String, rerun_core::sys::fake::FakeHold)>>>;

/// From now on (until the hook is cleared), every `.tmp.old` that appears in the game folder is
/// mapped as an image (a game, an overlay or an Explorer window could), right before a rename;
/// with `after`, only once that many flushes of a folder were seen.
fn map_olds(sys: &FakeSystem, after: Option<usize>) -> Held {
    let held: Held = std::sync::Arc::default();
    let slot = std::sync::Arc::clone(&held);
    let mut flushes = 0;
    sys.fake_fs().on_step(move |f, ev| {
        if ev.call == Some(Prim::FlushDir) {
            flushes += 1;
        }
        if ev.call != Some(Prim::Rename) || after.is_some_and(|n| flushes < n) {
            return;
        }
        #[expect(clippy::disallowed_methods, reason = "test: list the fixture folder")]
        let Ok(d) = rerun_core::sys::Fs::open_dir(f, Path::new(GAME)) else {
            return;
        };
        let mut h = slot.lock().unwrap();
        for e in d.read_dir(None).unwrap_or_default() {
            if e.name.ends_with(".tmp.old") && !h.iter().any(|(n, _)| *n == e.name) {
                let held = f
                    .map_image_as(4242, &Path::new(GAME).join(&e.name))
                    .unwrap();
                h.push((e.name.clone(), held));
            }
        }
    });
    held
}

/// C-CL1 and C-CL3: a revert while the restore's `.old` is mapped exits 5 and says why;
/// `status` shows "only cleanup pending"; an apply on the same file is refused with what to do;
/// forget says everything is reverted; once the file is free, the revert asks, deletes it and
/// closes, identical.
#[test]
fn c_cl1_a_mapped_dot_old_keeps_the_transaction_open_until_it_is_free() {
    let sys = build(with_package(), &replace_steps());
    let before = snap_game(&sys);
    let txn = applied(&sys);
    let held = map_olds(&sys, None);
    let r = expect(&sys, &["revert", &txn, "--yes"], Answer::No, Exit::Open);
    sys.fake_fs().clear_on_step();
    let old = held.lock().unwrap()[0].0.clone();
    assert!(
        r.stdout.contains(&format!(
            "transaction {txn} is reverted; 1 file Rerun replaced is still in use and stays for \
             now; close the game and any window showing its folder, then run rerun revert {txn} \
             again\n"
        )),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains(&format!(
            "  in use, stays for now (Rerun's copy; the transaction stays open): {old}\n"
        )),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("    left: "),
        "reported once: {}",
        r.stdout
    );

    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.starts_with(&format!(
            "transaction {txn}: everything reverted, only cleanup pending\n"
        )),
        "{}",
        s.stdout
    );
    assert!(
        s.stdout.contains(&format!("    pending cleanup: {old}\n")),
        "{}",
        s.stdout
    );
    assert!(
        s.stdout.contains(&format!(
            "  a file Rerun left is still there; rerun revert {txn} deletes it or says why it \
             stays (close the game and any window showing its folder first)\n"
        )),
        "{}",
        s.stdout
    );

    // C-CL3: the same file again.
    let p = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    let a = expect(
        &sys,
        &["apply", &hash_of(&p), "--yes"],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        a.stderr.contains(&format!(
            "transaction {txn} is reverted, but a file Rerun left is still there; run rerun \
             revert {txn}, it deletes the file or says why it stays"
        )),
        "{}",
        a.stderr
    );

    // Forget's own text (senior-dev S3), declined.
    let f = expect(&sys, &["forget", &txn], Answer::No, Exit::Refused);
    assert!(
        f.stdout.contains(
            "Everything is reverted; only the files listed as pending cleanup stay, and Rerun \
             will not delete them.\n"
        ),
        "{}",
        f.stdout
    );
    assert!(
        !f.stdout.contains("Changes still in place stay"),
        "{}",
        f.stdout
    );

    // Free: the preview names what is deleted, the revert asks, deletes and closes.
    held.lock().unwrap().clear();
    let d = expect(
        &sys,
        &["revert", &txn, "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        d.stdout.contains(&format!(
            "  will delete Rerun's copy (known content, SHA-256 {NEW_SHA}): {old}\n"
        )),
        "{}",
        d.stdout
    );
    let r = expect(&sys, &["revert", &txn], Answer::Yes, Exit::Report);
    assert_eq!(
        r.asked,
        vec!["Everything is reverted. Delete the file Rerun left? [y/N]".to_owned()]
    );
    assert!(
        r.stdout
            .contains(&format!("  deleted Rerun's copy: {old}\n")),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains(&format!("transaction {txn} reverted and closed\n")),
        "{}",
        r.stdout
    );
    same(&before, &snap_game(&sys));
}

/// A rollback with the restore's `.old` mapped (senior-dev B1): exit 5 with its own text.
#[test]
fn c_cl1_a_rollback_with_a_mapped_dot_old_exits_5() {
    let sys = build(with_package(), &replace_steps());
    let before = snap_game(&sys);
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    // The flushes of a successful apply on a copy: the game folder's is the second to last.
    let copy = build(with_package(), &replace_steps());
    let h2 = hash_of(&expect(&copy, &["plan", STEPS], Answer::No, Exit::Report));
    copy.fake_fs().clear_faults();
    copy.fake_fs().record_calls(true);
    expect(&copy, &["apply", &h2, "--yes"], Answer::No, Exit::Report);
    copy.fake_fs().record_calls(false);
    let n = copy
        .fake_fs()
        .take_calls()
        .iter()
        .filter(|c| **c == Prim::FlushDir)
        .count()
        - 1;
    sys.fake_fs().clear_faults();
    let held = map_olds(&sys, Some(n));
    sys.fake_fs()
        .fail_at(Prim::FlushDir, n, rerun_core::sys::SysErrorKind::Other);
    let r = expect(&sys, &["apply", &hash, "--yes"], Answer::No, Exit::Open);
    sys.fake_fs().clear_on_step();
    sys.fake_fs().clear_faults();
    let open = after(
        &r.stderr,
        "close the game and any window showing its folder, then run: rerun revert ",
    )
    .to_owned();
    assert!(
        r.stderr.contains(&format!(
            "the apply failed and was rolled back, but a file Rerun left is still there: \
             transaction {open} stays open until it is deleted\n"
        )),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("  in use, stays for now"), "{}", r.stderr);
    held.lock().unwrap().clear();
    expect(&sys, &["revert", &open, "--yes"], Answer::No, Exit::Report);
    same(&before, &snap_game(&sys));
}

/// Review S1 (security, E-C4): a rollback whose `.old` is not Rerun's any more by the time the
/// cleanup looks (mapped during step 8, then replaced) closes `RolledBack` (exit 4) and reports
/// it.
#[test]
fn c_cl_a_rollback_reports_a_foreign_dot_old() {
    let sys = build(with_package(), &replace_steps());
    let hash = hash_of(&expect(&sys, &["plan", STEPS], Answer::No, Exit::Report));
    let copy = build(with_package(), &replace_steps());
    let h2 = hash_of(&expect(&copy, &["plan", STEPS], Answer::No, Exit::Report));
    copy.fake_fs().clear_faults();
    copy.fake_fs().record_calls(true);
    expect(&copy, &["apply", &h2, "--yes"], Answer::No, Exit::Report);
    copy.fake_fs().record_calls(false);
    let n = copy
        .fake_fs()
        .take_calls()
        .iter()
        .filter(|c| **c == Prim::FlushDir)
        .count()
        - 1;
    sys.fake_fs().clear_faults();
    // Mapped at the restore's step 7; at the next flush (the game folder before `RevertDone`)
    // the mapping goes and someone else's file takes the name.
    let held: Held = std::sync::Arc::default();
    let slot = std::sync::Arc::clone(&held);
    let mut flushes = 0;
    let mut planted = false;
    sys.fake_fs().on_step(move |f, ev| {
        if ev.call == Some(Prim::FlushDir) {
            flushes += 1;
            let mut h = slot.lock().unwrap();
            if !planted && let Some((name, _)) = h.first() {
                let p = Path::new(GAME).join(name);
                h.clear();
                f.remove_abs(&p).unwrap();
                f.put_file(&p, b"someone else's file").unwrap();
                planted = true;
            }
            return;
        }
        if ev.call != Some(Prim::Rename) || flushes < n || planted {
            return;
        }
        #[expect(clippy::disallowed_methods, reason = "test: list the fixture folder")]
        let Ok(d) = rerun_core::sys::Fs::open_dir(f, Path::new(GAME)) else {
            return;
        };
        let mut h = slot.lock().unwrap();
        for e in d.read_dir(None).unwrap_or_default() {
            if e.name.ends_with(".tmp.old") && h.is_empty() {
                let x = f
                    .map_image_as(4242, &Path::new(GAME).join(&e.name))
                    .unwrap();
                h.push((e.name.clone(), x));
            }
        }
    });
    sys.fake_fs()
        .fail_at(Prim::FlushDir, n, rerun_core::sys::SysErrorKind::Other);
    let r = expect(
        &sys,
        &["apply", &hash, "--yes"],
        Answer::No,
        Exit::RolledBack,
    );
    sys.fake_fs().clear_on_step();
    sys.fake_fs().clear_faults();
    assert!(
        r.stderr
            .contains("  not Rerun's file, or it cannot be checked as Rerun's; left as it is: "),
        "{}",
        r.stderr
    );
}

/// Review S1 (senior) / N2 (security): a copy `verify` sees in use (a process holds it with
/// delete sharing) is asked for, and the revert deletes it.
#[test]
fn c_cl_a_copy_in_use_is_asked_for_before_it_may_be_deleted() {
    let sys = build(with_package(), &replace_steps());
    let before = snap_game(&sys);
    let txn = applied(&sys);
    let held = map_olds(&sys, None);
    expect(&sys, &["revert", &txn, "--yes"], Answer::No, Exit::Open);
    sys.fake_fs().clear_on_step();
    let old = held.lock().unwrap()[0].0.clone();
    held.lock().unwrap().clear();
    let scanner = sys
        .fake_fs()
        .hold_open_as(
            4243,
            &Path::new(GAME).join(&old),
            rerun_core::sys::contract::Access::READ,
            rerun_core::sys::contract::Share::RWD,
        )
        .unwrap();
    let r = expect(&sys, &["revert", &txn], Answer::Yes, Exit::Report);
    drop(scanner);
    assert_eq!(
        r.asked,
        vec![
            "Everything is reverted. Delete the file Rerun left (it is in use now and may stay)? [y/N]"
                .to_owned()
        ]
    );
    assert!(
        r.stdout
            .contains(&format!("  deleted Rerun's copy: {old}\n")),
        "{}",
        r.stdout
    );
    same(&before, &snap_game(&sys));
}
