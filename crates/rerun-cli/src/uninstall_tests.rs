//! `rerun uninstall-check` (P5-13b, ADR 0030) against the fake, never the real machine:
//! - U1 without Rerun's folder: exit 0, golden, nothing created; elevated: exit 3, nothing read.
//! - U2 every transaction that is not settled blocks with exit 5 and is listed as `rerun status`
//!   lists it (applied, interrupted, unreadable); nothing is written.
//! - U3 closed and forgotten ones do not block (exit 0); forgotten ones get the backup note.
//! - U4 a held profile and a launch result give the launch option warning (golden), also after
//!   the revert (the Steam app from the closed head); exit by the journal alone.
//! - U5 a launch result without any transaction ("unknown game"), an unreadable one.
//! - U6 a Rerun firewall rule no transaction owns: the lines of `rerun status`, exit 0.

use std::path::Path;

use rerun_core::sys::fake::{FakeSystem, Fault, Prim};
use rerun_core::sys::firewall::FwRule;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::lm_tests::{lm_sys, steps};
use crate::tests::{
    RERUN, STEPS, after, applied, bare, build, expect, file_steps, no_package_steps, same,
    snap_all, with_package,
};

const CHECK: &[&str] = &["uninstall-check"];
const NO_FOLDER: &str = r"Rerun's folder (does not exist): C:\Users\Player\AppData\Local\Rerun";
const FOLDER: &str = r"Rerun's folder: C:\Users\Player\AppData\Local\Rerun";
/// The ID of app 220 (`plan::profile_id`, pinned in the core).
const ID: &str = "323ad79fbc93ca3e73b0b152a5d44616";
const APPLIED: &str = "rerun-result 1\nprofile=323ad79fbc93ca3e73b0b152a5d44616\ntime=1762600000\nrule=applied\ncpu=hard:8:32\npriority=none\ncheck=ok\nstart=created\nrule_child=none\nmethod=direct\n";

fn rerun_exists(sys: &FakeSystem) -> bool {
    rerun_core::policy::root::AppDir::open(sys, rerun_core::policy::root::Create::Never)
        .unwrap()
        .is_some()
}

fn put(sys: &FakeSystem, path: &str, body: &[u8]) {
    let _ = sys.fake_fs().remove_abs(Path::new(path));
    sys.fake_fs().put_file(Path::new(path), body).unwrap();
}

#[test]
fn u1_nothing_without_rerun_s_folder_and_nothing_elevated() {
    let sys = build(bare(), &no_package_steps());
    let r = expect(&sys, CHECK, Answer::No, Exit::Report);
    assert_eq!(
        r.stdout,
        format!("uninstall check: no change of Rerun is open\n\n{NO_FOLDER}\n")
    );
    assert!(r.stderr.is_empty(), "{}", r.stderr);
    assert!(!rerun_exists(&sys));
    // Elevated: refused before anything is read (E3).
    applied(&sys);
    sys.fake_registry().set_elevated(true);
    let before = snap_all(&sys);
    let r = expect(&sys, CHECK, Answer::No, Exit::Refused);
    assert!(r.stdout.is_empty(), "{}", r.stdout);
    assert!(r.stderr.contains("runs as administrator"), "{}", r.stderr);
    same(&before, &snap_all(&sys));
}

#[test]
fn u2_every_transaction_not_settled_blocks_and_is_listed() {
    let sys = build(bare(), &no_package_steps());
    let t = applied(&sys);
    let before = snap_all(&sys);
    let r = expect(&sys, CHECK, Answer::No, Exit::Open);
    let status = expect(&sys, &["status"], Answer::No, Exit::Report);
    // Listed exactly as `rerun status` lists it, then the verdict and Rerun's folder.
    assert_eq!(
        r.stdout,
        format!(
            "{}\nuninstall check: 1 transaction is still open; undo each in Rerun first (or forget it), then uninstall again\n\n{FOLDER}\n",
            status.stdout
        )
    );
    assert!(r.stdout.starts_with(&format!("transaction {t}: applied")));
    same(&before, &snap_all(&sys));

    // Unreadable: an entry with a transaction name that is no folder.
    let odd = format!(r"{RERUN}\journal\00000077-00000000000000cd");
    put(&sys, &odd, b"x");
    let r = expect(&sys, CHECK, Answer::No, Exit::Open);
    assert!(
        r.stdout.contains("2 transactions are still open"),
        "{}",
        r.stdout
    );
    // (A damaged entry blocks every revert: take it away for the revert.)
    sys.fake_fs().remove_abs(Path::new(&odd)).unwrap();
    expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    put(&sys, &odd, b"x");
    let r = expect(&sys, CHECK, Answer::No, Exit::Open);
    assert!(
        r.stdout.contains("1 transaction is still open"),
        "{}",
        r.stdout
    );
    sys.fake_fs().remove_abs(Path::new(&odd)).unwrap();
    let r = expect(&sys, CHECK, Answer::No, Exit::Report);
    assert_eq!(
        r.stdout,
        format!("uninstall check: no change of Rerun is open\n\n{FOLDER}\n")
    );

    // Interrupted: an apply that crashed after its first change.
    let sys = build(with_package(), &file_steps());
    let p = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    let hash = after(&p.stdout, "apply with: rerun apply ").to_owned();
    sys.fake_fs().clear_faults();
    sys.fake_fs().fault(Prim::Rename, 3, Fault::CrashAfter);
    let crashed = crate::tests::cli(&sys, &["apply", &hash, "--yes"], Answer::Yes);
    assert_ne!(crashed.exit, Exit::Report, "{}", crashed.stderr);
    sys.fake_fs().restart();
    let r = expect(&sys, CHECK, Answer::No, Exit::Open);
    assert!(
        r.stdout.contains(": open (in progress or interrupted)\n"),
        "{}",
        r.stdout
    );
}

#[test]
fn u3_closed_and_forgotten_do_not_block() {
    let sys = build(bare(), &no_package_steps());
    let t = applied(&sys);
    expect(&sys, &["forget", &t, "--yes"], Answer::No, Exit::Report);
    let r = expect(&sys, CHECK, Answer::No, Exit::Report);
    assert_eq!(
        r.stdout,
        format!(
            "uninstall check: no change of Rerun is open\n\
             note: 1 forgotten transaction keeps its backups in Rerun's folder; removing that folder deletes them\n\n{FOLDER}\n"
        )
    );
}

#[test]
fn u4_a_held_profile_and_its_last_start_warn() {
    let sys = lm_sys(false, &steps(8));
    let t = applied(&sys);
    put(
        &sys,
        &format!(r"{RERUN}\launch\{ID}.result"),
        APPLIED.as_bytes(),
    );
    let r = expect(&sys, CHECK, Answer::No, Exit::Open);
    let warning = format!(
        "warning: Steam may still start these games through rerun-launch.exe; once it is removed they do not start until you remove their launch option in Steam: C:\\Users\\Player\\AppData\\Local\\Programs\\Rerun\\rerun-launch.exe\n  \
         Steam app 220: launch option with --profile {ID}\n"
    );
    let started = "    last start through rerun-launch: 2025-11-08 11:06:40 UTC\n  \
                   Rerun does not read Steam's settings: check each game's Properties > General > Launch options\n";
    assert!(
        r.stdout.contains(&format!(
            "{warning}    transaction {t} holds its profile\n{started}"
        )),
        "{}",
        r.stdout
    );
    // After the revert nothing holds the profile; the last start still warns, exit 0.
    expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    let r = expect(&sys, CHECK, Answer::No, Exit::Report);
    assert_eq!(
        r.stdout,
        format!("uninstall check: no change of Rerun is open\n\n{warning}{started}\n{FOLDER}\n")
    );
    // A forgotten holder: named as such.
    let t2 = applied(&sys);
    expect(&sys, &["forget", &t2, "--yes"], Answer::No, Exit::Report);
    let r = expect(&sys, CHECK, Answer::No, Exit::Report);
    assert!(
        r.stdout.contains(&format!(
            "    the forgotten transaction {t2} left its profile\n"
        )),
        "{}",
        r.stdout
    );
}

#[test]
fn u5_a_launch_result_without_a_transaction_and_an_unreadable_one() {
    let sys = build(bare(), &no_package_steps());
    let other = "0123456789abcdef0123456789abcdef";
    put(
        &sys,
        &format!(r"{RERUN}\launch\{other}.result"),
        APPLIED.replace(ID, other).as_bytes(),
    );
    put(
        &sys,
        &format!(r"{RERUN}\launch\ffffffffffffffffffffffffffffffff.result"),
        b"rerun-result 1\nprofile=\x1b[2J\n",
    );
    let before = snap_all(&sys);
    let r = expect(&sys, CHECK, Answer::No, Exit::Report);
    assert!(
        r.stdout.contains(&format!(
            "  unknown game: launch option with --profile {other}\n    last start through rerun-launch: 2025-11-08 11:06:40 UTC\n"
        )),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains(
            "  unknown game: launch option with --profile ffffffffffffffffffffffffffffffff\n    \
             the result of its last start cannot be read: launch result line 2: control character\n"
        ),
        "{}",
        r.stdout
    );
    same(&before, &snap_all(&sys));
}

#[test]
fn u6_a_firewall_rule_no_transaction_owns_is_named() {
    let rule = FwRule {
        name: "Rerun rule of another account".to_owned(),
        description: String::new(),
        grouping: rerun_core::policy::firewall::GROUP.to_owned(),
        program: r"D:\Games\G\game.exe".to_owned(),
        direction: 2,
        action: 0,
        profiles: 0x7fff_ffff,
        protocol: 256,
        enabled: true,
        rest: rerun_core::policy::firewall::rest(),
    };
    let sys = build(bare().fw_rule(rule), &no_package_steps());
    applied(&sys);
    let t = expect(&sys, &["status"], Answer::No, Exit::Report);
    let t = after(&t.stdout, "transaction ")
        .split(':')
        .next()
        .unwrap()
        .to_owned();
    expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    let r = expect(&sys, CHECK, Answer::No, Exit::Report);
    assert!(
        r.stdout.contains(
            "Rerun firewall rules that no transaction of this account owns:\n  \
             Rerun rule of another account: program D:\\Games\\G\\game.exe\n"
        ),
        "{}",
        r.stdout
    );
}
