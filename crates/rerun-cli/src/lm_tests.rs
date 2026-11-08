//! C-LM (P3-3d, plan `P3-3` §7.5): `launch_method` through the CLI against the fake, with the
//! 5950X topology and synthetic PE images (the sparse bytes of `rerun-core`'s test builder).
//! - C-LM1 `plan` shows the profile, the selection on this computer, the launcher hint, the
//!   note and the launch option with the install folder; without `rerun-launch.exe` a warning.
//! - C-LM2 `plan --dry-run` writes nothing (no `Rerun`, no `profiles`).
//! - C-LM3 to C-LM5 the revert of a created profile: "once the revert completes" and after it,
//!   remove the option (named literally) and any option with `--profile <id>`; the `forget`
//!   preview: the profile stays and keeps applying (never "finds no profile"); `apply` ends with
//!   "now paste" only with an option and the shim (X12, review M1/B1, L3).
//! - C-LM6 (S3) a revert after `<LocalAppData>` moved: the profiles folder's two paths.
//! - C-LM7 (A6, A7, S1, S2) `status`: the check covered the launcher while a transaction holds
//!   the profile (forgotten included, not after the revert); `profile_missing` names the holder,
//!   or advises removing the option.
//! - C-LM8 a stacked profile: reverting the second brings the first back, the option stays.
//! - C-LM9 a changed profile is left and keeps applying.
//! - C-LM10 `plan` stores nothing when Rerun's folder moved between the preview and creating it.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rerun_core::detect::steam::RootSource;
use rerun_core::policy::root::{AppDir, Create};
use rerun_core::sys::System;
use rerun_core::sys::fake::{FakeSystem, FsOp};
use rerun_core::sys::fs::tag;
use rerun_core::sys::registry::RegValue;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::tests::{INSTALL, LAD, RERUN, Ran, bare, build, expect, hash_of, txn_of};

const STEAM: &str = r"C:\Program Files (x86)\Steam";
const LIB: &str = r"D:\SteamLibrary";
const G: &str = r"D:\SteamLibrary\steamapps\common\G";
const RYZEN_5950X: &str = include_str!("../../../tests/fixtures/cpu/ryzen9-5950x.json");
/// The ID of app 220 (`plan::profile_id`, pinned in the core).
const ID: &str = "323ad79fbc93ca3e73b0b152a5d44616";

/// A synthetic PE image from its non-zero byte runs (`rerun-core`, `detect::pe::testfx`,
/// `Builder::x86`/`x64`).
fn pe(runs: &[(usize, &str)]) -> Vec<u8> {
    let mut b = vec![0u8; 1024];
    for (at, hex) in runs {
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(pair).unwrap();
            b[at + i] = u8::from_str_radix(s, 16).unwrap();
        }
    }
    b
}

fn x86() -> Vec<u8> {
    pe(&[
        (0x0, "4d5a"),
        (0x3c, "80"),
        (0x80, "5045"),
        (0x84, "4c0101"),
        (0x94, "e0"),
        (0x96, "02010b01"),
        (0xb6, "40"),
        (0xd5, "02"),
        (0xdc, "02"),
        (0xde, "4081"),
        (0xf4, "10"),
        (0x178, "2e7264617461"),
        (0x180, "01"),
        (0x185, "10"),
        (0x189, "02"),
        (0x18d, "02"),
    ])
}

fn x64() -> Vec<u8> {
    pe(&[
        (0x0, "4d5a"),
        (0x3c, "80"),
        (0x80, "5045"),
        (0x84, "648601"),
        (0x94, "f0"),
        (0x96, "22"),
        (0x98, "0b02"),
        (0xb3, "4001"),
        (0xd5, "02"),
        (0xdc, "02"),
        (0xde, "6081"),
        (0x104, "10"),
        (0x188, "2e7264617461"),
        (0x190, "01"),
        (0x195, "10"),
        (0x199, "02"),
        (0x19d, "02"),
    ])
}

fn lib_vdf() -> String {
    let mut out = String::from("\"libraryfolders\"\n{\n");
    for (i, p) in [STEAM, LIB].iter().enumerate() {
        out.push_str(&format!(
            "\t\"{i}\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n",
            p.replace('\\', r"\\")
        ));
    }
    out.push_str("}\n");
    out
}

/// The step file: a hard rule of at most `max` threads, Steam starts `FFLauncher.exe`, the
/// game is `game.exe`.
fn steps(max: u16) -> String {
    format!(
        r#"{{"format":1,"game":{{"steam":220}},"main_exe":"game.exe","steps":[{{"launch_method":{{"method":"direct","start":"FFLauncher.exe","cpu":{{"max_threads":{max},"single_l3":true,"smt":false}}}}}}]}}"#
    )
}

/// Steam with app 220 in `G` (a launcher and an x86 game), the 5950X topology, and the shim in
/// the install folder unless `no_shim`.
fn lm_sys(no_shim: bool, json: &str) -> FakeSystem {
    let acf = "\"AppState\"\n{\n\t\"appid\"\t\t\"220\"\n\t\"name\"\t\t\"G\"\n\t\"StateFlags\"\t\t\"4\"\n\t\"installdir\"\t\t\"G\"\n}\n";
    let mut b = bare()
        .value(
            RootSource::CurrentUser.key(),
            RootSource::CurrentUser.value_name(),
            RegValue::String(STEAM.to_owned()),
        )
        .file(
            format!(r"{STEAM}\steamapps\libraryfolders.vdf"),
            lib_vdf().into_bytes(),
        )
        .file(
            format!(r"{LIB}\steamapps\appmanifest_220.acf"),
            acf.as_bytes().to_vec(),
        )
        .file(format!(r"{G}\game.exe"), x86())
        .file(format!(r"{G}\FFLauncher.exe"), x64())
        .topology_json(RYZEN_5950X);
    if !no_shim {
        b = b.file(format!(r"{INSTALL}\rerun-launch.exe"), x64());
    }
    build(b, json)
}

fn option() -> String {
    format!(r#""{INSTALL}\rerun-launch.exe" --profile {ID} %command%"#)
}

const STEPS: &str = r"D:\Work\steps.json";

/// The plan output of C-LM1 (plan `P3-3` §5), golden; the profile bytes are LP1's.
fn c_lm1_golden(hash: &str) -> String {
    let note = rerun_core::plan::PROFILE_NOTE;
    let not = rerun_core::plan::NOT_RESTORED;
    let o = option();
    format!(
        r"root 0: {G}
  Steam app 220, library: {LIB}
  main executable: game.exe
root 1: {RERUN}\profiles
  Rerun's launch profiles: written by apply, read by rerun-launch at a game start
op 0: create file in root 1: {ID}.profile
  content: the launch profile, carried by the plan (no package)
  new: sha256 5546af7f07852e7c8d037c14250f85eb1ea713bba5d21d59409d83bafe6e649e, 297 bytes, attributes -
     launch profile {ID}: method direct, x86
     cpu max_threads 8, prefer any, single_l3 true, prefer_l3 none, smt false, mode hard
     start {G}\FFLauncher.exe
note: {not}
note: {note}
on this computer now (not part of the plan; rerun-launch selects again at every start):
  8 of 32 logical processors, group 0, mask 0x0000000000005555, cores 0-7, L3 #0 (32 MiB)
  hard: job affinity, inherited by the programs the started program starts
  hint: Steam starts a launcher, not the game; the game inherits the limit through the job unless it leaves it, and the check after about 5 s covers the launcher (a launcher that exits sooner shows exited_early); the launcher: {G}\FFLauncher.exe
  the game: game.exe
launch option for Steam (copy it):
  {o}
  paste it in Steam: the game > Properties > General > Launch options
  Rerun does not change Steam's settings: remove the option by hand after a revert
  existing launch options of the game go after %command%; an option that already holds %command% (another wrapper) cannot be combined
  moving or deleting rerun-launch.exe breaks the start through Steam until the option is removed

plan {hash} stored: 1 change
apply with: rerun apply {hash}
"
    )
}

#[test]
fn c_lm1_plan_shows_the_profile_the_selection_and_the_launch_option() {
    let sys = lm_sys(false, &steps(8));
    let p = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    assert_eq!(p.stdout, c_lm1_golden(&hash_of(&p)));
    assert!(p.stderr.is_empty(), "{}", p.stderr);
    // Without the shim in the install folder: a warning, the plan stays valid; the apply then
    // does not say "paste it now" (review L3).
    let sys = lm_sys(true, &steps(8));
    let p = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    assert!(
        p.stdout.contains(&format!(
            r"warning: rerun-launch.exe is not in Rerun's install folder; the option would not start the game: {INSTALL}\rerun-launch.exe"
        )),
        "{}",
        p.stdout
    );
    let a = expect(
        &sys,
        &["apply", &hash_of(&p), "--yes"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        a.stdout
            .contains("the launch option could not be offered or would not start the game")
    );
    assert!(!a.stdout.contains("now paste"));
}

#[test]
fn c_lm2_plan_dry_run_writes_nothing() {
    let sys = lm_sys(false, &steps(8));
    let dirs = [G, LAD];
    let before = crate::tests::snap_dirs(&sys, &dirs);
    let p = expect(
        &sys,
        &["plan", STEPS, "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert!(p.stdout.contains(&option()), "{}", p.stdout);
    crate::tests::same(&before, &crate::tests::snap_dirs(&sys, &dirs));
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
    // The plan stored afterwards has the hash the dry run showed (F1).
    let dry = p
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("plan "))
        .and_then(|l| l.split(' ').next())
        .unwrap()
        .to_owned();
    let real = expect(&sys, &["plan", STEPS], Answer::No, Exit::Report);
    assert_eq!(dry, hash_of(&real));
}

/// Plans and applies the step file: the transaction and the apply's output.
fn applied(sys: &FakeSystem) -> (String, Ran) {
    let p = expect(sys, &["plan", STEPS], Answer::No, Exit::Report);
    let a = expect(
        sys,
        &["apply", &hash_of(&p), "--yes"],
        Answer::No,
        Exit::Report,
    );
    (txn_of(&a), a)
}

/// The X12 lines of a profile that is gone.
fn gone() -> [String; 3] {
    [
        format!(
            "launch option: Rerun does not change Steam's settings; remove this launch option of the game in Steam by hand: {}",
            option()
        ),
        format!("  (and any launch option with --profile {ID})"),
        "  until it is removed, Steam starts the game through rerun-launch, which finds no profile and starts it unchanged".to_owned(),
    ]
}

fn has_all(text: &str, want: &[String]) {
    for w in want {
        assert!(text.contains(w.as_str()), "{w}\n{text}");
    }
}

const STAYS: &str =
    "stays and keeps applying through the launch option until the option is removed";
const BACK: &str =
    "from before this transaction is back and keeps applying through the launch option";
const NO_PROFILE: &str = "finds no profile";

#[test]
fn c_lm3_to_5_apply_revert_and_forget_say_what_becomes_of_the_profile() {
    let sys = lm_sys(false, &steps(8));
    let (t, a) = applied(&sys);
    // C-LM5.
    assert!(
        a.stdout
            .contains("now paste the launch option shown in the preview into Steam"),
        "{}",
        a.stdout
    );
    // C-LM4: forget's preview (declined): the profile stays and applies; nothing says it is gone.
    let f = expect(&sys, &["forget", &t], Answer::No, Exit::Refused);
    assert!(f.stdout.contains(STAYS), "{}", f.stdout);
    assert!(f.stdout.contains(&format!("to stop it, remove this launch option of the game in Steam by hand (Rerun does not change Steam's settings): {}", option())), "{}", f.stdout);
    assert!(!f.stdout.contains(NO_PROFILE), "{}", f.stdout);
    // C-LM3: the revert of a created profile: gone, once the revert completes, and after it.
    let d = expect(&sys, &["revert", &t, "--dry-run"], Answer::No, Exit::Report);
    assert!(
        d.stdout.contains("once the revert completes:"),
        "{}",
        d.stdout
    );
    has_all(&d.stdout, &gone());
    let r = expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    has_all(&r.stdout, &gone());
    assert!(!r.stdout.contains(STAYS), "{}", r.stdout);
}

#[test]
fn c_lm8_a_stacked_profile_comes_back_and_the_option_stays_set() {
    let sys = lm_sys(false, &steps(8));
    let (t1, _) = applied(&sys);
    crate::tests::put_steps(&sys, &steps(4));
    let (t2, _) = applied(&sys);
    // Txn 2 replaced Txn 1's profile: its revert brings that back, the option must stay.
    for args in [
        vec!["revert", t2.as_str(), "--dry-run"],
        vec!["revert", t2.as_str(), "--yes"],
    ] {
        let r = expect(&sys, &args, Answer::No, Exit::Report);
        assert!(r.stdout.contains(BACK), "{}", r.stdout);
        assert!(
            !r.stdout.contains("remove this launch option"),
            "{}",
            r.stdout
        );
        assert!(!r.stdout.contains(NO_PROFILE), "{}", r.stdout);
    }
    let r = expect(&sys, &["revert", &t1, "--yes"], Answer::No, Exit::Report);
    has_all(&r.stdout, &gone());
}

#[test]
fn c_lm9_a_changed_profile_is_left_and_keeps_applying() {
    let sys = lm_sys(false, &steps(8));
    let (t, _) = applied(&sys);
    let prof = format!(r"{RERUN}\profiles\{ID}.profile");
    let fx = sys.fake_fs();
    fx.remove_abs(Path::new(&prof)).unwrap();
    fx.put_file(Path::new(&prof), b"rerun-profile 1\nmethod=direct\n")
        .unwrap();
    sys.sync_all();
    let r = expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Open);
    assert!(r.stdout.contains(STAYS), "{}", r.stdout);
    assert!(!r.stdout.contains(NO_PROFILE), "{}", r.stdout);
}

#[test]
fn c_lm6_a_revert_after_local_app_data_moved_names_both_paths() {
    let sys = lm_sys(false, &steps(8));
    let fx = sys.fake_fs();
    // `LocalAppData` reached through a junction, so it can move under the same name.
    fx.rename_abs(Path::new(LAD), Path::new(&format!("{LAD}A")))
        .unwrap();
    fx.put_link(Path::new(LAD), tag::MOUNT_POINT, &format!("{LAD}A"))
        .unwrap();
    sys.sync_all();
    let (t, _) = applied(&sys);
    fx.rename_abs(Path::new(&format!("{LAD}A")), Path::new(&format!("{LAD}B")))
        .unwrap();
    fx.retarget(Path::new(LAD), &format!("{LAD}B")).unwrap();
    sys.sync_all();
    let want = [
        format!(
            r"Rerun's profiles folder is at another path than the transaction names (its hashes decide): named {LAD}A\Rerun\profiles"
        ),
        format!(r"  now {LAD}B\Rerun\profiles"),
    ];
    let d = expect(&sys, &["revert", &t, "--dry-run"], Answer::No, Exit::Report);
    has_all(&d.stdout, &want);
    let r = expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    has_all(&r.stdout, &want);
}

/// Replaces the launch result of the profile with `body`.
fn result(sys: &FakeSystem, body: &str) {
    let p = format!(r"{RERUN}\launch\{ID}.result");
    let _ = sys.fake_fs().remove_abs(Path::new(&p));
    sys.fake_fs()
        .put_file(Path::new(&p), body.as_bytes())
        .unwrap();
}

const APPLIED: &str = "rerun-result 1\nprofile=323ad79fbc93ca3e73b0b152a5d44616\ntime=1762600000\nrule=applied\ncpu=hard:8:32\npriority=none\ncheck=ok\nstart=created\nrule_child=none\n";
const MISSING: &str = "rerun-result 1\nprofile=323ad79fbc93ca3e73b0b152a5d44616\ntime=1762600000\nrule=skipped:profile_missing\ncpu=none\npriority=none\ncheck=none\nstart=created\nrule_child=none\n";
const LAUNCHER: &str = "Steam starts a launcher here: the check covered the launcher, not the game";

#[test]
fn c_lm7_status_names_the_launcher_and_the_launch_option() {
    let sys = lm_sys(false, &steps(8));
    let (t, _) = applied(&sys);
    // A6: the applied transaction holds a launcher profile.
    result(&sys, APPLIED);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout
            .contains(&format!(r"{LAUNCHER}: {G}\FFLauncher.exe")),
        "{}",
        s.stdout
    );
    // S1: a profile_missing result while a transaction holds the profile is no advice to remove.
    result(&sys, MISSING);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains(&format!(
            "was still set in Steam at that start; transaction {t} holds this profile now"
        )),
        "{}",
        s.stdout
    );
    assert!(!s.stdout.contains("remove it"), "{}", s.stdout);
    // After the revert: no holder. The applied result names no launcher any more (S2 bite), the
    // missing one advises removing the option.
    expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    result(&sys, APPLIED);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(!s.stdout.contains(LAUNCHER), "{}", s.stdout);
    result(&sys, MISSING);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains(&format!(
            "    the launch option with --profile {ID} was still set in Steam at that start; remove it"
        )),
        "{}",
        s.stdout
    );
    // A forgotten transaction whose profile stays still holds it (S2: forgotten included).
    let (t2, _) = applied(&sys);
    expect(&sys, &["forget", &t2, "--yes"], Answer::No, Exit::Report);
    result(&sys, APPLIED);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(s.stdout.contains(LAUNCHER), "{}", s.stdout);
    // Review L-b: a forgotten holder cannot be reverted: no "rerun revert" hint, remove the option.
    result(&sys, MISSING);
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains("a forgotten transaction left a profile of this ID and it was missing then: remove the launch option"),
        "{}",
        s.stdout
    );
    assert!(
        !s.stdout.contains("--dry-run shows its state"),
        "{}",
        s.stdout
    );
}

#[test]
fn c_lm10_plan_stores_nothing_when_rerun_s_folder_moved_meanwhile() {
    let sys = lm_sys(false, &steps(8));
    let fx = sys.fake_fs();
    fx.rename_abs(Path::new(LAD), Path::new(&format!("{LAD}A")))
        .unwrap();
    fx.put_link(Path::new(LAD), tag::MOUNT_POINT, &format!("{LAD}A"))
        .unwrap();
    fx.mkdir_all(Path::new(&format!("{LAD}B"))).unwrap();
    sys.sync_all();
    // After the preview (its second look at the install folder, the shim check), the next open
    // of LocalAppData is the one that creates Rerun's folder: point the junction elsewhere.
    let installs = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let (i2, d2) = (Arc::clone(&installs), Arc::clone(&done));
    fx.on_step(move |fs, ev| {
        if ev.op != FsOp::OpenAbs {
            return;
        }
        if ev.name == INSTALL {
            i2.fetch_add(1, Ordering::SeqCst);
        } else if ev.name == LAD
            && i2.load(Ordering::SeqCst) >= 2
            && d2.fetch_add(1, Ordering::SeqCst) == 0
        {
            fs.retarget(Path::new(LAD), &format!("{LAD}B")).unwrap();
        }
    });
    let r = expect(&sys, &["plan", STEPS], Answer::No, Exit::Refused);
    fx.clear_on_step();
    assert_eq!(done.load(Ordering::SeqCst), 1, "the hook fired once");
    assert!(
        r.stderr
            .contains("Rerun's folder moved while the plan was made; nothing stored"),
        "{}",
        r.stderr
    );
    for d in [
        format!(r"{LAD}A\Rerun\plans"),
        format!(r"{LAD}B\Rerun\plans"),
    ] {
        #[expect(clippy::disallowed_methods, reason = "test: look into the fake")]
        let open = sys.fs().open_dir(Path::new(&d));
        let files = open.map(|h| h.read_dir(None).unwrap().len()).unwrap_or(0);
        assert_eq!(files, 0, "{d}");
    }
}
