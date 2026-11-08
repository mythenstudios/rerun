//! C-LM (P3-3d, plan `P3-3` §7.5): `launch_method` through the CLI against the fake, with the
//! 5950X topology and synthetic PE images (the sparse bytes of `rerun-core`'s test builder).
//! - C-LM1 `plan` shows the profile, the selection on this computer, the launcher hint, the
//!   note and the launch option with the install folder; without `rerun-launch.exe` a warning.
//! - C-LM2 `plan --dry-run` writes nothing (no `Rerun`, no `profiles`).
//! - C-LM3 `revert --dry-run` and the revert report name the launch option literally and any
//!   option with `--profile <id>` (X12).
//! - C-LM4 the `forget` preview: the profile stays and keeps applying through the option.
//! - C-LM5 `apply` ends with "now paste the launch option".
//! - C-LM6 (S3) a revert after `<LocalAppData>` moved: the profiles folder's two paths.
//! - C-LM7 (A6, A7) `status`: the check covered the launcher; `profile_missing` says the option
//!   is still set.

use std::path::Path;

use rerun_core::detect::steam::RootSource;
use rerun_core::policy::root::{AppDir, Create};
use rerun_core::sys::fs::tag;
use rerun_core::sys::registry::RegValue;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::tests::{INSTALL, LAD, RERUN, bare, build, expect, hash_of, txn_of};

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

/// The step file: a hard rule, Steam starts `FFLauncher.exe`, the game is `game.exe`.
fn steps(extra: &str) -> String {
    format!(
        r#"{{"format":1,"game":{{"steam":220}},"main_exe":"game.exe","steps":[{{"launch_method":{{"method":"direct","start":"FFLauncher.exe","cpu":{{"max_threads":8,"single_l3":true,"smt":false}}{extra}}}}}]}}"#
    )
}

/// Steam with app 220 in `G` (a launcher and an x86 game), the 5950X topology, and the shim in
/// the install folder unless `no_shim`.
fn lm_sys(no_shim: bool, json: &str) -> rerun_core::sys::fake::FakeSystem {
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

#[test]
fn c_lm1_plan_shows_the_profile_the_selection_and_the_launch_option() {
    let sys = lm_sys(false, &steps(""));
    let p = expect(
        &sys,
        &["plan", r"D:\Work\steps.json"],
        Answer::No,
        Exit::Report,
    );
    let o = &p.stdout;
    for want in [
        &format!(r"root 1: {RERUN}\profiles"),
        "  Rerun's launch profiles: written by apply, read by rerun-launch at a game start",
        &format!("     launch profile {ID}: method direct, x86"),
        "     cpu max_threads 8, prefer any, single_l3 true, prefer_l3 none, smt false, mode hard",
        &format!(r"     start {G}\FFLauncher.exe"),
        "on this computer now (not part of the plan; rerun-launch selects again at every start):",
        "  8 of 32 logical processors, group 0, mask 0x0000000000005555, cores 0-7, L3 #0 (32 MiB)",
        "  hard: job affinity, inherited by the programs the started program starts",
        &format!(
            r"the check after about 5 s covers the launcher (a launcher that exits sooner shows exited_early); the launcher: {G}\FFLauncher.exe"
        ),
        "  the game: game.exe",
        "note: launch profile: rerun-launch runs only when Steam starts the game",
        "launch option for Steam (copy it):",
        &format!("  {}", option()),
        "  paste it in Steam: the game > Properties > General > Launch options",
        "  Rerun does not change Steam's settings: remove the option by hand after a revert",
    ] {
        assert!(o.contains(want), "{want}\n{o}");
    }
    assert!(!o.contains("warning: rerun-launch.exe"), "{o}");
    assert!(!o.contains("hint: this computer has more than one"), "{o}");
    // Without the shim in the install folder: a warning, the plan stays valid.
    let sys = lm_sys(true, &steps(""));
    let p = expect(
        &sys,
        &["plan", r"D:\Work\steps.json"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        p.stdout.contains(&format!(
            r"warning: rerun-launch.exe is not in Rerun's install folder; the option would not start the game: {INSTALL}\rerun-launch.exe"
        )),
        "{}",
        p.stdout
    );
}

#[test]
fn c_lm2_plan_dry_run_writes_nothing() {
    let sys = lm_sys(false, &steps(""));
    let before = crate::tests::snap_all(&sys);
    let p = expect(
        &sys,
        &["plan", r"D:\Work\steps.json", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert!(p.stdout.contains(&option()), "{}", p.stdout);
    crate::tests::same(&before, &crate::tests::snap_all(&sys));
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
    // The plan stored afterwards has the same hash as the dry run showed.
    let dry = p
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("plan "))
        .and_then(|l| l.split(' ').next())
        .unwrap()
        .to_owned();
    let real = expect(
        &sys,
        &["plan", r"D:\Work\steps.json"],
        Answer::No,
        Exit::Report,
    );
    assert_eq!(
        dry,
        hash_of(&real),
        "F1: the same plan with and without Rerun's folder"
    );
}

/// Plans and applies the steps: the transaction and the apply's output.
fn applied(sys: &rerun_core::sys::fake::FakeSystem) -> (String, crate::tests::Ran) {
    let p = expect(
        sys,
        &["plan", r"D:\Work\steps.json"],
        Answer::No,
        Exit::Report,
    );
    let a = expect(
        sys,
        &["apply", &hash_of(&p), "--yes"],
        Answer::No,
        Exit::Report,
    );
    (txn_of(&a), a)
}

#[test]
fn c_lm3_to_5_apply_revert_and_forget_name_the_launch_option() {
    let sys = lm_sys(false, &steps(""));
    let (t, a) = applied(&sys);
    // C-LM5.
    assert!(
        a.stdout
            .contains("now paste the launch option shown in the preview into Steam"),
        "{}",
        a.stdout
    );
    assert!(a.stdout.contains(&option()), "{}", a.stdout);
    // C-LM3: the preview of the revert and its report.
    let x12 = [
        format!(
            "launch option: Rerun does not change Steam's settings; remove this launch option of the game in Steam by hand: {}",
            option()
        ),
        format!("  (and any launch option with --profile {ID})"),
        "  until it is removed, Steam starts the game through rerun-launch, which finds no profile and starts it unchanged (rerun status: profile_missing)".to_owned(),
    ];
    let d = expect(&sys, &["revert", &t, "--dry-run"], Answer::No, Exit::Report);
    for w in &x12 {
        assert!(d.stdout.contains(w.as_str()), "{w}\n{}", d.stdout);
    }
    // C-LM4: forget's preview (declined).
    let f = expect(&sys, &["forget", &t], Answer::No, Exit::Refused);
    assert!(
        f.stdout.contains(&format!(
            "forget leaves the launch profile {ID} where it is: it keeps applying through the launch option until you remove the option"
        )),
        "{}",
        f.stdout
    );
    assert!(f.stdout.contains(&x12[0]), "{}", f.stdout);
    let r = expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    for w in &x12 {
        assert!(r.stdout.contains(w.as_str()), "{w}\n{}", r.stdout);
    }
}

#[test]
fn c_lm6_a_revert_after_local_app_data_moved_names_both_paths() {
    let sys = lm_sys(false, &steps(""));
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
    for w in &want {
        assert!(d.stdout.contains(w.as_str()), "{w}\n{}", d.stdout);
    }
    let r = expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    for w in &want {
        assert!(r.stdout.contains(w.as_str()), "{w}\n{}", r.stdout);
    }
}

#[test]
fn c_lm7_status_names_the_launcher_and_a_launch_option_still_set() {
    let sys = lm_sys(false, &steps(""));
    let (t, _) = applied(&sys);
    let launch = format!(r"{RERUN}\launch");
    let ok = format!(
        "rerun-result 1\nprofile={ID}\ntime=1762600000\nrule=applied\ncpu=hard:8:32\npriority=none\ncheck=ok\nstart=created\nrule_child=none\n"
    );
    sys.fake_fs()
        .put_file(Path::new(&format!(r"{launch}\{ID}.result")), ok.as_bytes())
        .unwrap();
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains(&format!(
            r"    Steam starts a launcher here: the check covered the launcher, not the game: {G}\FFLauncher.exe"
        )),
        "{}",
        s.stdout
    );
    expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    let missing = format!(
        "rerun-result 1\nprofile={ID}\ntime=1762600000\nrule=skipped:profile_missing\ncpu=none\npriority=none\ncheck=none\nstart=created\nrule_child=none\n"
    );
    sys.fake_fs()
        .remove_abs(Path::new(&format!(r"{launch}\{ID}.result")))
        .unwrap();
    sys.fake_fs()
        .put_file(
            Path::new(&format!(r"{launch}\{ID}.result")),
            missing.as_bytes(),
        )
        .unwrap();
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.contains(&format!(
            "    the launch option with --profile {ID} is still set in Steam; remove it"
        )),
        "{}",
        s.stdout
    );
    assert!(!s.stdout.contains("covered the launcher"), "{}", s.stdout);
}
