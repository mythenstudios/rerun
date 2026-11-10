//! Windows Sandbox tests (tier 3 of `docs/09-testing.md`, audit A2 "sandbox script before
//! P2-11"): real writes to the real `HKCU` and the real `LocalAppData`, run by
//! `scripts/sandbox-test.wsb` in the disposable Sandbox VM and nowhere else.
//!
//! Every test here is `#[ignore]` and calls [`sandbox_guard`] **first**: it panics unless
//! `RERUN_SANDBOX=1`, `USERNAME` is `WDAGUtilityAccount` and the profile is that account's, so
//! an `--ignored` run on a developer machine or a CI runner changes nothing. The decision is
//! tested on injected values below (normal tests), and a source check keeps the guard the first
//! statement of every ignored test.
//!
//! Game folders are `C:\RerunSandbox\<case>\game` (not below `target/`: the Sandbox has no
//! checkout to build in). The tests share one VM session, run with `--test-threads=1`, and
//! undo what they leave in shared registry keys.
//!
//! SB-L5 (P2-11b): `compat_layer` with the production tokens on the real `HKCU`, drift by
//! `reg add`, a link key at `AppCompatFlags\Layers`. The facts it builds on (the tab's
//! spelling, which path name Windows matches) came from the probes SB-L1 to SB-L4 and SB-L6
//! (`scripts/sandbox-probe-layers.ps1`, `docs/09-testing.md`).
//!
//! Open (`docs/09-testing.md` manual list): an exFAT volume and a third party holding the
//! folder need admin tooling or a second process.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use std::time::Duration;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use sha2::{Digest, Sha256};

use super::super::testfx::{
    AppHive, is_elevated, note, process_account, sandbox_decision, sandbox_guard,
};
use super::super::{WinHttp, WinRegistry, WinSystem};
use crate::catalog::model::{
    Api, Arch, ArchList, Asset, Hex, Id, Package, PackageFile, PackageSource, Status, Tier,
};
use crate::exec::reg_tests::{SUB, VENDOR_GAME, rt1_steps};
use crate::exec::tests::{N, NEW, OLD, X, t1_spec};
use crate::exec::{ApplyError, ExecCtx, Outcome, Refusal, apply, forget, revert, verify};
use crate::journal::{Closing, InstanceTag, Observed};
use crate::pkg::download::{cache_name, downloads, fetch};
use crate::pkg::extract::{How, extract, layout};
use crate::plan::{PlanHash, store};
use crate::policy::root::{AppDir, Create, ForbiddenRoots, GameDir};
use crate::prim::GameBuild;
use crate::prim::tests::rel;
use crate::prim::{PlanCtx, Step, plan};
use crate::sys::contract::{RegFixture, registry_read_contract, registry_write_contract};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, Registry, reg_type};
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use crate::sys::{KnownFolder, System};

/// Where the sandbox tests keep their game folders.
const BASE: &str = r"C:\RerunSandbox";

// ---------- The guard (normal tests, run everywhere) ----------

fn hkcu(p: impl AsRef<str>) -> RegKey {
    RegKey::new(Hive::CurrentUser, RegView::Native, p)
}

const OK_PROFILE: &str = r"C:\Users\WDAGUtilityAccount";

#[test]
fn sandbox_gate_needs_all_three_conditions() {
    let ok = |f, u, p| sandbox_decision(f, u, p, Some("WDAGUtilityAccount"), None).is_ok();
    assert!(ok(Some("1"), Some("WDAGUtilityAccount"), Some(OK_PROFILE)));
    assert!(ok(
        Some("1"),
        Some("wdagutilityaccount"),
        Some(r"c:\users\wdagutilityaccount\")
    ));
    // Each condition alone missing refuses.
    assert!(!ok(None, Some("WDAGUtilityAccount"), Some(OK_PROFILE)));
    assert!(!ok(Some("0"), Some("WDAGUtilityAccount"), Some(OK_PROFILE)));
    assert!(!ok(
        Some("true"),
        Some("WDAGUtilityAccount"),
        Some(OK_PROFILE)
    ));
    assert!(!ok(Some(""), Some("WDAGUtilityAccount"), Some(OK_PROFILE)));
    assert!(!ok(Some("1"), None, Some(OK_PROFILE)));
    assert!(!ok(Some("1"), Some("developer"), Some(OK_PROFILE)));
    assert!(!ok(Some("1"), Some("WDAGUtilityAccount"), None));
    assert!(!ok(
        Some("1"),
        Some("WDAGUtilityAccount"),
        Some(r"C:\Users\developer")
    ));
    // The environment says Sandbox but the process token belongs to another account (or none).
    for who in [Some("developer"), None] {
        assert!(
            sandbox_decision(
                Some("1"),
                Some("WDAGUtilityAccount"),
                Some(OK_PROFILE),
                who,
                None
            )
            .is_err()
        );
    }
    // The flag alone, or the account name alone (a developer who sets one by habit), refuses.
    assert!(!ok(
        Some("1"),
        Some("developer"),
        Some(r"C:\Users\developer")
    ));
    assert!(!ok(None, Some("WDAGUtilityAccount"), Some(OK_PROFILE)));
    // The account name only as a prefix or a parent folder is not the account.
    assert!(!ok(
        Some("1"),
        Some("WDAGUtilityAccount2"),
        Some(OK_PROFILE)
    ));
    assert!(!ok(
        Some("1"),
        Some("WDAGUtilityAccount"),
        Some(r"C:\Users\WDAGUtilityAccount\other")
    ));
}

/// The CI opt-in (`RERUN_CI_SANDBOX=1`) admits the runner's two accounts and only with the
/// flag; the account must still be the process token's and match `USERNAME` and the profile.
#[test]
fn sandbox_gate_admits_the_ci_accounts_only_with_the_ci_flag() {
    fn d(
        flag: Option<&str>,
        user: Option<&str>,
        p: Option<&str>,
        who: Option<&str>,
        ci: Option<&str>,
    ) -> bool {
        sandbox_decision(flag, user, p, who, ci).is_ok()
    }
    for name in ["runneradmin", "rerunci"] {
        let profile = format!(r"C:\Users\{name}");
        let p = Some(profile.as_str());
        assert!(d(Some("1"), Some(name), p, Some(name), Some("1")));
        // Without the CI flag (every normal run on a runner) the guard refuses.
        assert!(!d(Some("1"), Some(name), p, Some(name), None));
        assert!(!d(Some("1"), Some(name), p, Some(name), Some("0")));
        // Without the sandbox flag, or with the environment of another account.
        assert!(!d(None, Some(name), p, Some(name), Some("1")));
        assert!(!d(Some("1"), Some("developer"), p, Some(name), Some("1")));
        assert!(!d(
            Some("1"),
            Some(name),
            Some(r"C:\Users\developer"),
            Some(name),
            Some("1")
        ));
        // The environment names the CI account but the token is a developer's.
        assert!(!d(Some("1"), Some(name), p, Some("developer"), Some("1")));
    }
    // The CI flag does not admit any other account.
    assert!(!d(
        Some("1"),
        Some("developer"),
        Some(r"C:\Users\developer"),
        Some("developer"),
        Some("1")
    ));
}

/// On any machine that is not the Sandbox the real guard panics (and so does every ignored
/// test, before it touches anything). Skipped inside the Sandbox, where it passes.
#[test]
fn sandbox_guard_refuses_outside_the_sandbox() {
    #[expect(
        clippy::disallowed_methods,
        reason = "reads the account name, not a path"
    )]
    let username = std::env::var("USERNAME").unwrap_or_default();
    if username.eq_ignore_ascii_case("WDAGUtilityAccount") {
        return;
    }
    let r = std::panic::catch_unwind(sandbox_guard);
    assert!(r.is_err(), "the guard let a non-Sandbox account through");
}

/// Every `#[ignore]` test of this file calls `sandbox_guard()` as its first statement, and the
/// file has no other ignored attribute form. Sandbox tests belong in this file only: the check
/// reads this file's source, so a sandbox test elsewhere would escape it.
#[test]
fn every_ignored_sandbox_test_starts_with_the_guard() {
    const IGNORED: &str = r##"#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]"##;
    let src = include_str!("sandbox.rs");
    let lines: Vec<&str> = src.lines().collect();
    let mut seen = 0;
    for (i, l) in lines.iter().enumerate() {
        if l.trim() != IGNORED {
            // Built from parts so that this check does not match its own source.
            let bad = [format!("{}{}", "#[", "ignore"), format!("cfg_{}", "attr")];
            let code =
                !l.trim_start().starts_with("//") && !l.trim_start().starts_with("const IGNORED");
            assert!(
                !code || bad.iter().all(|b| !l.contains(b.as_str())),
                "line {}: use the one ignore attribute with the Sandbox hint, on its own line \
                 (no conditional ignore, no second attribute on the line)",
                i + 1
            );
            continue;
        }
        seen += 1;
        let body = lines[i + 1..]
            .iter()
            .skip_while(|l| !l.trim_end().ends_with('{'))
            .nth(1)
            .map(|l| l.trim());
        assert_eq!(
            body,
            Some("sandbox_guard();"),
            "line {}: the ignored test does not start with the guard",
            i + 1
        );
    }
    assert!(seen >= 8, "found only {seen} ignored tests");
}

// ---------- Harness ----------

/// A game folder `C:\RerunSandbox\<case>\game` with a copy of `cmd.exe` as `game.exe` (the
/// Sandbox of build 26100 has no `System32\notepad.exe`: Notepad is a Store app there), the
/// real `WinSystem` (real `LocalAppData`, real `HKCU`), and the package files of
/// `t1_spec` in the real `LocalAppData\Rerun\packages`.
struct Sb {
    sys: WinSystem,
    game: PathBuf,
    install: PathBuf,
}

impl Sb {
    fn new(case: &str) -> Self {
        sandbox_guard();
        assert!(
            !is_elevated(),
            "the sandbox runner is elevated: the registry write side refuses an elevated \
             process (S2); start the tests from a non-elevated shell (scripts/sandbox-run.ps1)"
        );
        let base = Path::new(BASE).join(case);
        let _ = std::fs::remove_dir_all(&base);
        let game = base.join("game");
        let install = base.join("install");
        std::fs::create_dir_all(&game).unwrap();
        std::fs::create_dir_all(&install).unwrap();
        let sys = WinSystem::new().unwrap_or_else(|e| panic!("{e}"));
        let lad = sys.known_folders().get(KnownFolder::LocalAppData).unwrap();
        let account = process_account().expect("the guard passed, so the account is known");
        assert!(
            lad.to_string_lossy()
                .to_ascii_lowercase()
                .contains(&format!(r"\users\{}\", account.to_ascii_lowercase())),
            "LocalAppData is {}, not the profile of the account the guard accepted",
            lad.display()
        );
        let pkg = lad.join(r"Rerun\packages\fix-pack\1.0.2");
        let _ = std::fs::remove_dir_all(&pkg);
        std::fs::create_dir_all(pkg.join("mods")).unwrap();
        std::fs::write(pkg.join("d3d9.dll"), NEW).unwrap();
        std::fs::write(pkg.join(r"mods\x.dll"), X).unwrap();
        std::fs::write(pkg.join("new.dll"), N).unwrap();
        std::fs::write(game.join("d3d9.dll"), OLD).unwrap();
        let mut perm = std::fs::metadata(game.join("d3d9.dll"))
            .unwrap()
            .permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(game.join("d3d9.dll"), perm).unwrap();
        // A real PE image: users() and Busy see a real mapped image, with Defender watching.
        let image = sys
            .known_folders()
            .get(KnownFolder::Windows)
            .unwrap()
            .join(r"System32\cmd.exe");
        std::fs::copy(&image, game.join("game.exe"))
            .unwrap_or_else(|e| panic!("{}: {e}", image.display()));
        Self { sys, game, install }
    }

    fn with<R>(&self, f: impl FnOnce(&ExecCtx<'_>, &ForbiddenRoots) -> R) -> R {
        let fr =
            ForbiddenRoots::resolve(&self.sys, &self.install).unwrap_or_else(|e| panic!("{e}"));
        let app = AppDir::open(&self.sys, Create::IfMissing)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap();
        let cx = ExecCtx {
            sys: &self.sys,
            fr: &fr,
            app: &app,
            tag: InstanceTag::new(),
        };
        f(&cx, &fr)
    }

    /// Plans `steps` (main executable `game.exe`) and stores the plan; `Err` is the planner's
    /// refusal.
    fn try_plan(&self, steps: &[Step]) -> Result<PlanHash, String> {
        self.with(|cx, fr| {
            let g = GameDir::open_manual(&self.sys, fr, &self.game)
                .unwrap_or_else(|e| panic!("game folder refused: {e}"));
            let main = rel("game.exe");
            let p = plan(
                steps,
                &PlanCtx {
                    game: &g,
                    app: Some(cx.app),
                    steam_app: None,
                    main_exe: Some(&main),
                    reg: crate::policy::registry::RegPolicy.reader(&self.sys),
                    app_path: None,
                    user_data: None,
                },
            )
            .map_err(|e| e.to_string())?;
            Ok(store(cx.app, &p.encode().unwrap()).unwrap())
        })
    }

    fn plan_steps(&self, steps: &[Step]) -> PlanHash {
        self.try_plan(steps).unwrap_or_else(|e| panic!("{e}"))
    }

    fn snap(&self, keys: Vec<RegKey>) -> Snapshot {
        self.with(|_, fr| {
            let g = GameDir::open_manual(&self.sys, fr, &self.game).unwrap();
            snapshot(
                self.sys.registry(),
                &Scope {
                    dirs: vec![SnapRoot::new(g.dir(), "game")],
                    keys,
                },
            )
            .unwrap()
        })
    }

    fn apply_ok(&self, h: &PlanHash) -> crate::journal::TxnId {
        match self.with(|cx, _| apply(cx, h)) {
            Ok(Outcome::Applied(t)) => t,
            other => panic!("{other:?}"),
        }
    }
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

/// The keys the registry round trips compare.
fn rt_keys() -> Vec<RegKey> {
    vec![hkcu(r"Software\Vendor"), hkcu(r"Software\New")]
}

/// The real-`HKCU` fixture with the starting state of the R-T1 plan: `VENDOR_GAME` holds a
/// `REG_SZ` `TypeChange`; the keys of `SUB` do not exist.
fn rt_hive() -> AppHive {
    let h = AppHive::real_user().unwrap_or_else(|e| panic!("{e}"));
    wipe(&h);
    h.key(&hkcu(VENDOR_GAME)).unwrap();
    let text = RegValue::String("text".into()).encode().unwrap().1;
    h.raw(&hkcu(VENDOR_GAME), "TypeChange", reg_type::REG_SZ, &text)
        .unwrap();
    h
}

/// Removes what the registry round trips create or leave, bottom-up; missing keys are fine.
fn wipe(h: &AppHive) {
    for p in [
        SUB,
        r"Software\New\Prod",
        r"Software\New",
        VENDOR_GAME,
        r"Software\Vendor",
        r"Software\RerunVendor",
    ] {
        let _ = h.delete_key(&hkcu(p));
    }
}

// ---------- File side on the real LocalAppData (T1, T6, T8) ----------

/// T1 on the real `LocalAppData`: apply, verify, revert; the game folder identical.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_t1_round_trip_on_the_real_local_app_data() {
    sandbox_guard();
    let w = Sb::new("t1");
    let before = w.snap(vec![]);
    let h = w.plan_steps(&[Step::FileInstall(t1_spec())]);
    let t = w.apply_ok(&h);
    assert_eq!(read(&w.game.join("d3d9.dll")), NEW);
    assert_eq!(read(&w.game.join(r"mods\a\x.dll")), X);
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.halted.is_none(), "{v:?}");
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = w.snap(vec![]);
    assert!(before == after, "{:#?}", before.diff(&after));
    assert_eq!(w.plan_steps(&[Step::FileInstall(t1_spec())]), h);
}

/// T6: a file the user edited is left; everything else reverts; `forget` closes.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_t6_leaves_a_file_the_user_edited() {
    sandbox_guard();
    let w = Sb::new("t6");
    let h = w.plan_steps(&[Step::FileInstall(t1_spec())]);
    let t = w.apply_ok(&h);
    std::fs::write(w.game.join("new.dll"), b"edited by the user").unwrap();
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, None, "{rep:?}");
    for o in &rep.ops {
        let want = if o.op == 4 {
            Observed::Foreign
        } else {
            Observed::After
        };
        assert_eq!(o.observed, want, "{rep:?}");
    }
    assert_eq!(read(&w.game.join("new.dll")), b"edited by the user");
    assert_eq!(read(&w.game.join("d3d9.dll")), OLD);
    w.with(|cx, _| forget(cx, &t)).unwrap();
}

fn start_game(w: &Sb) -> Child {
    // `cmd /d /q /k` reads commands from its stdin: with a pipe that stays open (held by the
    // returned `Child`) it waits until it is killed. No console window, no AutoRun.
    let mut c = Command::new(w.game.join("game.exe"))
        .args(["/d", "/q", "/k"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start the cmd copy: {e}"));
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        c.try_wait().unwrap().is_none(),
        "the cmd copy exited at once; no running image to test with"
    );
    c
}

/// T8 with a real running process: a copy of `cmd.exe` is the main executable and runs.
/// `apply` is refused as `Busy` (a real image mapped, real `users()`), nothing is written;
/// after the process ended, the same plan applies and reverts.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_t8_refuses_while_the_real_game_process_runs() {
    sandbox_guard();
    let w = Sb::new("t8");
    let h = w.plan_steps(&[Step::FileInstall(t1_spec())]);
    let before = w.snap(vec![]);
    let mut child = start_game(&w);
    let r = w.with(|cx, _| apply(cx, &h));
    let busy = matches!(&r, Err(ApplyError::Refused(Refusal::Busy(s))) if s.as_str().ends_with("game.exe"));
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(busy, "{r:?}");
    let after = w.snap(vec![]);
    assert!(before == after, "{:#?}", before.diff(&after));
    // Ended: a moment for the image section to go, then the plan applies and reverts.
    std::thread::sleep(Duration::from_millis(500));
    let t = w.apply_ok(&h);
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let end = w.snap(vec![]);
    assert!(before == end, "{:#?}", before.diff(&end));
}

// ---------- Registry on the real HKCU ----------

/// `registry_write_contract` against the real `WinRegistry` at `HKCU\Software\RerunSandbox`:
/// link keys under a `Software\<Vendor>` key (RW5), `RegFlushKey` on the real
/// `RegOpenCurrentUser` handle (RW7), kernel names (`\REGISTRY\USER\<SID>\...`), rename and
/// delete races. A skipped case is reported, not hidden.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_registry_write_contract_on_the_real_hkcu() {
    sandbox_guard();
    assert!(!is_elevated(), "elevated: the write side would refuse");
    let h = AppHive::real_user().unwrap_or_else(|e| panic!("{e}"));
    let reg = WinRegistry::new().unwrap();
    let root = hkcu(r"Software\RerunSandbox\WriteContract");
    h.key(&root).unwrap();
    let skips = registry_write_contract(&reg, &h, &root)
        .unwrap_or_else(|e| panic!("registry_write_contract: {e}"));
    for s in &skips {
        super::super::testfx::note(&format!("sandbox: registry_write_contract skipped {s}"));
    }
    // Links are followed in a real hive and the real hive does the renames.
    assert!(skips.is_empty(), "skipped in the real HKCU: {skips:?}");
}

/// `registry_read_contract` against the real `HKCU` (links are followed here, which an app hive
/// refuses).
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_registry_read_contract_on_the_real_hkcu() {
    sandbox_guard();
    let h = AppHive::real_user().unwrap_or_else(|e| panic!("{e}"));
    let reg = WinRegistry::new().unwrap();
    // A fresh root per run: the contract wants it empty, and a Sandbox restarted from inside
    // keeps the keys of an earlier run (seen in the first run). The root is never removed, on
    // purpose: the Sandbox is disposable.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = hkcu(format!(
        r"Software\RerunSandbox\ReadContract-{}-{stamp}",
        std::process::id()
    ));
    h.key(&root).unwrap();
    let skips = registry_read_contract(&reg, &h, &root).unwrap_or_else(|e| panic!("{e}"));
    for s in skips {
        super::super::testfx::note(&format!("sandbox: registry_read_contract skipped {s}"));
    }
}

/// The read side of `AppCompatFlags` (the keys `compat_layer` will use, P2-11): they read
/// without error whether present or not, in both views, for the user and the machine; none is a
/// link. Reads only.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_app_compat_flags_read_side() {
    sandbox_guard();
    let reg = WinRegistry::new().unwrap();
    let flags = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags";
    for hive in [Hive::CurrentUser, Hive::LocalMachine] {
        for view in [RegView::Native, RegView::Wow32] {
            for sub in ["", r"\Layers"] {
                let k = RegKey::new(hive, view, format!("{flags}{sub}"));
                let exists = reg.key_exists(&k).unwrap_or_else(|e| panic!("{k}: {e}"));
                if exists {
                    reg.values(&k).unwrap_or_else(|e| panic!("{k}: {e}"));
                    reg.subkeys(&k).unwrap_or_else(|e| panic!("{k}: {e}"));
                    assert!(reg.link(&k).unwrap().is_none(), "{k} is a link key");
                }
            }
        }
    }
}

/// A link key planted at `Software\RerunVendor` (a `Software\<Vendor>` key) pointing elsewhere
/// in `HKCU`: `registry_set` must not write through it. The planner may refuse, or `apply`
/// must; either way nothing appears at the link target.
fn vendor_link_case(case: &str, link_before_plan: bool) {
    let w = Sb::new(case);
    let h = AppHive::real_user().unwrap_or_else(|e| panic!("{e}"));
    wipe(&h);
    let target = hkcu(r"Software\RerunSandbox\LinkTarget");
    let vendor = hkcu(r"Software\RerunVendor");
    h.key(&target).unwrap();
    let steps = [crate::prim::reg_tests::step(
        r"HKCU\Software\RerunVendor\Prod",
        vec![crate::prim::reg_tests::dword("A", 1)],
    )];
    let before = w.snap(vec![target.clone()]);
    let mut planned = None;
    if !link_before_plan {
        planned = Some(w.try_plan(&steps));
    }
    assert!(
        h.link(&vendor, &target).unwrap(),
        "real HKCU makes link keys"
    );
    if link_before_plan {
        planned = Some(w.try_plan(&steps));
    }
    match planned.unwrap() {
        Err(why) => super::super::testfx::note(&format!("sandbox {case}: planner refused: {why}")),
        Ok(hash) => {
            let r = w.with(|cx, _| apply(cx, &hash));
            assert!(
                !matches!(r, Ok(Outcome::Applied(_))),
                "applied through a link key at Software\\RerunVendor"
            );
            super::super::testfx::note(&format!("sandbox {case}: apply refused: {r:?}"));
        }
    }
    let after = w.snap(vec![target.clone()]);
    assert!(before == after, "{:#?}", before.diff(&after));
    assert!(
        !w.sys
            .registry()
            .key_exists(&target.join("Prod"))
            .unwrap_or_else(|e| panic!("{e}")),
        "a key appeared at the link target"
    );
    // The link key itself is removed again (a link is deleted by its own handle).
    h.delete_key(&vendor).unwrap();
}

#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_link_key_at_a_vendor_key_planted_before_the_plan() {
    sandbox_guard();
    vendor_link_case("link-before", true);
}

#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_link_key_at_a_vendor_key_planted_after_the_plan() {
    sandbox_guard();
    vendor_link_case("link-after", false);
}

/// Snapshot over a link key in the real hive: the link is one `RegLink` entry and is not
/// entered; a value behind it shows only at its target, once.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_snapshot_over_a_link_key() {
    sandbox_guard();
    let h = AppHive::real_user().unwrap_or_else(|e| panic!("{e}"));
    let reg = WinRegistry::new().unwrap();
    let scope = hkcu(r"Software\RerunSandbox\SnapLink");
    let target = scope.join("Target");
    let link = scope.join("Link");
    h.key(&target).unwrap();
    h.raw(
        &target,
        "OnlyAtTarget",
        reg_type::REG_DWORD,
        &7u32.to_le_bytes(),
    )
    .unwrap();
    assert!(h.link(&link, &target).unwrap());
    let snap = snapshot(
        &reg,
        &Scope {
            dirs: vec![],
            keys: vec![scope.clone()],
        },
    )
    .unwrap();
    let lines = Snapshot::default().diff(&snap);
    let shown = lines.join("\n");
    let value_lines: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("OnlyAtTarget"))
        .collect();
    assert_eq!(value_lines.len(), 1, "{shown}");
    assert!(value_lines[0].contains("Target"), "{shown}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Link") && !l.contains("OnlyAtTarget")),
        "the link key is not in the snapshot: {shown}"
    );
    // Reads follow the link: the value is visible through it.
    assert_eq!(
        reg.get(&link, "OnlyAtTarget").unwrap(),
        Some(RegValue::Dword(7))
    );
    h.delete_key(&link).unwrap();
    h.delete_value(&target, "OnlyAtTarget").unwrap();
    h.delete_key(&target).unwrap();
}

/// R-T1 on the real `HKCU`: `file_install` + `registry_set` applied, verified and reverted with
/// `WinSystem` (the real `RegFlushKey` before every record); the game folder and the keys
/// identical.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_r_t1_round_trip_on_the_real_hkcu() {
    sandbox_guard();
    let w = Sb::new("r-t1");
    let h = rt_hive();
    let before = w.snap(rt_keys());
    let hash = w.plan_steps(&rt1_steps());
    let t = w.apply_ok(&hash);
    assert_eq!(
        w.sys.registry().get(&hkcu(SUB), "A").unwrap(),
        Some(RegValue::Dword(1))
    );
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.halted.is_none() && v.ops.len() == 11, "{v:?}");
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = w.snap(rt_keys());
    assert!(before == after, "{:#?}", before.diff(&after));
    assert_eq!(
        w.plan_steps(&rt1_steps()),
        hash,
        "planned again: the same hash"
    );
    wipe(&h);
}

/// R-T6 on the real `HKCU`: a value another program changed is left (`Foreign`), the rest
/// reverts; `forget` closes.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_r_t6_leaves_a_value_another_program_changed() {
    sandbox_guard();
    let w = Sb::new("r-t6");
    let h = rt_hive();
    let hash = w.plan_steps(&rt1_steps());
    let t = w.apply_ok(&hash);
    h.raw(&hkcu(SUB), "A", reg_type::REG_DWORD, &9u32.to_le_bytes())
        .unwrap();
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, None, "{rep:?}");
    let foreign: Vec<u16> = rep
        .ops
        .iter()
        .filter(|o| o.observed == Observed::Foreign)
        .map(|o| o.op)
        .collect();
    assert_eq!(foreign, [8, 7, 6, 5], "{rep:?}");
    assert_eq!(
        w.sys.registry().get(&hkcu(SUB), "A").unwrap(),
        Some(RegValue::Dword(9))
    );
    w.with(|cx, _| forget(cx, &t)).unwrap();
    wipe(&h);
}

// ---------- SB-L5: compatibility layers on the real HKCU (P2-11b) ----------

/// `HKCU\...\AppCompatFlags\Layers`.
fn layers_key() -> RegKey {
    hkcu(crate::prim::layer_tests::LAYERS_KEY)
}

/// The production tables of `policy::registry::layers` while alive (the test binary uses the
/// synthetic ones by default).
struct Production;

impl Production {
    fn on() -> Self {
        crate::policy::registry::layers::knob::production(true);
        Self
    }
}

impl Drop for Production {
    fn drop(&mut self) {
        crate::policy::registry::layers::knob::production(false);
    }
}

/// The value name of the game folder's `game.exe` (its canonical path).
fn layer_name(w: &Sb) -> String {
    w.with(|_, fr| {
        let g = GameDir::open_manual(&w.sys, fr, &w.game).unwrap_or_else(|e| panic!("{e}"));
        format!(r"{}\game.exe", g.path())
    })
}

/// Another program writing the value: `reg.exe add` (a real writer outside Rerun).
fn reg_add_layer(name: &str, data: &str) {
    let key = format!(r"HKCU\{}", crate::prim::layer_tests::LAYERS_KEY);
    let st = Command::new("reg")
        .args(["add", &key, "/v", name, "/t", "REG_SZ", "/d", data, "/f"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("reg add: {e}"));
    assert!(st.success(), "reg add {name} = {data}: {st}");
}

/// The step with every production token for `game.exe`.
fn production_layers() -> Vec<Step> {
    vec![crate::prim::layer_tests::layer_step(
        "game.exe",
        crate::policy::registry::layers::LAYER_TOKENS,
    )]
}

/// `HKCU\...\AppCompatFlags`.
fn appcompat_key() -> RegKey {
    hkcu(crate::exec::layer_tests::APPCOMPAT)
}

/// `k` exists as a plain key (not a link) with no value and no subkey.
fn empty_plain_key(reg: &dyn Registry, k: &RegKey) -> bool {
    reg.key_exists(k).unwrap_or_else(|e| panic!("{k}: {e}"))
        && reg.link(k).unwrap_or_else(|e| panic!("{k}: {e}")).is_none()
        && reg
            .values(k)
            .unwrap_or_else(|e| panic!("{k}: {e}"))
            .is_empty()
        && reg
            .subkeys(k)
            .unwrap_or_else(|e| panic!("{k}: {e}"))
            .is_empty()
}

/// SB-L5 (P2-11b): `compat_layer` with the production tokens on the real `HKCU`. A round trip
/// without a value (the `Layers` key as before: when it was absent, Rerun creates it and the
/// revert deletes it again, empty (E6 b); the value gone, the same hash planned again); then a
/// drift: `reg add` appends `RUNASINVOKER` after the apply, the revert leaves exactly
/// `~ RUNASINVOKER` and closes. At the end the value goes, and `Layers` (and `AppCompatFlags`)
/// if they were absent at the start and are empty plain keys now. Nothing is created to look
/// (no `AppHive` write before the plan).
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_sb_l5_compat_layer_round_trip_on_the_real_hkcu() {
    sandbox_guard();
    let _p = Production::on();
    let w = Sb::new("sb-l5");
    let h = AppHive::real_user().unwrap_or_else(|e| panic!("{e}"));
    let name = layer_name(&w);
    let layers = layers_key();
    let flags = appcompat_key();
    let tail = crate::policy::registry::layers::LAYER_TOKENS.join(" ");
    let reg = w.sys.registry();
    let flags_existed = reg.key_exists(&flags).unwrap_or_else(|e| panic!("{e}"));
    let layers_existed = reg.key_exists(&layers).unwrap_or_else(|e| panic!("{e}"));
    if layers_existed && reg.get(&layers, &name).unwrap().is_some() {
        h.delete_value(&layers, &name).unwrap();
    }

    // Round trip.
    let before = w.snap(vec![layers.clone()]);
    let hash = w.plan_steps(&production_layers());
    let t = w.apply_ok(&hash);
    assert_eq!(
        reg.get(&layers, &name).unwrap(),
        Some(RegValue::String(format!("~ {tail}")))
    );
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = w.snap(vec![layers.clone()]);
    assert!(before == after, "{:#?}", before.diff(&after));
    if !layers_existed {
        assert!(
            !reg.key_exists(&layers).unwrap(),
            "Layers created by Rerun and empty: the revert deletes it (E6 b)"
        );
    }
    assert_eq!(
        w.plan_steps(&production_layers()),
        hash,
        "planned again: the same hash"
    );

    // Drift by another program.
    let t = w.apply_ok(&w.plan_steps(&production_layers()));
    reg_add_layer(&name, &format!("~ {tail} RUNASINVOKER"));
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    // The token list is the newest op (after the `CreateKey`s); the report runs newest first.
    let list = rep.ops.iter().max_by_key(|o| o.op).map(|o| o.observed);
    assert_eq!(list, Some(Observed::Drifted), "{rep:?}");
    assert_eq!(
        reg.get(&layers, &name).unwrap(),
        Some(RegValue::String("~ RUNASINVOKER".into()))
    );
    if !layers_existed {
        assert!(
            reg.key_exists(&layers).unwrap(),
            "Layers holding another value stays (E6 b)"
        );
    }

    // Clean up: the value, then the keys that were absent at the start, if empty and plain.
    h.delete_value(&layers, &name).unwrap();
    if !layers_existed && empty_plain_key(reg, &layers) {
        h.delete_key(&layers).unwrap();
    }
    if !flags_existed && empty_plain_key(reg, &flags) {
        h.delete_key(&flags).unwrap();
    }
}

/// Removes the link key planted at `Layers` when dropped (also after a panic), so nothing
/// later in the Sandbox session (the probe script) follows it.
struct LinkAtLayers<'h> {
    h: &'h AppHive,
    reg: WinRegistry,
}

impl Drop for LinkAtLayers<'_> {
    fn drop(&mut self) {
        let layers = layers_key();
        if matches!(self.reg.link(&layers), Ok(Some(_))) {
            let _ = self.h.delete_key(&layers);
        }
    }
}

/// SB-L5, the link key (P2-11b): a link key planted at `AppCompatFlags\Layers` pointing
/// elsewhere in `HKCU`, before the plan: the planner refuses it (a symbolic-link key on the
/// way) or the apply does, nothing appears at the target. `Layers` must be absent or an empty
/// plain key (then it is removed first); anything else fails the test. Named so that it runs
/// before the round trip (libtest orders by name).
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_sb_l5_a_link_key_at_layers_is_refused() {
    sandbox_guard();
    let _p = Production::on();
    let w = Sb::new("sb-l5-link");
    let h = AppHive::real_user().unwrap_or_else(|e| panic!("{e}"));
    let layers = layers_key();
    let reg = w.sys.registry();
    if reg.key_exists(&layers).unwrap_or_else(|e| panic!("{e}")) {
        assert!(
            empty_plain_key(reg, &layers),
            "Layers exists and is not an empty plain key: the link case cannot run"
        );
        h.delete_key(&layers).unwrap();
    }
    let flags_existed = reg.key_exists(&appcompat_key()).unwrap();
    let target = hkcu(r"Software\RerunSandbox\LayersTarget");
    h.key(&target).unwrap();
    let guard = LinkAtLayers {
        h: &h,
        reg: WinRegistry::new().unwrap(),
    };
    assert!(
        h.link(&layers, &target).unwrap(),
        "real HKCU makes link keys"
    );
    let before = w.snap(vec![target.clone()]);
    let planned = w.try_plan(&production_layers());
    let refused = match &planned {
        Err(why) => why.contains("symbolic-link key"),
        Ok(hash) => !matches!(w.with(|cx, _| apply(cx, hash)), Ok(Outcome::Applied(_))),
    };
    // The link goes first, whatever the result.
    drop(guard);
    // `key_exists` follows a link, so a link left behind (its target exists) counts as present;
    // `link()` on the then missing key is `NotFound`, not `None` (seen in the first run).
    assert!(
        !reg.key_exists(&layers).unwrap_or_else(|e| panic!("{e}")),
        "the link key is removed"
    );
    assert!(
        refused,
        "compat_layer through a link key at Layers: {planned:?}"
    );
    let after = w.snap(vec![target.clone()]);
    assert!(before == after, "{:#?}", before.diff(&after));
    assert!(
        reg.values(&target).unwrap().is_empty(),
        "a value appeared at the link target"
    );
    h.delete_key(&target).unwrap();
    if !flags_existed && empty_plain_key(reg, &appcompat_key()) {
        h.delete_key(&appcompat_key()).unwrap();
    }
}

// ---------- Packages (P4-7, ADR 0025 part 2) ----------

/// DXVK 2.7.1 (`tar.gz`) from `doitsujin/dxvk`: the archive's SHA-256 is the `digest` GitHub
/// reports for the asset in its release API (read 2026-11-10); the files' SHA-256 were measured
/// from that archive with Rerun's reader and, independently, Python's `tarfile` (2026-11-10).
/// The test measures them a third time with System32's `tar.exe`.
const DXVK_URL: &str =
    "https://github.com/doitsujin/dxvk/releases/download/v2.7.1/dxvk-2.7.1.tar.gz";
const DXVK_SHA256: &str = "D85CE7C79F57ECD765AAA1B9E7007CB875E6FDE9F6D331DF799BCE73D513CE87";
const DXVK_X64_D3D9: &str = "2740233A94774FA64A1E07C6EAF94F67027A3C7594FF3B48F7A1C9801777E5A9";
const DXVK_X32_D3D9: &str = "00ECD422B3B12E9D3B309785F3F19431405389D80EB4A37018EBC63E2D87D900";
const DXVK_X64_DXGI: &str = "EC02EB37620FF52361CB45376A4611FC4210D96E71D0363F1CC9807F151C01BE";
/// Ultimate ASI Loader v10.0.2 (`zip`, one asset per architecture) from
/// `ThirteenAG/Ultimate-ASI-Loader`; the same provenance of the hashes (Python's `zipfile`).
const ASI_X86_URL: &str = "https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/v10.0.2/Ultimate-ASI-Loader.zip";
const ASI_X86_SHA256: &str = "A8F76A891F9BEEEF3B02BABF1062C128B00E0285FA17C227A45EC4F81F45116F";
const ASI_X64_URL: &str = "https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/v10.0.2/Ultimate-ASI-Loader_x64.zip";
const ASI_X64_SHA256: &str = "A99E188E1F40D7AAC9DB9C0339990332152D372E0359FAA06A52FA339E8B218F";
const ASI_X86_DINPUT8: &str = "63B465DBC1BF9C5AB4E33C3CCAD099D9EDB702F2C51587AC8D4F196497396437";
const ASI_X64_DINPUT8: &str = "FA2B9BD317BB597906BC2C4CC2008C1444E50BFDC367E648D18F36F015812E27";

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// The two packages as a signed index would hold them.
fn real_packages() -> (Package, Package) {
    let f = |from: &str, to: &str, sha: &str, arch: Arch, api: Option<Api>| PackageFile {
        from: rel(from),
        to: rel(to),
        sha256: Hex::parse(sha).unwrap(),
        config: false,
        arch: Some(vec![arch]),
        api: api.map(|a| vec![a]),
    };
    let dxvk: Package = Package {
        format: 1,
        id: Id::parse("dxvk").unwrap(),
        name: "DXVK".into(),
        status: Status::Active,
        tier: Tier::Established,
        source: PackageSource {
            repo: Some("https://github.com/doitsujin/dxvk".into()),
            page: None,
            release: Some(DXVK_URL.into()),
        },
        version: "2.7.1".into(),
        sha256: Some(Hex::parse(DXVK_SHA256).unwrap()),
        assets: None,
        license: "Zlib".into(),
        arch: ArchList::List(vec![Arch::X86, Arch::X64]),
        apis: Some(vec![Api::D3d9, Api::D3d11]),
        slots: vec![],
        // Every DLL a package installs is one of its slots (P4-8, catalog::check::slots_bound).
        slots_by_api: Some(std::collections::BTreeMap::from([
            (Api::D3d9, vec!["d3d9.dll".to_owned()]),
            (Api::D3d11, vec!["dxgi.dll".to_owned()]),
        ])),
        requires: vec![],
        requires_gpu: vec![],
        supports_exe_sha1: vec![],
        files: vec![
            f(
                "dxvk-2.7.1/x64/d3d9.dll",
                "d3d9.dll",
                DXVK_X64_D3D9,
                Arch::X64,
                Some(Api::D3d9),
            ),
            f(
                "dxvk-2.7.1/x32/d3d9.dll",
                "d3d9.dll",
                DXVK_X32_D3D9,
                Arch::X86,
                Some(Api::D3d9),
            ),
            f(
                "dxvk-2.7.1/x64/dxgi.dll",
                "dxgi.dll",
                DXVK_X64_DXGI,
                Arch::X64,
                Some(Api::D3d11),
            ),
        ],
        options: Default::default(),
    };
    let mut asi = dxvk.clone();
    asi.id = Id::parse("ultimate-asi-loader").unwrap();
    asi.name = "Ultimate ASI Loader".into();
    asi.source = PackageSource {
        repo: Some("https://github.com/ThirteenAG/Ultimate-ASI-Loader".into()),
        page: None,
        release: None,
    };
    asi.version = "10.0.2".into();
    asi.sha256 = None;
    asi.license = "MIT".into();
    asi.apis = None;
    asi.slots = vec!["dinput8.dll".to_owned()];
    asi.slots_by_api = None;
    asi.assets = Some(vec![
        Asset {
            arch: Arch::X86,
            url: ASI_X86_URL.into(),
            sha256: Hex::parse(ASI_X86_SHA256).unwrap(),
        },
        Asset {
            arch: Arch::X64,
            url: ASI_X64_URL.into(),
            sha256: Hex::parse(ASI_X64_SHA256).unwrap(),
        },
    ]);
    asi.files = vec![
        f(
            "dinput8.dll",
            "dinput8.dll",
            ASI_X86_DINPUT8,
            Arch::X86,
            None,
        ),
        f(
            "dinput8.dll",
            "dinput8.dll",
            ASI_X64_DINPUT8,
            Arch::X64,
            None,
        ),
    ];
    for p in [&dxvk, &asi] {
        crate::catalog::check::package(p, crate::catalog::check::Rules::Release)
            .unwrap_or_else(|e| panic!("{}: {e}", p.id));
    }
    (dxvk, asi)
}

/// Extracts `archive` with System32's `tar.exe` (bsdtar: zip and tar.gz) into `into` and returns
/// the SHA-256 of `name` there: a reader independent of Rerun's.
fn bsdtar_sha256(windows: &Path, archive: &Path, into: &Path, name: &str) -> String {
    let _ = std::fs::remove_dir_all(into);
    std::fs::create_dir_all(into).unwrap();
    let st = Command::new(windows.join(r"System32\tar.exe"))
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .arg(name)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("tar.exe: {e}"));
    assert!(
        st.success(),
        "tar.exe -xf {} {name}: {st}",
        archive.display()
    );
    hex_upper(&Sha256::digest(read(&into.join(name))))
}

/// [SB] P4-7: DXVK (`tar.gz`) and Ultimate ASI Loader (`zip`, per architecture) downloaded
/// through the product path, unpacked (only the named files), measured against `tar.exe`,
/// installed into a sandbox game folder by the `package` planner's steps, verified, reverted:
/// the game folder identical. Network: the CI sandbox job only (the local Windows Sandbox has
/// none); `ci-sandbox.ps1` fails pass 1 without its `MEASURED package` lines. Leaves the cache
/// and the packages folder as it found them.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_package_dxvk_and_asi_loader_round_trip() {
    sandbox_guard();
    #[expect(
        clippy::disallowed_methods,
        reason = "test gate: the CI opt-in is an environment variable by design, not a path"
    )]
    let ci = std::env::var("RERUN_CI_SANDBOX").is_ok_and(|v| v == "1");
    if !ci {
        note(
            "sandbox_package_dxvk_and_asi_loader_round_trip: skipped (no network outside the CI job)",
        );
        return;
    }
    super::super::restrict_dll_search().unwrap();
    let w = Sb::new("pkg");
    let (dxvk, asi) = real_packages();
    let windows = w.sys.known_folders().get(KnownFolder::Windows).unwrap();
    let lad = w
        .sys
        .known_folders()
        .get(KnownFolder::LocalAppData)
        .unwrap();
    let cache = lad.join(r"Rerun\cache");
    let packages = lad.join(r"Rerun\packages");
    let leftovers = |p: &Package| {
        let _ = std::fs::remove_dir_all(packages.join(p.id.as_str()));
        for d in downloads(p).unwrap() {
            let _ = std::fs::remove_file(cache.join(cache_name(d.sha256())));
        }
    };
    leftovers(&dxvk);
    leftovers(&asi);

    // 1. Download, unpack, measure.
    let x64 = GameBuild {
        arch: Some(Arch::X64),
        api: Api::D3d9,
    };
    let mut steps = Vec::new();
    for p in [&dxvk, &asi] {
        w.with(|cx, _| {
            for d in downloads(p).unwrap() {
                let got = fetch(&w.sys, &WinHttp::new(), cx.app, &d)
                    .unwrap_or_else(|e| panic!("{}: {e}", p.id));
                note(&format!(
                    "MEASURED package {} {} archive {}: {} bytes, sha256 {}",
                    p.id,
                    p.version,
                    d.url(),
                    got.len,
                    cache_name(&got.sha256).to_ascii_uppercase()
                ));
            }
            let unpacked = extract(&w.sys, cx.app, p).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(unpacked.len(), layout(p).unwrap().len(), "{unpacked:?}");
            for u in &unpacked {
                assert_eq!(u.how, How::Extracted, "{u:?}");
            }
        });
        // Only the named files are there, and tar.exe reads the same bytes.
        let version = packages.join(p.id.as_str()).join(&p.version);
        let mut on_disk = Vec::new();
        let mut todo = vec![version.clone()];
        while let Some(d) = todo.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    todo.push(e.path());
                } else {
                    on_disk.push(e.path());
                }
            }
        }
        let placed = layout(p).unwrap();
        assert_eq!(on_disk.len(), placed.len(), "{on_disk:?}");
        for x in &placed {
            let ours = hex_upper(&Sha256::digest(read(&version.join(x.dest.as_str()))));
            let d = downloads(p)
                .unwrap()
                .into_iter()
                .find(|d| d.arch() == x.arch)
                .unwrap();
            let theirs = bsdtar_sha256(
                &windows,
                &cache.join(cache_name(d.sha256())),
                &w.game.parent().unwrap().join("bsdtar"),
                &x.from.as_str().replace('\\', "/"),
            );
            note(&format!(
                "MEASURED package {} {} file {}: sha256 {ours} (tar.exe {theirs}, pinned {})",
                p.id,
                p.version,
                x.dest,
                hex_upper(&x.sha256)
            ));
            assert_eq!(ours, theirs, "{}", x.dest);
            assert_eq!(ours, hex_upper(&x.sha256), "{}", x.dest);
        }
        steps.push(Step::FileInstall(
            crate::prim::package::file_install(p, &x64).unwrap_or_else(|e| panic!("{e}")),
        ));
    }

    // 2. Installed into the game folder by the planner's steps, verified, reverted.
    let before = w.snap(vec![]);
    let h = w.plan_steps(&steps);
    let t = w.apply_ok(&h);
    assert_eq!(
        hex_upper(&Sha256::digest(read(&w.game.join("d3d9.dll")))),
        DXVK_X64_D3D9
    );
    assert_eq!(
        hex_upper(&Sha256::digest(read(&w.game.join("dinput8.dll")))),
        ASI_X64_DINPUT8
    );
    assert!(
        !w.game.join("dxgi.dll").exists(),
        "a d3d11 file for a d3d9 game"
    );
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.halted.is_none(), "{v:?}");
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = w.snap(vec![]);
    assert!(before == after, "{:#?}", before.diff(&after));
    leftovers(&dxvk);
    leftovers(&asi);
    note("sandbox_package_dxvk_and_asi_loader_round_trip: passed, cache and packages removed");
}

// ---------- laa_patch (P4-10) ----------

/// Starts `exe` and returns its exit code and first output line.
fn run_stub(exe: &Path) -> (i32, String) {
    let o = Command::new(exe)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("cannot start {}: {e}", exe.display()));
    let line = String::from_utf8_lossy(&o.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    (o.status.code().unwrap_or(-1), line)
}

/// `laa_patch` on real Windows (P4-10 [SB]): the repository's own 32-bit test program
/// (`tests/support/laa_stub.rs`, staged next to this test binary by `sandbox-launch.ps1`; linked
/// without the flag and with a stored checksum) is copied into the game folder, started (16: no
/// large address space), patched through the real `WinSystem` (the flag set, the checksum as
/// `CheckSumMappedFile` computes it), started again (32: Windows gave it the large address
/// space), reverted bit for bit and started a third time (16). `ci-sandbox.ps1` fails pass 1
/// without its `MEASURED laa_patch` line.
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_laa_patch_round_trip_starts_the_patched_exe() {
    sandbox_guard();
    let w = Sb::new("laa");
    let stub = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("laa-stub.exe");
    assert!(
        stub.exists(),
        "{} is missing (staged by scripts/sandbox-launch.ps1)",
        stub.display()
    );
    let exe = w.game.join("Game32.exe");
    std::fs::copy(&stub, &exe).unwrap();
    let original = read(&exe);
    let (before_code, before_line) = run_stub(&exe);
    assert_eq!(before_code, 16, "before the patch: {before_line}");
    let pe = |b: &[u8]| {
        let p = crate::detect::pe::Pe::parse(
            std::io::Cursor::new(b.to_vec()),
            &crate::detect::pe::Limits::DEFAULT,
        )
        .unwrap();
        (p.headers().large_address_aware(), p.image_fields().checksum)
    };
    let (laa, stored) = pe(&original);
    assert!(!laa && stored != 0, "the stub has no flag and a checksum");

    let before = w.snap(vec![]);
    let step = Step::LaaPatch(crate::prim::LaaPatchSpec {
        exe: rel("Game32.exe"),
        sha256: Sha256::digest(&original).into(),
    });
    let h = w.plan_steps(std::slice::from_ref(&step));
    let t = w.apply_ok(&h);
    let patched = read(&exe);
    let (laa, new_sum) = pe(&patched);
    assert!(laa, "the flag is set");
    let (w_stored, w_computed) = super::checksum::windows_of(&patched).unwrap();
    assert_eq!(
        (w_stored, w_computed),
        (new_sum, new_sum),
        "CheckSumMappedFile agrees"
    );
    let changed = (0..original.len())
        .filter(|&i| original[i] != patched[i])
        .count();
    let (after_code, after_line) = run_stub(&exe);
    assert_eq!(after_code, 32, "after the patch: {after_line}");
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    assert_eq!(read(&exe), original, "bit for bit");
    let after = w.snap(vec![]);
    assert!(before == after, "{:#?}", before.diff(&after));
    let (again_code, again_line) = run_stub(&exe);
    assert_eq!(again_code, 16, "after the revert: {again_line}");
    note(&format!(
        "MEASURED laa_patch: {} bytes, {changed} bytes changed, checksum {stored:#x} -> \
         {new_sum:#x} (CheckSumMappedFile agrees); exit before {before_code} ({before_line}), \
         patched {after_code} ({after_line}), reverted {again_code}; reverted bit for bit",
        original.len()
    ));
}

// ---------- gpu_preference (P4-11) ----------

/// `reg.exe query` of the value `name` below `UserGpuPreferences`: its `REG_SZ` data as another
/// reader than Rerun sees it (`None`: missing).
fn reg_query_pref(name: &str) -> Option<String> {
    let key = format!(r"HKCU\{}", crate::exec::gpu_pref_tests::PREFS_KEY);
    let o = Command::new("reg")
        .args(["query", &key, "/v", name])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("reg query: {e}"));
    if !o.status.success() {
        return None;
    }
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    out.lines()
        .find_map(|l| l.split_once("REG_SZ").map(|(_, d)| d.trim().to_owned()))
}

/// Another program writing the value: `reg.exe add`.
fn reg_add_pref(name: &str, data: &str) {
    let key = format!(r"HKCU\{}", crate::exec::gpu_pref_tests::PREFS_KEY);
    let st = Command::new("reg")
        .args(["add", &key, "/v", name, "/t", "REG_SZ", "/d", data, "/f"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("reg add: {e}"));
    assert!(st.success(), "reg add {name} = {data}: {st}");
}

/// SB-G2 (P4-11): `gpu_preference` on the real `HKCU`. (a) A round trip without a value (the
/// `DirectX` and `UserGpuPreferences` keys as found: created and deleted again when they were
/// absent); (b) a value with foreign pairs written by `reg add`: the apply appends only Rerun's
/// pair (`reg query` sees it), the revert restores the bytes exactly; (c) a drift: `reg add`
/// changes `AutoHDREnable` after the apply, the revert takes back only Rerun's pair and closes.
/// At the end the value goes, and the keys if they were absent at the start and are empty
/// plain keys now. `ci-sandbox.ps1` fails pass 1 without its `MEASURED gpu_preference` line.
/// Whether Windows or a game honours the value is not tested here (SB-G1 and the hybrid row
/// of the manual matrix, `docs/09-testing.md`).
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_sb_g2_gpu_preference_round_trip_on_the_real_hkcu() {
    sandbox_guard();
    let w = Sb::new("sb-g2");
    let h = AppHive::real_user().unwrap_or_else(|e| panic!("{e}"));
    let name = layer_name(&w);
    let prefs = hkcu(crate::exec::gpu_pref_tests::PREFS_KEY);
    let directx = hkcu(crate::exec::gpu_pref_tests::DIRECTX);
    let reg = w.sys.registry();
    let directx_existed = reg.key_exists(&directx).unwrap_or_else(|e| panic!("{e}"));
    let prefs_existed = reg.key_exists(&prefs).unwrap_or_else(|e| panic!("{e}"));
    if prefs_existed && reg.get(&prefs, &name).unwrap().is_some() {
        h.delete_value(&prefs, &name).unwrap();
    }
    let profile = crate::hw::read(&w.sys, crate::hw::GpuArchTable::builtin().ok());
    let hybrid = profile.gpu_hybrid();
    let adapters = profile.gpu.as_ref().map_or(0, |g| g.adapters.len());
    let step = || vec![crate::exec::gpu_pref_tests::pref_step("game.exe")];

    // (a) No value.
    let before = w.snap(vec![directx.clone()]);
    let hash = w.plan_steps(&step());
    let t = w.apply_ok(&hash);
    assert_eq!(reg_query_pref(&name).as_deref(), Some("GpuPreference=2;"));
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = w.snap(vec![directx.clone()]);
    assert!(before == after, "{:#?}", before.diff(&after));
    if !directx_existed {
        assert!(
            !reg.key_exists(&directx).unwrap(),
            "DirectX created by Rerun and empty: the revert deletes it"
        );
    }

    // (b) Foreign pairs, restored byte for byte.
    let old = "AutoHDREnable=1;SwapEffectUpgradeEnable=1;";
    reg_add_pref(&name, old);
    let t = w.apply_ok(&w.plan_steps(&step()));
    assert_eq!(
        reg_query_pref(&name),
        Some(format!("{old}GpuPreference=2;"))
    );
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    assert_eq!(
        reg.get(&prefs, &name).unwrap(),
        Some(RegValue::String(old.into())),
        "byte for byte"
    );

    // (c) Drift: Auto HDR switched off after the apply.
    let t = w.apply_ok(&w.plan_steps(&step()));
    reg_add_pref(
        &name,
        "AutoHDREnable=0;SwapEffectUpgradeEnable=1;GpuPreference=2;",
    );
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let pref_op = rep.ops.iter().max_by_key(|o| o.op).map(|o| o.observed);
    assert_eq!(pref_op, Some(Observed::Drifted), "{rep:?}");
    assert_eq!(
        reg_query_pref(&name).as_deref(),
        Some("AutoHDREnable=0;SwapEffectUpgradeEnable=1;")
    );

    // Clean up: the value, then the keys that were absent at the start, if empty and plain.
    h.delete_value(&prefs, &name).unwrap();
    if !prefs_existed && empty_plain_key(reg, &prefs) {
        h.delete_key(&prefs).unwrap();
    }
    if !directx_existed && empty_plain_key(reg, &directx) {
        h.delete_key(&directx).unwrap();
    }
    note(&format!(
        "MEASURED gpu_preference: DirectX key present={directx_existed}, UserGpuPreferences \
         present={prefs_existed}, hardware adapters={adapters}, gpu.hybrid={hybrid:?}; new, \
         merge (restored byte for byte) and drift round trips passed"
    ));
}

// ---------- The user data root (P4-12) ----------

/// SB-U1 (P4-12): `ini_set` in the real `Documents` of the CI user through the real `WinSystem`:
/// `Documents\My Games\RerunSbU1\settings.ini` (Documents made first if the fresh profile has
/// none, and measured), planned from a user data folder, applied, verified, reverted, the
/// folder identical; a junction `My Games\RerunSbU1J` (`mklink /J`, as the user) is refused as
/// a user data folder. Everything made here is removed at the end. `ci-sandbox.ps1` fails pass 1
/// without its `MEASURED user_data` line. Whether Documents on OneDrive carries the cloud tag is
/// not measured here (no OneDrive in the Sandbox; `docs/09-testing.md`, open row).
#[test]
#[ignore = "only in Windows Sandbox (RERUN_SANDBOX=1), see scripts/sandbox-test.wsb"]
fn sandbox_sb_u1_ini_set_in_the_real_documents() {
    sandbox_guard();
    use crate::policy::root::{SYNC_ROOT_MANAGER, UserBase, UserDataDir, sync_roots};
    use crate::prim::{IniSetSpec, IniSetValue, StepRoot};
    let w = Sb::new("sb-u1");
    let docs = w.sys.known_folders().get(KnownFolder::Documents).unwrap();
    let docs_existed = docs.is_dir();
    if !docs_existed {
        std::fs::create_dir_all(&docs).unwrap();
    }
    let my_games = docs.join("My Games");
    let my_games_existed = my_games.is_dir();
    let folder = my_games.join("RerunSbU1");
    let link = my_games.join("RerunSbU1J");
    let _ = std::fs::remove_dir(&link);
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(
        folder.join("settings.ini"),
        crate::prim::ini_tests::INI_TEXT,
    )
    .unwrap();
    let info = w
        .sys
        .fs()
        .open_dir(&docs)
        .and_then(|d| d.info())
        .unwrap_or_else(|e| panic!("{e}"));
    let srm = RegKey::new(Hive::LocalMachine, RegView::Native, SYNC_ROOT_MANAGER);
    let sync = match (w.sys.registry().key_exists(&srm), sync_roots(&w.sys)) {
        (Ok(false), _) => "absent".to_owned(),
        (_, Ok(v)) => format!("readable ({} roots)", v.len()),
        (_, Err(e)) => format!("unreadable ({e})"),
    };
    let step = |sub: &str| {
        let sub = rel(sub);
        let steps = [Step::IniSet(IniSetSpec {
            root: StepRoot::UserData,
            file: rel("settings.ini"),
            values: vec![IniSetValue {
                section: "Display".into(),
                key: "Width".into(),
                value: "1920".into(),
            }],
        })];
        w.with(|cx, fr| {
            let g = GameDir::open_manual(&w.sys, fr, &w.game).unwrap();
            let u = UserDataDir::open(&w.sys, fr, UserBase::Documents, &sub)
                .map_err(|e| e.to_string())?;
            let main = rel("game.exe");
            let p = plan(
                &steps,
                &PlanCtx {
                    game: &g,
                    app: Some(cx.app),
                    steam_app: None,
                    main_exe: Some(&main),
                    reg: crate::policy::registry::RegPolicy.reader(&w.sys),
                    app_path: None,
                    user_data: Some(&u),
                },
            )
            .map_err(|e| e.to_string())?;
            Ok::<_, String>(store(cx.app, &p.encode().unwrap()).unwrap())
        })
    };
    let snap_folder = || {
        w.with(|_, fr| {
            let d = GameDir::open_manual(&w.sys, fr, &folder).unwrap();
            snapshot(
                w.sys.registry(),
                &Scope {
                    dirs: vec![SnapRoot::new(d.dir(), "user data")],
                    keys: vec![],
                },
            )
            .unwrap()
        })
    };
    let before = snap_folder();
    let h = step(r"My Games\RerunSbU1").unwrap_or_else(|e| panic!("{e}"));
    let t = w.apply_ok(&h);
    assert!(
        String::from_utf8_lossy(&read(&folder.join("settings.ini"))).contains("Width=1920"),
        "the apply wrote the real file"
    );
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = snap_folder();
    assert!(before == after, "{:#?}", before.diff(&after));
    // A junction made by the user below My Games: never a user data folder.
    let st = Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&folder)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("mklink: {e}"));
    assert!(st.success(), "mklink /J: {st}");
    let refused = step(r"My Games\RerunSbU1J").expect_err("a junction is refused");
    assert!(refused.contains("reparse point"), "{refused}");
    // Clean up: the junction (the link only), the folder, what this test made.
    std::fs::remove_dir(&link).unwrap();
    std::fs::remove_dir_all(&folder).unwrap();
    if !my_games_existed {
        std::fs::remove_dir(&my_games).unwrap();
    }
    if !docs_existed {
        std::fs::remove_dir(&docs).unwrap();
    }
    note(&format!(
        "MEASURED user_data: documents={} (existed={docs_existed}), cloud={}, sync_roots={sync}; \
         round trip passed, junction refused",
        docs.display(),
        info.cloud
    ));
}
