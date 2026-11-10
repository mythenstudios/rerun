//! [DEV] the firewall round trip on the developer machine (ADR 0023 §14, P4-5b; user decision A
//! of 2026-11-10): Rerun's own `apply` and `revert` of a `firewall_rule` plan through the real
//! UAC prompt and the installed **test-key** helper. Run only by `scripts/dev-helper-firewall.ps1`,
//! which builds this test binary with the feature `test-key`, installs the test-key helper,
//! names every prompt in the window title and removes the helper (and any rule of this test)
//! again at the end.
//!
//! Everything Rerun writes stays in a fresh test folder below `target\rerun-fs-contract`: the
//! known folder `LocalAppData` of the system the test runs on is that folder (journal, plans,
//! request files, the index signed by the test key), and the game folder holds `game.exe`, a
//! minimal PE header without code (it cannot run). The one system change is the outbound block
//! rule of group `Rerun` for that `game.exe`, from the apply to the revert.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::super::testfx::{TestRoot, is_elevated};
use super::super::{WinFirewall, WinSystem};
use crate::catalog::key::test_key;
use crate::exec::{ApplyError, ExecCtx, ExecError, HelperFailure, Outcome, apply, revert, verify};
use crate::journal::{Closing, InstanceTag, Observed};
use crate::path::RelPath;
use crate::plan::{Op, Pick, PlanSource, RootIx, store};
use crate::policy::firewall::{Direction, GROUP};
use crate::policy::registry::RegPolicy;
use crate::policy::root::{AppDir, Create, ForbiddenRoots, GameDir};
use crate::prim::{PlanCtx, plan as plan_steps};
use crate::sys::firewall::{ACTION_BLOCK, DIR_OUT};
use crate::sys::{
    Elevation, Firewall, Fs, FwRule, Gpu, KnownFolder, KnownFolders, NoGpu, Registry,
    RegistryWrite, SysResult, System, Topology,
};

/// The name prefix of this test's rules (the Topo ID is `dev-firewall`).
const PREFIX: &str = "Rerun - dev-firewall - ";

/// The real system with `LocalAppData` redirected into the test folder; no GPU.
struct DevSys {
    full: WinSystem,
    kf: DevFolders,
}

struct DevFolders {
    full: WinSystem,
    lad: PathBuf,
}

impl KnownFolders for DevFolders {
    fn get(&self, folder: KnownFolder) -> SysResult<PathBuf> {
        if folder == KnownFolder::LocalAppData {
            Ok(self.lad.clone())
        } else {
            self.full.known_folders().get(folder)
        }
    }
}

impl System for DevSys {
    fn fs(&self) -> &dyn Fs {
        self.full.fs()
    }
    fn registry(&self) -> &dyn Registry {
        self.full.registry()
    }
    // The real write side: `exec::standard_user` asks it whether this process is elevated
    // (`NoRegistry` answers "refused" and reads as elevated). The plan holds no registry op, so
    // nothing is written through it.
    fn registry_write(&self) -> &dyn RegistryWrite {
        self.full.registry_write()
    }
    fn topology(&self) -> &dyn Topology {
        self.full.topology()
    }
    fn known_folders(&self) -> &dyn KnownFolders {
        &self.kf
    }
    fn gpu(&self) -> &dyn Gpu {
        &NoGpu
    }
    fn firewall(&self) -> &dyn Firewall {
        self.full.firewall()
    }
    fn elevation(&self) -> &dyn Elevation {
        self.full.elevation()
    }
}

/// Every rule of this test, read without elevation.
fn ours() -> Vec<FwRule> {
    WinFirewall
        .select(&|n, _| n.starts_with(PREFIX))
        .unwrap()
        .rules
}

/// The test Topo: `net/block` blocks `game.exe` (its SHA-256), status `active`: an index the
/// test key signed releases it in a `test-key` build only.
fn topo_json(exe: &[u8]) -> String {
    let sha: String = Sha256::digest(exe)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    format!(
        r#"{{"format":1,"id":"dev-firewall","title":"Rerun DEV firewall round trip","status":"active","rev":1,
"match":{{"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"issues":[{{"id":"net","title":"Online check","variants":[
 {{"id":"block","status":"verified","kind":"fix","steps":[{{"firewall_rule":{{"exe":"game.exe","direction":"out"}}}}]}}]}}]}}"#
    )
}

/// [DEV] (`scripts/dev-helper-firewall.ps1`): `RERUN_DEV_FIREWALL=decline`: the user declines the
/// prompt; the apply is rolled back (`Declined`, exit 4 in the CLI) and no rule exists.
/// `RERUN_DEV_FIREWALL=accept`: the user allows both prompts; the apply adds exactly the rule of
/// Rerun's form for the dummy `game.exe`, `verify` says `After`, the revert removes it and none
/// of this test's rules is left.
#[test]
#[ignore = "[DEV] adds and removes a real firewall rule through real UAC prompts; run by scripts/dev-helper-firewall.ps1"]
fn dev_helper_firewall_round_trip() {
    #[expect(
        clippy::disallowed_methods,
        reason = "[DEV] test: the hand-test script names the expected answer"
    )]
    let mode = std::env::var("RERUN_DEV_FIREWALL").unwrap_or_default();
    assert!(
        mode == "accept" || mode == "decline",
        "set RERUN_DEV_FIREWALL=accept or decline (scripts/dev-helper-firewall.ps1)"
    );
    if !crate::catalog::check::TEST_KEY_BUILD {
        panic!("build the test binary with --features test-key (scripts/dev-helper-firewall.ps1)");
    }
    assert!(!is_elevated(), "run from a non-elevated process");
    assert!(
        ours().is_empty(),
        "a rule of an earlier run exists; the script's removal step removes it"
    );

    let root = TestRoot::new("dev-fw").unwrap();
    let lad = root.work("lad");
    let game = root.work("game");
    std::fs::create_dir_all(&lad).unwrap();
    std::fs::create_dir_all(&game).unwrap();
    let exe = crate::detect::pe::testfx::Builder::x86().build().bytes;
    std::fs::write(game.join("game.exe"), &exe).unwrap();
    let sys = DevSys {
        full: WinSystem::new().unwrap(),
        kf: DevFolders {
            full: WinSystem::new().unwrap(),
            lad: lad.clone(),
        },
    };
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    // The index, signed with the published test key, in Rerun's `index` folder of the test.
    let index = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-10T12:00:00Z","topos":[{}],"packages":[]}}"#,
        topo_json(&exe)
    );
    let isha: [u8; 32] = Sha256::digest(index.as_bytes()).into();
    let hex = crate::wire::hex32::to_string(&isha);
    let idir = lad.join(r"Rerun\index");
    std::fs::create_dir_all(&idir).unwrap();
    std::fs::write(idir.join(format!("{hex}.json")), index.as_bytes()).unwrap();
    std::fs::write(
        idir.join(format!("{hex}.sig")),
        test_key::sign(index.as_bytes()),
    )
    .unwrap();

    // The plan: the rule op of the Topo's anchor, as the engine builds it.
    let install = std::env::current_exe().unwrap();
    let fr = ForbiddenRoots::resolve(&sys, install.parent().unwrap_or(Path::new("")))
        .unwrap_or_else(|e| panic!("{e}"));
    let g = GameDir::open_manual(&sys, &fr, &game).unwrap_or_else(|e| panic!("{e}"));
    let main = RelPath::parse("game.exe").unwrap();
    let mut p = plan_steps(
        &[],
        &PlanCtx {
            game: &g,
            app: Some(&app),
            steam_app: None,
            main_exe: Some(&main),
            reg: RegPolicy.reader(&sys),
            app_path: None,
        },
    )
    .unwrap();
    p.ops.push(Op::FirewallRule {
        root: RootIx(0),
        program: main.clone(),
        direction: Direction::Out,
    });
    p.source = Some(PlanSource {
        index: isha,
        topo: "dev-firewall".to_owned(),
        rev: 1,
        picks: vec![Pick {
            issue: "net".to_owned(),
            variant: "block".to_owned(),
        }],
    });
    let h = store(&app, &p.encode().unwrap()).unwrap();
    drop(g);
    let cx = ExecCtx {
        sys: &sys,
        fr: &fr,
        app: &app,
        tag: InstanceTag::new(),
    };

    if mode == "decline" {
        let r = apply(&cx, &h);
        println!("RERUN_DEV_FW_RUN: {r:?}");
        let declined = matches!(
            &r,
            Err(ApplyError::RolledBack { cause, .. })
                if matches!(&**cause, ExecError::Helper(HelperFailure::Declined))
        );
        assert!(
            declined,
            "expected the rollback of a declined prompt: {r:?}"
        );
        assert!(ours().is_empty(), "a declined apply left a rule");
        println!(
            "RERUN_DEV_FW_RESULT: PASS decline -> rolled back (Declined, exit 4 in the CLI), no rule"
        );
        return;
    }

    // Prompt 3: the apply.
    let t = match apply(&cx, &h) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("apply: {other:?}"),
    };
    let rules = ours();
    println!("RERUN_DEV_FW_RULE: {rules:?}");
    let program = format!(r"{}\game.exe", g_path(&game));
    let one = matches!(rules.as_slice(), [r] if r.grouping == GROUP
        && r.direction == DIR_OUT
        && r.action == ACTION_BLOCK
        && r.enabled
        && r.program.eq_ignore_ascii_case(&program));
    let seen = verify(&cx, &t).unwrap().ops;
    println!("RERUN_DEV_FW_VERIFY: {seen:?}");
    // Prompt 4: the revert (also when a check above failed, so the rule goes again).
    let reverted = revert(&cx, &t);
    println!("RERUN_DEV_FW_REVERT: {reverted:?}");
    let left = ours();
    assert!(
        one,
        "expected exactly one outbound block rule of group Rerun for {program}: {rules:?}"
    );
    assert!(
        seen.iter().all(|(_, o)| *o == Observed::After),
        "verify: {seen:?}"
    );
    assert!(
        matches!(
            reverted.as_ref().map(|r| r.closed),
            Ok(Some(Closing::Reverted))
        ),
        "the revert did not close the transaction: {reverted:?}"
    );
    assert!(left.is_empty(), "the revert left a rule: {left:?}");
    println!(
        "RERUN_DEV_FW_RESULT: PASS accept -> applied (rule {}), verify After, reverted, no rule left",
        rules[0].name
    );
}

/// The game folder's canonical path as Rerun spells the program (`Program::new`).
fn g_path(game: &Path) -> String {
    let fs = super::super::WinFs::new();
    #[expect(clippy::disallowed_methods, reason = "[DEV] test: its own test folder")]
    let d = fs.open_dir(game).unwrap();
    crate::path::RootPath::from_final_path(&d.info().unwrap().final_path)
        .unwrap()
        .to_string()
}
