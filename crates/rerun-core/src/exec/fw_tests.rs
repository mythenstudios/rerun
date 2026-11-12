//! `exec` with the helper batch (P4-2d; ADR 0023 §8, §9, §14) against a two-process fake: the
//! CLI side runs `exec` on a [`TwoProc`] system whose `Elevation` is the fake transport
//! ([`Wire`]): it calls `elevate::serve` in-process with the helper's view of the same world
//! (the fake firewall's write side), outside the CLI's fault sequence (another process).
//!
//! - F1 round trip `apply → verify → revert → snapshot identical` (the game folder and the
//!   firewall scope: group `Rerun` and every rule of a planned name), for a plan of rules alone
//!   and one with a file op before them; one helper run per direction (R3).
//! - F2 apply outcomes: declined, refused (tamper of the request, the index, the program after
//!   `begin`), a start that fails roll back (exit 4); unknown, a helper crash after its add and a
//!   disagreement stay open (exit 5) and the revert finishes them (N5, §8).
//! - F3 revert outcomes: declined halts before the ops below the batch (LIFO), no record but the
//!   repeatable `RevertBatch`; a rule an administrator changed is `Foreign`; a revert whose rules
//!   are gone starts no helper; `ensure_idle` before an unfinished batch (A4 S8).
//! - F4 the request file (N9): leftovers swept, a taken name moves on to the next number, the
//!   file gone after the run.
//! - F5 the plan format and the begin check (A4 S7): rules last, a source required, the plan
//!   refused when the game no longer matches the signed hash.
//! - F6 crashes and power losses (`fw_crash_tests`).

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

use super::{ApplyError, ExecCtx, ExecError, HelperFailure, Outcome, Refusal, RevertReport};
use crate::catalog::key::test_key;
use crate::elevate::serve::{Keys, serve_with};
use crate::journal::{Closing, InstanceTag, Journal, Observed, TxnId, TxnState};
use crate::plan::{Op, Pick, PlanHash, PlanSource, RootIx, store};
use crate::policy::firewall::{Direction, GROUP};
use crate::policy::root::{GameDir, helper_image};
use crate::prim::tests::{GAME, app, entry, fr, rel, spec};
use crate::prim::{PlanCtx, Step, plan as plan_steps};
use crate::sys::fake::{FakeHelperSystem, FakeHelperToken, FakeSd, FakeSystem, set_in_hook};
use crate::sys::snapshot::Snapshot;
use crate::sys::{
    Elevation, FwRule, HelperLock, HelperPresence, HelperProc, HelperRun, SysError, SysErrorKind,
    SysResult, System, TokenKind,
};
use crate::wire::hex32;

pub(crate) const PF: &str = r"C:\Program Files";
pub(crate) const HDIR: &str = r"C:\Program Files\Rerun";
pub(crate) const HEXE: &str = r"C:\Program Files\Rerun\rerun-helper.exe";
/// `index`, or `index-test` with the feature `test-key` (ADR 0024 amendment P4-13).
pub(crate) const INDEX: &str = if cfg!(feature = "test-key") {
    r"C:\Users\Player\AppData\Local\Rerun\index-test"
} else {
    r"C:\Users\Player\AppData\Local\Rerun\index"
};
pub(crate) const ELEVATE: &str = r"C:\Users\Player\AppData\Local\Rerun\elevate";
/// The game's executable: a minimal x86 PE (the engine and `check_plan` parse it).
pub(crate) fn game_exe() -> Vec<u8> {
    crate::detect::pe::testfx::Builder::x86().build().bytes
}

/// A second executable of the game: a minimal x64 PE.
pub(crate) fn tool_exe() -> Vec<u8> {
    crate::detect::pe::testfx::Builder::x64().build().bytes
}
/// The instance tag of every run of these tests: the first transaction is `00000001-…0f00`.
pub(crate) const TAG: u64 = 0xf00;

/// What the plan under test holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// One firewall rule, nothing else (the batch starts at op 0).
    Rules,
    /// A new file, then two firewall rules.
    Mixed,
    /// Two firewall rules, nothing else.
    TwoRules,
}

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// An invented Topo: `net/block` blocks `game.exe`, `other/also` blocks `tool.exe`.
fn topo_json() -> String {
    let game = hex_upper(&Sha256::digest(game_exe()));
    let tool = hex_upper(&Sha256::digest(tool_exe()));
    format!(
        r#"{{"format":1,"id":"invented-game","title":"Invented","status":"active","rev":3,
"match":{{"exes":[{{"path":"game.exe","sha256":"{game}","api":"d3d9"}},
{{"path":"tool.exe","sha256":"{tool}","api":"d3d9"}}]}},
"issues":[
 {{"id":"net","title":"Online check","variants":[
   {{"id":"block","status":"verified","kind":"fix","steps":[{{"firewall_rule":{{"exe":"game.exe","direction":"out"}}}}]}}]}},
 {{"id":"other","title":"Tool","variants":[
   {{"id":"also","status":"verified","kind":"fix","steps":[{{"firewall_rule":{{"exe":"tool.exe","direction":"out"}}}}]}}]}}
]}}"#
    )
}

/// The world: the game (with `tool.exe`), the packages, the helper installed admin-only, the
/// signed test index in Rerun's `index` folder; everything durable.
pub(crate) fn world() -> (FakeSystem, [u8; 32]) {
    let sys = super::tests::finish(
        super::tests::base()
            .file(format!(r"{GAME}\tool.exe"), tool_exe())
            .file(HEXE, b"MZ helper".to_vec())
            .dir(INDEX),
    );
    let exe = format!(r"{GAME}\game.exe");
    sys.fake_fs().remove_abs(Path::new(&exe)).unwrap();
    sys.fake_fs()
        .put_file(Path::new(&exe), &game_exe())
        .unwrap();
    for p in [PF, HDIR, HEXE] {
        sys.fake_fs()
            .set_sd(Path::new(p), FakeSd::admin_only())
            .unwrap();
    }
    let index = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-09T12:00:00Z","topos":[{}],"packages":[]}}"#,
        topo_json()
    );
    let sha: [u8; 32] = Sha256::digest(index.as_bytes()).into();
    let h = hex32::to_string(&sha);
    let fs = sys.fake_fs();
    fs.put_file(Path::new(&format!(r"{INDEX}\{h}.json")), index.as_bytes())
        .unwrap();
    fs.put_file(
        Path::new(&format!(r"{INDEX}\{h}.sig")),
        &test_key::sign(index.as_bytes()),
    )
    .unwrap();
    sys.sync_all();
    (sys, sha)
}

/// Runs `f` with the seams of these tests: `firewall_rule` reviewed, the test key trusted for an
/// add (both per thread).
pub(crate) fn seams<R>(f: impl FnOnce() -> R) -> R {
    super::helper::knob::set_index_keys(Some(vec![test_key::public()]));
    let r = f();
    super::helper::knob::set_index_keys(None);
    r
}

/// The plan of `k`, stored (rules from the Topo's anchors, as the engine builds them).
pub(crate) fn plan(sys: &FakeSystem, index: [u8; 32], k: Kind) -> PlanHash {
    let fr = fr(sys);
    let g = GameDir::open_manual(sys, &fr, Path::new(GAME)).unwrap();
    let app = app(sys);
    let main = rel("game.exe");
    let steps = match k {
        Kind::Rules | Kind::TwoRules => Vec::new(),
        Kind::Mixed => vec![Step::FileInstall(spec(vec![entry(
            "new.dll",
            "new.dll",
            super::tests::N,
        )]))],
    };
    let mut p = plan_steps(
        &steps,
        &PlanCtx {
            game: &g,
            app: Some(&app),
            steam_app: None,
            main_exe: Some(&main),
            reg: crate::policy::registry::RegPolicy.reader(sys),
            app_path: None,
            user_data: None,
        },
    )
    .unwrap();
    let (picks, exes): (Vec<&str>, Vec<&str>) = match k {
        Kind::Rules => (vec!["net/block"], vec!["game.exe"]),
        Kind::Mixed | Kind::TwoRules => (
            vec!["net/block", "other/also"],
            vec!["game.exe", "tool.exe"],
        ),
    };
    p.ops.extend(exes.iter().map(|e| Op::FirewallRule {
        root: RootIx(0),
        program: rel(e),
        direction: Direction::Out,
    }));
    // P5-2a: the engine records the matched build.
    p.roots[0].main_sha256 = Some(Sha256::digest(game_exe()).into());
    p.source = Some(PlanSource {
        index,
        topo: "invented-game".to_owned(),
        rev: 3,
        picks: picks
            .iter()
            .map(|s| {
                let (i, v) = s.split_once('/').unwrap();
                Pick {
                    issue: i.to_owned(),
                    variant: v.to_owned(),
                }
            })
            .collect(),
    });
    store(&app, &p.encode().unwrap()).unwrap()
}

/// What the next helper run does (the default: the helper runs).
pub(crate) enum Script {
    /// The UAC prompt is declined.
    Decline,
    /// Something that is not the helper ends with code 0.
    Unknown,
    /// `ShellExecuteExW` fails (WDAC, Smart App Control: 4551).
    StartFails,
    /// The world changes, then the helper runs.
    Before(fn(&FakeSystem)),
    /// The helper runs, then the world changes before the CLI observes.
    After(fn(&FakeSystem)),
    /// The prompt is declined, and the world changes (P4-2d review follow-up 5).
    DeclineAnd(fn(&FakeSystem)),
    /// `ShellExecuteExW` succeeded without a process handle: nothing ran here, but the CLI
    /// cannot know (`HelperRun::Lost`, review follow-up 1).
    LostBeforeRun,
    /// The helper ran, then the wait or the exit code failed (`HelperRun::Lost`).
    LostAfterRun,
}

/// The fake transport (module docs).
pub(crate) struct Wire<'w> {
    world: &'w FakeSystem,
    pub(crate) script: Mutex<VecDeque<Script>>,
    pub(crate) runs: AtomicUsize,
    pub(crate) args: Mutex<Vec<Vec<String>>>,
    pub(crate) presence: Mutex<HelperPresence>,
}

impl<'w> Wire<'w> {
    pub(crate) fn new(world: &'w FakeSystem) -> Self {
        Self {
            world,
            script: Mutex::new(VecDeque::new()),
            runs: AtomicUsize::new(0),
            args: Mutex::new(Vec::new()),
            presence: Mutex::new(HelperPresence::None),
        }
    }

    /// The helper in-process, outside the CLI's fault sequence (another process).
    fn serve(&self, args: &[&str]) -> u32 {
        set_in_hook(true);
        let nt = helper_image(self.world)
            .map(|i| i.nt_name)
            .unwrap_or_default();
        set_in_hook(false);
        let helper = FakeHelperSystem::new(self.world, FakeHelperToken::new(true).image(&nt));
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let keys = Keys {
            trusted: vec![test_key::public()],
            revoked: Vec::new(),
            min_seq: 1,
        };
        set_in_hook(true);
        let exit = serve_with(&helper, || args, &keys);
        set_in_hook(false);
        if self.world.fake_firewall().take_crash() {
            0xC000_0409
        } else {
            exit.to_code()
        }
    }
}

impl Elevation for Wire<'_> {
    fn token_kind(&self) -> SysResult<TokenKind> {
        Ok(TokenKind::Filtered)
    }

    fn run_helper(&self, _: &crate::path::RootPath, args: &[&str]) -> SysResult<HelperRun> {
        // A CLI that crashed starts nothing (its last call may have returned before the crash).
        if self.world.fake_fs().crashed() {
            return Err(SysError::new(SysErrorKind::Other, "fake: process crashed"));
        }
        self.runs.fetch_add(1, Ordering::Relaxed);
        self.args
            .lock()
            .unwrap()
            .push(args.iter().map(|a| (*a).to_owned()).collect());
        // The pre-checked image as the elevated process would report it; read outside the CLI's
        // fault sequence (the transport is not the CLI).
        set_in_hook(true);
        let nt = helper_image(self.world).map(|i| i.nt_name);
        set_in_hook(false);
        let nt = nt.map_err(|e| SysError::new(SysErrorKind::Other, e.to_string()))?;
        let proc = HelperProc {
            image: Some(nt),
            elevated: Some(true),
        };
        let next = self.script.lock().unwrap().pop_front();
        let code = match next {
            Some(Script::Decline) => return Ok(HelperRun::Declined),
            Some(Script::DeclineAnd(f)) => {
                f(self.world);
                return Ok(HelperRun::Declined);
            }
            Some(Script::LostBeforeRun) => {
                return Ok(HelperRun::Lost {
                    why: SysError::new(SysErrorKind::Other, "fake: no process handle"),
                });
            }
            Some(Script::LostAfterRun) => {
                let _ = self.serve(args);
                return Ok(HelperRun::Lost {
                    why: SysError::new(SysErrorKind::Other, "fake: the wait failed"),
                });
            }
            Some(Script::Unknown) => 0,
            Some(Script::StartFails) => {
                return Err(SysError::new(
                    SysErrorKind::AccessDenied,
                    "fake: the start was blocked (os error 4551)",
                ));
            }
            Some(Script::Before(f)) => {
                f(self.world);
                self.serve(args)
            }
            Some(Script::After(f)) => {
                let c = self.serve(args);
                f(self.world);
                c
            }
            None => self.serve(args),
        };
        Ok(HelperRun::Exited { code, proc })
    }

    fn helper_running(&self, _: &str) -> SysResult<HelperPresence> {
        Ok(*self.presence.lock().unwrap())
    }

    fn helper_lock(&self) -> SysResult<HelperLock> {
        Ok(HelperLock::Free)
    }
}

/// The CLI's system: the world, with the fake transport as its `Elevation`.
pub(crate) struct TwoProc<'w> {
    pub(crate) world: &'w FakeSystem,
    pub(crate) wire: Wire<'w>,
}

impl System for TwoProc<'_> {
    fn fs(&self) -> &dyn crate::sys::Fs {
        self.world.fs()
    }
    fn registry(&self) -> &dyn crate::sys::Registry {
        self.world.registry()
    }
    fn registry_write(&self) -> &dyn crate::sys::RegistryWrite {
        #[expect(clippy::disallowed_methods, reason = "test: delegation to the world")]
        let r = self.world.registry_write();
        r
    }
    fn topology(&self) -> &dyn crate::sys::Topology {
        self.world.topology()
    }
    fn known_folders(&self) -> &dyn crate::sys::KnownFolders {
        self.world.known_folders()
    }
    fn gpu(&self) -> &dyn crate::sys::Gpu {
        self.world.gpu()
    }
    fn firewall(&self) -> &dyn crate::sys::Firewall {
        self.world.firewall()
    }
    fn elevation(&self) -> &dyn Elevation {
        &self.wire
    }
}

/// One world and the runs on it.
pub(crate) struct Fw {
    pub(crate) sys: FakeSystem,
    pub(crate) index: [u8; 32],
    /// The instance tag of the next run (the first is [`TAG`]).
    next: std::sync::atomic::AtomicU64,
}

impl Fw {
    pub(crate) fn new() -> Self {
        let (sys, index) = world();
        Self {
            sys,
            index,
            next: std::sync::atomic::AtomicU64::new(TAG),
        }
    }

    /// `f` on the CLI's side with `script` for the helper runs; how many runs started.
    pub(crate) fn run<R>(
        &self,
        script: Vec<Script>,
        f: impl FnOnce(&ExecCtx<'_>) -> R,
    ) -> (R, usize) {
        let two = TwoProc {
            world: &self.sys,
            wire: Wire::new(&self.sys),
        };
        two.wire.script.lock().unwrap().extend(script);
        let fr = fr(&self.sys);
        let app = app(&self.sys);
        let cx = ExecCtx {
            sys: &two,
            fr: &fr,
            app: &app,
            tag: InstanceTag::fixed(self.next.fetch_add(1, Ordering::Relaxed)),
        };
        let r = f(&cx);
        (r, two.wire.runs.load(Ordering::Relaxed))
    }

    pub(crate) fn apply(
        &self,
        h: &PlanHash,
        s: Vec<Script>,
    ) -> (Result<Outcome, ApplyError>, usize) {
        self.run(s, |cx| super::apply(cx, h))
    }

    pub(crate) fn revert(
        &self,
        t: &TxnId,
        s: Vec<Script>,
    ) -> (Result<RevertReport, ExecError>, usize) {
        self.run(s, |cx| super::revert(cx, t))
    }

    pub(crate) fn verify(&self, t: &TxnId) -> Vec<(u16, Observed)> {
        self.run(Vec::new(), |cx| super::verify(cx, t))
            .0
            .unwrap()
            .ops
    }

    /// The game folder and the firewall scope (module docs).
    pub(crate) fn snap(&self) -> (Snapshot, Vec<FwRule>) {
        (super::tests::snap_at(&self.sys, GAME), fw_scope(&self.sys))
    }

    pub(crate) fn states(&self) -> Vec<(TxnId, Option<TxnState>)> {
        let app = app(&self.sys);
        let j = Journal::new(&app, InstanceTag::fixed(1));
        j.list()
            .unwrap()
            .txns
            .into_iter()
            .map(|l| (l.id, l.view.ok().map(|v| v.state)))
            .collect()
    }

    pub(crate) fn state(&self, t: &TxnId) -> Option<TxnState> {
        self.states()
            .into_iter()
            .find(|(i, _)| i == t)
            .and_then(|(_, s)| s)
    }
}

/// The firewall scope of the round trip: group `Rerun` and every rule of Rerun's name form
/// (every planned name is of that form).
pub(crate) fn fw_scope(sys: &FakeSystem) -> Vec<FwRule> {
    crate::policy::firewall::rerun_rules(sys.firewall()).unwrap()
}

/// The first transaction of a fresh world.
pub(crate) fn txn1() -> TxnId {
    TxnId::new(1, TAG).unwrap()
}

fn applied(r: &Result<Outcome, ApplyError>) -> TxnId {
    match r {
        Ok(Outcome::Applied(t)) => *t,
        other => panic!("apply: {other:?}"),
    }
}

/// What a case expects of the helper failure.
type Want = fn(&HelperFailure) -> bool;

fn helper_cause(e: &ApplyError) -> Option<&HelperFailure> {
    let cause = match e {
        ApplyError::RolledBack { cause, .. }
        | ApplyError::HelperOpen { cause, .. }
        | ApplyError::LeftOpen { cause, .. } => cause,
        _ => return None,
    };
    match &**cause {
        ExecError::Helper(f) => Some(f),
        _ => None,
    }
}

// ---------- F1 ----------

#[test]
fn f1_round_trip_with_one_helper_run_per_direction() {
    seams(|| {
        for k in [Kind::Rules, Kind::Mixed] {
            let fw = Fw::new();
            let before = fw.snap();
            let h = plan(&fw.sys, fw.index, k);
            let (r, runs) = fw.apply(&h, Vec::new());
            let t = applied(&r);
            assert_eq!(runs, 1, "{k:?}: one prompt for the apply");
            let n = if k == Kind::Rules { 1 } else { 2 };
            assert_eq!(fw_scope(&fw.sys).len(), n, "{k:?}");
            let v = fw.verify(&t);
            assert!(v.iter().all(|(_, o)| *o == Observed::After), "{k:?}: {v:?}");
            assert_eq!(v.len(), if k == Kind::Rules { 1 } else { 3 });
            // The request file is gone again.
            assert!(names(&fw.sys, ELEVATE).is_empty(), "{k:?}");
            let (r, runs) = fw.revert(&t, Vec::new());
            let r = r.unwrap();
            assert_eq!(r.closed, Some(Closing::Reverted), "{k:?}: {r:?}");
            assert_eq!(runs, 1, "{k:?}: one prompt for the revert");
            assert_eq!(fw.snap(), before, "{k:?}");
        }
    });
}

/// The rules are named by Topo, transaction and op, in group `Rerun`, with the program of the
/// head (`policy::firewall::rule`).
#[test]
fn f1_the_rules_have_rerun_s_form() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Mixed);
        let t = applied(&fw.apply(&h, Vec::new()).0);
        let rules = fw_scope(&fw.sys);
        let names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            [
                format!("Rerun - invented-game - {t}-001"),
                format!("Rerun - invented-game - {t}-002")
            ]
        );
        assert!(rules.iter().all(|r| r.grouping == GROUP));
        assert_eq!(rules[0].program, format!(r"{GAME}\game.exe"));
        assert_eq!(rules[1].program, format!(r"{GAME}\tool.exe"));
    });
}

// ---------- F2: apply outcomes ----------

/// Declined, refused (tampered after `begin`) or not started: the rollback of every earlier op
/// (exit 4), the batch recorded `Before` without a second helper run.
#[test]
fn f2_declined_refused_or_not_started_roll_back() {
    let tamper_request: fn(&FakeSystem) = |s| {
        for e in names(s, ELEVATE) {
            let p = format!(r"{ELEVATE}\{e}");
            s.fake_fs().remove_abs(Path::new(&p)).unwrap();
            s.fake_fs().put_file(Path::new(&p), b"{}").unwrap();
        }
    };
    let tamper_index: fn(&FakeSystem) = |s| {
        for e in names(s, INDEX) {
            if e.ends_with(".sig") {
                let p = format!(r"{INDEX}\{e}");
                s.fake_fs().remove_abs(Path::new(&p)).unwrap();
                s.fake_fs().put_file(Path::new(&p), &[0; 64]).unwrap();
            }
        }
    };
    let tamper_program: fn(&FakeSystem) = |s| {
        let p = format!(r"{GAME}\tool.exe");
        s.fake_fs().remove_abs(Path::new(&p)).unwrap();
        s.fake_fs().put_file(Path::new(&p), b"MZ patched").unwrap();
    };
    let cases: Vec<(&str, Script, Want)> = vec![
        ("declined", Script::Decline, |f| {
            matches!(f, HelperFailure::Declined)
        }),
        ("start blocked", Script::StartFails, |f| {
            matches!(f, HelperFailure::Start(_))
        }),
        ("request changed", Script::Before(tamper_request), |f| {
            matches!(f, HelperFailure::Refused(crate::elevate::Reason::Request))
        }),
        ("index changed", Script::Before(tamper_index), |f| {
            matches!(f, HelperFailure::Refused(crate::elevate::Reason::Index))
        }),
        ("program changed", Script::Before(tamper_program), |f| {
            matches!(f, HelperFailure::Refused(crate::elevate::Reason::Program))
        }),
    ];
    seams(|| {
        for (what, script, want) in cases {
            let fw = Fw::new();
            let before = super::tests::snap_at(&fw.sys, GAME);
            let h = plan(&fw.sys, fw.index, Kind::Mixed);
            let (r, runs) = fw.apply(&h, vec![script]);
            let e = r.unwrap_err();
            assert!(matches!(e, ApplyError::RolledBack { .. }), "{what}: {e:?}");
            assert!(helper_cause(&e).is_some_and(want), "{what}: {e:?}");
            assert_eq!(runs, 1, "{what}");
            assert_eq!(
                fw.state(&txn1()),
                Some(TxnState::Closed(Closing::RolledBack)),
                "{what}"
            );
            if what != "program changed" {
                assert_eq!(super::tests::snap_at(&fw.sys, GAME), before, "{what}");
            }
            assert!(fw_scope(&fw.sys).is_empty(), "{what}");
        }
    });
}

/// Unknown, a helper that crashed after its add, a disagreement: no rollback (it would need a
/// second prompt, R3), the transaction open (exit 5); the revert finishes it.
#[test]
fn f2_unknown_crash_or_disagreement_stay_open_and_revert_finishes() {
    let admin_removes: fn(&FakeSystem) = |s| s.fake_firewall().set_rules(Vec::new());
    let crash: fn(&FakeSystem) = |s| {
        s.fake_firewall()
            .fault_write(1, crate::sys::fake::WriteFault::CrashAfter);
    };
    let cases: Vec<(&str, Script, usize, Want)> = vec![
        ("unknown", Script::Unknown, 0, |f| {
            matches!(f, HelperFailure::Unknown)
        }),
        ("crash after the add", Script::Before(crash), 1, |f| {
            matches!(f, HelperFailure::Unknown)
        }),
        ("disagreement", Script::After(admin_removes), 0, |f| {
            matches!(f, HelperFailure::Disagree)
        }),
    ];
    seams(|| {
        for (what, script, left, want) in cases {
            let fw = Fw::new();
            let before = fw.snap();
            let h = plan(&fw.sys, fw.index, Kind::Mixed);
            let (r, _) = fw.apply(&h, vec![script]);
            let e = r.unwrap_err();
            assert!(matches!(e, ApplyError::HelperOpen { .. }), "{what}: {e:?}");
            assert!(helper_cause(&e).is_some_and(want), "{what}: {e:?}");
            assert_eq!(fw.state(&txn1()), Some(TxnState::Open), "{what}");
            assert_eq!(fw_scope(&fw.sys).len(), left, "{what}");
            // The revert: a helper run only if a rule is there.
            let (r, runs) = fw.revert(&txn1(), Vec::new());
            let r = r.unwrap();
            assert_eq!(r.closed, Some(Closing::RolledBack), "{what}: {r:?}");
            assert_eq!(runs, usize::from(left > 0), "{what}");
            assert_eq!(fw.snap(), before, "{what}");
        }
    });
}

// ---------- F3: revert outcomes ----------

/// A declined prompt at the revert halts at the batch: nothing below it is reverted (LIFO), the
/// transaction stays applied, the next revert asks again.
#[test]
fn f3_a_declined_revert_reverts_nothing() {
    seams(|| {
        let fw = Fw::new();
        let before = fw.snap();
        let h = plan(&fw.sys, fw.index, Kind::Mixed);
        let t = applied(&fw.apply(&h, Vec::new()).0);
        let mid = fw.snap();
        let (r, runs) = fw.revert(&t, vec![Script::Decline]);
        let r = r.unwrap();
        assert_eq!(runs, 1);
        assert_eq!(r.closed, None);
        assert!(r.ops.is_empty(), "{r:?}");
        let h = r.halted.unwrap();
        assert_eq!(h.op, 2);
        assert!(
            matches!(*h.why, Refusal::Helper(HelperFailure::Declined)),
            "{:?}",
            h.why
        );
        assert_eq!(fw.snap(), mid);
        assert_eq!(fw.state(&t), Some(TxnState::Applied));
        let (r, runs) = fw.revert(&t, Vec::new());
        assert_eq!(r.unwrap().closed, Some(Closing::Reverted));
        assert_eq!(runs, 1);
        assert_eq!(fw.snap(), before);
    });
}

/// A rule an administrator changed is `Foreign` and stays; the rest is reverted; only forget
/// closes. A rule an administrator removed needs no helper.
#[test]
fn f3_foreign_and_gone_rules() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Mixed);
        let t = applied(&fw.apply(&h, Vec::new()).0);
        let name = format!("Rerun - invented-game - {t}-002");
        fw.sys
            .fake_firewall()
            .edit(|r| r.name == name, |r| r.enabled = false);
        let (r, runs) = fw.revert(&t, Vec::new());
        let r = r.unwrap();
        assert_eq!(runs, 1, "the other rule is removed by the helper");
        assert_eq!(r.closed, None);
        let seen: Vec<(u16, Observed)> = r.ops.iter().map(|o| (o.op, o.observed)).collect();
        assert_eq!(
            seen,
            [
                (2, Observed::Foreign),
                (1, Observed::After),
                (0, Observed::After)
            ]
        );
        assert_eq!(fw_scope(&fw.sys).len(), 1);
        assert!(fw.run(Vec::new(), |cx| super::forget(cx, &t)).0.is_ok());
        // Gone already: no helper at all.
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Rules);
        let t = applied(&fw.apply(&h, Vec::new()).0);
        fw.sys.fake_firewall().set_rules(Vec::new());
        let (r, runs) = fw.revert(&t, Vec::new());
        assert_eq!(r.unwrap().closed, Some(Closing::Reverted));
        assert_eq!(runs, 0);
    });
}

/// A4 S8: before a batch without a result is observed, no helper of an earlier run may run;
/// else the revert is refused before its first record.
#[test]
fn f3_ensure_idle_before_an_unfinished_batch() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Rules);
        let (r, _) = fw.apply(&h, vec![Script::Unknown]);
        assert!(matches!(r, Err(ApplyError::HelperOpen { .. })));
        let two = TwoProc {
            world: &fw.sys,
            wire: Wire::new(&fw.sys),
        };
        *two.wire.presence.lock().unwrap() = HelperPresence::Running;
        let fr_ = fr(&fw.sys);
        let app_ = app(&fw.sys);
        let cx = ExecCtx {
            sys: &two,
            fr: &fr_,
            app: &app_,
            tag: InstanceTag::fixed(TAG + 50),
        };
        let r = super::revert(&cx, &txn1());
        assert!(
            matches!(
                r,
                Err(ExecError::Refused(Refusal::Helper(HelperFailure::Busy(_))))
            ),
            "{r:?}"
        );
        assert_eq!(fw.state(&txn1()), Some(TxnState::Open));
        // An applied batch has its result: no check.
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Rules);
        let t = applied(&fw.apply(&h, Vec::new()).0);
        let two = TwoProc {
            world: &fw.sys,
            wire: Wire::new(&fw.sys),
        };
        *two.wire.presence.lock().unwrap() = HelperPresence::Running;
        let fr_ = fr(&fw.sys);
        let app_ = app(&fw.sys);
        let cx = ExecCtx {
            sys: &two,
            fr: &fr_,
            app: &app_,
            tag: InstanceTag::fixed(TAG + 51),
        };
        assert_eq!(
            super::revert(&cx, &t).unwrap().closed,
            Some(Closing::Reverted)
        );
    });
}

// ---------- F4: the request file (N9) ----------

#[test]
fn f4_leftovers_are_swept_and_a_taken_name_moves_on() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Rules);
        let fs = fw.sys.fake_fs();
        let leftover = format!(r"{ELEVATE}\00000009-00000000000000ff-3.req");
        fs.put_file(Path::new(&leftover), b"old").unwrap();
        let other = format!(r"{ELEVATE}\notes.txt");
        fs.put_file(Path::new(&other), b"not Rerun's").unwrap();
        // The name of this transaction's first request, held by a file that cannot be deleted
        // (a second link): the request takes the next number.
        let taken = format!(r"{ELEVATE}\{}-1.req", txn1());
        fs.put_file(Path::new(&taken), b"taken").unwrap();
        fs.put_hardlink(Path::new(&taken), Path::new(r"C:\Users\Player\link.req"))
            .unwrap();
        let two = TwoProc {
            world: &fw.sys,
            wire: Wire::new(&fw.sys),
        };
        let fr_ = fr(&fw.sys);
        let app_ = app(&fw.sys);
        let cx = ExecCtx {
            sys: &two,
            fr: &fr_,
            app: &app_,
            tag: InstanceTag::fixed(TAG),
        };
        assert!(matches!(super::apply(&cx, &h), Ok(Outcome::Applied(_))));
        let args = two.wire.args.lock().unwrap().clone();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0][5], format!("{}-2.req", txn1()));
        let mut left = names(&fw.sys, ELEVATE);
        left.sort();
        assert_eq!(left, [format!("{}-1.req", txn1()), "notes.txt".to_owned()]);
    });
}

// ---------- F5: the plan format and the begin check (A4 S7) ----------

#[test]
fn f5_rules_are_last_need_a_source_and_are_rechecked_at_begin() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Mixed);
        let app = app(&fw.sys);
        let bytes = crate::plan::load(&app, &h).unwrap();
        let p = crate::plan::decode(bytes.bytes()).unwrap();
        // The format's rules, each refused with its own words (review follow-up 10).
        let refused = |q: &crate::plan::Plan, why: &str| {
            let e = q.encode().expect_err(why).to_string();
            assert!(e.contains(why), "{e} (wanted: {why})");
        };
        let mut q = p.clone();
        q.ops.swap(0, 1);
        refused(&q, "an op after a firewall rule");
        let mut q = p.clone();
        q.source = None;
        refused(&q, "a firewall rule needs the plan's source");
        let mut q = p.clone();
        if let Op::FirewallRule { program, .. } = &mut q.ops[1] {
            *program = rel(r"bin\%x%.exe");
        }
        refused(&q, "a program a firewall rule cannot name");
        let mut q = p.clone();
        q.ops.push(q.ops[1].clone());
        refused(&q, "two firewall rules for one executable");
        // More than one helper batch holds.
        let mut q = p.clone();
        for i in 0..7 {
            q.ops.push(Op::FirewallRule {
                root: RootIx(0),
                program: rel(&format!("extra{i}.exe")),
                direction: Direction::Out,
            });
        }
        refused(&q, "more than 8 firewall rules");
        // A rule outside a game folder (Rerun's profiles root).
        let mut q = p.clone();
        q.roots[0].origin = crate::plan::PlanOrigin::Steam {
            store: crate::path::RootPath::new(r"D:\SteamLibrary").unwrap(),
            store_id: crate::policy::root::RootId {
                volume_serial: 9,
                file_id: 9,
            },
            app_id: 220,
            installdir: rel("G"),
        };
        q.roots.push(crate::plan::PlanRoot {
            kind: crate::plan::RootKind::Profiles,
            path: crate::path::RootPath::new(r"C:\Users\Player\AppData\Local\Rerun\profiles")
                .unwrap(),
            id: crate::plan::PROFILES_ROOT_ID,
            origin: crate::plan::PlanOrigin::AppDir,
            main_exe: None,
            main_sha256: None,
        });
        if let Op::FirewallRule { root, .. } = &mut q.ops[2] {
            *root = RootIx(1);
        }
        refused(&q, "a firewall rule outside a game folder");
        // Security review N2: a rule for an executable a file op of the same plan writes.
        let mut q = p.clone();
        if let Op::CreateFile { path, .. } = &mut q.ops[0] {
            *path = rel("tool.exe");
        }
        refused(&q, "a firewall rule for an executable the plan writes");
        // The game changed since planning: refused before `begin`, nothing written, no prompt.
        let p = format!(r"{GAME}\tool.exe");
        fw.sys.fake_fs().remove_abs(Path::new(&p)).unwrap();
        fw.sys
            .fake_fs()
            .put_file(Path::new(&p), b"MZ patched")
            .unwrap();
        let (r, runs) = fw.apply(&h, Vec::new());
        assert!(
            matches!(r, Err(ApplyError::Refused(Refusal::HelperPlan(_)))),
            "{r:?}"
        );
        assert_eq!(runs, 0);
        assert!(fw.states().is_empty());
        // `check` (a dry run) refuses the same.
        let (r, _) = fw.run(Vec::new(), |cx| super::check(cx, &h));
        assert!(matches!(r, Err(Refusal::HelperPlan(_))), "{r:?}");
    });
}

/// The helper is not installed safely: refused before the lock, no prompt (ADR 0023 §2).
#[test]
fn f5_an_unsafe_helper_is_refused_before_the_lock() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Rules);
        let mut sd = FakeSd::admin_only();
        if let Some(d) = sd.dacl.as_mut() {
            d.push(FakeSd::allow("S-1-5-32-545", 0x2));
        }
        fw.sys.fake_fs().set_sd(Path::new(HDIR), sd).unwrap();
        let (r, runs) = fw.apply(&h, Vec::new());
        assert!(
            matches!(r, Err(ApplyError::Refused(Refusal::HelperUnsafe(_)))),
            "{r:?}"
        );
        assert_eq!(runs, 0);
        assert!(fw.states().is_empty());
    });
}

/// The names in the folder `abs` (empty if it is missing).
pub(crate) fn names(sys: &FakeSystem, abs: &str) -> Vec<String> {
    #[expect(clippy::disallowed_methods, reason = "test: a listing of the world")]
    let d = match sys.fs().open_dir(Path::new(abs)) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    d.read_dir(None)
        .map(|v| v.into_iter().map(|e| e.name).collect())
        .unwrap_or_default()
}

/// A4 N6: the Rerun rules no transaction of this account owns: none while the transaction is
/// open; the rule `forget` left, and another account's, afterwards.
#[test]
fn f6_rules_no_transaction_of_this_account_owns() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Rules);
        let t = applied(&fw.apply(&h, Vec::new()).0);
        let app = app(&fw.sys);
        assert_eq!(super::firewall_orphans(&fw.sys, &app).unwrap(), Vec::new());
        // Another Windows account's rule (its journal is not this one).
        let mut other = fw_scope(&fw.sys)[0].clone();
        other.name = "Rerun - invented-game - 00000003-00000000000000aa-000".to_owned();
        fw.sys.fake_firewall().push(other);
        let o = super::firewall_orphans(&fw.sys, &app).unwrap();
        assert_eq!(o.len(), 1);
        assert_eq!(
            o[0].name.to_string(),
            "Rerun - invented-game - 00000003-00000000000000aa-000"
        );
        // Forget leaves the rule in place: no open transaction owns it now.
        assert!(fw.run(Vec::new(), |cx| super::forget(cx, &t)).0.is_ok());
        assert_eq!(super::firewall_orphans(&fw.sys, &app).unwrap().len(), 2);
        // An unreadable firewall is an error of the list only.
        fw.sys
            .fake_firewall()
            .fail_with(Some(SysErrorKind::AccessDenied));
        assert!(super::firewall_orphans(&fw.sys, &app).is_err());
    });
}

/// The wire form of the op (ADR 0020 amendment P4-2d).
#[test]
fn f6_the_op_has_one_wire_form() {
    let op = Op::FirewallRule {
        root: RootIx(0),
        program: rel(r"bin\game.exe"),
        direction: Direction::Out,
    };
    assert_eq!(
        serde_json::to_string(&op).unwrap(),
        r#"{"firewall_rule":{"root":0,"program":"bin\\game.exe","direction":"out"}}"#
    );
}

// ---------- F7: review follow-ups of P4-2d ----------

/// The CLI side with the helper presence `p` (A4 S8 tests).
fn revert_with_presence(fw: &Fw, t: &TxnId, p: HelperPresence) -> Result<RevertReport, ExecError> {
    let two = TwoProc {
        world: &fw.sys,
        wire: Wire::new(&fw.sys),
    };
    *two.wire.presence.lock().unwrap() = p;
    let fr_ = fr(&fw.sys);
    let app_ = app(&fw.sys);
    let cx = ExecCtx {
        sys: &two,
        fr: &fr_,
        app: &app_,
        tag: InstanceTag::fixed(TAG + 70),
    };
    super::revert(&cx, t)
}

fn log_len(fw: &Fw, t: &TxnId) -> usize {
    let app = app(&fw.sys);
    let j = Journal::new(&app, InstanceTag::fixed(3));
    j.load(t, crate::journal::VerifyBackups::Length)
        .unwrap()
        .log
        .len()
}

/// 1: once the start succeeded, a missing process handle or a failed wait is `Unknown`, never
/// `Start`: no rollback (a helper may still add a rule), open, exit 5; the revert finishes it.
#[test]
fn f7_a_lost_result_after_the_start_stays_open() {
    use crate::elevate::{Judged, judge};
    let fw = Fw::new();
    let image = helper_image(&fw.sys).unwrap();
    let lost = HelperRun::Lost {
        why: SysError::new(SysErrorKind::Other, "wait"),
    };
    assert_eq!(judge(&lost, &image, 1), Judged::Unknown);
    seams(|| {
        for (script, left) in [(Script::LostBeforeRun, 0), (Script::LostAfterRun, 2)] {
            let fw = Fw::new();
            let before = fw.snap();
            let h = plan(&fw.sys, fw.index, Kind::Mixed);
            let (r, runs) = fw.apply(&h, vec![script]);
            let e = r.unwrap_err();
            assert!(matches!(e, ApplyError::HelperOpen { .. }), "{e:?}");
            assert!(
                matches!(helper_cause(&e), Some(HelperFailure::Unknown)),
                "{e:?}"
            );
            assert_eq!(runs, 1);
            assert_eq!(fw.state(&txn1()), Some(TxnState::Open));
            assert_eq!(fw_scope(&fw.sys).len(), left);
            let (r, _) = fw.revert(&txn1(), Vec::new());
            assert_eq!(r.unwrap().closed, Some(Closing::RolledBack));
            assert_eq!(fw.snap(), before);
        }
    });
}

/// 2 (security L2): before an unfinished batch is observed, the request files of earlier runs
/// go first, then `ensure_idle`; `forget` sweeps them too.
#[test]
fn f7_leftover_requests_are_swept_before_ensure_idle_and_by_forget() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Rules);
        let (r, _) = fw.apply(&h, vec![Script::Unknown]);
        assert!(matches!(r, Err(ApplyError::HelperOpen { .. })));
        let stale = format!(r"{ELEVATE}\{}-1.req", txn1());
        fw.sys
            .fake_fs()
            .put_file(Path::new(&stale), b"stale")
            .unwrap();
        let r = revert_with_presence(&fw, &txn1(), HelperPresence::Running);
        assert!(
            matches!(
                r,
                Err(ExecError::Refused(Refusal::Helper(HelperFailure::Busy(_))))
            ),
            "{r:?}"
        );
        assert!(
            names(&fw.sys, ELEVATE).is_empty(),
            "swept before the refusal"
        );
        // Forget.
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Rules);
        let t = applied(&fw.apply(&h, Vec::new()).0);
        let stale = format!(r"{ELEVATE}\{t}-4.req");
        fw.sys
            .fake_fs()
            .put_file(Path::new(&stale), b"stale")
            .unwrap();
        assert!(fw.run(Vec::new(), |cx| super::forget(cx, &t)).0.is_ok());
        assert!(names(&fw.sys, ELEVATE).is_empty());
    });
}

/// 3: a `RevertBatch` without its `RevertDone` (a declined revert) is a batch without a result:
/// `ensure_idle` refuses while a helper runs, before the first record of the run.
#[test]
fn f7_a_revert_batch_without_its_done_is_unfinished() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Rules);
        let t = applied(&fw.apply(&h, Vec::new()).0);
        let (r, _) = fw.revert(&t, vec![Script::Decline]);
        assert!(r.unwrap().halted.is_some());
        let n = log_len(&fw, &t);
        let r = revert_with_presence(&fw, &t, HelperPresence::Running);
        assert!(
            matches!(
                r,
                Err(ExecError::Refused(Refusal::Helper(HelperFailure::Busy(_))))
            ),
            "{r:?}"
        );
        assert_eq!(log_len(&fw, &t), n, "nothing written");
    });
}

/// 4: a `HelperBatch` cut short of the head's rule ops does not fit the head: `Blocked`.
#[test]
fn f7_a_truncated_helper_batch_does_not_fit_the_head() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::TwoRules);
        let t = {
            let app_ = app(&fw.sys);
            let bytes = crate::plan::load(&app_, &h).unwrap();
            let j = Journal::new(&app_, InstanceTag::fixed(TAG + 80));
            let lock = j.lock().unwrap();
            let mut w = lock.begin(bytes.bytes()).unwrap();
            let t = *w.id();
            let d = crate::journal::Digest {
                sha256: [1; 32],
                len: 1,
            };
            w.helper_batch(0, 0, d).unwrap();
            t
        };
        let r = fw.run(Vec::new(), |cx| super::verify(cx, &t)).0;
        assert!(
            matches!(r, Err(ExecError::Refused(Refusal::Blocked { .. }))),
            "{r:?}"
        );
        let (r, runs) = fw.revert(&t, Vec::new());
        assert!(
            matches!(r, Err(ExecError::Refused(Refusal::Blocked { .. }))),
            "{r:?}"
        );
        assert_eq!(runs, 0);
    });
}

/// 5: the run's verdict before any observation: after a declined prompt the batch itself reads
/// nothing (the rollback's observation is the only one, exit 4), and a firewall that cannot be
/// read then leaves the cause `Declined` (the rollback, which must observe before it records
/// `Before`, stays open: exit 5), never `Unreadable` or `HelperOpen`.
#[test]
fn f7_declined_is_decided_before_the_firewall_is_read() {
    seams(|| {
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Mixed);
        let n = fw.sys.fake_firewall().selects();
        let (r, _) = fw.apply(&h, vec![Script::Decline]);
        let e = r.unwrap_err();
        assert!(matches!(e, ApplyError::RolledBack { .. }), "{e:?}");
        assert_eq!(
            fw.sys.fake_firewall().selects() - n,
            1,
            "the rollback's read only"
        );
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Mixed);
        let (r, _) = fw.apply(
            &h,
            vec![Script::DeclineAnd(|s| s.fake_firewall().fail_next(1))],
        );
        let e = r.unwrap_err();
        assert!(matches!(e, ApplyError::LeftOpen { .. }), "{e:?}");
        assert!(
            matches!(helper_cause(&e), Some(HelperFailure::Declined)),
            "{e:?}"
        );
    });
}

/// 9: a game-folder flush that fails before `HelperBatch` (the mixed apply's `flush_all`) rolls
/// the apply back without any helper run.
#[test]
fn f7_a_failed_game_flush_before_the_batch_rolls_back_without_a_helper() {
    use std::sync::{Arc, Mutex as M};
    seams(|| {
        // Which directory flush is the game folder's: the one that runs while `D:` has pending
        // changes (the file op's), traced on a clean run.
        let fw = Fw::new();
        let h = plan(&fw.sys, fw.index, Kind::Mixed);
        let seen: Arc<M<Vec<usize>>> = Arc::new(M::new(Vec::new()));
        let s2 = Arc::clone(&seen);
        fw.sys.fake_fs().on_step(move |fx, ev| {
            if ev.call == Some(crate::sys::fake::Prim::FlushDir) {
                s2.lock().unwrap().push(fx.pending('D'));
            }
        });
        let _ = applied(&fw.apply(&h, Vec::new()).0);
        fw.sys.fake_fs().clear_on_step();
        let flushes = seen.lock().unwrap().clone();
        let nth = flushes.iter().position(|p| *p > 0).expect("a flush of D:") + 1;
        // The same apply with that flush failing.
        let fw = Fw::new();
        let before = fw.snap();
        let h = plan(&fw.sys, fw.index, Kind::Mixed);
        let (r, runs) = fw.run(Vec::new(), |cx| {
            fw.sys.fake_fs().clear_faults();
            fw.sys
                .fake_fs()
                .fail_at(crate::sys::fake::Prim::FlushDir, nth, SysErrorKind::Other);
            super::apply(cx, &h)
        });
        assert!(matches!(r, Err(ApplyError::RolledBack { .. })), "{r:?}");
        assert_eq!(runs, 0);
        assert_eq!(fw.snap(), before);
        let app_ = app(&fw.sys);
        let j = Journal::new(&app_, InstanceTag::fixed(4));
        let v = j
            .load(&txn1(), crate::journal::VerifyBackups::Length)
            .unwrap();
        assert!(v.ops.values().all(|o| !o.intent.batch), "no HelperBatch");
    });
}

// ---------- F8 (P4-10 review) ----------

/// The order the engine names when a plan has a `laa_patch` and a `firewall_rule` of one
/// executable (`topo/laa_tests.rs` LA11): the rule first, in its own plan, then the patch. The
/// rule is bound to the executable by its path; only its add hashes the file, so the patched
/// file does not disturb it: either revert order ends identical.
#[test]
fn f8_a_rule_first_then_the_patch() {
    seams(|| {
        for rule_reverted_first in [false, true] {
            let fw = Fw::new();
            let before = fw.snap();
            let (r, _) = fw.apply(&plan(&fw.sys, fw.index, Kind::Rules), Vec::new());
            let rule = applied(&r);
            // The patch of the same game.exe, in a plan of its own.
            let fr = fr(&fw.sys);
            let g = GameDir::open_manual(&fw.sys, &fr, Path::new(GAME)).unwrap();
            let a = app(&fw.sys);
            let main = rel("game.exe");
            let p = plan_steps(
                &[Step::LaaPatch(crate::prim::LaaPatchSpec {
                    exe: rel("game.exe"),
                    sha256: Sha256::digest(game_exe()).into(),
                })],
                &PlanCtx {
                    game: &g,
                    app: Some(&a),
                    steam_app: None,
                    main_exe: Some(&main),
                    reg: crate::policy::registry::RegPolicy.reader(&fw.sys),
                    app_path: None,
                    user_data: None,
                },
            )
            .unwrap();
            let h = store(&a, &p.encode().unwrap()).unwrap();
            drop((g, a));
            let (r, runs) = fw.apply(&h, Vec::new());
            let patch = applied(&r);
            assert_eq!(runs, 0, "the patch needs no helper");
            assert_eq!(fw_scope(&fw.sys).len(), 1);
            let order = if rule_reverted_first {
                [rule, patch]
            } else {
                [patch, rule]
            };
            for t in order {
                let (r, _) = fw.revert(&t, Vec::new());
                assert_eq!(r.unwrap().closed, Some(Closing::Reverted), "{t}");
            }
            assert_eq!(fw.snap(), before, "rule first: {rule_reverted_first}");
        }
    });
}
