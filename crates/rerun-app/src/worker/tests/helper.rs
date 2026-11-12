//! The elevated helper from the app (P5-5c, ADR 0023 and ADR 0027 amendments P5-5c), without a
//! window and without a real prompt. Every ID, step and hash is invented. The world has the
//! helper installed admin-only in `C:\Program Files\Rerun` and a UAC policy of an administrator
//! in admin approval mode (consent on the secure desktop); the Topo has `ini` (an INI edit) and
//! `block` (a firewall rule, the helper).
//! - AH1 a ready helper: the fix is selectable but never preselected and says that Windows asks;
//!   the preview names the prompt (consent, credentials, not on the secure desktop, no dialog at
//!   all); nothing asks Windows by looking.
//! - AH2 apply: the worker says it waits for Windows before the result, the helper runs once with
//!   the batch derived from the plan (the request form of ADR 0023 §3 step 5), the rule is there,
//!   the card lists it; undo asks once, the rule is gone and the game folder is bit-identical.
//! - AH3 a declined prompt on apply: one prompt, the earlier ops rolled back, the transaction
//!   closed; the result says so with the transaction's ID; nothing in the game or the firewall
//!   changed.
//! - AH4 a helper result Rerun cannot trust (`HelperOpen`): the change stays open with a card
//!   that can be undone; a declined prompt on undo halts there and keeps the card and the rule.
//! - AH5 no safe helper or no elevation: the fix is locked with the reason, nothing is planned,
//!   an undo that needs it cannot be confirmed and keeps no token; Windows is never asked.
//! - AH6 the nonce and the second click: a second Apply and a stale undo confirm never start the
//!   helper a second time.
//! - AH7 the window's handle reaches the helper start: the world is built at once with a
//!   `PromptOwnerSlot`, `Worker::set_owner` fills it later (a late owner is not lost, the first
//!   one stays), the fake records it with the run (the `WinSystem::with_prompt_owner_slot`
//!   path); never handed over, the run has none.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::Path;
use std::sync::Mutex;

use rerun_core::elevate::prompt::POLICY_KEY;
use rerun_core::journal::TxnId;
use rerun_core::plan::Pick;
use rerun_core::policy::firewall::GROUP;
use rerun_core::policy::root::helper_image;
use rerun_core::sys::fake::{FAKE_USER_SID, FakeHelperSystem, FakeHelperToken, FakeSd};
use rerun_core::sys::registry::{Hive, RegKey, RegView};
use rerun_core::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use rerun_core::sys::{
    Elevation, Firewall, FwRule, Gpu, HelperLock, HelperPresence, HelperProc, HelperRun,
    KnownFolders, PromptOwner, PromptOwnerSlot, Registry, RegistryWrite, SysResult, System,
    TokenKind, Topology,
};

use super::*;
use crate::text::{Msg, t};
use crate::vm::{DialogVm, Offer, PreviewVm, ResultVm, Selection, Tone, UacVm};

const PF: &str = r"C:\Program Files";
const HDIR: &str = r"C:\Program Files\Rerun";
const HEXE: &str = r"C:\Program Files\Rerun\rerun-helper.exe";
const INI: &str = "[Display]\r\nWidth=800\r\n";

/// The Topo: `ini` edits `game.ini`, `block` blocks `game.exe` outbound (the helper).
fn helper_index(sha: &str) -> String {
    let ini = r#"{"ini_set":{"file":"game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}"#;
    format!(
        r#"{{"format":1,"seq":9,"issued":"2026-11-12T12:00:00Z","topos":[{{"format":1,"id":"invented-h","title":"Invented H","status":"active","rev":1,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"issues":[
 {{"id":"display","title":"Wrong resolution","variants":[{{"id":"ini","status":"verified","kind":"fix","steps":[{ini}]}}]}},
 {{"id":"net","title":"The game phones home","variants":[{{"id":"block","status":"verified","kind":"fix","steps":[{{"firewall_rule":{{"exe":"game.exe","direction":"out"}}}}]}}]}}
]}}],"packages":[]}}"#
    )
}

/// The UAC policy of the world: `(value, data)` below `POLICY_KEY`.
type Policy = &'static [(&'static str, u32)];

/// An administrator in admin approval mode, consent on the secure desktop (Windows' default).
const CONSENT: Policy = &[
    ("EnableLUA", 1),
    ("ConsentPromptBehaviorAdmin", 5),
    ("PromptOnSecureDesktop", 1),
];

/// Steam with the game, its `game.ini`, the Topo imported; the helper installed admin-only when
/// `helper`; the UAC policy `policy`.
fn helper_world(helper: bool, policy: Policy) -> FakeSystem {
    let key = RegKey::new(Hive::LocalMachine, RegView::Native, POLICY_KEY);
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
            acf(220, "Invented H", 4, "G").into_bytes(),
        )
        .file(format!(r"{G}\game.exe"), x86())
        .file(format!(r"{G}\game.ini"), INI.as_bytes().to_vec());
    if helper {
        b = b.file(HEXE, b"MZ helper".to_vec());
    }
    for (name, v) in policy {
        b = b.value(key.clone(), name, RegValue::Dword(*v));
    }
    let sys = b.build().unwrap();
    if helper {
        for p in [PF, HDIR, HEXE] {
            sys.fake_fs()
                .set_sd(Path::new(p), FakeSd::admin_only())
                .unwrap();
        }
    }
    let ix = helper_index(&sha256_of(&sys, "game.exe"));
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    catalog::store::import(
        &app,
        ix.as_bytes(),
        &test_key::sign(ix.as_bytes()),
        &catalog::trusted_keys(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    drop(app);
    sys.fake_fs().sync_all();
    sys
}

/// What the in-process helper does with the next start.
enum Script {
    /// The user declines the prompt.
    Decline,
}

/// The two-process fake (as `rerun-core`'s `exec::fw_tests`): the app's side runs on the world,
/// and a helper start runs `elevate::serve` in-process with the helper's view of the same world
/// (its file system and the firewall's write side), elevated, its image the pre-checked one.
#[derive(Default)]
struct Wire {
    script: Mutex<VecDeque<Script>>,
    runs: Mutex<Vec<Vec<String>>>,
}

struct TwoProc<'w> {
    world: &'w FakeSystem,
    wire: &'w Wire,
}

impl Elevation for TwoProc<'_> {
    fn token_kind(&self) -> SysResult<TokenKind> {
        self.world.elevation().token_kind()
    }

    fn run_helper(&self, _: &rerun_core::path::RootPath, args: &[&str]) -> SysResult<HelperRun> {
        self.wire
            .runs
            .lock()
            .unwrap()
            .push(args.iter().map(|a| (*a).to_owned()).collect());
        if let Some(Script::Decline) = self.wire.script.lock().unwrap().pop_front() {
            return Ok(HelperRun::Declined);
        }
        let nt = helper_image(self.world).unwrap().nt_name;
        let helper = FakeHelperSystem::new(self.world, FakeHelperToken::new(true).image(&nt));
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let code = rerun_core::elevate::serve(&helper, || args).to_code();
        Ok(HelperRun::Exited {
            code,
            proc: HelperProc {
                image: Some(nt),
                elevated: Some(true),
            },
        })
    }

    fn helper_running(&self, _: &str) -> SysResult<HelperPresence> {
        Ok(HelperPresence::None)
    }

    fn helper_lock(&self) -> SysResult<HelperLock> {
        Ok(HelperLock::Free)
    }
}

impl System for TwoProc<'_> {
    fn fs(&self) -> &dyn rerun_core::sys::Fs {
        self.world.fs()
    }
    fn registry(&self) -> &dyn Registry {
        self.world.registry()
    }
    fn registry_write(&self) -> &dyn RegistryWrite {
        #[expect(clippy::disallowed_methods, reason = "test: delegation to the world")]
        let r = self.world.registry_write();
        r
    }
    fn topology(&self) -> &dyn Topology {
        self.world.topology()
    }
    fn known_folders(&self) -> &dyn KnownFolders {
        self.world.known_folders()
    }
    fn gpu(&self) -> &dyn Gpu {
        self.world.gpu()
    }
    fn firewall(&self) -> &dyn Firewall {
        self.world.firewall()
    }
    fn elevation(&self) -> &dyn Elevation {
        self
    }
}

/// A world, a session and a language; with `two_proc`, helper starts run the real helper
/// in-process ([`Wire`]), else they go to the world's `FakeElevation` (scripted).
struct Rig {
    sys: FakeSystem,
    wire: Wire,
    two_proc: bool,
    session: Session,
    lang: Lang,
    nonce: u64,
}

impl Rig {
    fn new(sys: FakeSystem, two_proc: bool, lang: Lang) -> Self {
        Self {
            sys,
            wire: Wire::default(),
            two_proc,
            session: Session::default(),
            lang,
            nonce: 0,
        }
    }

    fn run(&mut self, job: Job) -> Vec<Event> {
        let http = FakeHttp::default();
        let install = install();
        let two = TwoProc {
            world: &self.sys,
            wire: &self.wire,
        };
        let sys: &dyn System = if self.two_proc { &two } else { &self.sys };
        let env = Env {
            sys,
            http: &http,
            install: &install,
        };
        let mut out = Vec::new();
        let _ = run_in(
            env,
            &job,
            self.lang,
            &mut self.session,
            &mut || None,
            &mut |e| out.push(e),
        );
        if let Some(Event::Dialog(d)) = out.iter().rev().find(|e| matches!(e, Event::Dialog(_))) {
            self.nonce = d.nonce;
        }
        out
    }

    fn page(&mut self) -> GameVm {
        let ev = self.run(Job::Game {
            app_id: 220,
            name: Some(escape::text("Invented H").into_owned()),
        });
        match ev.as_slice() {
            [Event::Game(g)] => g.clone(),
            other => panic!("{other:?}"),
        }
    }

    /// Plans `picks` (the page read first) and hands the preview over.
    fn preview_of(&mut self, picks: Vec<Pick>) -> PreviewVm {
        self.page();
        let ev = self.run(Job::Plan { app_id: 220, picks });
        let pv = match ev.as_slice() {
            [Event::Preview { vm, .. }] => (**vm).clone(),
            other => panic!("{other:?}"),
        };
        let ready = self.run(Job::PreviewShown {
            hash: pv.hash.clone(),
        });
        assert_eq!(
            ready,
            [Event::PreviewReady {
                hash: pv.hash.clone()
            }]
        );
        pv
    }

    /// The helper starts so far (the in-process helper's and the scripted fake's).
    fn starts(&self) -> usize {
        self.wire.runs.lock().unwrap().len() + self.sys.fake_elevation().calls().len()
    }

    /// The game folder and the firewall: what an undo must restore.
    fn snap(&self) -> (Snapshot, Vec<FwRule>) {
        let fr = ForbiddenRoots::resolve(&self.sys, Path::new(INSTALL)).unwrap();
        let g = GameDir::open_manual(&self.sys, &fr, Path::new(G)).unwrap();
        let s = snapshot(
            System::registry(&self.sys),
            &Scope {
                dirs: vec![SnapRoot::new(g.dir(), G)],
                keys: Vec::new(),
            },
        )
        .unwrap();
        (s, self.sys.fake_firewall().rules())
    }

    fn rerun_rules(&self) -> usize {
        self.sys
            .fake_firewall()
            .rules()
            .iter()
            .filter(|r| r.grouping == GROUP)
            .count()
    }
}

fn pick(issue: &str, variant: &str) -> Pick {
    Pick {
        issue: issue.to_owned(),
        variant: variant.to_owned(),
    }
}

fn both() -> Vec<Pick> {
    vec![pick("display", "ini"), pick("net", "block")]
}

fn result_of(ev: &[Event]) -> &ResultVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Result(r) => Some(r),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no result in {ev:?}"))
}

fn dialog_of(ev: &[Event]) -> &DialogVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Dialog(d) => Some(&**d),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no dialog in {ev:?}"))
}

fn wait_of(ev: &[Event]) -> Option<&UacVm> {
    ev.iter().find_map(|e| match e {
        Event::WaitingForUac(u) => Some(&**u),
        _ => None,
    })
}

/// The position of the first event of `kind` ([`super::kinds`]).
fn at(ev: &[Event], kind: &str) -> usize {
    super::kinds(ev)
        .iter()
        .position(|k| *k == kind)
        .unwrap_or_else(|| panic!("no {kind} in {ev:?}"))
}

fn open_cards(ev: &[Event]) -> Vec<TxnId> {
    ev.iter()
        .find_map(|e| match e {
            Event::Applied(a) => Some(a.cards.iter().map(|c| c.txn).collect()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no applied page in {ev:?}"))
}

fn has_detail(r: &ResultVm, text: &str) -> bool {
    r.notice.details.iter().any(|d| d.what.as_str() == text)
}

// ---------- AH1 ----------

#[test]
fn ah1_a_ready_helper_offers_the_fix_and_the_preview_names_the_prompt() {
    for lang in Lang::ALL {
        let mut rig = Rig::new(helper_world(true, CONSENT), false, lang);
        let g = rig.page();
        let block = g.fixes.iter().find(|f| f.key == "block").unwrap();
        assert_eq!(block.offer, Offer::Selectable);
        assert_eq!(
            block.note.as_deref(),
            Some(&*t(lang, Msg::FixHelperAsks)),
            "{lang:?}"
        );
        // Verified and affects this PC, but an administrator change is never preselected.
        assert!(!block.preselect);
        let sel = Selection::preselected(&g);
        assert!(sel.contains("ini") && !sel.contains("block"));

        let pv = rig.preview_of(both());
        assert!(pv.can_apply);
        assert_eq!(pv.admin, t(lang, Msg::PreviewAdminYes));
        assert_eq!(pv.admin_notes, [t(lang, Msg::AdminConsent).into_owned()]);
        assert!(pv.ops.iter().any(|o| o.action == t(lang, Msg::ActFirewall)));
        assert_eq!(rig.starts(), 0, "looking asks nobody");
    }
    // Credentials on the user's desktop; signed images only.
    let policy: Policy = &[
        ("EnableLUA", 1),
        ("ConsentPromptBehaviorAdmin", 3),
        ("PromptOnSecureDesktop", 0),
        ("ValidateAdminCodeSignatures", 1),
    ];
    let mut rig = Rig::new(helper_world(true, policy), false, Lang::En);
    let pv = rig.preview_of(vec![pick("net", "block")]);
    assert_eq!(
        pv.admin_notes,
        [
            t(Lang::En, Msg::AdminCredentials).into_owned(),
            t(Lang::En, Msg::AdminNotSecure).into_owned(),
            t(Lang::En, Msg::AdminSignedOnly).into_owned(),
        ]
    );
    // No dialog at all (ConsentPromptBehaviorAdmin 0): the click on Apply is the only boundary.
    let policy: Policy = &[("EnableLUA", 1), ("ConsentPromptBehaviorAdmin", 0)];
    let mut rig = Rig::new(helper_world(true, policy), false, Lang::De);
    let pv = rig.preview_of(vec![pick("net", "block")]);
    assert_eq!(pv.admin, t(Lang::De, Msg::PreviewAdminNoDialog));
    assert!(pv.can_apply);
    assert_eq!(rig.starts(), 0);
}

// ---------- AH2 ----------

#[test]
fn ah2_apply_runs_the_helper_once_and_undo_asks_once_more() {
    let mut rig = Rig::new(helper_world(true, CONSENT), true, Lang::En);
    let before = rig.snap();
    let pv = rig.preview_of(both());
    let ev = rig.run(Job::Apply {
        hash: pv.hash.clone(),
    });
    // The wait for Windows comes before the result, with what to do.
    let wait = wait_of(&ev).unwrap_or_else(|| panic!("{ev:?}"));
    assert_eq!(wait.title, "Waiting for Windows (UAC) ...");
    assert!(at(&ev, "uac") < at(&ev, "result"), "{ev:?}");
    let r = result_of(&ev);
    assert_eq!(r.tone, Tone::Done, "{r:?}");
    // One start, with exactly the request form of ADR 0023 §3 step 5 for this transaction.
    let runs = rig.wire.runs.lock().unwrap().clone();
    assert_eq!(runs.len(), 1);
    let txn = open_cards(&ev)[0];
    let args = &runs[0];
    assert_eq!(args.len(), 8, "{args:?}");
    assert_eq!(
        [&args[0], &args[2], &args[4], &args[6]],
        ["--volume", "--dir", "--request", "--sha256"]
    );
    assert_eq!(args[5], format!("{txn}-1.req"));
    assert_eq!(args[7].len(), 64);
    // The rule is there, and the card lists it with the INI edit.
    assert_eq!(rig.rerun_rules(), 1);
    let card = match ev.iter().find_map(|e| match e {
        Event::Applied(a) => Some(a),
        _ => None,
    }) {
        Some(a) => a.cards[0].clone(),
        None => panic!("{ev:?}"),
    };
    assert!(
        card.ops
            .iter()
            .any(|o| o.action == t(Lang::En, Msg::ActFirewall))
    );
    assert!(card.can_undo);

    // Undo: the dialog names the prompt and can be confirmed; one more start removes the rule.
    let ev = rig.run(Job::RevertPreview { txn });
    let d = dialog_of(&ev);
    assert!(d.can_confirm && d.blocked.is_none(), "{d:?}");
    assert!(
        d.notes
            .contains(&t(Lang::En, Msg::PreviewAdminYes).into_owned())
    );
    let nonce = rig.nonce;
    let ev = rig.run(Job::Revert { txn, nonce });
    assert!(at(&ev, "uac") < at(&ev, "result"), "{ev:?}");
    assert_eq!(result_of(&ev).tone, Tone::Done, "{ev:?}");
    assert_eq!(rig.wire.runs.lock().unwrap().len(), 2);
    assert!(open_cards(&ev).is_empty());
    assert!(rig.snap() == before, "game folder and firewall as before");
}

// ---------- AH3 ----------

#[test]
fn ah3_a_declined_prompt_on_apply_changes_nothing() {
    for lang in Lang::ALL {
        let mut rig = Rig::new(helper_world(true, CONSENT), false, lang);
        let before = rig.snap();
        rig.sys.fake_elevation().push_run(Ok(HelperRun::Declined));
        let pv = rig.preview_of(both());
        let ev = rig.run(Job::Apply { hash: pv.hash });
        assert!(wait_of(&ev).is_some(), "{ev:?}");
        let r = result_of(&ev);
        assert_eq!(r.tone, Tone::Calm);
        assert_eq!(r.notice.title, t(lang, Msg::ResDeclinedTitle));
        assert_eq!(r.notice.body, t(lang, Msg::ResDeclinedBody));
        // Exactly one prompt; the INI edit before it was rolled back and the transaction closed:
        // no card, nothing in the game folder or the firewall changed.
        assert_eq!(rig.starts(), 1);
        assert!(open_cards(&ev).is_empty(), "{ev:?}");
        assert!(rig.snap() == before);
        // The result names the transaction it closed.
        let st = rerun_core::exec::status(&AppDir::open(&rig.sys, Create::Never).unwrap().unwrap())
            .unwrap();
        let txn = st.txns.last().unwrap().id;
        assert!(has_detail(r, &txn.to_string()), "{r:?}");
        assert!(st.txns.last().unwrap().is_settled());
    }
}

// ---------- AH4 ----------

#[test]
fn ah4_an_untrusted_helper_result_stays_open_and_a_declined_undo_keeps_it() {
    let mut rig = Rig::new(helper_world(true, CONSENT), false, Lang::En);
    // A process ran, but its exit code is none of the helper's: the result is unknown.
    let nt = helper_image(&rig.sys).unwrap().nt_name;
    rig.sys.fake_elevation().push_run(Ok(HelperRun::Exited {
        code: 0,
        proc: HelperProc {
            image: Some(nt),
            elevated: Some(true),
        },
    }));
    let pv = rig.preview_of(both());
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let r = result_of(&ev);
    assert_eq!(r.tone, Tone::Attention);
    assert_eq!(r.notice.title, t(Lang::En, Msg::ResOpenTitle));
    assert_eq!(r.notice.body, t(Lang::En, Msg::ResHelperOpenBody));
    let cards = open_cards(&ev);
    assert_eq!(cards.len(), 1, "the open transaction has its card");
    assert!(has_detail(r, &cards[0].to_string()));
    assert_eq!(rig.starts(), 1, "never a second prompt in the same run");

    // The two-process world: a rule that is there, and an undo whose prompt is declined.
    let mut rig = Rig::new(helper_world(true, CONSENT), true, Lang::De);
    let pv = rig.preview_of(both());
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = open_cards(&ev)[0];
    let with_rule = rig.snap();
    rig.wire.script.lock().unwrap().push_back(Script::Decline);
    rig.run(Job::RevertPreview { txn });
    let nonce = rig.nonce;
    let ev = rig.run(Job::Revert { txn, nonce });
    assert!(wait_of(&ev).is_some());
    let r = result_of(&ev);
    assert_eq!(r.notice.title, t(Lang::De, Msg::ResUndoDeclinedTitle));
    assert_eq!(r.tone, Tone::Calm);
    // Nothing below the batch was undone (LIFO): the INI edit and the rule are as they were.
    assert_eq!(open_cards(&ev), [txn]);
    assert!(rig.snap() == with_rule);
    // Asked again, it goes through.
    rig.run(Job::RevertPreview { txn });
    let nonce = rig.nonce;
    let ev = rig.run(Job::Revert { txn, nonce });
    assert_eq!(result_of(&ev).tone, Tone::Done, "{ev:?}");
    assert_eq!(rig.rerun_rules(), 0);
    assert_eq!(rig.wire.runs.lock().unwrap().len(), 3);
}

// ---------- AH5 ----------

#[test]
fn ah5_without_a_safe_helper_or_elevation_windows_is_never_asked() {
    for lang in Lang::ALL {
        // Not installed.
        let mut rig = Rig::new(helper_world(false, CONSENT), false, lang);
        let g = rig.page();
        let block = g.fixes.iter().find(|f| f.key == "block").unwrap();
        assert_eq!(block.offer, Offer::NeedsHelper);
        assert_eq!(block.note.as_deref(), Some(&*t(lang, Msg::FixNeedsHelper)));
        let ev = rig.run(Job::Plan {
            app_id: 220,
            picks: vec![pick("net", "block")],
        });
        assert!(
            matches!(ev.as_slice(), [Event::PreviewRefused { .. }]),
            "{ev:?}"
        );
        // Windows denies standard users elevation.
        let policy: Policy = &[("EnableLUA", 1), ("ConsentPromptBehaviorUser", 0)];
        let mut rig = Rig::new(helper_world(true, policy), false, lang);
        rig.sys
            .fake_elevation()
            .set_token_kind(Ok(TokenKind::Standard));
        let g = rig.page();
        let block = g.fixes.iter().find(|f| f.key == "block").unwrap();
        assert_eq!(block.offer, Offer::NeedsHelper);
        assert_eq!(block.note.as_deref(), Some(&*t(lang, Msg::FixNoElevation)));
        assert_eq!(rig.starts(), 0);
    }

    // Applied while the helper was there; then its file is no longer admin-only (replaced by
    // someone): the undo says why it cannot go on, keeps no token, and asks nobody.
    let mut rig = Rig::new(helper_world(true, CONSENT), true, Lang::En);
    let pv = rig.preview_of(both());
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = open_cards(&ev)[0];
    let mine = FakeSd {
        owner: Some(FAKE_USER_SID.to_owned()),
        dacl: Some(vec![FakeSd::allow(FAKE_USER_SID, 0x001F_01FF)]),
    };
    rig.sys.fake_fs().set_sd(Path::new(HEXE), mine).unwrap();
    let state = rig.snap();
    let ev = rig.run(Job::RevertPreview { txn });
    let d = dialog_of(&ev);
    assert!(!d.can_confirm);
    assert_eq!(d.blocked.as_deref(), Some(&*t(Lang::En, Msg::UndoPrompt)));
    assert!(rig.session.pending.revert.is_none(), "no token kept");
    let nonce = rig.nonce;
    let ev = rig.run(Job::Revert { txn, nonce });
    // Without a token the confirm shows the preview again and writes nothing.
    assert!(matches!(ev.as_slice(), [Event::Dialog(_)]), "{ev:?}");
    assert!(rig.snap() == state);
    assert_eq!(rig.wire.runs.lock().unwrap().len(), 1, "only the apply's");
    // The page locks the fix now too.
    let g = rig.page();
    let block = g.fixes.iter().find(|f| f.key == "block").unwrap();
    assert_eq!(block.offer, Offer::NeedsHelper);
}

// ---------- AH6 ----------

#[test]
fn ah6_a_second_click_never_starts_the_helper_twice() {
    let mut rig = Rig::new(helper_world(true, CONSENT), true, Lang::En);
    let pv = rig.preview_of(both());
    let ev = rig.run(Job::Apply {
        hash: pv.hash.clone(),
    });
    let txn = open_cards(&ev)[0];
    // The same click again (a key repeat queued behind the first): no shown plan any more.
    let ev = rig.run(Job::Apply { hash: pv.hash });
    assert!(wait_of(&ev).is_none());
    assert_eq!(
        result_of(&ev).notice.title,
        t(Lang::En, Msg::RefNoPreviewTitle)
    );
    assert_eq!(rig.wire.runs.lock().unwrap().len(), 1);
    // An undo confirm with the nonce of an older dialog: the current preview again, no start.
    rig.run(Job::RevertPreview { txn });
    let old = rig.nonce;
    rig.run(Job::RevertPreview { txn });
    let ev = rig.run(Job::Revert { txn, nonce: old });
    assert!(wait_of(&ev).is_none());
    assert!(matches!(ev.as_slice(), [Event::Dialog(_)]), "{ev:?}");
    assert_eq!(rig.wire.runs.lock().unwrap().len(), 1);
    // The confirm of the dialog shown: one start.
    let nonce = rig.nonce;
    let ev = rig.run(Job::Revert { txn, nonce });
    assert_eq!(result_of(&ev).tone, Tone::Done);
    assert_eq!(rig.wire.runs.lock().unwrap().len(), 2);
    // And that confirm once more: nothing left to undo, no start.
    let ev = rig.run(Job::Revert { txn, nonce });
    assert!(wait_of(&ev).is_none(), "{ev:?}");
    assert_eq!(rig.wire.runs.lock().unwrap().len(), 2);
}

// ---------- AH7 ----------

/// The world shared between the worker thread and the test.
struct Shared(std::sync::Arc<FakeSystem>);

impl System for Shared {
    fn fs(&self) -> &dyn rerun_core::sys::Fs {
        self.0.fs()
    }
    fn registry(&self) -> &dyn Registry {
        self.0.registry()
    }
    fn registry_write(&self) -> &dyn RegistryWrite {
        #[expect(clippy::disallowed_methods, reason = "test: delegation to the world")]
        let r = self.0.registry_write();
        r
    }
    fn topology(&self) -> &dyn Topology {
        self.0.topology()
    }
    fn known_folders(&self) -> &dyn KnownFolders {
        self.0.known_folders()
    }
    fn gpu(&self) -> &dyn Gpu {
        self.0.gpu()
    }
    fn firewall(&self) -> &dyn Firewall {
        self.0.firewall()
    }
    fn elevation(&self) -> &dyn Elevation {
        self.0.elevation()
    }
}

/// Waits for the first event `pick` accepts.
fn wait_until<T>(worker: &Worker, mut pick: impl FnMut(&Event) -> Option<T>) -> T {
    for _ in 0..2000 {
        while let Some(e) = worker.poll() {
            if let Some(x) = pick(&e) {
                return x;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("the event never came");
}

/// Runs one apply of `block` whose UAC prompt is declined, through the worker thread, and
/// returns what the fake recorded for the run. `owner` is handed over after the world was built
/// (`Some`) or never (`None`).
fn apply_through_the_worker(owner: Option<PromptOwner>) -> Vec<rerun_core::sys::fake::RunCall> {
    let (tx, rx) = std::sync::mpsc::channel();
    let make = move |slot: PromptOwnerSlot| {
        let world = helper_world(true, CONSENT).with_prompt_owner_slot(slot);
        world.fake_elevation().push_run(Ok(HelperRun::Declined));
        let world = std::sync::Arc::new(world);
        tx.send(world.clone()).unwrap();
        Ok(World {
            sys: Box::new(Shared(world)),
            http: Box::new(FakeHttp::default()),
            install: install(),
        })
    };
    let woken = std::sync::Arc::new(AtomicUsize::new(0));
    let worker = Worker::start(Lang::En, make, Box::new(Count(woken))).unwrap();
    // The world does not wait for the window: it is built and answers before any owner.
    let world = rx.recv().unwrap();
    worker.send(Job::Game {
        app_id: 220,
        name: None,
    });
    wait_until(&worker, |e| matches!(e, Event::Game(_)).then_some(()));
    // The window's handle arrives late (after the world was built): it is not lost.
    if let Some(o) = owner {
        assert!(worker.set_owner(Some(o)));
        let other = PromptOwner::from_raw(0x0004_0001).unwrap();
        assert!(!worker.set_owner(Some(other)), "the first owner stays");
    }
    assert!(!worker.set_owner(None));
    worker.send(Job::Plan {
        app_id: 220,
        picks: vec![pick("net", "block")],
    });
    let hash = wait_until(&worker, |e| match e {
        Event::Preview { vm, .. } => Some(vm.hash.clone()),
        _ => None,
    });
    worker.send(Job::PreviewShown { hash: hash.clone() });
    wait_until(&worker, |e| {
        matches!(e, Event::PreviewReady { .. }).then_some(())
    });
    worker.send(Job::Apply { hash });
    assert!(worker.busy_writing(), "closing is refused while it runs");
    let title = wait_until(&worker, |e| match e {
        Event::Result(r) => Some(r.notice.title.clone()),
        _ => None,
    });
    assert_eq!(title, t(Lang::En, Msg::ResDeclinedTitle));
    world.fake_elevation().calls()
}

#[test]
fn ah7_the_window_s_handle_reaches_the_helper_start() {
    // Handed over after the world was built: the run has it.
    let owner = PromptOwner::from_raw(0x0003_0e52).unwrap();
    let calls = apply_through_the_worker(Some(owner));
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].owner,
        Some(owner),
        "the dialog belongs to the window"
    );
    // Never handed over (the window had no native handle): the run goes on without one, as
    // the CLI's would (its console window, none in a GUI process).
    let calls = apply_through_the_worker(None);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].owner, None);
}
