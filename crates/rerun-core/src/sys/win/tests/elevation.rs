//! The helper start of `sys::win::elevation` on real Windows (ADR 0023 §7, A4 S2, N3) without
//! any prompt, the [SB] runas probe, and the [DEV] dialog test with the installed helper.
//!
//! Normal tests (every Windows run, nothing changed on the machine; only `System32\cmd.exe` and
//! `System32\hostname.exe` start and exit at once, without a window):
//! - `SEE_MASK_CLASSKEY` takes the verb's command from the given class key: `hostname.exe`
//!   started with the `HKLM` `scrfile` key gets that key's `"%1" /S` (exit 1), with the `HKLM`
//!   `exefile` key `"%1" %*` (exit 0). An app hive's key cannot serve as `hkeyClass` (the shell
//!   reports `SE_ERR_NOASSOC`, 31; measured 2026-11-09), so the positive control uses two
//!   machine classes.
//! - On the handle `ShellExecuteExW` returns, `QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)`
//!   and `TokenElevation` are readable from this process, before and after the process has
//!   exited, and the native image equals the NT name `sd_facts` reads for the file (the
//!   comparison of `elevate::judge`). The Win32 form fails after exit (31).
//! - The token kind, the prompt state of this machine and `helper_image`, read only.
//! - An owner value that names no window does not stop a start (P5-5c).
//!
//! `#[ignore]`: the [SB] probe (`sb_runas_redirection_and_the_class_key`, writes the real
//! `HKCU`, CI runner only behind `sandbox_guard`) and the [DEV] dialog test
//! (`dev_uac_helper_dialog`, behind `RERUN_DEV_UAC`, run by `scripts/dev-helper-uac.ps1`).

use std::ffi::OsString;
use std::os::windows::io::AsHandle;
use std::path::{Path, PathBuf};

use super::super::elevation::{
    ERROR_CANCELLED, WinElevation, exefile_class, facts, image_of, start, wait,
};
use super::super::reg::{self, OwnedKey, ReadAccess, Root, View};
use super::super::testfx::{AppHive, is_elevated, note, sandbox_guard};
use super::super::{WinFs, WinSystem, shell};
use crate::elevate::exit::{HelperExit, Reason};
use crate::elevate::judge::{Judged, judge};
use crate::elevate::prompt;
use crate::fold::fold;
use crate::path::RelPath;
use crate::policy::root::{RootError, helper_image};
use crate::sys::fs::Fs;
use crate::sys::{Elevation, HelperPresence, HelperRun, System, TokenKind};

fn system32() -> PathBuf {
    let windir: OsString = shell::system_windows_directory().unwrap();
    PathBuf::from(windir).join("System32")
}

/// The NT name `sd_facts` reads for `System32\<name>`.
fn nt_name_of(sys32: &Path, name: &str) -> String {
    let fs = WinFs::new();
    #[expect(
        clippy::disallowed_methods,
        reason = "test: System32 by absolute path, read only"
    )]
    let dir = fs.open_dir(sys32).unwrap();
    let f = dir.sd_facts(Some(&RelPath::parse(name).unwrap())).unwrap();
    f.nt_name.unwrap()
}

fn hklm_class(name: &str) -> OwnedKey {
    let path = format!(r"SOFTWARE\Classes\{name}");
    reg::open(
        &Root::LocalMachine,
        &path,
        ReadAccess::Enumerate,
        View::Native,
    )
    .unwrap()
}

#[test]
fn the_class_key_decides_the_verb_command() {
    let sys32 = system32();
    let hostname = sys32.join("hostname.exe");
    let nt = nt_name_of(&sys32, "hostname.exe");
    for (class, expected) in [("scrfile", 1), ("exefile", 0)] {
        let p = start("open", &hostname, "", &sys32, &hklm_class(class), None).unwrap();
        assert_eq!(wait(p.as_handle()), Ok(expected), "{class}");
        assert_eq!(
            fold(&image_of(p.as_handle()).unwrap()),
            fold(&nt),
            "{class}"
        );
    }
    // The HKLM exefile key has no verb of another class, and nothing falls back to HKCR.
    let r = start(
        "rerunprobe",
        &hostname,
        "",
        &sys32,
        &exefile_class().unwrap(),
        None,
    );
    note(&format!(
        "S2: an unknown verb with the HKLM exefile key: {:?}",
        r.as_ref().map(|_| "started").map_err(|c| *c)
    ));
    assert!(
        r.is_err(),
        "an unknown verb of the HKLM key started something"
    );
}

/// ADR 0023 amendment P5-5c: the owner is a window handle value Windows checks, never memory.
/// A value that names no window (the app's window closed, or a stale value) does not stop the
/// start: the process runs and exits as without an owner. No window and no prompt are involved
/// (`open`, `hostname.exe`).
#[test]
fn an_owner_that_is_no_window_still_starts() {
    use crate::sys::PromptOwner;
    let sys32 = system32();
    let hostname = sys32.join("hostname.exe");
    // A value no window of this test owns (whether it names some other window or none, the
    // start must go through).
    let owner = PromptOwner::from_raw(0x7fff_0001).unwrap();
    let p = start(
        "open",
        &hostname,
        "",
        &sys32,
        &exefile_class().unwrap(),
        Some(owner),
    )
    .unwrap();
    assert_eq!(wait(p.as_handle()), Ok(0));
}

#[test]
fn image_and_token_are_readable_on_the_handle_also_after_exit() {
    let sys32 = system32();
    let cmd = sys32.join("cmd.exe");
    let nt = nt_name_of(&sys32, "cmd.exe");
    let p = start(
        "open",
        &cmd,
        "/c exit 5",
        &sys32,
        &exefile_class().unwrap(),
        None,
    )
    .unwrap();
    let before = facts(p.as_handle());
    assert_eq!(wait(p.as_handle()), Ok(5));
    let after = facts(p.as_handle());
    for f in [&before, &after] {
        let image = f.image.as_deref().unwrap();
        assert_eq!(fold(image), fold(&nt), "{image}");
        assert_eq!(f.elevated, Some(is_elevated()));
    }
}

#[test]
fn token_kind_matches_this_process() {
    let kind = WinElevation::default().token_kind().unwrap();
    if is_elevated() {
        assert_eq!(kind, TokenKind::Elevated);
    } else {
        assert_ne!(kind, TokenKind::Elevated);
    }
    note(&format!("token kind: {kind:?}"));
}

#[test]
fn the_prompt_state_of_this_machine_is_read_only() {
    let sys = WinSystem::new().unwrap();
    let f = prompt::facts(&sys);
    // EnableLUA is present on every Windows 11 installation.
    assert!(f.enable_lua.is_some(), "{f:?}");
    note(&format!("prompt facts: {f:?} -> {:?}", prompt::decide(&f)));
}

/// The pre-check on this machine, read only: either the helper is installed admin-only, or it
/// is "not installed" (which means `Program Files` itself passed the admin-only rule).
#[test]
fn helper_image_reads_program_files() {
    let sys = WinSystem::new().unwrap();
    match helper_image(&sys) {
        Ok(image) => note(&format!(
            "helper installed: {} ({})",
            image.path, image.nt_name
        )),
        Err(RootError::HelperUnsafe { path, reason }) if reason == "not installed" => {
            note(&format!(
                "helper not installed ({path}); Program Files is admin-only"
            ));
        }
        Err(e) => panic!("{e}"),
    }
}

// ---------- [SB] the HKCU runas redirection (A4 S2) ----------

/// [SB] (CI runner only, writes the real `HKCU`): with `HKCU\Software\Classes\exefile\shell\
/// runas\command` (default and `IsolatedCommand`) pointing to `cmd.exe /c exit 77`, a `runas`
/// start of `hostname.exe` through the merged `HKCR\exefile` key is measured (redirected or
/// not), and through the `HKLM` key must start `hostname.exe` itself. The runner's
/// administrator is elevated and `ConsentPromptBehaviorAdmin` is 0, so no dialog appears.
/// `scripts/ci-sandbox.ps1` runs it last and deletes the `runas` key afterwards, also after a
/// failure.
#[test]
#[ignore = "[SB] writes the real HKCU; CI runner only (scripts/ci-sandbox.ps1)"]
fn sb_runas_redirection_and_the_class_key() {
    sandbox_guard();
    let sys32 = system32();
    let cmd = sys32.join("cmd.exe");
    let hostname = sys32.join("hostname.exe");
    let host_nt = nt_name_of(&sys32, "hostname.exe");
    let cmd_nt = nt_name_of(&sys32, "cmd.exe");
    let command = format!("\"{}\" /c exit 77", cmd.display());
    let hkcu = AppHive::real_user().unwrap();
    drop(
        hkcu.class_key(r"Software\Classes\exefile", "runas", &command, true)
            .unwrap(),
    );
    let run = |class: &OwnedKey| {
        let p = start("runas", &hostname, "", &sys32, class, None).unwrap();
        let f = facts(p.as_handle());
        (f, wait(p.as_handle()))
    };
    let (merged, merged_code) = run(&AppHive::classes_root("exefile").unwrap());
    let redirected = merged
        .image
        .as_deref()
        .is_some_and(|i| fold(i) == fold(&cmd_nt));
    println!(
        "MEASURED S2 runas via HKCR with the HKCU redirection: image {:?}, elevated {:?}, \
         code {merged_code:?}, redirected {redirected}",
        merged.image, merged.elevated
    );
    let (hklm, hklm_code) = run(&exefile_class().unwrap());
    println!(
        "MEASURED S2 runas via the HKLM exefile class key: image {:?}, elevated {:?}, code \
         {hklm_code:?}",
        hklm.image, hklm.elevated
    );
    let image = hklm.image.as_deref().unwrap();
    assert_eq!(
        fold(image),
        fold(&host_nt),
        "the HKLM class key was redirected"
    );
    assert_eq!(hklm_code, Ok(0));
}

// ---------- [DEV] the real UAC dialog (ADR 0023 §14) ----------

/// [DEV] (`scripts/dev-helper-uac.ps1`): starts the installed scaffold helper through the real
/// `WinElevation::run_helper`. `RERUN_DEV_UAC=accept`: the user allows the prompt; the run must
/// be `Exited` with the image equal to the pre-checked one, the token elevated (both read by
/// this non-elevated process on `hProcess`: A4 S2) and `judge` = `Refused(Usage)`.
/// `RERUN_DEV_UAC=decline`: the user declines; the run must be `Declined` (1223).
#[test]
#[ignore = "[DEV] shows a real UAC prompt; run by scripts/dev-helper-uac.ps1"]
fn dev_uac_helper_dialog() {
    #[expect(
        clippy::disallowed_methods,
        reason = "[DEV] test: the hand-test script names the expected answer"
    )]
    let mode = std::env::var("RERUN_DEV_UAC").unwrap_or_default();
    assert!(
        mode == "accept" || mode == "decline",
        "set RERUN_DEV_UAC=accept or decline (scripts/dev-helper-uac.ps1)"
    );
    assert!(!is_elevated(), "run from a non-elevated process");
    let sys = WinSystem::new().unwrap();
    let image = helper_image(&sys).unwrap_or_else(|e| panic!("pre-check: {e}"));
    #[expect(
        clippy::disallowed_methods,
        reason = "[DEV] test: the real helper start"
    )]
    let run = sys.elevation().run_helper(&image.path, &[]).unwrap();
    println!("RERUN_DEV_UAC_RUN: {run:?}");
    if mode == "decline" {
        assert_eq!(
            run,
            HelperRun::Declined,
            "expected a declined prompt ({ERROR_CANCELLED})"
        );
        println!("RERUN_DEV_UAC_RESULT: PASS decline -> Declined ({ERROR_CANCELLED})");
        return;
    }
    let HelperRun::Exited { code, proc } = &run else {
        panic!("expected the helper to run (was the prompt declined?)");
    };
    println!(
        "RERUN_DEV_UAC_S2: image {:?} (expected {}), elevated {:?}, code {code:#010x}",
        proc.image, image.nt_name, proc.elevated
    );
    assert_eq!(
        proc.elevated,
        Some(true),
        "the token's elevation was not readable, or not elevated"
    );
    assert!(
        proc.image
            .as_deref()
            .is_some_and(|i| fold(i) == fold(&image.nt_name)),
        "the image differs from the pre-checked one"
    );
    let usage = HelperExit::refused(Reason::Usage);
    assert_eq!(judge(&run, &image, 0), Judged::Exit(usage));
    println!("RERUN_DEV_UAC_RESULT: PASS accept -> Refused(Usage) {code:#010x}, S2 checks hold");
}

// ---------- the helper's process facts (ADR 0023 §3 step 4, A4 S8) ----------

/// The own image is this test binary's NT name; the process check finds this very process by
/// it (the file name pre-filter and the image comparison), and nothing for an image no process
/// runs. Read only.
#[test]
fn own_image_and_the_process_check() {
    use super::super::process;
    let own = process::own_image().unwrap();
    assert!(own.starts_with(r"\Device\"), "{own}");
    assert_eq!(process::running(&own), Ok(HelperPresence::Running));
    assert_eq!(
        process::running(&own.to_uppercase()),
        Ok(HelperPresence::Running)
    );
    let elsewhere = format!(
        r"\Device\HarddiskVolume999\nowhere\{}",
        own.rsplit('\\').next().unwrap()
    );
    assert_eq!(process::running(&elsewhere), Ok(HelperPresence::None));
    assert_eq!(
        process::running(r"\Device\HarddiskVolume999\nowhere\rerun-helper-none.exe"),
        Ok(HelperPresence::None)
    );
    assert_eq!(
        WinElevation::default().helper_running(&own).unwrap(),
        HelperPresence::Running,
        "through the Elevation trait"
    );
}

/// The instance mutex (under a test name, so a helper that happens to run is not disturbed):
/// a second one is `ERROR_ALREADY_EXISTS` while the first is held, free again after the drop.
#[test]
fn the_instance_mutex_admits_one_holder() {
    use super::super::process;
    let name = format!(r"Local\Rerun.Test.{}", std::process::id());
    let first = process::named_mutex(&name).unwrap();
    let second = process::named_mutex(&name).map(|_| ()).unwrap_err();
    assert_eq!(second.code, 183);
    // Created by this (non-elevated or elevated) process: its owner is readable on the handle.
    assert!(
        second
            .owner
            .as_deref()
            .is_some_and(|o| o.starts_with("S-1-")),
        "{second:?}"
    );
    // The CLI's view of the same lock: held, owner readable (created by this very user).
    assert!(matches!(
        process::lock_state(&name),
        Ok(crate::sys::HelperLock::Held { owner: Some(_) })
    ));
    drop(first);
    assert_eq!(process::lock_state(&name), Ok(crate::sys::HelperLock::Free));
    assert!(process::named_mutex(&name).is_ok());
}

/// The helper's own system (ADR 0023 §11) reads what its chain needs, read only: every known
/// folder (`ProgramData` and `UserProfiles` from the machine's `ProfileList` without a user
/// hive), the forbidden list, the helper pre-check, the firewall's rules (P4-5b; read only here,
/// the write side is the [SB] contract's); it has no GPU, no topology and no registry.
#[test]
fn the_helper_system_has_what_the_chain_needs_and_nothing_else() {
    use super::super::WinHelperSystem;
    use crate::policy::root::ForbiddenRoots;
    use crate::sys::registry::{Hive, RegKey, RegView};
    use crate::sys::{KnownFolder, SysErrorKind};
    let h = WinHelperSystem::new();
    let full = WinSystem::new().unwrap();
    for k in KnownFolder::ALL {
        assert_eq!(
            h.known_folders().get(k).unwrap(),
            full.known_folders().get(k).unwrap(),
            "{k}"
        );
    }
    let pf = h.known_folders().get(KnownFolder::ProgramFiles).unwrap();
    // The helper passes its own folder; it may not be installed here, so its parent stands in.
    ForbiddenRoots::resolve(&h, &pf).unwrap();
    assert_eq!(
        helper_image(&h).map(|i| i.nt_name),
        helper_image(&full).map(|i| i.nt_name)
    );
    let unsupported = |k| assert_eq!(k, SysErrorKind::Unsupported);
    unsupported(h.gpu().adapters().unwrap_err().kind);
    unsupported(h.topology().read().unwrap_err().kind);
    // Readable (two enumerations may see different totals: an installer can add a rule).
    assert!(h.firewall().select(&|_, _| false).unwrap().total > 0);
    let key = RegKey::new(Hive::LocalMachine, RegView::Native, "SOFTWARE");
    unsupported(h.registry().key_exists(&key).unwrap_err().kind);
    unsupported(h.elevation().token_kind().unwrap_err().kind);
    // The machine-only registry under the known folders never opens a user hive.
    let machine = super::super::registry::WinRegistry::machine_only();
    let user = RegKey::new(Hive::CurrentUser, RegView::Native, "Software");
    unsupported(
        crate::sys::Registry::key_exists(&machine, &user)
            .unwrap_err()
            .kind,
    );
    assert!(crate::sys::Registry::key_exists(&machine, &key).unwrap());
}

// ---------- [DEV] the validation chain with the test-key helper (ADR 0023 §14, A4 S3) ----------

/// [DEV] (`scripts/dev-helper-chain.ps1`, `RERUN_DEV_CHAIN=accept`): the installed test-key
/// helper (a debug build with the feature `test-key`) is started through the real
/// `WinElevation` for a real request: the `elevate` and `index` folders and the game folder are
/// fresh folders of a test root below `target\` (the helper opens them by `{volume GUID, file
/// ID}`, so where they lie does not matter), the index is signed with the published test key and
/// names no Topo. Expected: the helper passes §3 (own image in `Program Files\Rerun`, instance
/// lock, arguments), reads the request by identity with its hash and build ID, verifies the
/// index under its trusted keys (the test key) and refuses the unknown Topo: `Refused(Topo)`.
/// A release helper (empty key slots) would give `Refused(Index)`. Nothing is changed; the test
/// root is removed when the test ends.
#[test]
#[ignore = "[DEV] shows a real UAC prompt; run by scripts/dev-helper-chain.ps1"]
fn dev_helper_chain_with_the_test_key() {
    use sha2::{Digest, Sha256};

    use super::super::testfx::TestRoot;
    use crate::catalog::key::test_key;
    use crate::elevate::client;
    use crate::elevate::request::{
        AddOp, Body, DirRef, Request, RequestName, RequestRef, RootRef, encode,
    };
    use crate::path::RootPath;
    use crate::plan::{Pick, PlanSource};
    use crate::policy::root::RootId;
    use crate::sys::contract::FsFixture;

    #[expect(
        clippy::disallowed_methods,
        reason = "[DEV] test: the hand-test script names the expected answer"
    )]
    let mode = std::env::var("RERUN_DEV_CHAIN").unwrap_or_default();
    assert_eq!(
        mode, "accept",
        "set RERUN_DEV_CHAIN=accept (scripts/dev-helper-chain.ps1)"
    );
    assert!(!is_elevated(), "run from a non-elevated process");
    let sys = WinSystem::new().unwrap();
    let image = helper_image(&sys).unwrap_or_else(|e| panic!("pre-check: {e}"));
    let root = TestRoot::new("dev-chain").unwrap();
    let elevate = root.work("elevate");
    let index = root.work("index");
    let game = root.work("game");
    let fs = WinFs::new();
    let info = |p: &Path| {
        #[expect(clippy::disallowed_methods, reason = "[DEV] test: its own test root")]
        let d = fs.open_dir(p).unwrap();
        d.info().unwrap()
    };
    let dir_ref = |p: &Path| {
        let i = info(p);
        DirRef {
            volume: i
                .volume_guid
                .expect("the test root's volume has a GUID path"),
            file_id: i.file_id,
        }
    };
    let bytes = br#"{"format":1,"seq":1,"issued":"2026-11-09T12:00:00Z","topos":[],"packages":[]}"#;
    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let hex = crate::wire::hex32::to_string(&sha);
    root.fx()
        .file(&index.join(format!("{hex}.json")), bytes)
        .unwrap();
    root.fx()
        .file(&index.join(format!("{hex}.sig")), &test_key::sign(bytes))
        .unwrap();
    let gi = info(&game);
    let txn = "00000001-00000000000000de".parse().unwrap();
    let req = Request {
        build: crate::BUILD_ID.to_owned(),
        txn,
        body: Body::Add {
            source: PlanSource {
                index: sha,
                topo: "dev-unknown-topo".to_owned(),
                rev: 1,
                picks: vec![Pick {
                    issue: "net".to_owned(),
                    variant: "block".to_owned(),
                }],
            },
            index_dir: dir_ref(&index),
            root: RootRef {
                volume: gi.volume_guid.unwrap(),
                id: RootId::of(&gi),
                path: RootPath::from_final_path(&gi.final_path).unwrap(),
            },
            ops: vec![AddOp {
                op: 1,
                program: RelPath::parse("game.exe").unwrap(),
                direction: crate::policy::firewall::Direction::Out,
            }],
        },
    };
    let file = encode(&req).unwrap();
    let name = RequestName::new(txn, 1).unwrap();
    root.fx().file(&elevate.join(name.as_str()), &file).unwrap();
    let at = RequestRef {
        dir: dir_ref(&elevate),
        name,
    };
    let file_sha: [u8; 32] = Sha256::digest(&file).into();
    let judged = client::start(&WinElevation::default(), &image, &at, &file_sha, 1).unwrap();
    println!("RERUN_DEV_CHAIN_RUN: {judged:?}");
    let topo = Judged::Exit(HelperExit::refused(Reason::Topo));
    if judged == Judged::Exit(HelperExit::refused(Reason::Index)) {
        panic!(
            "Refused(Index): the installed helper does not trust the test key (a release build?)"
        );
    }
    assert_eq!(judged, topo);
    println!(
        "RERUN_DEV_CHAIN_RESULT: PASS accept -> Refused(Topo) 0x52170000, the chain up to step 3 holds"
    );
}
