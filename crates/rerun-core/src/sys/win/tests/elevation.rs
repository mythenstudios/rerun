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
use crate::sys::{Elevation, HelperRun, System, TokenKind};

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
        let p = start("open", &hostname, "", &sys32, &hklm_class(class)).unwrap();
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

#[test]
fn image_and_token_are_readable_on_the_handle_also_after_exit() {
    let sys32 = system32();
    let cmd = sys32.join("cmd.exe");
    let nt = nt_name_of(&sys32, "cmd.exe");
    let p = start("open", &cmd, "/c exit 5", &sys32, &exefile_class().unwrap()).unwrap();
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
    let kind = WinElevation.token_kind().unwrap();
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
/// administrator is elevated and `ConsentPromptBehaviorAdmin` is 0, so no dialog appears. The
/// key stays (the runner is disposable; this runs last in `scripts/ci-sandbox.ps1`).
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
        let p = start("runas", &hostname, "", &sys32, class).unwrap();
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
