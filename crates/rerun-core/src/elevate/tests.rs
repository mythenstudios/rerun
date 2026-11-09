//! Tests of the helper's exit code (ADR 0023 §7, A4 N4) and the scaffold `serve` (§3) against
//! the fake token.

use std::ffi::OsString;

use super::exit::{ExitClass, HelperExit, MAGIC, OpResult, Reason};
use super::{MAX_BATCH_OPS, serve};
use crate::sys::fake::{FakeHelperToken, TokenCall};

const CLASSES: [ExitClass; 4] = [
    ExitClass::Done,
    ExitClass::Refused,
    ExitClass::RolledBack,
    ExitClass::LeftOpen,
];
const OPS: [OpResult; 4] = [
    OpResult::NotRun,
    OpResult::Before,
    OpResult::After,
    OpResult::Foreign,
];
const REASONS: [Reason; 14] = [
    Reason::Usage,
    Reason::NotElevated,
    Reason::ImageFolder,
    Reason::Build,
    Reason::Request,
    Reason::Index,
    Reason::Topo,
    Reason::Root,
    Reason::Program,
    Reason::AntiCheat,
    Reason::Ops,
    Reason::DuplicateName,
    Reason::Firewall,
    Reason::Internal,
];

/// The codes are an interface between two binaries of one build and the hand-test script
/// (`scripts/dev-helper-common.ps1`): pinned.
#[test]
fn codes_are_pinned() {
    assert_eq!(HelperExit::refused(Reason::Usage).to_code(), 0x5211_0000);
    assert_eq!(
        HelperExit::refused(Reason::NotElevated).to_code(),
        0x5212_0000
    );
    assert_eq!(HelperExit::refused(Reason::Internal).to_code(), 0x521E_0000);
    let mut ops = [OpResult::NotRun; MAX_BATCH_OPS];
    ops[0] = OpResult::After;
    ops[1] = OpResult::Before;
    ops[7] = OpResult::Foreign;
    let left = HelperExit {
        class: ExitClass::LeftOpen,
        reason: Some(Reason::Firewall),
        ops,
    };
    assert_eq!(left.to_code(), 0x523D_C006);
}

#[test]
fn every_valid_exit_round_trips() {
    let mut n = 0;
    for class in CLASSES {
        let reasons: Vec<Option<Reason>> = if class == ExitClass::Done {
            vec![None]
        } else {
            REASONS.iter().copied().map(Some).collect()
        };
        for reason in reasons {
            for batch in 1..=MAX_BATCH_OPS {
                for pattern in 0..4usize.pow(u32::try_from(batch).unwrap()) {
                    let mut ops = [OpResult::NotRun; MAX_BATCH_OPS];
                    for (i, op) in ops.iter_mut().take(batch).enumerate() {
                        *op = OPS[(pattern >> (2 * i)) & 3];
                    }
                    let used = &ops[..batch];
                    let valid = match class {
                        ExitClass::Done => used.iter().all(|o| *o != OpResult::NotRun),
                        ExitClass::Refused => used.iter().all(|o| *o == OpResult::NotRun),
                        _ => true,
                    };
                    let exit = HelperExit { class, reason, ops };
                    let code = exit.to_code();
                    assert_eq!(code >> 24, MAGIC);
                    // A positive i32 for std::process::exit.
                    assert!(i32::try_from(code).is_ok(), "{code:#010x}");
                    let back = HelperExit::from_code(code, batch);
                    if valid {
                        assert_eq!(back, Some(exit), "{code:#010x}");
                        n += 1;
                    } else {
                        assert_eq!(back, None, "{code:#010x}");
                    }
                }
            }
        }
    }
    assert!(n > 100_000, "{n}");
}

#[test]
fn from_code_is_strict() {
    let usage = 0x5211_0000;
    assert_eq!(
        HelperExit::from_code(usage, 1),
        Some(HelperExit::refused(Reason::Usage))
    );
    for bad in [
        // Not the magic: a crash's NTSTATUS, STILL_ACTIVE, 0, a plain exit code.
        0xC000_0005,
        0xC000_0409,
        259,
        0,
        1,
        0x5311_0000,
        // Class 4 to 15.
        0x5241_0000,
        0x52F1_0000,
        // Reason 15; no reason with Refused; a reason with Done.
        0x521F_0000,
        0x5210_0000,
        0x5201_0002,
        // Done with an op not reached; Refused with an op reported.
        0x5200_0000,
        0x5211_0001,
    ] {
        assert_eq!(HelperExit::from_code(bad, 1), None, "{bad:#010x}");
    }
    // A slot beyond the batch must be NotRun.
    let two = 0x5200_000A; // Done, ops 0 and 1 After
    assert!(HelperExit::from_code(two, 2).is_some());
    assert_eq!(HelperExit::from_code(two, 1), None);
    // Done needs a batch of at least one op; a refusal of an empty batch decodes.
    assert_eq!(HelperExit::from_code(0x5200_0000, 0), None);
    assert!(HelperExit::from_code(usage, 0).is_some());
    // A batch larger than the code has slots decodes nothing.
    assert_eq!(HelperExit::from_code(usage, MAX_BATCH_OPS + 1), None);
    assert!(HelperExit::from_code(usage, MAX_BATCH_OPS).is_some());
}

fn args(a: &[&str]) -> Vec<OsString> {
    a.iter().map(OsString::from).collect()
}

#[test]
fn serve_drops_privileges_first_then_requires_elevation() {
    let t = FakeHelperToken::new(false);
    assert_eq!(
        serve(&t, Vec::new),
        HelperExit::refused(Reason::NotElevated)
    );
    assert_eq!(
        t.calls(),
        [TokenCall::DropPrivileges, TokenCall::IsElevated]
    );
    // A privilege that cannot be dropped stops before anything else.
    let t = FakeHelperToken::new(true).fail(TokenCall::DropPrivileges);
    assert_eq!(serve(&t, Vec::new), HelperExit::refused(Reason::Internal));
    assert_eq!(t.calls(), [TokenCall::DropPrivileges]);
    // An unreadable elevation is no elevation.
    let t = FakeHelperToken::new(true).fail(TokenCall::IsElevated);
    assert_eq!(serve(&t, Vec::new), HelperExit::refused(Reason::Internal));
}

/// The arguments are read only after steps 2 and 3 passed (review nit 6).
#[test]
fn serve_reads_the_arguments_only_after_privileges_and_elevation() {
    use std::cell::Cell;
    let read = Cell::new(false);
    let args = || {
        read.set(true);
        Vec::new()
    };
    for t in [
        FakeHelperToken::new(false),
        FakeHelperToken::new(true).fail(TokenCall::DropPrivileges),
        FakeHelperToken::new(true).fail(TokenCall::IsElevated),
    ] {
        let _ = serve(&t, args);
        assert!(!read.get(), "{:?}", t.calls());
    }
    let _ = serve(&FakeHelperToken::new(true), args);
    assert!(read.get());
}

/// P4-2a: elevated, every argument list is a usage refusal, also the form of §3 step 5.
#[test]
fn the_scaffold_refuses_every_argument_list() {
    let form = args(&[
        "--volume",
        "{00000000-0000-0000-0000-000000000000}",
        "--dir",
        "0123456789abcdef0123456789abcdef",
        "--request",
        "00000001-0000000000000001-1.req",
        "--sha256",
        &"0".repeat(64),
    ]);
    for a in [vec![], args(&["--help"]), args(&["x"; 40]), form] {
        let t = FakeHelperToken::new(true);
        assert_eq!(serve(&t, || a), HelperExit::refused(Reason::Usage));
        assert_eq!(
            t.calls(),
            [TokenCall::DropPrivileges, TokenCall::IsElevated]
        );
    }
}

/// The hand-test scripts (A4 S12, P4-2b) compare the helper's exit codes with their own copies
/// in `scripts/dev-helper-common.ps1`.
#[test]
fn the_dev_script_codes_are_the_helper_codes() {
    let script = include_str!("../../../../scripts/dev-helper-common.ps1");
    for (name, reason) in [
        ("NotElevated", Reason::NotElevated),
        ("Usage", Reason::Usage),
    ] {
        let line = format!("${name} = {:#010x}", HelperExit::refused(reason).to_code());
        assert!(
            script.contains(&line),
            "scripts/dev-helper-common.ps1 lacks `{line}`"
        );
    }
}

// ---------- judge (A4 S2) ----------

mod judging {
    use super::super::judge::{Judged, judge};
    use super::{HelperExit, Reason};
    use crate::path::RootPath;
    use crate::policy::root::HelperImage;
    use crate::sys::{HelperProc, HelperRun};

    const NT: &str = r"\Device\HarddiskVolume3\Program Files\Rerun\rerun-helper.exe";

    fn image() -> HelperImage {
        HelperImage {
            path: RootPath::new(r"C:\Program Files\Rerun\rerun-helper.exe").unwrap(),
            nt_name: NT.to_owned(),
        }
    }

    fn run(code: u32, image: Option<&str>, elevated: Option<bool>) -> HelperRun {
        HelperRun::Exited {
            code,
            proc: HelperProc {
                image: image.map(str::to_owned),
                elevated,
            },
        }
    }

    #[test]
    fn the_code_counts_only_for_the_elevated_pre_checked_image() {
        let image = image();
        let usage = HelperExit::refused(Reason::Usage);
        let code = usage.to_code();
        assert_eq!(
            judge(&run(code, Some(NT), Some(true)), &image, 0),
            Judged::Exit(usage)
        );
        // Compared folded, like every path.
        let lower = NT.to_lowercase();
        assert_eq!(
            judge(&run(code, Some(&lower), Some(true)), &image, 0),
            Judged::Exit(usage)
        );
        assert_eq!(judge(&HelperRun::Declined, &image, 3), Judged::Declined);
        for (img, elevated) in [
            // Another program (a redirected start), lookalike names, the Win32 form (never
            // what the process reports), a non-elevated helper (its code can be forged with
            // TerminateProcess), and unreadable facts.
            (
                Some(r"\Device\HarddiskVolume3\Windows\System32\cmd.exe"),
                Some(true),
            ),
            (
                Some(r"\Device\HarddiskVolume3\Program Files\Rerun\rerun-helper.exe.exe"),
                Some(true),
            ),
            (
                Some(r"\Device\HarddiskVolume4\Program Files\Rerun\rerun-helper.exe"),
                Some(true),
            ),
            (Some(r"C:\Program Files\Rerun\rerun-helper.exe"), Some(true)),
            (Some(NT), Some(false)),
            (Some(NT), None),
            (None, Some(true)),
        ] {
            assert_eq!(
                judge(&run(code, img, elevated), &image, 0),
                Judged::Unknown,
                "{img:?} {elevated:?}"
            );
        }
        // A code that does not decode strictly (a crash's NTSTATUS, STILL_ACTIVE, an op slot
        // beyond the batch) is Unknown even from the right process.
        for bad in [0xC000_0005, 259, 0, code | 0b11] {
            assert_eq!(
                judge(&run(bad, Some(NT), Some(true)), &image, 0),
                Judged::Unknown,
                "{bad:#x}"
            );
        }
    }
}

// ---------- prompt state (§10, A4 N7) ----------

mod prompting {
    use super::super::prompt::{POLICY_KEY, PromptFacts, PromptKind, decide, facts, read};
    use crate::sys::fake::FakeSystem;
    use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
    use crate::sys::{SysError, SysErrorKind, TokenKind};

    fn f(token: TokenKind, lua: Option<u32>, admin: Option<u32>, user: Option<u32>) -> PromptFacts {
        PromptFacts {
            token: Some(token),
            enable_lua: lua,
            admin,
            user,
            secure_desktop: Some(1),
            validate_signatures: Some(0),
        }
    }

    #[test]
    fn administrators_follow_consent_prompt_behavior_admin() {
        use PromptKind::{Consent, Credentials, NoPrompt, Unknown};
        for (v, kind, secure) in [
            (Some(0), NoPrompt, None),
            (Some(1), Credentials, Some(true)),
            (Some(2), Consent, Some(true)),
            (Some(3), Credentials, Some(true)),
            (Some(4), Consent, Some(true)),
            (Some(5), Consent, Some(true)),
            (Some(6), Unknown, None),
            (None, Unknown, None),
        ] {
            let s = decide(&f(TokenKind::Filtered, Some(1), v, Some(0)));
            assert_eq!((s.kind, s.secure_desktop), (kind, secure), "{v:?}");
            assert_eq!(s.has_dialog(), matches!(kind, Consent | Credentials));
        }
        // PromptOnSecureDesktop = 0 moves 3, 4 and 5 to the user's desktop, never 1 and 2.
        for (v, secure) in [(1, true), (2, true), (3, false), (4, false), (5, false)] {
            let mut x = f(TokenKind::Filtered, Some(1), Some(v), None);
            x.secure_desktop = Some(0);
            assert_eq!(decide(&x).secure_desktop, Some(secure), "{v}");
            x.secure_desktop = None;
            let unknown = decide(&x).secure_desktop;
            assert_eq!(unknown, if v <= 2 { Some(true) } else { None }, "{v}");
        }
    }

    #[test]
    fn standard_users_get_credentials_unless_denied() {
        for (v, kind) in [
            (Some(0), PromptKind::Denied),
            (Some(1), PromptKind::Credentials),
            (Some(3), PromptKind::Credentials),
            // N7: an unknown or missing value is Credentials, the default for standard users.
            (Some(2), PromptKind::Credentials),
            (None, PromptKind::Credentials),
        ] {
            let s = decide(&f(TokenKind::Standard, Some(1), Some(0), v));
            assert_eq!(s.kind, kind, "{v:?}");
        }
        let s = decide(&f(TokenKind::Standard, Some(1), None, Some(1)));
        assert_eq!(s.secure_desktop, Some(true));
    }

    #[test]
    fn uac_off_elevated_and_unreadable_have_no_dialog() {
        let off = decide(&f(TokenKind::Filtered, Some(0), Some(5), Some(3)));
        assert_eq!(off.kind, PromptKind::UacOff);
        for lua in [None, Some(2)] {
            assert_eq!(
                decide(&f(TokenKind::Filtered, lua, Some(5), Some(3))).kind,
                PromptKind::Unknown
            );
        }
        assert_eq!(
            decide(&f(TokenKind::Elevated, Some(1), Some(5), Some(3))).kind,
            PromptKind::Elevated
        );
        let mut none = f(TokenKind::Filtered, Some(1), Some(5), Some(3));
        none.token = None;
        let s = decide(&none);
        assert_eq!(s.kind, PromptKind::Unknown);
        assert!(!s.has_dialog());
        // ValidateAdminCodeSignatures (N7).
        let mut signed = f(TokenKind::Filtered, Some(1), Some(5), None);
        signed.validate_signatures = Some(1);
        assert!(decide(&signed).signed_only);
        assert!(!decide(&f(TokenKind::Filtered, Some(1), Some(5), None)).signed_only);
    }

    #[test]
    fn the_facts_come_from_hklm_and_the_token() {
        let key = RegKey::new(Hive::LocalMachine, RegView::Native, POLICY_KEY);
        let sys = FakeSystem::builder()
            .value(key.clone(), "EnableLUA", RegValue::Dword(1))
            .value(
                key.clone(),
                "ConsentPromptBehaviorAdmin",
                RegValue::Dword(0),
            )
            .value(
                key.clone(),
                "ConsentPromptBehaviorUser",
                RegValue::String("3".into()),
            )
            .value(key, "PromptOnSecureDesktop", RegValue::Dword(1))
            .build()
            .unwrap();
        let x = facts(&sys);
        assert_eq!(x.token, Some(TokenKind::Filtered));
        assert_eq!((x.enable_lua, x.admin), (Some(1), Some(0)));
        // A value of another type is unreadable; a missing one too.
        assert_eq!((x.user, x.validate_signatures), (None, None));
        assert_eq!(read(&sys).kind, PromptKind::NoPrompt);
        // An unreadable token: no dialog assumed.
        sys.fake_elevation()
            .set_token_kind(Err(SysError::new(SysErrorKind::AccessDenied, "token")));
        assert_eq!(read(&sys).kind, PromptKind::Unknown);
        // Nothing in the registry at all.
        assert_eq!(read(&FakeSystem::new()).kind, PromptKind::Unknown);
    }
}

// ---------- the fake elevation ----------

#[test]
fn the_fake_elevation_runs_as_scripted_and_records_the_command_line() {
    use crate::path::RootPath;
    use crate::sys::fake::FakeSystem;
    use crate::sys::{HelperProc, HelperRun, SysErrorKind, System};
    let sys = FakeSystem::new();
    let image = RootPath::new(r"C:\Program Files\Rerun\rerun-helper.exe").unwrap();
    let exited = HelperRun::Exited {
        code: 7,
        proc: HelperProc {
            image: None,
            elevated: None,
        },
    };
    sys.fake_elevation().push_run(Ok(HelperRun::Declined));
    sys.fake_elevation().push_run(Ok(exited.clone()));
    let e = sys.elevation();
    #[expect(clippy::disallowed_methods, reason = "test: the fake's own behaviour")]
    let runs = [
        e.run_helper(&image, &["--a", "b"]),
        e.run_helper(&image, &[]),
        e.run_helper(&image, &[]),
        e.run_helper(&image, &["not plain"]),
    ];
    let [a, b, c, d] = runs;
    assert_eq!(a.unwrap(), HelperRun::Declined);
    assert_eq!(b.unwrap(), exited);
    assert_eq!(c.unwrap_err().kind, SysErrorKind::Unsupported);
    assert_eq!(d.unwrap_err().kind, SysErrorKind::InvalidPath);
    let calls = sys.fake_elevation().calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].parameters, "--a b");
    assert_eq!(calls[0].image, image);
}
