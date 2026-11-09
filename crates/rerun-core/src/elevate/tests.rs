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
/// (`scripts/dev-helper-sac.ps1`): pinned.
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

/// The hand-test script of A4 S12 compares the helper's exit codes with its own copies.
#[test]
fn the_dev_script_codes_are_the_helper_codes() {
    let script = include_str!("../../../../scripts/dev-helper-sac.ps1");
    for (name, reason) in [
        ("NotElevated", Reason::NotElevated),
        ("Usage", Reason::Usage),
    ] {
        let line = format!("${name} = {:#010x}", HelperExit::refused(reason).to_code());
        assert!(
            script.contains(&line),
            "scripts/dev-helper-sac.ps1 lacks `{line}`"
        );
    }
}
