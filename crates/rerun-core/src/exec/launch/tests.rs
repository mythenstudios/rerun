//! The reader of the launch result files against the fake (ADR 0022 amendment P3-2).

use rerun_proto::cpu::rule::Mode;
use rerun_proto::launch::{AppliedCpu, Check, LaunchResult, Outcome, SkipReason, Start, encode};
use rerun_proto::profile::ProfileId;

use super::{MAX_LAUNCH_ENTRIES, launch_results};
use crate::policy::root::{AppDir, Create, RootError};
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};

const LAUNCH: &str = r"C:\Users\Player\AppData\Local\Rerun\launch";

fn id(b: u8) -> ProfileId {
    ProfileId([b; 16])
}

fn ok(b: u8) -> LaunchResult {
    LaunchResult {
        profile: id(b),
        unix_s: 1_762_600_000,
        outcome: Outcome::Applied {
            cpu: Some(AppliedCpu {
                mode: Mode::Hard,
                threads: 8,
                of: 32,
            }),
            priority: None,
            check: Check::Ok,
        },
    }
}

fn at(name: &str) -> String {
    format!(r"{LAUNCH}\{name}")
}

fn file_of(b: u8) -> String {
    at(&format!("{}.result", id(b)))
}

fn base() -> FakeSystemBuilder {
    FakeSystem::builder().dir(r"C:\Users\Player\AppData\Local\Rerun")
}

fn read(sys: &FakeSystem) -> Result<Option<super::LaunchResults>, RootError> {
    let app = AppDir::open(sys, Create::Never).unwrap().unwrap();
    launch_results(&app)
}

#[test]
fn no_launch_folder_is_none() {
    let sys = base().build().unwrap();
    assert_eq!(read(&sys).unwrap(), None);
}

#[test]
fn results_are_read_by_id_and_temps_skipped() {
    let skipped = LaunchResult {
        profile: id(0x01),
        unix_s: 5,
        outcome: Outcome::Skipped {
            reason: SkipReason::PathMismatch,
            start: Start::Created,
            ended: None,
            priority_restore: None,
        },
    };
    let sys = base()
        .file(file_of(0xbb), encode(&ok(0xbb)).unwrap())
        .file(file_of(0x01), encode(&skipped).unwrap())
        .file(at(&format!("{}.1234-5.tmp", id(0xcc))), b"half".to_vec())
        .file(at("notes.txt"), b"x".to_vec())
        .file(at(&format!("{}.RESULT", id(0xdd))), b"x".to_vec())
        .build()
        .unwrap();
    let r = read(&sys).unwrap().unwrap();
    assert_eq!(r.other, 2);
    assert_eq!(r.entries.len(), 2);
    assert_eq!(r.entries[0].id, id(0x01));
    assert_eq!(r.entries[0].result, Ok(skipped));
    assert_eq!(r.entries[1].result, Ok(ok(0xbb)));
}

#[test]
fn every_bad_file_is_one_unreadable_entry() {
    let mut big = encode(&ok(0x05)).unwrap();
    big.resize(1025, b'x');
    let sys = base()
        // Garbage, a result naming another profile, an oversize file.
        .file(file_of(0x02), b"rerun-result 1\n\x1b[31m\n".to_vec())
        .file(file_of(0x03), encode(&ok(0x04)).unwrap())
        .file(file_of(0x05), big)
        // A link, a folder, a restricted file.
        .junction(file_of(0x06), r"C:\Elsewhere")
        .dir(file_of(0x07))
        .file(file_of(0x08), encode(&ok(0x08)).unwrap())
        .restricted(file_of(0x08))
        .build()
        .unwrap();
    let r = read(&sys).unwrap().unwrap();
    let why: Vec<String> = r
        .entries
        .iter()
        .map(|e| e.result.as_ref().unwrap_err().as_str().to_owned())
        .collect();
    assert_eq!(r.entries.len(), 6, "{why:?}");
    assert!(why[0].starts_with("launch result line 2: "), "{why:?}");
    assert!(!why[0].contains('\x1b'));
    assert_eq!(why[1], "it names another profile than its file name");
    assert_eq!(why[2], "larger than 1024 bytes");
    assert_eq!(why[3], "a link (not followed)");
    assert_eq!(why[4], "a folder, not a file");
    assert_eq!(why[5], "access denied");
}

#[test]
fn a_link_at_launch_is_refused() {
    let sys = base()
        .dir(r"C:\Elsewhere")
        .junction(LAUNCH, r"C:\Elsewhere")
        .build()
        .unwrap();
    assert!(matches!(read(&sys), Err(RootError::Reparse { .. })));
}

#[test]
fn too_many_entries_are_refused_as_a_whole() {
    let mut b = base();
    for n in 0..=MAX_LAUNCH_ENTRIES {
        b = b.file(at(&format!("x{n}")), Vec::new());
    }
    let sys = b.build().unwrap();
    assert!(matches!(read(&sys), Err(RootError::Sys(_))));
}
