//! Journal writer and reader against the fake (P2-7: J1, J3, J7, J9; the crash and
//! power-loss matrix J4 to J6 is in `crash_tests.rs`).

use std::path::Path;

use super::record::{self, Record};
use super::{
    BackupFault, Closing, Damage, InstanceTag, Journal, JournalError, JournalLock, Limits,
    Observed, TxnId, TxnState, TxnView, TxnWriter, VerifyBackups,
};
use crate::path::RelPath;
use crate::policy::root::{AppDir, Create, RootError};
use crate::sys::fake::{FakeSystem, FsOp};
use crate::sys::fs::{DirWrite, Fs, WriteCap, tag};
use crate::sys::{SysErrorKind, System};

pub(crate) const LAD: &str = r"C:\Users\Player\AppData\Local";
pub(super) const JDIR: &str = r"C:\Users\Player\AppData\Local\Rerun\journal";
pub(super) const HEAD: &[u8] = br#"{"format":1,"ops":["a","b"]}"#;
pub(super) const OLD: &[u8] = b"old content of a.bin";
pub(super) const TAG: u64 = 0xab;

pub(super) fn r(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

pub(super) fn system() -> FakeSystem {
    FakeSystem::builder()
        .dir(LAD)
        .file(r"D:\G\a.bin", OLD)
        .build()
        .unwrap()
}

pub(super) fn open_app(sys: &dyn System) -> AppDir<'_> {
    AppDir::open(sys, Create::IfMissing).unwrap().unwrap()
}

/// The write handle of a test folder (no `policy::root` in between: test code).
#[expect(
    clippy::disallowed_methods,
    reason = "test: the game folder of the journal tests"
)]
pub(super) fn game<'s>(sys: &'s dyn System, abs: &str) -> Box<dyn DirWrite + 's> {
    sys.fs()
        .open_dir_write(Path::new(abs), &WriteCap::new())
        .unwrap()
}

/// `Err(JournalError::Root(RootError::Reparse { .. }))`.
pub(crate) fn is_reparse<T>(r: &Result<T, JournalError>) -> bool {
    matches!(r, Err(JournalError::Root(e)) if matches!(**e, RootError::Reparse { .. }))
}

pub(super) fn txn_dir(id: &TxnId) -> String {
    format!(r"{JDIR}\{id}")
}

/// Begins and applies two ops: op 0 with a backup of `a.bin`, op 1 without.
pub(super) fn apply2<'l>(lock: &'l JournalLock<'_>, g: &dyn DirWrite) -> TxnWriter<'l> {
    let mut w = lock.begin(HEAD).unwrap();
    let mut guard = g.guard(&r("a.bin")).unwrap();
    let b = w.backup(&mut *guard).unwrap();
    drop(guard);
    let t0 = w.tmp();
    w.intent(0, Some(t0), Some(b)).unwrap();
    w.done(0, 7, false).unwrap();
    w.intent(1, None, None).unwrap();
    w.done(1, 8, true).unwrap();
    w.applied(2).unwrap();
    w
}

fn names_in(sys: &FakeSystem, abs: &str) -> Vec<String> {
    #[expect(clippy::disallowed_methods, reason = "test: list a fixture folder")]
    let d = sys.fake_fs().open_dir(Path::new(abs)).unwrap();
    let mut v: Vec<String> = d
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    v.sort();
    v
}

fn load(j: &Journal<'_>, id: &TxnId) -> TxnView {
    j.load(id, VerifyBackups::Hash).unwrap()
}

fn state(j: &Journal<'_>, id: &TxnId) -> TxnState {
    load(j, id).state
}

/// J1 on any system: every record kind written, read back as written. `src` holds `a.bin`
/// with `old`. Returns the transaction.
pub(crate) fn j1_round_trip(app: &AppDir<'_>, src: &dyn DirWrite, old: &[u8]) -> TxnId {
    let j = Journal::new(app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap_or_else(|e| panic!("{e}"));
    let mut w = lock.begin(HEAD).unwrap_or_else(|e| panic!("{e}"));
    let id = *w.id();
    assert_eq!((id.seq(), id.tag()), (1, TAG));
    assert_eq!(state(&j, &id), TxnState::Empty);
    let mut guard = src.guard(&r("a.bin")).unwrap();
    let b = w.backup(&mut *guard).unwrap_or_else(|e| panic!("{e}"));
    drop(guard);
    let (t0, t1, t2) = (w.tmp(), w.tmp(), w.tmp());
    w.intent(0, Some(t0.clone()), Some(b)).unwrap();
    assert_eq!(state(&j, &id), TxnState::Open);
    w.done(0, u128::MAX, false).unwrap();
    w.intent(1, None, None).unwrap();
    w.done(1, 8, true).unwrap();
    w.applied(2).unwrap();
    assert_eq!(state(&j, &id), TxnState::Applied);
    w.revert_intent(1, Some(t1.clone())).unwrap();
    w.revert_intent(1, None).unwrap();
    w.revert_done(1, Observed::After, true).unwrap();
    w.revert_intent(0, Some(t2.clone())).unwrap();
    w.revert_done(0, Observed::Drifted, false).unwrap();
    w.close(Closing::Reverted).unwrap();

    let v = load(&j, &id);
    assert_eq!(v.state, TxnState::Closed(Closing::Reverted));
    assert_eq!((v.head.as_deref(), v.anomaly.as_ref()), (Some(HEAD), None));
    let sha: [u8; 32] =
        sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(old)).into();
    let backup = Some(record::BackupRef {
        sha256: sha,
        len: u64::try_from(old.len()).unwrap(),
    });
    assert_eq!(
        v.log,
        [
            Record::Intent {
                op: 0,
                tmp: Some(t0.clone()),
                backup,
            },
            Record::Done {
                op: 0,
                file_id: u128::MAX,
                old_left: false,
            },
            Record::Intent {
                op: 1,
                tmp: None,
                backup: None,
            },
            Record::Done {
                op: 1,
                file_id: 8,
                old_left: true,
            },
            Record::Applied { ops: 2 },
            Record::RevertIntent {
                op: 1,
                tmp: Some(t1.clone()),
            },
            Record::RevertIntent { op: 1, tmp: None },
            Record::RevertDone {
                op: 1,
                observed: Observed::After,
                old_left: true,
            },
            Record::RevertIntent {
                op: 0,
                tmp: Some(t2),
            },
            Record::RevertDone {
                op: 0,
                observed: Observed::Drifted,
                old_left: false,
            },
            Record::Closed {
                how: Closing::Reverted,
            },
        ]
    );
    assert_eq!(v.ops[&1].reverts, [Some(t1), None]);
    assert_eq!(v.ops[&0].intent.tmp, Some(t0));
    // The backup is the old content, under its op's name.
    let jd = app.dir().open_dir(&r(&format!(r"journal\{id}"))).unwrap();
    assert_eq!(jd.read(&r("op-0000.bin")).unwrap(), old);
    let mut names: Vec<String> = jd
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();
    let mut want: Vec<String> = (1..=11).map(|n| format!("{n:04}.json")).collect();
    want.extend(["head.json".to_owned(), "op-0000.bin".to_owned()]);
    want.sort();
    assert_eq!(
        names, want,
        "nothing else in the folder (no temp file left)"
    );
    // Listed, and the next transaction gets the next number.
    let listing = j.list().unwrap();
    assert_eq!(listing.txns.len(), 1);
    assert_eq!(listing.foreign, 0);
    let w2 = lock.begin(b"{}").unwrap();
    assert_eq!(w2.id().seq(), 2);
    w2.close(Closing::Forgotten).unwrap();
    id
}

// ---------- J1 ----------

#[test]
fn j1_every_record_kind_round_trips() {
    let sys = system();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    j1_round_trip(&app, &*g, OLD);
}

#[test]
fn j1_rollback_and_forget_paths() {
    let sys = system();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    // Rollback of an op that failed during its change (intent without done).
    let mut w = lock.begin(HEAD).unwrap();
    let id = *w.id();
    w.intent(0, None, None).unwrap();
    w.done(0, 1, false).unwrap();
    w.intent(1, None, None).unwrap();
    assert_eq!(w.next_revert(), Some(1));
    assert!(!w.is_applied());
    assert_eq!(w.ops()[&1].done, None);
    w.revert_intent(1, None).unwrap();
    w.revert_done(1, Observed::Before, false).unwrap();
    w.revert_intent(0, None).unwrap();
    w.revert_done(0, Observed::After, false).unwrap();
    assert_eq!(w.next_revert(), None);
    w.close(Closing::RolledBack).unwrap();
    assert_eq!(state(&j, &id), TxnState::Closed(Closing::RolledBack));
    // A Foreign op: only Forgotten closes (D10).
    let mut w = apply2(&lock, &*g);
    let id = *w.id();
    w.revert_intent(1, None).unwrap();
    w.revert_done(1, Observed::Foreign, false).unwrap();
    w.revert_intent(0, None).unwrap();
    w.revert_done(0, Observed::After, false).unwrap();
    drop(w);
    let mut w = lock.resume(&id).unwrap();
    assert!(w.is_applied());
    assert_eq!((w.id(), w.ops().len()), (&id, 2));
    assert_eq!(w.tmp().tag(), TAG);
    let e = w.revert_intent(0, None).unwrap_err();
    assert!(matches!(e, JournalError::Order(_)), "{e}");
    w.close(Closing::Forgotten).unwrap();
    assert_eq!(state(&j, &id), TxnState::Closed(Closing::Forgotten));
}

#[test]
fn j1_the_writer_refuses_what_the_reader_would_call_damaged() {
    let sys = system();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    let mut w = lock.begin(HEAD).unwrap();
    let id = *w.id();
    let order = |r: Result<(), JournalError>| matches!(r, Err(JournalError::Order(_)));
    assert!(order(w.done(0, 1, false)));
    assert!(order(w.intent(1, None, None)));
    assert!(order(w.applied(0)));
    assert!(order(w.revert_intent(0, None)));
    let mut guard = g.guard(&r("a.bin")).unwrap();
    let b = w.backup(&mut *guard).unwrap();
    assert!(matches!(w.backup(&mut *guard), Err(JournalError::Order(_))));
    drop(guard);
    assert!(
        order(w.intent(0, None, None)),
        "an intent without its backup"
    );
    w.intent(0, None, Some(b)).unwrap();
    assert!(order(w.applied(1)), "op 0 is not done");
    w.done(0, 1, false).unwrap();
    w.applied(1).unwrap();
    assert!(order(w.intent(1, None, None)));
    drop(w);
    assert_eq!(
        state(&j, &id),
        TxnState::Applied,
        "nothing refused was written"
    );
    assert_eq!(load(&j, &id).log.len(), 3);
}

#[test]
fn j1_a_backup_that_reads_back_differently_is_refused_and_its_orphan_allowed() {
    let sys = system();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    let mut w = lock.begin(HEAD).unwrap();
    let id = *w.id();
    let bin = format!(r"{}\op-0000.bin", txn_dir(&id));
    sys.fake_fs().on_step(move |fs, ev| {
        if ev.op == FsOp::OpenRead && ev.name == "op-0000.bin" {
            fs.put_file(Path::new(&bin), b"swapped").unwrap();
        }
    });
    let mut guard = g.guard(&r("a.bin")).unwrap();
    let e = w.backup(&mut *guard).unwrap_err();
    sys.fake_fs().clear_on_step();
    assert!(matches!(e, JournalError::BackupMismatch(0)), "{e}");
    drop((guard, w));
    // B1: the orphan of op 0 (no intent 0 yet) never damages the transaction.
    assert_eq!(state(&j, &id), TxnState::Empty);
    let mut w = lock.resume(&id).unwrap();
    assert_eq!(w.next_revert(), None);
    w.revert_done(0, Observed::Before, false).unwrap_err();
    w.close(Closing::RolledBack).unwrap();
    assert_eq!(state(&j, &id), TxnState::Closed(Closing::RolledBack));
}

// ---------- J3: tampering ----------

/// A system with one applied transaction (5 records, `op-0000.bin`), and its ID.
fn tampered(f: impl FnOnce(&FakeSystem, &str)) -> (FakeSystem, TxnId) {
    let sys = system();
    let id = {
        let app = open_app(&sys);
        let g = game(&sys, r"D:\G");
        let j = Journal::new(&app, InstanceTag::fixed(TAG));
        let lock = j.lock().unwrap();
        *apply2(&lock, &*g).id()
    };
    f(&sys, &txn_dir(&id));
    (sys, id)
}

fn read_back(sys: &FakeSystem, id: &TxnId, v: VerifyBackups) -> TxnView {
    let app = open_app(sys);
    Journal::new(&app, InstanceTag::fixed(1))
        .load(id, v)
        .unwrap()
}

fn put(sys: &FakeSystem, abs: String, data: &[u8]) {
    sys.fake_fs().put_file(Path::new(&abs), data).unwrap();
}

fn record_bytes(sys: &FakeSystem, dir: &str, n: u16) -> Vec<u8> {
    #[expect(clippy::disallowed_methods, reason = "test: read a fixture")]
    let d = sys.fake_fs().open_dir(Path::new(dir)).unwrap();
    d.read(&r(&format!("{n:04}.json"))).unwrap()
}

fn head_sha() -> [u8; 32] {
    sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(HEAD)).into()
}

#[test]
fn j3_edited_removed_duplicated_and_planted_records() {
    let edit = |n: u16, f: fn(String) -> String| {
        move |sys: &FakeSystem, dir: &str| {
            let s = String::from_utf8(record_bytes(sys, dir, n)).unwrap();
            put(sys, format!(r"{dir}\{n:04}.json"), f(s).as_bytes());
        }
    };
    type Case = (&'static str, Box<dyn FnOnce(&FakeSystem, &str)>, TxnState);
    let damaged = TxnState::Damaged;
    let cases: Vec<Case> = vec![
        (
            "unparsable",
            Box::new(|s, d| put(s, format!(r"{d}\0003.json"), b"{")),
            damaged(Damage::Unparsable { n: 3 }),
        ),
        (
            "unknown field",
            Box::new(edit(3, |s| {
                s.replace(r#""ops":1"#, r#""ops":1,"x":0"#)
                    .replace(r#""op":1,"#, r#""op":1,"x":0,"#)
            })),
            damaged(Damage::Unparsable { n: 3 }),
        ),
        (
            "format 2",
            Box::new(edit(3, |s| s.replace(r#""format":1"#, r#""format":2"#))),
            damaged(Damage::Format { n: 3 }),
        ),
        (
            "wrong n",
            Box::new(edit(3, |s| s.replace(r#""n":3"#, r#""n":4"#))),
            damaged(Damage::Numbering { n: 3 }),
        ),
        (
            "head edited",
            Box::new(|s, d| put(s, format!(r"{d}\head.json"), b"{}")),
            damaged(Damage::HeadHash { n: 1 }),
        ),
        (
            "head removed",
            Box::new(|s, d| {
                s.fake_fs()
                    .remove_abs(Path::new(&format!(r"{d}\head.json")))
                    .unwrap()
            }),
            damaged(Damage::HeadMissing),
        ),
        (
            "gap",
            Box::new(|s, d| {
                s.fake_fs()
                    .remove_abs(Path::new(&format!(r"{d}\0003.json")))
                    .unwrap()
            }),
            damaged(Damage::Gap { at: 3 }),
        ),
        (
            "duplicated",
            Box::new(|s, d| {
                let b = record_bytes(s, d, 2);
                put(s, format!(r"{d}\0003.json"), &b);
            }),
            damaged(Damage::Numbering { n: 3 }),
        ),
        (
            "planted name",
            Box::new(|s, d| put(s, format!(r"{d}\notes.txt"), b"x")),
            damaged(Damage::UnknownEntry),
        ),
        (
            "planted other case",
            Box::new(|s, d| put(s, format!(r"{d}\HEAD.JSON.bak"), b"x")),
            damaged(Damage::UnknownEntry),
        ),
        (
            "planted folder",
            Box::new(|s, d| {
                s.fake_fs()
                    .mkdir_all(Path::new(&format!(r"{d}\0006.json")))
                    .unwrap()
            }),
            damaged(Damage::UnknownEntry),
        ),
        (
            "planted link",
            Box::new(|s, d| {
                s.fake_fs()
                    .put_link(
                        Path::new(&format!(r"{d}\op-0001.bin")),
                        tag::SYMLINK,
                        r"C:\x",
                    )
                    .unwrap()
            }),
            damaged(Damage::UnknownEntry),
        ),
        (
            "stray backup",
            Box::new(|s, d| put(s, format!(r"{d}\op-0005.bin"), b"x")),
            damaged(Damage::UnknownEntry),
        ),
        (
            "backup of a backup-less op",
            Box::new(|s, d| put(s, format!(r"{d}\op-0001.bin"), b"x")),
            damaged(Damage::UnknownEntry),
        ),
        // B1: the orphan of the next op is allowed.
        (
            "orphan backup",
            Box::new(|s, d| put(s, format!(r"{d}\op-0002.bin"), b"x")),
            TxnState::Applied,
        ),
        // Crash remnants are ignored.
        (
            "temp remnant",
            Box::new(|s, d| put(s, format!(r"{d}\.rerun-00000000000000ab-99.tmp"), b"x")),
            TxnState::Applied,
        ),
        (
            "oversized record",
            Box::new(|s, d| put(s, format!(r"{d}\0002.json"), &vec![b' '; 64 * 1024 + 1])),
            damaged(Damage::TooLarge { n: 2 }),
        ),
        (
            "oversized head",
            Box::new(|s, d| put(s, format!(r"{d}\head.json"), &vec![b' '; (1 << 20) + 1])),
            damaged(Damage::HeadTooLarge),
        ),
        (
            "backup truncated",
            Box::new(|s, d| put(s, format!(r"{d}\op-0000.bin"), b"old")),
            damaged(Damage::Backup {
                op: 0,
                why: BackupFault::Length,
            }),
        ),
        (
            "backup removed",
            Box::new(|s, d| {
                s.fake_fs()
                    .remove_abs(Path::new(&format!(r"{d}\op-0000.bin")))
                    .unwrap()
            }),
            damaged(Damage::Backup {
                op: 0,
                why: BackupFault::Missing,
            }),
        ),
        (
            "backup swapped",
            Box::new(|s, d| put(s, format!(r"{d}\op-0000.bin"), &vec![b'x'; OLD.len()])),
            damaged(Damage::Backup {
                op: 0,
                why: BackupFault::Hash,
            }),
        ),
        // A removed tail leaves a valid prefix: accepted (documented, ADR 0019 amendment).
        (
            "tail removed",
            Box::new(|s, d| {
                s.fake_fs()
                    .remove_abs(Path::new(&format!(r"{d}\0005.json")))
                    .unwrap()
            }),
            TxnState::Open,
        ),
        (
            "valid record appended",
            Box::new(|s, d| {
                let b = record::encode(6, &head_sha(), &Record::RevertIntent { op: 1, tmp: None })
                    .unwrap();
                put(s, format!(r"{d}\0006.json"), &b);
            }),
            TxnState::Applied,
        ),
        (
            "record against the grammar appended",
            Box::new(|s, d| {
                let b = record::encode(
                    6,
                    &head_sha(),
                    &Record::Intent {
                        op: 2,
                        tmp: None,
                        backup: None,
                    },
                )
                .unwrap();
                put(s, format!(r"{d}\0006.json"), &b);
            }),
            damaged(Damage::Grammar {
                n: 6,
                why: "an intent after Applied",
            }),
        ),
    ];
    for (what, f, want) in cases {
        let (sys, id) = tampered(f);
        let got = read_back(&sys, &id, VerifyBackups::Hash);
        assert_eq!(got.state, want, "{what}");
        if let TxnState::Damaged(d) = &want {
            assert_eq!(
                d.head_unusable(),
                matches!(
                    d,
                    Damage::HeadMissing | Damage::HeadTooLarge | Damage::HeadHash { .. }
                ),
                "{what}"
            );
        }
    }
    // E3: `status` checks existence and length only; the swapped backup passes that.
    let (sys, id) = tampered(|s, d| put(s, format!(r"{d}\op-0000.bin"), &vec![b'x'; OLD.len()]));
    assert_eq!(
        read_back(&sys, &id, VerifyBackups::Length).state,
        TxnState::Applied
    );
}

#[test]
fn j3_a_closed_prefix_with_a_planted_tail_counts_as_closed_with_an_anomaly() {
    let sys = system();
    let id = {
        let app = open_app(&sys);
        let g = game(&sys, r"D:\G");
        let j = Journal::new(&app, InstanceTag::fixed(TAG));
        let lock = j.lock().unwrap();
        let w = apply2(&lock, &*g);
        let id = *w.id();
        w.close(Closing::Forgotten).unwrap();
        id
    };
    let dir = txn_dir(&id);
    let b = record::encode(7, &head_sha(), &Record::Applied { ops: 2 }).unwrap();
    put(&sys, format!(r"{dir}\0007.json"), &b);
    put(&sys, format!(r"{dir}\notes.txt"), b"x");
    sys.fake_fs()
        .remove_abs(Path::new(&format!(r"{dir}\op-0000.bin")))
        .unwrap();
    let v = read_back(&sys, &id, VerifyBackups::Hash);
    assert_eq!(v.state, TxnState::Closed(Closing::Forgotten));
    assert_eq!(
        v.anomaly,
        Some(Damage::Grammar {
            n: 7,
            why: "a record after Closed"
        })
    );
    assert_eq!(v.log.len(), 6, "the valid prefix");
}

#[test]
fn j3_links_planted_in_the_journal_are_never_followed() {
    // At a transaction folder: listed as an error, load refuses, the target is untouched.
    let (sys, id) = tampered(|s, d| {
        s.fake_fs().mkdir_all(Path::new(r"C:\Out")).unwrap();
        s.fake_fs()
            .put_file(Path::new(r"C:\Out\canary.txt"), b"canary")
            .unwrap();
        s.swap_with_junction(d, r"C:\Out").unwrap();
    });
    let app = open_app(&sys);
    let j = Journal::new(&app, InstanceTag::fixed(1));
    let listing = j.list().unwrap();
    assert_eq!(listing.txns.len(), 1);
    assert_eq!(listing.foreign, 1, "the swapped-away folder");
    assert!(is_reparse(&listing.txns[0].view));
    assert!(is_reparse(&j.load(&id, VerifyBackups::Length)));
    let lock = j.lock().unwrap();
    assert!(is_reparse(&lock.resume(&id)));
    drop(lock);
    assert_eq!(names_in(&sys, r"C:\Out"), ["canary.txt"]);

    // At `journal` itself.
    let sys = system();
    sys.fake_fs().mkdir_all(Path::new(r"C:\Out")).unwrap();
    sys.fake_fs()
        .put_link(Path::new(JDIR), tag::MOUNT_POINT, r"C:\Out")
        .unwrap();
    let app = open_app(&sys);
    let j = Journal::new(&app, InstanceTag::fixed(1));
    assert!(is_reparse(&j.list()));
    assert!(is_reparse(&j.lock()));
    assert!(names_in(&sys, r"C:\Out").is_empty());

    // At `lock`.
    let sys = system();
    sys.fake_fs().mkdir_all(Path::new(r"C:\Out")).unwrap();
    sys.fake_fs()
        .put_link(
            Path::new(&format!(r"{JDIR}\lock")),
            tag::SYMLINK,
            r"C:\Out\lock",
        )
        .unwrap();
    let app = open_app(&sys);
    let j = Journal::new(&app, InstanceTag::fixed(1));
    let r = j.lock().map(|_| ());
    assert!(is_reparse(&r), "{r:?}");
    assert!(names_in(&sys, r"C:\Out").is_empty());
}

#[test]
fn j3_planted_transaction_folders() {
    // The highest possible seq: begin refuses instead of wrapping.
    let sys = system();
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{JDIR}\99999999-0000000000000000")))
        .unwrap();
    let app = open_app(&sys);
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    assert!(matches!(
        lock.begin(HEAD),
        Err(JournalError::SeqExhausted { highest }) if highest.to_string() == "99999999-0000000000000000"
    ));
    drop(lock);
    // S5: a second folder with the same seq makes both damaged.
    let (sys, id) = tampered(|s, _| {
        s.fake_fs()
            .mkdir_all(Path::new(&format!(r"{JDIR}\00000001-0000000000000001")))
            .unwrap();
        s.fake_fs()
            .put_file(Path::new(&format!(r"{JDIR}\desktop.ini")), b"x")
            .unwrap();
    });
    let app = open_app(&sys);
    let j = Journal::new(&app, InstanceTag::fixed(1));
    let listing = j.list().unwrap();
    assert_eq!(listing.foreign, 1);
    let states: Vec<_> = listing
        .txns
        .iter()
        .map(|l| (l.id, l.view.as_ref().map(|v| v.state.clone()).unwrap()))
        .collect();
    assert_eq!(states.len(), 2);
    assert!(
        states
            .iter()
            .all(|(_, s)| *s == TxnState::Damaged(Damage::DuplicateSeq)),
        "{states:?}"
    );
    assert!(states.iter().any(|(i, _)| *i == id));
    // A file of a transaction name counts for seq but is no transaction.
    let sys = system();
    sys.fake_fs()
        .put_file(
            Path::new(&format!(r"{JDIR}\00000041-0000000000000000")),
            b"x",
        )
        .unwrap();
    let app = open_app(&sys);
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    assert_eq!(lock.begin(HEAD).unwrap().id().seq(), 42);
    // B2: a folder without head and records is Empty.
    let empty = TxnId::new(41, 0).unwrap();
    assert!(
        j.load(&empty, VerifyBackups::Length).is_err(),
        "a file, not a folder"
    );
    let bare = TxnId::new(50, 0).unwrap();
    sys.fake_fs().mkdir_all(Path::new(&txn_dir(&bare))).unwrap();
    assert_eq!(
        j.load(&bare, VerifyBackups::Length).unwrap().state,
        TxnState::Empty
    );
    assert!(
        matches!(lock.resume(&bare), Err(JournalError::NotResumable { .. })),
        "no head to write against"
    );
}

#[test]
fn j3_resume_refuses_closed_and_damaged_transactions() {
    let (sys, id) = tampered(|s, d| put(s, format!(r"{d}\notes.txt"), b"x"));
    let app = open_app(&sys);
    let j = Journal::new(&app, InstanceTag::fixed(1));
    let lock = j.lock().unwrap();
    assert!(matches!(
        lock.resume(&id),
        Err(JournalError::NotResumable {
            state: TxnState::Damaged(Damage::UnknownEntry),
            ..
        })
    ));
    let missing = TxnId::new(9, 9).unwrap();
    assert!(matches!(
        lock.resume(&missing),
        Err(JournalError::NotFound(_))
    ));
    assert!(matches!(
        j.load(&missing, VerifyBackups::Length),
        Err(JournalError::NotFound(_))
    ));
    let g = game(&sys, r"D:\G");
    let w = apply2(&lock, &*g);
    let id2 = *w.id();
    w.close(Closing::Forgotten).unwrap();
    assert!(matches!(
        lock.resume(&id2),
        Err(JournalError::NotResumable {
            state: TxnState::Closed(Closing::Forgotten),
            ..
        })
    ));
}

// ---------- J7: the lock ----------

#[test]
fn j7_one_lock_at_a_time_released_by_a_crash_and_list_needs_none() {
    let sys = system();
    let app1 = open_app(&sys);
    let app2 = open_app(&sys);
    let j1 = Journal::new(&app1, InstanceTag::fixed(1));
    let j2 = Journal::new(&app2, InstanceTag::fixed(2));
    let lock = j1.lock().unwrap();
    assert!(matches!(j2.lock(), Err(JournalError::Busy)));
    assert!(
        matches!(j1.lock(), Err(JournalError::Busy)),
        "also in the same journal"
    );
    // Status without the lock.
    let g = game(&sys, r"D:\G");
    let id = *apply2(&lock, &*g).id();
    assert_eq!(j2.list().unwrap().txns.len(), 1);
    assert_eq!(
        j2.load(&id, VerifyBackups::Length).unwrap().state,
        TxnState::Applied
    );
    drop(lock);
    drop(j2.lock().unwrap());
    // A crash while the lock is held: the restart releases it.
    let held = j1.lock().unwrap();
    let fx = sys.fake_fs();
    fx.clear_faults();
    fx.fault(
        crate::sys::fake::Prim::ReadSide(FsOp::ReadDir),
        1,
        crate::sys::fake::Fault::CrashAfter,
    );
    assert!(j1.list().is_err());
    assert!(fx.crashed());
    drop(held);
    drop(g);
    drop(j1);
    drop(j2);
    drop(app1);
    drop(app2);
    fx.restart();
    let app3 = open_app(&sys);
    let j3 = Journal::new(&app3, InstanceTag::fixed(3));
    drop(j3.lock().unwrap());
}

// ---------- J9: budgets ----------

fn small(f: impl FnOnce(&mut Limits)) -> Limits {
    let mut l = Limits::default();
    f(&mut l);
    l
}

#[test]
fn j9_writer_budgets_refuse_before_writing() {
    let sys = FakeSystem::builder()
        .dir(LAD)
        .file(r"D:\G\a.bin", [1u8; 10])
        .file(r"D:\G\b.bin", [2u8; 10])
        .build()
        .unwrap();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    let too_large = |r: Result<(), JournalError>| matches!(r, Err(JournalError::TooLarge { .. }));

    let j = Journal::with_limits(&app, InstanceTag::fixed(1), small(|l| l.head = 4));
    let lock = j.lock().unwrap();
    assert!(too_large(lock.begin(b"12345").map(|_| ())));
    assert!(lock.begin(b"1234").is_ok());
    drop(lock);

    // S3: an intent only with room for its done, a full revert, Applied and Closed.
    let j = Journal::with_limits(&app, InstanceTag::fixed(2), small(|l| l.records = 5));
    let lock = j.lock().unwrap();
    let mut w = lock.begin(HEAD).unwrap();
    assert!(too_large(w.intent(0, None, None)), "needs 6 records");
    let mut guard = g.guard(&r("a.bin")).unwrap();
    assert!(
        too_large(w.backup(&mut *guard).map(|_| ())),
        "checked before streaming"
    );
    drop(guard);
    let dir = txn_dir(w.id());
    drop(w);
    drop(lock);
    assert_eq!(names_in(&sys, &dir), ["head.json"]);

    let j = Journal::with_limits(&app, InstanceTag::fixed(6), small(|l| l.records = 8));
    let lock = j.lock().unwrap();
    let mut w = lock.begin(HEAD).unwrap();
    w.intent(0, None, None).unwrap();
    w.done(0, 1, false).unwrap();
    assert!(
        too_large(w.intent(1, None, None)),
        "op 1 would need 10 records"
    );
    // What is left is always enough to roll back and close.
    w.revert_intent(0, None).unwrap();
    w.revert_done(0, Observed::After, false).unwrap();
    let id = *w.id();
    w.close(Closing::RolledBack).unwrap();
    drop(lock);
    assert_eq!(
        j.load(&id, VerifyBackups::Length).unwrap().state,
        TxnState::Closed(Closing::RolledBack)
    );

    // The last slot is only for Closed: repeated revert intents cannot take it.
    let j = Journal::with_limits(&app, InstanceTag::fixed(7), small(|l| l.records = 6));
    let lock = j.lock().unwrap();
    let mut w = lock.begin(HEAD).unwrap();
    w.intent(0, None, None).unwrap();
    w.done(0, 1, false).unwrap();
    w.applied(1).unwrap();
    w.revert_intent(0, None).unwrap();
    w.revert_intent(0, None).unwrap();
    assert!(too_large(w.revert_intent(0, None)));
    let id = *w.id();
    w.close(Closing::Forgotten).unwrap();
    drop(lock);
    let v = j.load(&id, VerifyBackups::Length).unwrap();
    assert_eq!(
        (v.state, v.log.len()),
        (TxnState::Closed(Closing::Forgotten), 6)
    );

    let j = Journal::with_limits(&app, InstanceTag::fixed(3), small(|l| l.record = 80));
    let lock = j.lock().unwrap();
    let mut w = lock.begin(HEAD).unwrap();
    let tmp = Some(w.tmp());
    assert!(too_large(w.intent(0, tmp, None)));
    let id = *w.id();
    drop(w);
    drop(lock);
    assert_eq!(
        j.load(&id, VerifyBackups::Length).unwrap().state,
        TxnState::Empty
    );

    let j = Journal::with_limits(&app, InstanceTag::fixed(4), small(|l| l.backup = 9));
    let lock = j.lock().unwrap();
    let mut w = lock.begin(HEAD).unwrap();
    let mut guard = g.guard(&r("a.bin")).unwrap();
    assert!(too_large(w.backup(&mut *guard).map(|_| ())));
    drop(guard);
    let dir = txn_dir(w.id());
    drop(w);
    drop(lock);
    assert_eq!(names_in(&sys, &dir), ["head.json"]);

    let j = Journal::with_limits(&app, InstanceTag::fixed(5), small(|l| l.backups = 15));
    let lock = j.lock().unwrap();
    let mut w = lock.begin(HEAD).unwrap();
    let mut guard = g.guard(&r("a.bin")).unwrap();
    let b = w.backup(&mut *guard).unwrap();
    drop(guard);
    w.intent(0, None, Some(b)).unwrap();
    w.done(0, 1, false).unwrap();
    let mut guard = g.guard(&r("b.bin")).unwrap();
    assert!(too_large(w.backup(&mut *guard).map(|_| ())));
    drop(guard);
    let dir = txn_dir(w.id());
    drop(w);
    drop(lock);
    assert_eq!(
        names_in(&sys, &dir),
        ["0001.json", "0002.json", "head.json", "op-0000.bin"]
    );
}

#[test]
fn j9_reader_budgets() {
    let (sys, id) = tampered(|_, _| {});
    let app = open_app(&sys);
    let lim = |f: fn(&mut Limits)| Journal::with_limits(&app, InstanceTag::fixed(1), small(f));
    let st = |j: &Journal<'_>| j.load(&id, VerifyBackups::Length).unwrap().state;
    assert_eq!(
        st(&lim(|l| l.txn_entries = 6)),
        TxnState::Damaged(Damage::TooManyEntries)
    );
    assert_eq!(st(&lim(|l| l.txn_entries = 7)), TxnState::Applied);
    assert_eq!(
        st(&lim(|l| l.head = 4)),
        TxnState::Damaged(Damage::HeadTooLarge)
    );
    assert!(matches!(
        st(&lim(|l| l.record = 100)),
        TxnState::Damaged(Damage::TooLarge { n: 1 })
    ));
    // Records beyond the record limit are not records.
    assert_eq!(
        st(&lim(|l| l.records = 4)),
        TxnState::Damaged(Damage::UnknownEntry)
    );
    // `journal\` holds `lock` and one transaction.
    let e = lim(|l| l.journal_entries = 1).list().unwrap_err();
    assert!(
        matches!(e, JournalError::Sys(ref s) if s.kind == SysErrorKind::TooLarge),
        "{e}"
    );
    assert_eq!(lim(|l| l.journal_entries = 2).list().unwrap().txns.len(), 1);
}

// ---------- Review follow-ups ----------

#[test]
fn a_head_is_usable_only_when_a_record_confirmed_it() {
    // Swapped head.json and a mangled first record: nothing confirms the planted head.
    let (sys, id) = tampered(|s, d| {
        put(s, format!(r"{d}\head.json"), b"{\"planted\":1}");
        put(s, format!(r"{d}\0001.json"), b"{");
    });
    let v = read_back(&sys, &id, VerifyBackups::Length);
    assert_eq!(v.state, TxnState::Damaged(Damage::Unparsable { n: 1 }));
    assert!(!v.head_usable());
    // Damage at a later record: record 1 confirmed the head.
    let (sys, id) = tampered(|s, d| put(s, format!(r"{d}\0003.json"), b"{"));
    let v = read_back(&sys, &id, VerifyBackups::Length);
    assert_eq!(v.state, TxnState::Damaged(Damage::Unparsable { n: 3 }));
    assert!(v.head_usable());
    // Damage before the head was read, or of the head itself.
    for (what, f) in [
        (
            "head edited",
            Box::new(|s: &FakeSystem, d: &str| put(s, format!(r"{d}\head.json"), b"{}"))
                as Box<dyn FnOnce(&FakeSystem, &str)>,
        ),
        (
            "head removed",
            Box::new(|s: &FakeSystem, d: &str| {
                s.fake_fs()
                    .remove_abs(Path::new(&format!(r"{d}\head.json")))
                    .unwrap()
            }),
        ),
        (
            "gap at 1",
            Box::new(|s: &FakeSystem, d: &str| {
                s.fake_fs()
                    .remove_abs(Path::new(&format!(r"{d}\0001.json")))
                    .unwrap()
            }),
        ),
    ] {
        let (sys, id) = tampered(f);
        assert!(
            !read_back(&sys, &id, VerifyBackups::Length).head_usable(),
            "{what}"
        );
    }
    let (sys, id) = tampered(|_, _| {});
    let app = open_app(&sys);
    let small = Journal::with_limits(&app, InstanceTag::fixed(1), small(|l| l.txn_entries = 2));
    let v = small.load(&id, VerifyBackups::Length).unwrap();
    assert_eq!(
        (v.state.clone(), v.head_usable()),
        (TxnState::Damaged(Damage::TooManyEntries), false)
    );
    // A head without records (Empty) is usable; a clean applied one too.
    assert!(read_back(&sys, &id, VerifyBackups::Length).head_usable());
    let sys = system();
    let app = open_app(&sys);
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    let id = *lock.begin(HEAD).unwrap().id();
    let v = j.load(&id, VerifyBackups::Length).unwrap();
    assert_eq!((v.state.clone(), v.head_usable()), (TxnState::Empty, true));
}

#[test]
fn list_keeps_head_hashes_only_and_duplicates_keep_closed_and_first_causes() {
    let sys = system();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    let closed = {
        let w = apply2(&lock, &*g);
        let id = *w.id();
        w.close(Closing::Forgotten).unwrap();
        id
    };
    let applied = *apply2(&lock, &*g).id();
    drop(lock);
    let listed = j.list().unwrap();
    for l in &listed.txns {
        let v = l.view.as_ref().unwrap();
        assert_eq!((v.head.as_ref(), v.head_sha256), (None, Some(head_sha())));
        assert!(v.head_usable());
    }
    // Plant a twin of each seq; damage the applied one first.
    for id in [closed, applied] {
        let twin = TxnId::new(id.seq(), 0).unwrap();
        sys.fake_fs().mkdir_all(Path::new(&txn_dir(&twin))).unwrap();
    }
    put(&sys, format!(r"{}\notes.txt", txn_dir(&applied)), b"x");
    let listed = j.list().unwrap();
    let state = |id: TxnId| {
        let v = listed
            .txns
            .iter()
            .find(|l| l.id == id)
            .unwrap()
            .view
            .as_ref()
            .unwrap();
        (v.state.clone(), v.anomaly.clone())
    };
    assert_eq!(
        state(closed),
        (
            TxnState::Closed(Closing::Forgotten),
            Some(Damage::DuplicateSeq)
        )
    );
    assert_eq!(
        state(applied),
        (TxnState::Damaged(Damage::UnknownEntry), None)
    );
    assert_eq!(
        state(TxnId::new(closed.seq(), 0).unwrap()),
        (TxnState::Damaged(Damage::DuplicateSeq), None)
    );
    // `load` keeps the head bytes.
    assert_eq!(
        j.load(&closed, VerifyBackups::Length)
            .unwrap()
            .head
            .as_deref(),
        Some(HEAD)
    );
}

#[test]
fn a_backup_token_of_another_transaction_is_refused() {
    let sys = system();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    let mut w1 = lock.begin(HEAD).unwrap();
    let mut w2 = lock.begin(HEAD).unwrap();
    let mut guard = g.guard(&r("a.bin")).unwrap();
    let b1 = w1.backup(&mut *guard).unwrap();
    drop(guard);
    assert!(matches!(
        w2.intent(0, None, Some(b1)),
        Err(JournalError::Order(_))
    ));
    assert_eq!(state(&j, w2.id()), TxnState::Empty);
}

#[test]
fn resume_hands_out_the_hashed_head() {
    let sys = system();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    let id = *apply2(&lock, &*g).id();
    let w = lock.resume(&id).unwrap();
    assert_eq!(w.head(), HEAD);
}

/// Tamper helper for the `exec` tests: rewrites `head.json` of the transaction folder `dir`
/// (absolute, fake) to `head` and every record consistently with its hash, as someone who
/// knows the format would; `edit` may change each record. Returns the number of records.
pub(crate) fn rewrite(
    fx: &crate::sys::fake::FakeFs,
    dir: &str,
    head: Option<&[u8]>,
    mut edit: impl FnMut(&mut RecordEdit),
) -> u16 {
    let read = |name: &str| -> Option<Vec<u8>> {
        #[expect(clippy::disallowed_methods, reason = "test: read a fixture file")]
        let d = fx.open_dir(Path::new(dir)).ok()?;
        d.read(&r(name)).ok()
    };
    let old_head = read("head.json").unwrap();
    let old_sha: [u8; 32] =
        sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(&old_head)).into();
    let new_head = head.map_or(old_head.clone(), <[u8]>::to_vec);
    let new_sha: [u8; 32] =
        sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(&new_head)).into();
    let put = |name: &str, bytes: &[u8]| {
        let p = Path::new(dir).join(name);
        fx.remove_abs(&p).unwrap();
        fx.put_file(&p, bytes).unwrap();
    };
    let mut n = 1u16;
    while let Some(bytes) = read(&format!("{n:04}.json")) {
        let rec = record::decode(&bytes, n, &old_sha).unwrap();
        let mut e = RecordEdit(rec);
        edit(&mut e);
        put(
            &format!("{n:04}.json"),
            &record::encode(n, &new_sha, &e.0).unwrap(),
        );
        n += 1;
    }
    put("head.json", &new_head);
    n - 1
}

/// One record as [`rewrite`] passes it.
pub(crate) struct RecordEdit(Record);

impl RecordEdit {
    /// Sets the file ID of the `Done` of `op`.
    pub(crate) fn done_file_id(&mut self, of: u16, id: u128) {
        if let Record::Done { op, file_id, .. } = &mut self.0
            && *op == of
        {
            *file_id = id;
        }
    }
}

#[test]
fn d2_a_forget_marker_covers_the_head_it_names() {
    let sys = system();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    let j = Journal::new(&app, InstanceTag::fixed(TAG));
    let lock = j.lock().unwrap();
    let id = *apply2(&lock, &*g).id();
    // Damage it: a gap.
    let fx = sys.fake_fs();
    fx.put_file(Path::new(&format!(r"{}\0009.json", txn_dir(&id))), b"{}")
        .unwrap();
    let listed = |j: &Journal<'_>| j.list().unwrap().txns.into_iter().next().unwrap();
    let l = listed(&j);
    assert!(matches!(
        l.view.as_ref().unwrap().state,
        TxnState::Damaged(_)
    ));
    assert!(!l.forgotten);
    let head = l.view.as_ref().unwrap().head_sha256;
    lock.forget_marker(&id, head.as_ref()).unwrap();
    lock.forget_marker(&id, head.as_ref()).unwrap();
    assert!(listed(&j).forgotten);
    assert_eq!(j.list().unwrap().foreign, 0, "a marker is no foreign entry");
    match lock.forget_marker(&id, None) {
        Err(JournalError::MarkerInTheWay { path }) => {
            assert!(path.ends_with(&format!("{id}.forgotten")), "{path}");
        }
        other => panic!("{other:?}"),
    }
    // A head swapped in afterwards is not covered.
    fx.remove_abs(Path::new(&format!(r"{}\head.json", txn_dir(&id))))
        .unwrap();
    fx.put_file(Path::new(&format!(r"{}\head.json", txn_dir(&id))), b"{}")
        .unwrap();
    assert!(!listed(&j).forgotten);
    // A marker that is a folder does not count.
    let other = TxnId::new(5, 1).unwrap();
    fx.mkdir_all(Path::new(&format!(r"{JDIR}\{other}.forgotten")))
        .unwrap();
    assert_eq!(j.list().unwrap().foreign, 1);
}
