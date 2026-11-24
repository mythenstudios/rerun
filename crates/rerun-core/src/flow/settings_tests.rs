//! The settings file (P5-10b, ADR 0027 amendment P5-10) against the fake world:
//! - ST1 no file: a read creates nothing (no Rerun folder before or after);
//! - ST2 the first write creates `Rerun\app\settings.json` with exactly the bytes;
//! - ST3 the same bytes again write nothing (the file keeps its ID);
//! - ST4 a file over the bound is unusable but replaced by the next write; one too large to hash
//!   is never written over; more than the bound to write is refused;
//! - ST6 a junction at `app`, a file symlink, a hard link or a folder in the file's place is
//!   unusable, and a write is refused without writing anything outside;
//! - ST7 compare-and-swap: a file changed or created since the read is `Changed`, nothing written;
//! - ST8 a crash after any call of a create or a replace leaves the old or the new file, never a
//!   torn one (between the two renames of a replace: none, the defaults); the next write goes
//!   through;
//! - ST9 elevated: the guard stops before anything is read.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{
    SETTINGS_MAX, Seen, SettingsError, SettingsRead, Unusable, read_settings, write_settings,
};
use crate::flow::{Env, Gate, Guarded, guard};
use crate::path::RelPath;
use crate::policy::root::{AppDir, Create};
use crate::sys::System;
use crate::sys::fake::{FakeHttp, FakeSystem, FakeSystemBuilder, Fault};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const RERUN: &str = r"C:\Users\Player\AppData\Local\Rerun";
const APP: &str = r"C:\Users\Player\AppData\Local\Rerun\app";
const FILE: &str = r"C:\Users\Player\AppData\Local\Rerun\app\settings.json";

const OLD: &[u8] = b"{\"format\":1,\"grouped\":false}\n";
const NEW: &[u8] = b"{\"format\":1,\"grouped\":true}\n";

fn base() -> FakeSystemBuilder {
    FakeSystem::builder().windows_layout().dir(INSTALL)
}

fn with_guard<R>(sys: &FakeSystem, f: impl FnOnce(&mut Guarded<'_>) -> R) -> R {
    let http = FakeHttp::default();
    let ok: Result<PathBuf, String> = Ok(PathBuf::from(INSTALL));
    let mut g = guard(Env {
        sys,
        http: &http,
        install: &ok,
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    f(&mut g)
}

fn read(sys: &FakeSystem) -> SettingsRead {
    with_guard(sys, |g| read_settings(g))
}

fn write(sys: &FakeSystem, bytes: &[u8], seen: &Seen) -> Result<Seen, SettingsError> {
    with_guard(sys, |g| write_settings(g, bytes, seen))
}

fn hash(b: &[u8]) -> Seen {
    Seen::Hash(Sha256::digest(b).into())
}

fn seg(s: &str) -> RelPath {
    RelPath::from_segment(s).unwrap()
}

/// The bytes at `abs`, or `None`; read through the fake's read side, never following a link.
#[expect(clippy::disallowed_methods, reason = "test: look at a fixture file")]
fn file_at(sys: &FakeSystem, abs: &str) -> Option<Vec<u8>> {
    let p = Path::new(abs);
    let dir = sys.fs().open_dir(p.parent()?).ok()?;
    let name = seg(p.file_name()?.to_str()?);
    dir.read(&name).ok()
}

#[expect(clippy::disallowed_methods, reason = "test: look at a fixture file")]
fn file_id(sys: &FakeSystem) -> u128 {
    let dir = sys.fs().open_dir(Path::new(APP)).unwrap();
    dir.metadata(&seg("settings.json"))
        .unwrap()
        .unwrap()
        .file_id
}

#[expect(clippy::disallowed_methods, reason = "test: look at a fixture file")]
fn exists(sys: &FakeSystem, abs: &str) -> bool {
    let p = Path::new(abs);
    let Ok(dir) = sys.fs().open_dir(p.parent().unwrap()) else {
        return false;
    };
    dir.metadata(&seg(p.file_name().unwrap().to_str().unwrap()))
        .unwrap()
        .is_some()
}

#[expect(clippy::disallowed_methods, reason = "test: look at a fixture file")]
fn entries(sys: &FakeSystem) -> usize {
    let dir = sys.fs().open_dir(Path::new(APP)).unwrap();
    dir.read_dir(None).unwrap().len()
}

#[test]
fn st1_a_read_creates_nothing() {
    let sys = base().build().unwrap();
    assert!(!exists(&sys, RERUN));
    assert_eq!(read(&sys), SettingsRead::Absent);
    assert!(!exists(&sys, RERUN));
    // Rerun's folder without `app`, and `app` without the file: absent too, nothing created.
    let sys = base().dir(RERUN).build().unwrap();
    assert_eq!(read(&sys), SettingsRead::Absent);
    assert!(!exists(&sys, APP));
    let sys = base().dir(APP).build().unwrap();
    assert_eq!(read(&sys), SettingsRead::Absent);
    assert!(!exists(&sys, FILE));
}

#[test]
fn st2_st3_the_first_write_creates_the_file_and_the_same_bytes_write_nothing() {
    let sys = base().build().unwrap();
    let seen = write(&sys, NEW, &Seen::Absent).unwrap();
    assert_eq!(seen, hash(NEW));
    assert_eq!(file_at(&sys, FILE).as_deref(), Some(NEW));
    assert_eq!(
        read(&sys),
        SettingsRead::Bytes {
            bytes: NEW.to_vec(),
            seen: hash(NEW)
        }
    );
    // The same bytes: no write at all (the file keeps its identity).
    let id = file_id(&sys);
    assert_eq!(write(&sys, NEW, &seen).unwrap(), seen);
    assert_eq!(file_id(&sys), id);
    // Other bytes: replaced (a new file under the same name).
    let seen = write(&sys, OLD, &seen).unwrap();
    assert_eq!(seen, hash(OLD));
    assert_eq!(file_at(&sys, FILE).as_deref(), Some(OLD));
    assert_ne!(file_id(&sys), id);
    // Nothing else in `app` (the temp file is gone).
    assert_eq!(entries(&sys), 1);
}

#[test]
fn st4_an_oversized_file_is_unusable_and_replaced_by_the_next_write() {
    let big = vec![b' '; usize::try_from(SETTINGS_MAX).unwrap() + 1];
    let sys = base().file(FILE, big.clone()).build().unwrap();
    let r = read(&sys);
    assert_eq!(
        r,
        SettingsRead::Unusable {
            why: Unusable::TooLarge,
            seen: hash(&big)
        }
    );
    write(&sys, NEW, &r.seen()).unwrap();
    assert_eq!(file_at(&sys, FILE).as_deref(), Some(NEW));
    // Exactly the bound is read.
    let edge = vec![b' '; usize::try_from(SETTINGS_MAX).unwrap()];
    let sys = base().file(FILE, edge.clone()).build().unwrap();
    assert!(matches!(read(&sys), SettingsRead::Bytes { bytes, .. } if bytes == edge));
    // Too large to hash: never written over.
    let huge = vec![b' '; (1 << 20) + 1];
    let sys = base().file(FILE, huge.clone()).build().unwrap();
    let r = read(&sys);
    assert_eq!(
        r,
        SettingsRead::Unusable {
            why: Unusable::TooLarge,
            seen: Seen::Unknown
        }
    );
    assert!(matches!(
        write(&sys, NEW, &r.seen()),
        Err(SettingsError::Unwritable(_))
    ));
    assert_eq!(file_at(&sys, FILE), Some(huge));
    // More than the bound to write: refused, nothing created.
    let sys = base().build().unwrap();
    assert_eq!(
        write(&sys, &big, &Seen::Absent),
        Err(SettingsError::TooLarge)
    );
    assert!(!exists(&sys, RERUN));
}

#[test]
fn st6_links_and_folders_are_unusable_and_never_written_through() {
    let elsewhere = r"C:\Elsewhere";
    let outside = r"C:\Elsewhere\settings.json";
    // A junction at `app`.
    let sys = base()
        .file(outside, OLD.to_vec())
        .dir(RERUN)
        .junction(APP, elsewhere)
        .build()
        .unwrap();
    let r = read(&sys);
    assert!(
        matches!(
            &r,
            SettingsRead::Unusable {
                why: Unusable::Folder(_),
                seen: Seen::Unknown
            }
        ),
        "{r:?}"
    );
    for seen in [Seen::Absent, hash(OLD)] {
        assert!(
            matches!(
                write(&sys, NEW, &seen),
                Err(SettingsError::Unwritable(Unusable::Folder(_)))
            ),
            "{seen:?}"
        );
    }
    assert_eq!(file_at(&sys, outside).as_deref(), Some(OLD));
    // A file symlink in the file's place.
    let sys = base()
        .file(outside, OLD.to_vec())
        .dir(APP)
        .file_symlink(FILE, outside)
        .build()
        .unwrap();
    assert_eq!(
        read(&sys),
        SettingsRead::Unusable {
            why: Unusable::Link,
            seen: Seen::Unknown
        }
    );
    for seen in [Seen::Absent, hash(OLD)] {
        assert!(write(&sys, NEW, &seen).is_err(), "{seen:?}");
    }
    assert_eq!(file_at(&sys, outside).as_deref(), Some(OLD));
    // A hard link: the other name is never changed.
    let sys = base()
        .file(outside, OLD.to_vec())
        .dir(APP)
        .hardlink(outside, FILE)
        .build()
        .unwrap();
    assert_eq!(
        read(&sys),
        SettingsRead::Unusable {
            why: Unusable::Link,
            seen: Seen::Unknown
        }
    );
    assert!(matches!(
        write(&sys, NEW, &hash(OLD)),
        Err(SettingsError::Unwritable(Unusable::Link))
    ));
    assert_eq!(file_at(&sys, outside).as_deref(), Some(OLD));
    assert_eq!(file_at(&sys, FILE).as_deref(), Some(OLD));
    // A folder in the file's place.
    let sys = base().dir(FILE).build().unwrap();
    assert_eq!(
        read(&sys),
        SettingsRead::Unusable {
            why: Unusable::NotAFile,
            seen: Seen::Unknown
        }
    );
    assert!(write(&sys, NEW, &Seen::Absent).is_err());
    assert!(write(&sys, NEW, &hash(OLD)).is_err());
}

#[test]
fn st7_a_file_changed_since_the_read_is_not_overwritten() {
    // Read, then another Rerun writes: `Changed`, its bytes stay.
    let sys = base().file(FILE, OLD.to_vec()).build().unwrap();
    let seen = read(&sys).seen();
    let theirs = b"{\"format\":1,\"theme\":\"mythen\"}\n";
    sys.fake_fs().put_file(Path::new(FILE), theirs).unwrap();
    assert_eq!(write(&sys, NEW, &seen), Err(SettingsError::Changed));
    assert_eq!(file_at(&sys, FILE).as_deref(), Some(&theirs[..]));
    // Read again: the write goes through.
    let seen = read(&sys).seen();
    write(&sys, NEW, &seen).unwrap();
    assert_eq!(file_at(&sys, FILE).as_deref(), Some(NEW));
    // Absent at the read, created since: `Changed`.
    let sys = base().build().unwrap();
    let seen = read(&sys).seen();
    assert_eq!(seen, Seen::Absent);
    sys.fake_fs().put_file(Path::new(FILE), theirs).unwrap();
    assert_eq!(write(&sys, NEW, &seen), Err(SettingsError::Changed));
    assert_eq!(file_at(&sys, FILE).as_deref(), Some(&theirs[..]));
    // Removed since: `Changed`, nothing created.
    let sys = base().file(FILE, OLD.to_vec()).build().unwrap();
    let seen = read(&sys).seen();
    sys.fake_fs().remove_abs(Path::new(FILE)).unwrap();
    assert_eq!(write(&sys, NEW, &seen), Err(SettingsError::Changed));
    assert!(!exists(&sys, FILE));
}

/// Every call a write from `seen` makes, in order (with its occurrence).
fn calls_of(make: &dyn Fn() -> FakeSystem, seen: &Seen) -> Vec<(crate::sys::fake::Prim, usize)> {
    let sys = make();
    let fx = sys.fake_fs();
    with_guard(&sys, |g| {
        fx.clear_faults();
        fx.record_calls(true);
        write_settings(g, NEW, seen).unwrap();
        fx.record_calls(false);
    });
    let calls = fx.take_calls();
    calls
        .iter()
        .enumerate()
        .map(|(i, c)| (*c, calls[..=i].iter().filter(|x| *x == c).count()))
        .collect()
}

/// A world, what a write expects there, and the bytes there before.
type Case<'a> = (&'a dyn Fn() -> FakeSystem, Seen, Option<&'a [u8]>);

#[test]
fn st8_a_crash_after_any_call_leaves_the_old_or_the_new_file() {
    let fresh = || base().build().unwrap();
    let existing = || base().file(FILE, OLD.to_vec()).build().unwrap();
    let cases: [Case<'_>; 2] = [
        (&fresh, Seen::Absent, None),
        (&existing, hash(OLD), Some(OLD)),
    ];
    let mut bad = Vec::new();
    for (make, seen, before) in cases {
        let calls = calls_of(make, &seen);
        assert!(calls.len() > 5, "{calls:?}");
        for (call, nth) in calls {
            let sys = make();
            let fx = sys.fake_fs();
            with_guard(&sys, |g| {
                fx.clear_faults();
                fx.fault(call, nth, Fault::CrashAfter);
                let _ = write_settings(g, NEW, &seen);
            });
            if !fx.crashed() {
                bad.push(format!("{call:?} #{nth}: no crash"));
                continue;
            }
            sys.restart();
            let now = file_at(&sys, FILE);
            // Between the two renames of a replace the name is free: no file, so the next start
            // takes the defaults (the old bytes stay in `<tmp>.old`). Never a torn file.
            let gap = before.is_some() && now.is_none();
            if now.as_deref() != before && now.as_deref() != Some(NEW) && !gap {
                bad.push(format!("{call:?} #{nth}: {now:?}"));
            }
            // The next start reads it or the defaults, and the next write goes through.
            let seen = read(&sys).seen();
            if let Err(e) = write(&sys, NEW, &seen) {
                bad.push(format!("{call:?} #{nth}: next write {e:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn st9_elevated_nothing_is_read() {
    let sys = base().file(FILE, OLD.to_vec()).build().unwrap();
    sys.fake_registry().set_elevated(true);
    let http = FakeHttp::default();
    let ok: Result<PathBuf, String> = Ok(PathBuf::from(INSTALL));
    sys.fake_fs().record_calls(true);
    let g = guard(Env {
        sys: &sys,
        http: &http,
        install: &ok,
    });
    assert!(matches!(g, Err(Gate::Elevated(_))));
    sys.fake_fs().record_calls(false);
    assert!(sys.fake_fs().take_calls().is_empty());
    // Control: not elevated, the same file is read.
    sys.fake_registry().set_elevated(false);
    assert!(matches!(read(&sys), SettingsRead::Bytes { .. }));
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_some());
}
