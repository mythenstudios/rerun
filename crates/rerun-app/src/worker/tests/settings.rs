//! The settings through the worker (P5-10b, ADR 0027 amendment P5-10), against the fake world:
//! - ST1 a session without a change: no Rerun folder before or after, also when the window sends
//!   the defaults;
//! - ST2 the first change creates `Rerun\app\settings.json` in its canonical form;
//! - ST3 the same settings again write nothing (the file keeps its ID);
//! - ST4 a broken file: the defaults, no event, and the next change replaces it;
//! - ST5 a newer format: the defaults, and the file stays byte for byte after changes;
//! - ST7 another Rerun wrote meanwhile: read once more, the last writer wins;
//! - ST9 elevated: nothing read at the start, nothing written;
//! - ST10 "Got it" and the grouping survive a restart (two sessions).

use std::path::Path;

use rerun_core::path::RelPath;
use rerun_core::sys::System;

use super::*;
use crate::settings::{Memo, Settings, Writable, at_start, encode};

const FILE: &str = r"C:\Users\Player\AppData\Local\Rerun\app\settings.json";
const RERUN: &str = r"C:\Users\Player\AppData\Local\Rerun";

/// The settings as `main` reads them before the window.
fn start(sys: &FakeSystem) -> Memo {
    let http = FakeHttp::default();
    let install = install();
    at_start(Env {
        sys,
        http: &http,
        install: &install,
    })
}

/// A session started like the app's.
fn session(sys: &FakeSystem) -> Session {
    Session {
        settings: start(sys),
        ..Session::default()
    }
}

#[expect(clippy::disallowed_methods, reason = "test: look at a fixture file")]
fn file(sys: &FakeSystem) -> Option<Vec<u8>> {
    let dir = sys.fs().open_dir(Path::new(FILE).parent()?).ok()?;
    dir.read(&RelPath::from_segment("settings.json").unwrap())
        .ok()
}

#[expect(clippy::disallowed_methods, reason = "test: look at a fixture file")]
fn file_id(sys: &FakeSystem) -> Option<u128> {
    let dir = sys.fs().open_dir(Path::new(FILE).parent()?).ok()?;
    Some(
        dir.metadata(&RelPath::from_segment("settings.json").unwrap())
            .ok()??
            .file_id,
    )
}

#[expect(clippy::disallowed_methods, reason = "test: look at a fixture file")]
fn rerun_exists(sys: &FakeSystem) -> bool {
    sys.fs().open_dir(Path::new(RERUN)).is_ok()
}

fn save(sys: &FakeSystem, session: &mut Session, s: &Settings) -> Vec<Event> {
    events_in(sys, session, &Job::SaveSettings(s.clone()))
}

#[test]
fn st1_a_session_without_a_change_creates_nothing() {
    let sys = indexed("Invented AC");
    // `indexed` imports the index (Rerun's folder exists); a bare world has none.
    let bare = bare().build().unwrap();
    for sys in [&bare, &sys] {
        let had = rerun_exists(sys);
        let mut s = session(sys);
        assert_eq!(s.settings.settings, Settings::default());
        assert_eq!(s.settings.writable(), Writable::Yes);
        // The window may send what it has: the defaults are no change.
        assert!(save(sys, &mut s, &Settings::default()).is_empty());
        for job in [Job::Library, Job::Status] {
            let _ = events_in(sys, &mut s, &job);
        }
        assert_eq!(rerun_exists(sys), had);
        assert_eq!(file(sys), None);
    }
}

#[test]
fn st2_st3_st10_a_change_is_written_once_and_survives_a_restart() {
    let sys = bare().build().unwrap();
    let mut s = session(&sys);
    let seen = Settings {
        intro_seen: true,
        ..Settings::default()
    };
    assert!(save(&sys, &mut s, &seen).is_empty(), "no event");
    assert_eq!(file(&sys), Some(encode(&seen)));
    assert_eq!(
        String::from_utf8(file(&sys).unwrap()).unwrap(),
        "{\"format\":1,\"language\":\"windows\",\"theme\":\"mythen\",\"library\":\"list\",\
         \"grouped\":true,\"intro_seen\":true}\n"
    );
    // The same again: nothing written.
    let id = file_id(&sys);
    save(&sys, &mut s, &seen);
    assert_eq!(file_id(&sys), id);
    // The grouping off.
    let both = Settings {
        grouped: false,
        ..seen
    };
    save(&sys, &mut s, &both);
    assert_ne!(file_id(&sys), id);
    // The next start has both.
    let again = session(&sys);
    assert_eq!(again.settings.settings, both);
    assert!(again.settings.settings.intro_seen);
    assert!(!again.settings.settings.grouped);
}

#[test]
fn st4_a_broken_file_is_replaced_by_the_next_change() {
    let sys = bare()
        .file(FILE, b"{\"format\":1,\"theme\":".to_vec())
        .build()
        .unwrap();
    let mut s = session(&sys);
    assert_eq!(s.settings.settings, Settings::default());
    assert_eq!(s.settings.writable(), Writable::Yes);
    // The defaults: no change, the broken file stays.
    save(&sys, &mut s, &Settings::default());
    assert_eq!(
        file(&sys).as_deref(),
        Some(&b"{\"format\":1,\"theme\":"[..])
    );
    let new = Settings {
        grouped: false,
        ..Settings::default()
    };
    assert!(save(&sys, &mut s, &new).is_empty());
    assert_eq!(file(&sys), Some(encode(&new)));
    // Too large: the same.
    let big = vec![b' '; 5000];
    let sys = bare().file(FILE, big).build().unwrap();
    let mut s = session(&sys);
    save(&sys, &mut s, &new);
    assert_eq!(file(&sys), Some(encode(&new)));
}

#[test]
fn st5_a_newer_format_is_never_written_over() {
    let newer = b"{\"format\":2,\"grouped\":false,\"accent\":\"stein\"}\n".to_vec();
    let sys = bare().file(FILE, newer.clone()).build().unwrap();
    let mut s = session(&sys);
    assert_eq!(s.settings.settings, Settings::default());
    assert_eq!(s.settings.writable(), Writable::SessionOnly);
    for grouped in [false, true, false] {
        let new = Settings {
            grouped,
            intro_seen: true,
            ..Settings::default()
        };
        assert!(save(&sys, &mut s, &new).is_empty());
        // The session has it; the file stays.
        assert_eq!(s.settings.settings, new);
        assert_eq!(file(&sys), Some(newer.clone()));
    }
}

#[test]
fn st7_another_rerun_wrote_meanwhile_the_last_writer_wins() {
    let sys = bare().build().unwrap();
    let mut s = session(&sys);
    // Another Rerun created the file after this one started.
    let theirs = encode(&Settings {
        grouped: false,
        ..Settings::default()
    });
    sys.fake_fs().put_file(Path::new(FILE), &theirs).unwrap();
    let mine = Settings {
        intro_seen: true,
        ..Settings::default()
    };
    save(&sys, &mut s, &mine);
    assert_eq!(file(&sys), Some(encode(&mine)));
    // And again with a file both read: changed by the other, then by this one.
    let theirs = encode(&Settings::default());
    sys.fake_fs().put_file(Path::new(FILE), &theirs).unwrap();
    let mine2 = Settings {
        grouped: false,
        ..mine
    };
    save(&sys, &mut s, &mine2);
    assert_eq!(file(&sys), Some(encode(&mine2)));
    // The other one now writes a newer format: this one keeps its hands off.
    let newer = b"{\"format\":2}".to_vec();
    sys.fake_fs().put_file(Path::new(FILE), &newer).unwrap();
    save(&sys, &mut s, &Settings::default());
    assert_eq!(file(&sys), Some(newer));
    assert_eq!(s.settings.writable(), Writable::SessionOnly);
}

#[test]
fn st9_elevated_nothing_is_read_or_written() {
    let mine = encode(&Settings {
        grouped: false,
        ..Settings::default()
    });
    let sys = bare().file(FILE, mine.clone()).build().unwrap();
    sys.fake_registry().set_elevated(true);
    let mut s = session(&sys);
    assert_eq!(s.settings, Memo::session_only());
    let ev = save(
        &sys,
        &mut s,
        &Settings {
            intro_seen: true,
            ..Settings::default()
        },
    );
    assert!(
        matches!(ev.as_slice(), [Event::Blocked(b)] if b.elevated),
        "{ev:?}"
    );
    assert_eq!(file(&sys), Some(mine));
    // Control: not elevated, the file is read.
    sys.fake_registry().set_elevated(false);
    assert!(!session(&sys).settings.settings.grouped);
}
