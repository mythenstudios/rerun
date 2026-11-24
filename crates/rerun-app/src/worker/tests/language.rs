//! The language and the library view (P5-10d, E3 b, E2 a):
//! - LG1 the worker speaks the language it was last given: the rows, the library summary and the
//!   pages it caches (the system page) come out in the new one, without a restart;
//! - LG2 the fixed pieces of a row for the compact view (the name, the status symbol and the
//!   status word) are in both languages and differ in the word;
//! - LG3 a language or view change is written once, only when it really changes, and survives a
//!   restart; the defaults without a file are no change.

use std::path::Path;

use rerun_core::path::RelPath;

use super::*;
use crate::settings::{LangChoice, LibView, Settings, at_start, decode, encode};

use rerun_core::sys::System;

const FILE: &str = r"C:\Users\Player\AppData\Local\Rerun\app\settings.json";

fn world(
    sys: FakeSystem,
) -> impl FnOnce(rerun_core::sys::PromptOwnerSlot) -> Result<World, escape::Shown<'static>> {
    move |_| {
        Ok(World {
            shell: std::sync::Arc::new(rerun_core::sys::NoShell),
            sys: Box::new(sys),
            http: Box::new(FakeHttp::default()),
            install: install(),
        })
    }
}

#[test]
fn lg1_a_new_language_reaches_the_rows_and_the_cached_pages_without_a_restart() {
    let probe = indexed("Invented AC");
    let n = events(&probe, &Job::Library, Lang::En).len();
    let worker = Worker::start(
        Lang::En,
        crate::settings::Memo::default(),
        world(indexed("Invented AC")),
        Box::new(super::Count(Arc::new(AtomicUsize::new(0)))),
    )
    .unwrap();

    worker.send(Job::Library);
    worker.send(Job::System);
    let en = wait_for(&worker, n + 1);
    worker.set_lang(Lang::De);
    worker.send(Job::Library);
    worker.send(Job::System);
    let de = wait_for(&worker, n + 1);

    let words = |ev: &[Event]| -> Vec<String> {
        rows_of(ev).iter().map(|r| r.badge.word.clone()).collect()
    };
    assert!(!words(&en).is_empty());
    assert_eq!(words(&en).len(), words(&de).len());
    assert_ne!(
        words(&en),
        words(&de),
        "the status words follow the language"
    );
    assert_eq!(words(&en), words(&events(&probe, &Job::Library, Lang::En)));
    assert_eq!(words(&de), words(&events(&probe, &Job::Library, Lang::De)));

    let summary = |ev: &[Event]| {
        ev.iter()
            .find_map(|e| match e {
                Event::LibraryDone(l) => Some(l.summary.clone()),
                _ => None,
            })
            .unwrap()
    };
    assert_ne!(summary(&en), summary(&de));
    // The system page is cached in the session: it is made again in the new language.
    let label = |ev: &[Event]| {
        ev.iter()
            .find_map(|e| match e {
                Event::System(s) => Some(s.lines[0].label.clone()),
                _ => None,
            })
            .unwrap()
    };
    assert_ne!(label(&en), label(&de));
    // And back.
    worker.set_lang(Lang::En);
    worker.send(Job::System);
    assert_eq!(label(&wait_for(&worker, 1)), label(&en));
}

#[test]
fn lg2_a_compact_row_has_its_name_its_symbol_and_its_word_in_both_languages() {
    let sys = indexed("Invented AC");
    for lang in Lang::ALL {
        let ev = events(&sys, &Job::Library, lang);
        let rows = rows_of(&ev);
        assert!(!rows.is_empty());
        for r in &rows {
            assert!(!r.name.as_str().is_empty());
            assert!(!r.badge.sym.glyph().is_empty());
            assert!(
                !r.badge.word.is_empty(),
                "{lang:?}: a symbol never stands alone"
            );
        }
    }
}

#[test]
fn lg3_a_language_or_view_change_is_written_once_and_survives_a_restart() {
    let sys = bare().build().unwrap();
    let start = |sys: &FakeSystem| {
        let http = FakeHttp::default();
        let install = install();
        at_start(Env {
            sys,
            http: &http,
            install: &install,
        })
    };
    let mut s = Session {
        settings: start(&sys),
        ..Session::default()
    };
    let file = |sys: &FakeSystem| -> Option<Vec<u8>> {
        #[expect(clippy::disallowed_methods, reason = "test: look at a fixture file")]
        let dir = sys.fs().open_dir(Path::new(FILE).parent()?).ok()?;
        dir.read(&RelPath::from_segment("settings.json").unwrap())
            .ok()
    };
    // The defaults are no change (the window sends what it has).
    events_in(&sys, &mut s, &Job::SaveSettings(Settings::default()));
    assert_eq!(file(&sys), None);
    let german = Settings {
        language: LangChoice::De,
        library: LibView::Compact,
        ..Settings::default()
    };
    events_in(&sys, &mut s, &Job::SaveSettings(german.clone()));
    let written = file(&sys).unwrap();
    assert_eq!(written, encode(&german));
    assert!(
        String::from_utf8(written.clone())
            .unwrap()
            .contains("\"language\":\"de\"")
    );
    // The same again: the file stays as it is.
    events_in(&sys, &mut s, &Job::SaveSettings(german.clone()));
    assert_eq!(file(&sys), Some(written));
    // The next start has them.
    assert_eq!(start(&sys).settings, german);
    let again = decode(&rerun_core::flow::SettingsRead::Bytes {
        bytes: encode(&german),
        seen: rerun_core::flow::Seen::Unknown,
    });
    assert_eq!(again.0, german);
}
