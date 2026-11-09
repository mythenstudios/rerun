//! `rerun index import` and `rerun index show` (ADR 0024) against the fake, signed with the
//! published test key (feature `test-key`, dev-dependency only).

use std::path::Path;

use rerun_core::catalog::key::test_key;
use rerun_core::sys::fake::FakeSystem;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::tests::{RERUN, bare, expect};

const INDEX: &str = r"D:\Work\index.json";
const SIG: &str = r"D:\Work\index.json.sig";

fn index(seq: u64, issued: &str) -> Vec<u8> {
    format!(r#"{{"format":1,"seq":{seq},"issued":"{issued}","topos":[],"packages":[]}}"#)
        .into_bytes()
}

fn sys() -> FakeSystem {
    let sys = bare().dir(r"D:\Work").build().unwrap();
    sys.fake_fs().sync_all();
    sys
}

fn put(sys: &FakeSystem, index: &[u8], sig: &[u8]) {
    sys.fake_fs().put_file(Path::new(INDEX), index).unwrap();
    sys.fake_fs().put_file(Path::new(SIG), sig).unwrap();
}

fn put_signed(sys: &FakeSystem, seq: u64, issued: &str) {
    let b = index(seq, issued);
    put(sys, &b, &test_key::sign(&b));
}

fn rerun_exists(sys: &FakeSystem) -> bool {
    #[expect(clippy::disallowed_methods, reason = "test: look at the fake's folder")]
    let d = rerun_core::sys::Fs::open_dir(sys.fake_fs(), Path::new(RERUN));
    d.is_ok()
}

#[test]
fn import_then_show() {
    let sys = sys();
    let r = expect(&sys, &["index", "show"], Answer::No, Exit::Report);
    assert!(
        r.stdout
            .starts_with("no signed index has been imported yet"),
        "{}",
        r.stdout
    );
    assert!(!rerun_exists(&sys), "show creates nothing");

    put_signed(&sys, 3, "2026-11-09T12:00:00Z");
    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
    assert!(r.stdout.starts_with("index 3 imported\n"), "{}", r.stdout);
    assert!(
        r.stdout
            .contains(&format!("key {}", test_key::public().id()))
    );
    assert!(r.stdout.contains("  issued: 2026-11-09T12:00:00Z\n"));

    let r = expect(&sys, &["index", "show"], Answer::No, Exit::Report);
    assert!(
        r.stdout.starts_with("index 3: 0 topos, 0 packages, key "),
        "{}",
        r.stdout
    );

    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
    assert!(
        r.stdout.starts_with("index 3 is already the current index"),
        "{}",
        r.stdout
    );

    put_signed(&sys, 4, "2026-11-10T12:00:00Z");
    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
    assert!(
        r.stdout.starts_with("index 4 imported (replaces index 3)"),
        "{}",
        r.stdout
    );
}

#[test]
fn an_older_index_or_a_second_one_with_the_same_number_is_refused() {
    let sys = sys();
    put_signed(&sys, 5, "2026-11-09T12:00:00Z");
    expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );

    put_signed(&sys, 4, "2026-11-09T12:00:00Z");
    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Refused,
    );
    assert!(r.stderr.contains("rollback is refused"), "{}", r.stderr);

    put_signed(&sys, 5, "2026-11-11T12:00:00Z");
    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Refused,
    );
    assert!(r.stderr.contains("same number 5"), "{}", r.stderr);

    let r = expect(&sys, &["index", "show"], Answer::No, Exit::Report);
    assert!(r.stdout.starts_with("index 5:"), "{}", r.stdout);
    assert!(r.stdout.contains("2026-11-09T12:00:00Z"), "{}", r.stdout);
}

#[test]
fn a_bad_signature_is_refused_and_creates_nothing() {
    let sys = sys();
    let b = index(1, "2026-11-09T12:00:00Z");
    put(&sys, &b, &test_key::sign_foreign(&b));
    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        r.stderr
            .starts_with("rerun: index refused: the signature does not match the index"),
        "{}",
        r.stderr
    );
    assert!(!rerun_exists(&sys), "a refused index creates no folder");

    // Changed after signing.
    let mut changed = b.clone();
    changed[b.len() - 3] = b' ';
    put(&sys, &changed, &test_key::sign(&b));
    expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Refused,
    );

    // A signature file of the wrong length: one byte more is refused while reading.
    put(&sys, &b, &[test_key::sign(&b).as_slice(), &[0]].concat());
    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        r.stderr
            .starts_with("rerun: cannot read the signature file"),
        "{}",
        r.stderr
    );
    put(&sys, &b, &test_key::sign(&b)[..63]);
    expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Refused,
    );

    // Signed bytes that are no index: refused after the signature, by position only.
    let junk = br#"{"format":1,"seq":1,"issued":"\u001b[2J"}"#.to_vec();
    put(&sys, &junk, &test_key::sign(&junk));
    let r = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        r.stderr
            .contains("is not a valid index (data at line 1, column"),
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains('\u{1b}'));
    assert!(!rerun_exists(&sys));
}

#[test]
fn import_is_refused_when_elevated() {
    let sys = sys();
    put_signed(&sys, 1, "2026-11-09T12:00:00Z");
    sys.fake_registry().set_elevated(true);
    expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Refused,
    );
    assert!(!rerun_exists(&sys));
}
