//! `rerun package list | remove | prune` (P5-8b-2) against the fake: the golden lists, every
//! file in a preview, the stays with their reasons and users, the exit codes (0 done or nothing
//! to do, 3 refused, 1 a lock or a file in use, 2 no console), and that `--dry-run`, a declined
//! question and a refusal change nothing.

use std::path::Path;

use rerun_core::journal::{InstanceTag, Journal};
use rerun_core::policy::root::{AppDir, Create};
use rerun_core::sys::contract::{Access, Share};
use rerun_core::sys::fake::FakeSystem;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::tests::{RERUN, applied, build, expect, file_steps, same, snap_all, with_package};

const PREVIEW: &str = "Removed from Rerun's package store:\n  fix-pack 1.0.2  not in the signed \
     index (cannot be downloaded again)  unpacked, 2 files, 45 bytes\n    d3d9.dll\n    new.dll\n\
     Game folders, the registry and the firewall stay unchanged. Undoing a fix never needs a \
     package.\n\n";

fn put(sys: &FakeSystem, rel: &str, data: &[u8]) {
    sys.fake_fs()
        .put_file(Path::new(&format!(r"{RERUN}\{rel}")), data)
        .unwrap();
}

#[test]
fn list_shows_every_part_and_who_uses_it() {
    let sys = build(with_package(), &file_steps());
    let t = applied(&sys);
    put(
        &sys,
        &format!(r"cache\{}", "cd".repeat(32)),
        b"older archive",
    );
    put(&sys, r"cache\.rerun-00000000000000ab-0.tmp", b"half");
    put(&sys, r"packages\Bad", b"x");
    let before = snap_all(&sys);
    let r = expect(&sys, &["package", "list"], Answer::No, Exit::Report);
    assert_eq!(
        r.stdout,
        format!(
            "Packages:\n  fix-pack 1.0.2  not in the signed index (cannot be downloaded again)  \
             unpacked, 2 files, 45 bytes\n    used by {t}  applied\n    stays: used by a \
             transaction that is not settled; revert it first\nArchives without a package:\n  \
             {}  13 bytes\n1 leftover of interrupted runs, 4 bytes\nNot Rerun's (never \
             touched):\n  packages\\Bad: a name that is not Rerun's\n",
            "cd".repeat(32)
        )
    );
    same(&before, &snap_all(&sys));

    // No Rerun folder: an empty store.
    let sys = build(crate::tests::bare(), &file_steps());
    let r = expect(&sys, &["package", "list"], Answer::No, Exit::Report);
    assert_eq!(r.stdout, "Rerun's package store is empty\n");
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
}

#[test]
fn remove_lists_every_file_asks_and_removes_exactly_that() {
    let sys = build(with_package(), &file_steps());
    let t = applied(&sys);
    // Used: the stays with the transaction, exit 3, nothing removed.
    let before = snap_all(&sys);
    let r = expect(
        &sys,
        &["package", "remove", "fix-pack@1.0.2", "--dry-run"],
        Answer::No,
        Exit::Refused,
    );
    assert_eq!(
        r.stdout,
        format!(
            "Stays:\n  fix-pack 1.0.2: used by a transaction that is not settled; revert it \
             first\n    used by {t}  applied\nnothing to remove\n"
        )
    );
    expect(
        &sys,
        &["package", "remove", "fix-pack@1.0.2", "--yes"],
        Answer::No,
        Exit::Refused,
    );
    same(&before, &snap_all(&sys));

    // Reverted: the preview lists every file.
    expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    let before = snap_all(&sys);
    let r = expect(
        &sys,
        &["package", "remove", "fix-pack@1.0.2", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert_eq!(r.stdout, PREVIEW);
    same(&before, &snap_all(&sys));
    // Declined: 3, nothing removed; no console without --yes: 2.
    let no = expect(
        &sys,
        &["package", "remove", "fix-pack@1.0.2"],
        Answer::No,
        Exit::Refused,
    );
    assert_eq!(
        no.asked,
        ["Remove 1 package, 0 archives without a package and 0 leftovers (45 bytes)? [y/N]"]
    );
    expect(
        &sys,
        &["package", "remove", "fix-pack@1.0.2"],
        Answer::NoConsole,
        Exit::Usage,
    );
    same(&before, &snap_all(&sys));
    let yes = expect(
        &sys,
        &["package", "remove", "fix-pack@1.0.2", "--yes"],
        Answer::No,
        Exit::Report,
    );
    assert_eq!(
        yes.stdout,
        format!("{PREVIEW}1 package, 0 archives and 0 leftovers removed, 45 bytes freed\n")
    );
    // Gone now: not in the store, 3.
    let r = expect(
        &sys,
        &["package", "remove", "fix-pack@1.0.2"],
        Answer::No,
        Exit::Refused,
    );
    assert_eq!(
        r.stderr,
        "rerun: package fix-pack@1.0.2 is not in Rerun's package store\n"
    );
    // The fix can be planned again only after a fetch: the revert needed nothing.
    let s = expect(&sys, &["status", "--all"], Answer::No, Exit::Report);
    assert!(s.stdout.contains(&t), "{}", s.stdout);
}

#[test]
fn prune_removes_everything_unused_and_then_has_nothing_to_do() {
    let sys = build(with_package(), &file_steps());
    let archive = "cd".repeat(32);
    put(&sys, &format!(r"cache\{archive}"), b"older archive");
    put(&sys, r"cache\.rerun-00000000000000ab-0.tmp", b"half");
    let before = snap_all(&sys);
    let r = expect(
        &sys,
        &["package", "prune", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    let goes = format!(
        "Removed from Rerun's package store:\n  fix-pack 1.0.2  not in the signed index (cannot \
         be downloaded again)  unpacked, 2 files, 45 bytes\n    d3d9.dll\n    new.dll\n  \
         {archive}  13 bytes\n1 leftover of interrupted runs, 4 bytes\nGame folders, the \
         registry and the firewall stay unchanged. Undoing a fix never needs a package.\n\n"
    );
    assert_eq!(r.stdout, goes);
    same(&before, &snap_all(&sys));
    let no = expect(&sys, &["package", "prune"], Answer::No, Exit::Refused);
    assert_eq!(
        no.asked,
        ["Remove 1 package, 1 archive without a package and 1 leftover (62 bytes)? [y/N]"]
    );
    let yes = expect(&sys, &["package", "prune"], Answer::Yes, Exit::Report);
    assert!(
        yes.stdout
            .ends_with("1 package, 1 archive and 1 leftover removed, 62 bytes freed\n"),
        "{}",
        yes.stdout
    );
    let again = expect(
        &sys,
        &["package", "prune", "--yes"],
        Answer::No,
        Exit::Report,
    );
    assert_eq!(again.stdout, "nothing to remove\n");
    // No Rerun folder at all: nothing to do.
    let sys = build(crate::tests::bare(), &file_steps());
    let r = expect(&sys, &["package", "prune"], Answer::No, Exit::Report);
    assert_eq!(r.stdout, "nothing to remove\n");
}

#[test]
fn a_lock_or_a_file_in_use_is_exit_1_and_elevated_is_refused() {
    // Another Rerun holds the journal lock: 1, nothing removed.
    let sys = build(with_package(), &file_steps());
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    let j = Journal::new(&app, InstanceTag::fixed(0x77));
    drop(j.lock().unwrap());
    let before = snap_all(&sys);
    let lock = j.lock().unwrap();
    let r = expect(
        &sys,
        &["package", "prune", "--yes"],
        Answer::No,
        Exit::Fatal,
    );
    assert!(r.stderr.starts_with("rerun: another Rerun"), "{}", r.stderr);
    drop(lock);
    drop(j);
    drop(app);
    same(&before, &snap_all(&sys));
    let pkg = |f: &str| format!(r"{RERUN}\packages\fix-pack\1.0.2\{f}");

    // A scanner holds a file: the package stays, named with its reason, exit 1.
    let held = sys
        .fake_fs()
        .hold_open_as(4242, Path::new(&pkg("new.dll")), Access::READ, Share::RW)
        .unwrap();
    let r = expect(
        &sys,
        &["package", "prune", "--yes"],
        Answer::No,
        Exit::Fatal,
    );
    assert!(
        r.stdout.ends_with(
            // `d3d9.dll` went before the held `new.dll` stopped the package.
            "0 packages, 0 archives and 0 leftovers removed, 23 bytes freed\nStays:\n  \
             fix-pack@1.0.2: in use right now (a scanner, say); try again later\n"
        ),
        "{}",
        r.stdout
    );
    drop(held);
    expect(
        &sys,
        &["package", "prune", "--yes"],
        Answer::No,
        Exit::Report,
    );

    // Elevated: refused before anything is read.
    let sys = build(with_package(), &file_steps());
    sys.fake_registry().set_elevated(true);
    for args in [
        &["package", "list"][..],
        &["package", "prune", "--yes"],
        &["package", "remove", "fix-pack@1.0.2", "--yes"],
    ] {
        expect(&sys, args, Answer::No, Exit::Refused);
    }
}

/// Every reason a package stays or stopped has its own words (the core's `StoreKeep` and
/// `PackageKeep`, including the ones of the P5-8b-1 review).
#[test]
fn every_reason_has_its_words() {
    use rerun_core::escape;
    use rerun_core::journal::TxnId;
    use rerun_core::pkg::store::StoreKeep;

    use crate::messages::{StaysWhy, StoreMsg};

    let t: TxnId = "00000007-00000000000000ab".parse().unwrap();
    let stays = |why| {
        StoreMsg::PackageStays {
            id: escape::text("fix-pack"),
            version: escape::text("1.0"),
            why,
        }
        .to_string()
    };
    assert_eq!(
        stays(StaysWhy::SharedArchive),
        "  fix-pack 1.0: it is only its archive, which a package that stays needs too"
    );
    assert_eq!(
        stays(StaysWhy::UnknownUse(vec![t])),
        format!(
            "  fix-pack 1.0: transaction {t} cannot be read, so any package may be in use; rerun \
             status shows it"
        )
    );
    let stopped = |why| {
        StoreMsg::Stopped {
            name: escape::text("fix-pack@1.0"),
            why,
        }
        .to_string()
    };
    assert_eq!(
        stopped(StoreKeep::Changed),
        "  fix-pack@1.0: it changed while it was removed; look at the store again"
    );
    assert_eq!(
        stopped(StoreKeep::Unsupported),
        "  fix-pack@1.0: the drive does not allow it to be removed (FAT or exFAT)"
    );
    assert_eq!(
        stays(StaysWhy::Store(StoreKeep::Reparse)),
        "  fix-pack 1.0: it holds a link (a junction or a symbolic link)"
    );
}
