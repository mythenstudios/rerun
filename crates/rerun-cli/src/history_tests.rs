//! `rerun history clear` (P5-6d-1b) against the fake: the list (golden), `--dry-run` and a
//! declined question change nothing, `--yes` removes exactly what was listed, the quiet line of
//! the history's cap after a write.

use rerun_core::flow::{Tidied, TidyNote};
use rerun_core::journal::JournalError;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::messages::Message;
use crate::tests::{applied, build, expect, file_steps, same, snap_all, with_package};

#[test]
fn history_clear_lists_then_removes_exactly_what_it_listed() {
    let sys = build(with_package(), &file_steps());
    let t0 = applied(&sys);
    expect(&sys, &["revert", &t0, "--yes"], Answer::No, Exit::Report);
    let t1 = applied(&sys);
    let before = snap_all(&sys);
    let dry = expect(
        &sys,
        &["history", "clear", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert_eq!(
        dry.stdout,
        format!(
            "Removed from the history:\n  {t0}  reverted\nStays:\n  {t1}  not \
             settled (open, applied or damaged)\nGame folders, the registry and the firewall stay \
             unchanged.\n\n"
        )
    );
    same(&before, &snap_all(&sys));
    // Declined: nothing removed.
    let no = expect(&sys, &["history", "clear"], Answer::No, Exit::Refused);
    assert_eq!(
        no.asked,
        ["Remove 1 history entry and 0 launch results? [y/N]"]
    );
    same(&before, &snap_all(&sys));
    // Removed: the reverted one; the applied one stays.
    let yes = expect(
        &sys,
        &["history", "clear", "--yes"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        yes.stdout
            .ends_with("1 history entry and 0 launch results removed\n"),
        "{}",
        yes.stdout
    );
    let s = expect(&sys, &["status", "--all"], Answer::No, Exit::Report);
    assert!(
        !s.stdout.contains(&t0) && s.stdout.contains(&t1),
        "{}",
        s.stdout
    );
    // Nothing left to remove.
    let again = expect(
        &sys,
        &["history", "clear", "--yes"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        again.stdout.ends_with("nothing to clear\n"),
        "{}",
        again.stdout
    );
}

#[test]
fn the_cap_line_is_quiet_unless_entries_went() {
    let line = |t| crate::txn::tidied_line(&t).map(|m: Message<'_>| m.to_string());
    assert_eq!(line(Ok(Tidied { removed: 0 })), None);
    assert_eq!(
        line(Ok(Tidied { removed: 1 })).as_deref(),
        Some("1 older history entry removed (Rerun keeps the last 100 undone or rolled back)")
    );
    assert_eq!(
        line(Ok(Tidied { removed: 3 })).as_deref(),
        Some("3 older history entries removed (Rerun keeps the last 100 undone or rolled back)")
    );
    assert_eq!(line(Err(TidyNote::Journal(JournalError::Busy))), None);
}

/// Review S2, S3, N5: empty entries as one line; an entry refused when it is deleted (a backup
/// in use) is listed under "Stays" after the run; an error while removing is exit 1.
#[test]
fn history_clear_sums_up_empty_entries_and_names_what_it_could_not_remove() {
    use std::path::Path;

    use rerun_core::sys::contract::{Access, Share};

    use crate::tests::RERUN;

    let sys = build(with_package(), &file_steps());
    let t0 = applied(&sys);
    expect(&sys, &["revert", &t0, "--yes"], Answer::No, Exit::Report);
    for n in [7, 8] {
        let empty = format!(r"{RERUN}\journal\0000000{n}-0000000000000001");
        sys.fake_fs().mkdir_all(Path::new(&empty)).unwrap();
    }
    let dry = expect(
        &sys,
        &["history", "clear", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert_eq!(
        dry.stdout,
        format!(
            "Removed from the history:\n  {t0}  reverted\n  2 empty entries (they changed \
             nothing)\nGame folders, the registry and the firewall stay unchanged.\n\n"
        )
    );
    // A file of t0 held by a scanner: refused when it is deleted, named under "Stays".
    let bin = format!(r"{RERUN}\journal\{t0}\head.json");
    let held = sys
        .fake_fs()
        .hold_open_as(4242, Path::new(&bin), Access::READ, Share::RW)
        .unwrap();
    let yes = expect(
        &sys,
        &["history", "clear", "--yes"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        yes.stdout.ends_with(&format!(
            "2 history entries and 0 launch results removed\nStays:\n  {t0}: a backup is in use \
             right now; a later clean-up removes the entry\n"
        )),
        "{}",
        yes.stdout
    );
    drop(held);

    // An error while removing: exit 1.
    let sys = build(with_package(), &file_steps());
    let t = applied(&sys);
    expect(&sys, &["revert", &t, "--yes"], Answer::No, Exit::Report);
    sys.fake_fs().clear_faults();
    sys.fake_fs().fail_at(
        rerun_core::sys::fake::Prim::OpenFileDelete,
        1,
        rerun_core::sys::SysErrorKind::Other,
    );
    expect(
        &sys,
        &["history", "clear", "--yes"],
        Answer::No,
        Exit::Fatal,
    );
}
