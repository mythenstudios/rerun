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
            "Removed from the history:\n  {t0}  no game  reverted\nStays:\n  {t1}  no game  not \
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
