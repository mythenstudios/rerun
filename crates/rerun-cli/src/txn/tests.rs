//! `status`, `revert` and `forget` rendering: golden strings on directly built journal views
//! (every transaction state, op state and backup kind), the lines of what a revert does now
//! (INI keys, a `.old` before a step of Rerun, a halt) and of its report. The net never fires.

use std::collections::BTreeMap;

use rerun_core::escape;
use rerun_core::exec::{
    Backup, BeforeStep, Detail, Halt, IniKey, OpReport, OpState, OpStatus, Refusal, RerunStep,
    RevertReport, Status, TxnLine, TxnStatus, Verified,
};
use rerun_core::journal::{Closing, Damage, Observed, TxnId};
use rerun_core::path::RelPath;
use rerun_core::plan::{NOT_RESTORED, Preview, PreviewOp, PreviewRoot, RootKind};
use rerun_core::policy::ini::{IniName, KeyState};

use super::{now_lines, render_status, report_lines};
use crate::messages::Message;
use crate::out::Out;

fn shown(ms: &[Message<'_>]) -> String {
    let mut out = Out::new(Vec::new());
    out.lines(ms).unwrap();
    String::from_utf8(out.into_inner()).unwrap()
}

fn txn(seq: u32) -> TxnId {
    format!("{seq:08}-00000000000000ab").parse().unwrap()
}

const APP: &str = r"C:\Users\Player\AppData\Local\Rerun";

fn folder(t: TxnId) -> escape::Shown<'static> {
    escape::path(&format!(r"{APP}\journal\{t}")).into_owned()
}

fn bin(t: TxnId, k: u16, len: u64) -> Option<Backup> {
    Some(Backup::Bin {
        path: escape::path(&format!(r"{APP}\journal\{t}\op-{k:04}.bin")).into_owned(),
        len,
    })
}

fn file_op(index: usize, action: &'static str, path: &str) -> PreviewOp {
    PreviewOp {
        index,
        action,
        root: Some(0),
        path: escape::path(path).into_owned(),
        name: None,
        old_value: None,
        new_value: None,
        tokens: None,
        machine: Vec::new(),
        type_change: false,
        source: None,
        content: None,
        attrs: None,
        old: None,
        config: false,
        ini: Vec::new(),
        profile: None,
        replaces: false,
        firewall: None,
        held: false,
        patch: Vec::new(),
    }
}

fn head() -> Preview {
    let mut key = file_op(2, "set value", r"HKCU\Software\Vendor\Game");
    key.root = None;
    key.name = Some(escape::path("Width").into_owned());
    Preview {
        roots: vec![PreviewRoot {
            index: 0,
            kind: RootKind::Game,
            path: escape::path(r"D:\Games\G").into_owned(),
            steam: None,
            main_exe: Some(escape::path("game.exe").into_owned()),
        }],
        ops: vec![
            file_op(0, "replace file", "d3d9.dll"),
            file_op(1, "edit ini", "game.ini"),
            key,
        ],
        not_restored: NOT_RESTORED,
        registry: None,
        layers: None,
        ini: None,
        profiles: None,
        firewall: None,
        held: None,
        patched: None,
        gpu_pref: None,
        user_data: None,
    }
}

fn op(op: u16, state: OpState, backup: Option<Backup>, cleanup: &[&str]) -> OpStatus {
    OpStatus {
        op,
        state,
        backup,
        cleanup: cleanup
            .iter()
            .map(|c| escape::path(c).into_owned())
            .collect(),
    }
}

fn st(
    id: TxnId,
    state: TxnLine,
    preview: Option<Result<Preview, &str>>,
    ops: Vec<OpStatus>,
) -> TxnStatus {
    TxnStatus {
        id,
        state,
        forgotten: false,
        folder: folder(id),
        preview: preview.map(|p| p.map_err(|e| escape::text(e).into_owned())),
        ops,
        rebinds: Vec::new(),
        shares: Vec::new(),
        shares_error: None,
    }
}

#[test]
fn status_shows_every_state() {
    let old = ".rerun-00000000000000ab-3.tmp.old";
    let s = Status {
        txns: vec![
            // Closed with a pending cleanup: shown although closed.
            st(
                txn(1),
                TxnLine::Closed(Closing::Reverted),
                Some(Ok(head())),
                vec![op(
                    0,
                    OpState::Reverted(Observed::After),
                    bin(txn(1), 0, 20),
                    &[old],
                )],
            ),
            st(txn(2), TxnLine::Empty, None, Vec::new()),
            st(
                txn(3),
                TxnLine::Closed(Closing::RolledBack),
                None,
                Vec::new(),
            ),
            // Applied, a revert interrupted at op 2, op 1's old value inline.
            st(
                txn(4),
                TxnLine::Applied,
                Some(Ok(head())),
                vec![
                    op(2, OpState::RevertInterrupted, Some(Backup::Inline), &[]),
                    op(1, OpState::Applied, bin(txn(4), 1, 35), &[]),
                    op(0, OpState::Applied, bin(txn(4), 0, 20), &[]),
                ],
            ),
            // Open: an interrupted apply.
            st(
                txn(5),
                TxnLine::Open,
                Some(Ok(head())),
                vec![op(0, OpState::Interrupted, bin(txn(5), 0, 20), &[])],
            ),
            // Applied, one op left as found by a revert: forget closes it.
            st(
                txn(6),
                TxnLine::Applied,
                Some(Ok(head())),
                vec![
                    op(1, OpState::Reverted(Observed::Before), None, &[]),
                    op(
                        0,
                        OpState::Reverted(Observed::Foreign),
                        bin(txn(6), 0, 20),
                        &[],
                    ),
                ],
            ),
            // Damaged, and a head that cannot be read; unreadable.
            st(
                txn(7),
                TxnLine::Damaged(Damage::Gap { at: 3 }),
                Some(Err("its head cannot be read or was changed")),
                vec![op(0, OpState::Applied, None, &[])],
            ),
            st(
                txn(8),
                TxnLine::Unreadable(escape::text("access denied").into_owned()),
                None,
                Vec::new(),
            ),
            // Forgotten by a record, and by a marker.
            st(
                txn(9),
                TxnLine::Closed(Closing::Forgotten),
                None,
                vec![
                    op(1, OpState::Applied, None, &[]),
                    op(0, OpState::Applied, bin(txn(9), 0, 20), &[]),
                ],
            ),
            TxnStatus {
                forgotten: true,
                ..st(
                    txn(10),
                    TxnLine::Damaged(Damage::HeadMissing),
                    None,
                    Vec::new(),
                )
            },
        ],
        foreign_entries: 2,
    };
    let t = |n| txn(n).to_string();
    let want = format!(
        r"transaction {t1}: reverted
  op 0, reverted: replace file in root 0: d3d9.dll
    pending cleanup: {old}
transaction {t4}: applied; a revert began and did not finish
root 0: D:\Games\G
  main executable: game.exe
  op 2, revert interrupted: set value: HKCU\Software\Vendor\Game
    value: Width
    backup: kept in the journal record
  op 1, applied: edit ini in root 0: game.ini
    backup (35 bytes): {APP}\journal\{t4}\op-0001.bin
  op 0, applied: replace file in root 0: d3d9.dll
    backup (20 bytes): {APP}\journal\{t4}\op-0000.bin
  revert with: rerun revert {t4}

transaction {t5}: open (in progress or interrupted)
root 0: D:\Games\G
  main executable: game.exe
  op 0, interrupted while it was applied: replace file in root 0: d3d9.dll
    backup (20 bytes): {APP}\journal\{t5}\op-0000.bin
  revert with: rerun revert {t5}

transaction {t6}: applied; a revert began and did not finish
root 0: D:\Games\G
  main executable: game.exe
  op 1, reverted: edit ini in root 0: game.ini
  op 0, left as found (changed by someone else): replace file in root 0: d3d9.dll
    backup (20 bytes): {APP}\journal\{t6}\op-0000.bin
  changes were left as found; forget closes it: rerun forget {t6}

transaction {t7}: damaged: record 3 is missing
  its plan cannot be shown: its head cannot be read or was changed
  op 0, applied
  blocks every apply; only forget closes it: rerun forget {t7}

transaction {t8}: unreadable: access denied
  blocks every apply; only forget closes it: rerun forget {t8}

transaction {t9}: forgotten
  op 0, applied
    backup (20 bytes): {APP}\journal\{t9}\op-0000.bin
  its backups stay in: {APP}\journal\{t9}

transaction {t10}: forgotten
  its backups stay in: {APP}\journal\{t10}

journal: 2 entries not Rerun's (left alone)
10 transactions: 5 not closed, 3 closed, 2 forgotten (rerun status --all lists the closed ones)
note: rerun revert --dry-run <txn> and rerun forget <txn> show what is on disk now
",
        t1 = t(1),
        t4 = t(4),
        t5 = t(5),
        t6 = t(6),
        t7 = t(7),
        t8 = t(8),
        t9 = t(9),
        t10 = t(10),
    );
    assert_eq!(shown(&render_status(&s, false)), want);
    let all = shown(&render_status(&s, true));
    assert!(
        all.contains(&format!(
            "transaction {}: empty (it changed nothing)\n",
            t(2)
        )),
        "{all}"
    );
    assert!(
        all.contains(&format!("transaction {}: rolled back\n", t(3))),
        "{all}"
    );
    assert!(all.ends_with("10 transactions: 5 not closed, 3 closed, 2 forgotten\nnote: rerun revert --dry-run <txn> and rerun forget <txn> show what is on disk now\n"), "{all}");
}

fn name(s: &str) -> IniName {
    IniName::parse(s).unwrap()
}

#[test]
fn what_a_revert_does_now_and_its_report() {
    let s = st(
        txn(4),
        TxnLine::Applied,
        Some(Ok(head())),
        vec![
            op(2, OpState::Applied, None, &[]),
            op(1, OpState::Applied, bin(txn(4), 1, 35), &[]),
            op(0, OpState::Applied, bin(txn(4), 0, 20), &[]),
        ],
    );
    let ini = Detail::Ini {
        keys: vec![
            IniKey {
                section: name("Display"),
                key: name("Width"),
                state: KeyState::New,
            },
            IniKey {
                section: name("Display"),
                key: name("Height"),
                state: KeyState::Changed,
            },
        ],
        before_step: Some(BeforeStep {
            step: RerunStep::Restore,
            file: RelPath::parse(".rerun-00000000000000ab-9.tmp.old").unwrap(),
        }),
    };
    let v = Verified {
        ops: vec![(1, Observed::Foreign), (2, Observed::After)],
        halted: Some(Halt {
            op: 0,
            root: 0,
            why: Box::new(Refusal::NeedsHelper),
        }),
        details: BTreeMap::from([(1, ini.clone())]),
        cleanup: Vec::new(),
        profiles_moved: None,
        virtual_store: Vec::new(),
    };
    let t4 = txn(4);
    assert_eq!(
        shown(&now_lines(&s, &v)),
        format!(
            r"on disk now, newest op first:
  op 2, will be undone: set value: HKCU\Software\Vendor\Game
    value: Width
  op 1, left as it is (changed by someone else); the transaction stays open: edit ini in root 0: game.ini
    holds Rerun's value: [Display] Width
    changed since; stays as it is: [Display] Height
    the file as it was before Rerun's restore is kept next to it (never call it the original; the backup is): .rerun-00000000000000ab-9.tmp.old
    backup (35 bytes): {APP}\journal\{t4}\op-0001.bin
the revert stops at op 0: the game folder needs administrator rights (not supported yet)
"
        )
    );
    let rep = RevertReport {
        txn: t4,
        closed: None,
        ops: vec![
            OpReport {
                op: 2,
                observed: Observed::Before,
                left: Vec::new(),
                backup: None,
                detail: None,
            },
            OpReport {
                op: 1,
                observed: Observed::Foreign,
                left: vec![RelPath::parse(".rerun-00000000000000ab-9.tmp.old").unwrap()],
                backup: bin(t4, 1, 35),
                detail: Some(ini),
            },
        ],
        halted: None,
        cleanup: Vec::new(),
        profiles_moved: None,
    };
    assert_eq!(
        shown(&report_lines(
            &st(t4, TxnLine::Applied, None, Vec::new()),
            &rep,
            &v
        )),
        format!(
            r"  op 2: was already as before (changed since the preview)
  op 1: left as found (changed by someone else)
    holds Rerun's value: [Display] Width
    changed since; stays as it is: [Display] Height
    the file as it was before Rerun's restore is kept next to it (never call it the original; the backup is): .rerun-00000000000000ab-9.tmp.old
    backup (35 bytes): {APP}\journal\{t4}\op-0001.bin
    left: .rerun-00000000000000ab-9.tmp.old
"
        )
    );
}

/// C-CL2 (P2-15, rule 5): the preview of a revert names every pending `.old` by what it does
/// (delete Rerun's copy by its known SHA-256, or why it stays), the report what it did, and the
/// status line of a transaction with only its cleanup pending. A path is always escaped: one
/// from the journal cannot hold a control or bidi character (`RelPath`), and the line escapes
/// whatever it gets.
#[test]
fn c_cl2_pending_cleanup_in_the_preview_the_report_and_status() {
    use rerun_core::exec::{OldSeen, PendingOld};
    let t = txn(5);
    let item = |op: u16, p: &str, seen: OldSeen| PendingOld {
        op,
        root: 0,
        path: RelPath::parse(p).unwrap(),
        sha256: [0xab; 32],
        seen,
    };
    let s = st(
        t,
        TxnLine::CleanupPending,
        Some(Ok(head())),
        vec![op(
            0,
            OpState::Reverted(Observed::After),
            bin(t, 0, 20),
            &[".rerun-00000000000000ab-3.tmp.old"],
        )],
    );
    let v = Verified {
        ops: vec![(0, Observed::Before)],
        halted: None,
        details: BTreeMap::new(),
        cleanup: vec![
            item(0, ".rerun-00000000000000ab-3.tmp.old", OldSeen::Ours),
            item(0, ".rerun-00000000000000ab-4.tmp.old", OldSeen::InUse),
            item(0, r"cfg\.rerun-00000000000000ab-5.tmp.old", OldSeen::Kept),
            item(0, ".rerun-00000000000000ab-6.tmp.old", OldSeen::Foreign),
            item(0, ".rerun-00000000000000ab-7.tmp.old", OldSeen::Gone),
        ],
        profiles_moved: None,
        virtual_store: Vec::new(),
    };
    let sha = "ab".repeat(32);
    assert_eq!(
        shown(&now_lines(&s, &v)),
        format!(
            r"on disk now, newest op first:
  op 0, nothing to do (as before): replace file in root 0: d3d9.dll
  will delete Rerun's copy (known content, SHA-256 {sha}): .rerun-00000000000000ab-3.tmp.old
  in use, stays for now (Rerun's copy; the transaction stays open): .rerun-00000000000000ab-4.tmp.old
  kept: the file next to it changed since the revert, so Rerun's copy stays (delete it yourself, or forget the transaction): cfg\.rerun-00000000000000ab-5.tmp.old
  not Rerun's file, or it cannot be checked as Rerun's; left as it is: .rerun-00000000000000ab-6.tmp.old
"
        )
    );
    let rep = RevertReport {
        txn: t,
        closed: None,
        ops: Vec::new(),
        halted: None,
        cleanup: vec![
            item(0, ".rerun-00000000000000ab-3.tmp.old", OldSeen::Deleted),
            item(0, ".rerun-00000000000000ab-4.tmp.old", OldSeen::InUse),
        ],
        profiles_moved: None,
    };
    assert_eq!(
        shown(&report_lines(&s, &rep, &v)),
        "  deleted Rerun's copy: .rerun-00000000000000ab-3.tmp.old\n  in use, stays for now (Rerun's copy; the transaction stays open): .rerun-00000000000000ab-4.tmp.old\n"
    );
    let all = shown(&render_status(
        &Status {
            txns: vec![s],
            foreign_entries: 0,
        },
        false,
    ));
    assert!(
        all.starts_with(&format!(
            "transaction {t}: everything reverted, only cleanup pending\n"
        )),
        "{all}"
    );
    assert!(
        all.contains("    pending cleanup: .rerun-00000000000000ab-3.tmp.old\n"),
        "{all}"
    );
    assert!(
        all.contains(&format!(
            "  a file Rerun left is still there; rerun revert {t} deletes it or says why it stays (close the game and any window showing its folder first)\n"
        )),
        "{all}"
    );
    // The line escapes what it gets (ESC, U+202E).
    let evil = Message::Txn(crate::messages::TxnMsg::WillDelete {
        sha256: sha.clone(),
        path: escape::path("cfg\\a\u{1b}[31m\u{202e}lld.tmp.old"),
    })
    .to_string();
    assert!(
        !evil.contains('\u{1b}') && !evil.contains('\u{202e}'),
        "{evil:?}"
    );
    assert!(
        evil.starts_with(&format!(
            "  will delete Rerun's copy (known content, SHA-256 {sha}): "
        )),
        "{evil}"
    );
}

/// Review N5: a revert refused because the journal has no room for another attempt says that
/// only forget closes it.
#[test]
fn a_full_journal_names_forget() {
    let t = txn(6);
    let r = Refusal::Journal(Box::new(rerun_core::journal::JournalError::TooLarge {
        what: "the records of a transaction",
        limit: 1024,
    }));
    let mut err = Out::new(Vec::new());
    assert_eq!(super::refusal(&r, t, &mut err), crate::cli::Exit::Refused);
    let text = String::from_utf8(err.into_inner()).unwrap();
    assert!(
        text.ends_with(&format!(
            "the journal of transaction {t} has no room for another revert attempt; only rerun forget {t} closes it (backups stay)\n"
        )),
        "{text}"
    );
}

/// P3-3d: a halt at the profiles root says what it means (also the tolerated halt a rebind
/// preview shows), and a moved profiles folder names both paths (S3).
#[test]
fn a_halt_at_the_profiles_root_and_a_moved_profiles_folder_are_explained() {
    let mut h = head();
    h.roots.push(PreviewRoot {
        index: 1,
        kind: RootKind::Profiles,
        path: escape::path(r"C:\Users\Player\AppData\Local\Rerun\profiles").into_owned(),
        steam: None,
        main_exe: None,
    });
    let s = st(txn(4), TxnLine::Applied, Some(Ok(h)), Vec::new());
    let v = Verified {
        ops: Vec::new(),
        halted: Some(Halt {
            op: 0,
            root: 1,
            why: Box::new(Refusal::NeedsHelper),
        }),
        details: BTreeMap::new(),
        cleanup: Vec::new(),
        profiles_moved: Some(rerun_core::exec::ProfilesMoved {
            planned: escape::path(r"C:\A\Rerun\profiles").into_owned(),
            now: escape::path(r"C:\B\Rerun\profiles").into_owned(),
        }),
        virtual_store: Vec::new(),
    };
    let text = shown(&now_lines(&s, &v));
    for want in [
        r"Rerun's profiles folder is at another path than the transaction names (its hashes decide): named C:\A\Rerun\profiles",
        r"  now C:\B\Rerun\profiles",
        "  Rerun's profiles folder is missing: the revert stops at the launch profile after everything else is reverted; forget closes the transaction then",
    ] {
        assert!(text.contains(want), "{want}\n{text}");
    }
    // A halt at the game root says nothing about profiles.
    let mut v = v;
    v.halted = Some(Halt {
        op: 0,
        root: 0,
        why: Box::new(Refusal::NeedsHelper),
    });
    v.profiles_moved = None;
    assert!(!shown(&now_lines(&s, &v)).contains("profiles"));
}

/// A head with a launch profile op 0 (`replace`: it replaced a profile) and a game file op 1.
fn profile_head(replace: bool) -> Preview {
    let mut p = head();
    let mut prof = file_op(
        0,
        if replace {
            "replace file"
        } else {
            "create file"
        },
        "323ad79fbc93ca3e73b0b152a5d44616.profile",
    );
    prof.root = Some(1);
    prof.replaces = replace;
    // The decoded form is not needed here: the ID comes from the file name.
    prof.profile = Some(rerun_core::plan::ProfilePreview::Unreadable("x".to_owned()));
    p.ops = vec![prof, file_op(1, "create file", "new.dll")];
    p.roots.push(PreviewRoot {
        index: 1,
        kind: RootKind::Profiles,
        path: escape::path(r"C:\Users\Player\AppData\Local\Rerun\profiles").into_owned(),
        steam: None,
        main_exe: None,
    });
    p
}

const INSTALL: &str = r"C:\Rerun";
const GONE: &str = "finds no profile";
const STAYS: &str = "stays and keeps applying";
const BACK: &str = "from before this transaction is back";
const LEFT: &str = "was left as found by an earlier revert";

fn says(lines: &[Message<'_>], want: &str, what: &str) {
    let text = shown(lines);
    for other in [GONE, STAYS, BACK, LEFT] {
        assert_eq!(
            text.contains(other),
            other == want,
            "{what}: {other}\n{text}"
        );
    }
}

/// X12 (review M1/B1): the text follows what becomes of the profile. Which fate a revert, its
/// report or a forget gives is `flow`'s (`flow/revert_tests.rs`, FX1).
#[test]
fn x12_says_what_becomes_of_the_profile() {
    use crate::preview::{Fate, x12_lines};
    let install = Ok(std::path::PathBuf::from(INSTALL));
    let id = rerun_core::flow::profile_id_of(&profile_head(false)).unwrap();
    for (fate, want) in [
        (Fate::Gone, GONE),
        (Fate::PreviousBack, BACK),
        (Fate::Stays, STAYS),
        (Fate::Left, LEFT),
    ] {
        says(
            &x12_lines(&install, id, fate, false),
            want,
            &format!("{fate:?}"),
        );
        let before = shown(&x12_lines(&install, id, fate, true));
        assert!(before.contains("once the revert completes"), "{before}");
    }
    let back = shown(&x12_lines(&install, id, Fate::PreviousBack, false));
    assert!(!back.contains("remove this launch option"), "{back}");
}

/// A4 N6 (P4-2d): the `status` lines of Rerun rules no transaction of this account owns, worded
/// for every account on the PC; nothing without such rules; one line when unreadable.
#[test]
fn orphan_rules_are_worded_for_this_account() {
    use rerun_core::exec::OrphanRule;
    let r = Ok(vec![OrphanRule {
        name: escape::text("Rerun - invented-game - 00000003-00000000000000aa-000").into_owned(),
        program: escape::path(r"D:\Games\G\game.exe").into_owned(),
    }]);
    let s = shown(&super::orphan_lines(&r));
    assert!(
        s.contains("Rerun firewall rules that no transaction of this account owns:\n"),
        "{s}"
    );
    assert!(s.contains("  Rerun - invented-game - 00000003-00000000000000aa-000: program "));
    assert!(s.contains("Rules of other Windows accounts on this PC appear here too."));
    assert!(s.contains("group Rerun); a non-elevated Rerun never removes it."));
    assert!(!s.contains("orphan") && !s.contains("left behind"), "{s}");
    assert_eq!(shown(&super::orphan_lines(&Ok(Vec::new()))), "");
    let e = Err(rerun_core::exec::OrphansError::Firewall(
        rerun_core::sys::SysError::new(
            rerun_core::sys::SysErrorKind::AccessDenied,
            "firewall rules",
        ),
    ));
    assert!(
        shown(&super::orphan_lines(&e))
            .starts_with("Rerun firewall rules: the firewall cannot be read now: ")
    );
    // Review follow-up N1: a journal that cannot be listed has its own words.
    let e = Err(rerun_core::exec::OrphansError::Journal(
        rerun_core::journal::JournalError::Busy,
    ));
    let s = shown(&super::orphan_lines(&e));
    assert!(
        s.starts_with(
            "Rerun firewall rules: which belong to this account cannot be told: the journal \
             cannot be read now: "
        ),
        "{s}"
    );
    assert!(!s.contains("firewall cannot be read"), "{s}");
}

/// P4-8b (E6): the lines of a hand-over in `verify`, the report and `status`, every outcome,
/// with hostile paths escaped and standing last on their line.
#[test]
fn hand_over_lines_are_golden_and_escaped() {
    use rerun_core::exec::{Inherited, InheritedOutcome as O, LeftWhy, ShareKind, ShareLine};
    let (t1, t2, t3) = (txn(1), txn(2), txn(3));
    let hostile = "mods\u{1b}[31m\u{202e}x";
    let item = |outcome, dir| Inherited {
        from: t1,
        path: escape::path(hostile).into_owned(),
        dir,
        outcome,
    };
    let items = vec![
        item(O::Removed, false),
        item(O::Removed, true),
        item(O::StillRelied(t3), false),
        item(O::Gone, false),
        item(O::Left(LeftWhy::Changed), false),
        item(O::Left(LeftWhy::OtherFileId), false),
        item(O::Left(LeftWhy::NotEmpty), true),
    ];
    let mut st = st(t2, TxnLine::Applied, None, Vec::new());
    let p = escape::path(hostile).to_string();
    assert!(!p.contains('\u{1b}') && !p.contains('\u{202e}'), "{p}");
    let v = Verified {
        ops: vec![(0, Observed::After), (1, Observed::Kept)],
        halted: None,
        details: BTreeMap::from([
            (0, Detail::Inherited(items.clone())),
            (1, Detail::Kept { by: vec![t2, t3] }),
        ]),
        cleanup: Vec::new(),
        profiles_moved: None,
        virtual_store: Vec::new(),
    };
    let now = shown(&now_lines(&st, &v));
    for want in [
        format!(
            "  op 1, kept for a later transaction that relies on it (the last revert that relies on it removes it)\n    kept for {t2}, {t3}, which relies on it (the last revert that relies on it removes it)\n"
        ),
        format!("    removes the file {t1} installed and handed over (unchanged): {p}\n"),
        format!("    removes the folder {t1} installed and handed over (unchanged): {p}\n"),
        format!("    keeps the file {t1} installed: {t3} still relies on it: {p}\n"),
        format!("    the file {t1} installed is gone already: {p}\n"),
        format!("    leaves the file {t1} installed (it changed since): {p}\n"),
        format!(
            "    leaves the file {t1} installed (the same content, but not the same file any more): {p}\n"
        ),
        format!("    leaves the folder {t1} installed (it holds something else): {p}\n"),
    ] {
        assert!(now.contains(&want), "{want:?} not in\n{now}");
    }
    let rep = RevertReport {
        txn: t2,
        closed: Some(Closing::Reverted),
        ops: vec![OpReport {
            op: 0,
            observed: Observed::After,
            left: Vec::new(),
            backup: None,
            detail: Some(Detail::Inherited(items)),
        }],
        halted: None,
        cleanup: Vec::new(),
        profiles_moved: None,
    };
    let did = shown(&report_lines(&st, &rep, &v));
    assert!(
        did.contains(&format!(
            "    removed the file {t1} installed and handed over: {p}\n"
        )),
        "{did}"
    );
    assert!(
        did.contains(&format!(
            "    left the folder {t1} installed (it holds something else): {p}\n"
        )),
        "{did}"
    );
    st.shares = vec![
        ShareLine {
            op: 0,
            path: escape::path(hostile).into_owned(),
            dir: false,
            kind: ShareKind::Inherits { from: t1 },
        },
        ShareLine {
            op: 0,
            path: escape::path("mods").into_owned(),
            dir: true,
            kind: ShareKind::RemovedBy { from: t1, by: t3 },
        },
    ];
    let s = shown(&render_status(
        &Status {
            txns: vec![st],
            foreign_entries: 0,
        },
        false,
    ));
    for want in [
        format!(
            "  relies on the file {t1} installed and handed over; its revert removes it if unchanged: {p}\n"
        ),
        format!(
            "  relies on the folder {t1} installed; the revert of {t3} removes it once nothing else relies on it: mods\n"
        ),
    ] {
        assert!(s.contains(&want), "{want:?} not in\n{s}");
    }
}
