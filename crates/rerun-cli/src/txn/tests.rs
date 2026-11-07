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
use rerun_core::plan::{NOT_RESTORED, Preview, PreviewOp, PreviewRoot};
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
        type_change: false,
        source: None,
        content: None,
        attrs: None,
        old: None,
        config: false,
        ini: Vec::new(),
    }
}

fn head() -> Preview {
    let mut key = file_op(2, "set value", r"HKCU\Software\Vendor\Game");
    key.root = None;
    key.name = Some(escape::path("Width").into_owned());
    Preview {
        roots: vec![PreviewRoot {
            index: 0,
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

transaction {t6}: applied
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
    };
    assert_eq!(
        shown(&report_lines(&rep, &v)),
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
