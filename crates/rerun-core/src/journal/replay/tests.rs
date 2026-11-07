//! J2: the grammar table (pure).

use super::Machine;
use crate::journal::TxnState;
use crate::journal::record::{Before, Closing, Digest, INLINE_MAX, Observed, Record};
use crate::sys::fs::TmpName;

fn i(op: u16) -> Record {
    Record::Intent {
        op,
        tmp: Some(TmpName::new(1, u64::from(op))),
        before: (op == 0).then_some(Before::Bin(Digest {
            sha256: [1; 32],
            len: 1,
        })),
    }
}
fn d(op: u16) -> Record {
    Record::Done {
        op,
        file_id: Some(u128::from(op) + 1),
        old_left: false,
    }
}
fn a(ops: u16) -> Record {
    Record::Applied { ops }
}
fn ri(op: u16) -> Record {
    Record::RevertIntent {
        op,
        tmp: None,
        from: None,
        to: None,
    }
}
fn rd(op: u16) -> Record {
    rdo(op, Observed::After)
}
fn rdo(op: u16, observed: Observed) -> Record {
    Record::RevertDone {
        op,
        observed,
        old_left: false,
    }
}
fn c(how: Closing) -> Record {
    Record::Closed { how }
}

/// Replays `rs`: the state, or the index of the refused record and the rule.
fn replay(rs: &[Record]) -> Result<TxnState, (usize, &'static str)> {
    let mut m = Machine::default();
    for (k, r) in rs.iter().enumerate() {
        m.step(r).map_err(|why| (k, why))?;
    }
    Ok(m.state())
}

#[test]
fn j2_valid_sequences() {
    use Closing::{Forgotten, Reverted, RolledBack};
    let ok: Vec<(Vec<Record>, TxnState)> = vec![
        (vec![], TxnState::Empty),
        (vec![i(0)], TxnState::Open),
        (vec![i(0), d(0), i(1)], TxnState::Open),
        (vec![i(0), d(0), i(1), d(1), a(2)], TxnState::Applied),
        // Full apply and revert, newest op first.
        (
            vec![
                i(0),
                d(0),
                i(1),
                d(1),
                a(2),
                ri(1),
                rd(1),
                ri(0),
                rd(0),
                c(Reverted),
            ],
            TxnState::Closed(Reverted),
        ),
        // A repeated revert intent after a crash.
        (
            vec![i(0), d(0), a(1), ri(0), ri(0), ri(0), rd(0), c(Reverted)],
            TxnState::Closed(Reverted),
        ),
        // A rollback of an op whose intent has no done (failed during the change).
        (
            vec![i(0), d(0), i(1), ri(1), rd(1), ri(0), rd(0), c(RolledBack)],
            TxnState::Closed(RolledBack),
        ),
        // A rollback before the first intent (head only, then closed).
        (vec![c(RolledBack)], TxnState::Closed(RolledBack)),
        // Partly reverted: still applied.
        (
            vec![i(0), d(0), i(1), d(1), a(2), ri(1), rd(1)],
            TxnState::Applied,
        ),
        (vec![i(0), d(0), a(1), ri(0)], TxnState::Applied),
        // Foreign: only Forgotten closes.
        (
            vec![
                i(0),
                d(0),
                a(1),
                ri(0),
                rdo(0, Observed::Foreign),
                c(Forgotten),
            ],
            TxnState::Closed(Forgotten),
        ),
        // A revert goes on after a Foreign op.
        (
            vec![
                i(0),
                d(0),
                i(1),
                d(1),
                a(2),
                ri(1),
                rdo(1, Observed::Foreign),
                ri(0),
                rd(0),
            ],
            TxnState::Applied,
        ),
        // Forgotten at any time.
        (vec![i(0), c(Forgotten)], TxnState::Closed(Forgotten)),
        (
            vec![i(0), d(0), a(1), ri(0), c(Forgotten)],
            TxnState::Closed(Forgotten),
        ),
        (vec![c(Forgotten)], TxnState::Closed(Forgotten)),
    ];
    for (rs, want) in ok {
        assert_eq!(replay(&rs), Ok(want), "{rs:?}");
    }
}

#[test]
fn j2_invalid_sequences_name_the_record_and_rule() {
    use Closing::{Forgotten, Reverted, RolledBack};
    let bad: Vec<(Vec<Record>, usize, &str)> = vec![
        (vec![i(1)], 0, "an intent out of order"),
        (
            vec![i(0), i(1)],
            1,
            "an intent before the previous op is done",
        ),
        (vec![i(0), d(0), i(0)], 2, "an intent out of order"),
        (vec![i(0), d(0), i(2)], 2, "an intent out of order"),
        (vec![d(0)], 0, "done not directly after its intent"),
        (vec![i(0), d(1)], 1, "done not directly after its intent"),
        (
            vec![i(0), d(0), d(0)],
            2,
            "done not directly after its intent",
        ),
        (
            vec![i(0), d(0), i(1), d(0)],
            3,
            "done not directly after its intent",
        ),
        (vec![a(0)], 0, "Applied does not count every intent"),
        (
            vec![i(0), d(0), a(2)],
            2,
            "Applied does not count every intent",
        ),
        (vec![i(0), a(1)], 1, "Applied before every op is done"),
        (vec![i(0), d(0), a(1), a(1)], 3, "a second Applied"),
        (vec![i(0), d(0), a(1), i(1)], 3, "an intent after Applied"),
        (
            vec![i(0), d(0), ri(0), i(1)],
            3,
            "an intent after a revert started",
        ),
        (
            vec![i(0), d(0), ri(0), rd(0), a(1)],
            4,
            "Applied after a revert started",
        ),
        // Reverts run descending over intended ops.
        (
            vec![i(0), d(0), i(1), d(1), a(2), ri(0)],
            5,
            "a revert intent out of order",
        ),
        (vec![ri(0)], 0, "a revert intent out of order"),
        (
            vec![i(0), d(0), a(1), ri(1)],
            3,
            "a revert intent out of order",
        ),
        (
            vec![i(0), d(0), a(1), ri(0), rd(0), ri(0)],
            5,
            "a revert intent out of order",
        ),
        (
            vec![i(0), d(0), a(1), rd(0)],
            3,
            "revert done not directly after its revert intent",
        ),
        (
            vec![i(0), d(0), i(1), d(1), a(2), ri(1), rd(1), rd(1)],
            7,
            "revert done not directly after its revert intent",
        ),
        // S3: RolledBack needs a RevertDone for every op with an intent.
        (
            vec![i(0), c(RolledBack)],
            1,
            "closed before every op is reverted",
        ),
        (
            vec![i(0), d(0), i(1), ri(1), rd(1), c(RolledBack)],
            5,
            "closed before every op is reverted",
        ),
        (
            vec![i(0), d(0), a(1), ri(0), c(Reverted)],
            4,
            "closed before every op is reverted",
        ),
        (
            vec![i(0), d(0), a(1), ri(0), rd(0), c(RolledBack)],
            5,
            "RolledBack after Applied",
        ),
        (
            vec![i(0), d(0), ri(0), rd(0), c(Reverted)],
            4,
            "Reverted without Applied",
        ),
        (vec![c(Reverted)], 0, "Reverted without Applied"),
        // S3: never closed as reverted after a Foreign observation (D10).
        (
            vec![
                i(0),
                d(0),
                a(1),
                ri(0),
                rdo(0, Observed::Foreign),
                c(Reverted),
            ],
            5,
            "closed as reverted although an op was Foreign",
        ),
        (
            vec![i(0), ri(0), rdo(0, Observed::Foreign), c(RolledBack)],
            3,
            "closed as reverted although an op was Foreign",
        ),
        // Nothing after Closed.
        (vec![c(Forgotten), c(Forgotten)], 1, "a record after Closed"),
        (vec![c(RolledBack), i(0)], 1, "a record after Closed"),
        (
            vec![i(0), d(0), a(1), ri(0), rd(0), c(Reverted), ri(0)],
            6,
            "a record after Closed",
        ),
    ];
    for (rs, at, why) in bad {
        assert_eq!(replay(&rs), Err((at, why)), "{rs:?}");
    }
}

#[test]
fn j2_replay_keeps_the_records_of_each_op() {
    let mut m = Machine::default();
    for r in [i(0), d(0), i(1), d(1), a(2), ri(1), ri(1), rd(1)] {
        m.step(&r).unwrap();
    }
    assert_eq!((m.intents(), m.records(), m.applied()), (2, 8, true));
    assert_eq!(m.next_revert(), Some(0));
    let op1 = &m.ops()[&1];
    assert_eq!(op1.done.and_then(|x| x.file_id), Some(2));
    assert_eq!(
        op1.reverts
            .iter()
            .map(|r| r.tmp.clone())
            .collect::<Vec<_>>(),
        vec![None, None]
    );
    assert_eq!(op1.reverted.map(|x| x.observed), Some(Observed::After));
    assert_eq!(
        m.ops()[&0].intent.before,
        Some(Before::Bin(Digest {
            sha256: [1; 32],
            len: 1
        }))
    );
    // A refused record changes nothing.
    let before = format!("{m:?}");
    assert!(m.step(&i(2)).is_err());
    assert_eq!(format!("{m:?}"), before);
    assert_eq!(m.closed(), None);
}

/// The record contents of P2-10a: an inline old state up to 16 KiB, `from` and `to` of a
/// revert intent both or neither (J test of the P2-10 plan: "`from` without `to` is a grammar
/// error").
#[test]
fn j2_inline_old_states_and_semantic_revert_intents() {
    let inline = |n: usize| Record::Intent {
        op: 0,
        tmp: None,
        before: Some(Before::Inline(vec![7; n])),
    };
    let mut m = Machine::default();
    assert_eq!(
        m.step(&inline(INLINE_MAX + 1)),
        Err("an inline old state larger than 16 KiB")
    );
    m.step(&inline(INLINE_MAX)).unwrap();
    m.step(&d(0)).unwrap();
    m.step(&a(1)).unwrap();
    let dg = Digest {
        sha256: [3; 32],
        len: 3,
    };
    for (from, to) in [(Some(dg), None), (None, Some(dg))] {
        let r = Record::RevertIntent {
            op: 0,
            tmp: None,
            from,
            to,
        };
        assert_eq!(
            m.check(&r),
            Err("a revert intent with only one of from and to")
        );
    }
    // Both is grammatical (`exec` refuses it for every op kind of P2-10, `records_fit`).
    m.step(&Record::RevertIntent {
        op: 0,
        tmp: None,
        from: Some(dg),
        to: Some(dg),
    })
    .unwrap();
    assert_eq!(m.ops()[&0].reverts[0].from, Some(dg));
}

/// A `Rebind` of `root` with directory proofs for `dirs` (P2-14).
fn rb(root: u16, dirs: &[u16]) -> Record {
    let id = |f: u128| crate::policy::root::RootId {
        volume_serial: 0x45,
        file_id: f,
    };
    Record::Rebind {
        root,
        old: id(1),
        store: crate::path::RootPath::new(r"E:\SteamLibrary").unwrap(),
        store_id: id(2),
        id: id(3),
        dirs: dirs
            .iter()
            .map(|op| crate::journal::DirProof {
                op: *op,
                file_id: u128::from(*op) + 10,
            })
            .collect(),
    }
}

/// J2 for `Rebind` (P2-14, user decision E-R3): only after `Applied` and before `Closed`, also
/// after the revert of other ops (the journal does not know their roots) and after an open
/// `RevertIntent` that is repeated afterwards; repeatable; `RevertDone` never directly after it.
#[test]
fn j2_rebind_only_after_applied_and_never_between_a_revert_intent_and_its_done() {
    use Closing::{Forgotten, Reverted};
    let applied = || vec![i(0), d(0), i(1), d(1), a(2)];
    let with = |tail: Vec<Record>| {
        let mut v = applied();
        v.extend(tail);
        v
    };
    let ok: Vec<(Vec<Record>, TxnState)> = vec![
        (with(vec![rb(0, &[])]), TxnState::Applied),
        (with(vec![rb(0, &[0, 1])]), TxnState::Applied),
        (with(vec![rb(0, &[]), rb(0, &[1])]), TxnState::Applied),
        (with(vec![rb(15, &[])]), TxnState::Applied),
        // After the revert of a later op (a registry op of another root, in `exec`'s terms).
        (with(vec![ri(1), rd(1), rb(0, &[0])]), TxnState::Applied),
        // After an open revert intent, which is repeated before its done.
        (
            with(vec![
                ri(1),
                rb(0, &[]),
                ri(1),
                rd(1),
                ri(0),
                rd(0),
                c(Reverted),
            ]),
            TxnState::Closed(Reverted),
        ),
        (
            with(vec![rb(0, &[]), ri(1), rd(1), ri(0), rd(0), c(Reverted)]),
            TxnState::Closed(Reverted),
        ),
        (
            with(vec![rb(0, &[]), c(Forgotten)]),
            TxnState::Closed(Forgotten),
        ),
    ];
    for (rs, want) in ok {
        assert_eq!(replay(&rs), Ok(want), "{rs:?}");
    }
    let many: Vec<u16> = (0..129).collect();
    let bad: Vec<(Vec<Record>, usize, &str)> = vec![
        (vec![rb(0, &[])], 0, "a rebind before Applied"),
        (vec![i(0), d(0), rb(0, &[])], 2, "a rebind before Applied"),
        (
            vec![i(0), ri(0), rd(0), rb(0, &[])],
            3,
            "a rebind before Applied",
        ),
        (
            with(vec![rb(16, &[])]),
            5,
            "a rebind of a root outside a head",
        ),
        (
            with(vec![rb(0, &[1, 0])]),
            5,
            "a rebind's directories out of order",
        ),
        (
            with(vec![rb(0, &[1, 1])]),
            5,
            "a rebind's directories out of order",
        ),
        (
            with(vec![rb(0, &many)]),
            5,
            "a rebind with too many directories",
        ),
        (
            with(vec![rb(0, &[2])]),
            5,
            "a rebind names an op without intent",
        ),
        (
            with(vec![ri(1), rb(0, &[]), rd(1)]),
            7,
            "revert done not directly after its revert intent",
        ),
        (
            with(vec![ri(1), rd(1), ri(0), rd(0), c(Reverted), rb(0, &[])]),
            10,
            "a record after Closed",
        ),
    ];
    for (rs, at, why) in bad {
        assert_eq!(replay(&rs), Err((at, why)), "{rs:?}");
    }
}

/// The replay keeps every `Rebind` in order, and for each the lowest op that had a revert
/// intent before it (`exec` refuses a rebind after a revert intent of an op of its root).
#[test]
fn j2_replay_keeps_rebinds_with_the_revert_that_had_begun() {
    let mut m = Machine::default();
    for r in [i(0), d(0), i(1), d(1), i(2), d(2), a(3)] {
        m.step(&r).unwrap();
    }
    m.step(&rb(0, &[0])).unwrap();
    for r in [ri(2), rd(2), ri(1)] {
        m.step(&r).unwrap();
    }
    m.step(&rb(1, &[])).unwrap();
    let got: Vec<(u16, Option<u16>, usize)> = m
        .rebinds()
        .iter()
        .map(|r| (r.root, r.reverting, r.dirs.len()))
        .collect();
    assert_eq!(got, vec![(0, None, 1), (1, Some(1), 0)]);
    assert_eq!(m.rebinds()[0].dirs[0].file_id, 10);
    assert_eq!(m.next_revert(), Some(1));
    assert_eq!(m.state(), TxnState::Applied);
}
