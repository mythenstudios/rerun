//! The hand-over of shared files and folders (P4-8b, user decision E6, ADR 0020 amendment
//! P4-8b): a file or folder an earlier transaction created stays while a later transaction relies
//! on it, and the last revert that relies on it removes it.
//!
//! - **Relying op** (S6): a `Hold` of a file the creator's `CreateFile` wrote (the same object,
//!   hash and length), or a `CreateFile`, `CreateDir` or `Hold` whose object lies below a folder
//!   the creator's `CreateDir` made. It relies while it has an intent and no `RevertDone` (an
//!   interrupted apply counts: conservative, it keeps the object).
//! - **Creator side** (`stack::for_revert`): a later transaction that meets the reverting one only
//!   through relying ops (applied, `Done`, no revert begun, no `Rebind` on either side, not
//!   damaged) no longer refuses the revert; the ops it relies on are [`Keeps`]. The loop records
//!   such an op `Observed::Kept` when the object is exactly as the op left it with the op's file
//!   ID (and, for a file, every relying `Hold` recorded that ID): nothing is deleted.
//! - **Inheritor side** ([`duties`]): for an applied transaction `R`, an object handed over
//!   (`RevertDone { Kept }` of a creator that is not forgotten) that an op of `R` relies on (for a
//!   file: its `Hold` recorded the creator's file ID) is `R`'s **duty** once no other transaction
//!   that is not closed (the creator included) has an op on it (a folder: at or below it) without
//!   `RevertDone`. A file duty is carried by `R`'s `Hold`, a folder duty by `R`'s lowest relying
//!   op below the folder, deepest folder first, after that op's own act. Disk facts (file ID,
//!   content, emptiness) are checked when acting, never in the derivation.
//! - **Invariant (S1):** every inherited deletion relies only on records read in this run under
//!   the lock and happens after this run's flushed `RevertIntent` of the carrying op.
//! - **Generations (B1):** only a `Kept` op makes a duty, a file duty needs the `Hold`'s recorded
//!   file ID equal to the creator's, and a folder with another file ID than the creator's is not
//!   Rerun's (skipped, not reported as installed by it). File IDs are assumed not to be reused
//!   for another object while a transaction records them (NTFS IDs carry a sequence number, ReFS
//!   IDs are not reused; N1).
//! - **Cost (S4):** forgotten, empty and rolled-back transactions are skipped from the listing;
//!   a closed one is read only if the reverting transaction has a relying op and its listed
//!   records hold a `Kept`; at most [`MAX_SHARE_HEADS`] heads are read
//!   ([`Refusal::TooManyTransactions`]).

use std::collections::BTreeMap;

use super::Refusal;
use super::bind::Bindings;
use crate::journal::{Closing, Journal, Listed, Listing, Observed, OpLog, TxnId, TxnState};
use crate::path::RelPath;
use crate::plan::{ContentRef, Object, Op, Plan};
use crate::sys::fs::Attrs;

/// Most heads of other transactions one revert reads for the hand-over (S4).
pub const MAX_SHARE_HEADS: usize = 1024;

/// Another transaction as the hand-over reads it.
#[derive(Debug)]
pub(super) struct Other {
    pub(super) id: TxnId,
    /// Not closed (open, applied, damaged with a usable head).
    pub(super) live: bool,
    /// Applied, no revert begun.
    pub(super) applied: bool,
    /// Damaged with a usable head.
    pub(super) damaged: bool,
    pub(super) plan: Plan,
    /// The head's object of each op (index aligned with the ops).
    pub(super) objs: Vec<Object>,
    pub(super) ops: BTreeMap<u16, OpLog>,
}

/// The other transactions of a listing a revert needs.
#[derive(Debug, Default)]
pub(super) struct Others {
    pub(super) txns: Vec<Other>,
    /// Entries that cannot be read (a view error, an unusable head or one that does not decode):
    /// their ops are unknown.
    pub(super) blocked: Vec<TxnId>,
}

/// The listed transaction `t` loaded as an [`Other`] (`None`: unreadable).
pub(super) fn load(j: &Journal<'_>, t: &Listed) -> Option<Other> {
    load_or_err(j, t).ok().flatten()
}

/// [`load`], but an error of the journal read is an error (fail closed: a read that fails now
/// may succeed later; skipping it could miss a duty), a head that cannot be used `None`.
fn load_or_err(j: &Journal<'_>, t: &Listed) -> Result<Option<Other>, Refusal> {
    let Ok(v) = t.view.as_ref() else {
        return Ok(None);
    };
    let full = j
        .load(&t.id, crate::journal::VerifyBackups::Length)
        .map_err(Refusal::from)?;
    Ok(other_of(t, v, full))
}

fn other_of(
    t: &Listed,
    v: &crate::journal::TxnView,
    full: crate::journal::TxnView,
) -> Option<Other> {
    if full.head_sha256 != v.head_sha256 || !full.head_usable() {
        return None;
    }
    let plan = super::decode_head(full.head.as_deref()?).ok()?;
    Bindings::of(&plan, &full.rebinds)?;
    let objs = Object::of(&plan).ok()?;
    let reverting = full.ops.values().any(|o| !o.reverts.is_empty());
    Some(Other {
        id: t.id,
        live: !matches!(full.state, TxnState::Closed(_) | TxnState::Empty),
        applied: full.state == TxnState::Applied && !reverting && full.rebinds.is_empty(),
        damaged: matches!(full.state, TxnState::Damaged(_)),
        plan,
        objs,
        ops: full.ops,
    })
}

/// Reads the transactions of `l` other than `own` that the hand-over of `own` can depend on
/// (module docs, S4). `closed`: also closed ones whose listed records hold a `Kept` op.
pub(super) fn read(
    j: &Journal<'_>,
    l: &Listing,
    own: &TxnId,
    closed: bool,
) -> Result<Others, Refusal> {
    let mut out = Others::default();
    // K-HO3 (tests): a forgotten creator honoured.
    let forgotten_too = super::knob_ho(3);
    for t in l
        .txns
        .iter()
        .filter(|t| t.id != *own && (!t.forgotten || forgotten_too))
    {
        let Ok(v) = &t.view else {
            out.blocked.push(t.id);
            continue;
        };
        let wanted = match &v.state {
            TxnState::Empty | TxnState::Closed(Closing::RolledBack) => false,
            TxnState::Closed(Closing::Forgotten) if !forgotten_too => false,
            TxnState::Closed(Closing::Reverted | Closing::Forgotten) => {
                closed
                    && v.ops.values().any(|o| {
                        o.reverted
                            .as_ref()
                            .is_some_and(|r| r.observed == Observed::Kept)
                    })
            }
            TxnState::Damaged(_) if !v.head_usable() => {
                out.blocked.push(t.id);
                false
            }
            TxnState::Open | TxnState::Applied | TxnState::Damaged(_) => true,
        };
        if !wanted {
            continue;
        }
        if out.txns.len() >= MAX_SHARE_HEADS {
            return Err(Refusal::TooManyTransactions {
                limit: MAX_SHARE_HEADS,
            });
        }
        match load_or_err(j, t)? {
            Some(o) => out.txns.push(o),
            None if matches!(v.state, TxnState::Closed(_)) => {}
            None => out.blocked.push(t.id),
        }
    }
    Ok(out)
}

/// The same file of one root (folded path; nested roots are not one file here).
pub(super) fn same_file(a: &Object, b: &Object) -> bool {
    match (a, b) {
        (
            Object::File {
                root: ra,
                path: pa,
                dir: false,
                ..
            },
            Object::File {
                root: rb,
                path: pb,
                dir: false,
                ..
            },
        ) => ra == rb && pa == pb,
        _ => false,
    }
}

/// `o` lies strictly below the folder `dir` of the same root: the folded first segment of `o`
/// below it.
pub(super) fn below(o: &Object, dir: &Object) -> Option<String> {
    match (o, dir) {
        (
            Object::File {
                root: ro, path: po, ..
            },
            Object::File {
                root: rd,
                path: pd,
                dir: true,
                ..
            },
        ) if ro == rd => {
            let rest = po.strip_prefix(pd.as_str())?.strip_prefix('\\')?;
            Some(rest.split('\\').next().unwrap_or(rest).to_owned())
        }
        _ => None,
    }
}

/// `o` is the folder `dir` or lies below it.
fn at_or_below(o: &Object, dir: &Object) -> bool {
    match (o, dir) {
        (
            Object::File {
                root: ro, path: po, ..
            },
            Object::File {
                root: rd, path: pd, ..
            },
        ) => ro == rd && (po == pd || below(o, dir).is_some()),
        _ => false,
    }
}

/// The content of a created file.
fn created(op: &Op) -> Option<&ContentRef> {
    match op {
        Op::CreateFile { content, .. } => Some(content),
        _ => None,
    }
}

/// A relying op (S6): `later` on object `lo` relies on the creator's op `c` on object `co`.
/// For a folder, the folded first segment of `lo` below it; for a file, an empty name.
pub(super) fn relies(later: &Op, lo: &Object, c: &Op, co: &Object) -> Option<String> {
    let kind = matches!(
        later,
        Op::CreateFile { .. } | Op::CreateDir { .. } | Op::Hold { .. }
    );
    if !kind {
        return None;
    }
    match c {
        Op::CreateFile { content, .. } => match later {
            Op::Hold { content: held, .. }
                if same_file(lo, co)
                    && held.sha256() == content.sha256()
                    && held.len() == content.len() =>
            {
                Some(String::new())
            }
            _ => None,
        },
        Op::CreateDir { .. } => below(lo, co),
        _ => None,
    }
}

/// A later op that relies on an op of the reverting transaction (creator side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Relier {
    /// The later transaction.
    pub(super) txn: TxnId,
    /// Its op.
    pub(super) op: u16,
    /// `Done.file_id` of a relying `Hold`.
    pub(super) held_id: Option<u128>,
    /// For a folder: the folded name below it the op accounts for.
    pub(super) name: String,
}

/// The ops of the reverting transaction that later transactions rely on, by op.
pub(super) type Keeps = BTreeMap<u16, Vec<Relier>>;

/// What an inheritor removes, if it is still the creator's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Duty {
    /// A file the creator's `CreateFile` wrote.
    File {
        /// The creator.
        from: TxnId,
        /// Root index in the reverting transaction's head.
        root: u16,
        /// The path in the reverting transaction's spelling.
        path: RelPath,
        /// The creator's content.
        sha256: [u8; 32],
        /// Its length.
        len: u64,
        /// The creator's R/H/S.
        attrs: Attrs,
        /// The creator's `Done.file_id`.
        file_id: u128,
    },
    /// A folder the creator's `CreateDir` made.
    Dir {
        /// The creator.
        from: TxnId,
        /// Root index in the reverting transaction's head.
        root: u16,
        /// The path below the root (a prefix of the carrying op's path).
        path: RelPath,
        /// The creator's `Done.file_id`.
        file_id: u128,
    },
}

impl Duty {
    pub(super) fn from(&self) -> TxnId {
        match self {
            Self::File { from, .. } | Self::Dir { from, .. } => *from,
        }
    }

    pub(super) fn path(&self) -> &RelPath {
        match self {
            Self::File { path, .. } | Self::Dir { path, .. } => path,
        }
    }

    fn depth(&self) -> usize {
        self.path().segments().count()
    }
}

/// An object handed over that another transaction still relies on (for the report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Still {
    /// The creator.
    pub(super) from: TxnId,
    /// The path.
    pub(super) path: RelPath,
    /// A transaction that still relies on it.
    pub(super) by: TxnId,
    /// A folder.
    pub(super) dir: bool,
    /// The creator's file ID (a folder with another one is not Rerun's: not reported).
    pub(super) file_id: u128,
    /// Root index in the reverting transaction's head.
    pub(super) root: u16,
}

/// The inheritor side of one revert.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Inherit {
    /// Carrying op -> duties (a file first, then folders deepest first).
    pub(super) duties: BTreeMap<u16, Vec<Duty>>,
    /// Carrying op -> objects handed over that another transaction still relies on.
    pub(super) still: BTreeMap<u16, Vec<Still>>,
}

/// The ops of `plan` an inheritor could carry a duty on: a relying kind with an intent and no
/// `RevertDone`.
fn relying_ops<'a>(
    plan: &'a Plan,
    ops: &'a BTreeMap<u16, OpLog>,
) -> impl Iterator<Item = (u16, &'a Op)> + 'a {
    plan.ops.iter().enumerate().filter_map(move |(k, op)| {
        let k = super::op_ix(k);
        let log = ops.get(&k)?;
        (matches!(
            op,
            Op::CreateFile { .. } | Op::CreateDir { .. } | Op::Hold { .. }
        ) && log.reverted.is_none())
        .then_some((k, op))
    })
}

/// The reverting transaction has an op that could inherit (S4: closed heads are read only then).
pub(super) fn may_inherit(plan: &Plan, ops: &BTreeMap<u16, OpLog>) -> bool {
    relying_ops(plan, ops).next().is_some()
}

/// Another transaction that is not closed has an op on `obj` (a folder: at or below it) without
/// `RevertDone` (condition d); `None` if none.
fn live_on(others: &Others, obj: &Object, dir: bool) -> Option<TxnId> {
    // K-HO2 (tests): condition (d) off.
    if super::knob_ho(2) {
        return None;
    }
    others.txns.iter().filter(|o| o.live).find_map(|o| {
        o.objs.iter().enumerate().find_map(|(k, x)| {
            let on = if dir {
                at_or_below(x, obj)
            } else {
                same_file(x, obj)
            };
            let open = o
                .ops
                .get(&super::op_ix(k))
                .is_some_and(|l| l.reverted.is_none());
            (on && open).then_some(o.id)
        })
    })
}

/// The duties and the still-relied objects of the applied transaction `own` (module docs).
pub(super) fn duties(
    others: &Others,
    own: &TxnId,
    plan: &Plan,
    ops: &BTreeMap<u16, OpLog>,
) -> Result<Inherit, Refusal> {
    let mine = Object::of(plan).map_err(|_| Refusal::Blocked { txn: *own })?;
    let mut out = Inherit::default();
    // Folder duties by folder: (creator, creator op) -> (carrying op, duty).
    let mut dirs: BTreeMap<(TxnId, u16), (u16, Duty)> = BTreeMap::new();
    let mut stills: BTreeMap<(TxnId, u16), (u16, Still)> = BTreeMap::new();
    for (k, op) in relying_ops(plan, ops) {
        let Some(mo) = mine.get(usize::from(k)) else {
            continue;
        };
        let held_id = ops.get(&k).and_then(|l| l.done).and_then(|d| d.file_id);
        let Some(root) = (match op.target() {
            crate::plan::Target::File { root, .. } => Some(root.0),
            _ => None,
        }) else {
            continue;
        };
        let Some(my_path) = (match op.target() {
            crate::plan::Target::File { path, .. } => Some(path.clone()),
            _ => None,
        }) else {
            continue;
        };
        for c in others.txns.iter().filter(|c| c.id < *own) {
            for (ck, cop) in c.plan.ops.iter().enumerate() {
                let ck16 = super::op_ix(ck);
                let kept = c
                    .ops
                    .get(&ck16)
                    .and_then(|l| l.reverted.as_ref())
                    .is_some_and(|r| r.observed == Observed::Kept);
                if !kept {
                    continue;
                }
                let Some(co) = c.objs.get(ck) else { continue };
                let Some(cid) = c
                    .ops
                    .get(&ck16)
                    .and_then(|l| l.done)
                    .and_then(|d| d.file_id)
                else {
                    continue;
                };
                if relies(op, mo, cop, co).is_none() {
                    continue;
                }
                match cop {
                    Op::CreateFile { attrs, .. } => {
                        // (c) the `Hold` recorded the creator's file ID.
                        if held_id != Some(cid) && !super::knob_ho(1) {
                            continue;
                        }
                        let Some(content) = created(cop) else {
                            continue;
                        };
                        match live_on(others, co, false) {
                            Some(by) => {
                                stills.entry((c.id, ck16)).or_insert((
                                    k,
                                    Still {
                                        from: c.id,
                                        path: my_path.clone(),
                                        by,
                                        dir: false,
                                        file_id: cid,
                                        root,
                                    },
                                ));
                            }
                            None => out.duties.entry(k).or_default().push(Duty::File {
                                from: c.id,
                                root,
                                path: my_path.clone(),
                                sha256: *content.sha256(),
                                len: content.len(),
                                attrs: *attrs,
                                file_id: cid,
                            }),
                        }
                    }
                    Op::CreateDir { .. } => {
                        // The folder in this head's spelling: the prefix of `my_path`.
                        let depth = match co {
                            Object::File { path, .. } => path.split('\\').count(),
                            _ => continue,
                        };
                        let segs: Vec<&str> = my_path.segments().take(depth).collect();
                        let Ok(dir_path) = RelPath::parse(&segs.join("\\")) else {
                            continue;
                        };
                        match live_on(others, co, true) {
                            Some(by) => {
                                // The lowest op of `own` below it reports it.
                                let e = stills.entry((c.id, ck16)).or_insert((
                                    k,
                                    Still {
                                        from: c.id,
                                        path: dir_path.clone(),
                                        by,
                                        dir: true,
                                        file_id: cid,
                                        root,
                                    },
                                ));
                                if k < e.0 {
                                    e.0 = k;
                                }
                            }
                            None => {
                                let duty = Duty::Dir {
                                    from: c.id,
                                    root,
                                    path: dir_path,
                                    file_id: cid,
                                };
                                let e = dirs.entry((c.id, ck16)).or_insert((k, duty));
                                if k < e.0 {
                                    e.0 = k;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    for (_, (k, d)) in dirs {
        out.duties.entry(k).or_default().push(d);
    }
    for (_, (k, s)) in stills {
        out.still.entry(k).or_default().push(s);
    }
    for v in out.duties.values_mut() {
        // A file first, then folders deepest first.
        v.sort_by_key(|d| match d {
            Duty::File { .. } => (0, 0),
            Duty::Dir { .. } => (1, usize::MAX - d.depth()),
        });
    }
    Ok(out)
}

/// What happens to a file or folder another transaction created that an op relies on, journal
/// only (for `status` and the `forget` preview, S3 and default 2 of P4-8b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Line {
    /// Handed over to this transaction: its revert removes it if unchanged; `forget` leaves it
    /// until a later transaction that relies on it is reverted.
    Inherits { from: TxnId },
    /// Created by `from`; the revert of `by` (the creator, or another transaction that still
    /// relies on it) removes it once nothing else relies on it.
    RemovedBy { from: TxnId, by: TxnId },
}

/// The lines of `own` (module docs of [`Line`]), by op, path and whether it is a folder.
pub(super) fn lines(
    others: &Others,
    own: &TxnId,
    plan: &Plan,
    ops: &BTreeMap<u16, OpLog>,
) -> Vec<(u16, RelPath, bool, Line)> {
    let mut out = Vec::new();
    if let Ok(inh) = duties(others, own, plan, ops) {
        for (k, ds) in &inh.duties {
            for d in ds {
                out.push((
                    *k,
                    d.path().clone(),
                    matches!(d, Duty::Dir { .. }),
                    Line::Inherits { from: d.from() },
                ));
            }
        }
        for (k, ss) in &inh.still {
            for s in ss {
                out.push((
                    *k,
                    s.path.clone(),
                    s.dir,
                    Line::RemovedBy {
                        from: s.from,
                        by: s.by,
                    },
                ));
            }
        }
    }
    // A creator that still owns the object (not reverted yet).
    let Ok(mine) = Object::of(plan) else {
        return out;
    };
    for (k, op) in relying_ops(plan, ops) {
        let Some(mo) = mine.get(usize::from(k)) else {
            continue;
        };
        let crate::plan::Target::File { path, .. } = op.target() else {
            continue;
        };
        for c in others.txns.iter().filter(|c| c.live && c.id < *own) {
            for (ck, cop) in c.plan.ops.iter().enumerate() {
                let open = c
                    .ops
                    .get(&super::op_ix(ck))
                    .is_some_and(|l| l.done.is_some() && l.reverted.is_none());
                let Some(co) = c.objs.get(ck) else { continue };
                if !open || relies(op, mo, cop, co).is_none() {
                    continue;
                }
                let (p, dir) = match cop {
                    Op::CreateDir { path: d, .. } => (d.clone(), true),
                    _ => (path.clone(), false),
                };
                if !out.iter().any(|(_, q, _, _)| *q == p) {
                    out.push((
                        k,
                        p,
                        dir,
                        Line::RemovedBy {
                            from: c.id,
                            by: c.id,
                        },
                    ));
                }
            }
        }
    }
    out
}
