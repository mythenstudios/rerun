//! The binding of each root of a recorded head (P2-14, ADR 0020 amendment): the head's root, or
//! the folder the last `Rebind` record of that root names. The head itself is never rewritten:
//! a binding acts only where a root is opened (`roots::open_root`), so on the file ops, the
//! game-closed check (D4) and the file objects of stacking; every registry location is built
//! from the head's roots (the values Rerun wrote, user decision E-R4 a).
//!
//! The journal is untrusted (`docs/06-security.md`, row 14) and does not parse the head, so
//! [`Bindings::of`] checks every rebind against it on every run: a root index inside the head,
//! a Steam root (a manual root is never rebound), `old` the identity bound before (the chain), a
//! binding that changes something, a library path from which the game folder
//! `<store>\steamapps\common\<installdir>` (the head's install folder) is a root path, proofs
//! only for `CreateDir` ops of that root, and no `RevertIntent` of a file op of that root before
//! the record (user decision E-R3), and no rebound root on the folder of another root or inside or around
//! one (review S1). Any violation: `None`, which the caller turns into `Blocked`.

use std::collections::BTreeMap;

use crate::journal::RebindRec;
use crate::path::RootPath;
use crate::plan::{FileRoot, Object, Op, Plan, PlanError, PlanOrigin, Target};
use crate::policy::root::RootId;

/// How a `CreateDir` of a root proves that the folder there is the one Rerun created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Proof {
    /// The head's folder: `Done.file_id` (or the in-process result; D1 for a recovery).
    Done,
    /// A rebound root: the file ID its `Rebind` record names for the op; without one only a
    /// missing folder is accepted (`Before`), anything else is `Foreign` (E-R2 a).
    Rebound(BTreeMap<u16, u128>),
    /// Read only, before a rebind is recorded: the folder found there counts, if it is empty but
    /// for what later ops remove (E-R2 a: exactly what the preview shows, "not provably Rerun's").
    Found,
}

/// Where root `i` of a head is bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Binding {
    /// Canonical path of the game folder.
    pub(super) path: RootPath,
    /// Its identity.
    pub(super) id: RootId,
    /// How it is reopened (a rebound Steam root: the new library with the head's app ID and
    /// install folder).
    pub(super) origin: PlanOrigin,
    /// How its created folders are proven.
    pub(super) proof: Proof,
}

impl Binding {
    /// The game folder of the head's Steam root `head` in the library `store` (identity
    /// `store_id`), with identity `id`: `None` for a manual root or if the path is no root path.
    pub(super) fn steam(
        head: &crate::plan::PlanRoot,
        store: &RootPath,
        store_id: RootId,
        id: RootId,
        proof: Proof,
    ) -> Option<Self> {
        let PlanOrigin::Steam {
            app_id, installdir, ..
        } = &head.origin
        else {
            return None;
        };
        let path = store
            .child("steamapps")
            .and_then(|p| p.child("common"))
            .and_then(|p| p.child(installdir.as_str()))
            .ok()?;
        Some(Self {
            path,
            id,
            origin: PlanOrigin::Steam {
                store: store.clone(),
                store_id,
                app_id: *app_id,
                installdir: installdir.clone(),
            },
            proof,
        })
    }

    /// The library of a Steam binding.
    pub(super) fn store(&self) -> Option<(&RootPath, RootId)> {
        match &self.origin {
            PlanOrigin::Steam {
                store, store_id, ..
            } => Some((store, *store_id)),
            PlanOrigin::Manual | PlanOrigin::AppDir => None,
        }
    }
}

/// The binding of every root of a head, by index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Bindings {
    roots: Vec<Binding>,
    /// Some root is bound to another folder than the head's.
    rebound: bool,
}

impl Bindings {
    /// The head's roots as they are (an apply, a transaction without rebinds).
    pub(super) fn head(plan: &Plan) -> Self {
        Self {
            roots: plan
                .roots
                .iter()
                .map(|r| Binding {
                    path: r.path.clone(),
                    id: r.id,
                    origin: r.origin.clone(),
                    proof: Proof::Done,
                })
                .collect(),
            rebound: false,
        }
    }

    /// The head's roots with `rebinds` applied in order, checked against the head (module
    /// docs); `None` if one does not fit (the caller: `Blocked`).
    pub(super) fn of(plan: &Plan, rebinds: &[RebindRec]) -> Option<Self> {
        let mut b = Self::head(plan);
        for r in rebinds {
            let i = usize::from(r.root);
            let head = plan.roots.get(i)?;
            let now = b.roots.get(i)?;
            if r.old != now.id {
                return None;
            }
            if now
                .store()
                .is_some_and(|(s, sid)| *s == r.store && sid == r.store_id && now.id == r.id)
            {
                // Nothing changes: no writer of Rerun records such a rebind.
                return None;
            }
            let mut dirs = BTreeMap::new();
            for d in &r.dirs {
                match plan.ops.get(usize::from(d.op))? {
                    Op::CreateDir { root, .. } if root.0 == r.root => {}
                    _ => return None,
                }
                dirs.insert(d.op, d.file_id);
            }
            // E-R3: never once a file op of this root had a revert intent.
            if let Some(from) = r.reverting
                && file_ops(plan, r.root).any(|k| k >= from)
            {
                return None;
            }
            let new = Binding::steam(head, &r.store, r.store_id, r.id, Proof::Rebound(dirs))?;
            *b.roots.get_mut(i)? = new;
            b.rebound = true;
            if b.clashes(i) {
                return None;
            }
        }
        Some(b)
    }

    /// Root `i` is bound to the folder of another root of the head, or to a folder inside or
    /// around one (P2-14 security review S1: apps sharing an install folder, `Half-Life` of the
    /// GoldSrc apps; two ops on one file would revert each other's state).
    pub(super) fn clashes(&self, i: usize) -> bool {
        let Some(x) = self.roots.get(i) else {
            return true;
        };
        self.roots.iter().enumerate().any(|(j, y)| {
            j != i && (y.id == x.id || x.path.contains(&y.path) || y.path.contains(&x.path))
        })
    }

    /// Root `i`.
    pub(super) fn get(&self, i: usize) -> Option<&Binding> {
        self.roots.get(i)
    }

    /// With root `i` bound to `b` (the observation before a rebind).
    pub(super) fn with(&self, i: usize, b: Binding) -> Option<Self> {
        let mut out = self.clone();
        *out.roots.get_mut(i)? = b;
        out.rebound = true;
        Some(out)
    }

    /// Every root, by index.
    pub(super) fn iter(&self) -> impl Iterator<Item = &Binding> {
        self.roots.iter()
    }

    /// Number of roots.
    pub(super) fn len(&self) -> usize {
        self.roots.len()
    }

    /// The objects of `plan` for stacking (E-R3): at the head's roots and, while a root is
    /// rebound, also at the bound folders, until the transaction is closed. Registry objects
    /// always from the head.
    pub(super) fn objects(&self, plan: &Plan) -> Result<Vec<Object>, PlanError> {
        Ok(self
            .objects_by_op(plan)?
            .into_iter()
            .map(|(_, o)| o)
            .collect())
    }

    /// [`Self::objects`], each with the index of its op (P4-8: a `Hold` and the package of a
    /// file are found by the op).
    pub(super) fn objects_by_op(&self, plan: &Plan) -> Result<Vec<(usize, Object)>, PlanError> {
        let mut objs: Vec<(usize, Object)> = Object::of(plan)?.into_iter().enumerate().collect();
        if self.rebound && super::knob_objects_from_binding_only() {
            // K-RB4 (tests): the objects at the old identity dropped (what E-R3 forbids).
            objs.retain(|(_, o)| !matches!(o, Object::File { .. }));
        }
        if self.rebound && !super::knob_objects_from_head() {
            let roots: Vec<FileRoot> = self
                .roots
                .iter()
                .map(|b| FileRoot {
                    id: b.id,
                    path: b.path.clone(),
                })
                .collect();
            objs.extend(
                Object::of_bound(plan, &roots)?
                    .into_iter()
                    .enumerate()
                    .filter(|(_, o)| matches!(o, Object::File { .. })),
            );
        }
        Ok(objs)
    }
}

/// The indices of the file ops of root `root`.
pub(super) fn file_ops(plan: &Plan, root: u16) -> impl Iterator<Item = u16> + '_ {
    plan.ops
        .iter()
        .enumerate()
        .filter(move |(_, o)| matches!(o.target(), Target::File { root: r, .. } if r.0 == root))
        .map(|(k, _)| super::op_ix(k))
}
