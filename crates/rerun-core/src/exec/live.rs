//! What the journal says is live for one game (ADR 0032 amendment P5-OE, slice O-2b): the launch
//! profile a plan carries parts of (S6), and the executables live transactions installed package
//! files or set compatibility flags for (user decision E4 b). [`live_state`] reads without the
//! lock, as the plan's slot check does; the apply checks again under the lock
//! ([`exe_switch`]: E4 b and the profile the plan relied on; the old state of the profile's
//! `ReplaceFile`).
//!
//! **The source of the carried profile (S6):** the newest transaction whose head holds a profile
//! op for the game's profile ID that is done and not reverted, forgotten ones included (the
//! holders of `flow::status`). If it is forgotten, nothing is carried. If it is applied and live,
//! its head's `Inline` bytes are the source, decoded bounded by `rerun_proto::profile`; the file
//! in `profiles` is only hashed, and another content (or none, or one that cannot be read)
//! refuses. An older live holder below a forgotten one is never the source. A transaction whose
//! head cannot be read is passed over: one that is not forgotten blocks every apply anyway
//! (stacking), and one that is forgotten and wrote the profile left a file whose hash is not an
//! older holder's head, so the plan is refused as changed.

use sha2::{Digest, Sha256};

use super::{Refusal, decode_head};
use crate::fold::fold;
use crate::journal::{Closing, InstanceTag, Journal, Listing, TxnId, TxnState, VerifyBackups};
use crate::path::RelPath;
use crate::plan::{
    ContentRef, MAX_PROFILE_OLD_BYTES, Manual, Op, Plan, PlanOrigin, RootKind, Target,
    profile_file, profile_id,
};
use crate::policy::registry::{RegSlot, TokenName};
use crate::policy::root::{AppDir, RootId};
use rerun_proto::profile::{self as proto, LaunchProfile};

/// The live launch profile a plan carries parts of (S6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProfile {
    /// The transaction that wrote it.
    pub txn: TxnId,
    /// The profile, decoded from that transaction's head.
    pub profile: LaunchProfile,
    /// SHA-256 of its bytes (the head's content, equal to the file's).
    pub sha256: [u8; 32],
}

/// The main executable a live transaction of the game was planned for when it installed package
/// files or set compatibility flags (E4 b): its game root's `main_exe` (for flags too, which
/// may name another executable; security F5 of the O-2b review: the wording says "while
/// planned for").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveExe {
    /// The transaction.
    pub txn: TxnId,
    /// The root's `main_exe`, relative to the game folder.
    pub exe: RelPath,
}

/// An option value a live transaction of the game set (its plan's `PlanSource::choices`), for
/// the game page (the UI slice of ADR 0032): the newest live transaction that chose a value of
/// the option, per option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveChoice {
    /// The transaction (applied completely, not forgotten, no op reverted).
    pub txn: TxnId,
    /// The Topo it was planned from.
    pub topo: String,
    /// The option ID.
    pub option: String,
    /// The value ID.
    pub value: String,
}

/// The user's own settings ("Advanced", ADR 0029) the live transactions of the game applied, for
/// the game page's form: what each part of the form shows, with the change that set it. The
/// launch part is the newest live one (a later profile replaces an earlier one), flags add up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveManual {
    /// The newest live transaction that recorded own settings.
    pub txn: TxnId,
    /// What is live of them, merged: the newest launch part, every flag once. As the plans
    /// recorded it (display and form only: the ops are the truth).
    pub manual: Manual,
    /// The transaction that set the launch part (`None`: no launch part is live).
    pub launch_txn: Option<TxnId>,
    /// Each live flag with the transaction that set it (the newest, if one was set twice).
    pub flags: Vec<(TokenName, TxnId)>,
}

/// What is live for one game.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveState {
    /// The profile to carry parts of (`None`: nothing live, or the newest holder is forgotten).
    pub profile: Option<LiveProfile>,
    /// Executables of live transactions of the game folder with package files or flags.
    pub exes: Vec<LiveExe>,
    /// The option values live transactions of the game folder chose, newest per option.
    pub choices: Vec<LiveChoice>,
    /// The user's own settings the newest live transaction of the game folder applied.
    pub manual: Option<LiveManual>,
}

/// Why the live state does not allow a plan for the game.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LiveError {
    /// The journal cannot be listed.
    #[error("Rerun's journal cannot be read: {0}")]
    Journal(String),
    /// The newest holder of the profile is interrupted, being undone or damaged.
    #[error(
        "transaction {txn} holds the launch profile of this game and is not applied completely \
         (interrupted, being undone or damaged); undo or forget {txn} first"
    )]
    Interrupted {
        /// The transaction.
        txn: TxnId,
    },
    /// The newest holder's head holds bytes that are no launch profile of this version.
    #[error(
        "the launch profile transaction {txn} wrote is not one this version reads; undo or \
         forget {txn} first"
    )]
    Unreadable {
        /// The transaction.
        txn: TxnId,
    },
    /// The file is not what the newest holder wrote (changed, removed or unreadable).
    #[error(
        "the launch profile changed since transaction {txn} wrote it (or cannot be read); undo \
         or forget {txn} first"
    )]
    Changed {
        /// The transaction.
        txn: TxnId,
    },
}

/// The op of `p` on its profiles root, with its index (a plan has at most one).
pub(crate) fn profile_op(p: &Plan) -> Option<(usize, &Op, &RelPath)> {
    p.ops.iter().enumerate().find_map(|(k, op)| {
        let Target::File { root, path, .. } = op.target() else {
            return None;
        };
        let r = p.roots.get(usize::from(root.0))?;
        (r.kind == RootKind::Profiles).then_some((k, op, path))
    })
}

/// The inline bytes a profile op writes.
pub(crate) fn inline_bytes(op: &Op) -> Option<&[u8]> {
    match op.content() {
        Some(ContentRef::Inline { bytes, .. }) => Some(bytes),
        _ => None,
    }
}

/// The ops of `p` that hold package files or compatibility flags (E4 b, B1), each with its op
/// index, its game root and the executable it is bound to: a file op with package content (a
/// `Hold` too) to its root's `main_exe` (the build it was planned for); a `TokenList` with
/// `by_slot` to the executable of its `CompatLayers` slot (B1: the flags on the executable a
/// `run` starts, security F5), else to its root's `main_exe` (E4 b: the executable the plan was
/// for; a flag on a launcher must not hold every later plan of the game).
pub(crate) fn bound_exes(p: &Plan, by_slot: bool) -> Vec<(usize, usize, RelPath)> {
    let mut out = Vec::new();
    for (k, op) in p.ops.iter().enumerate() {
        let at = match (op, op.target()) {
            (
                Op::TokenList {
                    slot: RegSlot::CompatLayers { root, exe },
                    ..
                },
                _,
            ) if by_slot => Some((usize::from(root.0), exe.clone())),
            (Op::TokenList { slot, .. }, _) => crate::plan::slot_root(slot).and_then(|root| {
                let i = usize::from(root.0);
                p.roots
                    .get(i)
                    .and_then(|r| r.main_exe.clone())
                    .map(|m| (i, m))
            }),
            (_, Target::File { root, .. }) if op.package_file().is_some() => {
                let i = usize::from(root.0);
                p.roots
                    .get(i)
                    .and_then(|r| r.main_exe.clone())
                    .map(|m| (i, m))
            }
            _ => None,
        };
        if let Some((i, exe)) = at
            && p.roots.get(i).is_some_and(|r| r.kind == RootKind::Game)
        {
            out.push((k, i, exe));
        }
    }
    out
}

/// The newest holder of a profile seen in a listing.
pub(crate) struct Holder {
    /// The transaction.
    pub(crate) txn: TxnId,
    /// It is forgotten.
    forgotten: bool,
    /// Applied completely, no revert begun, no rebind.
    usable: bool,
    /// Its profile op's inline bytes.
    bytes: Option<Vec<u8>>,
}

/// What one pass over the listing found for profile `name` and game root `game`.
struct Scan {
    holder: Option<Holder>,
    exes: Vec<LiveExe>,
    choices: Vec<LiveChoice>,
    manual: Option<LiveManual>,
}

fn scan(j: &Journal<'_>, l: &Listing, name: Option<&RelPath>, game: Option<RootId>) -> Scan {
    let mut holder: Option<Holder> = None;
    let mut exes = Vec::new();
    let mut choices: Vec<LiveChoice> = Vec::new();
    let mut manual: Option<LiveManual> = None;
    for t in &l.txns {
        let Ok(v) = &t.view else { continue };
        if matches!(v.state, TxnState::Empty) {
            continue;
        }
        let Ok(full) = j.load(&t.id, VerifyBackups::Length) else {
            continue;
        };
        let Some(p) = full.head.as_deref().and_then(|h| decode_head(h).ok()) else {
            continue;
        };
        let forgotten = t.forgotten || full.state == TxnState::Closed(Closing::Forgotten);
        if let (Some(name), Some((k, op, path))) = (name, profile_op(&p))
            && path == name
            && full
                .ops
                .get(&super::op_ix(k))
                .is_some_and(|o| o.done.is_some() && o.reverted.is_none())
        {
            let usable = !forgotten
                && full.state == TxnState::Applied
                && full.rebinds.is_empty()
                && full.ops.values().all(|o| o.reverts.is_empty());
            holder = Some(Holder {
                txn: t.id,
                forgotten,
                usable,
                bytes: inline_bytes(op).map(<[u8]>::to_vec),
            });
        }
        let Some(game) = game else { continue };
        if forgotten || matches!(full.state, TxnState::Closed(_)) {
            continue;
        }
        // The option values and the own settings of a transaction that is applied completely; a
        // later one that chose another value of the same option (or set own settings again)
        // replaces the entry (the listing is in order).
        let here_live = full.state == TxnState::Applied
            && full.ops.values().all(|o| o.reverted.is_none())
            && p.roots
                .iter()
                .any(|r| r.kind == RootKind::Game && r.id == game);
        if here_live && let Some(m) = &p.manual {
            let live = manual.get_or_insert_with(|| LiveManual {
                txn: t.id,
                manual: Manual::default(),
                launch_txn: None,
                flags: Vec::new(),
            });
            live.txn = t.id;
            if m.launch.is_some() {
                live.manual.launch.clone_from(&m.launch);
                live.launch_txn = Some(t.id);
            }
            for l in &m.layers {
                live.flags.retain(|(x, _)| x != l);
                live.flags.push((l.clone(), t.id));
            }
            live.manual.layers = live.flags.iter().map(|(x, _)| x.clone()).collect();
        }
        if here_live && let Some(src) = &p.source {
            for c in &src.choices {
                choices.retain(|x| !(x.topo == src.topo && x.option == c.option));
                choices.push(LiveChoice {
                    txn: t.id,
                    topo: src.topo.clone(),
                    option: c.option.clone(),
                    value: c.value.clone(),
                });
            }
        }
        for (k, i, exe) in bound_exes(&p, false) {
            let reverted = full
                .ops
                .get(&super::op_ix(k))
                .is_some_and(|o| o.reverted.is_some());
            let here = p.roots.get(i).is_some_and(|r| r.id == game);
            if here && !reverted && !exes.iter().any(|e: &LiveExe| e.txn == t.id && e.exe == exe) {
                exes.push(LiveExe { txn: t.id, exe });
            }
        }
    }
    Scan {
        holder,
        exes,
        choices,
        manual,
    }
}

/// The profile a usable holder wrote, decoded, with its SHA-256 (`Unreadable` for content that
/// is not inline or not a profile of this version).
pub(crate) fn source_of(
    txn: TxnId,
    bytes: Option<&[u8]>,
) -> Result<(LaunchProfile, [u8; 32]), LiveError> {
    let bytes = bytes.ok_or(LiveError::Unreadable { txn })?;
    let profile = proto::decode(bytes).map_err(|_| LiveError::Unreadable { txn })?;
    Ok((profile, Sha256::digest(bytes).into()))
}

/// What is live for the Steam app `app_id` (its profile; `None`: no profile looked for) in the
/// game folder `game` (module docs).
///
/// # Errors
/// [`LiveError`]: the journal cannot be listed, or the newest holder of the profile cannot be
/// the source.
pub fn live_state(
    app: &AppDir<'_>,
    app_id: Option<u32>,
    game: RootId,
) -> Result<LiveState, LiveError> {
    let j = Journal::new(app, InstanceTag::new());
    let l = j
        .list()
        .map_err(|e| LiveError::Journal(crate::escape::text(&e.to_string()).to_string()))?;
    let name = app_id.map(|id| profile_file(profile_id(id)));
    let s = scan(&j, &l, name.as_ref(), Some(game));
    let profile = match s.holder {
        None => None,
        Some(h) if h.forgotten => None,
        Some(h) if !h.usable => return Err(LiveError::Interrupted { txn: h.txn }),
        Some(h) => {
            let txn = h.txn;
            let (profile, sha256) = source_of(txn, h.bytes.as_deref())?;
            let file = name
                .as_ref()
                .and_then(|n| {
                    let dir = app.profiles_read().ok()??;
                    dir.read_limited(n, MAX_PROFILE_OLD_BYTES).ok()
                })
                .ok_or(LiveError::Changed { txn })?;
            let file_sha: [u8; 32] = Sha256::digest(&file).into();
            if file_sha != sha256 {
                return Err(LiveError::Changed { txn });
            }
            Some(LiveProfile {
                txn,
                profile,
                sha256,
            })
        }
    };
    Ok(LiveState {
        profile,
        exes: s.exes,
        choices: s.choices,
        manual: s.manual,
    })
}

/// E4 b and the kept profile under the journal lock (security F1 of the O-2b review), from the
/// listing and the heads only, after stacking:
/// 1. a live transaction (not forgotten, not closed) of a game root of `plan` (identity) with
///    package files or flags for another executable than the root's `main_exe` (folded):
///    [`Refusal::ExeSwitch`];
/// 2. a plan that names the live profile it relied on (`PlanSource::kept_profile`): the newest
///    holder of the game's profile must be applied completely and hold exactly those bytes,
///    else [`Refusal::ProfileChanged`] (the profile was undone, replaced or forgotten between
///    plan and apply: the plan's main executable may no longer be the one that starts);
/// 3. a plan with package files or flags and without a profile op of its own that names no
///    kept profile: a usable newest holder with a `run` must start the root's `main_exe`, else
///    [`Refusal::ProfileChanged`].
pub(crate) fn exe_switch(j: &Journal<'_>, l: &Listing, plan: &Plan) -> Result<(), Refusal> {
    for r in plan.roots.iter().filter(|r| r.kind == RootKind::Game) {
        let Some(main) = &r.main_exe else { continue };
        let app_id = match &r.origin {
            PlanOrigin::Steam { app_id, .. } => Some(*app_id),
            _ => None,
        };
        let name = app_id.map(|id| profile_file(profile_id(id)));
        let s = scan(j, l, name.as_ref(), Some(r.id));
        if let Some(e) = s
            .exes
            .iter()
            .find(|e| fold(e.exe.as_str()) != fold(main.as_str()))
        {
            return Err(Refusal::ExeSwitch { txn: e.txn });
        }
        let kept = plan.source.as_ref().and_then(|s| s.kept_profile);
        let usable = s.holder.as_ref().filter(|h| h.usable);
        let held = usable.and_then(|h| source_of(h.txn, h.bytes.as_deref()).ok());
        if let Some(sha) = kept {
            if held.as_ref().is_none_or(|(_, x)| *x != sha) {
                return Err(Refusal::ProfileChanged);
            }
            continue;
        }
        let bound = !bound_exes(plan, false).is_empty();
        if bound
            && profile_op(plan).is_none()
            && let Some((p, _)) = &held
            && let Some(run) = &p.run
            && below(&r.path.to_string(), run).is_none_or(|x| x != fold(main.as_str()))
        {
            return Err(Refusal::ProfileChanged);
        }
    }
    Ok(())
}

/// The executable below game root `root` (its canonical path) that `abs` names, folded: `abs`
/// starts with the root's path and one `\` exactly (the planner builds the profile's paths so).
pub(crate) fn below(root: &str, abs: &str) -> Option<String> {
    let rest = abs.strip_prefix(root)?.strip_prefix('\\')?;
    RelPath::parse(rest).ok().map(|r| fold(r.as_str()))
}

#[cfg(test)]
mod tests {
    use super::{LiveError, source_of};

    /// F3 of the O-2b review: a holder's content that is no inline profile, or bytes that are
    /// no profile of this version, is `Unreadable` (the fence of `plan::decode` refuses such a
    /// head first; this is the step behind it).
    #[test]
    fn a_holder_without_a_readable_profile_is_unreadable() {
        let t: crate::journal::TxnId = "00000003-0000000000000001".parse().unwrap();
        assert_eq!(
            source_of(t, None).unwrap_err(),
            LiveError::Unreadable { txn: t }
        );
        assert_eq!(
            source_of(t, Some(b"rerun-profile 9\n")).unwrap_err(),
            LiveError::Unreadable { txn: t }
        );
    }
}
