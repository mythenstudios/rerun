//! What the journal says is live for one game (ADR 0032 amendment P5-OE, slice O-2b): the launch
//! profile a plan carries parts of (S6), and the main executables of live transactions with
//! package files or compatibility flags (user decision E4 b). Read only, without the lock, like
//! the plan's slot check: the apply checks again under the lock (stacking, the old state of the
//! profile's `ReplaceFile`).
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

use super::decode_head;
use crate::fold::fold;
use crate::journal::{Closing, InstanceTag, Journal, TxnId, TxnState, VerifyBackups};
use crate::path::RelPath;
use crate::plan::{
    ContentRef, MAX_PROFILE_OLD_BYTES, Op, Plan, RootKind, Target, profile_file, profile_id,
};
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

/// A live transaction of the game with package files or compatibility flags, and the main
/// executable it was planned for (E4 b, B1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveExe {
    /// The transaction.
    pub txn: TxnId,
    /// Its game root's main executable.
    pub main_exe: RelPath,
}

/// What is live for one game.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveState {
    /// The profile to carry parts of (`None`: nothing live, or the newest holder is forgotten).
    pub profile: Option<LiveProfile>,
    /// Live transactions of the game folder with package files or compatibility flags.
    pub exes: Vec<LiveExe>,
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

/// The op holds package files or compatibility flags (E4 b, B1): a file op with package content,
/// or a `TokenList`.
pub(crate) fn exe_bound(op: &Op) -> bool {
    op.package_file().is_some() || matches!(op, Op::TokenList { .. })
}

/// The holder seen last in the listing.
struct Holder {
    txn: TxnId,
    forgotten: bool,
    usable: bool,
    bytes: Option<Vec<u8>>,
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
    let mut holder: Option<Holder> = None;
    let mut exes = Vec::new();
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
        let not_reverted = |k: usize| {
            full.ops
                .get(&super::op_ix(k))
                .is_none_or(|o| o.reverted.is_none())
        };
        if let (Some(name), Some((k, op, path))) = (&name, profile_op(&p))
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
        if forgotten || matches!(full.state, TxnState::Closed(_)) {
            continue;
        }
        for (i, r) in p.roots.iter().enumerate() {
            let (RootKind::Game, Some(main)) = (r.kind, &r.main_exe) else {
                continue;
            };
            if r.id != game {
                continue;
            }
            let holds = p.ops.iter().enumerate().any(|(k, op)| {
                let on_root = match op.target() {
                    Target::File { root, .. } => usize::from(root.0) == i,
                    _ => true,
                };
                on_root && exe_bound(op) && not_reverted(k)
            });
            if holds {
                exes.push(LiveExe {
                    txn: t.id,
                    main_exe: main.clone(),
                });
            }
        }
    }
    let profile = match holder {
        None => None,
        Some(h) if h.forgotten => None,
        Some(h) if !h.usable => return Err(LiveError::Interrupted { txn: h.txn }),
        Some(h) => {
            let txn = h.txn;
            let bytes = h.bytes.ok_or(LiveError::Unreadable { txn })?;
            let profile = proto::decode(&bytes).map_err(|_| LiveError::Unreadable { txn })?;
            let sha256: [u8; 32] = Sha256::digest(&bytes).into();
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
    Ok(LiveState { profile, exes })
}

/// The executable below game root `root` (its canonical path) that `abs` names, folded: `abs`
/// starts with the root's path and one `\` exactly (the planner builds the profile's paths so).
pub(crate) fn below(root: &str, abs: &str) -> Option<String> {
    let rest = abs.strip_prefix(root)?.strip_prefix('\\')?;
    RelPath::parse(rest).ok().map(|r| fold(r.as_str()))
}
