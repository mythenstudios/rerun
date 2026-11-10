//! Plans (ADR 0020 and its P2-8 amendment): the ops a primitive's planner emits, serialised
//! once, bound to the preview by [`PlanHash`], stored below `<AppDir>\plans` and, as the
//! transaction's `head.json`, read again by `exec`.
//!
//! Wire format 1 (`serde_json`, `deny_unknown_fields`, no maps): `{"format":1,"roots":[…],
//! "ops":[…]}`; enums are externally tagged in `snake_case` (`{"create_file":{…}}`, a unit
//! variant as its name, `"manual"`); every SHA-256 is 64 lower-case hex digits, a [`RootId`]
//! `<16 hex>-<32 hex>`, paths are strings with `\`. [`Plan::encode`] is the one serialisation:
//! its bytes are what the preview shows, what is stored and what `exec` applies, and
//! [`PlanHash`] is SHA-256 over exactly these bytes. [`decode`] treats bytes as untrusted:
//! the format first, then a strict parse, then the one-form check (re-encoding the result
//! gives the same bytes: no whitespace, field order, `/`, lower-case drive letter or other
//! spelling), then the same bounds as `encode` ([`MAX_OPS`], [`MAX_OP_BYTES`],
//! [`MAX_PLAN_BYTES`], root indices, package names, one op per object).
//!
//! Phase 2 has the file op kinds `CreateDir`, `CreateFile`, `ReplaceFile`, `IniValue` (P2-12) and
//! the registry op kinds `CreateKey`, `SetValue` (P2-10b) and `TokenList` (P2-11) (format 1
//! stays unstable until the first release, ADR 0019 amendment E1).
//!
//! Registry ops (ADR 0020 amendment P2-10b), checked on encode and decode alike (the journal
//! head is untrusted): every slot passes `RegPolicy::check` with the plan's roots, every new
//! value `RegPolicy::check_new` (a `CompatLayers` value is never set: only a `TokenList` names
//! that slot's value, P2-11); every
//! registry op comes after every file op (a revert that halts at a file op has then reverted
//! every registry op, 6b-d); one op per key and per value (folded); a `CreateKey` names its
//! key by `segs` within its slot, and comes before every key and value below it; an old value
//! is consistent (length at most 1 MiB, its bytes inline exactly up to [`OLD_INLINE`] with
//! their hash), differs from the new one, and is absent in a key the plan creates; a plan with
//! registry ops has at least one root and a main executable for each (user decision E2).
//!
//! Two rule sets (P2-11, user decision E4; the rule half of ADR 0018 open point S1): planning,
//! [`Plan::encode`] and the apply decode with [`Rules::Current`], every rule in force now;
//! the revert, `verify` and the stacking check decode a recorded head with
//! [`Rules::Recorded`]: the same location and form rules, without the rules for new values
//! (`RegPolicy::check_new`), so a rule tightened by a later version never makes an applied
//! transaction unrevertable. A revert only writes back old values from the journal; it never
//! writes a new value.
//!
//! `TokenList` (P2-11, ADR 0020 amendment P2-11): only on a `CompatLayers` slot; the old value
//! missing or a `REG_SZ` in the strict grammar of `policy::registry::layers` (at most 1 KiB, so
//! always inline); 1 to 8 tokens in byte order (unique), none already in the old value
//! (folded); the new value in the grammar and other than the old one; with an old value not in a
//! key the plan creates. [`Rules::Current`] adds the token rules (`RegPolicy::check_tokens`:
//! allowlist, groups of the added tokens, an old value without a joined prefix, length) and `new` equal to `layers::merge(old, add)`; [`Rules::Recorded`]
//! keeps the form and the version-independent relation (an old value: `new` is it, one space
//! and the tokens; none: `new` ends with the tokens), not the allowlist, the groups or the
//! prefix of a new value (a later allowlist or prefix must not block the revert). Its optional
//! `machine` (P3-6, ADR 0018 amendment P3-6) records the "all users" (`HKLM`) value of the same
//! executable the planner read, per view, for the preview only (never written or re-observed):
//! at most one per view in view order, each in the grammar; [`Rules::Current`] adds that none
//! holds a word of a group of an added token.
//!
//! `GpuPref` (P4-11, ADR 0020 amendment P4-11): only on a `GpuPreference` slot; the old value
//! missing or an inline `REG_SZ` (at most `gpu_pref::MAX_PREF_BYTES`, so always inline); with an
//! old value not in a key the plan creates; the new value other than the old one and exactly
//! the old one with Rerun's pair set to `pref` (in its place, or appended; none: the pair alone),
//! a version-independent string relation checked by both rule sets (the S-1 analogue: a
//! recorded head can never make the restore of `After` write a pair the plan did not set).
//! [`Rules::Current`] adds the grammar of the old and the new value and
//! `RegPolicy::check_pref` (not "Power saving", not set already) with `new` equal to
//! `gpu_pref::set(old, pref)`. A later, tighter grammar never blocks a revert.
//!
//! `IniValue` (P2-12, ADR 0020 amendment P2-12, ADR 0021): a file op on an existing `.ini` file
//! (`policy::ini::path_ok`: not `desktop.ini`); its edits pass `policy::ini::check_edits` (1 to
//! 8, canonical order, unique, a section new or existing as a whole, every new value not empty
//! and other than its old one); old and new content at most 1 MiB and different. The new
//! content is [`FileHash`] (its R/H/S are the old ones). [`Rules::Current`] adds
//! `IniText::check_new` for every new value; [`Rules::Recorded`] keeps the form, the extension
//! and the dialect (a narrower dialect is a format change, never silent). An `IniValue`, like a
//! registry op, needs the main executable of every root ([`Op::needs_main_exe`], user decision
//! E5: the game holds no INI open while it runs).
//!
//! Launch profiles (P3-3, ADR 0020 amendment P3-3, `profile`): a second root kind
//! [`RootKind::Profiles`] (`<LocalAppData>\Rerun\profiles`, origin [`PlanOrigin::AppDir`], the
//! fixed identity [`PROFILES_ROOT_ID`]: reopened only through `AppDir`, never by the head's path or
//! by identity) and a second content source [`ContentRef::Inline`] (the bytes in the plan, at most
//! [`MAX_INLINE_BYTES`]). `profile::fence` checks both on encode and decode alike (the head is
//! untrusted); [`Rules::Current`] adds the profile decode, its start and target paths below
//! root 0 and each at most [`MAX_EXE_PATH_UNITS`] UTF-16 units, the target of a `watch` profile
//! equal to `<root 0>\<main executable of root 0>` (P3-4), and its file name from the Steam app
//! ID ([`profile_id`]).
//!
//! `Hold` (P4-8, ADR 0020 amendment P4-8): a package file the game folder already holds with
//! exactly the content of the step (a shared dependency another transaction installed, such as
//! the ASI loader's `dinput8.dll`, or the user's own copy). Nothing is written: the op names the
//! file as an object of the transaction it relies on: an earlier transaction that created it
//! hands it over when it is reverted first, and the last revert that relies on it removes it
//! (P4-8b, `exec::share`; a file an earlier transaction replaced stays newest first). Its content is a [`ContentRef::Package`] (the
//! package and the place it comes from, for the preview and the slots of later plans), never
//! inline, on a [`RootKind::Game`] root; it is a file op (`Target::File`, before every registry
//! op). Its revert changes nothing.
//!
//! [`ContentRef::Patch`] (P4-10, `laa_patch`, ADR 0020 amendment P4-10): the content of a
//! `ReplaceFile` that is the old file with single bytes changed ([`ByteEdit`]: offset, old byte,
//! new byte; 1 to [`MAX_PATCH_EDITS`], strictly ascending, inside the file, each a change) and
//! the SHA-256 of the result. `patch_check` holds on encode and decode alike: only in a
//! `ReplaceFile` on a game root, its `base` exactly the op's `old`. The op is otherwise a plain
//! replace: backup, observation and revert are those of `ReplaceFile`.

mod preview;
mod profile;
mod store;
mod user_data;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use preview::{
    FIREWALL_NOTE, FirewallShown, GPU_PREF_ACTION, GPU_PREF_NOTE, HOLD_ACTION, HOLD_NOTE, INI_NOTE,
    IniOldShown, IniShown, LAYERS_NOTE, NOT_RESTORED, PATCH_ACTION, PATCH_NOTE, PROFILE_NOTE,
    PROFILE_WATCH_NOTE, PatchByte, Preview, PreviewOp, PreviewRoot, ProfilePreview, ProfileShown,
    REGISTRY_NOTE, RegShown, USER_DATA_NOTE, preview, preview_head, preview_stored,
};
#[cfg(test)]
pub(crate) use profile::knob as profile_knob;
pub use profile::{MAX_EXE_PATH_UNITS, MAX_PROFILE_OLD_BYTES, profile_file, profile_id};
pub use store::{load, store};

use crate::fold::fold;
use crate::path::{RelPath, RootPath};
use crate::policy::firewall::{Direction, Program};
use crate::policy::ini::{self, IniEdit, IniError};
use crate::policy::registry::{
    GpuPref, RegPolicy, RegPolicyError, RegSlot, TokenName, gpu_pref, layers,
};
use crate::policy::root::{RootError, RootId, UserBase};
use crate::sys::SysError;
use crate::sys::fs::Attrs;
use crate::sys::registry::{MAX_VALUE_BYTES, RegKey, RegValue};

/// The one plan format.
pub const FORMAT: u32 = 1;
/// Most ops of a plan (ADR 0019, condition S1).
pub const MAX_OPS: usize = 128;
/// Most bytes of one serialised op.
pub const MAX_OP_BYTES: usize = 8 << 10;
/// Most bytes of a serialised plan (`head.json`).
pub const MAX_PLAN_BYTES: usize = 1 << 20;
/// Most roots of a plan.
pub const MAX_ROOTS: usize = 16;
/// Largest file a plan installs or replaces (the hash limit of ADR 0014, a backup's limit).
pub const MAX_FILE_LEN: u64 = 2 << 30;
/// Most bytes of all backups of one plan (the journal's limit per transaction).
pub const MAX_BACKUP_BYTES: u64 = 4 << 30;
/// Most bytes of [`ContentRef::Inline`] (a launch profile with a start path of at most
/// [`MAX_EXE_PATH_UNITS`] is about 1.8 KiB; as hex the op stays below [`MAX_OP_BYTES`]).
pub const MAX_INLINE_BYTES: usize = 2 << 10;
/// The identity of the profiles root in every plan: none is checked (ADR 0020 amendment P3-3,
/// F1), one fixed value so a plan's bytes are the same with and without `--dry-run`. No game
/// root may carry it (a fake or a volume never hands out serial 0 with file ID 0).
pub const PROFILES_ROOT_ID: RootId = RootId {
    volume_serial: 0,
    file_id: 0,
};

/// A plan (ADR 0020).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// [`FORMAT`].
    pub format: u32,
    /// The roots the ops write into.
    pub roots: Vec<PlanRoot>,
    /// The ops, applied in this order and reverted newest first.
    pub ops: Vec<Op>,
    /// Where the steps came from (P4-4): the signed index and the Topo with the variants
    /// picked. `None` for a plan from a step file (unsigned, L8). Omitted on the wire then, so
    /// a plan of the same steps has the same bytes apart from this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PlanSource>,
}

/// Most variants a Topo plan names.
pub const MAX_PICKS: usize = 32;

/// The origin of a plan built by the Topo engine (P4-4, ADR 0020 amendment P4-4): the SHA-256
/// of the signed index it was planned from (kept under `<AppDir>index` by that name, so a
/// revert finds it again, P4 condition R1; the elevated helper checks against it, L8) and
/// the Topo with every variant picked. Display and binding only: nothing of it is trusted
/// when read back beyond its form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSource {
    /// SHA-256 of the signed index bytes.
    #[serde(with = "crate::wire::hex32")]
    pub index: [u8; 32],
    /// The Topo ID.
    pub topo: String,
    /// Its revision.
    pub rev: u32,
    /// The variants picked, in the order given: one per issue.
    pub picks: Vec<Pick>,
}

/// One picked variant of a Topo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pick {
    /// The issue ID.
    pub issue: String,
    /// The variant ID.
    pub variant: String,
}

impl PlanSource {
    /// The form rules (encode and decode alike): IDs of the Topo form, `rev` from 1, 1 to
    /// [`MAX_PICKS`] picks, each issue once.
    pub(crate) fn check(&self) -> Result<(), PlanError> {
        let id = |s: &str| crate::catalog::model::Id::parse(s).is_some();
        if !id(&self.topo) || self.rev == 0 {
            return Err(invalid(None, "a source without a Topo ID and revision"));
        }
        if self.picks.is_empty() || self.picks.len() > MAX_PICKS {
            return Err(invalid(None, "a source names 1 to 32 variants"));
        }
        for (i, p) in self.picks.iter().enumerate() {
            if !id(&p.issue) || !id(&p.variant) {
                return Err(invalid(None, "a pick that is no issue and variant ID"));
            }
            if self.picks[..i].iter().any(|q| q.issue == p.issue) {
                return Err(invalid(None, "two variants of one issue"));
            }
        }
        Ok(())
    }
}

/// A root of a plan: reopened through `policy::root` and checked by identity before every
/// apply and revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRoot {
    /// The kind of root.
    pub kind: RootKind,
    /// Canonical path as of planning.
    pub path: RootPath,
    /// Identity as of planning.
    pub id: RootId,
    /// How it is reopened.
    pub origin: PlanOrigin,
    /// The game's main executable (relative to the root), asked by `users()` before apply
    /// and revert (user decision D4).
    pub main_exe: Option<RelPath>,
}

/// Kind of a plan root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    /// A game folder.
    Game,
    /// Rerun's launch profiles, `<LocalAppData>\Rerun\profiles` (P3-3): origin
    /// [`PlanOrigin::AppDir`], identity [`PROFILES_ROOT_ID`], no main executable.
    Profiles,
    /// A game's own folder below the user's `Documents` (P4-12, D6): origin
    /// [`PlanOrigin::UserFolder`], no main executable, only `IniValue` ops (`user_data` fence).
    UserData,
}

/// Where a plan root came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanOrigin {
    /// `steamapps\common\<installdir>` of a Steam library.
    Steam {
        /// Canonical path of the library.
        store: RootPath,
        /// Identity of the library.
        store_id: RootId,
        /// The app whose state is checked.
        app_id: u32,
        /// The install folder name.
        installdir: RelPath,
    },
    /// A folder added by the user, reopened by absolute path.
    Manual,
    /// Rerun's profiles folder (P3-3), reopened only through `AppDir` (handle-relative, no
    /// reparse point, its final path checked), never by the head's path or identity.
    AppDir,
    /// A folder below a known folder of the user (P4-12): reopened only through
    /// `policy::root::UserDataDir` from `base` and `sub` (never by the head's path), its path and
    /// identity then compared with the head's.
    UserFolder {
        /// The known folder.
        base: UserBase,
        /// The folder below it, as the Topo or step file names it.
        sub: RelPath,
    },
}

/// Index into [`Plan::roots`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RootIx(pub u16);

/// A registry view of an "all users" compatibility-layer value (P3-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerView {
    /// The native (64-bit) view.
    Native,
    /// The 32-bit view (`WOW6432Node`).
    Wow32,
}

/// The "all users" (`HKLM`) compatibility-layer value of a `TokenList`'s executable in one view,
/// as the planner read it (P3-6): a `REG_SZ` in the strict grammar of
/// `policy::registry::layers`, display only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineLayers {
    /// The view it was read in.
    pub view: LayerView,
    /// The value.
    pub value: String,
}

/// One op (ADR 0020). There is no delete op: deleting is only ever a revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    /// Creates one directory.
    CreateDir {
        /// Root.
        root: RootIx,
        /// Path below the root.
        path: RelPath,
    },
    /// Creates a file that does not exist.
    CreateFile {
        /// Root.
        root: RootIx,
        /// Path below the root.
        path: RelPath,
        /// Its content.
        content: ContentRef,
        /// Read-only, hidden, system of the new file.
        attrs: Attrs,
    },
    /// Replaces an existing file whose state was `old` when planned.
    ReplaceFile {
        /// Root.
        root: RootIx,
        /// Path below the root.
        path: RelPath,
        /// The old state, re-observed on the guard before the change.
        old: FileState,
        /// The new content.
        content: ContentRef,
        /// Read-only, hidden, system of the new file.
        attrs: Attrs,
    },
    /// Creates one registry key: the key of `slot` cut to its first `segs` segments below
    /// `HKCU` (below the slot's anchor, at most the slot's key itself), so no key outside the
    /// slot can be expressed.
    CreateKey {
        /// The slot whose key (or ancestor) is created.
        slot: RegSlot,
        /// Segments of the created key below the hive root.
        segs: u8,
    },
    /// Sets the value of `slot` to `new`: a new value (`old` is `None`) or a replaced one.
    SetValue {
        /// The value.
        slot: RegSlot,
        /// The old value as planned, re-observed before the change (`None`: missing).
        old: Option<ValueState>,
        /// The new value.
        new: NewValue,
    },
    /// Appends `add` to the compatibility-layer value of `slot` (P2-11): the old value keeps its
    /// bytes, every other token stays; a revert restores the old value exactly, or removes only
    /// `add` from a value someone changed since.
    TokenList {
        /// The value (a `CompatLayers` slot).
        slot: RegSlot,
        /// The old value as planned, re-observed before the change (`None`: missing).
        old: Option<ValueState>,
        /// The tokens added, in byte order.
        add: Vec<TokenName>,
        /// The new value: `old` with `add` appended (`policy::registry::layers::merge`).
        new: String,
        /// The "all users" value of the same executable in `HKLM` as planned, per view in which
        /// it exists (P3-6, ADR 0018 amendment P3-6): for the preview only, never written,
        /// never re-observed. Omitted on the wire when empty.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        machine: Vec<MachineLayers>,
    },
    /// Sets Windows' graphics preference of the executable of `slot` (P4-11): only the
    /// `GpuPreference` pair of the `UserGpuPreferences` value changes, every other pair keeps
    /// its bytes and place; a revert restores the old value exactly, or sets back only Rerun's
    /// pair in a value someone changed since (when it is still Rerun's).
    GpuPref {
        /// The value (a `GpuPreference` slot).
        slot: RegSlot,
        /// The old value as planned, re-observed before the change (`None`: missing).
        old: Option<ValueState>,
        /// The preference set.
        pref: GpuPref,
        /// The new value: `old` with Rerun's pair (`policy::registry::gpu_pref::set`).
        new: String,
    },
    /// Sets keys of an existing INI file whose state was `old` when planned (P2-12): only the
    /// edits change (`policy::ini::edit`); a revert restores the old content exactly, or puts
    /// back only Rerun's keys in a file the game rewrote since.
    IniValue {
        /// Root.
        root: RootIx,
        /// Path below the root (a `.ini` file).
        path: RelPath,
        /// The old state, re-observed on the guard before the change.
        old: FileState,
        /// The new content: `edit(old content, edits)`, with the old R/H/S.
        new: FileHash,
        /// The keys, in canonical order.
        edits: Vec<IniEdit>,
    },
    /// A package file the game folder holds already with exactly this content (P4-8): nothing is
    /// written, the file is an object the transaction relies on (handed over to it if its creator
    /// is reverted first, P4-8b); the revert of the hold itself changes nothing, the last revert
    /// that relies on a handed-over file removes it.
    Hold {
        /// Root.
        root: RootIx,
        /// Path below the root, in its stored spelling.
        path: RelPath,
        /// The package file it is (a [`ContentRef::Package`]).
        content: ContentRef,
    },
    /// Rerun's block rule in the Windows Firewall for an executable of a game folder (P4-2d,
    /// ADR 0023 §6, §9): added and removed only by the elevated helper, as the last ops of a
    /// plan with a [`Plan::source`]. The rule's name follows from the Topo, the transaction and
    /// the op index; its program is the root's planned path and `program`, never a rebound one.
    FirewallRule {
        /// The game folder (a [`RootKind::Game`] root).
        root: RootIx,
        /// The executable below it, in the spelling of the Topo's `match.exes` entry.
        program: RelPath,
        /// The direction the rule blocks.
        direction: Direction,
    },
}

/// The new content of an `IniValue` (P2-12): SHA-256 and length; its R/H/S are the old ones.
/// Deliberately its own type, not `journal::Digest` of the same shape: the plan format does not
/// borrow the journal's wire types, so the two formats can change apart (review nit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileHash {
    /// SHA-256 of the content.
    #[serde(with = "crate::wire::hex32")]
    pub sha256: [u8; 32],
    /// Length in bytes.
    pub len: u64,
}

/// Largest old registry value whose bytes a plan carries inline (for the preview only; the
/// revert's source is always the journal's `Intent.before`).
pub const OLD_INLINE: usize = 1 << 10;

/// A registry value as planned: its type, length and SHA-256, and its bytes up to
/// [`OLD_INLINE`] (`data` is there exactly then).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueState {
    /// The registry type number (`REG_*`, also an unknown one).
    pub kind: u32,
    /// Length of the data in bytes (at most `MAX_VALUE_BYTES`).
    pub len: u32,
    /// SHA-256 of the data.
    #[serde(with = "crate::wire::hex32")]
    pub sha256: [u8; 32],
    /// The data, lower-case hex, if `len` is at most [`OLD_INLINE`].
    #[serde(with = "crate::wire::hex_bytes_opt")]
    pub data: Option<Vec<u8>>,
}

impl ValueState {
    /// The state of `v` as it is stored; `None` if it has no encoding or is larger than
    /// `MAX_VALUE_BYTES`.
    pub fn of(v: &RegValue) -> Option<Self> {
        let (kind, data) = v.encode()?;
        if data.len() > MAX_VALUE_BYTES {
            return None;
        }
        Some(Self {
            kind,
            len: u32::try_from(data.len()).ok()?,
            sha256: Sha256::digest(&data).into(),
            data: (data.len() <= OLD_INLINE).then_some(data),
        })
    }

    /// `v` (`None`: missing) is exactly this state: type, length, SHA-256.
    pub fn is(this: Option<&Self>, v: Option<&RegValue>) -> bool {
        match (this, v) {
            (None, None) => true,
            (Some(s), Some(v)) => v.encode().is_some_and(|(kind, data)| {
                kind == s.kind
                    && usize::try_from(s.len).is_ok_and(|l| l == data.len())
                    && <[u8; 32]>::from(Sha256::digest(&data)) == s.sha256
            }),
            _ => false,
        }
    }
}

/// A new registry value (only what `RegPolicy::check_new` may allow). On the wire
/// `{"dword":1}`, `{"qword":"<decimal>"}` (no JSON number above 2^53), `{"sz":"…"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NewValue {
    /// `REG_DWORD`.
    Dword(u32),
    /// `REG_QWORD`.
    Qword(#[serde(with = "crate::wire::dec_u64")] u64),
    /// `REG_SZ`.
    Sz(String),
}

impl NewValue {
    /// As a registry value.
    pub fn value(&self) -> RegValue {
        match self {
            Self::Dword(v) => RegValue::Dword(*v),
            Self::Qword(v) => RegValue::Qword(*v),
            Self::Sz(s) => RegValue::String(s.clone()),
        }
    }
}

/// What an op targets (audit A2 should-item 3): the generic paths of `plan` and `exec`
/// (objects and "one op per object", records, flushes, the game-closed check) go through
/// this, never through an op kind, so a new kind of target (registry keys and values,
/// P2-10b) is one more variant whose every use the compiler names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    /// A file or directory below a root.
    File {
        /// Root.
        root: RootIx,
        /// Path below the root.
        path: &'a RelPath,
        /// The op creates a directory.
        dir: bool,
    },
    /// A registry key the op creates: the key of `slot` cut to `segs` segments.
    Key {
        /// The slot.
        slot: &'a RegSlot,
        /// Segments below the hive root.
        segs: u8,
    },
    /// A registry value.
    Value {
        /// The slot.
        slot: &'a RegSlot,
    },
    /// A firewall rule of the elevated helper's batch (P4-2d): its object is its rule name,
    /// unique per transaction and op, so it overlaps nothing.
    Rule {
        /// The game folder whose executable it names.
        root: RootIx,
        /// The executable below it.
        program: &'a RelPath,
    },
}

impl Target<'_> {
    /// A registry key or value.
    pub fn is_registry(&self) -> bool {
        matches!(self, Self::Key { .. } | Self::Value { .. })
    }

    /// An op of the elevated helper's batch (P4-2d).
    pub fn is_helper(&self) -> bool {
        matches!(self, Self::Rule { .. })
    }
}

impl Op {
    /// What the op targets.
    pub fn target(&self) -> Target<'_> {
        match self {
            Self::CreateDir { root, path } => Target::File {
                root: *root,
                path,
                dir: true,
            },
            Self::CreateFile { root, path, .. }
            | Self::ReplaceFile { root, path, .. }
            | Self::Hold { root, path, .. }
            | Self::IniValue { root, path, .. } => Target::File {
                root: *root,
                path,
                dir: false,
            },
            Self::CreateKey { slot, segs } => Target::Key { slot, segs: *segs },
            Self::SetValue { slot, .. }
            | Self::TokenList { slot, .. }
            | Self::GpuPref { slot, .. } => Target::Value { slot },
            Self::FirewallRule { root, program, .. } => Target::Rule {
                root: *root,
                program,
            },
        }
    }

    /// The op needs the main executable of every root of its plan: a registry op (user decision
    /// E2 of P2-10b, review M1: no file target, so without `main_exe` the game-closed check D4
    /// would ask nothing) and an `IniValue` (user decision E5 of P2-12: a running game holds no
    /// INI file open and writes it when it exits, so asking the file itself proves nothing).
    pub fn needs_main_exe(&self) -> bool {
        self.target().is_registry() || matches!(self, Self::IniValue { .. })
    }

    /// The content a file op writes (`None` for a [`Self::Hold`], which writes nothing).
    pub fn content(&self) -> Option<&ContentRef> {
        match self {
            Self::CreateDir { .. }
            | Self::IniValue { .. }
            | Self::Hold { .. }
            | Self::CreateKey { .. }
            | Self::SetValue { .. }
            | Self::TokenList { .. }
            | Self::GpuPref { .. }
            | Self::FirewallRule { .. } => None,
            Self::CreateFile { content, .. } | Self::ReplaceFile { content, .. } => Some(content),
        }
    }

    /// The package file a file op puts or holds at its target (P4-8: slots): the content of a
    /// `CreateFile`, `ReplaceFile` or `Hold` from a package.
    pub fn package_file(&self) -> Option<(&str, &ContentRef)> {
        match self {
            Self::CreateFile { content, .. }
            | Self::ReplaceFile { content, .. }
            | Self::Hold { content, .. } => match content {
                ContentRef::Package { id, .. } => Some((id.as_str(), content)),
                ContentRef::Inline { .. } | ContentRef::Patch { .. } => None,
            },
            _ => None,
        }
    }
}

/// The value or key a registry slot names, by the rules of `policy::registry` and with the
/// plan's roots (parsed again): what `check`, the objects and `exec` use.
pub(crate) fn allowed(
    plan: &Plan,
    slot: &RegSlot,
    op: usize,
) -> Result<crate::policy::registry::AllowedValue, PlanError> {
    let roots: Vec<RootPath> = plan.roots.iter().map(|r| r.path.clone()).collect();
    RegPolicy
        .check(slot, &roots)
        .map_err(|source| PlanError::Registry { op, source })
}

/// The plan root a registry slot names, if any (the executable of a `CompatLayers` or
/// `GpuPreference` slot).
pub(crate) fn slot_root(s: &RegSlot) -> Option<RootIx> {
    match s {
        RegSlot::CompatLayers { root, .. } | RegSlot::GpuPreference { root, .. } => Some(*root),
        RegSlot::GameValue { .. } => None,
    }
}

/// A registry slot that names a plan root names a game root (P4-12, both rule sets: the value
/// name is the canonical path of an executable of a game folder, never one of Rerun's profiles
/// or of a user data folder).
fn slot_on_game(plan: &Plan, k: usize, slot: &RegSlot) -> Result<(), PlanError> {
    let Some(root) = slot_root(slot) else {
        return Ok(());
    };
    match plan.roots.get(usize::from(root.0)) {
        Some(r) if r.kind == RootKind::Game => Ok(()),
        Some(_) => Err(invalid(
            Some(k),
            "a registry slot names an executable outside a game folder",
        )),
        None => Err(invalid(Some(k), "root index outside the plan's roots")),
    }
}

/// The key a `CreateKey` op creates.
pub(crate) fn created_key(
    plan: &Plan,
    slot: &RegSlot,
    segs: u8,
    op: usize,
) -> Result<(crate::policy::registry::AllowedValue, RegKey), PlanError> {
    let av = allowed(plan, slot, op)?;
    let key = av.key().cut(segs).ok_or_else(|| {
        invalid(
            Some(op),
            "a created key outside its slot (below the anchor, at most the key)",
        )
    })?;
    Ok((av, key))
}

/// `k` is `of` or lies below it.
pub(crate) fn key_at_or_below(k: &RegKey, of: &RegKey) -> bool {
    k == of || is_below(k, of)
}

/// `k` lies strictly below `of` (folded paths, same hive and view).
pub(crate) fn is_below(k: &RegKey, of: &RegKey) -> bool {
    k.hive == of.hive
        && k.view == of.view
        && fold(&k.path)
            .strip_prefix(&fold(&of.path))
            .is_some_and(|rest| rest.starts_with('\\'))
}

/// The state of a file: what a guard observes and a revert restores (ADR 0017, "exact").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileState {
    /// SHA-256 of the content.
    #[serde(with = "crate::wire::hex32")]
    pub sha256: [u8; 32],
    /// Length in bytes.
    pub len: u64,
    /// Read-only, hidden, system.
    pub attrs: Attrs,
}

/// Where the content of a file op comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ContentRef {
    /// A file below `<AppDir>\packages\<id>\<version>\` (ADR 0020, D11).
    Package {
        /// Package ID (`docs/02-topo-format.md`).
        id: String,
        /// Package version.
        version: String,
        /// The file below the version folder.
        file: RelPath,
        /// SHA-256 of the file, checked while it is streamed.
        #[serde(with = "crate::wire::hex32")]
        sha256: [u8; 32],
        /// Length in bytes.
        len: u64,
        /// A configuration file the user may edit: a revert then finds it `Foreign` and
        /// leaves it (ADR 0020); the preview says so.
        config: bool,
    },
    /// Bytes the plan carries (P3-3: a launch profile, only on the profiles root), lower-case
    /// hex on the wire, at most [`MAX_INLINE_BYTES`], with their SHA-256.
    Inline {
        /// The content.
        #[serde(with = "crate::wire::hex_bytes")]
        bytes: Vec<u8>,
        /// SHA-256 of `bytes` (checked by the format, and again while it is streamed).
        #[serde(with = "crate::wire::hex32")]
        sha256: [u8; 32],
    },
    /// The file as it is (`base`, the old state of its `ReplaceFile`) with single bytes changed
    /// (P4-10, `laa_patch`): the same length, every byte the old one except at the offsets of
    /// `edits`. `sha256` is the SHA-256 of the result, computed by the planner; `exec` streams
    /// the old bytes from the journal's backup, applies the edits and checks the result's hash
    /// before the rename (ADR 0017). Only in a `ReplaceFile` on a game root.
    Patch {
        /// The file the edits apply to: the op's `old` exactly.
        base: FileState,
        /// The changed bytes, 1 to [`MAX_PATCH_EDITS`], strictly ascending by offset.
        edits: Vec<ByteEdit>,
        /// SHA-256 of the patched file.
        #[serde(with = "crate::wire::hex32")]
        sha256: [u8; 32],
    },
}

/// Most bytes one [`ContentRef::Patch`] changes (`laa_patch`: one byte of `Characteristics`
/// and the four of `CheckSum`).
pub const MAX_PATCH_EDITS: usize = 8;

/// One changed byte of a [`ContentRef::Patch`]: at `offset`, `old` becomes `new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteEdit {
    /// File offset.
    pub offset: u64,
    /// The byte there in the base file.
    pub old: u8,
    /// The byte written instead.
    pub new: u8,
}

/// The old bytes with a patch's edits applied while they are streamed (P4-10): every edited
/// byte must hold its `old` value (else `InvalidData`: the source is not the base), and becomes
/// `new`. The edits are sorted by offset (`patch_check`). `exec` streams a backup through it,
/// `prim::laa_patch` the file it plans for.
pub(crate) struct Patched<'e, R> {
    inner: R,
    at: u64,
    edits: &'e [ByteEdit],
}

impl<'e, R> Patched<'e, R> {
    pub(crate) fn new(inner: R, edits: &'e [ByteEdit]) -> Self {
        Self {
            inner,
            at: 0,
            edits,
        }
    }
}

impl<R: std::io::Read> std::io::Read for Patched<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        let chunk = buf.get_mut(..n).unwrap_or_default();
        apply_edits(self.edits, self.at, chunk)?;
        self.at = self.at.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }
}

/// Applies the edits that fall into `chunk`, the bytes of the file from offset `at`: each edited
/// byte must hold the edit's `old` value (else `InvalidData`) and becomes its `new` one.
pub(crate) fn apply_edits(edits: &[ByteEdit], at: u64, chunk: &mut [u8]) -> std::io::Result<()> {
    let end = at.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
    for e in edits {
        if e.offset < at || e.offset >= end {
            continue;
        }
        let b = usize::try_from(e.offset - at)
            .ok()
            .and_then(|i| chunk.get_mut(i))
            .ok_or_else(|| std::io::Error::other("a patch offset outside the buffer"))?;
        if *b != e.old {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the file to patch has another byte at a patched offset",
            ));
        }
        *b = e.new;
    }
    Ok(())
}

impl ContentRef {
    /// SHA-256 of the content.
    pub fn sha256(&self) -> &[u8; 32] {
        match self {
            Self::Package { sha256, .. }
            | Self::Inline { sha256, .. }
            | Self::Patch { sha256, .. } => sha256,
        }
    }

    /// Length of the content.
    pub fn len(&self) -> u64 {
        match self {
            Self::Package { len, .. } => *len,
            Self::Inline { bytes, .. } => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            Self::Patch { base, .. } => base.len,
        }
    }

    /// The content is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// SHA-256 over the serialised plan bytes ([`PlanBytes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanHash(pub [u8; 32]);

impl fmt::Display for PlanHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::wire::hex32::to_string(&self.0))
    }
}

impl FromStr for PlanHash {
    type Err = PlanError;

    /// Exactly 64 lower-case hex digits.
    fn from_str(s: &str) -> Result<Self, PlanError> {
        crate::wire::hex32::from_str(s)
            .map(Self)
            .ok_or(PlanError::BadHash)
    }
}

/// The one serialisation of a plan and its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanBytes {
    bytes: Vec<u8>,
    hash: PlanHash,
}

impl PlanBytes {
    /// Bytes read back (stored plan, `head.json`); the hash is computed here.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        let hash = PlanHash(Sha256::digest(&bytes).into());
        Self { bytes, hash }
    }

    /// The bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Their hash.
    pub fn hash(&self) -> PlanHash {
        self.hash
    }
}

/// Which rules a decoded plan must meet (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rules {
    /// Planning, encode and apply: every rule in force now.
    Current,
    /// Revert, `verify` and stacking of a recorded head: location and form, not the rules for
    /// new values.
    Recorded,
}

/// Bounds of a plan (crate-internal so tests can shrink them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) ops: usize,
    pub(crate) op_bytes: usize,
    pub(crate) plan_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            ops: MAX_OPS,
            op_bytes: MAX_OP_BYTES,
            plan_bytes: MAX_PLAN_BYTES,
        }
    }
}

/// An error of planning, of the plan format, or of plan storage.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// Another plan format.
    #[error("plan format {0} is not supported")]
    Format(u32),
    /// Not a plan of format 1.
    #[error("the plan cannot be parsed")]
    Unparsable,
    /// Parsed, but not in the one written form.
    #[error("the plan is not in its one written form")]
    NotOneForm,
    /// More bytes than [`MAX_PLAN_BYTES`].
    #[error("the plan is larger than {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// More ops than [`MAX_OPS`].
    #[error("the plan has {n} ops, at most {limit} are allowed")]
    TooManyOps {
        /// Ops of the plan.
        n: usize,
        /// The limit.
        limit: usize,
    },
    /// One op larger than [`MAX_OP_BYTES`] serialised.
    #[error("op {op} is larger than {limit} bytes")]
    OpTooLarge {
        /// Op index.
        op: usize,
        /// The limit.
        limit: usize,
    },
    /// A rule of the plan format is broken (`op` is `None` for the plan itself).
    #[error("{}{why}", op.map(|o| format!("op {o}: ")).unwrap_or_default())]
    Invalid {
        /// Op index.
        op: Option<usize>,
        /// The rule.
        why: &'static str,
    },
    /// Not 64 lower-case hex digits.
    #[error("not a plan hash (64 lower-case hex digits)")]
    BadHash,
    /// No stored plan with this hash.
    #[error("no stored plan {0}; run plan again")]
    NotFound(PlanHash),
    /// The stored bytes do not hash to the name they are stored under.
    #[error("the stored plan {0} was changed; run plan again")]
    HashMismatch(PlanHash),
    /// A registry slot or new value `policy::registry` refuses.
    #[error("op {op}: {source}")]
    Registry {
        /// Op index.
        op: usize,
        /// The rule.
        source: RegPolicyError,
    },
    /// The edits of an `IniValue` break a rule of `policy::ini`.
    #[error("op {op}: {source}")]
    Ini {
        /// Op index.
        op: usize,
        /// The rule.
        source: IniError,
    },
    /// The step file of `rerun plan` (P2-13).
    #[error(transparent)]
    StepFile(#[from] crate::prim::StepFileError),
    /// A step the planner refuses (`file_install`, `registry_set`).
    #[error("{0}")]
    Step(String),
    /// The game folder cannot be written by the current user; phase 3 sends such a plan to
    /// the elevated helper.
    #[error("the game folder needs administrator rights (not supported yet)")]
    NeedsHelper,
    /// Serialising failed.
    #[error("the plan is not serialisable: {0}")]
    Encode(String),
    /// Opening Rerun's folder or a root.
    #[error(transparent)]
    Root(Box<RootError>),
    /// The system layer.
    #[error(transparent)]
    Sys(#[from] SysError),
}

impl From<RootError> for PlanError {
    fn from(e: RootError) -> Self {
        Self::Root(Box::new(e))
    }
}

fn invalid(op: Option<usize>, why: &'static str) -> PlanError {
    PlanError::Invalid { op, why }
}

/// A package ID of `docs/02-topo-format.md`: lower-case letters, digits and hyphens, 1 to
/// 64 characters, and a valid path segment.
pub(crate) fn package_id_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && RelPath::from_segment(s).is_ok()
}

/// A package version of `docs/02-topo-format.md`: `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`,
/// without `..`, and a valid path segment.
pub(crate) fn package_version_ok(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        && !s.contains("..")
        && RelPath::from_segment(s).is_ok()
}

impl Plan {
    /// The one serialisation and its hash; refuses a plan outside the bounds of the format.
    pub fn encode(&self) -> Result<PlanBytes, PlanError> {
        self.encode_with(&Limits::default())
    }

    pub(crate) fn encode_with(&self, lim: &Limits) -> Result<PlanBytes, PlanError> {
        let bytes = serde_json::to_vec(self).map_err(|e| PlanError::Encode(e.to_string()))?;
        check(self, bytes.len(), lim, Rules::Current)?;
        Ok(PlanBytes::from_bytes(bytes))
    }
}

/// Parses plan bytes as untrusted input (module docs), with the rules in force now (apply).
pub(crate) fn decode(b: &[u8]) -> Result<Plan, PlanError> {
    decode_with(b, &Limits::default(), Rules::Current)
}

/// Parses a recorded head as untrusted input with [`Rules::Recorded`] (revert, `verify`,
/// stacking).
pub(crate) fn decode_recorded(b: &[u8]) -> Result<Plan, PlanError> {
    decode_with(b, &Limits::default(), Rules::Recorded)
}

pub(crate) fn decode_with(b: &[u8], lim: &Limits, rules: Rules) -> Result<Plan, PlanError> {
    if b.len() > lim.plan_bytes {
        return Err(PlanError::TooLarge {
            limit: lim.plan_bytes,
        });
    }
    #[derive(Deserialize)]
    struct Probe {
        format: u32,
    }
    let probe: Probe = serde_json::from_slice(b).map_err(|_| PlanError::Unparsable)?;
    if probe.format != FORMAT {
        return Err(PlanError::Format(probe.format));
    }
    let plan: Plan = serde_json::from_slice(b).map_err(|_| PlanError::Unparsable)?;
    if serde_json::to_vec(&plan).ok().as_deref() != Some(b) {
        return Err(PlanError::NotOneForm);
    }
    check(&plan, b.len(), lim, rules)?;
    Ok(plan)
}

/// The registry ops `check` has seen so far.
#[derive(Default)]
struct RegSeen {
    /// A registry op came (every file op must come before).
    any: bool,
    /// The keys `CreateKey` ops create.
    created: Vec<RegKey>,
    /// The key and folded name of each `SetValue`.
    values: Vec<(RegKey, String)>,
}

impl RegSeen {
    fn key(&mut self, plan: &Plan, k: usize, slot: &RegSlot, segs: u8) -> Result<(), PlanError> {
        self.any = true;
        let (_, key) = created_key(plan, slot, segs, k)?;
        if self.created.contains(&key) {
            return Err(invalid(Some(k), "a second op on the same object"));
        }
        // A key or value below a created key comes after its `CreateKey` (the revert, newest
        // first, then finds the key empty).
        if self.created.iter().any(|c| is_below(c, &key))
            || self.values.iter().any(|(v, _)| key_at_or_below(v, &key))
        {
            return Err(invalid(
                Some(k),
                "a key or value below a created key comes before it",
            ));
        }
        self.created.push(key);
        Ok(())
    }

    fn value(
        &mut self,
        plan: &Plan,
        k: usize,
        op: &Op,
        slot: &RegSlot,
        rules: Rules,
    ) -> Result<(), PlanError> {
        self.any = true;
        let av = allowed(plan, slot, k)?;
        let obj = (av.key().key().clone(), fold(av.name()));
        if self.values.contains(&obj) {
            return Err(invalid(Some(k), "a second op on the same object"));
        }
        let (old, new) = match op {
            Op::SetValue { old, new, .. } => (old, new),
            Op::TokenList {
                old,
                add,
                new,
                machine,
                ..
            } => {
                self.tokens(k, &av, &obj.0, old.as_ref(), add, new, rules)?;
                machine_rules(k, add, machine, rules)?;
                self.values.push(obj);
                return Ok(());
            }
            Op::GpuPref { old, pref, new, .. } => {
                self.pref(k, &av, &obj.0, old.as_ref(), *pref, new, rules)?;
                self.values.push(obj);
                return Ok(());
            }
            _ => return Err(invalid(Some(k), "a value target of no value op")),
        };
        // Review N2, P2-11: a compatibility-layer value is shared; Rerun only adds tokens.
        if matches!(slot, RegSlot::CompatLayers { .. }) {
            return Err(invalid(
                Some(k),
                "a compatibility-layer value is never set, only tokens are added",
            ));
        }
        // P4-11: a graphics preference is shared as well; both rule sets.
        if matches!(slot, RegSlot::GpuPreference { .. }) {
            return Err(invalid(
                Some(k),
                "a graphics preference is never set as a whole, only its own pair",
            ));
        }
        if rules == Rules::Current {
            RegPolicy
                .check_new(&av, &new.value())
                .map_err(|source| PlanError::Registry { op: k, source })?;
        }
        if let Some(s) = old {
            let len = usize::try_from(s.len).unwrap_or(usize::MAX);
            let data_ok = match &s.data {
                Some(d) => {
                    len <= OLD_INLINE
                        && d.len() == len
                        && <[u8; 32]>::from(Sha256::digest(d)) == s.sha256
                }
                None => len > OLD_INLINE,
            };
            if len > MAX_VALUE_BYTES || !data_ok {
                return Err(invalid(
                    Some(k),
                    "an old value whose length, hash or inline data do not fit",
                ));
            }
            if ValueState::is(Some(s), Some(&new.value())) {
                return Err(invalid(Some(k), "a value set to the value it has"));
            }
            if self.created.iter().any(|c| key_at_or_below(&obj.0, c)) {
                return Err(invalid(
                    Some(k),
                    "a value in a created key with an old value",
                ));
            }
        }
        self.values.push(obj);
        Ok(())
    }
}

impl RegSeen {
    /// The rules of a `TokenList` (module docs).
    #[expect(
        clippy::too_many_arguments,
        reason = "the fields of the op and its context"
    )]
    fn tokens(
        &self,
        k: usize,
        av: &crate::policy::registry::AllowedValue,
        key: &RegKey,
        old: Option<&ValueState>,
        add: &[TokenName],
        new: &str,
        rules: Rules,
    ) -> Result<(), PlanError> {
        if !matches!(av.slot(), RegSlot::CompatLayers { .. }) {
            return Err(invalid(
                Some(k),
                "tokens are only added to a compatibility-layer value",
            ));
        }
        let old = match old {
            None => None,
            Some(s) => Some(layers_old(s).ok_or_else(|| {
                invalid(
                    Some(k),
                    "an old compatibility-layer value that is no inline REG_SZ in the grammar",
                )
            })?),
        };
        if add.is_empty() || add.len() > layers::MAX_ADD || add.windows(2).any(|w| w[0] >= w[1]) {
            return Err(invalid(Some(k), "1 to 8 tokens, unique and in byte order"));
        }
        if let Some(o) = &old {
            let words: Vec<String> = o.split(' ').map(fold).collect();
            if add.iter().any(|t| words.contains(&fold(t.as_str()))) {
                return Err(invalid(Some(k), "a token already in the old value"));
            }
            if self.created.iter().any(|c| key_at_or_below(key, c)) {
                return Err(invalid(
                    Some(k),
                    "a value in a created key with an old value",
                ));
            }
        }
        if layers::parse(new).is_err() || old.as_deref() == Some(new) {
            return Err(invalid(
                Some(k),
                "a new compatibility-layer value outside the grammar or equal to the old one",
            ));
        }
        // Both rule sets (security review S-1): `new` is the old value with the tokens
        // appended, whatever prefix a version writes for a missing old value, so a recorded
        // head can never make the restore of `After` write a token the plan did not add.
        let tail: Vec<&str> = add.iter().map(TokenName::as_str).collect();
        let tail = tail.join(" ");
        let appended = match &old {
            Some(o) => {
                new.strip_prefix(o.as_str())
                    .and_then(|r| r.strip_prefix(' '))
                    == Some(&tail)
            }
            None => new == tail || new.ends_with(&format!(" {tail}")),
        };
        if !appended {
            return Err(invalid(
                Some(k),
                "a new value that is not the old one with the tokens appended",
            ));
        }
        if rules == Rules::Current {
            RegPolicy
                .check_tokens(av, old.as_deref(), add)
                .map_err(|source| PlanError::Registry { op: k, source })?;
            if layers::merge(old.as_deref(), add) != new {
                return Err(invalid(
                    Some(k),
                    "a new value other than the old one with the tokens appended",
                ));
            }
        }
        Ok(())
    }
}

impl RegSeen {
    /// The rules of a `GpuPref` (module docs).
    #[expect(
        clippy::too_many_arguments,
        reason = "the fields of the op and its context"
    )]
    fn pref(
        &self,
        k: usize,
        av: &crate::policy::registry::AllowedValue,
        key: &RegKey,
        old: Option<&ValueState>,
        pref: GpuPref,
        new: &str,
        rules: Rules,
    ) -> Result<(), PlanError> {
        if !matches!(av.slot(), RegSlot::GpuPreference { .. }) {
            return Err(invalid(
                Some(k),
                "a graphics preference only on a UserGpuPreferences value",
            ));
        }
        let old = match old {
            None => None,
            Some(s) => Some(pref_old(s).ok_or_else(|| {
                invalid(
                    Some(k),
                    "an old graphics preference value that is no inline REG_SZ",
                )
            })?),
        };
        if old.is_some() && self.created.iter().any(|c| key_at_or_below(key, c)) {
            return Err(invalid(
                Some(k),
                "a value in a created key with an old value",
            ));
        }
        // Both rule sets (the S-1 analogue): `new` is `old` with Rerun's pair, whatever the
        // grammar of a later version says.
        if old.as_deref() == Some(new) || !pref_relation(old.as_deref(), new, pref) {
            return Err(invalid(
                Some(k),
                "a new value that is not the old one with Rerun's graphics preference",
            ));
        }
        if rules == Rules::Current {
            let formed = RegPolicy
                .check_pref(av, old.as_deref(), pref)
                .map_err(|source| PlanError::Registry { op: k, source })?;
            if formed != new || gpu_pref::parse(new).is_err() {
                return Err(invalid(
                    Some(k),
                    "a new value other than the old one with Rerun's graphics preference",
                ));
            }
        }
        Ok(())
    }
}

/// `new` is `old` with the pair `GpuPreference=<pref>;`: the first piece of `old` (split after
/// each `;`) that starts with `GpuPreference=` replaced by it, or it appended; without `old` the
/// pair alone. Plain string pieces, no grammar (module docs: both rule sets).
pub(crate) fn pref_relation(old: Option<&str>, new: &str, pref: GpuPref) -> bool {
    let pair = format!("{}={};", gpu_pref::PREF_KEY, pref.digit());
    let Some(old) = old else {
        return new == pair;
    };
    let head = format!("{}=", gpu_pref::PREF_KEY);
    let mut out = String::with_capacity(old.len() + pair.len());
    let mut replaced = false;
    for piece in old.split_inclusive(';') {
        if !replaced && piece.starts_with(&head) && piece.ends_with(';') {
            out.push_str(&pair);
            replaced = true;
        } else {
            out.push_str(piece);
        }
    }
    if !replaced {
        out.push_str(&pair);
    }
    out == new
}

/// The old value of a `GpuPref`: a `REG_SZ` with its NUL, inline with the length and hash it
/// claims, at most `gpu_pref::MAX_PREF_BYTES`. No grammar here (the recorded rules; the current
/// ones parse it).
pub(crate) fn pref_old(s: &ValueState) -> Option<String> {
    let d = s.data.as_ref()?;
    let len = usize::try_from(s.len).ok()?;
    if s.kind != crate::sys::registry::reg_type::REG_SZ
        || len > gpu_pref::MAX_PREF_BYTES
        || d.len() != len
        || <[u8; 32]>::from(Sha256::digest(d)) != s.sha256
    {
        return None;
    }
    match RegValue::decode(s.kind, d) {
        RegValue::String(t) => Some(t),
        _ => None,
    }
}

/// The rules of a `TokenList`'s "all users" values (P3-6, module docs): at most one per view,
/// in view order, each in the strict grammar; [`Rules::Current`] adds that none holds a word
/// of a group one of the added tokens holds (`layers::machine_conflict`). The recorded rules
/// skip the groups: a later group table must not block a revert.
fn machine_rules(
    k: usize,
    add: &[TokenName],
    machine: &[MachineLayers],
    rules: Rules,
) -> Result<(), PlanError> {
    if machine.windows(2).any(|w| w[0].view >= w[1].view) {
        return Err(invalid(
            Some(k),
            "all-users values: at most one per view, in view order",
        ));
    }
    for m in machine {
        let conflict = layers::machine_conflict(&m.value, add).map_err(|_| {
            invalid(
                Some(k),
                "an all-users compatibility-layer value outside the grammar",
            )
        })?;
        if rules == Rules::Current && conflict.is_some() {
            return Err(invalid(
                Some(k),
                "an all-users compatibility-layer value with a token of the group of an added token",
            ));
        }
    }
    Ok(())
}

/// The old compatibility-layer value of a `TokenList`: a `REG_SZ` with its NUL, inline with
/// the length and hash it claims, at most `MAX_LAYERS_BYTES`, in the grammar.
pub(crate) fn layers_old(s: &ValueState) -> Option<String> {
    let d = s.data.as_ref()?;
    let len = usize::try_from(s.len).ok()?;
    if s.kind != crate::sys::registry::reg_type::REG_SZ
        || len > layers::MAX_LAYERS_BYTES
        || d.len() != len
        || <[u8; 32]>::from(Sha256::digest(d)) != s.sha256
    {
        return None;
    }
    let RegValue::String(t) = RegValue::decode(s.kind, d) else {
        return None;
    };
    layers::parse(&t).ok()?;
    Some(t)
}

/// The rules of an `IniValue` (module docs).
fn ini_rules(
    k: usize,
    path: &RelPath,
    old: &FileState,
    new: &FileHash,
    edits: &[IniEdit],
    rules: Rules,
) -> Result<(), PlanError> {
    if !ini::path_ok(path) {
        return Err(invalid(
            Some(k),
            "INI values only in a .ini file other than desktop.ini",
        ));
    }
    ini::check_edits(edits).map_err(|source| PlanError::Ini { op: k, source })?;
    let max = u64::try_from(ini::MAX_INI_BYTES).unwrap_or(u64::MAX);
    if old.len > max || new.len > max {
        return Err(invalid(Some(k), "an INI file larger than 1 MiB"));
    }
    if old.sha256 == new.sha256 {
        return Err(invalid(Some(k), "INI values that do not change the file"));
    }
    if rules == Rules::Current {
        for e in edits {
            e.new
                .check_new()
                .map_err(|source| PlanError::Ini { op: k, source })?;
        }
    }
    Ok(())
}

/// The rules of a `Hold` (P4-8, module docs): a package file on a game root.
fn hold_check(plan: &Plan, k: usize, root: RootIx, content: &ContentRef) -> Result<(), PlanError> {
    if !matches!(content, ContentRef::Package { .. }) {
        return Err(invalid(Some(k), "a held file that is no package file"));
    }
    let r = plan
        .roots
        .get(usize::from(root.0))
        .ok_or_else(|| invalid(Some(k), "root index outside the plan's roots"))?;
    if r.kind != RootKind::Game {
        return Err(invalid(Some(k), "a held file outside a game folder"));
    }
    Ok(())
}

/// The rules of a [`ContentRef::Patch`] (P4-10, both rule sets: the head is untrusted): only the
/// content of a `ReplaceFile` on a game root, its base exactly the op's old state, 1 to
/// [`MAX_PATCH_EDITS`] edits strictly ascending by offset, each inside the file and changing its
/// byte. That the edits are the ones `laa_patch` derives is the planner's (`prim::laa_patch`);
/// `exec` checks the result's hash, so a recorded patch writes nothing but its own result.
fn patch_check(plan: &Plan, k: usize, op: &Op) -> Result<(), PlanError> {
    let (root, old, content) = match op {
        Op::ReplaceFile {
            root, old, content, ..
        } => (*root, old, content),
        Op::CreateFile {
            content: ContentRef::Patch { .. },
            ..
        } => {
            return Err(invalid(Some(k), "a patch only replaces an existing file"));
        }
        _ => return Ok(()),
    };
    let ContentRef::Patch { base, edits, .. } = content else {
        return Ok(());
    };
    let r = plan
        .roots
        .get(usize::from(root.0))
        .ok_or_else(|| invalid(Some(k), "root index outside the plan's roots"))?;
    if r.kind != RootKind::Game {
        return Err(invalid(Some(k), "a patch outside a game folder"));
    }
    if base != old {
        return Err(invalid(Some(k), "a patch of another file than the old one"));
    }
    if edits.is_empty() || edits.len() > MAX_PATCH_EDITS {
        return Err(invalid(Some(k), "a patch changes 1 to 8 bytes"));
    }
    if edits.windows(2).any(|w| w[0].offset >= w[1].offset)
        || edits.iter().any(|e| e.offset >= base.len || e.old == e.new)
    {
        return Err(invalid(
            Some(k),
            "patch edits ascending, inside the file, each changing its byte",
        ));
    }
    Ok(())
}

/// Most `FirewallRule` ops of a plan: one helper batch (`elevate::MAX_BATCH_OPS`).
pub const MAX_RULE_OPS: usize = crate::elevate::MAX_BATCH_OPS;

/// The rules of a `FirewallRule` (module docs): a plan with a source (a signed Topo), a game
/// root, and a program Rerun's rule form takes (`policy::firewall::Program`: no `%`, at most
/// 243 characters, an `.exe`).
fn rule_check(plan: &Plan, k: usize, root: RootIx, program: &RelPath) -> Result<(), PlanError> {
    if plan.source.is_none() {
        return Err(invalid(
            Some(k),
            "a firewall rule needs the plan's source (a signed Topo)",
        ));
    }
    let r = plan
        .roots
        .get(usize::from(root.0))
        .ok_or_else(|| invalid(Some(k), "root index outside the plan's roots"))?;
    if r.kind != RootKind::Game {
        return Err(invalid(Some(k), "a firewall rule outside a game folder"));
    }
    Program::new(&r.path, program)
        .map_err(|_| invalid(Some(k), "a program a firewall rule cannot name"))?;
    Ok(())
}

/// The bounds and rules shared by [`Plan::encode`] and [`decode`] (`rules`: module docs).
fn check(plan: &Plan, len: usize, lim: &Limits, rules: Rules) -> Result<(), PlanError> {
    if plan.format != FORMAT {
        return Err(PlanError::Format(plan.format));
    }
    if len > lim.plan_bytes {
        return Err(PlanError::TooLarge {
            limit: lim.plan_bytes,
        });
    }
    if plan.ops.len() > lim.ops {
        return Err(PlanError::TooManyOps {
            n: plan.ops.len(),
            limit: lim.ops,
        });
    }
    if plan.roots.len() > MAX_ROOTS {
        return Err(invalid(None, "more roots than allowed"));
    }
    if let Some(s) = &plan.source {
        s.check()?;
    }
    // E2, review M1, E5 of P2-12: ops that need it (registry ops, INI ops) need at least one
    // game root and a main executable for every game root (P3-3: the profiles root has none).
    let mut games = plan.roots.iter().filter(|r| r.kind == RootKind::Game);
    if plan.ops.iter().any(Op::needs_main_exe)
        && (games.clone().next().is_none() || games.any(|r| r.main_exe.is_none()))
    {
        return Err(invalid(
            None,
            "registry and INI ops need the main executable of every game root",
        ));
    }
    // P4-10: a patch only on a game root, before the profile fence (which refuses any
    // non-inline content on the profiles root with its own words).
    for (k, op) in plan.ops.iter().enumerate() {
        patch_check(plan, k, op)?;
    }
    // P3-3: the fence of the profiles root and of inline content (both rule sets).
    profile::fence(plan, rules)?;
    // P4-12: the fence of the user data root (both rule sets).
    user_data::fence(plan)?;
    for (i, r) in plan.roots.iter().enumerate() {
        if plan.roots[..i].iter().any(|o| o.id == r.id) {
            return Err(invalid(None, "a root is listed twice"));
        }
        // P2-15 (audit A2 nit N2): the rule of `Object::overlaps` and `Bindings::of` for the
        // roots of one plan. A recorded head keeps the rules it was applied with (E4).
        if rules == Rules::Current
            && plan.roots[..i]
                .iter()
                .any(|o| o.path.contains(&r.path) || r.path.contains(&o.path))
        {
            return Err(invalid(None, "a root inside another root"));
        }
        if let PlanOrigin::Steam { app_id, .. } = r.origin
            && app_id == 0
        {
            return Err(invalid(None, "a Steam root without an app ID"));
        }
    }
    let mut seen: Vec<(RootIx, String)> = Vec::with_capacity(plan.ops.len());
    let mut reg = RegSeen::default();
    let mut backups = 0u64;
    let mut rules_seen: Vec<(RootIx, String)> = Vec::new();
    for (k, op) in plan.ops.iter().enumerate() {
        let size = serde_json::to_vec(op)
            .map_err(|e| PlanError::Encode(e.to_string()))?
            .len();
        if size > lim.op_bytes {
            return Err(PlanError::OpTooLarge {
                op: k,
                limit: lim.op_bytes,
            });
        }
        // P4-2d (ADR 0023 §9): the helper batch is the last ops of a plan (both rule sets: a
        // revert reaches it first, so it never needs a second helper run).
        if !rules_seen.is_empty() && !op.target().is_helper() {
            return Err(invalid(Some(k), "an op after a firewall rule"));
        }
        match op.target() {
            Target::File { root, path, .. } => {
                // 6b-d: a halt at a file op must come after every registry op is reverted
                // (the head is untrusted: the planner's order alone is no guarantee).
                if reg.any {
                    return Err(invalid(Some(k), "a file op after a registry op"));
                }
                if usize::from(root.0) >= plan.roots.len() {
                    return Err(invalid(Some(k), "root index outside the plan's roots"));
                }
                let key = (root, fold(path.as_str()));
                if seen.contains(&key) {
                    return Err(invalid(Some(k), "a second op on the same object"));
                }
                seen.push(key);
            }
            Target::Key { slot, segs } => {
                slot_on_game(plan, k, slot)?;
                reg.key(plan, k, slot, segs)?;
            }
            Target::Value { slot } => {
                slot_on_game(plan, k, slot)?;
                reg.value(plan, k, op, slot, rules)?;
            }
            Target::Rule { root, program } => {
                rule_check(plan, k, root, program)?;
                let key = (root, fold(program.as_str()));
                // Security review N2 of P4-2d: the helper hashes the executable it blocks; a
                // plan that writes that very file would make its own rule fail the check.
                if seen.contains(&key) {
                    return Err(invalid(
                        Some(k),
                        "a firewall rule for an executable the plan writes",
                    ));
                }
                if rules_seen.contains(&key) {
                    return Err(invalid(Some(k), "two firewall rules for one executable"));
                }
                rules_seen.push(key);
                if rules_seen.len() > MAX_RULE_OPS {
                    return Err(invalid(Some(k), "more than 8 firewall rules"));
                }
            }
        }
        if let Op::Hold { root, content, .. } = op {
            hold_check(plan, k, *root, content)?;
        }
        if let Some((
            _,
            ContentRef::Package {
                id, version, len, ..
            },
        )) = op.package_file()
        {
            if !package_id_ok(id) || !package_version_ok(version) {
                return Err(invalid(Some(k), "not a valid package ID and version"));
            }
            if *len > MAX_FILE_LEN {
                return Err(invalid(Some(k), "content larger than 2 GiB"));
            }
        }
        if let Op::ReplaceFile { old, content, .. } = op {
            if old.sha256 == *content.sha256() {
                return Err(invalid(Some(k), "a replace with the content it replaces"));
            }
            if old.len > MAX_FILE_LEN {
                return Err(invalid(Some(k), "old content larger than 2 GiB"));
            }
            backups = backups.saturating_add(old.len);
        }
        if let Op::IniValue {
            path,
            old,
            new,
            edits,
            ..
        } = op
        {
            ini_rules(k, path, old, new, edits, rules)?;
            backups = backups.saturating_add(old.len);
        }
    }
    if backups > MAX_BACKUP_BYTES {
        return Err(invalid(None, "the backups exceed 4 GiB"));
    }
    Ok(())
}

/// Where the file ops of a root lie, for [`Object::of_bound`]: its identity and canonical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileRoot {
    /// Identity of the folder.
    pub(crate) id: RootId,
    /// Its canonical path.
    pub(crate) path: RootPath,
}

/// An object a plan's op touches, for stacking (ADR 0019, B-2), by [`Target`]: a file or
/// directory as root identity and folded path. Two objects overlap if they are the same, or
/// if one is a directory an op creates and the other lies below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Object {
    /// A file or directory.
    File {
        /// Identity of the root.
        root: RootId,
        /// Canonical path of the root as planned: roots of which one lies inside the other
        /// overlap as a whole (fail closed, review S2).
        root_path: RootPath,
        /// Folded path below the root.
        path: String,
        /// A directory the op creates.
        dir: bool,
    },
    /// A registry key.
    Key {
        /// The key (compared folded).
        key: RegKey,
        /// Everything below it is its object too: the op creates it, and it is not a shared
        /// Windows key (`AppCompatFlags`, `Layers`: only the key itself, user decision E7).
        created: bool,
    },
    /// A registry value.
    Value {
        /// Its key (compared folded).
        key: RegKey,
        /// Its folded name.
        name: String,
    },
    /// A firewall rule of the helper batch (P4-2d): named by its transaction and op, so it
    /// overlaps nothing.
    Rule,
}

impl Object {
    /// The objects of `plan`. A registry slot `policy::registry` refuses, or a root index
    /// outside the plan, is an error, never a missing object (`decode` refuses such a plan
    /// anyway; the caller fails closed).
    pub(crate) fn of(plan: &Plan) -> Result<Vec<Self>, PlanError> {
        let roots: Vec<FileRoot> = plan
            .roots
            .iter()
            .map(|r| FileRoot {
                id: r.id,
                path: r.path.clone(),
            })
            .collect();
        Self::of_bound(plan, &roots)
    }

    /// As [`Self::of`], but the objects of a file op of root `i` lie in `file_roots[i]` (P2-14:
    /// a root bound to another folder by a `Rebind`); registry objects always from the plan's
    /// roots (the values Rerun wrote, user decision E-R4 a).
    pub(crate) fn of_bound(plan: &Plan, file_roots: &[FileRoot]) -> Result<Vec<Self>, PlanError> {
        plan.ops
            .iter()
            .enumerate()
            .map(|(k, op)| match op.target() {
                Target::File { root, path, dir } => {
                    let r = file_roots
                        .get(usize::from(root.0))
                        .ok_or_else(|| invalid(Some(k), "root index outside the plan's roots"))?;
                    Ok(Self::File {
                        root: r.id,
                        root_path: r.path.clone(),
                        path: fold(path.as_str()),
                        dir,
                    })
                }
                Target::Key { slot, segs } => {
                    let (av, key) = created_key(plan, slot, segs, k)?;
                    Ok(Self::Key {
                        key,
                        created: !av.shared_keys(),
                    })
                }
                Target::Value { slot } => {
                    let av = allowed(plan, slot, k)?;
                    Ok(Self::Value {
                        key: av.key().key().clone(),
                        name: fold(av.name()),
                    })
                }
                Target::Rule { .. } => Ok(Self::Rule),
            })
            .collect()
    }

    /// Same object, or one a created directory or key with the other below it; any two
    /// objects of two different roots of which one lies inside the other (a manual root
    /// inside a Steam install folder): no rebasing of paths, fail closed. A file and a
    /// registry object never overlap.
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Rule, _) | (_, Self::Rule) => false,
            (
                Self::Key {
                    key: a,
                    created: ca,
                },
                Self::Key {
                    key: b,
                    created: cb,
                },
            ) => a == b || (*ca && is_below(b, a)) || (*cb && is_below(a, b)),
            (Self::Key { key, created }, Self::Value { key: v, .. })
            | (Self::Value { key: v, .. }, Self::Key { key, created }) => {
                *created && key_at_or_below(v, key)
            }
            (Self::Value { key: a, name: na }, Self::Value { key: b, name: nb }) => {
                a == b && na == nb
            }
            (Self::File { .. }, Self::Key { .. } | Self::Value { .. })
            | (Self::Key { .. } | Self::Value { .. }, Self::File { .. }) => false,
            (
                Self::File {
                    root: ra,
                    root_path: pa,
                    path: a,
                    dir: da,
                },
                Self::File {
                    root: rb,
                    root_path: pb,
                    path: b,
                    dir: db,
                },
            ) => {
                if ra != rb {
                    return pa.contains(pb) || pb.contains(pa);
                }
                let below = |dir: &str, p: &str| {
                    p.strip_prefix(dir)
                        .is_some_and(|rest| rest.starts_with('\\'))
                };
                a == b || (*da && below(a, b)) || (*db && below(b, a))
            }
        }
    }
}

/// Any object of `a` overlaps any of `b`.
pub(crate) fn overlap(a: &[Object], b: &[Object]) -> bool {
    a.iter().any(|x| b.iter().any(|y| x.overlaps(y)))
}

#[cfg(test)]
pub(crate) mod tests;
