//! Launch profiles in a plan (P3-3, ADR 0020 amendment P3-3): the fence of the profiles root and
//! of inline content, and the profile's ID.
//!
//! The fence holds on encode and decode alike, with both rule sets (the journal head is
//! untrusted; senior-dev condition B1 on which rule belongs to which set):
//! - Form, both sets: `kind: profiles` exactly with `origin: app_dir`; such a root has the
//!   identity [`PROFILES_ROOT_ID`], no main executable and a path that ends, folded, in
//!   `\Rerun\profiles`; at most one of it, and a plan with it has exactly two roots: one game
//!   root at index 0 from a Steam library, the profiles root at index 1. No game root carries
//!   [`PROFILES_ROOT_ID`] (condition A2). On the profiles root only `CreateFile` and
//!   `ReplaceFile`, as op 0 (a revert, newest first, reaches it last: a missing `profiles`
//!   halts only once everything else is reverted, F3), named `<32 lower-case hex>.profile`
//!   (one segment), with [`ContentRef::Inline`] content and no attributes; the old file of a
//!   `ReplaceFile` at most [`MAX_PROFILE_OLD_BYTES`]. No registry slot names the profiles root.
//!   [`ContentRef::Inline`] only on the profiles root, at most [`MAX_INLINE_BYTES`], with the
//!   SHA-256 of its bytes.
//! - [`Rules::Current`] only (planning, encode, apply): the bytes decode as a launch profile
//!   (`rerun_proto::profile`), its `start` and `target` lie below the path of root 0 (folded),
//!   each has at most [`MAX_EXE_PATH_UNITS`] UTF-16 units, root 0 names its main executable
//!   (D4 asks it, also for a plan whose only op is the profile; review S2), a `watch` profile's
//!   `target` is `<root 0>\<main executable>` (folded; P3-4 P1, P4: the shim sets the rule on
//!   exactly the program apply and revert ask), and the file name is [`profile_id`] of root 0's
//!   Steam app. A recorded head keeps only the form, so a rule a later version adds never
//!   blocks a revert (user decision E4 of P2-11); the revert only observes hashes and never
//!   reads the profile.

use rerun_proto::profile::{self as proto, Method, ProfileId};
use sha2::{Digest, Sha256};

use super::{
    ContentRef, MAX_INLINE_BYTES, Op, PROFILES_ROOT_ID, Plan, PlanError, PlanOrigin, RootIx,
    RootKind, Rules, Target, invalid,
};
use crate::fold::fold;
use crate::path::{RelPath, RootPath};
use crate::policy::registry::RegSlot;
use crate::sys::fs::Attrs;

/// Largest old file a profile op replaces (the shim's read limit, `rerun_proto`): anything
/// larger at that name is not a profile Rerun wrote, and stays.
pub const MAX_PROFILE_OLD_BYTES: u64 = 8 << 10;

/// Most UTF-16 units of a profile's `start` and `target` (ADR 0022 "Not decided here": no long
/// paths yet; P3-4 P4: the target too).
pub const MAX_EXE_PATH_UNITS: usize = 259;

/// Domain tag of [`profile_id`] (another form of ID, e.g. without Steam, gets another tag).
const ID_TAG: &[u8] = b"rerun-profile-id\0";

/// The profile ID of Steam app `app_id` (ADR 0020 amendment P3-3, user decision E1 a): the
/// first 16 bytes of SHA-256(`"rerun-profile-id\0"` ‖ `1u8` ‖ `"steam\0"` ‖ `app_id` as 4
/// bytes little-endian). One profile per game: a new plan, another start or a moved library
/// keep it, and with it the launch option the user pasted.
pub fn profile_id(app_id: u32) -> ProfileId {
    let mut h = Sha256::new();
    h.update(ID_TAG);
    h.update([1u8]);
    h.update(b"steam\0");
    h.update(app_id.to_le_bytes());
    let d = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    ProfileId(id)
}

/// The file name of profile `id` below the profiles root: `<32 hex>.profile`.
pub fn profile_file(id: ProfileId) -> RelPath {
    let name = format!("{id}.profile");
    match RelPath::from_segment(&name) {
        Ok(p) => p,
        Err(e) => unreachable!("{name} is a valid segment: {e}"),
    }
}

/// `p` is one segment `^[0-9a-f]{32}\.profile$`.
fn name_ok(p: &RelPath) -> bool {
    let s = p.as_str();
    s.strip_suffix(".profile")
        .and_then(ProfileId::from_hex)
        .is_some()
}

/// The path of a profiles root ends, folded, in `\Rerun\profiles`.
fn profiles_path(p: &RootPath) -> bool {
    fold(&p.to_string()).ends_with(r"\RERUN\PROFILES")
}

/// `abs` lies strictly below `root` (folded, segment-wise).
fn below(abs: &str, root: &RootPath) -> bool {
    fold(abs)
        .strip_prefix(&fold(&root.to_string()))
        .is_some_and(|rest| rest.starts_with('\\') && rest.len() > 1)
}

/// The plan root a registry slot names, if any.
fn slot_root(s: &RegSlot) -> Option<RootIx> {
    match s {
        RegSlot::CompatLayers { root, .. } | RegSlot::GpuPreference { root, .. } => Some(*root),
        RegSlot::GameValue { .. } => None,
    }
}

/// The fence (module docs).
pub(super) fn fence(plan: &Plan, rules: Rules) -> Result<(), PlanError> {
    let profiles = profiles_root(plan)?;
    let on_profiles = |root: RootIx| profiles == Some(usize::from(root.0));
    for (k, op) in plan.ops.iter().enumerate() {
        let target_profiles = match op.target() {
            Target::File { root, .. } => on_profiles(root),
            Target::Value { slot } => {
                if slot_root(slot).is_some_and(on_profiles) {
                    return Err(invalid(Some(k), "a registry slot on the profiles root"));
                }
                false
            }
            Target::Key { slot, .. } => {
                if slot_root(slot).is_some_and(on_profiles) {
                    return Err(invalid(Some(k), "a registry slot on the profiles root"));
                }
                false
            }
        };
        if target_profiles {
            profile_op(plan, k, op, rules)?;
        }
        if let Some(ContentRef::Inline { bytes, sha256 }) = op.content() {
            if !target_profiles && !knob::inline_anywhere() {
                return Err(invalid(
                    Some(k),
                    "inline content only for a launch profile on the profiles root",
                ));
            }
            if bytes.len() > MAX_INLINE_BYTES {
                return Err(invalid(Some(k), "inline content larger than 2 KiB"));
            }
            if <[u8; 32]>::from(Sha256::digest(bytes)) != *sha256 {
                return Err(invalid(
                    Some(k),
                    "inline content whose SHA-256 does not fit",
                ));
            }
        }
    }
    Ok(())
}

/// The roots' part of the fence: the index of the profiles root, if there is one.
fn profiles_root(plan: &Plan) -> Result<Option<usize>, PlanError> {
    let mut profiles = None;
    for (i, r) in plan.roots.iter().enumerate() {
        match (r.kind, &r.origin) {
            (RootKind::Profiles, PlanOrigin::AppDir) => {
                if profiles.replace(i).is_some() {
                    return Err(invalid(None, "more than one profiles root"));
                }
                if r.id != PROFILES_ROOT_ID || r.main_exe.is_some() || !profiles_path(&r.path) {
                    return Err(invalid(
                        None,
                        "a profiles root other than <LocalAppData>\\Rerun\\profiles without \
                         identity or main executable",
                    ));
                }
            }
            (RootKind::Profiles, _) | (RootKind::Game, PlanOrigin::AppDir) => {
                return Err(invalid(
                    None,
                    "the profiles root, and only it, comes from Rerun's folder",
                ));
            }
            (RootKind::Game, PlanOrigin::Steam { .. } | PlanOrigin::Manual) => {
                if r.id == PROFILES_ROOT_ID {
                    return Err(invalid(
                        None,
                        "a game root with the identity of the profiles root",
                    ));
                }
            }
        }
    }
    if let Some(p) = profiles {
        let steam0 = plan.roots.first().is_some_and(|r| {
            r.kind == RootKind::Game && matches!(r.origin, PlanOrigin::Steam { .. })
        });
        if !steam0 || plan.roots.len() != 2 || p != 1 {
            return Err(invalid(
                None,
                "a plan with a profiles root has one Steam game root at index 0 and the \
                 profiles root at index 1",
            ));
        }
    }
    Ok(profiles)
}

/// The rules of op `k`, which targets the profiles root.
fn profile_op(plan: &Plan, k: usize, op: &Op, rules: Rules) -> Result<(), PlanError> {
    if k != 0 && !knob::profile_op_anywhere() {
        return Err(invalid(Some(k), "the profile op is op 0"));
    }
    let (path, content, attrs) = match op {
        Op::CreateFile {
            path,
            content,
            attrs,
            ..
        } => (path, content, attrs),
        Op::ReplaceFile {
            path,
            old,
            content,
            attrs,
            ..
        } => {
            if old.len > MAX_PROFILE_OLD_BYTES {
                return Err(invalid(Some(k), "a replaced profile larger than 8 KiB"));
            }
            (path, content, attrs)
        }
        _ => {
            return Err(invalid(
                Some(k),
                "only create file and replace file on the profiles root",
            ));
        }
    };
    if !name_ok(path) {
        return Err(invalid(
            Some(k),
            "a profile is named <32 lower-case hex digits>.profile",
        ));
    }
    if *attrs != Attrs::default() {
        return Err(invalid(Some(k), "a profile without attributes"));
    }
    let ContentRef::Inline { bytes, .. } = content else {
        return Err(invalid(Some(k), "a profile's content is inline"));
    };
    if rules == Rules::Current {
        current(plan, k, path, bytes)?;
    }
    Ok(())
}

/// [`Rules::Current`] of a profile op (module docs).
fn current(plan: &Plan, k: usize, path: &RelPath, bytes: &[u8]) -> Result<(), PlanError> {
    let Some(game) = plan.roots.first() else {
        return Err(invalid(Some(k), "a profile without its game root"));
    };
    let PlanOrigin::Steam { app_id, .. } = &game.origin else {
        return Err(invalid(Some(k), "a profile without its game root"));
    };
    // P3-3c review S2: the game-closed check (D4) of a profile plan asks the game's main
    // executable, also when the profile is the plan's only op (F11).
    let Some(main) = &game.main_exe else {
        return Err(invalid(
            Some(k),
            "a profile plan without the game's main executable",
        ));
    };
    let p = proto::decode(bytes)
        .map_err(|_| invalid(Some(k), "inline bytes that are no launch profile"))?;
    if !below(&p.start, &game.path) || !below(&p.target, &game.path) {
        return Err(invalid(
            Some(k),
            "a profile whose start or target is not in the game folder",
        ));
    }
    if p.start.encode_utf16().count() > MAX_EXE_PATH_UNITS {
        return Err(invalid(Some(k), "a start path longer than 259 characters"));
    }
    if p.target.encode_utf16().count() > MAX_EXE_PATH_UNITS {
        return Err(invalid(Some(k), "a target path longer than 259 characters"));
    }
    // P3-4 P1, P4: `watch` sets the rule on the main executable and nothing else (`direct`:
    // `target == start`, the profile decoder's rule).
    if p.method == Method::Watch
        && !knob::watch_target_anywhere()
        && fold(&p.target) != fold(&format!(r"{}\{main}", game.path))
    {
        return Err(invalid(
            Some(k),
            "a watch profile whose target is not the game's main executable",
        ));
    }
    if *path != profile_file(profile_id(*app_id)) {
        return Err(invalid(Some(k), "a profile not named by its game's ID"));
    }
    Ok(())
}

/// Test knobs (controls K-LM1 and K-LM3, ADR 0020 amendment P3-3; K-LW1, P3-4): a rule of the
/// fence off.
#[cfg(test)]
pub(crate) mod knob {
    use std::cell::Cell;

    thread_local! {
        static INLINE_ANYWHERE: Cell<bool> = const { Cell::new(false) };
        static PROFILE_OP_ANYWHERE: Cell<bool> = const { Cell::new(false) };
        static WATCH_TARGET_ANYWHERE: Cell<bool> = const { Cell::new(false) };
    }

    /// K-LM1: inline content allowed on any root.
    pub(crate) fn allow_inline_anywhere(on: bool) {
        INLINE_ANYWHERE.with(|s| s.set(on));
    }
    pub(crate) fn inline_anywhere() -> bool {
        INLINE_ANYWHERE.with(Cell::get)
    }
    /// K-LM3: the profile op at any index (F3 off).
    pub(crate) fn allow_profile_op_anywhere(on: bool) {
        PROFILE_OP_ANYWHERE.with(|s| s.set(on));
    }
    pub(crate) fn profile_op_anywhere() -> bool {
        PROFILE_OP_ANYWHERE.with(Cell::get)
    }
    /// K-LW1: a `watch` target other than the main executable allowed (P4 off).
    pub(crate) fn allow_watch_target_anywhere(on: bool) {
        WATCH_TARGET_ANYWHERE.with(|s| s.set(on));
    }
    pub(crate) fn watch_target_anywhere() -> bool {
        WATCH_TARGET_ANYWHERE.with(Cell::get)
    }
}

#[cfg(not(test))]
mod knob {
    pub(super) fn inline_anywhere() -> bool {
        false
    }
    pub(super) fn profile_op_anywhere() -> bool {
        false
    }
    pub(super) fn watch_target_anywhere() -> bool {
        false
    }
}
