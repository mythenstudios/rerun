//! The user data root in a plan (P4-12, ADR 0020 amendment P4-12): its fence.
//!
//! Holds on encode and decode alike, with both rule sets (the journal head is untrusted; none of
//! these rules depends on a value a later version might tighten):
//! - `kind: user_data` exactly with `origin: user_folder`; such a root has no main executable,
//!   not the identity [`PROFILES_ROOT_ID`], a folder below its base that passes
//!   `policy::root::user_dir_ok` (the allowlist, also on decode: a head cannot name
//!   `WindowsPowerShell`), and a path that ends, folded, in `\<sub>`.
//! - At most one, and last: root 0 is a game root, the user data root has an index of 1 or more
//!   (after the profiles root, if there is one; `plan::profile`).
//! - On it only `IniValue` ops (user decision U1 a, L7): no folder, no package file, no inline
//!   content, no hold, no patch. Registry slots and firewall rules name game roots only
//!   (`plan::slot_on_game`, `plan::rule_check`).
//!
//! Exactly how `exec` opens it again (never by the head's path) is `exec::roots`.

use super::{Op, PROFILES_ROOT_ID, Plan, PlanError, PlanOrigin, RootKind, Target, invalid};
use crate::fold::fold;
use crate::path::{RelPath, RootPath};
use crate::policy::root::user_dir_ok;

/// `path` ends, folded and segment-wise, in `\<sub>`.
fn ends_in(path: &RootPath, sub: &RelPath) -> bool {
    fold(&path.to_string())
        .strip_suffix(&fold(sub.as_str()))
        .is_some_and(|head| head.ends_with('\\'))
}

/// The fence (module docs).
pub(super) fn fence(plan: &Plan) -> Result<(), PlanError> {
    let mut at = None;
    for (i, r) in plan.roots.iter().enumerate() {
        match (r.kind, &r.origin) {
            (RootKind::UserData, PlanOrigin::UserFolder { base, sub }) => {
                if at.replace(i).is_some() {
                    return Err(invalid(None, "more than one user data root"));
                }
                if r.main_exe.is_some() || r.id == PROFILES_ROOT_ID {
                    return Err(invalid(
                        None,
                        "a user data root without main executable or the profiles identity",
                    ));
                }
                if user_dir_ok(*base, sub).is_err() {
                    return Err(invalid(
                        None,
                        "a user data folder its allowlist does not allow",
                    ));
                }
                if !ends_in(&r.path, sub) {
                    return Err(invalid(
                        None,
                        "a user data root whose path does not end in its folder",
                    ));
                }
            }
            (RootKind::UserData, _) | (_, PlanOrigin::UserFolder { .. }) => {
                return Err(invalid(
                    None,
                    "the user data root, and only it, comes from a user folder",
                ));
            }
            _ => {}
        }
    }
    let Some(i) = at else {
        return Ok(());
    };
    let game0 = plan.roots.first().is_some_and(|r| r.kind == RootKind::Game);
    if i == 0 || i + 1 != plan.roots.len() || !game0 {
        return Err(invalid(
            None,
            "a user data root comes last, after the game root at index 0",
        ));
    }
    for (k, op) in plan.ops.iter().enumerate() {
        let on_it = match op.target() {
            Target::File { root, .. } | Target::Rule { root, .. } => usize::from(root.0) == i,
            Target::Key { .. } | Target::Value { .. } => false,
        };
        if on_it && !matches!(op, Op::IniValue { .. }) {
            return Err(invalid(Some(k), "only INI values in a user data folder"));
        }
    }
    Ok(())
}
