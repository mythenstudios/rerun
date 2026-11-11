//! The status (ADR 0016 `rerun status`, ADR 0027): the journal, the last start of each launch
//! profile, which transaction holds each profile, and the Rerun firewall rules no transaction
//! of this account owns. Reads only: no lock, no game folder, nothing observed. Runs elevated
//! too.

use crate::escape::Shown;
use crate::exec::launch_result::ProfileId;
use crate::exec::{self, LaunchResults, OpState, OrphanRule, OrphansError, TxnStatus};
use crate::journal::{JournalError, TxnId};
use crate::plan::{Preview, ProfilePreview, ProfileShown};
use crate::policy::root::{AppDir, RootError};
use crate::prim::launch_method::ProfileMethod;
use crate::sys::System;

/// The preview of a transaction's head, if it could be built.
pub fn head(st: &TxnStatus) -> Option<&Preview> {
    st.preview.as_ref().and_then(|p| p.as_ref().ok())
}

/// The launch profile a preview writes, decoded (a stored plan: `Rules::Current` decodes it).
pub fn profile_of(p: &Preview) -> Option<&ProfileShown> {
    p.ops.iter().find_map(|o| match &o.profile {
        Some(ProfilePreview::Decoded(s)) => Some(&**s),
        _ => None,
    })
}

/// The profile ID of the launch profile op of `p` (from its file name; also for a profile that
/// does not decode).
pub fn profile_id_of(p: &Preview) -> Option<ProfileId> {
    p.ops.iter().find_map(|o| {
        o.profile.as_ref()?;
        ProfileId::from_hex(o.path.as_str().strip_suffix(".profile")?)
    })
}

/// The op index of the launch profile op of `p`, and whether it replaces a profile.
pub fn profile_op(p: &Preview) -> Option<(u16, bool)> {
    p.ops
        .iter()
        .find(|o| o.profile.is_some())
        .map(|o| (u16::try_from(o.index).unwrap_or(u16::MAX), o.replaces))
}

/// A transaction whose launch profile op is not reverted (A6, A7): it holds the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    /// The profile.
    pub id: ProfileId,
    /// The transaction.
    pub txn: TxnId,
    /// It is forgotten (it cannot be reverted any more).
    pub forgotten: bool,
    /// The start, if it is a launcher (not the game) of a `direct` profile.
    pub launcher: Option<Shown<'static>>,
    /// The target, if the profile is `watch` (P3-4c).
    pub watch: Option<Shown<'static>>,
}

/// Per profile ID the newest transaction whose profile op is not reverted, forgotten included
/// (review S2; a head the status did not build is read on its own).
pub(crate) fn holders(app: &AppDir<'_>, s: &exec::Status) -> Vec<Holder> {
    let mut out: Vec<Holder> = Vec::new();
    for st in &s.txns {
        let read;
        let p = match head(st) {
            Some(p) => p,
            None if st.is_forgotten() => {
                read = exec::txn_status(app, &st.id).ok();
                match read.as_ref().and_then(head) {
                    Some(p) => p,
                    None => continue,
                }
            }
            None => continue,
        };
        let (Some((k, _)), Some(id), Some(prof)) = (profile_op(p), profile_id_of(p), profile_of(p))
        else {
            continue;
        };
        // Only an applied profile op holds a profile (an interrupted one may have no file).
        let applied = st
            .ops
            .iter()
            .any(|o| o.op == k && o.state == OpState::Applied);
        if !applied {
            continue;
        }
        let h = Holder {
            id,
            txn: st.id,
            forgotten: st.is_forgotten(),
            launcher: prof.launcher.then(|| prof.start.clone()),
            watch: (prof.decoded.method == ProfileMethod::Watch).then(|| prof.target.clone()),
        };
        // The listing is in order: a later transaction replaces an earlier one.
        out.retain(|x| x.id != id);
        out.push(h);
    }
    out
}

/// What `status` shows.
#[derive(Debug)]
pub struct StatusView {
    /// The journal.
    pub status: exec::Status,
    /// The last start per launch profile (`Ok(None)`: no `launch` folder).
    pub launch: Result<Option<LaunchResults>, RootError>,
    /// Which transaction holds each launch profile.
    pub holders: Vec<Holder>,
    /// Rerun's firewall rules no transaction of this account owns (ADR 0023 §6, A4 N6).
    pub orphans: Result<Vec<OrphanRule>, OrphansError>,
}

/// The status of Rerun's folder `app` (module docs); only an unreadable journal fails it.
pub fn status(sys: &dyn System, app: &AppDir<'_>) -> Result<StatusView, JournalError> {
    let status = exec::status(app)?;
    let launch = exec::launch_results(app);
    let holders = holders(app, &status);
    let orphans = exec::firewall_orphans(sys, app);
    Ok(StatusView {
        status,
        launch,
        holders,
        orphans,
    })
}
