//! Stored plans: `<AppDir>\plans\<plan-hash>.json` (ADR 0019 layout, ADR 0020 "Plan hash").
//!
//! A plan is written once with `create_new` (temp name, flush, rename without replace) under
//! the name of its hash; storing the same bytes again is a no-op. Loading is bounded
//! ([`MAX_PLAN_BYTES`]) and accepts the bytes only if they hash to the name: the hash binds
//! what the preview showed to what `exec` applies and catches accidents. It is no security
//! boundary (any process of the user can write there); `exec` parses the bytes as untrusted
//! input and re-checks everything.

use sha2::{Digest, Sha256};

use super::{MAX_PLAN_BYTES, PlanBytes, PlanError, PlanHash};
use crate::journal::InstanceTag;
use crate::path::RelPath;
use crate::policy::root::{AppDir, AppSub, Create};
use crate::sys::fs::{Attrs, NewFile, TmpName};
use crate::sys::{SysError, SysErrorKind};

/// `<hash>.json` as a segment.
fn name(h: &PlanHash) -> RelPath {
    match RelPath::from_segment(&format!("{h}.json")) {
        Ok(p) => p,
        Err(e) => unreachable!("64 hex digits and .json are a segment: {e}"),
    }
}

/// Stores `b` as `plans\<hash>.json` (created if missing) and flushes the folder. The same
/// bytes already stored are `Ok`; other bytes under that name are [`PlanError::HashMismatch`].
pub fn store(app: &AppDir<'_>, b: &PlanBytes) -> Result<PlanHash, PlanError> {
    let dir = app
        .sub_write(AppSub::Plans, Create::IfMissing)?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "plans"))?;
    let h = b.hash();
    let file = name(&h);
    let new = NewFile {
        tmp: TmpName::new(InstanceTag::new().get(), 0),
        attrs: Attrs::default(),
        sha256: h.0,
        max_len: u64::try_from(b.bytes().len()).unwrap_or(u64::MAX),
    };
    match dir.create_new(&file, &mut b.bytes(), &new) {
        Ok(_) => {}
        Err(e) if e.kind == SysErrorKind::AlreadyExists => {
            let have = dir.read_limited(&file, MAX_PLAN_BYTES as u64)?;
            let sha: [u8; 32] = Sha256::digest(&have).into();
            if sha != h.0 {
                return Err(PlanError::HashMismatch(h));
            }
        }
        Err(e) => return Err(e.into()),
    }
    dir.flush()?;
    Ok(h)
}

/// The stored bytes of plan `h`: at most [`MAX_PLAN_BYTES`], and only if they hash to `h`.
pub fn load(app: &AppDir<'_>, h: &PlanHash) -> Result<PlanBytes, PlanError> {
    let Some(dir) = app.sub(AppSub::Plans)? else {
        return Err(PlanError::NotFound(*h));
    };
    let bytes = match dir.read_limited(&name(h), MAX_PLAN_BYTES as u64) {
        Ok(b) => b,
        Err(e) if e.kind == SysErrorKind::NotFound => return Err(PlanError::NotFound(*h)),
        Err(e) if e.kind == SysErrorKind::TooLarge => {
            return Err(PlanError::TooLarge {
                limit: MAX_PLAN_BYTES,
            });
        }
        Err(e) => return Err(e.into()),
    };
    let b = PlanBytes::from_bytes(bytes);
    if b.hash() != *h {
        return Err(PlanError::HashMismatch(*h));
    }
    Ok(b)
}
