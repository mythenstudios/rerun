//! [`serve`]: the helper's run (ADR 0023 §3, §5), the only entry `rerun-helper.exe` calls.
//!
//! §3, in this order, each step fail closed: drop the privileges (step 2), require elevation
//! (step 3), the own image check (step 4: the admin-only `Program Files\Rerun\rerun-helper.exe`
//! of `policy::root::helper_image`, resolved by the helper itself, is the image this process
//! runs, compared by NT name folded as `elevate::judge` does), the instance lock (A4 S8), then
//! the arguments (step 5). Nothing of the caller is read before step 5.
//!
//! The request (§4, A4 S1): the `elevate` folder by `{volume GUID, file ID}`, the fixed-form
//! name one segment below it (a plain file with one link, no reparse point), read bounded, its
//! SHA-256 equal to the argument, [`decode`]d against this build's [`crate::BUILD_ID`], its
//! transaction the one its name carries.
//!
//! **Add** (§5 steps 1 to 7): the signed index by hash from the `index` folder by identity,
//! under [`trusted_keys`] (release slots, never a retired or revoked key) and at least
//! [`HELPER_MIN_SEQ`]; never `current.json`. The Topo with the request's revision, the picks
//! re-derived ([`derive_add`], no `when`). The root by identity against the helper's own
//! [`ForbiddenRoots`] (its install folder is its own). Each program hashed with SHA-256 on the
//! helper's own handle and compared with the signed value (R6). The anti-cheat check repeated
//! on the root handle (E4). The request's ops must be exactly the derived ones, in order.
//!
//! **Remove** (§5, R1): never an index, a `seq` floor, the game folder or a hash; the expected
//! rule is formed from the request alone.
//!
//! **Step 8** (P4-2d): the batch is written through `policy::firewall::{add_all, remove_all}`
//! (ADR 0023 §6): an add counts every name free (else `Refused(DuplicateName)`), adds in order,
//! reads again and reports `Done` with every op `After`, or removes its own adds again, newest
//! first (`RolledBack`, else `LeftOpen` with what it saw); a remove takes away each rule that is
//! exactly Rerun's, leaves `Foreign` ones, and reports `Done` per op (`Before` or `Foreign`).
//! The undo of an add takes back only the helper's own adds (exactly one rule of the exact name
//! in group `Rerun`), also one the firewall stored with other facts (security L3 of P4-2d). The
//! real helper writes through COM (`WinFirewallWrite`, P4-5b).

use std::ffi::OsString;
use std::path::Path;

use sha2::{Digest, Sha256 as Sha256Hasher};

use super::HELPER_MIN_SEQ;
use super::MAX_BATCH_OPS;
use super::derive::{DeriveError, derive_add};
use super::exit::{ExitClass, HelperExit, OpResult, Reason};
use super::request::{Body, MAX_REQUEST_BYTES, Request, RequestError, RequestRef, decode};
use crate::catalog::model::{Sha256, Topo};
use crate::catalog::{PublicKey, key, store, trusted_keys};
use crate::detect::exe::HashLimits;
use crate::detect::exe::anti_cheat::find_in;
use crate::detect::exe::hash::stream;
use crate::fold::fold;
use crate::path::RelPath;
use crate::policy::firewall::{Observed, Program, Written, add_all, remove_all, rule};
use crate::policy::root::{ForbiddenRoots, HelperImage, dir_by_id, helper_image, root_by_id};
use crate::sys::fs::{EntryKind, Metadata};
use crate::sys::{Dir, FwRule, HelperSystem, SysErrorKind, System};
use crate::topo::{anti_cheat_dirs, anti_cheat_state};

/// Runs the helper (module docs) and returns its report. `args` reads the arguments (without
/// the program name); it is called only after §3 steps 2 to 4 and the instance lock passed.
#[must_use]
pub fn serve(sys: &dyn HelperSystem, args: impl FnOnce() -> Vec<OsString>) -> HelperExit {
    let keys = Keys {
        trusted: trusted_keys(),
        revoked: key::REVOKED_KEYS.to_vec(),
        min_seq: HELPER_MIN_SEQ,
    };
    serve_with(sys, args, &keys)
}

/// What an add's index is checked against: this build's [`trusted_keys`] (release slots, never a
/// retired key), its revocation list and [`HELPER_MIN_SEQ`]; tests sign with the test key.
#[derive(Debug, Clone)]
pub(crate) struct Keys {
    pub(crate) trusted: Vec<PublicKey>,
    pub(crate) revoked: Vec<[u8; 32]>,
    pub(crate) min_seq: u64,
}

/// [`serve`] with explicit keys.
pub(crate) fn serve_with(
    sys: &dyn HelperSystem,
    args: impl FnOnce() -> Vec<OsString>,
    keys: &Keys,
) -> HelperExit {
    let token = sys.token();
    // §3 step 2, before anything else reads input.
    if token.drop_privileges().is_err() {
        return HelperExit::refused(Reason::Internal);
    }
    // §3 step 3.
    match token.is_elevated() {
        Ok(true) => {}
        Ok(false) => return HelperExit::refused(Reason::NotElevated),
        Err(_) => return HelperExit::refused(Reason::Internal),
    }
    // §3 step 4.
    let image = match own_image(sys) {
        Ok(i) => i,
        Err(r) => return HelperExit::refused(r),
    };
    // A4 S8: one helper at a time, held until this function returns.
    let _lock = match token.instance_lock() {
        Ok(l) => l,
        Err(e) if e.kind == SysErrorKind::Busy => return HelperExit::refused(Reason::Busy),
        Err(_) => return HelperExit::refused(Reason::Internal),
    };
    // §3 step 5.
    let Some((at, sha256)) = RequestRef::parse_args(&args()) else {
        return HelperExit::refused(Reason::Usage);
    };
    match run(sys, keys, &image, &at, &sha256) {
        Ok(exit) => exit,
        Err(reason) => HelperExit::refused(reason),
    }
}

/// §3 step 4: the pre-checked image, if this process runs it.
fn own_image(sys: &dyn HelperSystem) -> Result<HelperImage, Reason> {
    let image = helper_image(sys).map_err(|_| Reason::ImageFolder)?;
    let own = sys.token().own_image().map_err(|_| Reason::ImageFolder)?;
    if fold(&own) != fold(&image.nt_name) {
        return Err(Reason::ImageFolder);
    }
    Ok(image)
}

fn run(
    sys: &dyn HelperSystem,
    keys: &Keys,
    image: &HelperImage,
    at: &RequestRef,
    sha256: &[u8; 32],
) -> Result<HelperExit, Reason> {
    let req = read_request(sys, at, sha256)?;
    let (rules, adding) = match &req.body {
        Body::Add { .. } => (validate_add(sys, keys, image, &req)?, true),
        Body::Remove { topo, ops } => (
            ops.iter()
                .map(|o| rule(topo, &req.txn, o.op, &o.program, o.direction))
                .collect(),
            false,
        ),
    };
    execute(sys, &rules, adding)
}

/// A plain file with one link, no reparse point, readable.
fn plain(m: &Metadata) -> bool {
    m.kind == EntryKind::File && m.reparse.is_none() && m.is_single_link() && !m.restricted
}

/// The request file (module docs).
fn read_request(
    sys: &dyn HelperSystem,
    at: &RequestRef,
    sha256: &[u8; 32],
) -> Result<Request, Reason> {
    let dir = dir_by_id(sys, &at.dir.volume, at.dir.file_id).map_err(|_| Reason::Request)?;
    let name = RelPath::from_segment(at.name.as_str()).map_err(|_| Reason::Request)?;
    match dir.metadata(&name) {
        Ok(Some(m)) if plain(&m) => {}
        _ => return Err(Reason::Request),
    }
    let bytes = dir
        .read_limited(&name, MAX_REQUEST_BYTES)
        .map_err(|_| Reason::Request)?;
    let have: [u8; 32] = Sha256Hasher::digest(&bytes).into();
    if &have != sha256 {
        return Err(Reason::Request);
    }
    let req = decode(&bytes, crate::BUILD_ID).map_err(|e| match e {
        RequestError::Build => Reason::Build,
        _ => Reason::Request,
    })?;
    if req.txn != at.name.txn() {
        return Err(Reason::Request);
    }
    Ok(req)
}

/// SHA-256 of `rel` below `dir`, hashed on one handle opened handle-relative (no reparse point
/// followed), a plain single-link file before and after with the same file ID; bounded like
/// `--hashes` (R6). `None` for anything else.
fn sha256_on_handle(dir: &dyn Dir, rel: &RelPath) -> Option<[u8; 32]> {
    let before = dir.metadata(rel).ok()??;
    if !plain(&before) {
        return None;
    }
    let reader = dir.open_read(rel).ok()?;
    let limits = HashLimits::DEFAULT;
    let h = stream(reader, limits.max_file_bytes, limits.chunk_bytes).ok()?;
    let after = dir.metadata(rel).ok()??;
    if !plain(&after) || after.file_id != before.file_id {
        return None;
    }
    Sha256::parse(&h.sha256)?.bytes().copied()
}

/// §5 "Add" steps 1 to 7 (module docs): the rules of the batch, or the first refusal.
fn validate_add(
    sys: &dyn HelperSystem,
    keys: &Keys,
    image: &HelperImage,
    req: &Request,
) -> Result<Vec<FwRule>, Reason> {
    let Body::Add {
        source,
        index_dir,
        root,
        ops,
    } = &req.body
    else {
        return Err(Reason::Internal);
    };
    let txn = req.txn;
    // Step 2: the index by hash, never `current.json`.
    let idir = dir_by_id(sys, &index_dir.volume, index_dir.file_id).map_err(|_| Reason::Index)?;
    let catalog = store::load_with(&*idir, &source.index, &keys.trusted, &keys.revoked)
        .map_err(|_| Reason::Index)?;
    if catalog.seq() < keys.min_seq {
        return Err(Reason::Index);
    }
    // Step 3: the Topo and the picks, without `when`.
    let topo: &Topo = catalog
        .topo(&source.topo)
        .filter(|t| t.rev == source.rev)
        .ok_or(Reason::Topo)?;
    let anchors = derive_add(topo, &source.picks).map_err(|e| match e {
        DeriveError::NoSha256(_) => Reason::Program,
        _ => Reason::Topo,
    })?;
    // Step 4: the root by identity against the helper's own forbidden list.
    let install = image.path.path().parent().unwrap_or(Path::new(""));
    let up: &dyn System = sys;
    let fr = ForbiddenRoots::resolve(up, install).map_err(|_| Reason::Root)?;
    let game = root_by_id(
        up,
        &fr,
        &root.volume,
        root.id.file_id,
        root.id.volume_serial,
        &root.path,
    )
    .map_err(|_| Reason::Root)?;
    // Step 5: every program hashed on the helper's own handle (R6). The rule names the
    // request's spelling of the root (A4 S6 a), which matched the handle's folded.
    let mut programs = Vec::with_capacity(anchors.len());
    for a in &anchors {
        let program = Program::new(&root.path, &a.exe).map_err(|_| Reason::Program)?;
        if sha256_on_handle(game.dir(), &a.exe) != Some(a.sha256) {
            return Err(Reason::Program);
        }
        programs.push(program);
    }
    // Step 6: anti-cheat again (E4).
    let scan = find_in(game.dir(), &anti_cheat_dirs(topo));
    if anti_cheat_state(topo, &scan).enforced() {
        return Err(Reason::AntiCheat);
    }
    // Step 7: exactly the derived ops, in order.
    let same = ops.len() == anchors.len()
        && ops
            .iter()
            .zip(&anchors)
            .all(|(o, a)| o.program.same_spelling(&a.exe) && o.direction == a.direction);
    if !same {
        return Err(Reason::Ops);
    }
    Ok(ops
        .iter()
        .zip(anchors.iter().zip(&programs))
        .map(|(o, (a, p))| rule(&topo.id, &txn, o.op, p, a.direction))
        .collect())
}

/// One op's report from what the firewall holds for its rule.
fn result_of(o: Option<Observed>) -> OpResult {
    match o {
        Some(Observed::Before) => OpResult::Before,
        Some(Observed::After) => OpResult::After,
        Some(Observed::Foreign) => OpResult::Foreign,
        None => OpResult::NotRun,
    }
}

/// A report of class `class` with reason `Firewall` and these per-op results.
fn with_ops(class: ExitClass, ops: &[OpResult]) -> HelperExit {
    let mut all = [OpResult::NotRun; MAX_BATCH_OPS];
    for (slot, o) in all.iter_mut().zip(ops) {
        *slot = *o;
    }
    HelperExit {
        class,
        reason: Some(Reason::Firewall),
        ops: all,
    }
}

/// §5 step 8 (module docs): the batch written through `policy::firewall`, reported per op.
fn execute(sys: &dyn HelperSystem, rules: &[FwRule], adding: bool) -> Result<HelperExit, Reason> {
    let written = if adding {
        add_all(sys, rules)
    } else {
        remove_all(sys, rules)
    };
    match written {
        Written::Done(now) => {
            let ops: Vec<OpResult> = now.into_iter().map(|o| result_of(Some(o))).collect();
            HelperExit::done(&ops).ok_or(Reason::Internal)
        }
        Written::Duplicate => Err(Reason::DuplicateName),
        Written::Unreadable => Err(Reason::Firewall),
        Written::RolledBack => Ok(with_ops(
            ExitClass::RolledBack,
            &vec![OpResult::Before; rules.len()],
        )),
        Written::LeftOpen(now) => {
            let ops: Vec<OpResult> = now.into_iter().map(result_of).collect();
            Ok(with_ops(ExitClass::LeftOpen, &ops))
        }
    }
}
