//! Rebind against the fake (P2-14a; ADR 0020 amendment P2-14), each scenario a check function
//! with named findings (review N1) where a control needs it:
//! - RB-T1 a library moved to another volume (new file IDs): the revert without a rebind halts
//!   after the registry ops; `rebind_check` shows the old and the new folder and the created
//!   folders by the IDs found; `revert_rebound` closes; the folder identical to the copy before
//!   the apply, `HKCU\Software` identical.
//! - RB-T2 a reinstall at the same path (`IdentityMismatch`): the revert refused, nothing
//!   written; the rebind finds every file op `Before` and reverts the registry ops.
//! - RB-T3 the app moved to another library, the old library stays without its manifest: rebind
//!   without a revert before it; the registry ops reverted at the head's locations (the `Layers`
//!   value under the old executable path).
//! - RB-T4 an INI file the game rewrote in the new folder: `Drifted`, the rebind allowed, the
//!   semantic revert exact.
//! - RB-T5 every refusal of this cut without a record (the journal folder identical).
//! - RB-T6 the folder or a created folder changed between the preview and the rebind:
//!   `Changed`, nothing written.
//! - RB-T7 stacking: a rebound transaction left open blocks applies on its objects in the new
//!   folder; a later transaction in the new folder makes the rebind `Later` until reverted.
//! - RB-T8 tampering: rebinds that do not fit the head are `Blocked` for revert, verify and
//!   stacking; a planted directory proof on a foreign empty folder removes it (rest risk,
//!   `docs/06-security.md` row 14).
//! - RB-T9 resuming: a crash after the record, a revert without the rebind closes; the rebind
//!   again is a plain revert; a second move rebinds again (a chain).
//! - Controls: K-RB1 the head's roots rewritten with the binding (senior-dev B2) fails RB-T3;
//!   K-RB2 a created folder proven by `Done.file_id` only fails RB-T1; K-RB3 the objects of a
//!   rebound transaction from the head only fails RB-T7.

use std::path::Path;

use super::layer_tests::{layer_base, two_tokens};
use super::reg_tests::{SUB, plan_for};
use super::tests::{Env, NEW, OLD, RH, acf, closed, finish, manifest, snap_app, snap_at};
use super::{
    ApplyError, ExecError, Outcome, RebindPreview, RebindRefusal, RebindTo, Refusal, RevertReport,
};
use crate::journal::{Closing, DirProof, InstanceTag, Journal, Observed, TxnId, TxnState};
use crate::path::RootPath;
use crate::plan::{self, PlanHash, store};
use crate::policy::root::{RootError, StoreDir};
use crate::prim::Step;
use crate::prim::ini_tests::{INI, INI_TEXT, three};
use crate::prim::reg_tests::{dword, hkcu, step};
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app, entry, fr, rel, spec};
use crate::sys::fake::{FakeSystem, Prim};
use crate::sys::fs::EntryKind;
use crate::sys::snapshot::{Scope, Snapshot, snapshot};
use crate::sys::{Fs, SysErrorKind, System};

/// The library the tests move to, on another volume.
pub(crate) const LIB_E: &str = r"E:\SteamLibrary";
/// The game folder there.
pub(crate) const GAME_E: &str = r"E:\SteamLibrary\steamapps\common\G";
/// A copy of the game folder as it was before the apply (the reference of "identical").
pub(crate) const REF: &str = r"D:\Ref\G";

/// The registry keys `layer_base` sets up, the Steam library with app 220 in `G` (`game.exe`, a
/// read-only, hidden `d3d9.dll`, an INI file).
pub(crate) fn rb_sys() -> FakeSystem {
    let sys = finish(
        layer_base()
            .value(
                crate::detect::steam::RootSource::CurrentUser.key(),
                crate::detect::steam::RootSource::CurrentUser.value_name(),
                crate::sys::registry::RegValue::String(STEAM.to_owned()),
            )
            .file(LIB_FILE, lib_vdf(&[STEAM_LIB]).into_bytes())
            .file(manifest(220), acf(220, 4).into_bytes())
            .file(format!(r"{STEAM_GAME}\game.exe"), b"MZ".to_vec())
            .file(format!(r"{STEAM_GAME}\d3d9.dll"), OLD.to_vec())
            .file(format!(r"{STEAM_GAME}\{INI}"), INI_TEXT.to_vec()),
    );
    let fx = sys.fake_fs();
    fx.set_attrs(Path::new(&format!(r"{STEAM_GAME}\d3d9.dll")), RH)
        .unwrap();
    fx.sync_all();
    sys
}

/// The Steam folder (library 0, holding no app).
pub(crate) const STEAM: &str = r"C:\Program Files (x86)\Steam";
/// Its library list.
pub(crate) const LIB_FILE: &str = r"C:\Program Files (x86)\Steam\steamapps\libraryfolders.vdf";

/// `libraryfolders.vdf` listing the Steam folder and `libs`.
pub(crate) fn lib_vdf(libs: &[&str]) -> String {
    let mut out = String::from("\"libraryfolders\"\n{\n");
    for (i, p) in std::iter::once(STEAM)
        .chain(libs.iter().copied())
        .enumerate()
    {
        out.push_str(&format!(
            "\t\"{i}\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n",
            p.replace('\\', r"\\")
        ));
    }
    out.push_str("}\n");
    out
}

/// Steam's library list set to `libs` (as Steam rewrites it when libraries move).
pub(crate) fn set_libs(sys: &FakeSystem, libs: &[&str]) {
    let fx = sys.fake_fs();
    fx.remove_abs(Path::new(LIB_FILE)).unwrap();
    fx.put_file(Path::new(LIB_FILE), lib_vdf(libs).as_bytes())
        .unwrap();
    sys.sync_all();
}

/// Moves the library `from` to `to` and lists `to` instead of `from` (Steam's "move library").
pub(crate) fn move_lib(sys: &FakeSystem, from: &str, to: &str) {
    move_tree(sys, from, to);
    set_libs(sys, &[to]);
}

/// The steps of every rebind test: a replace over a read-only, hidden target, two nested
/// created folders with a file, a new file (T1), a compatibility layer for `game.exe` (two
/// shared keys and a `TokenList`), a registry value in three new keys; with `ini`, an INI edit.
pub(crate) fn rb_steps(ini: bool) -> Vec<Step> {
    let mut v = vec![
        Step::FileInstall(super::tests::t1_spec()),
        two_tokens(),
        step(&format!(r"HKCU\{SUB}"), vec![dword("A", 1)]),
    ];
    if ini {
        v.push(three());
    }
    v
}

/// Plans `steps` for the Steam root of app 220 in [`STEAM_LIB`] and stores the plan.
pub(crate) fn rb_plan(env: &Env, steps: &[Step]) -> PlanHash {
    let fr = fr(&env.sys);
    let store = StoreDir::open(&env.sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    plan_for(env, &g, Some(220), steps)
}

/// `HKCU\Software` as a snapshot.
pub(crate) fn keys(sys: &FakeSystem) -> Snapshot {
    snapshot(
        sys.registry(),
        &Scope {
            dirs: Vec::new(),
            keys: vec![hkcu("Software")],
        },
    )
    .unwrap()
}

/// The differences between two folders by content (names, case, lengths, hashes, R/H/S,
/// links), whatever their identity.
pub(crate) fn content_diff(sys: &FakeSystem, a: &str, b: &str) -> Vec<String> {
    snap_at(sys, a)
        .diff(&snap_at(sys, b))
        .into_iter()
        .filter(|l| !l.starts_with("~ root "))
        .collect()
}

/// Copies the tree `from` to `to` (as Steam copies a library to another volume: new file IDs,
/// the same names, contents and R/H/S).
#[expect(clippy::disallowed_methods, reason = "test: copy a fixture tree")]
pub(crate) fn copy_tree(sys: &FakeSystem, from: &str, to: &str) {
    let fx = sys.fake_fs();
    fx.mkdir_all(Path::new(to)).unwrap();
    let d = fx.open_dir(Path::new(from)).unwrap();
    for e in d.read_dir(None).unwrap() {
        let (src, dst) = (format!(r"{from}\{}", e.name), format!(r"{to}\{}", e.name));
        let name = rel(&e.name);
        let m = d.metadata(&name).unwrap().unwrap();
        match m.kind {
            EntryKind::Dir => copy_tree(sys, &src, &dst),
            EntryKind::File => {
                fx.put_file(Path::new(&dst), &d.read(&name).unwrap())
                    .unwrap();
                fx.set_attrs(Path::new(&dst), m.attrs).unwrap();
            }
            other => panic!("{src}: {other:?}"),
        }
    }
}

/// Removes the tree `abs`.
#[expect(clippy::disallowed_methods, reason = "test: remove a fixture tree")]
pub(crate) fn remove_tree(sys: &FakeSystem, abs: &str) {
    let fx = sys.fake_fs();
    let names: Vec<(String, EntryKind)> = {
        let d = fx.open_dir(Path::new(abs)).unwrap();
        d.read_dir(None)
            .unwrap()
            .into_iter()
            .map(|e| {
                let k = d.metadata(&rel(&e.name)).unwrap().unwrap().kind;
                (e.name, k)
            })
            .collect()
    };
    for (n, k) in names {
        let p = format!(r"{abs}\{n}");
        if k == EntryKind::Dir {
            remove_tree(sys, &p);
        } else {
            fx.remove_abs(Path::new(&p)).unwrap();
        }
    }
    fx.remove_abs(Path::new(abs)).unwrap();
}

/// Moves the tree `from` to `to` on another volume (copy, then remove).
pub(crate) fn move_tree(sys: &FakeSystem, from: &str, to: &str) {
    copy_tree(sys, from, to);
    remove_tree(sys, from);
    sys.sync_all();
}

/// Moves the file `from` to `to` on another volume.
pub(crate) fn move_file(sys: &FakeSystem, from: &str, to: &str) {
    let data = super::tests::read_abs(sys, from);
    super::tests::sys_put(sys, to, &data);
    sys.fake_fs().remove_abs(Path::new(from)).unwrap();
    sys.sync_all();
}

/// The indices of the file ops of the head of `t`.
fn file_ops_of(env: &Env, t: &TxnId) -> Vec<u16> {
    let a = app(&env.sys);
    let v = Journal::new(&a, InstanceTag::fixed(6))
        .load(t, crate::journal::VerifyBackups::Length)
        .unwrap();
    let p = plan::decode_recorded(v.head.as_deref().unwrap()).unwrap();
    super::bind::file_ops(&p, 0).collect()
}

/// One applied rebind scenario: the system, the transaction, `HKCU\Software` before the apply
/// (and [`REF`], the game folder before the apply).
pub(crate) struct Rb {
    pub(crate) env: Env,
    pub(crate) t: TxnId,
    pub(crate) keys: Snapshot,
}

/// Applies [`rb_steps`] on [`rb_sys`] after copying the game folder to [`REF`].
pub(crate) fn applied(ini: bool) -> Rb {
    let env = Env::new(rb_sys());
    copy_tree(&env.sys, STEAM_GAME, REF);
    env.sys.sync_all();
    let keys = keys(&env.sys);
    let t = env.applied(&rb_plan(&env, &rb_steps(ini)));
    Rb { env, t, keys }
}

/// The root path of `s`.
pub(crate) fn rp(s: &str) -> RootPath {
    RootPath::new(s).unwrap()
}

impl Env {
    pub(crate) fn rebind_check(&self, t: &TxnId) -> Result<RebindPreview, Refusal> {
        self.with(|cx| super::rebind_check(cx, t))
    }

    pub(crate) fn revert_rebound(
        &self,
        t: &TxnId,
        to: &RebindTo,
    ) -> Result<RevertReport, ExecError> {
        self.with(|cx| super::revert_rebound(cx, t, to))
    }

    /// `revert_rebound` with `arm` run on the fake right before it.
    pub(crate) fn revert_rebound_armed(
        &self,
        t: &TxnId,
        to: &RebindTo,
        arm: impl FnOnce(&crate::sys::fake::FakeFs),
    ) -> Result<RevertReport, ExecError> {
        self.with(|cx| {
            let fx = self.sys.fake_fs();
            fx.clear_faults();
            arm(fx);
            super::revert_rebound(cx, t, to)
        })
    }

    /// The records of `t`.
    pub(crate) fn records(&self, t: &TxnId) -> usize {
        let a = app(&self.sys);
        Journal::new(&a, InstanceTag::fixed(5))
            .load(t, crate::journal::VerifyBackups::Length)
            .map_or(0, |v| v.log.len())
    }
}

/// `r` is the refusal `want`.
fn refused(r: &Result<RebindPreview, Refusal>, want: impl Fn(&RebindRefusal) -> bool) -> bool {
    matches!(r, Err(Refusal::Rebind(x)) if want(x))
}

/// The created folders of the plan of `t` (by op).
fn created_dirs(env: &Env, t: &TxnId) -> Vec<u16> {
    let a = app(&env.sys);
    let v = Journal::new(&a, InstanceTag::fixed(6))
        .load(t, crate::journal::VerifyBackups::Length)
        .unwrap();
    let p = plan::decode_recorded(v.head.as_deref().unwrap()).unwrap();
    p.ops
        .iter()
        .enumerate()
        .filter(|(_, o)| matches!(o, plan::Op::CreateDir { .. }))
        .map(|(k, _)| u16::try_from(k).unwrap())
        .collect()
}

/// RB-T1 as a check (module docs).
pub(crate) fn rb_t1_check() -> Vec<String> {
    let mut f = Vec::new();
    let Rb { env, t, keys: k0 } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    // The revert without a rebind: the registry ops reverted, a halt at the newest file op.
    match env.revert(&t) {
        Ok(r) if r.closed.is_none() && r.halted.is_some() && !r.ops.is_empty() => {}
        r => f.push(format!("RB-T1 halt: {r:?}")),
    }
    if keys(&env.sys) != k0 {
        f.push(format!(
            "RB-T1 registry after the halt: {:#?}",
            k0.diff(&keys(&env.sys))
        ));
    }
    let n = env.records(&t);
    let app_before = snap_app(&env.sys);
    let p = match env.rebind_check(&t) {
        Ok(p) => p,
        Err(e) => {
            f.push(format!("RB-T1 rebind_check: {e:?}"));
            return f;
        }
    };
    if snap_app(&env.sys) != app_before || env.records(&t) != n {
        f.push("RB-T1 rebind_check wrote something".to_owned());
    }
    if p.to.from.path != rp(STEAM_GAME) || p.to.from.store != rp(STEAM_LIB) || p.path != rp(GAME_E)
    {
        f.push(format!("RB-T1 old and new folder: {p:?}"));
    }
    if p.to.store != rp(LIB_E) || p.to.id == p.to.from.id {
        f.push(format!("RB-T1 binding: {:?}", p.to));
    }
    let not_found = |r: &Refusal| matches!(r, Refusal::Root(e) if matches!(&**e, RootError::Sys(s) if s.kind == SysErrorKind::NotFound));
    if !not_found(&p.why) {
        f.push(format!("RB-T1 why: {:?}", p.why));
    }
    let dirs: Vec<u16> = p.to.dirs.iter().map(|d| d.op).collect();
    if dirs != created_dirs(&env, &t) {
        f.push(format!("RB-T1 created folders: {:?}", p.to.dirs));
    }
    if p.verified.halted.is_some()
        || p.verified
            .ops
            .iter()
            .any(|(_, o)| !matches!(o, Observed::After | Observed::Before))
    {
        f.push(format!("RB-T1 verified: {:?}", p.verified));
    }
    match env.revert_rebound(&t, &p.to) {
        Ok(r) if r.closed == Some(Closing::Reverted) => {}
        r => f.push(format!("RB-T1 revert_rebound: {r:?}")),
    }
    let d = content_diff(&env.sys, REF, GAME_E);
    if !d.is_empty() {
        f.push(format!("RB-T1 folder: {d:#?}"));
    }
    if keys(&env.sys) != k0 {
        f.push(format!("RB-T1 registry: {:#?}", k0.diff(&keys(&env.sys))));
    }
    // After the close: a binding to a closed transaction is refused.
    if env.rebind_check(&t).is_ok() {
        f.push("RB-T1 rebind_check after the close".to_owned());
    }
    f
}

#[test]
fn rb_t1_a_moved_library_is_rebound_and_reverted_exactly() {
    let f = rb_t1_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-RB2: a created folder of a rebound root proven by `Done.file_id` only (a copy has new
/// IDs): RB-T1 finds the folders `Foreign` and refuses the rebind.
#[test]
fn k_rb2_proving_created_folders_by_done_only_breaks_rb_t1() {
    super::knob::dir_proof_from_done(true);
    let f = rb_t1_check();
    super::knob::dir_proof_from_done(false);
    assert!(
        f.iter().any(|x| x.starts_with("RB-T1 rebind_check")),
        "K-RB2 not caught: {f:#?}"
    );
}

#[test]
fn rb_t2_a_reinstall_at_the_same_path_is_rebound_with_every_file_op_before() {
    let Rb { env, t, keys: k0 } = applied(false);
    remove_tree(&env.sys, STEAM_GAME);
    copy_tree(&env.sys, REF, STEAM_GAME);
    env.sys.sync_all();
    let n = env.records(&t);
    // Without a rebind: refused before any change (E3), the registry ops too.
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Root(e))) if matches!(**e, RootError::IdentityMismatch { .. })),
        "{r:?}"
    );
    assert_eq!(env.records(&t), n);
    let p = env.rebind_check(&t).unwrap();
    assert!(
        matches!(&*p.why, Refusal::Root(e) if matches!(**e, RootError::IdentityMismatch { .. })),
        "{:?}",
        p.why
    );
    assert_eq!(
        (p.to.store.clone(), p.path.clone()),
        (rp(STEAM_LIB), rp(STEAM_GAME))
    );
    assert!(p.to.dirs.is_empty(), "nothing created there: {:?}", p.to);
    let files = file_ops_of(&env, &t);
    assert_eq!(files.len(), 5);
    assert!(
        p.verified
            .ops
            .iter()
            .filter(|(k, _)| files.contains(k))
            .all(|(_, o)| *o == Observed::Before),
        "{p:?}"
    );
    let r = env.revert_rebound(&t, &p.to).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert_eq!(
        content_diff(&env.sys, REF, STEAM_GAME),
        Vec::<String>::new()
    );
    assert!(keys(&env.sys) == k0, "{:#?}", k0.diff(&keys(&env.sys)));
}

/// RB-T3 as a check (module docs).
pub(crate) fn rb_t3_check() -> Vec<String> {
    let mut f = Vec::new();
    let Rb { env, t, keys: k0 } = applied(false);
    // The app moved: its folder and manifest to `E:`, the library at `D:` stays.
    move_tree(
        &env.sys,
        STEAM_GAME,
        &format!(r"{LIB_E}\steamapps\common\G"),
    );
    move_file(
        &env.sys,
        &manifest(220),
        &format!(r"{LIB_E}\steamapps\appmanifest_220.acf"),
    );
    set_libs(&env.sys, &[STEAM_LIB, LIB_E]);
    let p = match env.rebind_check(&t) {
        Ok(p) => p,
        Err(e) => {
            f.push(format!("RB-T3 rebind_check: {e:?}"));
            return f;
        }
    };
    if !matches!(
        &*p.why,
        Refusal::SteamGone {
            gone: super::SteamGone::NoManifest,
            ..
        }
    ) {
        f.push(format!("RB-T3 why: {:?}", p.why));
    }
    match env.revert_rebound(&t, &p.to) {
        Ok(r) if r.closed == Some(Closing::Reverted) => {}
        r => f.push(format!("RB-T3 revert_rebound: {r:?}")),
    }
    let d = content_diff(&env.sys, REF, GAME_E);
    if !d.is_empty() {
        f.push(format!("RB-T3 folder: {d:#?}"));
    }
    // E-R4 a: the `Layers` value under the old path is the one Rerun wrote; it is restored, and
    // none appears under the new path.
    if keys(&env.sys) != k0 {
        f.push(format!("RB-T3 registry: {:#?}", k0.diff(&keys(&env.sys))));
    }
    f
}

#[test]
fn rb_t3_an_app_moved_to_another_library_is_rebound_with_the_registry_of_the_head() {
    let f = rb_t3_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-RB1 (senior-dev B2): the head's roots rewritten with the binding before the revert loop;
/// the `Layers` value is then looked up under the new path, Rerun's tokens stay in the old one.
#[test]
fn k_rb1_rewriting_the_head_breaks_rb_t3() {
    super::knob::rewrite_head(true);
    let f = rb_t3_check();
    super::knob::rewrite_head(false);
    assert!(
        f.iter().any(|x| x.starts_with("RB-T3 registry")),
        "K-RB1 not caught: {f:#?}"
    );
    // The revert itself closes: only the registry location is wrong (review nit).
    assert!(
        !f.iter().any(|x| x.starts_with("RB-T3 revert_rebound")),
        "{f:#?}"
    );
}

#[test]
fn rb_t4_an_ini_file_the_game_rewrote_in_the_new_folder_is_drifted_and_reverted_semantically() {
    let Rb { env, t, keys: k0 } = applied(true);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    // The game ran in the new folder and rewrote another key.
    let ini = format!(r"{GAME_E}\{INI}");
    let now = super::tests::read_abs(&env.sys, &ini);
    let rewritten = String::from_utf8(now)
        .unwrap()
        .replace("Height = 720", "Height = 1080");
    env.sys.fake_fs().remove_abs(Path::new(&ini)).unwrap();
    super::tests::sys_put(&env.sys, &ini, rewritten.as_bytes());
    let p = env.rebind_check(&t).unwrap();
    assert!(
        p.verified.ops.iter().any(|(_, o)| *o == Observed::Drifted),
        "{:?}",
        p.verified
    );
    let r = env.revert_rebound(&t, &p.to).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    let want = String::from_utf8(INI_TEXT.to_vec())
        .unwrap()
        .replace("Height = 720", "Height = 1080");
    assert_eq!(
        String::from_utf8(super::tests::read_abs(&env.sys, &ini)).unwrap(),
        want
    );
    assert!(keys(&env.sys) == k0, "{:#?}", k0.diff(&keys(&env.sys)));
}

/// A scenario of RB-T5: a change after the apply, the refusal (the Steam scan finds the
/// library, E-R1).
type Case = (
    &'static str,
    fn(&Rb),
    fn(&Result<RebindPreview, Refusal>) -> bool,
);

#[test]
fn rb_t5_every_refusal_writes_nothing() {
    let cases: Vec<Case> = vec![
        (
            "not needed",
            |_| {},
            |r| refused(r, |x| matches!(x, RebindRefusal::NotNeeded)),
        ),
        (
            "undecided: an update pending at the old library",
            |rb| {
                let fx = rb.env.sys.fake_fs();
                fx.remove_abs(Path::new(&manifest(220))).unwrap();
                super::tests::sys_put(&rb.env.sys, &manifest(220), acf(220, 6).as_bytes());
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::Undecided(_))),
        ),
        (
            "undecided: installed in another folder of the old library",
            |rb| {
                let fx = rb.env.sys.fake_fs();
                fx.remove_abs(Path::new(&manifest(220))).unwrap();
                let other =
                    acf(220, 4).replace("\"installdir\"\t\t\"G\"", "\"installdir\"\t\t\"G2\"");
                super::tests::sys_put(&rb.env.sys, &manifest(220), other.as_bytes());
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::Undecided(_))),
        ),
        (
            "no candidate: the app in no library",
            |rb| {
                rb.env
                    .sys
                    .fake_fs()
                    .remove_abs(Path::new(&manifest(220)))
                    .unwrap();
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::NoCandidate)),
        ),
        (
            "no candidate: no manifest there",
            |rb| {
                move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
                rb.env
                    .sys
                    .fake_fs()
                    .remove_abs(Path::new(&format!(
                        r"{LIB_E}\steamapps\appmanifest_220.acf"
                    )))
                    .unwrap();
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::NoCandidate)),
        ),
        (
            "update pending there",
            |rb| {
                move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
                let m = format!(r"{LIB_E}\steamapps\appmanifest_220.acf");
                rb.env.sys.fake_fs().remove_abs(Path::new(&m)).unwrap();
                super::tests::sys_put(&rb.env.sys, &m, acf(220, 6).as_bytes());
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::UpdatePending)),
        ),
        (
            "another install folder there",
            |rb| {
                move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
                let m = format!(r"{LIB_E}\steamapps\appmanifest_220.acf");
                rb.env.sys.fake_fs().remove_abs(Path::new(&m)).unwrap();
                let other =
                    acf(220, 4).replace("\"installdir\"\t\t\"G\"", "\"installdir\"\t\t\"G2\"");
                super::tests::sys_put(&rb.env.sys, &m, other.as_bytes());
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::OtherInstallDir)),
        ),
        (
            "a junction at the game folder there",
            |rb| {
                move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
                rb.env.sys.swap_with_junction(GAME_E, r"C:\x").unwrap();
            },
            |r| {
                refused(r, |x| {
                    matches!(x, RebindRefusal::Candidate(e)
                    if matches!(&**e, Refusal::Root(e) if matches!(**e, RootError::Reparse { .. })))
                })
            },
        ),
        (
            "not writable there",
            |rb| {
                move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
                rb.env
                    .sys
                    .fake_fs()
                    .set_user_writable(Path::new(GAME_E), false)
                    .unwrap();
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::NotWritable)),
        ),
        (
            "a file changed there",
            |rb| {
                moved_change(rb, "new.dll", b"changed by someone");
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::Foreign { .. })),
        ),
        (
            "a foreign file in a created folder there",
            |rb| {
                move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
                super::tests::sys_put(&rb.env.sys, &format!(r"{GAME_E}\mods\a\mine.txt"), b"x");
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::Foreign { .. })),
        ),
        (
            "the main executable missing there",
            |rb| {
                move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
                rb.env
                    .sys
                    .fake_fs()
                    .remove_abs(Path::new(&format!(r"{GAME_E}\game.exe")))
                    .unwrap();
            },
            |r| matches!(r, Err(Refusal::MainExe(_))),
        ),
        (
            "a library in a forbidden folder",
            |rb| move_lib(&rb.env.sys, STEAM_LIB, FORBIDDEN_LIB),
            |r| refused(r, |x| matches!(x, RebindRefusal::LibraryUnreadable(_))),
        ),
        (
            "an unreadable manifest there",
            |rb| {
                move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
                garbage_manifest(rb);
            },
            |r| refused(r, |x| matches!(x, RebindRefusal::LibraryUnreadable(_))),
        ),
    ];
    for (what, change, want) in cases {
        let rb = applied(false);
        change(&rb);
        rb.env.sys.sync_all();
        let before = snap_app(&rb.env.sys);
        let r = rb.env.rebind_check(&rb.t);
        assert!(want(&r), "{what}: {r:?}");
        assert!(
            snap_app(&rb.env.sys) == before,
            "{what}: rebind_check wrote"
        );
    }
}

/// Moves the library and changes `name` in the new folder.
fn moved_change(rb: &Rb, name: &str, data: &[u8]) {
    move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
    let p = format!(r"{GAME_E}\{name}");
    rb.env.sys.fake_fs().remove_abs(Path::new(&p)).unwrap();
    super::tests::sys_put(&rb.env.sys, &p, data);
}

#[test]
fn rb_t5_refusals_of_the_transaction_itself() {
    // A manual root: never rebound.
    let env = Env::new(rb_sys());
    let t = env.applied(&env.plan(&spec(vec![entry("new.dll", "new.dll", super::tests::N)])));
    env.sys
        .rename_abs(crate::prim::tests::GAME, r"D:\Games\Away")
        .unwrap();
    let r = env.rebind_check(&t);
    assert!(refused(&r, |x| matches!(x, RebindRefusal::Manual)), "{r:?}");
    // An interrupted apply: not applied.
    let env = Env::new(rb_sys());
    let open = super::tests::interrupted(
        &env,
        &spec(vec![entry(r"mods\x.dll", r"mods\x.dll", super::tests::X)]),
    );
    let r = env.rebind_check(&open);
    assert!(
        refused(&r, |x| matches!(x, RebindRefusal::NotApplied)),
        "{r:?}"
    );
    // A revert of a file op of that root has begun (E-R3).
    let Rb { env, t, .. } = applied(false);
    let r = env.revert_armed(&t, |fx| {
        fx.fail_at(Prim::PosixDelete, 1, SysErrorKind::Other);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().clear_faults();
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let r = env.rebind_check(&t);
    assert!(
        refused(&r, |x| matches!(x, RebindRefusal::RevertPending { .. })),
        "{r:?}"
    );
    // D4 in the new folder: the game runs there.
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let hold = env
        .sys
        .fake_fs()
        .hold_open_as(
            4242,
            Path::new(&format!(r"{GAME_E}\game.exe")),
            crate::sys::contract::Access::READ,
            crate::sys::contract::Share::RWD,
        )
        .unwrap();
    let r = env.rebind_check(&t);
    assert!(matches!(r, Err(Refusal::Busy(_))), "{r:?}");
    drop(hold);
    assert!(env.rebind_check(&t).is_ok());
    // More than one folder gone: a plan over the Steam root and a manual root.
    const H: &str = r"D:\Games\H";
    let env = Env::new(rb_sys());
    env.sys.fake_fs().mkdir_all(Path::new(H)).unwrap();
    super::tests::sys_put(&env.sys, &format!(r"{H}\game.exe"), b"MZ");
    let a = app(&env.sys);
    let mut p = plan::decode(
        plan::load(&a, &rb_plan(&env, &rb_steps(false)))
            .unwrap()
            .bytes(),
    )
    .unwrap();
    let other = {
        let fr = fr(&env.sys);
        let dir = crate::policy::root::GameDir::open_manual(&env.sys, &fr, Path::new(H)).unwrap();
        plan::decode(
            plan::load(
                &a,
                &env.plan_for(
                    &dir,
                    None,
                    &spec(vec![entry("new.dll", "new.dll", super::tests::N)]),
                ),
            )
            .unwrap()
            .bytes(),
        )
        .unwrap()
    };
    p.roots.push(other.roots[0].clone());
    let h = store(&a, &p.encode().unwrap()).unwrap();
    let t = env.applied(&h);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    env.sys.rename_abs(H, r"D:\Games\Away").unwrap();
    let r = env.rebind_check(&t);
    assert!(
        refused(&r, |x| matches!(x, RebindRefusal::MoreThanOne)),
        "{r:?}"
    );
}

#[test]
fn rb_t6_a_folder_changed_since_the_preview_is_refused_before_the_record() {
    // The game folder there replaced by another copy (another identity).
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let p = env.rebind_check(&t).unwrap();
    move_tree(&env.sys, GAME_E, r"E:\Tmp\G");
    move_tree(&env.sys, r"E:\Tmp\G", GAME_E);
    let n = env.records(&t);
    let r = env.revert_rebound(&t, &p.to);
    assert!(
        matches!(
            &r,
            Err(ExecError::Refused(Refusal::Rebind(RebindRefusal::Changed)))
        ),
        "{r:?}"
    );
    assert_eq!(env.records(&t), n);
    // Checked again, it binds the copy now.
    let p2 = env.rebind_check(&t).unwrap();
    assert_ne!(p2.to, p.to);
    // A created folder replaced (another file ID) since the preview.
    let mods = format!(r"{GAME_E}\mods");
    move_tree(&env.sys, &mods, r"E:\Tmp\mods");
    move_tree(&env.sys, r"E:\Tmp\mods", &mods);
    let r = env.revert_rebound(&t, &p2.to);
    assert!(
        matches!(
            &r,
            Err(ExecError::Refused(Refusal::Rebind(RebindRefusal::Changed)))
        ),
        "{r:?}"
    );
    assert_eq!(env.records(&t), n);
    let p3 = env.rebind_check(&t).unwrap();
    assert_eq!(
        closed(&env.revert_rebound(&t, &p3.to)),
        Some(Closing::Reverted)
    );
}

/// RB-T7 as a check (module docs).
pub(crate) fn rb_t7_check() -> Vec<String> {
    let mut f = Vec::new();
    // A rebound transaction left open (the crash right after its record): an apply on its
    // objects in the new folder is refused, beside them it goes on.
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let p = env.rebind_check(&t).unwrap();
    let r = env.revert_rebound_armed(&t, &p.to, |fx| {
        fx.fault(Prim::FlushDir, 1, crate::sys::fake::Fault::CrashAfter);
    });
    if r.is_ok() {
        f.push(format!("RB-T7 crash: {r:?}"));
    }
    env.sys.fake_fs().restart();
    let plan_e = |steps: Vec<crate::prim::FileEntry>| {
        let fr = fr(&env.sys);
        let st = StoreDir::open(&env.sys, &fr, Path::new(LIB_E)).unwrap();
        let g = st.game(&fr, "G").unwrap();
        env.plan_for(&g, Some(220), &spec(steps))
    };
    super::tests::sys_put(&env.sys, &super::tests::pkg("y.dll"), b"y of the package");
    let on_it = plan_e(vec![entry("y.dll", r"mods\a\y.dll", b"y of the package")]);
    match env.apply(&on_it) {
        Err(ApplyError::Refused(Refusal::Interrupted { txn })) if txn == t => {}
        r => f.push(format!("RB-T7 apply on its objects: {r:?}")),
    }
    let beside = plan_e(vec![entry("y.dll", "beside.dll", b"y of the package")]);
    let t2 = match env.apply(&beside) {
        Ok(Outcome::Applied(t2)) => Some(t2),
        r => {
            f.push(format!("RB-T7 apply beside: {r:?}"));
            None
        }
    };
    if let Some(t2) = t2 {
        let _ = env.revert(&t2);
    }
    if closed(&env.revert(&t)) != Some(Closing::Reverted) {
        f.push("RB-T7 resumed".to_owned());
    }
    // A later transaction in the new folder (before the rebind): the rebind is `Later` until
    // it is reverted (E-R6).
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let fr = fr(&env.sys);
    let st = StoreDir::open(&env.sys, &fr, Path::new(LIB_E)).unwrap();
    let g = st.game(&fr, "G").unwrap();
    let later = env.plan_for(
        &g,
        Some(220),
        &spec(vec![entry("d3d9.dll", "new.dll", NEW)]),
    );
    drop(g);
    drop(st);
    let t2 = env.applied(&later);
    match env.rebind_check(&t) {
        Err(Refusal::Later { txn }) if txn == t2 => {}
        r => f.push(format!("RB-T7 later: {r:?}")),
    }
    if closed(&env.revert(&t2)) != Some(Closing::Reverted) {
        f.push("RB-T7 later reverted".to_owned());
    }
    match env.rebind_check(&t) {
        Ok(p) => {
            if closed(&env.revert_rebound(&t, &p.to)) != Some(Closing::Reverted) {
                f.push("RB-T7 rebound after the later one".to_owned());
            }
        }
        r => f.push(format!("RB-T7 after the later one: {r:?}")),
    }
    f
}

#[test]
fn rb_t7_stacking_sees_a_rebound_transaction_at_its_new_folder() {
    let f = rb_t7_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-RB3: the objects of a rebound transaction from the head only: RB-T7's apply on its
/// objects in the new folder goes through.
#[test]
fn k_rb3_objects_from_the_head_only_break_rb_t7() {
    super::knob::objects_from_head(true);
    let f = rb_t7_check();
    super::knob::objects_from_head(false);
    assert!(
        f.iter()
            .any(|x| x.starts_with("RB-T7 apply on its objects")),
        "K-RB3 not caught: {f:#?}"
    );
}

/// A `Rebind` record to plant (Rerun's writer checks only the grammar; `exec` the fit to the
/// head).
struct Planted {
    root: u16,
    old: crate::policy::root::RootId,
    store: RootPath,
    store_id: crate::policy::root::RootId,
    id: crate::policy::root::RootId,
    dirs: Vec<DirProof>,
}

/// The head of `t`.
fn head_of(env: &Env, t: &TxnId) -> plan::Plan {
    let a = app(&env.sys);
    let v = Journal::new(&a, InstanceTag::fixed(8))
        .load(t, crate::journal::VerifyBackups::Length)
        .unwrap();
    plan::decode_recorded(v.head.as_deref().unwrap()).unwrap()
}

/// A well-formed rebind of root 0 of `t` (the chain right) into [`LIB_E`] with made-up
/// identities.
fn planted(env: &Env, t: &TxnId) -> Planted {
    let rid = |f| crate::policy::root::RootId {
        volume_serial: 0x5EED_0045,
        file_id: f,
    };
    Planted {
        root: 0,
        old: head_of(env, t).roots[0].id,
        store: rp(LIB_E),
        store_id: rid(1),
        id: rid(2),
        dirs: Vec::new(),
    }
}

/// Writes `p` into `t` with the journal writer, under the lock.
fn plant(env: &Env, t: &TxnId, p: &Planted) {
    let a = app(&env.sys);
    let j = Journal::new(&a, InstanceTag::fixed(0x77));
    let lock = j.lock().unwrap();
    let mut w = lock.resume(t).unwrap();
    w.rebind(&crate::journal::RebindArgs {
        root: p.root,
        old: p.old,
        store: &p.store,
        store_id: p.store_id,
        id: p.id,
        dirs: &p.dirs,
    })
    .unwrap();
}

/// `revert`, `verify` and an apply elsewhere are `Blocked` by `t`.
fn blocked_everywhere(env: &Env, t: &TxnId) -> Vec<String> {
    let mut f = Vec::new();
    let r = env.revert(t);
    if !matches!(&r, Err(ExecError::Refused(Refusal::Blocked { txn })) if txn == t) {
        f.push(format!("revert {r:?}"));
    }
    let v = env.verified(t);
    if !matches!(&v, Err(ExecError::Refused(Refusal::Blocked { .. }))) {
        f.push(format!("verify {v:?}"));
    }
    let other = env.plan(&spec(vec![entry(
        "new.dll",
        "elsewhere.dll",
        super::tests::N,
    )]));
    let r = env.apply(&other);
    if !matches!(&r, Err(ApplyError::Refused(Refusal::Blocked { txn })) if txn == t) {
        f.push(format!("stacking {r:?}"));
    }
    f
}

#[test]
fn rb_t8_rebinds_that_do_not_fit_the_head_are_blocked() {
    type Tamper = fn(&Env, &TxnId, &mut Planted);
    let cases: [(&str, Tamper); 4] = [
        ("root index outside the head", |_, _, p| p.root = 3),
        ("old is not the bound identity", |_, _, p| {
            p.old.file_id ^= 1
        }),
        ("a directory proof for a file op", |_, _, p| {
            // Op 0 is the replace of `d3d9.dll`.
            p.dirs = vec![DirProof { op: 0, file_id: 9 }];
        }),
        ("nothing changes: the head's own binding", |env, t, p| {
            let h = head_of(env, t);
            let plan::PlanOrigin::Steam {
                store, store_id, ..
            } = &h.roots[0].origin
            else {
                panic!("a Steam root");
            };
            p.store = store.clone();
            p.store_id = *store_id;
            p.id = h.roots[0].id;
        }),
    ];
    for (what, tamper) in cases {
        let Rb { env, t, .. } = applied(false);
        let mut p = planted(&env, &t);
        tamper(&env, &t, &mut p);
        plant(&env, &t, &p);
        let f = blocked_everywhere(&env, &t);
        assert!(f.is_empty(), "{what}: {f:#?}");
    }
    // A well-formed rebind of a manual root: never rebound.
    let env = Env::new(rb_sys());
    let t = env.applied(&env.plan(&spec(vec![entry("new.dll", "new.dll", super::tests::N)])));
    let p = planted(&env, &t);
    plant(&env, &t, &p);
    let f = blocked_everywhere(&env, &t);
    assert!(f.is_empty(), "manual: {f:#?}");
    // A rebind after a revert intent of a file op of its root (E-R3).
    let Rb { env, t, .. } = applied(false);
    let r = env.revert_armed(&t, |fx| {
        fx.fail_at(Prim::PosixDelete, 1, SysErrorKind::Other);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().clear_faults();
    let p = planted(&env, &t);
    plant(&env, &t, &p);
    let f = blocked_everywhere(&env, &t);
    assert!(f.is_empty(), "after a revert intent: {f:#?}");
    // The same rebind that fits is not blocked (the control of the cases above).
    let Rb { env, t, .. } = applied(false);
    let p = planted(&env, &t);
    plant(&env, &t, &p);
    let r = env.revert(&t);
    assert!(
        !matches!(&r, Err(ExecError::Refused(Refusal::Blocked { .. }))),
        "{r:?}"
    );
}

/// The rest risk of `docs/06-security.md` row 14, pinned: a planted rebind into a library the
/// user can write whose directory proofs name foreign empty folders of the planned names there.
/// The revert removes them (empty folders, by their file IDs; the same user could remove them
/// directly), and writes nothing else of the plan there.
#[test]
fn rb_t8_a_planted_proof_on_a_foreign_empty_folder_removes_it() {
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    // Someone else's empty folders of the planned names, nothing else of the plan there.
    remove_tree(&env.sys, &format!(r"{GAME_E}\mods"));
    env.sys
        .fake_fs()
        .mkdir_all(Path::new(&format!(r"{GAME_E}\mods\a")))
        .unwrap();
    env.sys.sync_all();
    let id_of = |p: &str| {
        super::tests::try_meta_abs(&env.sys, &format!(r"{GAME_E}\{p}"))
            .unwrap()
            .file_id
    };
    let fr = fr(&env.sys);
    let st = StoreDir::open(&env.sys, &fr, Path::new(LIB_E)).unwrap();
    let g = st.game(&fr, "G").unwrap();
    let dirs = created_dirs(&env, &t);
    let mut p = planted(&env, &t);
    p.store_id = st.id();
    p.id = g.id();
    p.dirs = vec![
        DirProof {
            op: dirs[0],
            file_id: id_of("mods"),
        },
        DirProof {
            op: dirs[1],
            file_id: id_of(r"mods\a"),
        },
    ];
    drop(g);
    drop(st);
    plant(&env, &t, &p);
    let r = env.revert(&t);
    assert!(r.is_ok(), "{r:?}");
    assert!(!super::tests::exists_abs(
        &env.sys,
        &format!(r"{GAME_E}\mods")
    ));
}

#[test]
fn rb_t9_a_crash_after_the_record_resumes_without_and_with_the_rebind() {
    for again in [false, true] {
        let Rb { env, t, keys: k0 } = applied(false);
        move_lib(&env.sys, STEAM_LIB, LIB_E);
        let p = env.rebind_check(&t).unwrap();
        let n = env.records(&t);
        // The first flush of the run is the rebind's (the checks write nothing).
        let r = env.revert_rebound_armed(&t, &p.to, |fx| {
            fx.fault(Prim::FlushDir, 1, crate::sys::fake::Fault::CrashAfter);
        });
        assert!(r.is_err(), "{r:?}");
        env.sys.fake_fs().restart();
        assert_eq!(env.records(&t), n + 1, "the rebind is recorded");
        assert_eq!(env.state(&t), Some(TxnState::Applied));
        let r = if again {
            // The same binding again: a plain revert of the bound transaction.
            env.revert_rebound(&t, &p.to)
        } else {
            env.revert(&t)
        };
        assert_eq!(closed(&r), Some(Closing::Reverted), "again {again}: {r:?}");
        assert_eq!(content_diff(&env.sys, REF, GAME_E), Vec::<String>::new());
        assert!(keys(&env.sys) == k0);
    }
    // A second move after a rebind (before any file op of the root was reverted): a chain.
    let Rb { env, t, keys: k0 } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let p = env.rebind_check(&t).unwrap();
    let r = env.revert_rebound_armed(&t, &p.to, |fx| {
        fx.fault(Prim::FlushDir, 1, crate::sys::fake::Fault::CrashAfter);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    move_lib(&env.sys, LIB_E, r"F:\SteamLibrary");
    let p2 = env.rebind_check(&t).unwrap();
    assert_eq!(
        p2.to.from.id, p.to.id,
        "the chain starts at the last binding"
    );
    let r = env.revert_rebound(&t, &p2.to);
    assert_eq!(closed(&r), Some(Closing::Reverted), "{r:?}");
    assert_eq!(
        content_diff(&env.sys, REF, r"F:\SteamLibrary\steamapps\common\G"),
        Vec::<String>::new()
    );
    assert!(keys(&env.sys) == k0);
    let a = app(&env.sys);
    let v = Journal::new(&a, InstanceTag::fixed(9))
        .load(&t, crate::journal::VerifyBackups::Length)
        .unwrap();
    assert_eq!(v.rebinds.len(), 2);
}

/// A file changed after the rebind record and before its act is `Foreign`; the transaction
/// stays open and bound, and the folder there is not touched for that op.
#[test]
fn rb_t9_a_change_after_the_record_is_foreign_and_the_binding_stays() {
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let p = env.rebind_check(&t).unwrap();
    let r = env.revert_rebound_armed(&t, &p.to, |fx| {
        fx.fault(Prim::FlushDir, 1, crate::sys::fake::Fault::CrashAfter);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    let x = format!(r"{GAME_E}\new.dll");
    env.sys.fake_fs().remove_abs(Path::new(&x)).unwrap();
    super::tests::sys_put(&env.sys, &x, b"the user's own");
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, None, "{r:?}");
    assert!(
        r.ops.iter().any(|o| o.observed == Observed::Foreign),
        "{r:?}"
    );
    assert_eq!(super::tests::read_abs(&env.sys, &x), b"the user's own");
    // Still bound: a rebind to the same library is a plain revert again, never a new record.
    let n = env.records(&t);
    let r = env.revert_rebound(&t, &p.to);
    assert!(r.is_ok_and(|r| r.closed.is_none()));
    assert_eq!(env.records(&t), n);
}

// ---------- P2-14a review follow-ups ----------

/// A library in a forbidden folder (below `Windows`).
const FORBIDDEN_LIB: &str = r"C:\Windows\SteamLibrary";

/// The manifest of app 220 in [`LIB_E`] made unreadable.
fn garbage_manifest(rb: &Rb) {
    let m = format!(r"{LIB_E}\steamapps\appmanifest_220.acf");
    rb.env.sys.fake_fs().remove_abs(Path::new(&m)).unwrap();
    super::tests::sys_put(&rb.env.sys, &m, b"\"AppState\"\n{\n");
}

/// Puts `data` at `abs`, creating its folder.
fn put(sys: &FakeSystem, abs: &str, data: &[u8]) {
    let p = Path::new(abs);
    sys.fake_fs().mkdir_all(p.parent().unwrap()).unwrap();
    super::tests::sys_put(sys, abs, data);
}

/// A plan over two roots: the Steam root of [`rb_steps`] and `g2` with the file ops of `s`
/// (root 1, before the registry ops).
fn two_roots(
    env: &Env,
    g2: &crate::policy::root::GameDir<'_>,
    app2: Option<u32>,
    s: &crate::prim::FileInstallSpec,
) -> PlanHash {
    let a = app(&env.sys);
    let load = |h| plan::decode(plan::load(&a, &h).unwrap().bytes()).unwrap();
    let mut p: plan::Plan = load(rb_plan(env, &rb_steps(false)));
    let other: plan::Plan = load(env.plan_for(g2, app2, s));
    let at = p
        .ops
        .iter()
        .position(|o| !matches!(o.target(), plan::Target::File { .. }))
        .unwrap();
    let ops: Vec<plan::Op> = other
        .ops
        .into_iter()
        .map(|mut o| {
            if let plan::Op::CreateDir { root, .. }
            | plan::Op::CreateFile { root, .. }
            | plan::Op::ReplaceFile { root, .. }
            | plan::Op::IniValue { root, .. } = &mut o
            {
                *root = plan::RootIx(1);
            }
            o
        })
        .collect();
    p.ops.splice(at..at, ops);
    p.roots.push(other.roots[0].clone());
    store(&a, &p.encode().unwrap()).unwrap()
}

/// A second root: the manual folder `D:\Games\H` with its main executable.
const H: &str = r"D:\Games\H";

/// A system with app 221 installed in `G` of [`LIB_E`] (as the GoldSrc apps share `Half-Life`).
fn with_221_in_e(env: &Env) {
    put(
        &env.sys,
        &format!(r"{LIB_E}\steamapps\appmanifest_221.acf"),
        acf(221, 4).as_bytes(),
    );
    put(&env.sys, &format!(r"{GAME_E}\game.exe"), b"MZ");
    set_libs(&env.sys, &[STEAM_LIB, LIB_E]);
}

/// A transaction over app 220 in `D:` and app 221 in `E:`, both in an install folder `G`.
fn shared_txn() -> (Env, TxnId) {
    let env = Env::new(rb_sys());
    with_221_in_e(&env);
    let fr = fr(&env.sys);
    let st = StoreDir::open(&env.sys, &fr, Path::new(LIB_E)).unwrap();
    let g2 = st.game(&fr, "G").unwrap();
    let h = two_roots(
        &env,
        &g2,
        Some(221),
        &spec(vec![entry("new.dll", "other.dll", super::tests::N)]),
    );
    drop(g2);
    drop(st);
    let t = env.applied(&h);
    (env, t)
}

/// Security review S1, natural: app 220 moved into the library of app 221, whose install folder
/// has the same name: the candidate is the folder of the other root. Refused before any record.
#[test]
fn rb_t5_a_candidate_that_is_another_root_of_the_transaction_is_refused() {
    let (env, t) = shared_txn();
    env.sys
        .fake_fs()
        .remove_abs(Path::new(&manifest(220)))
        .unwrap();
    put(
        &env.sys,
        &format!(r"{LIB_E}\steamapps\appmanifest_220.acf"),
        acf(220, 4).as_bytes(),
    );
    env.sys.sync_all();
    let n = env.records(&t);
    let r = env.rebind_check(&t);
    assert!(
        refused(&r, |x| matches!(x, RebindRefusal::SharedFolder)),
        "{r:?}"
    );
    assert_eq!(env.records(&t), n);
}

/// Review S3: a rebind checked on a clean state, then the state changes before the rebind under
/// the lock: the exact refusal, and no record (the real TOCTOU case).
#[test]
fn rb_t5_refusals_under_the_lock_after_a_valid_preview() {
    type LockCase = (&'static str, fn(&Rb), fn(&Refusal) -> bool);
    let cases: Vec<LockCase> = vec![
        (
            "not writable",
            |rb| {
                rb.env
                    .sys
                    .fake_fs()
                    .set_user_writable(Path::new(GAME_E), false)
                    .unwrap();
            },
            |r| matches!(r, Refusal::Rebind(RebindRefusal::NotWritable)),
        ),
        (
            "a file changed",
            |rb| {
                let p = format!(r"{GAME_E}\new.dll");
                rb.env.sys.fake_fs().remove_abs(Path::new(&p)).unwrap();
                super::tests::sys_put(&rb.env.sys, &p, b"changed by someone");
            },
            |r| matches!(r, Refusal::Rebind(RebindRefusal::Foreign { .. })),
        ),
        (
            "the main executable removed",
            |rb| {
                rb.env
                    .sys
                    .fake_fs()
                    .remove_abs(Path::new(&format!(r"{GAME_E}\game.exe")))
                    .unwrap();
            },
            |r| matches!(r, Refusal::MainExe(_)),
        ),
        (
            "the game started there",
            |rb| {
                std::mem::forget(
                    rb.env
                        .sys
                        .fake_fs()
                        .hold_open_as(
                            4242,
                            Path::new(&format!(r"{GAME_E}\game.exe")),
                            crate::sys::contract::Access::READ,
                            crate::sys::contract::Share::RWD,
                        )
                        .unwrap(),
                );
            },
            |r| matches!(r, Refusal::Busy(_)),
        ),
        ("the manifest there unreadable", garbage_manifest, |r| {
            matches!(r, Refusal::Rebind(RebindRefusal::LibraryUnreadable(_)))
        }),
        (
            "the old library back, access denied",
            |rb| {
                let fx = rb.env.sys.fake_fs();
                fx.mkdir_all(Path::new(STEAM_LIB)).unwrap();
                fx.set_restricted(Path::new(STEAM_LIB), true).unwrap();
            },
            |r| matches!(r, Refusal::Rebind(RebindRefusal::Undecided(_))),
        ),
        ("the journal full", fill_journal, |r| {
            matches!(r, Refusal::Rebind(RebindRefusal::NoRoom))
        }),
    ];
    for (what, change, want) in cases {
        let rb = applied(false);
        move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
        let p = rb
            .env
            .rebind_check(&rb.t)
            .unwrap_or_else(|e| panic!("{what}: {e:?}"));
        change(&rb);
        rb.env.sys.sync_all();
        let n = rb.env.records(&rb.t);
        let r = rb.env.revert_rebound(&rb.t, &p.to);
        assert!(
            matches!(&r, Err(ExecError::Refused(x)) if want(x)),
            "{what}: {r:?}"
        );
        assert_eq!(rb.env.records(&rb.t), n, "{what}: a record");
        // `rebind_check` sees the same now.
        let r = rb.env.rebind_check(&rb.t);
        assert!(matches!(&r, Err(x) if want(x)), "{what}: check {r:?}");
    }
}

/// Fills the record budget of the transaction with repeated revert intents of its newest op (a
/// registry op): one record short of the room a rebind needs.
fn fill_journal(rb: &Rb) {
    let a = app(&rb.env.sys);
    let j = Journal::new(&a, InstanceTag::fixed(0x78));
    let lock = j.lock().unwrap();
    let mut w = lock.resume(&rb.t).unwrap();
    let ops = w.ops().len();
    let k = w.next_revert().unwrap();
    let have = rb.env.records(&rb.t);
    // A rebind needs `records + 1 + 2 * open + 1 <= 1024`.
    for _ in have..(1024 - 2 * ops) {
        w.revert_intent(k, None, None).unwrap();
    }
}

/// Review nit: a halt the revert would meet at another root is its own refusal.
#[test]
fn rb_t5_a_halt_at_another_root_refuses_the_rebind() {
    let env = Env::new(rb_sys());
    put(&env.sys, &format!(r"{H}\game.exe"), b"MZ");
    let fr = fr(&env.sys);
    let g2 = crate::policy::root::GameDir::open_manual(&env.sys, &fr, Path::new(H)).unwrap();
    let h = two_roots(
        &env,
        &g2,
        None,
        &spec(vec![entry("new.dll", "new.dll", super::tests::N)]),
    );
    drop(g2);
    let t = env.applied(&h);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let p = env.rebind_check(&t).unwrap();
    env.sys
        .fake_fs()
        .set_user_writable(Path::new(H), false)
        .unwrap();
    let n = env.records(&t);
    let r = env.revert_rebound(&t, &p.to);
    assert!(
        matches!(
            &r,
            Err(ExecError::Refused(Refusal::Rebind(RebindRefusal::Halts(_))))
        ),
        "{r:?}"
    );
    assert_eq!(env.records(&t), n);
}

#[test]
fn rb_t8_more_rebinds_that_do_not_fit_the_head_are_blocked() {
    // Security review S1, planted: root 0 bound to the folder of root 1.
    let (env, t) = shared_txn();
    let roots = fr(&env.sys);
    let st = StoreDir::open(&env.sys, &roots, Path::new(LIB_E)).unwrap();
    let mut p = planted(&env, &t);
    p.store_id = st.id();
    p.id = head_of(&env, &t).roots[1].id;
    drop(st);
    plant(&env, &t, &p);
    let f = blocked_everywhere(&env, &t);
    assert!(f.is_empty(), "another root's folder: {f:#?}");

    // A directory proof for a `CreateDir` of another root.
    let env = Env::new(rb_sys());
    put(&env.sys, &format!(r"{H}\game.exe"), b"MZ");
    let roots2 = fr(&env.sys);
    let g2 = crate::policy::root::GameDir::open_manual(&env.sys, &roots2, Path::new(H)).unwrap();
    let h = two_roots(
        &env,
        &g2,
        None,
        &spec(vec![entry(r"mods\x.dll", r"mods2\x.dll", super::tests::X)]),
    );
    drop(g2);
    let t = env.applied(&h);
    let head = head_of(&env, &t);
    let other_dir = head
        .ops
        .iter()
        .position(|o| matches!(o, plan::Op::CreateDir { root, .. } if root.0 == 1))
        .unwrap();
    let mut p = planted(&env, &t);
    p.dirs = vec![DirProof {
        op: u16::try_from(other_dir).unwrap(),
        file_id: 9,
    }];
    plant(&env, &t, &p);
    let f = blocked_everywhere(&env, &t);
    assert!(f.is_empty(), "a proof for another root: {f:#?}");

    // A library path from which no game path can be formed.
    let Rb { env, t, .. } = applied(false);
    let long = format!(
        r"E:\{}\{}\{}\{}",
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60),
        "d".repeat(50)
    );
    let mut p = planted(&env, &t);
    p.store = rp(&long);
    plant(&env, &t, &p);
    let f = blocked_everywhere(&env, &t);
    assert!(f.is_empty(), "no game path: {f:#?}");
}

/// Review S4: a library renamed on its volume keeps the game folder's file ID; the rebind
/// records `old == id`, the bindings accept it, and the transaction closes.
#[test]
fn rb_t1_a_library_renamed_on_its_volume_is_rebound() {
    const LIB: &str = r"D:\Games\SteamLibrary";
    let Rb { env, t, keys: k0 } = applied(false);
    env.sys.rename_abs(STEAM_LIB, LIB).unwrap();
    set_libs(&env.sys, &[LIB]);
    env.sys.sync_all();
    let p = env.rebind_check(&t).unwrap();
    assert_eq!(p.to.id, p.to.from.id, "the same folder");
    assert_eq!(p.to.dirs.len(), 2);
    let r = env.revert_rebound(&t, &p.to).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    let a = app(&env.sys);
    let v = Journal::new(&a, InstanceTag::fixed(9))
        .load(&t, crate::journal::VerifyBackups::Length)
        .unwrap();
    assert_eq!(v.rebinds[0].old, v.rebinds[0].id);
    assert_eq!(
        content_diff(&env.sys, REF, &format!(r"{LIB}\steamapps\common\G")),
        Vec::<String>::new()
    );
    assert!(keys(&env.sys) == k0);
}

/// Review S4: E-R1 at the library level: the library recreated at the same path (another
/// identity); the revert refused, the rebind to the same path closes.
#[test]
fn rb_t2_a_library_recreated_at_its_path_is_rebound() {
    let Rb { env, t, keys: k0 } = applied(false);
    env.sys.rename_abs(STEAM_LIB, r"D:\OldLib").unwrap();
    copy_tree(&env.sys, r"D:\OldLib", STEAM_LIB);
    remove_tree(&env.sys, r"D:\OldLib");
    env.sys.sync_all();
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Root(e)))
            if matches!(&**e, RootError::IdentityMismatch { path, .. } if *path == rp(STEAM_LIB))),
        "{r:?}"
    );
    let p = env.rebind_check(&t).unwrap();
    assert!(
        matches!(&*p.why, Refusal::Root(e)
            if matches!(&**e, RootError::IdentityMismatch { path, .. } if *path == rp(STEAM_LIB))),
        "{:?}",
        p.why
    );
    assert_ne!(p.to.store_id, p.to.from.store_id);
    let r = env.revert_rebound(&t, &p.to).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert_eq!(
        content_diff(&env.sys, REF, STEAM_GAME),
        Vec::<String>::new()
    );
    assert!(keys(&env.sys) == k0);
}

/// Review S2 as a check: after the record, a created folder is proven by the recorded file ID
/// only. A folder swapped for another one (a new ID) after the record is `Foreign` and stays;
/// a folder missing at the preview (no proof) that appears after the record is `Foreign`.
pub(crate) fn rb_t9_dir_check() -> Vec<String> {
    let mut f = Vec::new();
    let crash_after_record = |rb: &Rb, p: &RebindPreview| {
        let r = rb.env.revert_rebound_armed(&rb.t, &p.to, |fx| {
            fx.fault(Prim::FlushDir, 1, crate::sys::fake::Fault::CrashAfter);
        });
        assert!(r.is_err(), "{r:?}");
        rb.env.sys.fake_fs().restart();
    };
    // Swapped.
    let rb = applied(false);
    move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
    let p = rb.env.rebind_check(&rb.t).unwrap();
    crash_after_record(&rb, &p);
    let a = format!(r"{GAME_E}\mods\a");
    move_tree(&rb.env.sys, &a, r"E:\Tmp\a");
    move_tree(&rb.env.sys, r"E:\Tmp\a", &a);
    let dirs = created_dirs(&rb.env, &rb.t);
    match rb.env.revert(&rb.t) {
        Ok(r)
            if r.closed.is_none()
                && r.ops
                    .iter()
                    .any(|o| o.op == dirs[1] && o.observed == Observed::Foreign) => {}
        r => f.push(format!("RB-T9 swapped: {r:?}")),
    }
    if super::tests::try_meta_abs(&rb.env.sys, &a).is_none() {
        f.push("RB-T9 swapped: the folder removed".to_owned());
    }
    // No proof.
    let rb = applied(false);
    move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
    remove_tree(&rb.env.sys, &format!(r"{GAME_E}\mods"));
    rb.env.sys.sync_all();
    let p = rb.env.rebind_check(&rb.t).unwrap();
    if !p.to.dirs.is_empty() {
        f.push(format!("RB-T9 no proof: {:?}", p.to.dirs));
    }
    crash_after_record(&rb, &p);
    let mods = format!(r"{GAME_E}\mods");
    rb.env.sys.fake_fs().mkdir_all(Path::new(&mods)).unwrap();
    rb.env.sys.sync_all();
    match rb.env.revert(&rb.t) {
        Ok(r)
            if r.closed.is_none()
                && r.ops
                    .iter()
                    .any(|o| o.op == dirs[0] && o.observed == Observed::Foreign) => {}
        r => f.push(format!("RB-T9 no proof: {r:?}")),
    }
    if super::tests::try_meta_abs(&rb.env.sys, &mods).is_none() {
        f.push("RB-T9 no proof: the folder removed".to_owned());
    }
    f
}

#[test]
fn rb_t9_a_created_folder_is_proven_by_the_recorded_id_only() {
    let f = rb_t9_dir_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-RB2b (review S2): after the record, the folder found counts as before it: both cases of
/// the check remove a folder that is not provably Rerun's.
#[test]
fn k_rb2b_a_folder_found_after_the_record_breaks_rb_t9() {
    super::knob::dir_found_after_record(true);
    let f = rb_t9_dir_check();
    super::knob::dir_found_after_record(false);
    for what in ["RB-T9 swapped", "RB-T9 no proof"] {
        assert!(
            f.iter().any(|x| x.starts_with(what)),
            "K-RB2b not caught ({what}): {f:#?}"
        );
    }
}

/// E-R3: the objects of a rebound transaction still count at the old identity. The library
/// copied (not moved) to `E:`, the app's manifest gone from `D:`: rebound and left open, an
/// apply on its objects in the old folder (still there) is refused.
pub(crate) fn rb_t7b_check() -> Vec<String> {
    let mut f = Vec::new();
    let Rb { env, t, .. } = applied(false);
    copy_tree(&env.sys, STEAM_LIB, LIB_E);
    set_libs(&env.sys, &[STEAM_LIB, LIB_E]);
    env.sys
        .fake_fs()
        .remove_abs(Path::new(&manifest(220)))
        .unwrap();
    env.sys.sync_all();
    let p = env.rebind_check(&t).unwrap();
    let r = env.revert_rebound_armed(&t, &p.to, |fx| {
        fx.fault(Prim::FlushDir, 1, crate::sys::fake::Fault::CrashAfter);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    super::tests::sys_put(&env.sys, &super::tests::pkg("y.dll"), b"y of the package");
    let fr = fr(&env.sys);
    let old =
        crate::policy::root::GameDir::open_manual(&env.sys, &fr, Path::new(STEAM_GAME)).unwrap();
    let h = env.plan_for(
        &old,
        None,
        &spec(vec![entry("y.dll", r"mods\a\y.dll", b"y of the package")]),
    );
    drop(old);
    match env.apply(&h) {
        Err(ApplyError::Refused(Refusal::Interrupted { txn })) if txn == t => {}
        r => f.push(format!("RB-T7b apply in the old folder: {r:?}")),
    }
    f
}

#[test]
fn rb_t7b_objects_still_count_at_the_old_identity() {
    let f = rb_t7b_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-RB4: the objects at the old identity dropped: RB-T7b's apply goes through.
#[test]
fn k_rb4_objects_from_the_binding_only_break_rb_t7b() {
    super::knob::objects_from_binding_only(true);
    let f = rb_t7b_check();
    super::knob::objects_from_binding_only(false);
    assert!(
        f.iter().any(|x| x.starts_with("RB-T7b apply")),
        "K-RB4 not caught: {f:#?}"
    );
}

// ---------- P2-14b: the candidate from the Steam scan (E-R1) ----------

/// RB-T10 (E-R1): the library comes from the Steam scan only. The app in two listed libraries
/// is `Ambiguous` (naming both); a listed library that is missing, also the old one (condition
/// b), is `LibraryUnreadable`; no Steam at all is `NoCandidate`; nothing is written.
#[test]
fn rb_t10_the_scan_finds_exactly_one_readable_library() {
    // Two libraries hold the app: the folder in `D:` gone, a copy in `E:`.
    let Rb { env, t, .. } = applied(false);
    copy_tree(&env.sys, STEAM_LIB, LIB_E);
    remove_tree(&env.sys, STEAM_GAME);
    set_libs(&env.sys, &[STEAM_LIB, LIB_E]);
    let before = snap_app(&env.sys);
    let r = env.rebind_check(&t);
    match &r {
        Err(Refusal::Rebind(RebindRefusal::Ambiguous(libs))) => {
            let libs: Vec<String> = libs.iter().map(ToString::to_string).collect();
            assert_eq!(libs, vec![STEAM_LIB.to_owned(), LIB_E.to_owned()]);
        }
        r => panic!("ambiguous: {r:?}"),
    }
    assert!(snap_app(&env.sys) == before);
    // The old library still listed but gone (an unplugged drive): refused, naming it.
    let Rb { env, t, .. } = applied(false);
    move_tree(&env.sys, STEAM_LIB, LIB_E);
    set_libs(&env.sys, &[STEAM_LIB, LIB_E]);
    let r = env.rebind_check(&t);
    assert!(
        matches!(&r, Err(Refusal::Rebind(RebindRefusal::LibraryUnreadable(w)))
            if w.to_string().contains(STEAM_LIB)),
        "{r:?}"
    );
    // No Steam: no candidate.
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    env.sys
        .fake_registry()
        .remove_value(
            &crate::detect::steam::RootSource::CurrentUser.key(),
            crate::detect::steam::RootSource::CurrentUser.value_name(),
        )
        .unwrap();
    let r = env.rebind_check(&t);
    assert!(
        refused(&r, |x| matches!(x, RebindRefusal::NoCandidate)),
        "{r:?}"
    );
}

/// RB-T11 (condition a): the scan runs again under the lock. A second library with the app
/// since the preview is `Ambiguous`, the library moved on since the preview is `Changed`;
/// neither writes a record.
#[test]
fn rb_t11_the_scan_under_the_lock_meets_what_changed_since_the_preview() {
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let p = env.rebind_check(&t).unwrap();
    copy_tree(&env.sys, LIB_E, r"F:\SteamLibrary");
    set_libs(&env.sys, &[LIB_E, r"F:\SteamLibrary"]);
    let n = env.records(&t);
    let r = env.revert_rebound(&t, &p.to);
    assert!(
        matches!(
            &r,
            Err(ExecError::Refused(Refusal::Rebind(
                RebindRefusal::Ambiguous(_)
            )))
        ),
        "{r:?}"
    );
    assert_eq!(env.records(&t), n);
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let p = env.rebind_check(&t).unwrap();
    move_lib(&env.sys, LIB_E, r"F:\SteamLibrary");
    let n = env.records(&t);
    let r = env.revert_rebound(&t, &p.to);
    assert!(
        matches!(
            &r,
            Err(ExecError::Refused(Refusal::Rebind(RebindRefusal::Changed)))
        ),
        "{r:?}"
    );
    assert_eq!(env.records(&t), n);
    // Checked again: the folder there; it closes.
    let p = env.rebind_check(&t).unwrap();
    assert_eq!(p.to.store, rp(r"F:\SteamLibrary"));
    assert_eq!(
        closed(&env.revert_rebound(&t, &p.to)),
        Some(Closing::Reverted)
    );
}

/// RB-T12 (conditions c and e): a transaction bound by an earlier rebind whose folder opens is
/// `AlreadyBound` with that folder (not `NotNeeded`); the preview names every created folder
/// with its path in the new folder and whether it was found there.
#[test]
fn rb_t12_already_bound_and_the_created_folders_of_the_preview() {
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    remove_tree(&env.sys, &format!(r"{GAME_E}\mods\a"));
    env.sys.sync_all();
    let p = env.rebind_check(&t).unwrap();
    let created: Vec<(String, bool)> = p
        .created
        .iter()
        .map(|d| (d.path.to_string(), d.found))
        .collect();
    assert_eq!(
        created,
        vec![
            (format!(r"{GAME_E}\mods"), true),
            (format!(r"{GAME_E}\mods\a"), false),
        ]
    );
    assert_eq!(p.to.dirs.len(), 1);
    let r = env.revert_rebound_armed(&t, &p.to, |fx| {
        fx.fault(Prim::FlushDir, 1, crate::sys::fake::Fault::CrashAfter);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    let r = env.rebind_check(&t);
    assert!(
        matches!(&r, Err(Refusal::Rebind(RebindRefusal::AlreadyBound { root: 0, path }))
            if path.to_string() == GAME_E),
        "{r:?}"
    );
}

/// Condition d: `status` shows every rebind of a transaction (journal only).
#[test]
fn rb_t12_status_shows_the_binding() {
    let Rb { env, t, .. } = applied(false);
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let p = env.rebind_check(&t).unwrap();
    let r = env.revert_rebound_armed(&t, &p.to, |fx| {
        fx.fault(Prim::FlushDir, 1, crate::sys::fake::Fault::CrashAfter);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    let a = app(&env.sys);
    let st = super::txn_status(&a, &t).unwrap();
    assert_eq!(st.rebinds.len(), 1);
    let l = &st.rebinds[0];
    assert_eq!(
        (
            l.root,
            l.library.to_string(),
            l.folder.as_ref().map(ToString::to_string)
        ),
        (0, LIB_E.to_owned(), Some(GAME_E.to_owned()))
    );
    assert_eq!((l.id, l.old), (p.to.id, p.to.from.id));
}
