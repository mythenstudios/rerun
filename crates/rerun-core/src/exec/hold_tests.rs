//! `Hold` (P4-8, ADR 0020 amendment P4-8) against the fake: H1 a shared file held by a later
//! transaction (the revert of the earlier one refused with its own text, newest first, then the
//! game folder identical), H2 a plan of nothing but holds changes nothing, H3 the held file
//! changed before the apply, H4 tampering at the hold of a head touches only the transaction's own
//! objects, H5 a DLL slot of another package's transaction (`Refusal::SlotTaken`, at the plan
//! and the apply).

use std::path::Path;

use super::tests::{Env, N, NEW, X, base, closed, finish, game, read_abs, same};
use super::{ApplyError, ExecError, Outcome, Refusal};
use crate::journal::{Closing, Observed};
use crate::plan::{self, Op};
use crate::prim::tests::{app, entry, spec};
use crate::prim::{FileInstallSpec, PlanCtx, Step, plan as plan_steps};

/// T1: `new.dll` and `mods\x.dll` (with its folder).
fn t1() -> FileInstallSpec {
    spec(vec![
        entry("new.dll", "new.dll", N),
        entry(r"mods\x.dll", r"mods\x.dll", X),
    ])
}

/// T2: `new.dll` again (T1 installed it: a hold) and a replace of `d3d9.dll`.
fn t2() -> FileInstallSpec {
    spec(vec![
        entry("new.dll", "new.dll", N),
        entry("d3d9.dll", "d3d9.dll", NEW),
    ])
}

fn kinds(env: &Env, h: &plan::PlanHash) -> Vec<&'static str> {
    let a = app(&env.sys);
    let p = plan::decode(plan::load(&a, h).unwrap().bytes()).unwrap();
    p.ops
        .iter()
        .map(|o| match o {
            Op::Hold { .. } => "hold",
            Op::CreateFile { .. } => "create",
            Op::ReplaceFile { .. } => "replace",
            Op::CreateDir { .. } => "dir",
            _ => "other",
        })
        .collect()
}

/// H1: the round trip of a shared file. T2 holds `new.dll` of T1: the revert of T1 is refused
/// (`Held`, nothing written) while T2 is there; T2 reverted leaves `new.dll` as T1 left it; then
/// T1 reverted leaves the game folder identical to before both.
#[test]
fn h1_a_held_file_keeps_the_earlier_transaction_until_the_later_is_reverted() {
    let env = Env::new(finish(base()));
    let floor = env.snap();
    let a = env.applied(&env.plan(&t1()));
    let mid = env.snap();
    let h2 = env.plan(&t2());
    assert_eq!(kinds(&env, &h2), ["hold", "replace"]);
    let b = env.applied(&h2);
    assert_eq!(
        env.verify(&b),
        [(0, Observed::After), (1, Observed::After)],
        "the hold is observed After while the file holds its content"
    );
    let both = env.snap();
    // The wrong order: refused before anything is written, with the text of a shared file.
    match env.revert(&a) {
        Err(ExecError::Refused(Refusal::Held { txn })) if txn == b => {}
        r => panic!("{r:?}"),
    }
    let text = Refusal::Held { txn: b }.to_string();
    assert!(
        text.contains("uses a file this transaction installed"),
        "{text}"
    );
    assert!(text.contains(&format!("revert {b} first")), "{text}");
    same(&both, &env.snap());
    // The right order.
    let rep = env.revert(&b).unwrap();
    assert_eq!(rep.closed, Some(Closing::Reverted));
    assert_eq!(read_abs(&env.sys, &game("new.dll")), N);
    same(&mid, &env.snap());
    assert_eq!(closed(&env.revert(&a)), Some(Closing::Reverted));
    same(&floor, &env.snap());
}

/// H2: a plan whose every file is there already changes nothing: no ops, no transaction.
#[test]
fn h2_a_plan_of_holds_only_is_nothing_to_do() {
    let env = Env::new(finish(base()));
    let a = env.applied(&env.plan(&t1()));
    let h = env.plan(&spec(vec![entry("new.dll", "new.dll", N)]));
    assert!(kinds(&env, &h).is_empty());
    assert!(matches!(env.apply(&h), Ok(Outcome::Nothing)));
    // T1 stays revertable: nothing holds its file.
    assert_eq!(closed(&env.revert(&a)), Some(Closing::Reverted));
}

/// H3: the held file changed after the plan: the apply is a mismatch, nothing is written.
#[test]
fn h3_a_held_file_that_changed_is_a_mismatch() {
    let env = Env::new(finish(base()));
    let a = env.applied(&env.plan(&t1()));
    let h2 = env.plan(&t2());
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&game("new.dll"))).unwrap();
    fx.put_file(Path::new(&game("new.dll")), b"changed by someone")
        .unwrap();
    let before = env.snap();
    assert!(
        matches!(
            env.apply(&h2),
            Err(ApplyError::Refused(Refusal::Mismatch { op: 0 }))
        ),
        "the hold re-observes its file"
    );
    same(&before, &env.snap());
    // A hold observes "not there as held" as `Before`, never `Foreign`: T1's own op is the one
    // that finds the change.
    let rep = env.revert(&a).unwrap();
    assert_eq!(rep.closed, None, "T1's create is foreign now: {rep:?}");
}

/// H4: a head whose hold was tampered with. Retargeted to another file of T1: T2's revert
/// observes it, changes nothing there and reverts only its own replace; T1's files stay as T1
/// left them, and T1 then reverts to the folder before both. Turned into a create (which a
/// revert would delete): the records do not fit, the revert is refused, nothing is touched.
#[test]
fn h4_tampering_at_a_hold_touches_only_own_objects() {
    use crate::journal::tests::rewrite;
    // Retargeted.
    let env = Env::new(finish(base()));
    let floor = env.snap();
    let a = env.applied(&env.plan(&t1()));
    let b = env.applied(&env.plan(&t2()));
    let dir = env.txn_dir(&b);
    let head = String::from_utf8(read_abs(&env.sys, &format!(r"{dir}\head.json"))).unwrap();
    let moved = head.replacen(
        r#"{"hold":{"root":0,"path":"new.dll""#,
        r#"{"hold":{"root":0,"path":"mods\\x.dll""#,
        1,
    );
    assert_ne!(moved, head);
    rewrite(env.sys.fake_fs(), &dir, Some(moved.as_bytes()), |_| {});
    let rep = env.revert(&b).unwrap();
    assert_eq!(rep.closed, Some(Closing::Reverted));
    assert_eq!(read_abs(&env.sys, &game("new.dll")), N);
    assert_eq!(read_abs(&env.sys, &game(r"mods\x.dll")), X);
    assert_eq!(closed(&env.revert(&a)), Some(Closing::Reverted));
    same(&floor, &env.snap());

    // Turned into a create of the held file.
    let env = Env::new(finish(base()));
    let _a = env.applied(&env.plan(&t1()));
    let b = env.applied(&env.plan(&t2()));
    let dir = env.txn_dir(&b);
    let head = String::from_utf8(read_abs(&env.sys, &format!(r"{dir}\head.json"))).unwrap();
    let start = head.find(r#"{"hold":"#).unwrap();
    let end =
        start + head[start..].find(r#""config":false}}}"#).unwrap() + r#""config":false}}}"#.len();
    let hold = &head[start..end];
    let create = hold
        .replacen(r#"{"hold":"#, r#"{"create_file":"#, 1)
        .replacen(
            r#""config":false}}}"#,
            r#""config":false}},"attrs":{"readonly":false,"hidden":false,"system":false}}"#,
            1,
        );
    let forged = head.replacen(hold, &create, 1);
    rewrite(env.sys.fake_fs(), &dir, Some(forged.as_bytes()), |_| {});
    let after = env.snap();
    assert!(
        matches!(
            env.revert(&b),
            Err(ExecError::Refused(Refusal::Blocked { .. }))
        ),
        "a create without its temp name does not fit its records"
    );
    same(&after, &env.snap());
    assert_eq!(read_abs(&env.sys, &game("new.dll")), N);
}

/// Plans `s` (package `id`) for the manual game folder; the planner's error as text.
fn plan_pkg(env: &Env, id: &str, s: &FileInstallSpec) -> Result<plan::PlanHash, String> {
    let fr = crate::prim::tests::fr(&env.sys);
    let g = crate::policy::root::GameDir::open_manual(
        &env.sys,
        &fr,
        Path::new(crate::prim::tests::GAME),
    )
    .unwrap();
    let a = app(&env.sys);
    let main = crate::prim::tests::rel("game.exe");
    let mut s = s.clone();
    s.package = id.to_owned();
    let p = plan_steps(
        &[Step::FileInstall(s)],
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: None,
            main_exe: Some(&main),
            reg: crate::policy::registry::RegPolicy.reader(&env.sys),
            app_path: None,
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(plan::store(&a, &p.encode().unwrap()).unwrap())
}

/// H5: the DLL slot of another package's transaction. The planner refuses with the transaction
/// and the package; a plan made before that transaction is refused by the apply (before
/// `begin`); a DLL of the same package (a hold) and a file that is no DLL are not slots.
#[test]
fn h5_a_dll_slot_of_another_package_is_refused() {
    let env = Env::new(finish(base().file(
        r"C:\Users\Player\AppData\Local\Rerun\packages\other-pack\1.0.2\d3d9.dll",
        b"another d3d9".to_vec(),
    )));
    let other = spec(vec![entry("d3d9.dll", "d3d9.dll", b"another d3d9")]);
    // Planned before the first transaction exists: the apply checks again.
    let early = plan_pkg(&env, "other-pack", &other).unwrap();
    let a = env.applied(&env.plan(&spec(vec![entry("d3d9.dll", "d3d9.dll", NEW)])));
    let e = plan_pkg(&env, "other-pack", &other).unwrap_err();
    assert!(
        e.contains(&format!(
            "d3d9.dll is the DLL slot of package fix-pack from transaction {a}"
        )) && e.contains("Rerun does not chainload"),
        "{e}"
    );
    let before = env.snap();
    match env.apply(&early) {
        Err(ApplyError::Refused(Refusal::SlotTaken { txn, op: 0, .. })) if txn == a => {}
        r => panic!("{r:?}"),
    }
    same(&before, &env.snap());
    // The same package again: a hold, no conflict (and alone, nothing to do).
    let again = plan_pkg(
        &env,
        "fix-pack",
        &spec(vec![entry("d3d9.dll", "d3d9.dll", NEW)]),
    );
    assert!(again.is_ok(), "{again:?}");
    // Reverted, the slot is free again.
    assert_eq!(closed(&env.revert(&a)), Some(Closing::Reverted));
    assert!(plan_pkg(&env, "other-pack", &other).is_ok());
}
