//! `exec` with `IniValue` against the fake (P2-12, C4), each scenario a check function with named
//! findings: R-I1 round trips (with `file_install`, per encoding; R-I1b only the attributes
//! changed: a rewrite back to the exact old content), R-I2 every row of the observation through
//! `verify` with the key states, R-I3 drift with exact bytes, R-I6 tampering, R-I7 stacking and
//! LIFO, R-I8 a value rule tightened after the apply, M1 and S2/S6 on constructed states.
//! Controls (through the check functions): K-I2 (`unedit` normalising line endings) fails R-I1,
//! K-I3 (a changed key `Foreign`) fails R-I3, K-I4 (no binding of head and backup) fails R-I6,
//! K-I5 (the leftover `X.old` deleted without M1's conditions) fails the M1 check. Crashes,
//! power losses and K-I1: `ini_crash_tests.rs`.

use std::path::Path;

use super::reg_tests::{Reset, plan_all};
use super::tests::{
    Env, base, closed, finish, game, read_abs, same, sys_put, t1_spec, try_read_abs,
};
use super::{Detail, ExecError, Outcome, Refusal};
use crate::journal::{Closing, Digest, Observed, TxnId};
use crate::plan::{self, PlanHash};
use crate::policy::ini::{self, IniEdit, IniName, IniText, KeyState, Old};
use crate::prim::Step;
use crate::prim::ini_tests::{INI, INI_TEXT, ini_step, three};
use crate::sys::fake::FakeSystemBuilder;
use crate::sys::fs::Attrs;

/// [`base`] with [`INI`] holding `text`.
pub(crate) fn ini_base(text: &[u8]) -> FakeSystemBuilder {
    base().file(game(INI), text.to_vec())
}

pub(crate) fn ini_env(text: &[u8]) -> Env {
    Env::new(finish(ini_base(text)))
}

/// The edits of [`three`], in canonical order.
pub(crate) fn edits3() -> Vec<IniEdit> {
    let n = |s: &str| IniName::parse(s).unwrap();
    let t = |s: &str| IniText::parse(s).unwrap();
    vec![
        IniEdit {
            section: n("Display"),
            key: n("Fullscreen"),
            old: Old::NoKey,
            new: t("1"),
        },
        IniEdit {
            section: n("Display"),
            key: n("Width"),
            old: Old::Value(t("1280")),
            new: t("1920"),
        },
        IniEdit {
            section: n("Zz Extra"),
            key: n("Mode"),
            old: Old::NoSection,
            new: t("2"),
        },
    ]
}

/// [`INI_TEXT`] after [`three`].
pub(crate) const APPLIED: &str = "; written by the game\r\n[Display]\r\nFullscreen=1\r\nWidth=1920\r\nHeight = 720\r\n\r\n[Audio]\r\nVolume=5\r\n[Zz Extra]\r\nMode=2\r\n";

pub(crate) fn ini_now(env: &Env) -> Option<Vec<u8>> {
    try_read_abs(&env.sys, &game(INI))
}

pub(crate) fn put_ini(env: &Env, b: &[u8]) {
    sys_put(&env.sys, &game(INI), b);
}

fn attrs_of(env: &Env) -> Option<Attrs> {
    super::tests::try_meta_abs(&env.sys, &game(INI)).map(|m| m.attrs)
}

fn set_attrs(env: &Env, a: Attrs) {
    env.sys
        .fake_fs()
        .set_attrs(Path::new(&game(INI)), a)
        .unwrap();
}

const HIDDEN: Attrs = Attrs {
    readonly: false,
    hidden: true,
    system: false,
};

fn applied(env: &Env, steps: &[Step], what: &str) -> Result<TxnId, String> {
    match env.apply(&plan_all(env, steps)) {
        Ok(Outcome::Applied(t)) => Ok(t),
        other => Err(format!("{what} apply: {other:?}")),
    }
}

/// Plans `steps` and stores the plan, or the planner's refusal.
fn try_plan(env: &Env, steps: &[Step]) -> Result<PlanHash, plan::PlanError> {
    let fr = crate::prim::tests::fr(&env.sys);
    let g = crate::policy::root::GameDir::open_manual(
        &env.sys,
        &fr,
        Path::new(crate::prim::tests::GAME),
    )?;
    let a = crate::prim::tests::app(&env.sys);
    let main = crate::prim::tests::rel("game.exe");
    let p = crate::prim::plan(
        steps,
        &crate::prim::PlanCtx {
            game: &g,
            app: &a,
            steam_app: None,
            main_exe: Some(&main),
            reg: crate::policy::registry::RegPolicy.reader(&env.sys),
        },
    )?;
    plan::store(&a, &p.encode()?)
}

/// The fixtures of R-I1: ANSI with CRLF, UTF-8 with BOM and LF, mixed line endings without one
/// at the end.
pub(crate) fn encodings() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("ANSI CRLF", {
            let mut v = b"; \xE9t\xE9\r\n".to_vec();
            v.extend_from_slice(INI_TEXT);
            v
        }),
        (
            "UTF-8 BOM LF",
            String::from_utf8_lossy(INI_TEXT)
                .replace("\r\n", "\n")
                .bytes()
                .fold(b"\xEF\xBB\xBF".to_vec(), |mut v, c| {
                    v.push(c);
                    v
                }),
        ),
        (
            "mixed, no line ending at the end",
            b"[Display]\nWidth = 1280\r\n[Audio]\r\nVolume=5".to_vec(),
        ),
    ]
}

/// R-I1 as a check (module docs).
pub(crate) fn i1_check() -> Vec<String> {
    let mut f = Vec::new();
    for (what, text) in encodings() {
        let env = ini_env(&text);
        let before = env.snap();
        let steps = [Step::FileInstall(t1_spec()), three()];
        let h = match try_plan(&env, &steps) {
            Ok(h) => h,
            Err(e) => {
                f.push(format!("RI1 {what} plan: {e}"));
                continue;
            }
        };
        let t = match env.apply(&h) {
            Ok(Outcome::Applied(t)) => t,
            other => {
                f.push(format!("RI1 {what} apply: {other:?}"));
                continue;
            }
        };
        if ini_now(&env) != ini::edit(&text, &edits3()).ok() {
            f.push(format!("RI1 {what} content after apply"));
        }
        match env.try_verify(&t) {
            Ok(v) if v.iter().all(|(_, o)| *o == Observed::After) => {}
            v => f.push(format!("RI1 {what} verify after apply: {v:?}")),
        }
        match env.revert(&t) {
            Ok(r)
                if r.closed == Some(Closing::Reverted)
                    && r.ops.iter().all(|o| o.observed == Observed::After) => {}
            r => f.push(format!("RI1 {what} revert: {r:?}")),
        }
        let now = env.snap();
        if before != now {
            f.push(format!("RI1 {what} snapshot: {:#?}", before.diff(&now)));
        }
        if try_plan(&env, &steps).ok() != Some(h) {
            f.push(format!("RI1 {what} planned again: another hash"));
        }
        match env.try_verify(&t) {
            Ok(v) if v.iter().all(|(_, o)| *o == Observed::Before) => {}
            v => f.push(format!("RI1 {what} verify after revert: {v:?}")),
        }
        // R-I1b: only the attributes changed since: the rewrite gives exactly the old content,
        // the current attributes stay.
        let env = ini_env(&text);
        let t = match applied(&env, &[three()], what) {
            Ok(t) => t,
            Err(e) => {
                f.push(format!("RI1b {e}"));
                continue;
            }
        };
        set_attrs(&env, HIDDEN);
        match env.revert(&t) {
            Ok(r)
                if r.closed == Some(Closing::Reverted)
                    && r.ops.iter().all(|o| o.observed == Observed::Drifted) => {}
            r => f.push(format!("RI1b {what} revert: {r:?}")),
        }
        if ini_now(&env).as_deref() != Some(&text[..]) {
            f.push(format!(
                "RI1b {what} content: {:?}",
                ini_now(&env).map(|b| String::from_utf8_lossy(&b).into_owned())
            ));
        }
        if attrs_of(&env) != Some(HIDDEN) {
            f.push(format!("RI1b {what} attributes: {:?}", attrs_of(&env)));
        }
    }
    f
}

#[test]
fn r_i1_ini_set_round_trips_exactly() {
    let f = i1_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-I2: `unedit` normalising line endings fails R-I1 (R-I1b, CRLF).
#[test]
fn k_i2_unedit_normalising_line_endings_breaks_ri1() {
    let _r = Reset(|| ini::knob::normalise_eol(false));
    ini::knob::normalise_eol(true);
    let f = i1_check();
    assert!(
        f.iter().any(|x| x.starts_with("RI1b ANSI CRLF content")),
        "{f:#?}"
    );
}

/// The key states `verify` names for the op.
fn keys_of(d: Option<&Detail>) -> Vec<KeyState> {
    match d {
        Some(Detail::Ini { keys, .. }) => keys.iter().map(|k| k.state).collect(),
        _ => Vec::new(),
    }
}

/// R-I2: every row of the observation through `verify`, with the key states.
#[test]
fn r_i2_verify_meets_every_row() {
    use KeyState::{Changed, New, Old as KOld};
    type Case = (&'static str, fn(&Env), Observed, &'static [KeyState]);
    let cases: [Case; 12] = [
        ("after", |_| {}, Observed::After, &[New, New, New]),
        (
            "before",
            |e| put_ini(e, INI_TEXT),
            Observed::Before,
            &[KOld, KOld, KOld],
        ),
        (
            "a foreign key changed",
            |e| put_ini(e, APPLIED.replace("Volume=5", "Volume=9").as_bytes()),
            Observed::Drifted,
            &[New, New, New],
        ),
        (
            "Rerun's key changed",
            |e| put_ini(e, APPLIED.replace("Width=1920", "Width=1600").as_bytes()),
            Observed::Drifted,
            &[New, Changed, New],
        ),
        (
            "Rerun's key removed (an old value)",
            |e| put_ini(e, APPLIED.replace("Width=1920\r\n", "").as_bytes()),
            Observed::Drifted,
            &[New, Changed, New],
        ),
        (
            "only the attributes",
            |e| set_attrs(e, HIDDEN),
            Observed::Drifted,
            &[New, New, New],
        ),
        (
            "gone (E2 a)",
            |e| e.sys.fake_fs().remove_abs(Path::new(&game(INI))).unwrap(),
            Observed::Drifted,
            &[],
        ),
        (
            "a NUL",
            |e| put_ini(e, format!("{APPLIED}\0").as_bytes()),
            Observed::Foreign,
            &[],
        ),
        (
            "UTF-16",
            |e| put_ini(e, b"\xFF\xFE[\x00"),
            Observed::Foreign,
            &[],
        ),
        (
            "Rerun's key twice",
            |e| {
                put_ini(
                    e,
                    APPLIED
                        .replace("Width=1920", "Width=1920\r\nWidth=1920")
                        .as_bytes(),
                )
            },
            Observed::Foreign,
            &[],
        ),
        (
            "a folder",
            |e| {
                e.sys.fake_fs().remove_abs(Path::new(&game(INI))).unwrap();
                e.sys.fake_fs().mkdir_all(Path::new(&game(INI))).unwrap();
            },
            Observed::Foreign,
            &[],
        ),
        (
            "a .old of its sequence with a foreign content",
            |e| {
                let t = e.states().last().unwrap().0;
                let x = super::tests::read_abs(&e.sys, &format!(r"{}\0001.json", e.txn_dir(&t)));
                let x = String::from_utf8(x).unwrap();
                let at = x.find(".rerun-").unwrap();
                let name = &x[at..at + x[at..].find('"').unwrap()];
                sys_put(&e.sys, &game(&format!(r"cfg\{name}.old")), b"someone's");
                put_ini(e, APPLIED.replace("Volume=5", "Volume=9").as_bytes());
            },
            Observed::Foreign,
            &[],
        ),
    ];
    for (what, change, want, keys) in cases {
        let env = ini_env(INI_TEXT);
        let t = applied(&env, &[three()], what).unwrap();
        change(&env);
        let v = env.verified(&t).unwrap();
        assert_eq!(v.ops, [(0, want)], "{what}");
        assert_eq!(keys_of(v.details.get(&0)), keys, "{what}");
    }
}

/// One drift of R-I3: what the game writes over [`APPLIED`] (`None`: the file deleted), the
/// file after the revert (`None`: missing), whether the transaction closes.
type I3Case = (
    &'static str,
    Option<fn() -> String>,
    Option<fn() -> String>,
    bool,
);

const I3_CASES: [I3Case; 12] = [
    (
        "a foreign key changed",
        Some(|| APPLIED.replace("Volume=5", "Volume=9")),
        Some(|| String::from_utf8_lossy(INI_TEXT).replace("Volume=5", "Volume=9")),
        true,
    ),
    (
        "a foreign key inserted",
        Some(|| APPLIED.replace("Volume=5\r\n", "Volume=5\r\nMusic=3\r\n")),
        Some(|| {
            String::from_utf8_lossy(INI_TEXT).replace("Volume=5\r\n", "Volume=5\r\nMusic=3\r\n")
        }),
        true,
    ),
    (
        "the game reorders and drops whitespace",
        Some(|| {
            "[Audio]\r\nVolume=5\r\n[Display]\r\nWidth=1920\r\nFullscreen=1\r\nHeight=720\r\n[Zz Extra]\r\nMode=2\r\n".to_owned()
        }),
        Some(|| "[Audio]\r\nVolume=5\r\n[Display]\r\nWidth=1280\r\nHeight=720\r\n".to_owned()),
        true,
    ),
    (
        "the game writes LF and a BOM",
        Some(|| format!("\u{feff}{}", APPLIED.replace("\r\n", "\n"))),
        Some(|| {
            format!(
                "\u{feff}{}",
                String::from_utf8_lossy(INI_TEXT).replace("\r\n", "\n")
            )
        }),
        true,
    ),
    (
        "Rerun's key changed (E1 b): it stays, the rest goes back",
        Some(|| APPLIED.replace("Width=1920", "Width=1600")),
        Some(|| String::from_utf8_lossy(INI_TEXT).replace("Width=1280", "Width=1600")),
        true,
    ),
    (
        "Rerun's key removed (an old value): it stays removed",
        Some(|| APPLIED.replace("Width=1920\r\n", "")),
        Some(|| String::from_utf8_lossy(INI_TEXT).replace("Width=1280\r\n", "")),
        true,
    ),
    (
        "Rerun's new key removed: as before",
        Some(|| APPLIED.replace("Fullscreen=1\r\n", "")),
        Some(|| String::from_utf8_lossy(INI_TEXT).into_owned()),
        true,
    ),
    (
        "a key of the game in Rerun's new section: the header stays",
        Some(|| APPLIED.replace("Mode=2\r\n", "Mode=2\r\nOther=1\r\n")),
        Some(|| {
            format!(
                "{}[Zz Extra]\r\nOther=1\r\n",
                String::from_utf8_lossy(INI_TEXT)
            )
        }),
        true,
    ),
    ("deleted (E2 a)", None, None, true),
    (
        "a NUL",
        Some(|| format!("{APPLIED}\0")),
        Some(|| format!("{APPLIED}\0")),
        false,
    ),
    (
        "UTF-16",
        Some(|| "\u{fffe}".to_owned()),
        Some(|| "\u{fffe}".to_owned()),
        false,
    ),
    (
        "Rerun's key twice",
        Some(|| APPLIED.replace("Width=1920", "Width=1920\r\nWidth=1920")),
        Some(|| APPLIED.replace("Width=1920", "Width=1920\r\nWidth=1920")),
        false,
    ),
];

/// R-I3 as a check: every drift of [`I3_CASES`] reverted to exactly the expected bytes, the
/// transaction closed or left open as expected.
pub(crate) fn i3_check() -> Vec<String> {
    let mut f = Vec::new();
    for (what, change, want, closes) in I3_CASES {
        let env = ini_env(INI_TEXT);
        let t = match applied(&env, &[three()], what) {
            Ok(t) => t,
            Err(e) => {
                f.push(format!("RI3 {e}"));
                continue;
            }
        };
        if ini_now(&env).as_deref() != Some(APPLIED.as_bytes()) {
            f.push(format!("RI3 {what}: not {APPLIED:?} after the apply"));
        }
        // UTF-16 with its BOM as bytes (the fixture strings are UTF-8).
        let bytes = |s: String| {
            if s == "\u{fffe}" {
                b"\xFF\xFE[\x00".to_vec()
            } else {
                s.into_bytes()
            }
        };
        match change {
            Some(c) => put_ini(&env, &bytes(c())),
            None => env.sys.fake_fs().remove_abs(Path::new(&game(INI))).unwrap(),
        }
        let r = env.revert(&t);
        if (closed(&r) == Some(Closing::Reverted)) != closes {
            f.push(format!("RI3 {what}: closed {r:?}"));
        }
        let got = ini_now(&env);
        let want = want.map(|w| bytes(w()));
        if got != want {
            f.push(format!(
                "RI3 {what}: {:?}, want {:?}",
                got.map(|b| String::from_utf8_lossy(&b).into_owned()),
                want.map(|b| String::from_utf8_lossy(&b).into_owned())
            ));
        }
    }
    f
}

#[test]
fn r_i3_a_rewritten_file_gets_back_only_rerun_keys() {
    let f = i3_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-I3: a key someone changed taken as `Foreign` (the ADR 0020 text before E1 b) fails R-I3.
#[test]
fn k_i3_a_changed_key_as_foreign_breaks_ri3() {
    let _r = Reset(|| super::ini::knob::changed_foreign(false));
    super::ini::knob::changed_foreign(true);
    let f = i3_check();
    assert!(
        f.iter().any(|x| x.starts_with("RI3 Rerun's key changed")),
        "{f:#?}"
    );
}

/// The records of transaction `t`.
fn records(env: &Env, t: &TxnId) -> usize {
    crate::journal::tests::rewrite(env.sys.fake_fs(), &env.txn_dir(t), None, |_| {}).into()
}

/// Rewrites the head of `t` with `f` on its plan (the records follow the new head hash).
fn tamper_head(env: &Env, t: &TxnId, f: impl FnOnce(&mut plan::Plan)) -> u16 {
    let dir = env.txn_dir(t);
    let head = read_abs(&env.sys, &format!(r"{dir}\head.json"));
    let mut p: plan::Plan = serde_json::from_slice(&head).unwrap();
    f(&mut p);
    let bytes = serde_json::to_vec(&p).unwrap();
    crate::journal::tests::rewrite(env.sys.fake_fs(), &dir, Some(&bytes), |_| {})
}

/// The edits of the last op of `p`.
fn edits_of(p: &mut plan::Plan) -> &mut Vec<IniEdit> {
    match p.ops.last_mut() {
        Some(plan::Op::IniValue { edits, .. }) => edits,
        other => panic!("{other:?}"),
    }
}

/// R-I6 as a check: every tampering of the head or the records is `Blocked` (verify and revert)
/// and writes nothing; a swapped backup is `BackupMismatch`.
pub(crate) fn i6_check() -> Vec<String> {
    use crate::journal::tests::append_semantic_revert_intent;
    let mut f = Vec::new();
    type Tamper = (&'static str, fn(&Env, &TxnId));
    let tampers: [Tamper; 4] = [
        ("from/to without a temp name", |env, t| {
            append_semantic_revert_intent(env.sys.fake_fs(), &env.txn_dir(t), 0);
        }),
        // The game rewrote a foreign key, so the revert would rewrite: the old value of Width
        // in the head changed to one the backup does not hold (S-1 of P2-11 carried over).
        ("an old value in the head", |env, t| {
            put_ini(env, APPLIED.replace("Volume=5", "Volume=9").as_bytes());
            tamper_head(env, t, |p| {
                edits_of(p)[1].old = Old::Value(IniText::parse("666").unwrap());
            });
        }),
        ("a new key's old state in the head", |env, t| {
            put_ini(env, APPLIED.replace("Volume=5", "Volume=9").as_bytes());
            tamper_head(env, t, |p| {
                edits_of(p)[0].old = Old::Value(IniText::parse("0").unwrap());
            });
        }),
        ("the new content in the head", |env, t| {
            tamper_head(env, t, |p| {
                if let Some(plan::Op::IniValue { new, .. }) = p.ops.last_mut() {
                    new.len += 1;
                }
            });
        }),
    ];
    for (what, tamper) in tampers {
        let env = ini_env(INI_TEXT);
        let t = match applied(&env, &[three()], what) {
            Ok(t) => t,
            Err(e) => {
                f.push(format!("RI6 {e}"));
                continue;
            }
        };
        tamper(&env, &t);
        let after = env.snap();
        let n = records(&env, &t);
        if !matches!(
            env.try_verify(&t),
            Err(ExecError::Refused(Refusal::Blocked { .. }))
        ) {
            f.push(format!("RI6 {what}: verify not blocked"));
        }
        let r = env.revert(&t);
        if !matches!(&r, Err(ExecError::Refused(Refusal::Blocked { .. }))) {
            f.push(format!("RI6 {what}: revert {r:?}"));
        }
        if after != env.snap() {
            f.push(format!("RI6 {what}: the game folder changed"));
        }
        if records(&env, &t) != n {
            f.push(format!("RI6 {what}: a record written"));
        }
    }
    // A swapped backup: `BackupMismatch`, nothing written.
    let env = ini_env(INI_TEXT);
    match applied(&env, &[three()], "bin") {
        Ok(t) => {
            // Same length (the listing checks lengths only): the hash check of the binding finds it.
            let swapped = String::from_utf8_lossy(INI_TEXT).replace("1280", "1281");
            sys_put(
                &env.sys,
                &format!(r"{}\op-0000.bin", env.txn_dir(&t)),
                swapped.as_bytes(),
            );
            let after = env.snap();
            let r = env.revert(&t);
            if !matches!(
                &r,
                Err(ExecError::Journal(
                    crate::journal::JournalError::BackupMismatch(0)
                ))
            ) {
                f.push(format!("RI6 bin: revert {r:?}"));
            }
            if after != env.snap() {
                f.push("RI6 bin: the game folder changed".to_owned());
            }
        }
        Err(e) => f.push(format!("RI6 {e}")),
    }
    f
}

#[test]
fn r_i6_tampering_is_refused() {
    let f = i6_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-I4: without the binding of head and backup, a tampered old value is written by the
/// revert of a drifted file.
#[test]
fn k_i4_no_binding_breaks_ri6() {
    let _r = Reset(|| super::ini::knob::unbound(false));
    super::ini::knob::unbound(true);
    let f = i6_check();
    assert!(
        f.iter()
            .any(|x| x.starts_with("RI6 an old value in the head: revert")),
        "{f:#?}"
    );
}

/// R-I6: `from`/`to` on any other op kind is `Blocked` (the file and registry cases are in
/// `tests.rs`, `reg_tests.rs` and `layer_tests.rs`); a recorded `to` that someone changed
/// makes the revert observe again and write `unedit` of what is there, never anything else.
#[test]
fn r_i6_a_forged_to_only_makes_the_revert_observe_again() {
    let env = ini_env(INI_TEXT);
    let t = applied(&env, &[three()], "to").unwrap();
    let drift = APPLIED.replace("Volume=5", "Volume=9");
    put_ini(&env, drift.as_bytes());
    let forged = Digest {
        sha256: [7; 32],
        len: 3,
    };
    let from = Digest {
        sha256: sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(
            drift.as_bytes(),
        ))
        .into(),
        len: u64::try_from(drift.len()).unwrap(),
    };
    crate::journal::tests::append_revert_intent(
        env.sys.fake_fs(),
        &env.txn_dir(&t),
        0,
        Some(crate::sys::fs::TmpName::new(0xfeed, 1)),
        Some((from, forged)),
    );
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert_eq!(
        ini_now(&env).unwrap(),
        String::from_utf8_lossy(INI_TEXT)
            .replace("Volume=5", "Volume=9")
            .as_bytes()
    );
}

/// R-I7: stacking and LIFO: a `file_install` of the INI file and an `ini_set` on it in two
/// transactions; two `ini_set` transactions on one file.
#[test]
fn r_i7_stacking_and_lifo() {
    use crate::prim::tests::entry;
    // T1 installs a new INI over the game's (a config file), T2 sets a key in it.
    let pkg_ini = b"[Display]\r\nWidth=800\r\n".to_vec();
    let env = Env::new(finish(
        ini_base(INI_TEXT).file(super::tests::pkg("game.ini"), pkg_ini.clone()),
    ));
    let before = env.snap();
    let mut fi = crate::prim::tests::spec(vec![entry("game.ini", INI, &pkg_ini)]);
    fi.files[0].config = true;
    let t1 = applied(&env, &[Step::FileInstall(fi)], "T1").unwrap();
    let mid = env.snap();
    let t2 = applied(
        &env,
        &[ini_step(INI, &[("Display", "Width", "1024")])],
        "T2",
    )
    .unwrap();
    assert_eq!(ini_now(&env).unwrap(), b"[Display]\r\nWidth=1024\r\n");
    assert!(matches!(
        env.revert(&t1),
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == t2
    ));
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    same(&mid, &env.snap());
    assert_eq!(closed(&env.revert(&t1)), Some(Closing::Reverted));
    same(&before, &env.snap());
    // Two `ini_set` transactions on one file.
    let env = ini_env(INI_TEXT);
    let before = env.snap();
    let t1 = applied(
        &env,
        &[ini_step(INI, &[("Display", "Width", "1920")])],
        "T1",
    )
    .unwrap();
    let mid = env.snap();
    let t2 = applied(
        &env,
        &[ini_step(INI, &[("Display", "Height", "1080")])],
        "T2",
    )
    .unwrap();
    assert!(matches!(
        env.revert(&t1),
        Err(ExecError::Refused(Refusal::Later { .. }))
    ));
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    same(&mid, &env.snap());
    assert_eq!(closed(&env.revert(&t1)), Some(Closing::Reverted));
    same(&before, &env.snap());
}

/// R-I8: a value rule tightened after the apply (a character forbidden) blocks neither `verify`
/// nor the revert, which is exact; the same plan applied again is refused.
#[test]
fn r_i8_a_tightened_value_rule_never_blocks_the_revert() {
    let _r = Reset(|| ini::knob::forbid(None));
    let env = ini_env(INI_TEXT);
    let before = env.snap();
    let h = plan_all(&env, &[three()]);
    let t = env.applied(&h);
    ini::knob::forbid(Some('9'));
    assert!(env.verify(&t).iter().all(|(_, o)| *o == Observed::After));
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
    same(&before, &env.snap());
    assert!(matches!(
        env.apply(&h),
        Err(super::ApplyError::Refused(Refusal::Plan(
            plan::PlanError::Ini { .. }
        )))
    ));
    ini::knob::forbid(None);
    assert!(matches!(env.apply(&h), Ok(Outcome::Applied(_))));
}

/// The temp name `X` of op 0 of `t`.
fn x_of(env: &Env, t: &TxnId) -> crate::sys::fs::TmpName {
    let a = crate::prim::tests::app(&env.sys);
    let j = crate::journal::Journal::new(&a, crate::journal::InstanceTag::fixed(3));
    j.load(t, crate::journal::VerifyBackups::Length)
        .unwrap()
        .ops[&0]
        .intent
        .tmp
        .clone()
        .unwrap()
}

/// A file the game makes when it finds none of its own (M1).
const GAME_NEW: &[u8] = b"[Display]\r\nWidth=640\r\n";

/// M1 and K-I5 as a check on constructed states: after a power loss that kept `Done` on `C:`
/// while `D:` went back to phase B (`X.old` the old content, `X` the new one, the target
/// missing), the game made a new file; or the apply was interrupted after its rename (no
/// `Done`) and the game rewrote the file. Either is `Foreign`: `X.old`, the user's old file,
/// is kept and named (S6). Only `Done` with `X` gone is the cleanup of a completed apply (M1).
pub(crate) fn i5_check() -> Vec<String> {
    let mut f = Vec::new();
    for (what, with_done, x_there) in [
        ("phase B with Done, the game made a new file", true, true),
        ("phase C without Done, the game rewrote it", false, false),
    ] {
        let env = ini_env(INI_TEXT);
        let t = match applied(&env, &[three()], what) {
            Ok(t) => t,
            Err(e) => {
                f.push(format!("RI5 {e}"));
                continue;
            }
        };
        let x = x_of(&env, &t);
        let at = |n: &str| game(&format!(r"cfg\{n}"));
        sys_put(&env.sys, &at(x.old().as_str()), INI_TEXT);
        if x_there {
            sys_put(&env.sys, &at(x.as_str()), APPLIED.as_bytes());
        }
        put_ini(&env, GAME_NEW);
        if !with_done {
            // Only the intent is left (Done and Applied were never durable).
            for n in ["0002.json", "0003.json"] {
                env.sys
                    .fake_fs()
                    .remove_abs(Path::new(&format!(r"{}\{n}", env.txn_dir(&t))))
                    .unwrap();
            }
        }
        let r = env.revert(&t);
        match &r {
            Ok(rep)
                if rep.closed.is_none()
                    && rep.ops.iter().any(|o| {
                        o.observed == Observed::Foreign
                            && matches!(&o.detail, Some(Detail::Ini { previous: Some(p), .. })
                                if p.as_str() == x.old().as_str())
                    }) => {}
            r => f.push(format!("RI5 {what}: revert {r:?}")),
        }
        if try_read_abs(&env.sys, &at(x.old().as_str())).as_deref() != Some(INI_TEXT) {
            f.push(format!("RI5 {what}: the old file in X.old was lost"));
        }
        if ini_now(&env).as_deref() != Some(GAME_NEW) {
            f.push(format!("RI5 {what}: the game's file changed"));
        }
    }
    // M1 proper: `Done`, `X` gone, the game rewrote the applied file: the cleanup of `X.old`
    // and the semantic revert.
    let env = ini_env(INI_TEXT);
    match applied(&env, &[three()], "M1") {
        Ok(t) => {
            let x = x_of(&env, &t);
            let at = game(&format!(r"cfg\{}", x.old()));
            sys_put(&env.sys, &at, INI_TEXT);
            put_ini(&env, APPLIED.replace("Volume=5", "Volume=9").as_bytes());
            let r = env.revert(&t);
            if closed(&r) != Some(Closing::Reverted) {
                f.push(format!("RI5 M1: revert {r:?}"));
            }
            if try_read_abs(&env.sys, &at).is_some() {
                f.push("RI5 M1: X.old left".to_owned());
            }
            if ini_now(&env).as_deref()
                != Some(
                    String::from_utf8_lossy(INI_TEXT)
                        .replace("Volume=5", "Volume=9")
                        .as_bytes(),
                )
            {
                f.push("RI5 M1: content".to_owned());
            }
        }
        Err(e) => f.push(format!("RI5 {e}")),
    }
    f
}

#[test]
fn r_i5_m1_keeps_the_old_file_unless_the_apply_completed() {
    let f = i5_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-I5: the leftover `X.old` next to a drift deleted without M1's conditions (`Done`, `X`
/// gone) loses the user's old file.
#[test]
fn k_i5_a_loose_m1_breaks_ri5() {
    let _r = Reset(|| super::ini::knob::loose_m1(false));
    super::ini::knob::loose_m1(true);
    let f = i5_check();
    for what in [
        "phase B with Done, the game made a new file",
        "phase C without Done, the game rewrote it",
    ] {
        assert!(
            f.iter()
                .any(|x| x == &format!("RI5 {what}: the old file in X.old was lost")),
            "{what}: {f:#?}"
        );
    }
}

/// S2: only Rerun's own temp name of a rewrite and no `.old`, next to a file the game rewrote
/// again: the temp name goes and the file is observed anew (not `Foreign`). S6: a rewrite in
/// its phase B, then the game made a new file: `Foreign`, the `.old` named as the previous file.
#[test]
fn r_i_s2_s6_traces_of_a_rewrite() {
    use crate::journal::tests::append_revert_intent;
    let digest = |b: &[u8]| Digest {
        sha256: sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(b)).into(),
        len: u64::try_from(b.len()).unwrap(),
    };
    let drift = APPLIED.replace("Volume=5", "Volume=9");
    let to = ini::unedit(drift.as_bytes(), &edits3()).unwrap().bytes;
    let y = crate::sys::fs::TmpName::new(0xbeef, 4);
    let at = |n: &str| game(&format!(r"cfg\{n}"));
    // S2.
    let env = ini_env(INI_TEXT);
    let t = applied(&env, &[three()], "S2").unwrap();
    append_revert_intent(
        env.sys.fake_fs(),
        &env.txn_dir(&t),
        0,
        Some(y.clone()),
        Some((digest(drift.as_bytes()), digest(&to))),
    );
    sys_put(&env.sys, &at(y.as_str()), b"[Disp");
    let again = APPLIED.replace("Volume=5", "Volume=7");
    put_ini(&env, again.as_bytes());
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert_eq!(r.ops[0].observed, Observed::Drifted);
    assert!(
        try_read_abs(&env.sys, &at(y.as_str())).is_none(),
        "Y deleted"
    );
    assert_eq!(
        ini_now(&env).unwrap(),
        String::from_utf8_lossy(INI_TEXT)
            .replace("Volume=5", "Volume=7")
            .as_bytes()
    );
    // S6.
    let env = ini_env(INI_TEXT);
    let t = applied(&env, &[three()], "S6").unwrap();
    append_revert_intent(
        env.sys.fake_fs(),
        &env.txn_dir(&t),
        0,
        Some(y.clone()),
        Some((digest(drift.as_bytes()), digest(&to))),
    );
    sys_put(&env.sys, &at(&y.old().to_string()), drift.as_bytes());
    sys_put(&env.sys, &at(y.as_str()), &to);
    put_ini(&env, GAME_NEW);
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, None);
    let op = &r.ops[0];
    assert_eq!(op.observed, Observed::Foreign);
    assert!(
        op.left.iter().any(|l| l.as_str() == y.old().as_str()),
        "{op:?}"
    );
    assert!(
        matches!(&op.detail, Some(Detail::Ini { previous: Some(p), .. }) if *p == y.old()),
        "{op:?}"
    );
    assert_eq!(
        try_read_abs(&env.sys, &at(&y.old().to_string())).as_deref(),
        Some(drift.as_bytes()),
        "the previous file is kept"
    );
    assert_eq!(ini_now(&env).as_deref(), Some(GAME_NEW));
}

/// E5: the main executable is asked before apply and revert; the INI file itself is asked too.
#[test]
fn r_i_d4_the_game_must_be_closed() {
    let env = ini_env(INI_TEXT);
    let h = plan_all(&env, &[three()]);
    let held = env
        .sys
        .fake_fs()
        .map_image_as(4242, Path::new(&game("game.exe")))
        .unwrap();
    assert!(matches!(
        env.apply(&h),
        Err(super::ApplyError::Refused(Refusal::Busy(_)))
    ));
    drop(held);
    let t = env.applied(&h);
    let _held = env
        .sys
        .fake_fs()
        .map_image_as(4242, Path::new(&game("game.exe")))
        .unwrap();
    assert!(matches!(
        env.revert(&t),
        Err(ExecError::Refused(Refusal::Busy(_)))
    ));
}
