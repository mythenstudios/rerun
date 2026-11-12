//! `laa_patch` (P4-10, ADR 0020 amendment P4-10) through the Topo engine, against the fake.
//! Every image is synthetic (`detect::pe::testfx`), every Topo, folder and hash invented.
//!
//! - LA1 the acceptance round trip: Topo → plan (one `patch file` op) → apply → the flag set and
//!   the checksum valid → `verify` `After` → revert → the game folder identical.
//! - LA2 golden bytes: the edits of an image with a stored checksum (the flag byte and the
//!   checksum bytes that change) and of one without (the flag byte only).
//! - LA3 Steam's "Verify integrity of game files" puts the original back before the revert:
//!   `Before`, the revert closes identical; an update puts another build there: `Foreign`, left.
//! - LA4 every refusal: 64-bit, Large Address Aware already, a DLL, .NET, each protected
//!   section, another build than the Topo's, an executable that did not match, an entry without
//!   `sha256`, an admin-only folder (E1), anti-cheat (E4), a hard link, the step file.
//! - LA5 a signed executable is planned with a warning.
//! - LA6 the loader: draft only until reviewed, a `match.exes` entry in exactly its spelling with
//!   a `sha256`.
//! - LA7 one executable once: two picks that patch it plan it once.
//! - LA9 Smart App Control warns, never refuses (P4-13); a Valve header warns more strongly.
//! - [DEV] `dev_mafia2_laa_patch_matches_ntcore`: the real Mafia II original gives NTCore's bytes.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::{EngineError, Facts, Refusal, StepKind, Warning, plan, read_game};
use crate::catalog::check::{self, Rules};
use crate::catalog::model::Topo;
use crate::detect::pe::checksum::checksum;
use crate::detect::pe::layout as l;
use crate::detect::pe::testfx::{Builder as PeBuilder, put32};
use crate::detect::pe::{Limits, Pe};
use crate::exec::rebind_tests::rb_sys;
use crate::exec::tests::{Env, read_abs, snap_at};
use crate::hw::{self, GpuArchTable, SystemProfile};
use crate::journal::{Closing, Observed};
use crate::plan::{ByteEdit, ContentRef, Op, Pick};
use crate::policy::registry::RegPolicy;
use crate::policy::root::StoreDir;
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app, fr};
use crate::prim::{PlanCtx, StepFile};
use crate::sys::fake::FakeSystem;

const APP: u32 = 220;
const INDEX: [u8; 32] = [7; 32];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// The `CheckSum` field offset of a built image.
fn checksum_at(img: &crate::detect::pe::testfx::Image) -> usize {
    img.opt + l::OPT_CHECKSUM
}

/// An x86 game executable (not Large Address Aware) with 0x300 bytes of data and, if
/// `with_checksum`, a valid stored checksum.
fn game_exe(with_checksum: bool) -> Vec<u8> {
    let mut b = PeBuilder::x86();
    b.data = (0..0x300u32)
        .map(|i| u8::try_from(i * 37 % 256).unwrap())
        .collect();
    let img = b.build();
    let mut bytes = img.bytes.clone();
    if with_checksum {
        let c = checksum(&bytes, 0).unwrap();
        put32(&mut bytes, checksum_at(&img), c);
    }
    bytes
}

fn put(sys: &FakeSystem, rel: &str, data: &[u8]) {
    let abs = format!(r"{STEAM_GAME}\{rel}");
    let _ = sys.fake_fs().remove_abs(Path::new(&abs));
    sys.fake_fs().put_file(Path::new(&abs), data).unwrap();
    sys.sync_all();
}

/// Steam app 220 with `Game.exe` = `exe`.
fn sys_with(exe: &[u8]) -> FakeSystem {
    let sys = rb_sys();
    put(&sys, "Game.exe", exe);
    sys
}

/// A draft Topo matching `Game.exe` by `sha256` (or by `sha1` only), issue `memory` with the
/// variant `laa` patching `step_exe`.
fn topo_with(exe: &[u8], step_exe: &str, sha1_only: bool) -> Topo {
    use sha1::Sha1;
    let hash = if sha1_only {
        format!(r#""sha1":"{}""#, hex(&Sha1::digest(exe)))
    } else {
        format!(r#""sha256":"{}""#, hex(&sha(exe)))
    };
    let j = format!(
        r#"{{"format":1,"id":"invented-game","title":"Invented Game","status":"draft","rev":1,
"match":{{"steam_appid":{APP},"exes":[{{"path":"Game.exe",{hash},"api":"d3d9"}}]}},
"issues":[
 {{"id":"memory","title":"Out of memory in large levels","variants":[
   {{"id":"laa","status":"unverified","kind":"fix","steps":[{{"laa_patch":{{"exe":"{step_exe}"}}}}]}}]}},
 {{"id":"again","title":"The same patch in a second issue","variants":[
   {{"id":"laa","status":"unverified","kind":"fix","steps":[{{"laa_patch":{{"exe":"{step_exe}"}}}}]}}]}}
]}}"#
    );
    serde_json::from_str(&j).unwrap()
}

fn topo(exe: &[u8]) -> Topo {
    let t = topo_with(exe, "Game.exe", false);
    check::topo(&t, Rules::Source).unwrap();
    t
}

fn profile() -> SystemProfile {
    hw::read(
        &FakeSystem::builder().build().unwrap(),
        Some(GpuArchTable::builtin().unwrap()),
    )
}

fn plan_picks(sys: &FakeSystem, t: &Topo, p: &[&str]) -> Result<super::TopoPlan, EngineError> {
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let gf = read_game(&g, t);
    let a = app(sys);
    let ctx = PlanCtx {
        game: &g,
        app: Some(&a),
        steam_app: Some(APP),
        main_exe: None,
        reg: RegPolicy.reader(sys),
        app_path: None,
        user_data: None,
    };
    let picks: Vec<Pick> = p
        .iter()
        .map(|s| {
            let (issue, variant) = s.split_once('/').unwrap();
            Pick {
                issue: issue.to_owned(),
                variant: variant.to_owned(),
            }
        })
        .collect();
    plan(
        &INDEX,
        t,
        &Facts {
            profile: &profile(),
            table: Some(GpuArchTable::builtin().unwrap()),
            game: &gf,
            packages: &[],
        },
        &picks,
        &ctx,
    )
}

fn plan_on(sys: &FakeSystem, t: &Topo) -> Result<super::TopoPlan, EngineError> {
    plan_picks(sys, t, &["memory/laa"])
}

/// The one patch op of a plan: its edits and result hash.
fn patch_of(tp: &super::TopoPlan) -> (Vec<ByteEdit>, [u8; 32]) {
    match tp.plan.ops.as_slice() {
        [
            Op::ReplaceFile {
                content: ContentRef::Patch { edits, sha256, .. },
                ..
            },
        ] => (edits.clone(), *sha256),
        other => panic!("{other:?}"),
    }
}

fn store_plan(env: &Env, tp: &super::TopoPlan) -> crate::plan::PlanHash {
    let a = app(&env.sys);
    crate::plan::store(&a, &tp.plan.encode().unwrap()).unwrap()
}

fn refused(r: Result<super::TopoPlan, EngineError>, want: &str) {
    match r {
        Err(e) => assert!(e.to_string().contains(want), "{want:?} not in {e}"),
        Ok(tp) => panic!("planned, wanted {want:?}: {:?}", tp.plan.ops),
    }
}

// ---------- LA1, LA2 ----------

#[test]
fn la1_round_trip_sets_the_flag_and_restores_the_exe() {
    let exe = game_exe(true);
    let env = Env::new(sys_with(&exe));
    let sys = &env.sys;
    let t = topo(&exe);
    let before = snap_at(sys, STEAM_GAME);
    let tp = plan_on(sys, &t).unwrap();
    assert!(tp.warnings.is_empty(), "{:?}", tp.warnings);
    let shown = crate::plan::preview(&tp.plan).to_string();
    assert!(shown.contains("  0. patch file 0:Game.exe\n"), "{shown}");
    assert!(shown.contains("byte at 0x"), "{shown}");
    let (_, result) = patch_of(&tp);
    let txn = env.applied(&store_plan(&env, &tp));
    let now = read_abs(sys, &format!(r"{STEAM_GAME}\Game.exe"));
    assert_eq!(sha(&now), result);
    let pe = Pe::parse(std::io::Cursor::new(&now[..]), &Limits::DEFAULT).unwrap();
    assert!(pe.headers().large_address_aware());
    let f = pe.image_fields();
    assert_eq!(
        checksum(&now, f.checksum),
        Some(f.checksum),
        "valid checksum"
    );
    // Only the flag and the checksum changed.
    let diff: Vec<usize> = (0..exe.len()).filter(|&i| exe[i] != now[i]).collect();
    assert!(diff.len() <= 5 && !diff.is_empty(), "{diff:?}");
    assert_eq!(env.verify(&txn), [(0, Observed::After)]);
    let rep = env.revert(&txn).unwrap();
    assert_eq!(rep.closed, Some(Closing::Reverted));
    let after = snap_at(sys, STEAM_GAME);
    assert!(before == after, "not identical: {:#?}", before.diff(&after));
    assert_eq!(read_abs(sys, &format!(r"{STEAM_GAME}\Game.exe")), exe);
}

/// LA2: the golden edits. The flag is bit 5 of the low byte of `Characteristics` (0x0102 of the
/// fixture becomes 0x0122). A valid stored checksum grows by exactly 0x20 (one word of the sum
/// grew by 0x20, no carry), so only its low byte changes; a stored 0 stays 0.
#[test]
fn la2_golden_bytes_for_the_flag_and_the_checksum() {
    let exe = game_exe(true);
    let img = PeBuilder::x86().build();
    let flag_at = u64::try_from(img.coff + l::FILE_CHARACTERISTICS).unwrap();
    let ck_at = checksum_at(&img);
    let stored = u32::from_le_bytes(exe[ck_at..ck_at + 4].try_into().unwrap());
    // Pinned: the stored checksum of the fixture and the one after the patch.
    assert_eq!(stored, 0x0000_3B32, "fixture checksum {stored:#x}");
    let sys = sys_with(&exe);
    let tp = plan_on(&sys, &topo(&exe)).unwrap();
    let (edits, result) = patch_of(&tp);
    let ck = u64::try_from(ck_at).unwrap();
    assert_eq!(
        edits,
        [
            ByteEdit {
                offset: flag_at,
                old: 0x02,
                new: 0x22,
            },
            ByteEdit {
                offset: ck,
                old: 0x32,
                new: 0x52,
            },
        ]
    );
    let mut want = exe.clone();
    want[usize::try_from(flag_at).unwrap()] = 0x22;
    put32(&mut want, ck_at, stored + 0x20);
    assert_eq!(result, sha(&want));
    assert_eq!(checksum(&want, stored + 0x20), Some(stored + 0x20));

    // No stored checksum: the flag byte only, the field stays 0.
    let exe = game_exe(false);
    let sys = sys_with(&exe);
    let tp = plan_on(&sys, &topo(&exe)).unwrap();
    let (edits, result) = patch_of(&tp);
    assert_eq!(
        edits,
        [ByteEdit {
            offset: flag_at,
            old: 0x02,
            new: 0x22,
        }]
    );
    let mut want = exe.clone();
    want[usize::try_from(flag_at).unwrap()] = 0x22;
    assert_eq!(result, sha(&want));
}

// ---------- LA3 ----------

#[test]
fn la3_steam_restoring_the_exe_is_before_an_update_is_foreign() {
    let exe = game_exe(true);
    let env = Env::new(sys_with(&exe));
    let sys = &env.sys;
    let before = snap_at(sys, STEAM_GAME);
    let txn = env.applied(&store_plan(&env, &plan_on(sys, &topo(&exe)).unwrap()));
    // "Verify integrity of game files": Steam writes the original back.
    put(sys, "Game.exe", &exe);
    assert_eq!(env.verify(&txn), [(0, Observed::Before)]);
    let rep = env.revert(&txn).unwrap();
    assert_eq!(rep.closed, Some(Closing::Reverted));
    assert_eq!(rep.ops[0].observed, Observed::Before);
    let after = snap_at(sys, STEAM_GAME);
    assert!(before == after, "not identical: {:#?}", before.diff(&after));

    // An update brings another build: left as it is, open until forget.
    let env = Env::new(sys_with(&exe));
    let sys = &env.sys;
    let txn = env.applied(&store_plan(&env, &plan_on(sys, &topo(&exe)).unwrap()));
    let mut update = game_exe(true);
    update[0x350] ^= 0xFF;
    put(sys, "Game.exe", &update);
    assert_eq!(env.verify(&txn), [(0, Observed::Foreign)]);
    let rep = env.revert(&txn).unwrap();
    assert_eq!(rep.closed, None);
    assert_eq!(read_abs(sys, &format!(r"{STEAM_GAME}\Game.exe")), update);
    env.forget(&txn).unwrap();
}

// ---------- LA4 ----------

#[test]
fn la4_every_refusal() {
    let image = |f: &dyn Fn(&mut PeBuilder)| {
        let mut b = PeBuilder::x86();
        f(&mut b);
        b.build().bytes
    };
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (
            PeBuilder::x64().build().bytes,
            "it is not a 32-bit (x86) executable",
        ),
        (
            image(&|b| b.characteristics |= l::FILE_LARGE_ADDRESS_AWARE),
            "Large Address Aware already",
        ),
        (image(&|b| b.characteristics |= l::FILE_DLL), "it is a DLL"),
        (
            image(&|b| b.dirs = vec![(l::DIR_COM_DESCRIPTOR, 0x2000, 0x48)]),
            "a .NET executable",
        ),
    ];
    for (exe, want) in cases {
        let sys = sys_with(&exe);
        refused(plan_on(&sys, &topo(&exe)), want);
    }
    // Every protected section, as the data section and as a later one, in any case.
    for (name, system) in crate::prim::laa_patch::PROTECTED_SECTIONS {
        let mut raw = [0u8; 8];
        raw[..name.len()].copy_from_slice(name.as_bytes());
        let mut upper = raw;
        upper.make_ascii_uppercase();
        for exe in [
            image(&|b| b.data_name = raw),
            image(&|b| {
                b.extra_sections = 2;
                b.extra_names = vec![*b".text\0\0\0", upper];
            }),
        ] {
            let sys = sys_with(&exe);
            refused(
                plan_on(&sys, &topo(&exe)),
                &format!("of {system}, a protected build"),
            );
        }
    }
    let exe = game_exe(true);
    // Another build than the Topo's: no match, nothing planned.
    let sys = sys_with(&game_exe(false));
    assert!(matches!(
        plan_on(&sys, &topo(&exe)),
        Err(EngineError::NoMatch(_))
    ));
    // Matched by SHA-1 only (a Topo that skipped the loader): the step needs the SHA-256.
    let sys = sys_with(&exe);
    refused(
        plan_on(&sys, &topo_with(&exe, "Game.exe", true)),
        "names no sha256",
    );
    // An executable that is no entry of match.exes, or in another spelling.
    refused(
        plan_on(&sys, &topo_with(&exe, "game.exe", false)),
        "no executable of the Topo's match.exes",
    );
    // E1 = 0: an admin-only game folder.
    let sys = sys_with(&exe);
    sys.fake_fs()
        .set_user_writable(Path::new(STEAM_GAME), false)
        .unwrap();
    sys.sync_all();
    refused(
        plan_on(&sys, &topo(&exe)),
        "only be changed with administrator rights",
    );
    // E4: anti-cheat refuses the step.
    let sys = sys_with(&exe);
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\BattlEye")))
        .unwrap();
    sys.sync_all();
    match plan_on(&sys, &topo(&exe)) {
        Err(EngineError::Refused {
            why: Refusal::AntiCheat(StepKind::LaaPatch),
            ..
        }) => {}
        r => panic!("{r:?}"),
    }
    // A hard-linked executable (a mod manager's).
    let sys = sys_with(&exe);
    sys.fake_fs()
        .put_hardlink(
            Path::new(&format!(r"{STEAM_GAME}\Game.exe")),
            Path::new(&format!(r"{STEAM_GAME}\Game.bak")),
        )
        .unwrap();
    sys.sync_all();
    refused(plan_on(&sys, &topo(&exe)), "hard-linked");
    // A step file never carries the step (its executable and hash come from a Topo).
    let file = format!(
        r#"{{"format":1,"game":{{"steam":220}},"main_exe":"Game.exe","steps":[{{"laa_patch":{{"exe":"Game.exe","sha256":"{}"}}}}]}}"#,
        hex(&sha(&exe)).to_lowercase()
    );
    let e = StepFile::parse(file.as_bytes()).unwrap_err();
    assert!(
        e.to_string()
            .contains("laa_patch comes only from a Topo of the signed index"),
        "{e}"
    );
}

// ---------- LA5 ----------

#[test]
fn la5_a_signed_exe_is_planned_with_a_warning() {
    let mut b = PeBuilder::x86();
    b.dirs = vec![(l::DIR_SECURITY, 0x400, 0x200)];
    let exe = b.build().bytes;
    let sys = sys_with(&exe);
    let tp = plan_on(&sys, &topo(&exe)).unwrap();
    assert!(
        matches!(tp.warnings.as_slice(), [Warning::SignedExe { exe }] if exe.as_str() == "Game.exe"),
        "{:?}",
        tp.warnings
    );
    patch_of(&tp);
}

// ---------- LA6 ----------

#[test]
fn la6_the_loader_wants_a_sha256_anchor() {
    let exe = game_exe(true);
    let draft = topo_with(&exe, "Game.exe", false);
    check::topo(&draft, Rules::Source).unwrap();
    // Reviewed (P4-10): an active Topo carries it, also by the release rules.
    const { assert!(check::LAA_PATCH_REVIEWED, "laa_patch is reviewed") };
    let mut active = draft.clone();
    active.status = crate::catalog::model::Status::Active;
    check::topo(&active, Rules::Source).unwrap();
    check::topo(&active, Rules::Release).unwrap();
    // Exactly the spelling of a match.exes entry, and that entry with a sha256.
    let e = check::topo(&topo_with(&exe, "game.exe", false), Rules::Source).unwrap_err();
    assert!(e.what.contains("an executable of match.exes"), "{e}");
    let e = check::topo(&topo_with(&exe, "Game.exe", true), Rules::Source).unwrap_err();
    assert!(e.what.contains("needs a sha256"), "{e}");
}

// ---------- LA7 ----------

#[test]
fn la7_one_executable_is_patched_once() {
    let exe = game_exe(true);
    let sys = sys_with(&exe);
    let tp = plan_picks(&sys, &topo(&exe), &["memory/laa", "again/laa"]).unwrap();
    patch_of(&tp);
    assert_eq!(tp.steps.len(), 1, "{:?}", tp.steps);
}

// ---------- LA8 ----------

/// LA8 (P4 lead condition R5): after the patch the executable has another SHA-256, yet a live
/// transaction's patch of the Topo's build still counts as that build (`read_game_with`,
/// `exec::patched_now`); `laa_patch` again is refused with the reason; after the revert, or once
/// the transaction is forgotten, nothing is derived any more.
#[test]
fn la8_a_live_patch_still_matches_its_build() {
    use super::{ExeState, read_game_with};
    let exe = game_exe(true);
    let env = Env::new(sys_with(&exe));
    let sys = &env.sys;
    let t = topo(&exe);
    let facts_now = || {
        let fr = fr(sys);
        let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
        let g = store.game(&fr, "G").unwrap();
        let patched = crate::exec::patched_now(&app(sys), g.id());
        (read_game(&g, &t), read_game_with(&g, &t, &patched), patched)
    };
    let txn = env.applied(&store_plan(&env, &plan_on(sys, &t).unwrap()));
    let (plain, derived, patched) = facts_now();
    assert_eq!(plain.exes[0].state, ExeState::Mismatch, "another hash now");
    assert_eq!(patched.len(), 1);
    assert_eq!(patched[0].txn, txn);
    assert_eq!(derived.exes[0].state, ExeState::Match);
    assert_eq!(derived.exes[0].patched_by, Some(txn));
    assert_eq!(derived.main_exe().unwrap().as_str(), "Game.exe");
    // Planned again on the derived match: refused, with the reason.
    {
        let fr = fr(sys);
        let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
        let g = store.game(&fr, "G").unwrap();
        let a = app(sys);
        let ctx = PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: Some(APP),
            main_exe: None,
            reg: RegPolicy.reader(sys),
            app_path: None,
            user_data: None,
        };
        let r = plan(
            &INDEX,
            &t,
            &Facts {
                profile: &profile(),
                table: Some(GpuArchTable::builtin().unwrap()),
                game: &derived,
                packages: &[],
            },
            &[Pick {
                issue: "memory".to_owned(),
                variant: "laa".to_owned(),
            }],
            &ctx,
        );
        refused(r, "has patched it already");
    }
    // Another content at the path is not the patch's result: no match.
    let mut other = game_exe(true);
    other[0x350] ^= 0xFF;
    put(sys, "Game.exe", &other);
    assert_eq!(facts_now().1.exes[0].state, ExeState::Mismatch);
    // Back to the patched bytes, then reverted: the original matches by its own hash.
    put(sys, "Game.exe", &{
        let mut p = exe.clone();
        let (edits, _) = patch_of(&plan_on(&sys_with(&exe), &t).unwrap());
        for e in edits {
            p[usize::try_from(e.offset).unwrap()] = e.new;
        }
        p
    });
    assert_eq!(facts_now().1.exes[0].patched_by, Some(txn));
    assert_eq!(env.revert(&txn).unwrap().closed, Some(Closing::Reverted));
    let (plain, derived, patched) = facts_now();
    assert!(patched.is_empty());
    assert_eq!(plain.exes[0].state, ExeState::Match);
    assert_eq!(derived.exes[0].patched_by, None);

    // A forgotten transaction derives nothing.
    let txn = env.applied(&store_plan(&env, &plan_on(sys, &t).unwrap()));
    put(sys, "Game.exe", b"MZ an update");
    env.revert(&txn).unwrap();
    env.forget(&txn).unwrap();
    assert!(facts_now().2.is_empty());
}

// ---------- LA9 ----------

/// LA9 (user decision of 2026-11-11, P4-13, which reverses the refusal of 2026-11-10): while
/// Smart App Control enforces, is in evaluation mode, or its state cannot be read, `laa_patch` is
/// planned with one warning naming the state; off (or absent) changes nothing. The report
/// refuses nothing. An executable with a Valve header in its DOS stub adds the stronger warning,
/// only while Smart App Control is not off.
#[test]
fn la9_smart_app_control_warns() {
    use crate::hw::SacState;
    use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
    let profile_with = |v: Option<RegValue>| {
        let key = RegKey::new(
            Hive::LocalMachine,
            RegView::Native,
            r"SYSTEM\CurrentControlSet\Control\CI\Policy",
        );
        let mut b = FakeSystem::builder().key(key.clone());
        if let Some(v) = v {
            b = b.value(key, "VerifiedAndReputablePolicyState", v);
        }
        hw::read(&b.build().unwrap(), Some(GpuArchTable::builtin().unwrap()))
    };
    let run = |exe: &[u8], p: &SystemProfile| {
        let sys = sys_with(exe);
        let t = topo(exe);
        let fr = fr(&sys);
        let store = StoreDir::open(&sys, &fr, Path::new(STEAM_LIB)).unwrap();
        let g = store.game(&fr, "G").unwrap();
        let gf = read_game(&g, &t);
        let a = app(&sys);
        let ctx = PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: Some(APP),
            main_exe: None,
            reg: RegPolicy.reader(&sys),
            app_path: None,
            user_data: None,
        };
        let facts = Facts {
            profile: p,
            table: Some(GpuArchTable::builtin().unwrap()),
            game: &gf,
            packages: &[],
        };
        let report = super::report(&t, &facts).unwrap();
        assert_eq!(report.issues[0].variants[0].refused, None);
        let tp = plan(
            &INDEX,
            &t,
            &facts,
            &[Pick {
                issue: "memory".to_owned(),
                variant: "laa".to_owned(),
            }],
            &ctx,
        )
        .unwrap();
        patch_of(&tp);
        tp.warnings
    };
    let plain = game_exe(true);
    // A Valve header in the DOS stub (the builder's NT headers start at 0x80).
    let mut valve = plain.clone();
    valve[0x40..0x44].copy_from_slice(b"VLV\0");
    let game = || crate::path::RelPath::parse("Game.exe").unwrap();
    for (v, state) in [
        (RegValue::Dword(1), SacState::Enforce),
        (RegValue::Dword(2), SacState::Evaluation),
        (RegValue::Dword(7), SacState::Unknown),
    ] {
        let p = profile_with(Some(v));
        assert_eq!(p.sac, state);
        assert_eq!(run(&plain, &p), [Warning::SmartAppControl { state }]);
        assert_eq!(
            run(&valve, &p),
            [
                Warning::SmartAppControl { state },
                Warning::SteamPerUserExe { exe: game() }
            ]
        );
    }
    // Off, or absent: nothing, a Valve header neither.
    for v in [Some(RegValue::Dword(0)), None] {
        let p = profile_with(v);
        assert!(run(&plain, &p).is_empty());
        assert!(run(&valve, &p).is_empty());
    }
}

/// [DEV] (P4-13): Rerun's `laa_patch` of the original Mafia II Classic executable
/// (`RERUN_DEV_MAFIA2_ORIG`, the `mafia2.exe.Backup` NTCore's 4GB Patch leaves) gives exactly
/// NTCore's output, SHA-256 `0895CE1B…`: the flag at `0x15e` and the true image checksum at
/// `0x1a0`, 4 bytes. The file is only read (into the fake system); nothing is written anywhere.
#[test]
#[ignore = "[DEV] reads a game executable of the developer machine; set RERUN_DEV_MAFIA2_ORIG"]
fn dev_mafia2_laa_patch_matches_ntcore() {
    const NTCORE: &str = "0895CE1B54151F03C4B0F6E286D10F5F84884B6671EA9B8494D655414572D4E3";
    const ORIGINAL_PREFIX: &str = "C7B719906AA01059";
    #[expect(
        clippy::disallowed_methods,
        reason = "[DEV] test: the developer names the original executable"
    )]
    let path = std::env::var("RERUN_DEV_MAFIA2_ORIG")
        .expect("set RERUN_DEV_MAFIA2_ORIG to the path of mafia2.exe.Backup");
    #[expect(
        clippy::disallowed_methods,
        reason = "[DEV] test: reads the original once, read only, into the fake system"
    )]
    let exe = std::fs::read(&path).unwrap();
    assert!(
        hex(&sha(&exe)).starts_with(ORIGINAL_PREFIX),
        "not the measured original: {}",
        hex(&sha(&exe))
    );
    let sys = sys_with(&exe);
    let t = topo(&exe);
    let tp = plan_on(&sys, &t).unwrap();
    let (edits, planned) = patch_of(&tp);
    let mut out = exe;
    for e in &edits {
        let at = usize::try_from(e.offset).unwrap();
        assert_eq!(out[at], e.old);
        out[at] = e.new;
    }
    println!("RERUN_DEV_MAFIA2_EDITS: {edits:?}");
    println!("RERUN_DEV_MAFIA2_SHA256: {}", hex(&sha(&out)));
    assert_eq!(sha(&out), planned);
    assert_eq!(hex(&sha(&out)), NTCORE);
    assert_eq!(
        edits.iter().map(|e| e.offset).collect::<Vec<_>>(),
        [0x15e, 0x1a0, 0x1a1, 0x1a2]
    );
    // The Valve header and Valve's signature are seen; Smart App Control is off here
    // (`profile()` reads an empty fake registry), so only the signature warns.
    let fields = Pe::parse(std::io::Cursor::new(&out[..]), &Limits::DEFAULT)
        .unwrap()
        .image_fields();
    assert!(fields.valve_stub);
    assert!(fields.certificates.is_some());
    assert_eq!(
        tp.warnings,
        [Warning::SignedExe {
            exe: crate::path::RelPath::parse("Game.exe").unwrap()
        }]
    );
}

// ---------- LA10, LA11 (P4-10 review follow-ups) ----------

/// LA10 (review S2): two builds name `Game.exe`; the step patches the one that matched, with its
/// SHA-256. The loader wants a `sha256` on every entry of that spelling.
#[test]
fn la10_two_builds_of_one_path() {
    let installed = game_exe(true);
    let mut other = game_exe(true);
    other[0x350] ^= 0xFF;
    let sys = sys_with(&installed);
    let mut v: serde_json::Value =
        serde_json::to_value(topo_with(&installed, "Game.exe", false)).unwrap();
    let mut first = v["match"]["exes"][0].clone();
    first["sha256"] = hex(&sha(&other)).into();
    v["match"]["exes"].as_array_mut().unwrap().insert(0, first);
    let t: Topo = serde_json::from_value(v.clone()).unwrap();
    check::topo(&t, Rules::Source).unwrap();
    let tp = plan_on(&sys, &t).unwrap();
    match tp.steps.as_slice() {
        [crate::prim::Step::LaaPatch(s)] => assert_eq!(s.sha256, sha(&installed)),
        other => panic!("{other:?}"),
    }
    patch_of(&tp);
    // One entry of that spelling without a sha256: refused by the loader.
    let e = v["match"]["exes"][0].as_object_mut().unwrap();
    e.remove("sha256");
    e.insert("sha1".to_owned(), "0".repeat(40).into());
    let t: Topo = serde_json::from_value(v).unwrap();
    let e = check::topo(&t, Rules::Source).unwrap_err();
    assert!(
        e.what
            .contains("every match.exes entry of it needs a sha256"),
        "{e}"
    );
}

/// LA11 (review, both): a `laa_patch` and a `firewall_rule` of the same executable in one plan
/// are refused with the way that works (the rule first, in its own plan; `exec/fw_tests.rs`
/// `f8_a_rule_first_then_the_patch` shows that order).
#[test]
fn la11_a_patch_and_a_rule_of_one_exe_in_one_plan() {
    let exe = game_exe(true);
    let sys = sys_with(&exe);
    let mut v: serde_json::Value =
        serde_json::to_value(topo_with(&exe, "Game.exe", false)).unwrap();
    // Another variant ID: one ID names one fix across issues (P5-4).
    v["issues"][1]["variants"][0]["id"] = serde_json::json!("block");
    v["issues"][1]["variants"][0]["steps"] =
        serde_json::json!([{"firewall_rule": {"exe": "Game.exe", "direction": "out"}}]);
    let t: Topo = serde_json::from_value(v).unwrap();
    check::topo(&t, Rules::Source).unwrap();
    refused(
        plan_picks(&sys, &t, &["memory/laa", "again/block"]),
        "plan and apply the firewall rule on its own first, then laa_patch in a second plan",
    );
}
