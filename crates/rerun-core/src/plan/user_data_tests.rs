//! P-U (P4-12, ADR 0020 amendment P4-12): the user data root in the plan format. P-U1 one form
//! on the wire (golden); P-U2 every rule of the fence refused on encode and, written by hand, on
//! decode with both rule sets; P-U3 every registry slot and firewall rule names a game root (the
//! check before P4-12 only kept them off the profiles root); P-U4 a profiles root, a user data
//! root and registry ops in one plan; P-U5 the preview; P-U6 the objects.

use super::super::{
    FileHash, FileState, Object, Op, PROFILES_ROOT_ID, Plan, PlanOrigin, PlanRoot, RootIx,
    RootKind, USER_DATA_NOTE, decode, decode_recorded, overlap, preview,
};
use super::{r, sha};
use crate::path::RootPath;
use crate::policy::firewall::Direction;
use crate::policy::ini::{IniEdit, IniName, IniText, Old};
use crate::policy::registry::RegSlot;
use crate::policy::root::{RootId, UserBase};
use crate::sys::fs::Attrs;

const GAME: &str = r"D:\Games\G";
const UD: &str = r"C:\Users\Player\Documents\My Games\G";

fn id(n: u128) -> RootId {
    RootId {
        volume_serial: 0xc,
        file_id: n,
    }
}

fn game_root() -> PlanRoot {
    PlanRoot {
        kind: RootKind::Game,
        path: RootPath::new(GAME).unwrap(),
        id: RootId {
            volume_serial: 0xd,
            file_id: 7,
        },
        origin: PlanOrigin::Manual,
        main_exe: Some(r("game.exe")),
        main_sha256: None,
    }
}

pub(crate) fn ud_root(path: &str, sub: &str, n: u128) -> PlanRoot {
    PlanRoot {
        kind: RootKind::UserData,
        path: RootPath::new(path).unwrap(),
        id: id(n),
        origin: PlanOrigin::UserFolder {
            base: UserBase::Documents,
            sub: r(sub),
        },
        main_exe: None,
        main_sha256: None,
    }
}

fn ini_op(root: u16, path: &str) -> Op {
    Op::IniValue {
        root: RootIx(root),
        path: r(path),
        old: FileState {
            sha256: sha(b"old ini"),
            len: 7,
            attrs: Attrs::default(),
        },
        new: FileHash {
            sha256: sha(b"new ini"),
            len: 7,
        },
        edits: vec![IniEdit {
            section: IniName::parse("Display").unwrap(),
            key: IniName::parse("Width").unwrap(),
            old: Old::Value(IniText::parse("1280").unwrap()),
            new: IniText::parse("1920").unwrap(),
        }],
    }
}

/// A game root and the user data root `Documents\My Games\G`, an INI op on each.
fn ud_plan() -> Plan {
    Plan {
        format: 1,
        source: None,
        roots: vec![game_root(), ud_root(UD, r"My Games\G", 9)],
        ops: vec![ini_op(0, "game.ini"), ini_op(1, "settings.ini")],
    }
}

fn with(f: &dyn Fn(&mut Plan)) -> Plan {
    let mut p = ud_plan();
    f(&mut p);
    p
}

/// `p` is refused on encode and, written by hand, on decode with both rule sets.
fn refused(p: &Plan, want: &str) {
    let e = p.encode().expect_err(want).to_string();
    assert!(e.contains(want), "encode, {want}: {e}");
    let bytes = serde_json::to_vec(p).unwrap();
    let e = decode(&bytes).expect_err(want).to_string();
    assert!(e.contains(want), "decode, {want}: {e}");
    let e = decode_recorded(&bytes).expect_err(want).to_string();
    assert!(e.contains(want), "decode_recorded, {want}: {e}");
}

#[test]
fn p_u1_one_form_on_the_wire() {
    let p = ud_plan();
    let b = p.encode().unwrap();
    assert_eq!(decode(b.bytes()).unwrap(), p);
    assert_eq!(decode_recorded(b.bytes()).unwrap(), p);
    let s = std::str::from_utf8(b.bytes()).unwrap();
    let want = concat!(
        r#"{"kind":"user_data","path":"C:\\Users\\Player\\Documents\\My Games\\G","#,
        r#""id":"000000000000000c-00000000000000000000000000000009","#,
        r#""origin":{"user_folder":{"base":"documents","sub":"My Games\\G"}},"main_exe":null}"#
    );
    assert!(s.contains(want), "{want} not in {s}");
    assert!(
        s.contains(r#""ini_value":{"root":1,"path":"settings.ini""#),
        "{s}"
    );
    for (from, to) in [
        (r#""base":"documents""#, r#""base":"saved_games""#),
        (r#""base":"documents""#, r#""base":"Documents""#),
        (r#""sub":"My Games\\G"}"#, r#""sub":"My Games\\G","x":1}"#),
        (r#""sub":"My Games\\G""#, r#""sub":"..\\G""#),
        (r#""kind":"user_data""#, r#""kind":"userdata""#),
    ] {
        let bad = s.replacen(from, to, 1);
        assert_ne!(bad, s, "{from}");
        assert!(decode_recorded(bad.as_bytes()).is_err(), "{to}");
    }
}

#[test]
fn p_u2_every_rule_of_the_fence() {
    refused(
        &with(&|p| p.roots[1].main_exe = Some(r("x.exe"))),
        "a user data root without main executable or the profiles identity",
    );
    refused(
        &with(&|p| p.roots[1].id = PROFILES_ROOT_ID),
        "a user data root without main executable or the profiles identity",
    );
    for sub in ["My Games", r"WindowsPowerShell\x", r"a\b\c\d\e"] {
        let path = format!(r"C:\Users\Player\Documents\{sub}");
        refused(
            &with(&|p| p.roots[1] = ud_root(&path, sub, 9)),
            "a user data folder its allowlist does not allow",
        );
    }
    refused(
        &with(&|p| p.roots[1] = ud_root(r"C:\Users\Player\Documents\My Games\H", r"My Games\G", 9)),
        "a user data root whose path does not end in its folder",
    );
    refused(
        &with(&|p| {
            p.roots[1] = ud_root(r"C:\Users\Player\Documents\XMy Games\G", r"My Games\G", 9)
        }),
        "a user data root whose path does not end in its folder",
    );
    // Review N2: a user data root without an op on it.
    refused(
        &with(&|p| {
            p.ops.pop();
        }),
        "a user data root without an op on it",
    );
    refused(
        &with(&|p| p.roots[1].origin = PlanOrigin::Manual),
        "the user data root, and only it, comes from a user folder",
    );
    refused(
        &with(&|p| {
            p.roots[1].kind = RootKind::Game;
            p.roots[1].main_exe = Some(r("x.exe"));
        }),
        "the user data root, and only it, comes from a user folder",
    );
    refused(
        &with(&|p| {
            p.roots
                .push(ud_root(r"E:\Docs\My Games\H", r"My Games\H", 10));
        }),
        "more than one user data root",
    );
    // Last, after a game root at 0.
    refused(
        &with(&|p| {
            p.roots.swap(0, 1);
            p.ops = vec![ini_op(1, "game.ini"), ini_op(0, "settings.ini")];
        }),
        "a user data root comes last, after the game root at index 0",
    );
    refused(
        &with(&|p| {
            let mut g2 = game_root();
            g2.path = RootPath::new(r"D:\Games\G2").unwrap();
            g2.id.file_id = 8;
            p.roots.push(g2);
        }),
        "a user data root comes last, after the game root at index 0",
    );
    // Only INI values on it (U1 a, L7).
    let pkg = || crate::plan::ContentRef::Package {
        id: "fix-pack".to_owned(),
        version: "1.0.2".to_owned(),
        file: r("x.dll"),
        sha256: sha(b"x"),
        len: 1,
        config: false,
    };
    for op in [
        Op::CreateDir {
            root: RootIx(1),
            path: r("Saves"),
        },
        Op::CreateFile {
            root: RootIx(1),
            path: r("x.dll"),
            content: pkg(),
            attrs: Attrs::default(),
        },
        Op::ReplaceFile {
            root: RootIx(1),
            path: r("x.dll"),
            old: FileState {
                sha256: sha(b"y"),
                len: 1,
                attrs: Attrs::default(),
            },
            content: pkg(),
            attrs: Attrs::default(),
        },
        Op::Hold {
            root: RootIx(1),
            path: r("x.dll"),
            content: pkg(),
        },
        Op::FirewallRule {
            root: RootIx(1),
            program: r("x.exe"),
            direction: Direction::Out,
        },
    ] {
        refused(
            &with(&|p| p.ops.insert(1, op.clone())),
            "only INI values in a user data folder",
        );
    }
}

/// P-U3, the check asked before P4-12 (lead): a `CompatLayers` or `GpuPreference` slot names a
/// game root, not just "not the profiles root"; a firewall rule too (`rule_check`).
#[test]
fn p_u3_registry_slots_and_rules_name_game_roots_only() {
    for slot in [
        RegSlot::CompatLayers {
            root: RootIx(1),
            exe: r("x.exe"),
        },
        RegSlot::GpuPreference {
            root: RootIx(1),
            exe: r("x.exe"),
        },
    ] {
        let op = match &slot {
            RegSlot::CompatLayers { .. } => Op::TokenList {
                slot: slot.clone(),
                old: None,
                add: vec![crate::policy::registry::TokenName::parse("HIGHDPIAWARE").unwrap()],
                new: "~ HIGHDPIAWARE".to_owned(),
                machine: Vec::new(),
            },
            _ => Op::GpuPref {
                slot: slot.clone(),
                old: None,
                pref: crate::policy::registry::GpuPref::HighPerformance,
                new: "GpuPreference=2;".to_owned(),
            },
        };
        refused(
            &with(&|p| p.ops.push(op.clone())),
            "a registry slot names an executable outside a game folder",
        );
        // The same op on the game root passes the fence (its own rules aside).
        let mut ok = ud_plan();
        let mut op0 = op.clone();
        match &mut op0 {
            Op::TokenList { slot, .. } | Op::GpuPref { slot, .. } => match slot {
                RegSlot::CompatLayers { root, .. } | RegSlot::GpuPreference { root, .. } => {
                    *root = RootIx(0);
                }
                RegSlot::GameValue { .. } => unreachable!(),
            },
            _ => unreachable!(),
        }
        ok.ops.push(op0);
        if let Err(e) = ok.encode() {
            assert!(!e.to_string().contains("outside a game folder"), "{e}");
        }
    }
}

/// P-U4: a Steam game, its launch profile, a user data root and a registry value in one plan;
/// the user data root after the profiles root, never before it.
#[test]
fn p_u4_profiles_user_data_and_registry_in_one_plan() {
    let pt = super::profiles_tests::lm_plan();
    let mut p = pt.clone();
    p.roots.push(ud_root(UD, r"My Games\G", 9));
    p.ops.insert(2, ini_op(2, "settings.ini"));
    p.ops.push(Op::SetValue {
        slot: super::reg_tests::slot("Vendor", "Game", &[], "Mode"),
        old: None,
        new: crate::plan::NewValue::Dword(1),
    });
    let b = p.encode().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decode(b.bytes()).unwrap(), p);
    assert_eq!(decode_recorded(b.bytes()).unwrap(), p);
    // The user data root between the game root and the profiles root: refused.
    let mut q = pt;
    q.roots.insert(1, ud_root(UD, r"My Games\G", 9));
    for o in &mut q.ops {
        if let Op::CreateFile { root, .. } = o
            && root.0 == 1
        {
            *root = RootIx(2);
        }
    }
    q.ops.insert(2, ini_op(1, "settings.ini"));
    assert!(q.encode().is_err());
    assert!(decode_recorded(&serde_json::to_vec(&q).unwrap()).is_err());
}

#[test]
fn p_u5_the_preview_names_the_root_and_says_the_note_once() {
    let v = preview(&ud_plan());
    assert_eq!(v.roots[1].kind, RootKind::UserData);
    assert_eq!(v.user_data, Some(USER_DATA_NOTE));
    let text = v.to_string();
    assert!(
        text.contains(r"root 1: C:\Users\Player\Documents\My Games\G (in your Documents folder)"),
        "{text}"
    );
    assert!(text.contains("edit ini 1:settings.ini"), "{text}");
    assert_eq!(text.matches("note: your Documents folder").count(), 1);
    let mut g = ud_plan();
    g.roots.pop();
    g.ops.pop();
    assert_eq!(preview(&g).user_data, None);
}

#[test]
fn p_u6_objects_lie_in_their_own_root() {
    let p = ud_plan();
    let a = Object::of(&p).unwrap();
    let mut q = ud_plan();
    q.ops = vec![ini_op(0, "settings.ini")];
    let b = Object::of(&q).unwrap();
    // `settings.ini` of the user data root and of the game root are two objects.
    assert!(!overlap(&a[1..], &b));
    assert!(overlap(&a, &Object::of(&ud_plan()).unwrap()));
}
