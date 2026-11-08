//! LM-P (P3-3a, ADR 0020 amendment P3-3): the profiles root and inline content in the plan
//! format. LM-P1 one form on the wire (golden); LM-P2 every rule of the fence refused on encode
//! and, written by hand, on decode, the form rules under both rule sets and the rules of
//! `Rules::Current` only by the apply decode (senior-dev condition B1); LM-P3 the main
//! executable rule only for game roots, old heads unchanged; LM-P4 the preview.

use rerun_proto::cpu::rule::{Bitness, CpuRule, Mode, Prefer};
use rerun_proto::profile::{self as proto, LaunchProfile, Method};

use super::super::{
    ContentRef, FileState, MAX_INLINE_BYTES, NewValue, Op, PROFILES_ROOT_ID, Plan, PlanError,
    PlanOrigin, PlanRoot, ProfilePreview, RootIx, RootKind, decode, decode_recorded, preview,
    preview_head, profile_file, profile_id,
};
use super::reg_tests::slot;
use super::{r, sha};
use crate::path::RootPath;
use crate::policy::registry::RegSlot;
use crate::policy::root::RootId;
use crate::sys::fs::Attrs;

const GAME: &str = r"D:\SteamLibrary\steamapps\common\G";
const PROFILES: &str = r"C:\Users\Player\AppData\Local\Rerun\profiles";

/// A direct profile for `start` with a hard rule of at most `max` threads.
pub(crate) fn profile_bytes(start: &str, max: u16) -> Vec<u8> {
    proto::encode(&LaunchProfile {
        method: Method::Direct,
        start: start.to_owned(),
        target: start.to_owned(),
        bitness: Bitness::X64,
        priority: None,
        watch_timeout_s: 120,
        cpu: Some(CpuRule {
            max_threads: Some(max),
            prefer: Prefer::Any,
            single_l3: false,
            prefer_l3: None,
            smt: true,
            mode: Mode::Hard,
        }),
    })
    .unwrap()
}

pub(crate) fn inline(bytes: Vec<u8>) -> ContentRef {
    ContentRef::Inline {
        sha256: sha(&bytes),
        bytes,
    }
}

fn game_root() -> PlanRoot {
    PlanRoot {
        kind: RootKind::Game,
        path: RootPath::new(GAME).unwrap(),
        id: RootId {
            volume_serial: 0xd,
            file_id: 8,
        },
        origin: PlanOrigin::Steam {
            store: RootPath::new(r"D:\SteamLibrary").unwrap(),
            store_id: RootId {
                volume_serial: 0xd,
                file_id: 1,
            },
            app_id: 220,
            installdir: r("G"),
        },
        main_exe: Some(r("game.exe")),
    }
}

fn profiles_root() -> PlanRoot {
    PlanRoot {
        kind: RootKind::Profiles,
        path: RootPath::new(PROFILES).unwrap(),
        id: PROFILES_ROOT_ID,
        origin: PlanOrigin::AppDir,
        main_exe: None,
    }
}

/// A plan of app 220: its profile (op 0) and a package file in the game folder.
fn lm_plan() -> Plan {
    Plan {
        format: 1,
        roots: vec![game_root(), profiles_root()],
        ops: vec![
            Op::CreateFile {
                root: RootIx(1),
                path: profile_file(profile_id(220)),
                content: inline(profile_bytes(&format!(r"{GAME}\game.exe"), 8)),
                attrs: Attrs::default(),
            },
            Op::CreateFile {
                root: RootIx(0),
                path: r("x.dll"),
                content: ContentRef::Package {
                    id: "fix-pack".to_owned(),
                    version: "1.0.2".to_owned(),
                    file: r("x.dll"),
                    sha256: sha(b"x"),
                    len: 1,
                    config: false,
                },
                attrs: Attrs::default(),
            },
        ],
    }
}

/// `lm_plan` with the profile op a replace of `old`.
fn lm_replace(old: &[u8]) -> Plan {
    let mut p = lm_plan();
    let Op::CreateFile { content, .. } = p.ops.remove(0) else {
        unreachable!()
    };
    p.ops.insert(
        0,
        Op::ReplaceFile {
            root: RootIx(1),
            path: profile_file(profile_id(220)),
            old: FileState {
                sha256: sha(old),
                len: u64::try_from(old.len()).unwrap(),
                attrs: Attrs {
                    readonly: true,
                    hidden: false,
                    system: false,
                },
            },
            content,
            attrs: Attrs::default(),
        },
    );
    p
}

/// The profile op of `p`.
fn op0(p: &mut Plan) -> &mut Op {
    &mut p.ops[0]
}

/// Sets the content of the profile op.
fn set_content(p: &mut Plan, c: ContentRef) {
    if let Op::CreateFile { content, .. } | Op::ReplaceFile { content, .. } = op0(p) {
        *content = c;
    }
}

#[test]
fn lm_p1_profiles_root_and_inline_content_round_trip_in_one_form() {
    // The ID of a Steam app (user decision E1 a), pinned.
    assert_eq!(
        profile_id(220).to_string(),
        "323ad79fbc93ca3e73b0b152a5d44616"
    );
    assert_eq!(
        profile_id(40960).to_string(),
        "79ac7ab577e4075a93c65cf04abd5211"
    );
    assert_eq!(
        profile_file(profile_id(221)).as_str(),
        "e57797f532b89fafe92362e799c95b4d.profile"
    );
    for p in [lm_plan(), lm_replace(b"an orphaned profile")] {
        let b = p.encode().unwrap();
        assert_eq!(decode(b.bytes()).unwrap(), p);
        assert_eq!(decode_recorded(b.bytes()).unwrap(), p);
        let s = std::str::from_utf8(b.bytes()).unwrap();
        assert!(
            s.contains(
                r#"{"kind":"profiles","path":"C:\\Users\\Player\\AppData\\Local\\Rerun\\profiles","id":"0000000000000000-00000000000000000000000000000000","origin":"app_dir","main_exe":null}"#
            ),
            "{s}"
        );
        let (Op::CreateFile { content, .. } | Op::ReplaceFile { content, .. }) = &p.ops[0] else {
            unreachable!()
        };
        let ContentRef::Inline { bytes, sha256 } = content else {
            unreachable!()
        };
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert!(hex.starts_with("72657275"), "rerun-profile 1");
        assert!(
            s.contains(r#""path":"323ad79fbc93ca3e73b0b152a5d44616.profile","#),
            "{s}"
        );
        let want = format!(
            r#""content":{{"inline":{{"bytes":"{hex}","sha256":"{}"}}}},"attrs":{{"readonly":false,"hidden":false,"system":false}}"#,
            crate::wire::hex32::to_string(sha256)
        );
        assert!(s.contains(&want), "{s}");
        // Upper-case hex is another form.
        let up = s.replace(&hex, &hex.to_uppercase());
        assert!(decode(up.as_bytes()).is_err());
    }
}

/// `p` is refused on encode and, written by hand, by the apply decode; `recorded`: also by
/// the decode of a recorded head (a form rule), else accepted there (a rule of `Current`).
fn refused(what: &str, p: &Plan, recorded: bool) {
    let e = p.encode().expect_err(what);
    assert!(
        matches!(e, PlanError::Invalid { .. }),
        "encode, {what}: {e}"
    );
    let bytes = serde_json::to_vec(p).unwrap();
    assert!(decode(&bytes).is_err(), "decode, {what}");
    assert_eq!(
        decode_recorded(&bytes).is_err(),
        recorded,
        "decode_recorded, {what}: {:?}",
        decode_recorded(&bytes).err()
    );
}

#[test]
fn lm_p2_every_rule_of_the_fence_is_refused_with_its_rule_set() {
    type Mutate = fn(&mut Plan);
    let form: Vec<(&str, Mutate)> = vec![
        ("profiles root of a manual origin", |p| {
            p.roots[1].origin = PlanOrigin::Manual;
        }),
        ("profiles root of a Steam origin", |p| {
            p.roots[1].origin = p.roots[0].origin.clone();
        }),
        ("app_dir origin of a game root", |p| {
            p.roots[1].kind = RootKind::Game;
        }),
        ("profiles root with an identity", |p| {
            p.roots[1].id.file_id = 9;
        }),
        ("profiles root with a main executable", |p| {
            p.roots[1].main_exe = Some(r("game.exe"));
        }),
        ("two profiles roots", |p| {
            let mut second = profiles_root();
            second.path = RootPath::new(r"E:\Rerun\profiles").unwrap();
            p.roots.push(second);
        }),
        ("profiles root elsewhere", |p| {
            p.roots[1].path = RootPath::new(r"C:\Users\Player\AppData\Local\Rerun\plans").unwrap();
        }),
        ("profiles root first", |p| {
            p.roots.swap(0, 1);
            for op in &mut p.ops {
                if let Op::CreateFile { root, .. } = op {
                    root.0 = 1 - root.0;
                }
            }
        }),
        ("manual game root with a profiles root", |p| {
            p.roots[0].origin = PlanOrigin::Manual;
        }),
        ("a game root with the profiles identity (A2)", |p| {
            p.roots[0].id = PROFILES_ROOT_ID;
        }),
        ("create dir on the profiles root", |p| {
            p.ops[0] = Op::CreateDir {
                root: RootIx(1),
                path: r("sub"),
            };
        }),
        ("package content on the profiles root", |p| {
            let c = p.ops[1].content().unwrap().clone();
            set_content(p, c);
        }),
        ("inline content on the game root", |p| {
            if let Op::CreateFile { content, .. } = &mut p.ops[1] {
                *content = inline(b"x".to_vec());
            }
        }),
        ("upper-case name", |p| {
            if let Op::CreateFile { path, .. } = op0(p) {
                *path = r("323AD79FBC93CA3E73B0B152A5D44616.profile");
            }
        }),
        ("short name", |p| {
            if let Op::CreateFile { path, .. } = op0(p) {
                *path = r("x.profile");
            }
        }),
        ("name in a folder", |p| {
            if let Op::CreateFile { path, .. } = op0(p) {
                *path = r(r"a\323ad79fbc93ca3e73b0b152a5d44616.profile");
            }
        }),
        ("other extension", |p| {
            if let Op::CreateFile { path, .. } = op0(p) {
                *path = r("323ad79fbc93ca3e73b0b152a5d44616.profile.txt");
            }
        }),
        ("inline content larger than 2 KiB", |p| {
            set_content(p, inline(vec![b'a'; MAX_INLINE_BYTES + 1]));
        }),
        ("inline content with another hash", |p| {
            if let Op::CreateFile {
                content: ContentRef::Inline { sha256, .. },
                ..
            } = op0(p)
            {
                sha256[0] ^= 1;
            }
        }),
        ("attributes on a profile", |p| {
            if let Op::CreateFile { attrs, .. } = op0(p) {
                attrs.hidden = true;
            }
        }),
        ("the profile op after a game op (F3)", |p| {
            p.ops.swap(0, 1);
        }),
        ("a compatibility layer on the profiles root", |p| {
            p.ops.push(Op::TokenList {
                slot: RegSlot::CompatLayers {
                    root: RootIx(1),
                    exe: r("game.exe"),
                },
                old: None,
                add: vec![crate::policy::registry::TokenName::parse("HIGHDPIAWARE").unwrap()],
                new: "~ HIGHDPIAWARE".to_owned(),
            });
        }),
    ];
    for (what, m) in &form {
        let mut p = lm_plan();
        m(&mut p);
        refused(what, &p, true);
    }
    // A replaced profile larger than 8 KiB.
    let mut p = lm_replace(b"old");
    if let Op::ReplaceFile { old, .. } = op0(&mut p) {
        old.len = (8 << 10) + 1;
    }
    refused("a replaced profile larger than 8 KiB", &p, true);
    // A2 without a profiles root: a game root never carries the profiles identity. Only this
    // single-root case shows that rule alone (review N6): without it, the two-root case above
    // would still be refused, as "a root is listed twice".
    let mut p = lm_plan();
    p.roots.truncate(1);
    p.ops.remove(0);
    p.roots[0].id = PROFILES_ROOT_ID;
    refused("a lone game root with the profiles identity", &p, true);

    // `Rules::Current` only (B1): the recorded decode keeps the form, a revert never reads
    // the profile.
    let current: Vec<(&str, Mutate)> = vec![
        ("the profile of another app", |p| {
            if let Op::CreateFile { path, .. } = op0(p) {
                *path = profile_file(profile_id(221));
            }
        }),
        ("bytes that are no profile", |p| {
            set_content(p, inline(b"rerun-profile 2\n".to_vec()));
        }),
        ("a start outside the game folder", |p| {
            set_content(
                p,
                inline(profile_bytes(
                    r"D:\SteamLibrary\steamapps\common\Gx\game.exe",
                    8,
                )),
            );
        }),
        ("a start equal to the game folder", |p| {
            set_content(p, inline(profile_bytes(GAME, 8)));
        }),
        ("a start of 260 characters", |p| {
            let start = format!(r"{GAME}\{}\{}.exe", "a".repeat(200), "b".repeat(20));
            assert_eq!(start.encode_utf16().count(), 260);
            set_content(p, inline(profile_bytes(&start, 8)));
        }),
    ];
    for (what, m) in &current {
        let mut p = lm_plan();
        m(&mut p);
        refused(what, &p, false);
    }
    // 259 characters is the limit, not over it.
    let mut p = lm_plan();
    let start = format!(r"{GAME}\{}\{}.exe", "a".repeat(199), "b".repeat(20));
    assert_eq!(start.encode_utf16().count(), 259);
    set_content(&mut p, inline(profile_bytes(&start, 8)));
    p.encode().unwrap();
    // The start in another case of the game folder is below it (folded).
    let mut p = lm_plan();
    set_content(
        &mut p,
        inline(profile_bytes(
            r"d:\steamlibrary\STEAMAPPS\common\g\GAME.exe",
            8,
        )),
    );
    p.encode().unwrap();
}

#[test]
fn lm_p3_main_executables_of_game_roots_only_and_old_heads_unchanged() {
    // A registry op needs the main executable of every game root, not of the profiles root.
    let mut p = lm_plan();
    p.ops.push(Op::SetValue {
        slot: slot("Ubisoft", "AC", &[], "Windowed"),
        old: None,
        new: NewValue::Dword(1),
    });
    p.encode().unwrap();
    p.roots[0].main_exe = None;
    refused("a registry op without the game's main executable", &p, true);
    // A head of before P3-3 decodes as before (the sample of the P2 tests).
    let old = super::sample();
    let b = old.encode().unwrap();
    assert_eq!(decode(b.bytes()).unwrap(), old);
    assert!(!String::from_utf8_lossy(b.bytes()).contains("inline"));
}

#[test]
fn lm_p4_preview_names_the_profiles_root_the_source_and_the_profile() {
    let p = lm_plan();
    let pv = preview(&p);
    assert_eq!(pv.roots[1].kind, RootKind::Profiles);
    let text = pv.to_string();
    for want in [
        r"root 1: C:\Users\Player\AppData\Local\Rerun\profiles (Rerun's launch profiles)",
        "  0. create file 1:323ad79fbc93ca3e73b0b152a5d44616.profile from inline (launch profile)",
        "     profile 323ad79fbc93ca3e73b0b152a5d44616: method direct, x64",
        "     cpu max_threads 8, prefer any, single_l3 false, prefer_l3 none, smt true, mode hard",
        r"     start D:\SteamLibrary\steamapps\common\G\game.exe",
        ", attributes -",
    ] {
        assert!(text.contains(want), "{want}\n{text}");
    }
    match &pv.ops[0].profile {
        Some(ProfilePreview::Decoded(s)) => {
            assert_eq!(s.priority, None);
            assert_eq!(s.target, s.start);
        }
        other => panic!("{other:?}"),
    }
    // A recorded head whose bytes are no profile of this version (B1): a hint, never the
    // content; the apply decode refuses it.
    let mut p = lm_plan();
    set_content(
        &mut p,
        inline(b"rerun-profile 1\nmethod=\x1b[31m\xe2\x80\xaeevil\n".to_vec()),
    );
    let bytes = serde_json::to_vec(&p).unwrap();
    assert!(decode(&bytes).is_err());
    let pv = preview_head(&bytes).unwrap();
    assert!(matches!(
        pv.ops[0].profile,
        Some(ProfilePreview::Unreadable(_))
    ));
    let text = pv.to_string();
    assert!(
        text.contains("not a launch profile of this version"),
        "{text}"
    );
    assert!(!text.contains('\x1b') && !text.contains('\u{202e}') && !text.contains("evil"));
}
