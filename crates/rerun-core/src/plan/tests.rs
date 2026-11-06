//! Plan format, hash, storage and preview (P2-8, C1).

use sha2::{Digest, Sha256};

use super::{
    ContentRef, FileState, Limits, Object, Op, Plan, PlanBytes, PlanError, PlanHash, PlanOrigin,
    PlanRoot, RootIx, RootKind, decode, decode_with, load, overlap, preview, store,
};
use crate::path::{RelPath, RootPath};
use crate::policy::root::{AppDir, Create, RootId};
use crate::sys::fake::FakeSystem;
use crate::sys::fs::Attrs;

const LAD: &str = r"C:\Users\Player\AppData\Local";

pub(crate) fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn r(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn root_id(n: u128) -> RootId {
    RootId {
        volume_serial: 0xd,
        file_id: n,
    }
}

fn content(file: &str, data: &[u8]) -> ContentRef {
    ContentRef::Package {
        id: "fix-pack".to_owned(),
        version: "1.0.2".to_owned(),
        file: r(file),
        sha256: sha(data),
        len: u64::try_from(data.len()).unwrap(),
        config: false,
    }
}

/// A plan of every op kind over two roots.
fn sample() -> Plan {
    Plan {
        format: 1,
        roots: vec![
            PlanRoot {
                kind: RootKind::Game,
                path: RootPath::new(r"D:\Games\G").unwrap(),
                id: root_id(7),
                origin: PlanOrigin::Manual,
                main_exe: Some(r("game.exe")),
            },
            PlanRoot {
                kind: RootKind::Game,
                path: RootPath::new(r"D:\SteamLibrary\steamapps\common\G2").unwrap(),
                id: root_id(8),
                origin: PlanOrigin::Steam {
                    store: RootPath::new(r"D:\SteamLibrary").unwrap(),
                    store_id: root_id(1),
                    app_id: 220,
                    installdir: r("G2"),
                },
                main_exe: None,
            },
        ],
        ops: vec![
            Op::CreateDir {
                root: RootIx(0),
                path: r("mods"),
            },
            Op::CreateFile {
                root: RootIx(0),
                path: r(r"mods\a.dll"),
                content: content("a.dll", b"a"),
                attrs: Attrs::default(),
            },
            Op::ReplaceFile {
                root: RootIx(1),
                path: r("d3d9.dll"),
                old: FileState {
                    sha256: sha(b"old"),
                    len: 3,
                    attrs: Attrs {
                        readonly: true,
                        hidden: true,
                        system: false,
                    },
                },
                content: content(r"bin\d3d9.dll", b"new"),
                attrs: Attrs::default(),
            },
        ],
    }
}

#[test]
fn p1_encode_decode_round_trip_in_one_form() {
    let p = sample();
    let b = p.encode().unwrap();
    assert_eq!(b.hash(), PlanHash(sha(b.bytes())));
    assert_eq!(decode(b.bytes()).unwrap(), p);
    assert_eq!(p.encode().unwrap(), b, "deterministic");
    let s = std::str::from_utf8(b.bytes()).unwrap();
    assert!(
        s.starts_with(
            r#"{"format":1,"roots":[{"kind":"game","path":"D:\\Games\\G","id":"000000000000000d-00000000000000000000000000000007","origin":"manual","main_exe":"game.exe"}"#
        ),
        "{s}"
    );
    assert!(
        s.contains(r#"{"create_dir":{"root":0,"path":"mods"}}"#),
        "{s}"
    );
    assert!(
        s.contains(r#""origin":{"steam":{"store":"D:\\SteamLibrary","#),
        "{s}"
    );
    // The hash parses back from its display form only.
    let h: PlanHash = b.hash().to_string().parse().unwrap();
    assert_eq!(h, b.hash());
    assert!("ABC".parse::<PlanHash>().is_err());
    assert!(
        b.hash()
            .to_string()
            .to_uppercase()
            .parse::<PlanHash>()
            .is_err()
    );
}

#[test]
fn p2_decode_refuses_every_other_form_and_every_broken_rule() {
    let good = String::from_utf8(sample().encode().unwrap().bytes().to_vec()).unwrap();
    let cases: Vec<(String, &str)> = vec![
        (good.replace(r#""format":1"#, r#""format":2"#), "format"),
        (good.replace(r#""format":1,"#, r#""format":1, "#), "form"),
        (format!("{good}\n"), "form"),
        (good.replace(r"mods\\a.dll", "mods/a.dll"), "form"),
        (good.replace(r"D:\\Games", r"d:\\Games"), "form"),
        (good.replace(r"mods\\a.dll", r"..\\a.dll"), "parse"),
        (good.replace(r"mods\\a.dll", r"C:\\a.dll"), "parse"),
        (good.replace(r#""len":3,"#, r#""len":3,"x":1,"#), "parse"),
        (good.replace(r#""root":1"#, r#""root":2"#), "root index"),
        (good.replace("fix-pack", "Fix-Pack"), "package"),
        (good.replace("1.0.2", "1..2"), "package"),
        (good.replace("1.0.2", "con"), "package"),
        (
            good.replace(r#""path":"mods"}"#, r#""path":"MODS\\a.dll"}"#),
            "same object",
        ),
        (
            good.replace(&super::tests::hex(b"old"), &hex(b"new")),
            "replace with",
        ),
        (
            good.replace(
                "000000000000000d-00000000000000000000000000000008",
                "000000000000000d-00000000000000000000000000000007",
            ),
            "listed twice",
        ),
        (good.replace(r#""app_id":220"#, r#""app_id":0"#), "app ID"),
        (good.replace(r#""len":3,"#, r#""len":3000000000,"#), "2 GiB"),
    ];
    for (bytes, want) in cases {
        let e = decode(bytes.as_bytes()).expect_err(&bytes).to_string();
        let ok = match want {
            "format" => e.contains("format 2"),
            "form" => e.contains("one written form"),
            "parse" => e.contains("cannot be parsed"),
            other => e.contains(other),
        };
        assert!(ok, "{want}: {e}\n{bytes}");
    }
    // 129 ops, an op over its limit, a plan over its limit (shrunk limits, same rules).
    let mut many = sample();
    many.ops = (0..129)
        .map(|i| Op::CreateDir {
            root: RootIx(0),
            path: r(&format!("d{i}")),
        })
        .collect();
    assert!(matches!(
        many.encode(),
        Err(PlanError::TooManyOps { n: 129, limit: 128 })
    ));
    let bytes = serde_json::to_vec(&many).unwrap();
    assert!(matches!(
        decode(&bytes),
        Err(PlanError::TooManyOps { n: 129, .. })
    ));
    let b = sample().encode().unwrap();
    let small = Limits {
        op_bytes: 100,
        ..Limits::default()
    };
    assert!(matches!(
        decode_with(b.bytes(), &small),
        Err(PlanError::OpTooLarge { op: 1, limit: 100 })
    ));
    let tiny = Limits {
        plan_bytes: 100,
        ..Limits::default()
    };
    assert!(matches!(
        decode_with(b.bytes(), &tiny),
        Err(PlanError::TooLarge { limit: 100 })
    ));
    assert!(matches!(
        sample().encode_with(&tiny),
        Err(PlanError::TooLarge { .. })
    ));
}

pub(crate) fn hex(b: &[u8]) -> String {
    crate::wire::hex32::to_string(&sha(b))
}

#[test]
fn p3_store_and_load_bind_the_bytes_to_their_hash() {
    let sys = FakeSystem::builder().dir(LAD).build().unwrap();
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    let b = sample().encode().unwrap();
    assert!(matches!(load(&app, &b.hash()), Err(PlanError::NotFound(_))));
    assert_eq!(store(&app, &b).unwrap(), b.hash());
    assert_eq!(store(&app, &b).unwrap(), b.hash(), "the same bytes again");
    assert_eq!(load(&app, &b.hash()).unwrap(), b);
    let file = format!(r"{LAD}\Rerun\plans\{}.json", b.hash());
    let fx = sys.fake_fs();
    // Changed bytes under the name: refused on load and on store.
    let mut changed = b.bytes().to_vec();
    changed[2] = b'X';
    fx.remove_abs(std::path::Path::new(&file)).unwrap();
    fx.put_file(std::path::Path::new(&file), &changed).unwrap();
    assert!(matches!(
        load(&app, &b.hash()),
        Err(PlanError::HashMismatch(_))
    ));
    assert!(matches!(store(&app, &b), Err(PlanError::HashMismatch(_))));
    // Oversized: refused without reading it whole.
    fx.remove_abs(std::path::Path::new(&file)).unwrap();
    fx.put_file(
        std::path::Path::new(&file),
        &vec![b' '; super::MAX_PLAN_BYTES + 1],
    )
    .unwrap();
    assert!(matches!(
        load(&app, &b.hash()),
        Err(PlanError::TooLarge { .. })
    ));
    let _ = PlanBytes::from_bytes(Vec::new());
}

#[test]
fn p4_preview_shows_every_op_and_what_is_not_restored() {
    let mut p = sample();
    if let Op::CreateFile { content, .. } = &mut p.ops[1] {
        let ContentRef::Package { config, .. } = content;
        *config = true;
    }
    let pv = preview(&p);
    assert_eq!(pv.ops.len(), 3);
    let text = pv.to_string();
    for want in [
        r"root 0: D:\Games\G, main executable game.exe",
        r"root 1: D:\SteamLibrary\steamapps\common\G2 (Steam app 220 in D:\SteamLibrary)",
        "  0. create folder 0:mods",
        r"  1. create file 0:mods\a.dll from fix-pack 1.0.2: a.dll",
        "configuration file",
        r"  2. replace file 1:d3d9.dll from fix-pack 1.0.2: bin\d3d9.dll",
        &format!("old sha256 {}, 3 bytes, attributes RH", hex(b"old")),
        &format!("new sha256 {}, 3 bytes, attributes -", hex(b"new")),
        "note: a revert restores",
    ] {
        assert!(text.contains(want), "{want:?} not in\n{text}");
    }
    assert_eq!(text.matches("note:").count(), 1);
    let empty = Plan {
        ops: Vec::new(),
        ..sample()
    };
    assert!(preview(&empty).to_string().contains("nothing to do"));
}

#[test]
fn p5_objects_overlap_when_equal_or_below_a_created_directory() {
    let p = sample();
    let objs = Object::of(&p);
    assert_eq!(objs.len(), 3);
    // The root paths of `sample` (7, 8) and one beside them (9).
    let one = |root: u128, path: &str, dir: bool| {
        let root_path = match root {
            7 => r"D:\Games\G",
            8 => r"D:\SteamLibrary\steamapps\common\G2",
            _ => r"D:\Games\H",
        };
        vec![Object::File {
            root: root_id(root),
            root_path: RootPath::new(root_path).unwrap(),
            path: crate::fold::fold(path),
            dir,
        }]
    };
    assert!(overlap(&objs, &one(7, "MODS", false)), "same, folded");
    assert!(
        overlap(&objs, &one(7, r"mods\x\y.txt", false)),
        "below a created dir"
    );
    assert!(overlap(&objs, &one(8, "D3D9.dll", false)));
    assert!(!overlap(&objs, &one(9, "mods", true)), "another root");
    assert!(!overlap(&objs, &one(7, "modsx", false)));
    assert!(
        !overlap(&objs, &one(8, r"d3d9.dll\x", false)),
        "a file is no dir"
    );
    assert!(overlap(
        &objs,
        &one(8, "", true)
            .into_iter()
            .map(|mut o| {
                let Object::File { path, .. } = &mut o;
                *path = "D3D9.DLL".into();
                o
            })
            .collect::<Vec<_>>()
    ),);
    assert!(overlap(&one(7, "a", true), &one(7, r"A\B", true)));
}
