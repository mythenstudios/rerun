//! The signed index (ADR 0024): signature before parsing, the bundle rules, and the store
//! under `<AppDir>\index` against the fake (rollback, same `seq`, by hash, tampering).

use std::path::Path;

use super::key::test_key;
use super::model::{
    Api, Arch, ArchList, Exe, Hex, Id, Index, Issue, Kind, Match, Package, PackageFile,
    PackageSource, Status, Tier, Topo, TopoStep, Variant, VariantStatus,
};
use super::store::{self, Imported, StoreError};
use super::{Catalog, IndexError, MAX_INDEX_BYTES, PublicKey, verify};
use crate::path::RelPath;
use crate::policy::root::{AppDir, Create};
use crate::sys::fake::FakeSystem;

const LAD: &str = r"C:\Users\Player\AppData\Local";
const INDEX_DIR: &str = r"C:\Users\Player\AppData\Local\Rerun\index";

fn id(s: &str) -> Id {
    Id::parse(s).unwrap()
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn package(name: &str) -> Package {
    Package {
        format: 1,
        id: id(name),
        name: "Fix pack".into(),
        status: Status::Active,
        tier: Tier::Established,
        source: PackageSource {
            repo: Some("https://github.com/owner/fix-pack".into()),
            page: None,
            release: Some(
                "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip".into(),
            ),
        },
        version: "1.0".into(),
        sha256: Some(Hex::new([0xAB; 32])),
        assets: None,
        license: "MIT".into(),
        arch: ArchList::List(vec![Arch::X86]),
        apis: None,
        slots: vec!["d3d9.dll".into()],
        slots_by_api: None,
        requires: vec![],
        requires_gpu: vec![],
        supports_exe_sha1: vec![],
        files: vec![PackageFile {
            from: rel("d3d9.dll"),
            to: rel("d3d9.dll"),
            sha256: Hex::new([0xCD; 32]),
            config: false,
            arch: None,
            api: None,
        }],
        options: Default::default(),
    }
}

fn topo(name: &str, pkg: &str) -> Topo {
    Topo {
        format: 1,
        id: id(name),
        title: "A game".into(),
        status: Status::Active,
        rev: 1,
        tested_on: vec![],
        matches: Match {
            steam_appid: Some(440),
            exes: vec![Exe {
                path: rel("game.exe"),
                sha1: None,
                sha256: Some(Hex::new([0x11; 32])),
                api: Api::D3d9,
            }],
        },
        launch: None,
        issues: vec![Issue {
            id: id("stutter"),
            title: "Stutter".into(),
            when: None,
            checks: vec![],
            variants: vec![Variant {
                id: id("fix-pack"),
                status: VariantStatus::Reported,
                kind: Kind::Fix,
                steps: vec![TopoStep::Package(id(pkg))],
                tradeoffs: vec![],
                sources: vec![],
            }],
        }],
        tips: None,
        links: None,
    }
}

fn index(seq: u64) -> Index {
    Index {
        format: 1,
        seq,
        issued: "2026-11-09T12:00:00Z".into(),
        topos: vec![topo("a-game", "fix-pack")],
        packages: vec![package("fix-pack")],
    }
}

fn bytes(i: &Index) -> Vec<u8> {
    serde_json::to_vec_pretty(i).unwrap()
}

fn keys() -> Vec<PublicKey> {
    vec![test_key::public()]
}

fn catalog(b: &[u8], sig: &[u8]) -> Result<Catalog, IndexError> {
    let v = verify(b, sig, &keys())?;
    Catalog::from_verified(&v)
}

// ---------- Signature before parsing ----------

#[test]
fn a_valid_index_becomes_a_typed_catalogue() {
    let b = bytes(&index(3));
    let c = catalog(&b, &test_key::sign(&b)).unwrap();
    assert_eq!(c.seq(), 3);
    assert_eq!(c.issued(), "2026-11-09T12:00:00Z");
    assert_eq!(c.key(), test_key::public().id());
    assert_eq!(c.topo("a-game").unwrap().matches.steam_appid, Some(440));
    assert_eq!(c.package("fix-pack").unwrap().version, "1.0");
    assert!(c.topo("fix-pack").is_none());
    assert_eq!(c.index(), &index(3));
}

#[test]
fn a_bad_signature_is_refused_before_anything_is_parsed() {
    let b = bytes(&index(1));
    let sig = test_key::sign(&b);
    // Garbage that would not parse: a parse error would show the bytes were looked at.
    let garbage = b"{ not json at all".to_vec();
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("empty signature", b.clone(), vec![]),
        ("truncated signature", b.clone(), sig[..63].to_vec()),
        ("signature too long", b.clone(), [&sig[..], &[0]].concat()),
        (
            "signature of other bytes",
            b.clone(),
            test_key::sign(b"other").to_vec(),
        ),
        (
            "foreign key",
            b.clone(),
            test_key::sign_foreign(&b).to_vec(),
        ),
        (
            "garbage, signature of the index",
            garbage.clone(),
            sig.to_vec(),
        ),
        ("zero signature", b.clone(), vec![0; 64]),
    ];
    for (what, bytes, sig) in cases {
        assert_eq!(
            catalog(&bytes, &sig).unwrap_err(),
            IndexError::Signature,
            "{what}"
        );
    }
    // Bytes changed after signing: every position counts.
    for at in [0, b.len() / 2, b.len() - 1] {
        let mut changed = b.clone();
        changed[at] ^= 0x01;
        assert_eq!(
            catalog(&changed, &sig).unwrap_err(),
            IndexError::Signature,
            "byte {at}"
        );
    }
    // Truncated bytes.
    assert_eq!(
        catalog(&b[..b.len() - 1], &sig).unwrap_err(),
        IndexError::Signature
    );
}

#[test]
fn no_trusted_key_refuses_every_index() {
    let b = bytes(&index(1));
    assert_eq!(
        verify(&b, &test_key::sign(&b), &[]).unwrap_err(),
        IndexError::NoKeys
    );
}

#[test]
fn an_oversized_index_is_refused_even_when_signed() {
    let mut b = vec![b' '; MAX_INDEX_BYTES + 1];
    b[0] = b'{';
    let sig = test_key::sign(&b);
    assert_eq!(
        catalog(&b, &sig).unwrap_err(),
        IndexError::TooLarge {
            limit: MAX_INDEX_BYTES
        }
    );
}

#[test]
fn the_second_key_slot_verifies_too() {
    let b = bytes(&index(1));
    let v = verify(
        &b,
        &test_key::sign(&b),
        &[test_key::foreign_public(), test_key::public()],
    )
    .unwrap();
    assert_eq!(v.key(), test_key::public().id());
}

// ---------- The bundle rules (after the signature) ----------

fn signed_err(b: &[u8]) -> IndexError {
    catalog(b, &test_key::sign(b)).unwrap_err()
}

fn rule(i: &Index) -> String {
    match signed_err(&bytes(i)) {
        IndexError::Rule(r) => r,
        other => panic!("expected a rule error, got {other:?}"),
    }
}

#[test]
fn signed_bytes_of_the_wrong_form_are_refused_by_position_only() {
    assert!(matches!(
        signed_err(b"{ not json"),
        IndexError::Parse {
            class: "syntax" | "eof",
            ..
        }
    ));
    let text = String::from_utf8(bytes(&index(1))).unwrap();
    let unknown = text.replacen("\"seq\"", "\"extra\": 1, \"seq\"", 1);
    assert!(matches!(
        signed_err(unknown.as_bytes()),
        IndexError::Parse { class: "data", .. }
    ));
    let format2 = text.replacen("\"format\": 1", "\"format\": 2", 1);
    assert_eq!(signed_err(format2.as_bytes()), IndexError::Format(2));
    let escape = text.replacen("\"game.exe\"", "\"..\\\\game.exe\"", 1);
    assert!(matches!(
        signed_err(escape.as_bytes()),
        IndexError::Parse { class: "data", .. }
    ));
    let lower = text.replacen(&"AB".repeat(32), &"ab".repeat(32), 1);
    assert!(matches!(
        signed_err(lower.as_bytes()),
        IndexError::Parse { class: "data", .. }
    ));
}

#[test]
fn a_release_index_holds_no_draft_and_no_todo() {
    let mut i = index(1);
    i.topos[0].status = Status::Draft;
    assert!(rule(&i).contains("draft"), "{}", rule(&i));

    let mut i = index(1);
    i.packages[0].files[0].sha256 = Hex::parse("TODO").unwrap();
    assert!(rule(&i).contains("TODO"), "{}", rule(&i));

    let mut i = index(1);
    i.packages[0].version = "TODO".into();
    assert!(rule(&i).contains("TODO"));
}

#[test]
fn the_bundle_is_sorted_complete_and_numbered() {
    let mut i = index(1);
    i.topos.push(topo("a-game", "fix-pack"));
    assert!(rule(&i).contains("sorted"));

    let mut i = index(1);
    i.topos.insert(0, topo("z-game", "fix-pack"));
    assert!(rule(&i).contains("sorted"));

    let mut i = index(1);
    i.topos[0] = topo("a-game", "missing-pack");
    assert!(rule(&i).contains("missing-pack"));

    let mut i = index(1);
    i.packages[0].requires = vec![id("other")];
    assert!(rule(&i).contains("requires other"));

    assert!(rule(&index(0)).contains("seq"));

    let mut i = index(1);
    i.issued = "2026-11-09".into();
    assert!(rule(&i).contains("issued"));
}

#[test]
fn issued_form() {
    assert!(super::issued_ok("2026-11-09T12:00:00Z"));
    for bad in [
        "2026-11-09T12:00:00",
        "2026-13-09T12:00:00Z",
        "2026-11-09 12:00:00Z",
        "2026-11-09T24:00:00Z",
        "+026-11-09T12:00:00Z",
        "",
    ] {
        assert!(!super::issued_ok(bad), "{bad}");
    }
}

// ---------- The store (fake) ----------

fn sys() -> FakeSystem {
    FakeSystem::builder().dir(LAD).build().unwrap()
}

fn signed(seq: u64) -> (Vec<u8>, Vec<u8>) {
    let b = bytes(&index(seq));
    let s = test_key::sign(&b).to_vec();
    (b, s)
}

fn import(sys: &FakeSystem, (b, s): &(Vec<u8>, Vec<u8>)) -> Result<Imported, StoreError> {
    let app = AppDir::open(sys, Create::IfMissing).unwrap().unwrap();
    store::import(&app, b, s, &keys())
}

fn current_seq(sys: &FakeSystem) -> Option<u64> {
    let app = AppDir::open(sys, Create::Never).unwrap()?;
    store::current(&app, &keys()).unwrap().map(|c| c.seq())
}

#[test]
fn import_keeps_every_index_and_refuses_a_rollback() {
    let sys = sys();
    assert_eq!(current_seq(&sys), None, "nothing imported yet");

    let first = signed(2);
    assert!(matches!(
        import(&sys, &first).unwrap(),
        Imported::New { previous: None, .. }
    ));
    assert_eq!(current_seq(&sys), Some(2));
    assert!(matches!(
        import(&sys, &first).unwrap(),
        Imported::AlreadyCurrent(_)
    ));

    let newer = signed(5);
    assert!(matches!(
        import(&sys, &newer).unwrap(),
        Imported::New {
            previous: Some(2),
            ..
        }
    ));
    assert_eq!(current_seq(&sys), Some(5));

    // Lower: a rollback, the pointer stays.
    assert_eq!(
        import(&sys, &first).unwrap_err(),
        StoreError::Rollback {
            current: 5,
            offered: 2
        }
    );
    assert_eq!(current_seq(&sys), Some(5));

    // Equal number, other bytes.
    let mut other = index(5);
    other.issued = "2026-11-10T00:00:00Z".into();
    let ob = bytes(&other);
    let os = test_key::sign(&ob).to_vec();
    assert_eq!(
        import(&sys, &(ob, os)).unwrap_err(),
        StoreError::SameSeq { seq: 5 }
    );
    assert_eq!(current_seq(&sys), Some(5));

    // R1: the older index stays readable by its hash, without a seq floor.
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    let sha: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&first.0).into()
    };
    assert_eq!(store::by_hash(&app, &sha, &keys()).unwrap().seq(), 2);
    // ... but only under a trusted key.
    assert!(matches!(
        store::by_hash(&app, &sha, &[test_key::foreign_public()]),
        Err(StoreError::Index(IndexError::Signature))
    ));
}

#[test]
fn a_refused_index_stores_nothing() {
    let sys = sys();
    let (b, _) = signed(1);
    let bad = test_key::sign_foreign(&b).to_vec();
    assert_eq!(
        import(&sys, &(b, bad)).unwrap_err(),
        StoreError::Index(IndexError::Signature)
    );
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    assert!(
        crate::policy::root::AppDir::sub(&app, crate::policy::root::AppSub::Index)
            .unwrap()
            .is_none(),
        "no index folder for a refused index"
    );
}

#[test]
fn a_tampered_store_is_damaged_not_trusted() {
    let sys = sys();
    let first = signed(1);
    import(&sys, &first).unwrap();
    let sha = {
        use sha2::Digest;
        crate::wire::hex32::to_string(&sha2::Sha256::digest(&first.0).into())
    };
    let app = || AppDir::open(&sys, Create::Never).unwrap().unwrap();

    // The stored bytes changed: they no longer hash to their name.
    let json = format!(r"{INDEX_DIR}\{sha}.json");
    let mut changed = first.0.clone();
    changed[10] ^= 1;
    sys.fake_fs().put_file(Path::new(&json), &changed).unwrap();
    assert!(matches!(
        store::current(&app(), &keys()),
        Err(StoreError::Damaged(_))
    ));
    // Importing the same index again repairs the copy.
    assert!(matches!(
        import(&sys, &first).unwrap(),
        Imported::AlreadyCurrent(_)
    ));
    assert_eq!(current_seq(&sys), Some(1));

    // A signature swapped for a foreign one.
    let sig = format!(r"{INDEX_DIR}\{sha}.sig");
    sys.fake_fs()
        .put_file(Path::new(&sig), &test_key::sign_foreign(&first.0))
        .unwrap();
    assert!(matches!(
        store::current(&app(), &keys()),
        Err(StoreError::Index(IndexError::Signature))
    ));
    import(&sys, &first).unwrap();

    // A pointer that names another seq than its index.
    let cur = format!(r"{INDEX_DIR}\{}", store::CURRENT);
    let forged = format!(r#"{{"format":1,"seq":9,"sha256":"{sha}"}}"#);
    sys.fake_fs()
        .put_file(Path::new(&cur), forged.as_bytes())
        .unwrap();
    assert!(matches!(
        store::current(&app(), &keys()),
        Err(StoreError::Damaged(_))
    ));
    // A pointer of another form.
    sys.fake_fs()
        .put_file(Path::new(&cur), b"{\"seq\":1}")
        .unwrap();
    assert!(matches!(
        store::current(&app(), &keys()),
        Err(StoreError::Damaged(_))
    ));
}
