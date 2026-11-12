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
/// `index`, or `index-test` with the feature `test-key` (ADR 0024 amendment P4-13).
const INDEX_DIR: &str = if cfg!(feature = "test-key") {
    r"C:\Users\Player\AppData\Local\Rerun\index-test"
} else {
    r"C:\Users\Player\AppData\Local\Rerun\index"
};

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
        anti_cheat: None,
        user_data: None,
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

/// The entries the client sets aside in `i` (ADR 0024 amendment "Forward compatibility"),
/// shown as `<kind> <id>: <why>`; the index itself is accepted.
fn aside(i: &Index) -> Vec<String> {
    let b = bytes(i);
    let c = catalog(&b, &test_key::sign(&b)).unwrap();
    c.aside().iter().map(ToString::to_string).collect()
}

/// [`aside`] of serialised text.
fn aside_text(text: &str) -> Vec<String> {
    let c = catalog(text.as_bytes(), &test_key::sign(text.as_bytes())).unwrap();
    c.aside().iter().map(ToString::to_string).collect()
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
    // Inside an entry of a known format the strict types still refuse it, by position, but the
    // entry is set aside instead of the whole index (ADR 0024 amendment "Forward
    // compatibility"): a path escaping the game folder, a hash in lower case.
    let escape = text.replacen("\"game.exe\"", "\"..\\\\game.exe\"", 1);
    let a = aside_text(&escape);
    assert_eq!(a.len(), 1, "{a:?}");
    assert!(
        a[0].starts_with("topo a-game: not readable by this build (data at line "),
        "{a:?}"
    );
    let lower = text.replacen(&"AB".repeat(32), &"ab".repeat(32), 1);
    let a = aside_text(&lower);
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!(
        a[0],
        "topo a-game: names package fix-pack, which this build cannot use"
    );
    assert!(
        a[1].starts_with("package fix-pack: not readable by this build (data at line "),
        "{a:?}"
    );
}

/// A draft or a `TODO` is never used from a signed index: since the amendment "Forward
/// compatibility" the entry is set aside as refused (the workbench never builds one), and the
/// rest of the index stays.
#[test]
fn a_release_index_holds_no_draft_and_no_todo() {
    let mut i = index(1);
    i.topos[0].status = Status::Draft;
    assert_eq!(
        aside(&i),
        vec!["topo a-game: breaks a rule of this build: status: a draft is never released"]
    );

    let mut i = index(1);
    i.packages[0].files[0].sha256 = Hex::parse("TODO").unwrap();
    assert_eq!(
        aside(&i),
        vec![
            "topo a-game: names package fix-pack, which this build cannot use",
            "package fix-pack: breaks a rule of this build: : a released entry has no TODO",
        ]
    );

    let mut i = index(1);
    i.packages[0].version = "TODO".into();
    assert!(aside(&i)[1].contains("TODO"));
}

#[test]
fn the_bundle_is_sorted_complete_and_numbered() {
    let mut i = index(1);
    i.topos.push(topo("a-game", "fix-pack"));
    assert!(rule(&i).contains("sorted"));

    let mut i = index(1);
    i.topos.insert(0, topo("z-game", "fix-pack"));
    assert!(rule(&i).contains("sorted"));

    // A duplicate across a known and a set-aside entry is refused too (FC5).
    let mut i = index(1);
    let mut draft = topo("a-game", "fix-pack");
    draft.status = Status::Draft;
    i.topos.push(draft);
    assert!(rule(&i).contains("sorted"));

    // A missing package sets aside what names it (the amendment "Forward compatibility").
    let mut i = index(1);
    i.topos[0] = topo("a-game", "missing-pack");
    assert_eq!(
        aside(&i),
        vec![
            "topo a-game: breaks a rule of this build: issues[0].variants[0].steps[0].package: \
             package missing-pack is not in the index"
        ]
    );

    let mut i = index(1);
    i.packages[0].requires = vec![id("other")];
    assert_eq!(
        aside(&i),
        vec![
            "topo a-game: names package fix-pack, which this build cannot use",
            "package fix-pack: breaks a rule of this build: requires[0]: requires other, which is \
             not in the index",
        ]
    );

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
    assert_eq!(store::by_hash_with(&app, &sha, &keys()).unwrap().seq(), 2);
    // ... but only under a trusted key.
    assert!(matches!(
        store::by_hash_with(&app, &sha, &[test_key::foreign_public()]),
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
    let cur = format!(r"{INDEX_DIR}\{}", store::CURRENT);
    let names_pointer = |r: Result<Imported, StoreError>| match r {
        Err(StoreError::Damaged(why)) => {
            assert!(why.contains(&cur) && why.contains("remove"), "{why}");
        }
        other => panic!("expected Damaged naming {cur}, got {other:?}"),
    };

    // The stored bytes changed: they no longer hash to their name. `current` and an import
    // (which checks its floor first, nit 5 of the review) say so and name the pointer to remove.
    let json = format!(r"{INDEX_DIR}\{sha}.json");
    let mut changed = first.0.clone();
    changed[10] ^= 1;
    sys.fake_fs().put_file(Path::new(&json), &changed).unwrap();
    assert!(matches!(
        store::current(&app(), &keys()),
        Err(StoreError::Damaged(_))
    ));
    names_pointer(import(&sys, &signed(2)));
    names_pointer(import(&sys, &first));
    // Removing the pointer (the user's decision) lets the same index in again and repairs it.
    sys.fake_fs().remove_abs(Path::new(&cur)).unwrap();
    assert!(matches!(
        import(&sys, &first).unwrap(),
        Imported::New { previous: None, .. }
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
    names_pointer(import(&sys, &signed(2)));
    sys.fake_fs()
        .put_file(Path::new(&sig), &test_key::sign(&first.0))
        .unwrap();

    // A pointer that names another seq than its index: not a rollback, damaged.
    let forged = format!(r#"{{"format":1,"seq":9,"sha256":"{sha}"}}"#);
    sys.fake_fs()
        .put_file(Path::new(&cur), forged.as_bytes())
        .unwrap();
    assert!(matches!(
        store::current(&app(), &keys()),
        Err(StoreError::Damaged(_))
    ));
    names_pointer(import(&sys, &signed(2)));
    // A pointer of another form.
    sys.fake_fs()
        .put_file(Path::new(&cur), b"{\"seq\":1}")
        .unwrap();
    assert!(matches!(
        store::current(&app(), &keys()),
        Err(StoreError::Damaged(_))
    ));
    names_pointer(import(&sys, &signed(2)));
    // A pointer naming an index that is not there.
    let missing = format!(r#"{{"format":1,"seq":1,"sha256":"{}"}}"#, "0".repeat(64));
    sys.fake_fs()
        .put_file(Path::new(&cur), missing.as_bytes())
        .unwrap();
    names_pointer(import(&sys, &signed(2)));
}

/// Review follow-up 1: a rotation must not make old indexes unreadable for a revert, and a
/// revoked key is refused everywhere.
#[test]
fn retired_keys_serve_reverts_only_and_revoked_keys_nothing() {
    let b = bytes(&index(1));
    let sig = test_key::sign(&b);
    let pk = test_key::public();
    // Revoked: refused even when the caller trusts the key.
    assert_eq!(
        super::verify_with(&b, &sig, &[pk], &[*pk.bytes()]).unwrap_err(),
        IndexError::Revoked(pk.id())
    );
    assert!(super::verify_with(&b, &sig, &[pk], &[[0; 32]]).is_ok());

    // The lists of this build: no test key retired or revoked, the revert set holds the trusted
    // set and never a revoked key.
    for k in [test_key::public(), test_key::foreign_public()] {
        assert!(!super::key::RETIRED_KEYS.contains(k.bytes()));
    }
    let revert = super::key::revert_keys();
    for k in super::key::trusted_keys() {
        assert!(revert.contains(&k));
    }
    assert!(revert.iter().all(|k| !super::key::revoked(k)));
    assert!(
        super::key::trusted_keys()
            .iter()
            .all(|k| !super::key::RETIRED_KEYS.contains(k.bytes()))
    );

    // A stored index signed by a key the import no longer trusts stays readable for a revert
    // when that key is passed as retired (here: explicitly, as `by_hash` does with
    // RETIRED_KEYS), but `current` refuses it.
    let sys = sys();
    let first = signed(1);
    import(&sys, &first).unwrap();
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    let sha: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&first.0).into()
    };
    let other = test_key::foreign_public();
    assert!(matches!(
        store::current(&app, &[other]),
        Err(StoreError::Index(IndexError::Signature))
    ));
    assert_eq!(
        store::by_hash_with(&app, &sha, &[other, test_key::public()])
            .unwrap()
            .seq(),
        1
    );
}

/// `firewall_rule` (P4-5a): its executable is a `match.exes` entry with a `sha256` (ADR 0024,
/// P4 R6), in a draft and, since it was reviewed (P4-5b), outside one too; the release rules
/// refuse a draft as they refuse every draft.
#[test]
fn firewall_rule_needs_a_draft_and_a_sha256_anchor() {
    use super::check::{self, Rules};
    use super::model::FirewallRuleSpec;
    use crate::policy::firewall::Direction;

    let mut t = topo("game", "fix-pack");
    t.status = Status::Draft;
    t.issues[0].variants[0].steps = vec![TopoStep::FirewallRule(FirewallRuleSpec {
        exe: rel("game.exe"),
        direction: Direction::Out,
    })];
    assert_eq!(check::topo(&t, Rules::Source), Ok(()));
    let what = |t: &Topo| check::topo(t, Rules::Source).unwrap_err().what;
    let mut active = t.clone();
    active.status = Status::Active;
    assert_eq!(check::topo(&active, Rules::Source), Ok(()));
    assert_eq!(check::topo(&active, Rules::Release), Ok(()));
    assert!(
        check::topo(&t, Rules::Release).is_err(),
        "a draft is never released"
    );
    let mut other = t.clone();
    other.issues[0].variants[0].steps = vec![TopoStep::FirewallRule(FirewallRuleSpec {
        exe: rel("other.exe"),
        direction: Direction::Out,
    })];
    assert_eq!(what(&other), "an executable of match.exes");
    // Exact spelling only: another case, or a Unicode fold twin (U+0131 against `I`), is no
    // anchor.
    for (entry, step) in [
        ("game.exe", "GAME.exe"),
        ("bin\\gam\u{131}.exe", "bin\\GAMI.exe"),
    ] {
        let mut twin = t.clone();
        twin.matches.exes[0].path = rel(entry);
        twin.issues[0].variants[0].steps = vec![TopoStep::FirewallRule(FirewallRuleSpec {
            exe: rel(step),
            direction: Direction::Out,
        })];
        assert_eq!(what(&twin), "an executable of match.exes", "{step}");
    }
    let mut sha1_only = t.clone();
    sha1_only.matches.exes[0].sha256 = None;
    sha1_only.matches.exes[0].sha1 = Some(Hex::new([0x22; 20]));
    assert!(
        what(&sha1_only).contains("needs a sha256"),
        "{}",
        what(&sha1_only)
    );
    let mut todo = t.clone();
    todo.matches.exes[0].sha256 = Some(Hex::parse("TODO").unwrap());
    assert_eq!(check::topo(&todo, Rules::Source), Ok(()), "TODO in a draft");
    assert!(
        check::topo(&t, Rules::Release).is_err(),
        "never released as a draft"
    );
}

/// `firewall_rule` is reviewed (P4-5b, after the [DEV] round trip of 2026-11-10): an index
/// releases it when one of this build's trusted keys signed it (the release slots, and the
/// published test key only in a `test-key` build); a foreign key's index is not verified at all,
/// so it releases nothing; a draft stays a draft (never in a signed index).
#[test]
fn firewall_rule_is_released_only_by_a_trusted_signed_index() {
    use super::check::{self, FIREWALL_RULE_REVIEWED, Rules};
    use super::key::{release_keys, trusted_keys};
    use super::model::FirewallRuleSpec;
    use crate::policy::firewall::Direction;

    const { assert!(FIREWALL_RULE_REVIEWED, "firewall_rule is reviewed") };
    let mut t = topo("game", "fix-pack");
    t.issues[0].variants[0].steps = vec![TopoStep::FirewallRule(FirewallRuleSpec {
        exe: rel("game.exe"),
        direction: Direction::Out,
    })];
    t.status = Status::Active;
    check::topo(&t, Rules::Release).unwrap();
    let index = |tt: &Topo| super::Index {
        format: 1,
        seq: 1,
        issued: "2026-11-10T12:00:00Z".to_owned(),
        topos: vec![tt.clone()],
        packages: Vec::new(),
    };
    let bytes = serde_json::to_vec(&index(&t)).unwrap();
    // A foreign key: refused by the signature check against this build's keys.
    let foreign = test_key::sign_foreign(&bytes);
    assert!(super::verify(&bytes, &foreign, &trusted_keys()).is_err());
    // The test key: trusted only by a test-key build; the release slots alone refuse it.
    let ours = test_key::sign(&bytes);
    assert_eq!(
        super::verify(&bytes, &ours, &trusted_keys()).is_ok(),
        cfg!(feature = "test-key")
    );
    assert!(super::verify(&bytes, &ours, &release_keys()).is_err());
    // Verified by a key the caller trusts, the index releases the step.
    let v = super::verify(&bytes, &ours, &[test_key::public()]).unwrap();
    super::Catalog::from_verified(&v).unwrap();
    // A draft is never used from a signed index, with or without the step (set aside).
    let mut draft = t.clone();
    draft.status = Status::Draft;
    let bytes = serde_json::to_vec(&index(&draft)).unwrap();
    assert_eq!(super::check_bundle(&bytes).unwrap().len(), 1);
}

#[test]
fn a_package_places_each_file_once() {
    use super::check::{Rules, package as check_package};
    use super::model::Asset;
    let f = |from: &str, sha: u8, arch: Option<Vec<Arch>>| PackageFile {
        from: rel(from),
        to: rel("d3d9.dll"),
        sha256: Hex::new([sha; 32]),
        config: false,
        arch,
        api: None,
    };
    let ok = |p: &Package| check_package(p, Rules::Release);
    // One download: one `from`, one hash (the same twice is fine; case counts as the same name).
    let mut p = package("fix-pack");
    p.files = vec![f("d3d9.dll", 1, None), f("d3d9.dll", 1, None)];
    ok(&p).unwrap();
    p.files = vec![f("d3d9.dll", 1, None), f("D3D9.DLL", 2, None)];
    assert_eq!(ok(&p).unwrap_err().at, "files[1].from");
    // An architecture the package does not name.
    p.files = vec![f("d3d9.dll", 1, Some(vec![Arch::X64]))];
    assert_eq!(ok(&p).unwrap_err().at, "files[0].arch");
    // Assets: one build per architecture, the same name with two hashes, each in its own place.
    let mut p = package("fix-pack");
    p.source.release = None;
    p.sha256 = None;
    p.arch = ArchList::List(vec![Arch::X86, Arch::X64]);
    let asset = |arch, file: &str| Asset {
        arch,
        url: format!("https://github.com/owner/fix-pack/releases/download/v1.0/{file}"),
        sha256: Hex::new([0xAB; 32]),
    };
    p.assets = Some(vec![asset(Arch::X86, "a.zip"), asset(Arch::X64, "b.zip")]);
    p.files = vec![
        f("dinput8.dll", 1, Some(vec![Arch::X86])),
        f("dinput8.dll", 2, Some(vec![Arch::X64])),
        f("readme.txt", 3, None),
    ];
    ok(&p).unwrap();
    // Without `arch` a file comes from every asset: then one hash for both is wrong.
    p.files = vec![
        f("dinput8.dll", 1, None),
        f("dinput8.dll", 2, Some(vec![Arch::X64])),
    ];
    assert_eq!(ok(&p).unwrap_err().at, "files[1].from");
    // An architecture without an asset.
    p.assets = Some(vec![asset(Arch::X86, "a.zip")]);
    p.files = vec![f("dinput8.dll", 1, Some(vec![Arch::X64]))];
    assert_eq!(ok(&p).unwrap_err().at, "files[0].arch");
}

/// P4-8: slots bound to files. Every DLL a package installs is a slot for each API it is for,
/// and once the package names files, every slot is installed by one of them.
#[test]
fn slots_are_bound_to_the_files() {
    use super::check::{Rules, package as check_package};
    use std::collections::BTreeMap;
    let ok = |p: &Package| check_package(p, Rules::Release);
    let f = |to: &str, api: Option<Vec<Api>>| PackageFile {
        from: rel(to),
        to: rel(to),
        sha256: Hex::new([0xCD; 32]),
        config: false,
        arch: None,
        api,
    };
    // The fixture: `d3d9.dll` is its slot.
    let mut p = package("fix-pack");
    ok(&p).unwrap();
    // A DLL that is no slot (also in a folder, also in another case of `.dll`).
    p.files.push(f(r"bin\extra.DLL", None));
    assert_eq!(ok(&p).unwrap_err().at, "files[1].to");
    p.slots.push("extra.dll".into());
    ok(&p).unwrap();
    // A slot nothing installs.
    p.slots.push("dxgi.dll".into());
    assert_eq!(ok(&p).unwrap_err().at, "slots[2]");
    // No files yet (a draft being curated): slots alone are fine.
    p.files.clear();
    ok(&p).unwrap();
    // Per API: a file for d3d9 is a slot of d3d9; one without `api` of every API of the package.
    let mut p = package("fix-pack");
    p.slots.clear();
    p.apis = Some(vec![Api::D3d9, Api::D3d11]);
    p.slots_by_api = Some(BTreeMap::from([
        (Api::D3d9, vec!["d3d9.dll".to_owned()]),
        (
            Api::D3d11,
            vec!["d3d11.dll".to_owned(), "dxgi.dll".to_owned()],
        ),
    ]));
    p.files = vec![
        f("d3d9.dll", Some(vec![Api::D3d9])),
        f("d3d11.dll", Some(vec![Api::D3d11])),
        f("dxgi.dll", Some(vec![Api::D3d11])),
        f("readme.txt", None),
    ];
    ok(&p).unwrap();
    p.files[0].api = None;
    assert_eq!(
        ok(&p).unwrap_err().at,
        "files[0].to",
        "d3d9.dll is no slot of d3d11"
    );
    p.files[0].api = Some(vec![Api::D3d9]);
    p.files.remove(2);
    let e = ok(&p).unwrap_err();
    assert!(e.at.starts_with("slots_by_api."), "{e}");
}

/// P4-8: a package that lists the builds it supports lists every SHA-1 of a Topo that names
/// it (the engine checks the matched build as well).
#[test]
fn supports_exe_sha1_covers_the_topos_builds() {
    let mut i = index(4);
    i.topos[0].matches.exes[0].sha1 = Some(Hex::new([0x22; 20]));
    assert!(aside(&i).is_empty());
    i.packages[0].supports_exe_sha1 = vec![Hex::new([0x33; 20])];
    assert_eq!(
        aside(&i),
        vec![
            "topo a-game: breaks a rule of this build: match.exes[0].sha1: package fix-pack does \
             not list the SHA-1 of game.exe in supports_exe_sha1"
        ]
    );
    i.packages[0].supports_exe_sha1.push(Hex::new([0x22; 20]));
    assert!(aside(&i).is_empty());
}

/// P5-4: one variant ID names one fix across the issues of a Topo. Copies with the same `kind`
/// and `steps` load (their `status`, `sources` and `tradeoffs` may differ); a copy with other
/// steps or another kind is refused at load and in the index, naming the Topo, the variant
/// and the field. No counter-rule: two IDs may hold the same steps.
#[test]
fn one_variant_id_names_one_fix_across_issues() {
    use super::check::{self, Rules};
    use super::model::{Source, SourceType};

    let mut i = index(5);
    let first = i.topos[0].issues[0].clone();
    let mut copy = first.clone();
    copy.id = id("crash");
    copy.title = "Crash".into();
    copy.variants[0].status = VariantStatus::Verified;
    copy.variants[0].tradeoffs = vec!["Slower start".into()];
    copy.variants[0].sources = vec![Source {
        kind: SourceType::Repo,
        url: "https://github.com/owner/fix-pack".into(),
    }];
    // Another ID with the same steps: no counter-rule.
    let mut twin = copy.variants[0].clone();
    twin.id = id("same-steps");
    copy.variants.push(twin);
    i.topos[0].issues.push(copy);
    for rules in [Rules::Source, Rules::Release] {
        assert_eq!(check::topo(&i.topos[0], rules), Ok(()), "{rules:?}");
    }
    assert!(aside(&i).is_empty());

    let mut steps = i.clone();
    steps.topos[0].issues[1].variants[0]
        .steps
        .push(TopoStep::Package(id("fix-pack")));
    let mut kind = i.clone();
    kind.topos[0].issues[1].variants[0].kind = Kind::Enhancement;
    for (bad, field) in [(&steps, "steps"), (&kind, "kind")] {
        for rules in [Rules::Source, Rules::Release] {
            let e = check::topo(&bad.topos[0], rules).unwrap_err();
            assert_eq!(e.at, format!("issues[1].variants[0].{field}"), "{rules:?}");
            assert_eq!(
                e.what,
                format!(
                    "variant fix-pack differs in {field} from its copy under issue stutter \
                     (issues[0].variants[0]): one variant ID names one fix"
                )
            );
        }
        let e = aside(bad).join("\n");
        assert!(
            e.starts_with("topo a-game: breaks a rule of this build: issues[1].variants[0].")
                && e.contains("variant fix-pack differs in"),
            "{e}"
        );
    }
}

/// P5-5c review: a variant that installs a package whose files depend on the graphics API (or
/// one it requires) is refused for a Topo whose executables name more than one API, until the
/// game options of ADR 0032 name the one the game runs; one API, or a package without API files,
/// passes.
#[test]
fn an_api_dependent_package_needs_one_api_in_the_topo() {
    let mut i = index(4);
    let mut dx10 = i.topos[0].matches.exes[0].clone();
    dx10.path = rel("game_dx10.exe");
    dx10.sha256 = Some(Hex::new([0x12; 32]));
    dx10.api = Api::D3d10;
    i.topos[0].matches.exes.push(dx10);
    assert!(aside(&i).is_empty());
    for by in ["file", "apis", "required"] {
        let mut j = i.clone();
        match by {
            "file" => j.packages[0].files[0].api = Some(vec![Api::D3d9]),
            "apis" => j.packages[0].apis = Some(vec![Api::D3d9]),
            _ => {
                let mut wrapper = package("api-wrapper");
                wrapper.files[0].api = Some(vec![Api::D3d9]);
                j.packages[0].requires = vec![id("api-wrapper")];
                j.packages.insert(0, wrapper);
            }
        }
        let e = aside(&j).join("\n");
        assert!(
            e.starts_with("topo a-game: breaks a rule of this build: issues[0].variants[0]: ")
                && e.contains("variant fix-pack installs package")
                && e.contains("depend on the graphics API"),
            "{by}: {e}"
        );
        // The same Topo with one API passes.
        j.topos[0].matches.exes.truncate(1);
        assert!(aside(&j).is_empty(), "{by}");
    }
}

/// Forward compatibility (ADR 0024 amendment): FC1 to FC7 and the frozen bundle.
mod fc;
