//! The helper's run against the fake (ADR 0023 §3, §5, §14; A4 S1, S7, S8): a two-process fake
//! with a fake transport. The CLI side writes the request into the fake world and starts the
//! helper through [`Wire`], an [`Elevation`] that calls `serve` in-process with the helper's view
//! of the same world ([`FakeHelperSystem`]) and hands back the exit code with the process facts
//! of a genuine elevated helper; `client::start` judges it as the CLI does.
//!
//! - H §3: the order (privileges, elevation, own image, instance lock, arguments) and the
//!   arguments read only after it.
//! - R the refusal matrix: every step of §3 and §5 fails once and gives its `Refused(...)`.
//! - T tamper cases: request hash, swapped file IDs, other build, index below the floor, revoked
//!   and foreign key, exe hash, anti-cheat that appears after the plan, ops that differ.
//! - M remove (R1): needs no index and no game folder; done only when nothing is left to do.
//! - D the shared derivation and the CLI's plan check (A4 S7); S the process check (A4 S8).
//!
//! Every Topo, folder, hash and ID is invented. The `firewall_rule` step is signed into the test
//! index under the test-only review seam (`catalog::check::review_seam`).

use std::ffi::OsString;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::client;
use super::derive::{DeriveError, PlanRefusal, check_plan, derive_add};
use super::exit::{HelperExit, OpResult, Reason};
use super::judge::Judged;
use super::request::{
    AddOp, Body, DirRef, RemoveOp, Request, RequestError, RequestName, RequestRef, RootRef, decode,
    encode,
};
use super::serve::{Keys, serve_with};
use crate::catalog::check::review_seam;
use crate::catalog::key::test_key;
use crate::catalog::model::{Id, Topo};
use crate::detect::exe::{AntiCheat, AntiCheatHit, AntiCheatScan};
use crate::path::{RelPath, RootPath};
use crate::plan::{Pick, PlanSource};
use crate::policy::firewall::{Direction, Program, TxnId, rule};
use crate::policy::root::{HelperImage, RootId, helper_image};
use crate::sys::fake::{
    FAKE_USER_SID, FakeElevation, FakeHelperSystem, FakeHelperToken, FakeKnownFolders, FakeSd,
    FakeSystem, TokenCall,
};
use crate::sys::{
    Elevation, HelperLock, HelperPresence, HelperProc, HelperRun, KnownFolder, SysError,
    SysErrorKind, SysResult, System, TokenKind,
};
use crate::topo::{ExeCheck, ExeState, GameFacts};
use crate::wire::hex32;

const PF: &str = r"C:\Program Files";
const HDIR: &str = r"C:\Program Files\Rerun";
const HEXE: &str = r"C:\Program Files\Rerun\rerun-helper.exe";
const APPDIR: &str = r"C:\Users\Player\AppData\Local\Rerun";
const ELEVATE: &str = r"C:\Users\Player\AppData\Local\Rerun\elevate";
const INDEX: &str = r"C:\Users\Player\AppData\Local\Rerun\index";
const GAME: &str = r"D:\Games\G";
const EXE: &str = r"D:\Games\G\bin\game.exe";
const GAME_BYTES: &[u8] = b"MZ invented game";
const TXN: &str = "00000007-00000000000000ab";

fn txn() -> TxnId {
    TXN.parse().unwrap()
}

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// A Topo with an issue `net` whose variant `block` blocks `bin\game.exe`, and an issue
/// `other` whose variant `also` blocks `bin\tool.exe`.
fn topo_json(id: &str, rev: u32, status: &str, game_sha: &str) -> String {
    let tool_sha = hex_upper(&Sha256::digest(b"tool"));
    format!(
        r#"{{"format":1,"id":"{id}","title":"Invented","status":"{status}","rev":{rev},
"match":{{"exes":[{{"path":"bin\\game.exe","sha256":"{game_sha}","api":"d3d9"}},
{{"path":"bin\\tool.exe","sha256":"{tool_sha}","api":"d3d9"}}]}},
"issues":[
 {{"id":"net","title":"Online check","variants":[
   {{"id":"block","status":"verified","kind":"fix","steps":[{{"firewall_rule":{{"exe":"bin\\game.exe","direction":"out"}}}}]}},
   {{"id":"none","status":"verified","kind":"fix","steps":[{{"steam_input":"enable"}}]}}]}},
 {{"id":"other","title":"Tool","variants":[
   {{"id":"also","status":"verified","kind":"fix","steps":[{{"firewall_rule":{{"exe":"bin\\tool.exe","direction":"out"}}}}]}},
   {{"id":"again","status":"verified","kind":"fix","steps":[{{"firewall_rule":{{"exe":"bin\\game.exe","direction":"out"}}}}]}}]}}
]}}"#
    )
}

fn game_sha() -> String {
    hex_upper(&Sha256::digest(GAME_BYTES))
}

/// Signs an index with `topos` and stores it under `INDEX` by hash; returns the hash.
fn put_index(
    sys: &FakeSystem,
    seq: u64,
    topos: &[String],
    sign: fn(&[u8]) -> [u8; 64],
) -> [u8; 32] {
    let index = format!(
        r#"{{"format":1,"seq":{seq},"issued":"2026-11-09T12:00:00Z","topos":[{}],"packages":[]}}"#,
        topos.join(",")
    );
    let sha: [u8; 32] = Sha256::digest(index.as_bytes()).into();
    let h = hex32::to_string(&sha);
    let fs = sys.fake_fs();
    fs.put_file(Path::new(&format!(r"{INDEX}\{h}.json")), index.as_bytes())
        .unwrap();
    fs.put_file(
        Path::new(&format!(r"{INDEX}\{h}.sig")),
        &sign(index.as_bytes()),
    )
    .unwrap();
    sha
}

/// The helper installed admin-only, the game, Rerun's `elevate` and `index` folders.
fn world() -> FakeSystem {
    let sys = FakeSystem::builder()
        .windows_layout()
        .file(HEXE, b"MZ helper".to_vec())
        .file(EXE, GAME_BYTES.to_vec())
        .file(r"D:\Games\G\bin\tool.exe", b"tool".to_vec())
        .dir(ELEVATE)
        .dir(INDEX)
        .dir(r"D:\Games\Other")
        .build()
        .unwrap();
    for p in [PF, HDIR, HEXE] {
        sys.fake_fs()
            .set_sd(Path::new(p), FakeSd::admin_only())
            .unwrap();
    }
    sys
}

fn info_of(sys: &FakeSystem, abs: &str) -> crate::sys::fs::RootInfo {
    #[expect(clippy::disallowed_methods, reason = "test: the CLI side's own handle")]
    let d = sys.fs().open_dir(Path::new(abs)).unwrap();
    d.info().unwrap()
}

fn dir_ref(sys: &FakeSystem, abs: &str) -> DirRef {
    let i = info_of(sys, abs);
    DirRef {
        volume: i.volume_guid.unwrap(),
        file_id: i.file_id,
    }
}

fn root_ref(sys: &FakeSystem, abs: &str) -> RootRef {
    let i = info_of(sys, abs);
    RootRef {
        volume: i.volume_guid.unwrap(),
        id: RootId {
            volume_serial: i.volume_serial,
            file_id: i.file_id,
        },
        path: RootPath::from_final_path(&i.final_path).unwrap(),
    }
}

fn picks(p: &[&str]) -> Vec<Pick> {
    p.iter()
        .map(|s| {
            let (issue, variant) = s.split_once('/').unwrap();
            Pick {
                issue: issue.to_owned(),
                variant: variant.to_owned(),
            }
        })
        .collect()
}

/// The add request the CLI would write for `net/block` of the index `index`.
fn add_request(sys: &FakeSystem, index: [u8; 32]) -> Request {
    Request {
        build: crate::BUILD_ID.to_owned(),
        txn: txn(),
        body: Body::Add {
            source: PlanSource {
                index,
                topo: "invented-game".to_owned(),
                rev: 3,
                picks: picks(&["net/block"]),
            },
            index_dir: dir_ref(sys, INDEX),
            root: root_ref(sys, GAME),
            ops: vec![AddOp {
                op: 4,
                program: RelPath::parse(r"bin\game.exe").unwrap(),
                direction: Direction::Out,
            }],
        },
    }
}

fn add_ops(req: &mut Request) -> &mut Vec<AddOp> {
    match &mut req.body {
        Body::Add { ops, .. } => ops,
        Body::Remove { .. } => unreachable!(),
    }
}

/// Writes the request bytes as `<txn>-1.req` (the CLI side); returns its reference and hash.
fn write_bytes(sys: &FakeSystem, bytes: &[u8]) -> (RequestRef, [u8; 32]) {
    let name = RequestName::new(txn(), 1).unwrap();
    let path = format!(r"{ELEVATE}\{name}");
    let _ = sys.fake_fs().remove_abs(Path::new(&path));
    sys.fake_fs().put_file(Path::new(&path), bytes).unwrap();
    let at = RequestRef {
        dir: dir_ref(sys, ELEVATE),
        name,
    };
    (at, Sha256::digest(bytes).into())
}

fn write(sys: &FakeSystem, req: &Request) -> (RequestRef, [u8; 32]) {
    write_bytes(sys, &encode(req).unwrap())
}

fn test_keys() -> Keys {
    Keys {
        trusted: vec![test_key::public()],
        revoked: Vec::new(),
        min_seq: 1,
    }
}

fn image(sys: &FakeSystem) -> HelperImage {
    helper_image(sys).unwrap()
}

/// The fake transport (module docs): the helper runs in-process in the same world.
struct Wire<'w> {
    world: &'w FakeSystem,
    keys: Keys,
    token: fn(FakeHelperToken) -> FakeHelperToken,
    known_folders: Option<FakeKnownFolders>,
}

impl<'w> Wire<'w> {
    fn new(world: &'w FakeSystem) -> Self {
        Self {
            world,
            keys: test_keys(),
            token: |t| t,
            known_folders: None,
        }
    }
}

impl Elevation for Wire<'_> {
    fn token_kind(&self) -> SysResult<TokenKind> {
        Ok(TokenKind::Filtered)
    }

    fn run_helper(&self, image_path: &RootPath, args: &[&str]) -> SysResult<HelperRun> {
        let nt = image(self.world).nt_name;
        assert_eq!(image_path, &image(self.world).path);
        let token = (self.token)(FakeHelperToken::new(true).image(&nt));
        let mut helper = FakeHelperSystem::new(self.world, token);
        if let Some(kf) = &self.known_folders {
            helper = helper.with_known_folders(kf.clone());
        }
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let exit = serve_with(&helper, || args, &self.keys);
        Ok(HelperRun::Exited {
            code: exit.to_code(),
            proc: HelperProc {
                image: Some(nt),
                elevated: Some(true),
            },
        })
    }

    fn helper_running(&self, _: &str) -> SysResult<HelperPresence> {
        Ok(HelperPresence::None)
    }

    fn helper_lock(&self) -> SysResult<HelperLock> {
        Ok(HelperLock::Free)
    }
}

/// The CLI side: starts the helper for `at` and judges the run.
fn run_on(wire: &Wire<'_>, at: &RequestRef, sha: &[u8; 32], batch: usize) -> Judged {
    client::start(wire, &image(wire.world), at, sha, batch).unwrap()
}

fn refused(r: Reason) -> Judged {
    Judged::Exit(HelperExit::refused(r))
}

/// A world with the index and an add request written; the request as the CLI wrote it.
fn ready() -> (FakeSystem, Request) {
    let sys = world();
    let idx = put_index(
        &sys,
        1,
        &[topo_json("invented-game", 3, "active", &game_sha())],
        test_key::sign,
    );
    let req = add_request(&sys, idx);
    (sys, req)
}

/// Runs `f` with `firewall_rule` counted as reviewed (module docs).
fn seam(f: impl FnOnce()) {
    review_seam::firewall_rule(f);
}

// ---------- H: §3 ----------

fn serve_alone(
    token: FakeHelperToken,
    sys: &FakeSystem,
    args: Vec<OsString>,
) -> (HelperExit, Vec<TokenCall>) {
    let helper = FakeHelperSystem::new(sys, token);
    let exit = serve_with(&helper, || args, &test_keys());
    (exit, helper.fake_token().calls())
}

#[test]
fn h_the_order_of_section_3() {
    let sys = world();
    let nt = image(&sys).nt_name;
    use TokenCall::{DropPrivileges as D, InstanceLock as L, IsElevated as E, OwnImage as I};
    let cases: Vec<(FakeHelperToken, Reason, Vec<TokenCall>)> = vec![
        (
            FakeHelperToken::new(true).image(&nt).fail(D),
            Reason::Internal,
            vec![D],
        ),
        (
            FakeHelperToken::new(false).image(&nt),
            Reason::NotElevated,
            vec![D, E],
        ),
        (
            FakeHelperToken::new(true).image(&nt).fail(E),
            Reason::Internal,
            vec![D, E],
        ),
        (
            FakeHelperToken::new(true),
            Reason::ImageFolder,
            vec![D, E, I],
        ),
        (
            FakeHelperToken::new(true).image(r"\Device\X\target\debug\rerun-helper.exe"),
            Reason::ImageFolder,
            vec![D, E, I],
        ),
        (
            FakeHelperToken::new(true).image(&nt).busy(),
            Reason::Busy,
            vec![D, E, I, L],
        ),
        (
            FakeHelperToken::new(true).image(&nt).fail(L),
            Reason::Internal,
            vec![D, E, I, L],
        ),
        (
            FakeHelperToken::new(true).image(&nt.to_uppercase()),
            Reason::Usage,
            vec![D, E, I, L],
        ),
    ];
    for (token, reason, calls) in cases {
        let (exit, got) = serve_alone(token, &sys, Vec::new());
        assert_eq!(exit, HelperExit::refused(reason), "{calls:?}");
        assert_eq!(got, calls);
    }
}

#[test]
fn h_the_arguments_are_read_only_after_section_3() {
    use std::cell::Cell;
    let sys = world();
    let nt = image(&sys).nt_name;
    let read = Cell::new(false);
    for token in [
        FakeHelperToken::new(false).image(&nt),
        FakeHelperToken::new(true)
            .image(&nt)
            .fail(TokenCall::DropPrivileges),
        FakeHelperToken::new(true),
        FakeHelperToken::new(true).image(&nt).busy(),
    ] {
        let helper = FakeHelperSystem::new(&sys, token);
        let _ = serve_with(
            &helper,
            || {
                read.set(true);
                Vec::new()
            },
            &test_keys(),
        );
        assert!(!read.get());
    }
}

#[test]
fn h_a_helper_not_installed_admin_only_refuses_its_image() {
    let sys = world();
    let nt = image(&sys).nt_name;
    let mut sd = FakeSd::admin_only();
    if let Some(d) = sd.dacl.as_mut() {
        d.push(FakeSd::allow("S-1-5-32-545", 0x2));
    }
    sys.fake_fs().set_sd(Path::new(HDIR), sd).unwrap();
    let (exit, _) = serve_alone(FakeHelperToken::new(true).image(&nt), &sys, Vec::new());
    assert_eq!(exit, HelperExit::refused(Reason::ImageFolder));
}

#[test]
fn h_only_the_exact_argument_form_is_read() {
    let (sys, req) = ready();
    let (at, sha) = write(&sys, &req);
    let good = at.to_args(&sha);
    let nt = image(&sys).nt_name;
    let mut bad: Vec<Vec<String>> = vec![
        Vec::new(),
        good[..6].to_vec(),
        [good.clone(), vec!["--extra".to_owned()]].concat(),
    ];
    for (i, v) in [
        (1, at.dir.volume.to_string().to_uppercase()),
        (3, format!("0{:032x}", at.dir.file_id)),
        (3, format!("{:032x}", at.dir.file_id).replace('1', "A")),
        (5, format!("{TXN}-01.req")),
        (5, format!(r"..\{TXN}-1.req")),
        (7, hex32::to_string(&sha).to_uppercase()),
        (0, "--Volume".to_owned()),
    ] {
        let mut a = good.clone();
        a[i] = v;
        bad.push(a);
    }
    for a in bad {
        let args = a.iter().map(OsString::from).collect();
        let (exit, _) = serve_alone(FakeHelperToken::new(true).image(&nt), &sys, args);
        assert_eq!(exit, HelperExit::refused(Reason::Usage), "{a:?}");
    }
}

// ---------- the codec ----------

#[test]
fn the_request_round_trips_and_is_strict() {
    let (sys, req) = ready();
    let bytes = encode(&req).unwrap();
    assert_eq!(decode(&bytes, crate::BUILD_ID).unwrap(), req);
    let text = String::from_utf8(bytes.clone()).unwrap();
    // Another build is told apart from a broken request, whatever else the file holds.
    assert_eq!(decode(&bytes, "0.0.0+other"), Err(RequestError::Build));
    let other = text.replacen(r#""format":1"#, r#""format":2"#, 1);
    assert_eq!(
        decode(other.as_bytes(), crate::BUILD_ID),
        Err(RequestError::Format)
    );
    let extra = text.replacen(r#""txn""#, r#""x":1,"txn""#, 1);
    assert!(matches!(
        decode(extra.as_bytes(), crate::BUILD_ID),
        Err(RequestError::Form(_))
    ));
    let deep = text.replacen(r#""op":4"#, r#""op":4,"x":1"#, 1);
    assert!(matches!(
        decode(deep.as_bytes(), crate::BUILD_ID),
        Err(RequestError::Form(_))
    ));
    let big = vec![b' '; usize::try_from(super::MAX_REQUEST_BYTES).unwrap() + 1];
    assert_eq!(decode(&big, crate::BUILD_ID), Err(RequestError::TooLarge));
    // 1 to 8 consecutive ops.
    let mut r = req.clone();
    add_ops(&mut r).clear();
    assert!(encode(&r).is_err());
    let mut r = req.clone();
    let op = add_ops(&mut r)[0].clone();
    add_ops(&mut r).push(AddOp {
        op: 6,
        ..op.clone()
    });
    assert!(encode(&r).is_err());
    let mut r = req;
    for i in 5..13 {
        add_ops(&mut r).push(AddOp {
            op: i,
            ..op.clone()
        });
    }
    assert!(encode(&r).is_err());
    // Op 0 is the profile fence, never a helper op.
    let mut r0 = r.clone();
    add_ops(&mut r0).truncate(1);
    add_ops(&mut r0)[0].op = 0;
    assert!(encode(&r0).is_err());
    let zero = text.replacen(r#""op":4"#, r#""op":0"#, 1);
    assert!(matches!(
        decode(zero.as_bytes(), crate::BUILD_ID),
        Err(RequestError::Form(_))
    ));
    // A direction this build does not know is no request.
    let inbound = text.replacen(r#""direction":"out""#, r#""direction":"in""#, 1);
    assert_ne!(inbound, text);
    assert!(matches!(
        decode(inbound.as_bytes(), crate::BUILD_ID),
        Err(RequestError::Form(_))
    ));
    drop(sys);
}

#[test]
fn request_names_have_one_form() {
    let n = RequestName::new(txn(), 12).unwrap();
    assert_eq!(n.as_str(), format!("{TXN}-12.req"));
    assert_eq!(RequestName::parse(n.as_str()), Some(n));
    for bad in [
        format!("{TXN}-0.req"),
        format!("{TXN}-01.req"),
        format!("{TXN}-1.REQ"),
        format!("{TXN}-1"),
        format!("{}-1.req", TXN.to_uppercase()),
        "1.req".to_owned(),
        format!("{TXN}--1.req"),
    ] {
        assert_eq!(RequestName::parse(&bad), None, "{bad}");
    }
    assert!(RequestName::new(txn(), 0).is_none());
}

// ---------- R: the refusal matrix ----------

/// The whole chain passes: the helper reaches step 8, observes once, and (P4-2c, no write side)
/// refuses with `Firewall`, every op `NotRun`.
#[test]
fn r_every_step_passes_up_to_the_write() {
    seam(|| {
        let (sys, req) = ready();
        let (at, sha) = write(&sys, &req);
        let wire = Wire::new(&sys);
        assert_eq!(run_on(&wire, &at, &sha, 1), refused(Reason::Firewall));
        assert_eq!(
            sys.fake_firewall().selects(),
            1,
            "one enumeration before the batch"
        );
        // A shipped helper (release slots empty, no test key) stops at the index.
        let mut shipped = Wire::new(&sys);
        shipped.keys.trusted = crate::catalog::key::release_keys();
        assert_eq!(run_on(&shipped, &at, &sha, 1), refused(Reason::Index));
    });
    // Without the review seam the same index is no valid index: `firewall_rule` is draft only
    // until reviewed, so even a test-key helper stops at the index.
    let (sys, req) = ready();
    let (at, sha) = write(&sys, &req);
    assert_eq!(
        run_on(&Wire::new(&sys), &at, &sha, 1),
        refused(Reason::Index)
    );
}

/// A request with a direction the helper does not derive (today the only one is `out`, so the
/// file form itself refuses another) is no request.
#[test]
fn r_another_direction_is_refused() {
    seam(|| {
        let (sys, req) = ready();
        let text = String::from_utf8(encode(&req).unwrap()).unwrap();
        let inbound = text.replacen(r#""direction":"out""#, r#""direction":"in""#, 1);
        let (at, sha) = write_bytes(&sys, inbound.as_bytes());
        assert_eq!(
            run_on(&Wire::new(&sys), &at, &sha, 1),
            refused(Reason::Request)
        );
    });
}

/// Each step of §5 fails once; the reason is that step's.
#[test]
fn r_each_step_fails_once() {
    type Breaker = fn(&FakeSystem, &mut Request, &mut Wire<'_>) -> Option<Vec<u8>>;
    let cases: Vec<(&str, Breaker, Reason)> = vec![
        ("empty request", |_, _, _| Some(Vec::new()), Reason::Request),
        (
            "not JSON",
            |_, _, _| Some(b"not json".to_vec()),
            Reason::Request,
        ),
        (
            "other build",
            |_, r, _| {
                r.build = "0.0.0+other".to_owned();
                None
            },
            Reason::Build,
        ),
        (
            "index missing",
            |_, r, _| {
                if let Body::Add { source, .. } = &mut r.body {
                    source.index = [9; 32];
                }
                None
            },
            Reason::Index,
        ),
        (
            "unknown Topo",
            |_, r, _| {
                if let Body::Add { source, .. } = &mut r.body {
                    source.topo = "unknown-game".to_owned();
                }
                None
            },
            Reason::Topo,
        ),
        (
            "other revision",
            |_, r, _| {
                if let Body::Add { source, .. } = &mut r.body {
                    source.rev = 2;
                }
                None
            },
            Reason::Topo,
        ),
        (
            "unknown variant",
            |_, r, _| {
                if let Body::Add { source, .. } = &mut r.body {
                    source.picks = picks(&["net/nothing"]);
                }
                None
            },
            Reason::Topo,
        ),
        (
            "two rules for one exe",
            |_, r, _| {
                if let Body::Add { source, .. } = &mut r.body {
                    source.picks = picks(&["net/block", "other/again"]);
                }
                None
            },
            Reason::Topo,
        ),
        (
            "root path differs",
            |s, r, _| {
                if let Body::Add { root, .. } = &mut r.body {
                    root.path = root_ref(s, r"D:\Games\Other").path;
                }
                None
            },
            Reason::Root,
        ),
        (
            "root serial differs",
            |_, r, _| {
                if let Body::Add { root, .. } = &mut r.body {
                    root.id.volume_serial ^= 1;
                }
                None
            },
            Reason::Root,
        ),
        (
            "exe differs",
            |s, _, _| {
                s.fake_fs().remove_abs(Path::new(EXE)).unwrap();
                s.fake_fs().put_file(Path::new(EXE), b"MZ patched").unwrap();
                None
            },
            Reason::Program,
        ),
        (
            "exe linked",
            |s, _, _| {
                s.fake_fs()
                    .put_hardlink(Path::new(EXE), Path::new(r"D:\Games\G\copy.exe"))
                    .unwrap();
                None
            },
            Reason::Program,
        ),
        (
            "exe missing",
            |s, _, _| {
                s.fake_fs().remove_abs(Path::new(EXE)).unwrap();
                None
            },
            Reason::Program,
        ),
        (
            "anti-cheat appears",
            |s, _, _| {
                s.fake_fs()
                    .mkdir_all(Path::new(r"D:\Games\G\bin\BattlEye"))
                    .unwrap();
                None
            },
            Reason::AntiCheat,
        ),
        (
            "other program",
            |_, r, _| {
                add_ops(r)[0].program = RelPath::parse(r"bin\tool.exe").unwrap();
                None
            },
            Reason::Ops,
        ),
        (
            "one op too many",
            |_, r, _| {
                let op = add_ops(r)[0].clone();
                add_ops(r).push(AddOp { op: 5, ..op });
                None
            },
            Reason::Ops,
        ),
        (
            "program spelled otherwise",
            |_, r, _| {
                add_ops(r)[0].program = RelPath::parse(r"bin\GAME.exe").unwrap();
                None
            },
            Reason::Ops,
        ),
        (
            "rule name taken",
            |s, r, _| {
                let Body::Add { root, .. } = &r.body else {
                    unreachable!()
                };
                let p =
                    Program::new(&root.path, &RelPath::parse(r"bin\game.exe").unwrap()).unwrap();
                let id = Id::parse("invented-game").unwrap();
                s.fake_firewall()
                    .push(rule(&id, &txn(), 4, &p, Direction::Out));
                None
            },
            Reason::DuplicateName,
        ),
        (
            "firewall unreadable",
            |s, _, _| {
                s.fake_firewall()
                    .fail_with(Some(SysErrorKind::AccessDenied));
                None
            },
            Reason::Firewall,
        ),
    ];
    seam(|| {
        for (what, brk, reason) in cases {
            let (sys, mut req) = ready();
            let mut wire_keys = Wire::new(&sys);
            let raw = brk(&sys, &mut req, &mut wire_keys);
            let keys = wire_keys.keys.clone();
            let (at, sha) = match raw {
                Some(b) => write_bytes(&sys, &b),
                None => write(&sys, &req),
            };
            let mut wire = Wire::new(&sys);
            wire.keys = keys;
            assert_eq!(run_on(&wire, &at, &sha, 1), refused(reason), "{what}");
        }
    });
}

// ---------- T: tampering ----------

#[test]
fn t_the_request_file_and_its_folder() {
    seam(|| {
        let (sys, req) = ready();
        let (at, sha) = write(&sys, &req);
        let wire = Wire::new(&sys);
        // Its hash differs from the argument (changed after the CLI wrote it).
        let mut other = sha;
        other[0] ^= 1;
        assert_eq!(run_on(&wire, &at, &other, 1), refused(Reason::Request));
        // Swapped file IDs: the index folder named as the `elevate` folder, and the other way.
        let mut swapped = at.clone();
        swapped.dir = dir_ref(&sys, INDEX);
        assert_eq!(run_on(&wire, &swapped, &sha, 1), refused(Reason::Request));
        let mut r = req.clone();
        if let Body::Add { index_dir, .. } = &mut r.body {
            *index_dir = dir_ref(&sys, ELEVATE);
        }
        let (at2, sha2) = write(&sys, &r);
        assert_eq!(run_on(&wire, &at2, &sha2, 1), refused(Reason::Index));
        // The root by the ID of another folder.
        let mut r = req.clone();
        if let Body::Add { root, .. } = &mut r.body {
            root.id.file_id = dir_ref(&sys, r"D:\Games\Other").file_id;
        }
        let (at3, sha3) = write(&sys, &r);
        assert_eq!(run_on(&wire, &at3, &sha3, 1), refused(Reason::Root));
        // A request whose name names another transaction than its body.
        let mut r = req.clone();
        r.txn = "00000008-00000000000000ab".parse().unwrap();
        let (at4, sha4) = write(&sys, &r);
        assert_eq!(run_on(&wire, &at4, &sha4, 1), refused(Reason::Request));
        // The `elevate` folder swapped for a junction after the CLI wrote the request: the
        // helper opens by identity, so the request it reads is still the CLI's.
        let (at5, sha5) = write(&sys, &req);
        sys.swap_with_junction(ELEVATE, r"D:\Games\Other").unwrap();
        assert_eq!(run_on(&wire, &at5, &sha5, 1), refused(Reason::Firewall));
        // A request file that is a hard link.
        let (sys, req) = ready();
        let (at, sha) = write(&sys, &req);
        sys.fake_fs()
            .put_hardlink(
                Path::new(&format!(r"{ELEVATE}\{}", at.name)),
                Path::new(r"C:\Users\Player\x.req"),
            )
            .unwrap();
        assert_eq!(
            run_on(&Wire::new(&sys), &at, &sha, 1),
            refused(Reason::Request)
        );
        let _ = APPDIR;
    });
}

#[test]
fn t_the_index() {
    seam(|| {
        // Signed by a key the helper does not trust (foreign, or retired: never for an add).
        let sys = world();
        let topo = topo_json("invented-game", 3, "active", &game_sha());
        let idx = put_index(&sys, 1, std::slice::from_ref(&topo), test_key::sign_foreign);
        let (at, sha) = write(&sys, &add_request(&sys, idx));
        assert_eq!(
            run_on(&Wire::new(&sys), &at, &sha, 1),
            refused(Reason::Index)
        );
        // Signed by a revoked key.
        let idx = put_index(&sys, 1, std::slice::from_ref(&topo), test_key::sign);
        let (at, sha) = write(&sys, &add_request(&sys, idx));
        let mut wire = Wire::new(&sys);
        wire.keys.revoked = vec![*test_key::public().bytes()];
        assert_eq!(run_on(&wire, &at, &sha, 1), refused(Reason::Index));
        // An older signed index below the floor of this build.
        let mut wire = Wire::new(&sys);
        wire.keys.min_seq = 2;
        assert_eq!(run_on(&wire, &at, &sha, 1), refused(Reason::Index));
        wire.keys.min_seq = 1;
        assert_eq!(run_on(&wire, &at, &sha, 1), refused(Reason::Firewall));
        // Bytes changed under their name.
        let h = hex32::to_string(&idx);
        let p = format!(r"{INDEX}\{h}.json");
        sys.fake_fs().remove_abs(Path::new(&p)).unwrap();
        sys.fake_fs().put_file(Path::new(&p), b"{}").unwrap();
        assert_eq!(
            run_on(&Wire::new(&sys), &at, &sha, 1),
            refused(Reason::Index)
        );
        // A retired Topo offers nothing elevated.
        let sys = world();
        let idx = put_index(
            &sys,
            1,
            &[topo_json("invented-game", 3, "retired", &game_sha())],
            test_key::sign,
        );
        let (at, sha) = write(&sys, &add_request(&sys, idx));
        assert_eq!(
            run_on(&Wire::new(&sys), &at, &sha, 1),
            refused(Reason::Topo)
        );
    });
}

#[test]
fn t_the_root() {
    seam(|| {
        // A forbidden folder named by its identity (here Rerun's own `elevate` folder below the
        // user's AppData).
        let (sys, mut req) = ready();
        if let Body::Add { root, .. } = &mut req.body {
            *root = root_ref(&sys, ELEVATE);
        }
        let (at, sha) = write(&sys, &req);
        assert_eq!(
            run_on(&Wire::new(&sys), &at, &sha, 1),
            refused(Reason::Root)
        );
        // The game folder swapped for a junction after the plan: opened by ID, the junction is
        // not followed, and the folder the request names has moved away.
        let (sys, req) = ready();
        let (at, sha) = write(&sys, &req);
        sys.swap_with_junction(GAME, r"D:\Games\Other").unwrap();
        assert_eq!(
            run_on(&Wire::new(&sys), &at, &sha, 1),
            refused(Reason::Root)
        );
        // Over-the-shoulder elevation: the helper runs as another account, so a game folder in
        // the user's profile is another user's and refused.
        let sys = world();
        sys.fake_fs()
            .put_file(
                Path::new(r"C:\Users\Player\Games\G\bin\game.exe"),
                GAME_BYTES,
            )
            .unwrap();
        let idx = put_index(
            &sys,
            1,
            &[topo_json("invented-game", 3, "active", &game_sha())],
            test_key::sign,
        );
        let mut req = add_request(&sys, idx);
        if let Body::Add { root, .. } = &mut req.body {
            *root = root_ref(&sys, r"C:\Users\Player\Games\G");
        }
        let (at, sha) = write(&sys, &req);
        assert_eq!(
            run_on(&Wire::new(&sys), &at, &sha, 1),
            refused(Reason::Firewall)
        );
        let mut admin = FakeKnownFolders::default();
        admin.set(KnownFolder::Profile, r"C:\Users\Admin");
        admin.set(KnownFolder::LocalAppData, r"C:\Users\Admin\AppData\Local");
        admin.set(
            KnownFolder::RoamingAppData,
            r"C:\Users\Admin\AppData\Roaming",
        );
        let mut wire = Wire::new(&sys);
        wire.known_folders = Some(admin);
        assert_eq!(run_on(&wire, &at, &sha, 1), refused(Reason::Root));
    });
}

// ---------- M: remove ----------

fn remove_request(sys: &FakeSystem) -> Request {
    let root = root_ref(sys, GAME);
    Request {
        build: crate::BUILD_ID.to_owned(),
        txn: txn(),
        body: Body::Remove {
            topo: Id::parse("invented-game").unwrap(),
            ops: vec![RemoveOp {
                op: 4,
                program: Program::new(&root.path, &RelPath::parse(r"bin\game.exe").unwrap())
                    .unwrap(),
                direction: Direction::Out,
            }],
        },
    }
}

#[test]
fn m_remove_needs_no_index_and_no_game() {
    let sys = world();
    let req = remove_request(&sys);
    // Nothing of the index or the game is read: both gone.
    sys.rename_abs(INDEX, r"C:\Users\Player\gone").unwrap();
    sys.fake_fs().remove_abs(Path::new(EXE)).unwrap();
    let (at, sha) = write(&sys, &req);
    let done = HelperExit::done(&[OpResult::Before]).unwrap();
    assert_eq!(run_on(&Wire::new(&sys), &at, &sha, 1), Judged::Exit(done));
    // A rule still there needs the write side (P4-5b): nothing is changed.
    let Body::Remove { topo, ops } = &req.body else {
        unreachable!()
    };
    let r = rule(topo, &txn(), 4, &ops[0].program, Direction::Out);
    sys.fake_firewall().push(r.clone());
    assert_eq!(
        run_on(&Wire::new(&sys), &at, &sha, 1),
        refused(Reason::Firewall)
    );
    assert_eq!(sys.fake_firewall().rules(), vec![r]);
    // Another build's remove is refused like an add.
    let mut other = req.clone();
    other.build = "0.0.0+other".to_owned();
    let (at, sha) = write(&sys, &other);
    assert_eq!(
        run_on(&Wire::new(&sys), &at, &sha, 1),
        refused(Reason::Build)
    );
}

// ---------- D: the derivation and the CLI's plan check (A4 S7) ----------

fn parsed(json: &str) -> Topo {
    serde_json::from_str(json).unwrap()
}

#[test]
fn d_the_cli_derives_what_the_helper_derives() {
    let t = parsed(&topo_json("invented-game", 3, "active", &game_sha()));
    let a = derive_add(&t, &picks(&["net/block", "other/also"])).unwrap();
    assert_eq!(
        a.iter().map(|x| x.exe.as_str()).collect::<Vec<_>>(),
        [r"bin\game.exe", r"bin\tool.exe"]
    );
    assert!(derive_add(&t, &picks(&["net/none"])).unwrap().is_empty());
    assert!(matches!(
        derive_add(&t, &picks(&["net/block", "other/again"])),
        Err(DeriveError::Duplicate(_))
    ));
    assert!(matches!(
        derive_add(&t, &picks(&["x/y"])),
        Err(DeriveError::Picks(_))
    ));
    let retired = parsed(&topo_json("invented-game", 3, "retired", &game_sha()));
    assert!(matches!(
        derive_add(&retired, &picks(&["net/block"])),
        Err(DeriveError::Retired(_))
    ));
    // sha1 alone anchors nothing elevated (R6), whatever the loader said.
    let sha1_only = topo_json("invented-game", 3, "active", &game_sha()).replacen(
        &format!(r#""sha256":"{}""#, game_sha()),
        r#""sha1":"0000000000000000000000000000000000000000""#,
        1,
    );
    assert!(matches!(
        derive_add(&parsed(&sha1_only), &picks(&["net/block"])),
        Err(DeriveError::NoSha256(_))
    ));
    // More than one batch holds.
    let mut many = t.clone();
    let step = many.issues[0].variants[0].steps[0].clone();
    let exe = many.matches.exes[0].clone();
    many.matches.exes.clear();
    many.issues[0].variants[0].steps.clear();
    for i in 0..9 {
        let mut e = exe.clone();
        e.path = RelPath::parse(&format!(r"bin\g{i}.exe")).unwrap();
        let mut s = step.clone();
        if let crate::catalog::model::TopoStep::FirewallRule(f) = &mut s {
            f.exe = e.path.clone();
        }
        many.matches.exes.push(e);
        many.issues[0].variants[0].steps.push(s);
    }
    assert!(matches!(
        derive_add(&many, &picks(&["net/block"])),
        Err(DeriveError::TooMany(9))
    ));
}

/// What `topo::read_game` would report: `game.exe` and `tool.exe` there with their hashes
/// unless `tool` says otherwise, anti-cheat as given.
fn facts(tool: ExeState, anti_cheat: AntiCheatScan) -> GameFacts {
    let check = |p: &str, state| ExeCheck {
        path: RelPath::parse(p).unwrap(),
        state,
    };
    GameFacts {
        exes: vec![
            check(r"bin\game.exe", ExeState::Match),
            check(r"bin\tool.exe", tool),
        ],
        anti_cheat,
    }
}

#[test]
fn d_the_plan_refuses_what_the_helper_would() {
    let sys = world();
    let t = parsed(&topo_json("invented-game", 3, "active", &game_sha()));
    let good = facts(ExeState::Match, AntiCheatScan::default());
    let both = picks(&["net/block", "other/also"]);
    let mut info = info_of(&sys, GAME);
    assert_eq!(check_plan(&t, &both, &info, &good).unwrap().len(), 2);
    // A non-main anchor with another hash, missing or unreadable: refused at plan time.
    for state in [
        ExeState::Mismatch,
        ExeState::Missing,
        ExeState::Unreadable("x".to_owned()),
    ] {
        let f = facts(state, AntiCheatScan::default());
        assert!(matches!(
            check_plan(&t, &both, &info, &f),
            Err(PlanRefusal::ExeMismatch(p)) if p.as_str() == r"bin\tool.exe"
        ));
        // Not picked, not checked.
        assert_eq!(
            check_plan(&t, &picks(&["net/block"]), &info, &f)
                .unwrap()
                .len(),
            1
        );
    }
    // Anti-cheat found (or a marker unreadable): refused.
    let ac = AntiCheatScan {
        found: vec![AntiCheatHit {
            system: AntiCheat::Battleye,
            path: RelPath::parse(r"bin\BattlEye").unwrap(),
        }],
        unreadable: Vec::new(),
    };
    assert!(matches!(
        check_plan(&t, &both, &info, &facts(ExeState::Match, ac)),
        Err(PlanRefusal::AntiCheat)
    ));
    // The drive.
    info.supports_open_by_id = false;
    assert!(matches!(
        check_plan(&t, &picks(&["net/block"]), &info, &good),
        Err(PlanRefusal::NoOpenById)
    ));
    // Without a helper op neither the drive nor the game matters.
    let bad = facts(ExeState::Missing, AntiCheatScan::default());
    assert!(
        check_plan(&t, &picks(&["net/none"]), &info, &bad)
            .unwrap()
            .is_empty()
    );
    info.supports_open_by_id = true;
    info.volume_guid = None;
    assert!(matches!(
        check_plan(&t, &picks(&["net/block"]), &info, &good),
        Err(PlanRefusal::NoOpenById)
    ));
}

// ---------- S: the process check (A4 S8) ----------

#[test]
fn s_a_running_helper_makes_the_cli_wait() {
    let sys = world();
    let img = image(&sys);
    let e = FakeElevation::default();
    assert!(client::ensure_idle(&e, &img).is_ok());
    e.set_helper_running(Ok(vec![img.nt_name.to_uppercase()]));
    assert_eq!(
        client::ensure_idle(&e, &img).unwrap_err().kind,
        SysErrorKind::Busy
    );
    e.set_helper_running(Ok(vec![r"\Device\X\other\rerun-helper.exe".to_owned()]));
    assert!(client::ensure_idle(&e, &img).is_ok());
    e.set_helper_running(Err(SysError::new(SysErrorKind::AccessDenied, "list")));
    assert_eq!(
        client::ensure_idle(&e, &img).unwrap_err().kind,
        SysErrorKind::AccessDenied
    );
    e.set_helper_running(Ok(Vec::new()));
    // A process of the helper's name that cannot be asked: busy, worded as interference.
    e.set_helper_unaskable(true);
    let why = client::ensure_idle(&e, &img).unwrap_err();
    assert_eq!(why.kind, SysErrorKind::Busy);
    assert!(why.to_string().contains("cannot inspect"), "{why}");
    e.set_helper_unaskable(false);
    // The lock: held by the user (a squatter), by Administrators, unreadable.
    e.set_helper_lock(Ok(HelperLock::Held {
        owner: Some(FAKE_USER_SID.to_owned()),
    }));
    let why = client::ensure_idle(&e, &img).unwrap_err();
    assert!(why.to_string().contains("non-administrator"), "{why}");
    assert!(why.to_string().contains(FAKE_USER_SID), "{why}");
    for owner in [Some("S-1-5-32-544".to_owned()), None] {
        e.set_helper_lock(Ok(HelperLock::Held { owner }));
        let why = client::ensure_idle(&e, &img).unwrap_err();
        assert_eq!(why.kind, SysErrorKind::Busy);
        assert!(!why.to_string().contains("non-administrator"), "{why}");
    }
    e.set_helper_lock(Ok(HelperLock::Free));
    assert!(client::ensure_idle(&e, &img).is_ok());
}
