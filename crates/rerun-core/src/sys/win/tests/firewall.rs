//! The firewall on real Windows (ADR 0023 §8 outcome A, A4 S10, S11; P4-5a, P4-5b). The normal
//! tests read only: nothing adds, changes or removes a rule, nothing changes the machine. The
//! S10 child runs with a decoy `SystemRoot`/`windir` in its own environment only.
//!
//! `#[ignore]`, [SB] only (`sandbox_guard` first, run by `scripts/ci-sandbox.ps1` pass 4 as the
//! runner's elevated administrator): the write contract (`sb_firewall_write_contract`) and the
//! installed test-key helper removing a rule (`sb_test_key_helper_removes_a_rule`). They add and
//! remove real rules of group `Rerun` and leave none behind.

use std::io::Write as _;
use std::time::Instant;

use windows_sys::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2;

use super::super::com::{self, Apartment, CreateError, EnvMismatch};
use super::super::testfx::{TestRoot, is_elevated, loaded_module, note, sandbox_guard};
use super::super::{WinFirewall, WinFirewallWrite, WinHelperSystem, WinRegistry, WinSystem};
use crate::sys::contract::firewall_read_contract;
use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
use crate::sys::{Firewall, FirewallWrite, FwRule, Registry, SysResult, System};

/// The read contract against this machine's firewall, through `WinFirewall` and `WinSystem`.
#[test]
fn win_firewall_fulfils_the_read_contract() {
    firewall_read_contract(&WinFirewall).unwrap_or_else(|e| panic!("{e}"));
    let sys = WinSystem::new().unwrap();
    let a = sys.firewall().select(&|_, _| false).unwrap();
    let b = WinFirewall.select(&|_, _| false).unwrap();
    assert_eq!(a.total, b.total);
}

/// A4 S11: the cost of one enumeration on this machine (name and grouping of every rule) and of
/// a full read of every rule; printed, the bound is `ENUM_DEADLINE`.
#[test]
fn win_firewall_enumeration_cost() {
    let t = Instant::now();
    let names = WinFirewall.select(&|_, _| false).unwrap();
    let names_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    let full = WinFirewall.select(&|_, _| true).unwrap();
    let full_ms = t.elapsed().as_secs_f64() * 1e3;
    let per = |ms: f64| ms * 1e3 / names.total.max(1) as f64;
    note(&format!(
        "MEASURED S11: {} rules; names and groupings {names_ms:.1} ms ({:.1} us per rule); \
         full read {full_ms:.1} ms ({:.1} us per rule)",
        names.total,
        per(names_ms),
        per(full_ms),
    ));
    assert_eq!(full.rules.len(), full.total);
}

const S10_CHILD_MARKER: &str = "RERUN_S10_CHILD";
const S10_CHILD_TEST: &str =
    "sys::win::tests::firewall::s10_child_activates_fwpolicy2_with_a_decoy_environment";
const S10: &str = "S10 ";

/// The child of [`com_and_the_process_environment`]: runs only with the marker set.
#[test]
fn s10_child_activates_fwpolicy2_with_a_decoy_environment() {
    #[expect(
        clippy::disallowed_methods,
        reason = "test gate: only the marker decides whether this is the child process"
    )]
    let child = std::env::var_os(S10_CHILD_MARKER).is_some_and(|v| v == "1");
    if !child {
        return;
    }
    let mut out = std::io::stdout().lock();
    writeln!(out).unwrap();
    let guard = com::check_environment();
    writeln!(out, "{S10}guard={guard:?}").unwrap();
    let apartment = Apartment::enter();
    writeln!(out, "{S10}apartment={}", apartment.is_ok()).unwrap();
    let (product, hr) = com::probe(&NetFwPolicy2);
    writeln!(out, "{S10}product={product:?}").unwrap();
    writeln!(out, "{S10}hr={:#010x}", hr.cast_unsigned()).unwrap();
    let module = loaded_module("FirewallAPI.dll")
        .map_or_else(|| "none".to_owned(), |p| p.display().to_string());
    writeln!(out, "{S10}module={module}").unwrap();
    drop(apartment);
}

/// A4 S10, the evidence: the type and value of `InprocServer32` of `HNetCfg.FwPolicy2` (on build
/// 26300 a `REG_SZ` absolute path, not the `REG_EXPAND_SZ` with `%SystemRoot%` A4 assumed;
/// either is accepted and printed), and a child whose own environment names a decoy folder as
/// `SystemRoot` and `windir` (the folder exists and is empty) shows whether the activation
/// depends on the process environment (it fails or loads from the decoy) or not
/// (`FirewallAPI.dll` from System32). Either way the product path (`create_inproc`) refuses in
/// that child before any activation.
#[test]
fn com_and_the_process_environment() {
    let key = RegKey::new(
        Hive::LocalMachine,
        RegView::Native,
        r"SOFTWARE\Classes\CLSID\{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}\InprocServer32",
    );
    let server = match WinRegistry::new().unwrap().get(&key, "").unwrap() {
        Some(RegValue::ExpandString(s)) => format!("REG_EXPAND_SZ {s}"),
        Some(RegValue::String(s)) => format!("REG_SZ {s}"),
        other => panic!("InprocServer32 is no string: {other:?}"),
    };
    assert!(
        server
            .to_ascii_lowercase()
            .ends_with(r"\system32\firewallapi.dll"),
        "{server}"
    );
    let Some(root) = TestRoot::new("s10-env") else {
        return;
    };
    let decoy = root.work("decoy");
    std::fs::create_dir_all(decoy.join("System32")).unwrap();
    let exe = std::env::current_exe().unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test: starts its own test binary as the child of this check"
    )]
    let mut cmd = std::process::Command::new(&exe);
    cmd.args([S10_CHILD_TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(S10_CHILD_MARKER, "1")
        .env("SystemRoot", &decoy)
        .env("windir", &decoy);
    std::os::windows::process::CommandExt::creation_flags(
        &mut cmd,
        windows_sys::Win32::System::Threading::CREATE_NO_WINDOW,
    );
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "child failed:\n{stdout}");
    let line = |k: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(S10).and_then(|l| l.strip_prefix(k)))
            .unwrap_or_else(|| panic!("no {k} line:\n{stdout}"))
            .to_owned()
    };
    // The product path refuses before any activation.
    let refused = EnvMismatch::Var("SystemRoot");
    assert_eq!(
        line("guard="),
        format!("{:?}", Err::<(), _>(refused.clone()))
    );
    assert_eq!(
        line("product="),
        format!("{:?}", Some(CreateError::Env(refused)))
    );
    let (hr, module) = (line("hr="), line("module="));
    note(&format!(
        "MEASURED S10: InprocServer32 = {server}; with SystemRoot = windir = <decoy> the raw \
         activation gives {hr}, FirewallAPI.dll loaded from {module}"
    ));
}

// ---------- [SB] the write side (P4-5b): the real firewall, CI runner only ----------

/// Where the [SB] firewall tests keep their folders (the CI runner's sandbox layout).
const SB_BASE: &str = r"C:\RerunSandbox\fw";

/// A Rerun rule of the one form for `program`, op `op` of a fixed [SB] transaction.
fn sb_rule(topo: &str, op: u16, program: &str) -> FwRule {
    use crate::catalog::model::Id;
    use crate::policy::firewall::{Direction, Program, rule};
    let program = Program::parse(program).unwrap_or_else(|e| panic!("{program}: {e}"));
    let txn = "00000001-00000000000005b0".parse().unwrap();
    rule(
        &Id::parse(topo).unwrap(),
        &txn,
        op,
        &program,
        Direction::Out,
    )
}

/// The rules of exactly `name`, read through `WinFirewall`.
fn sb_named(name: &str) -> Vec<FwRule> {
    WinFirewall.select(&|n, _| n == name).unwrap().rules
}

/// Adds `r` directly (no read-back check), runs `f` on what reads back, removes it by name.
fn sb_probe<T>(r: &FwRule, f: impl FnOnce(SysResult<()>, Vec<FwRule>) -> T) -> T {
    #[expect(
        clippy::disallowed_methods,
        reason = "[SB] write contract: the probe's own add"
    )]
    let added = WinFirewallWrite.add(r);
    let got = sb_named(&r.name);
    let out = f(added, got);
    #[expect(
        clippy::disallowed_methods,
        reason = "[SB] write contract: removes the probe's own rule"
    )]
    let _ = WinFirewallWrite.remove_named(&r.name);
    assert!(sb_named(&r.name).is_empty(), "probe rule left: {}", r.name);
    out
}

/// [SB] (`scripts/ci-sandbox.ps1` pass 4, the runner's elevated administrator): the firewall
/// write contract on the real Windows Firewall (ADR 0023 §6, §14; B12 c, A4 S6 c and d, N8). It
/// adds and removes rules of group `Rerun` named `Rerun - sb-… - 00000001-00000000000005b0-…`
/// and leaves none behind (the script removes group `Rerun` again afterwards, also after a
/// failure). Measured and logged as `MEASURED`:
/// - the contract (`firewall_write_contract`): every fact of an added rule reads back as set
///   (fails otherwise, with both rules in the message); `Remove` of a name two rules hold, with
///   the name in another case, of a missing name;
/// - the product path `policy::firewall::{add_all, remove_all}` on `WinHelperSystem` for
///   programs of several forms (spaces, `Program Files`, Rerun's longest): `Done` both ways, or
///   the rule as it reads back (normalisation, security L3);
/// - the longest name and program the firewall takes and returns unchanged;
/// - N8: whether the rule is in the service's registry key when `Add` returns, and whether
///   `RegFlushKey` on that key opened for reading succeeds;
/// - the cost of one add and one remove.
#[test]
#[ignore = "[SB] adds and removes real firewall rules; CI runner only (scripts/ci-sandbox.ps1)"]
fn sb_firewall_write_contract() {
    sandbox_guard();
    use crate::policy::firewall::{GROUP, Observed, Written, add_all, remove_all};
    use crate::sys::contract::firewall_write_contract;
    assert!(
        is_elevated(),
        "[SB] pass 4 runs as the runner's elevated administrator"
    );
    let exe = format!(r"{SB_BASE}\game.exe");
    // W1 to W4.
    let a = sb_rule("sb-contract", 1, &exe);
    let b = sb_rule("sb-contract", 2, &format!(r"{SB_BASE}\Other.exe"));
    let facts = firewall_write_contract(&WinFirewall, &WinFirewallWrite, &a, &b)
        .unwrap_or_else(|e| panic!("MEASURED write contract FAILED: {e}"));
    note(&format!(
        "MEASURED B12c/S6c Remove: takes every rule of the name {}, ignores ASCII case {}, a \
         missing name is ok {}",
        facts.takes_every_rule_of_the_name, facts.ignores_case, facts.missing_name_is_ok
    ));

    // The product path for programs of several forms (L3: normalised facts end RolledBack).
    let longest = {
        let head = format!(r"{SB_BASE}\");
        let fill = crate::policy::firewall::MAX_PROGRAM_CHARS - head.len() - ".exe".len();
        format!("{head}{}.exe", "a".repeat(fill))
    };
    let hs = WinHelperSystem::new();
    let mut normalised = Vec::new();
    for (i, program) in [
        format!(r"{SB_BASE}\Game Folder\bin\Game.exe"),
        r"C:\Program Files\RerunFwProbe\Game.exe".to_owned(),
        r"C:\Windows\System32\RerunFwProbe.exe".to_owned(),
        longest,
    ]
    .iter()
    .enumerate()
    {
        let r = sb_rule("sb-product", u16::try_from(10 + i).unwrap(), program);
        let t = Instant::now();
        let added = add_all(&hs, std::slice::from_ref(&r));
        let add_ms = t.elapsed().as_secs_f64() * 1e3;
        let seen = sb_named(&r.name);
        let t = Instant::now();
        let removed = remove_all(&hs, std::slice::from_ref(&r));
        let remove_ms = t.elapsed().as_secs_f64() * 1e3;
        note(&format!(
            "MEASURED product path {program}: add_all {added:?} ({add_ms:.0} ms), remove_all \
             {removed:?} ({remove_ms:.0} ms)"
        ));
        if added != Written::Done(vec![Observed::After]) {
            note(&format!("MEASURED normalised: set {r:?}\n  read {seen:?}"));
            normalised.push(program.clone());
        }
        // Whatever happened, nothing of it stays.
        if !sb_named(&r.name).is_empty() {
            #[expect(clippy::disallowed_methods, reason = "[SB] clean-up of its own rule")]
            let _ = WinFirewallWrite.remove_named(&r.name);
        }
        assert!(sb_named(&r.name).is_empty(), "left: {}", r.name);
    }

    // The longest name and program the firewall returns unchanged.
    let base = sb_rule("sb-len", 30, &exe);
    for n in [106_usize, 255, 256, 260, 1024, 4096, 10_000] {
        let mut r = base.clone();
        r.name = format!(
            "Rerun - sb-len - {}",
            "n".repeat(n - "Rerun - sb-len - ".len())
        );
        let verdict = sb_probe(&r, |added, got| match added {
            Err(e) => format!("refused ({e})"),
            Ok(()) if got.len() == 1 && got[0].name == r.name => "kept".to_owned(),
            Ok(()) => format!(
                "changed: {:?}",
                got.iter().map(|g| g.name.len()).collect::<Vec<_>>()
            ),
        });
        note(&format!("MEASURED name length {n}: {verdict}"));
        if n == 106 {
            assert_eq!(
                verdict, "kept",
                "Rerun's longest rule name (106 characters)"
            );
        }
    }
    for n in [243_usize, 259, 260, 261, 300, 1024, 4096, 32_000] {
        let mut r = base.clone();
        r.name = format!("Rerun - sb-len - program-{n}");
        let head = format!(r"{SB_BASE}\");
        r.program = format!("{head}{}.exe", "p".repeat(n - head.len() - ".exe".len()));
        let verdict = sb_probe(&r, |added, got| match added {
            Err(e) => format!("refused ({e})"),
            Ok(()) if got.len() == 1 && got[0].program == r.program => "kept".to_owned(),
            Ok(()) => format!(
                "changed: {:?}",
                got.iter()
                    .map(|g| g.program.chars().count())
                    .collect::<Vec<_>>()
            ),
        });
        note(&format!("MEASURED program length {n}: {verdict}"));
        if n == 243 {
            assert_eq!(verdict, "kept", "Rerun's longest program (243 characters)");
        }
    }

    // N8: the service's registry key right after Add returns, and RegFlushKey on it.
    let key = RegKey::new(
        Hive::LocalMachine,
        RegView::Native,
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
    );
    let r = sb_rule("sb-n8", 40, &exe);
    let in_registry = sb_probe(&r, |added, _| {
        added.unwrap();
        let marker = format!("|Name={}|", r.name);
        WinRegistry::new()
            .unwrap()
            .values(&key)
            .map(|vals| {
                vals.iter().any(|(_, v)| match v {
                    RegValue::String(s) | RegValue::ExpandString(s) => s.contains(&marker),
                    _ => false,
                })
            })
            .map_err(|e| e.to_string())
    });
    let flushed = super::super::reg::open(
        &super::super::reg::Root::LocalMachine,
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        super::super::reg::ReadAccess::Query,
        super::super::reg::View::Native,
    )
    .and_then(|k| super::super::reg::flush(&k));
    note(&format!(
        "MEASURED N8: the rule is in FirewallRules when Add returns: {in_registry:?}; \
         RegFlushKey on that key opened for KEY_QUERY_VALUE: {flushed:?}"
    ));
    assert!(
        WinFirewall
            .select(&|_, g| g == GROUP)
            .unwrap()
            .rules
            .iter()
            .all(|r| !r.name.contains(" - sb-")),
        "a [SB] rule was left behind"
    );
    assert!(
        normalised.is_empty(),
        "MEASURED: the firewall normalises facts of an added rule for {normalised:?} (see the \
         lines above); policy::firewall must compare the normalised form (security L3)"
    );
}

/// [SB] (`scripts/ci-sandbox.ps1` pass 4, after the script installed the **test-key** helper in
/// `C:\Program Files\Rerun`; A4 S3): the real helper started through Rerun's own start
/// (`WinElevation`, `runas`, no dialog on the runner) for (1) an add request of a Topo the
/// test-key index does not name: `Refused(Topo)` (the helper trusts the test key; a release
/// helper says `Refused(Index)`), and (2) a remove request for a rule of Rerun's form this test
/// added: `Done` with the op `Before`, the rule gone, through the helper's own COM write side
/// with every privilege but `SeChangeNotifyPrivilege` dropped (ADR 0023 §3 step 2: "the firewall
/// needs none", measured here).
#[test]
#[ignore = "[SB] adds and removes a real firewall rule and starts the installed helper; CI runner only"]
fn sb_test_key_helper_removes_a_rule() {
    sandbox_guard();
    use sha2::{Digest, Sha256};

    use super::super::{WinElevation, WinFs};
    use crate::catalog::key::test_key;
    use crate::catalog::model::Id;
    use crate::elevate::client;
    use crate::elevate::exit::{HelperExit, OpResult, Reason};
    use crate::elevate::judge::Judged;
    use crate::elevate::request::{
        AddOp, Body, DirRef, RemoveOp, Request, RequestName, RequestRef, RootRef, encode,
    };
    use crate::path::{RelPath, RootPath};
    use crate::plan::{Pick, PlanSource};
    use crate::policy::firewall::{Direction, Program, Written, add_all};
    use crate::policy::root::{RootId, helper_image};
    use crate::sys::Fs;

    assert!(
        is_elevated(),
        "[SB] pass 4 runs as the runner's elevated administrator"
    );
    let sys = WinSystem::new().unwrap();
    let image = helper_image(&sys).unwrap_or_else(|e| panic!("the helper is not installed: {e}"));
    let base = std::path::PathBuf::from(format!(r"{SB_BASE}\helper"));
    let _ = std::fs::remove_dir_all(&base);
    for d in ["elevate", "index", "game"] {
        std::fs::create_dir_all(base.join(d)).unwrap();
    }
    std::fs::write(base.join(r"game\game.exe"), b"MZ not a program").unwrap();
    let fs = WinFs::new();
    let info = |d: &str| {
        #[expect(clippy::disallowed_methods, reason = "[SB] test: its own folders")]
        let h = fs.open_dir(&base.join(d)).unwrap();
        h.info().unwrap()
    };
    let dir_ref = |d: &str| {
        let i = info(d);
        DirRef {
            volume: i.volume_guid.unwrap(),
            file_id: i.file_id,
        }
    };
    let txn = "00000001-00000000000005b1".parse().unwrap();
    let mut n = 0;
    let mut run = |req: &Request| {
        n += 1;
        let file = encode(req).unwrap();
        let name = RequestName::new(txn, n).unwrap();
        std::fs::write(base.join("elevate").join(name.as_str()), &file).unwrap();
        let at = RequestRef {
            dir: dir_ref("elevate"),
            name,
        };
        let sha: [u8; 32] = Sha256::digest(&file).into();
        let judged = client::start(&WinElevation, &image, &at, &sha, req.op_count()).unwrap();
        note(&format!("MEASURED helper run {n}: {judged:?}"));
        judged
    };

    // (1) The test-key index names no Topo.
    let bytes = br#"{"format":1,"seq":1,"issued":"2026-11-10T12:00:00Z","topos":[],"packages":[]}"#;
    let isha: [u8; 32] = Sha256::digest(bytes).into();
    let hex = crate::wire::hex32::to_string(&isha);
    std::fs::write(base.join(format!(r"index\{hex}.json")), bytes).unwrap();
    std::fs::write(
        base.join(format!(r"index\{hex}.sig")),
        test_key::sign(bytes),
    )
    .unwrap();
    let gi = info("game");
    let game_path = RootPath::from_final_path(&gi.final_path).unwrap();
    let add = Request {
        build: crate::BUILD_ID.to_owned(),
        txn,
        body: Body::Add {
            source: PlanSource {
                index: isha,
                topo: "sb-unknown-topo".to_owned(),
                rev: 1,
                picks: vec![Pick {
                    issue: "net".to_owned(),
                    variant: "block".to_owned(),
                }],
            },
            index_dir: dir_ref("index"),
            root: RootRef {
                volume: gi.volume_guid.unwrap(),
                id: RootId::of(&gi),
                path: game_path.clone(),
            },
            ops: vec![AddOp {
                op: 1,
                program: RelPath::parse("game.exe").unwrap(),
                direction: Direction::Out,
            }],
        },
    };
    assert_eq!(
        run(&add),
        Judged::Exit(HelperExit::refused(Reason::Topo)),
        "Refused(Index) would be a helper without the test key"
    );

    // (2) A rule of Rerun's form, added here, removed by the helper.
    let topo = Id::parse("sb-helper").unwrap();
    let program = Program::new(&game_path, &RelPath::parse("game.exe").unwrap()).unwrap();
    let rule = crate::policy::firewall::rule(&topo, &txn, 1, &program, Direction::Out);
    assert_eq!(
        add_all(&WinHelperSystem::new(), std::slice::from_ref(&rule)),
        Written::Done(vec![crate::policy::firewall::Observed::After])
    );
    let remove = Request {
        build: crate::BUILD_ID.to_owned(),
        txn,
        body: Body::Remove {
            topo,
            ops: vec![RemoveOp {
                op: 1,
                program,
                direction: Direction::Out,
            }],
        },
    };
    let judged = run(&remove);
    let gone = sb_named(&rule.name).is_empty();
    if !gone {
        #[expect(clippy::disallowed_methods, reason = "[SB] clean-up of its own rule")]
        let _ = WinFirewallWrite.remove_named(&rule.name);
    }
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(
        judged,
        Judged::Exit(HelperExit::done(&[OpResult::Before]).unwrap())
    );
    assert!(gone, "the helper's remove left the rule");
}
