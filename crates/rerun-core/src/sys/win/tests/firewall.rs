//! The firewall's read side on real Windows (ADR 0023 §8 outcome A, A4 S10, S11; P4-5a). Read
//! only: nothing adds, changes or removes a rule, nothing changes the machine. The S10 child
//! runs with a decoy `SystemRoot`/`windir` in its own environment only.

use std::io::Write as _;
use std::time::Instant;

use windows_sys::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2;

use super::super::com::{self, Apartment, CreateError, EnvMismatch};
use super::super::testfx::{TestRoot, loaded_module, note};
use super::super::{WinFirewall, WinRegistry, WinSystem};
use crate::sys::contract::firewall_read_contract;
use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
use crate::sys::{Firewall, Registry, System};

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
