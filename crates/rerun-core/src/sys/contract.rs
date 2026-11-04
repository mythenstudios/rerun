//! Contract tests of the system layer: the same checks for `fake` and `win`.
//!
//! Today they run against `sys::fake`. From phase 1/2 they run as `#[ignore]` tests in
//! Windows Sandbox against `sys::win` – that keeps the fake honest.
//!
//! Each function expects an **empty** working root and cleans up at the end.

use std::path::Path;

use super::fs::EntryKind;
use super::registry::{RegKey, RegValue};
use super::{SysErrorKind, SysResult, System};

/// Failed contract with a description.
pub type ContractResult = Result<(), String>;

fn ensure(cond: bool, what: &str) -> ContractResult {
    if cond {
        Ok(())
    } else {
        Err(format!("contract violated: {what}"))
    }
}

fn ok<T>(r: SysResult<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("contract violated: {what}: unexpected error {e}"))
}

fn err_kind<T: std::fmt::Debug>(r: SysResult<T>, kind: SysErrorKind, what: &str) -> ContractResult {
    match r {
        Err(e) if e.kind == kind => Ok(()),
        other => Err(format!(
            "contract violated: {what}: expected {kind}, got {other:?}"
        )),
    }
}

/// File system contract. `root` must be an existing, empty directory.
pub fn fs_contract(sys: &dyn System, root: &Path) -> ContractResult {
    let fs = sys.fs();
    let game = root.join("Game");
    let file = game.join("Data.bin");

    ok(fs.create_dir(&game), "create_dir")?;
    err_kind(
        fs.create_dir(&game),
        SysErrorKind::AlreadyExists,
        "create_dir twice",
    )?;
    ok(fs.write(&file, b"hello"), "write")?;
    ensure(
        ok(fs.read(&file), "read")? == b"hello",
        "read returns written data",
    )?;

    // Case-insensitive, original case is preserved.
    let upper = root.join("GAME").join("DATA.BIN");
    ensure(
        ok(fs.read(&upper), "read other case")? == b"hello",
        "case-insensitive read",
    )?;
    let names: Vec<String> = ok(fs.read_dir(root), "read_dir")?
        .into_iter()
        .map(|e| e.name)
        .collect();
    ensure(names == ["Game"], "read_dir keeps original case")?;

    // Metadata.
    let meta = ok(fs.metadata(&file), "metadata")?;
    ensure(
        meta.is_some_and(|m| m.kind == EntryKind::File && m.len == 5 && !m.readonly),
        "metadata of file",
    )?;
    ensure(
        ok(fs.metadata(&game.join("missing")), "metadata missing")?.is_none(),
        "missing = None",
    )?;
    ensure(
        ok(
            fs.metadata(&game.join("missing").join("deeper")),
            "metadata missing parent",
        )?
        .is_none(),
        "missing parent = None",
    )?;
    err_kind(
        fs.metadata(Path::new("relative\\path")),
        SysErrorKind::InvalidPath,
        "relative path",
    )?;

    // Invalid names (Win32: ERROR_INVALID_NAME).
    for bad in ["a\0b", "a<b", "a|b"] {
        err_kind(
            fs.write(&game.join(bad), b"x"),
            SysErrorKind::InvalidPath,
            "write with invalid name",
        )?;
    }

    // Missing parent directory.
    err_kind(
        fs.write(&game.join("nope").join("x.txt"), b"x"),
        SysErrorKind::NotFound,
        "write with missing parent",
    )?;

    // Non-empty directory.
    err_kind(
        fs.remove_dir(&game),
        SysErrorKind::NotEmpty,
        "remove_dir non-empty",
    )?;

    // Read-only attribute.
    ok(fs.set_readonly(&file, true), "set_readonly")?;
    err_kind(
        fs.write(&file, b"x"),
        SysErrorKind::AccessDenied,
        "write readonly",
    )?;
    err_kind(
        fs.remove_file(&file),
        SysErrorKind::AccessDenied,
        "remove readonly",
    )?;
    ok(fs.set_readonly(&file, false), "clear readonly")?;

    // Rename never overwrites, a case-only change is allowed.
    let other = game.join("Other.bin");
    ok(fs.write(&other, b"other"), "write other")?;
    err_kind(
        fs.rename(&file, &other),
        SysErrorKind::AlreadyExists,
        "rename onto existing",
    )?;
    let recased = game.join("DATA.bin");
    ok(fs.rename(&file, &recased), "rename case only")?;
    let names: Vec<String> = ok(fs.read_dir(&game), "read_dir after recase")?
        .into_iter()
        .map(|e| e.name)
        .collect();
    ensure(
        names.iter().any(|n| n == "DATA.bin"),
        "case-only rename changes stored name",
    )?;

    // Clean up.
    ok(fs.remove_file(&recased), "remove file")?;
    ok(fs.remove_file(&other), "remove other")?;
    err_kind(
        fs.remove_file(&other),
        SysErrorKind::NotFound,
        "remove missing file",
    )?;
    ok(fs.remove_dir(&game), "remove_dir")?;
    ensure(
        ok(fs.read_dir(root), "read_dir root")?.is_empty(),
        "root empty after cleanup",
    )
}

/// Registry contract. `root` must be an existing key without values and subkeys.
pub fn registry_contract(sys: &dyn System, root: &RegKey) -> ContractResult {
    let reg = sys.registry();
    let a = root.join("Alpha");

    ensure(
        ok(reg.create_key(&a), "create_key")?,
        "create_key reports new key",
    )?;
    ensure(
        !ok(reg.create_key(&a), "create_key again")?,
        "create_key reports existing key",
    )?;
    err_kind(
        reg.create_key(&root.join("Missing").join("Child")),
        SysErrorKind::NotFound,
        "create_key with missing parent",
    )?;

    // NUL would truncate the path in the Win32 call and must be rejected.
    err_kind(
        reg.create_key(&root.join("Bad\0Name")),
        SysErrorKind::InvalidPath,
        "create_key with NUL",
    )?;
    err_kind(
        reg.set(&a, "Bad\0Name", &RegValue::Dword(1)),
        SysErrorKind::InvalidPath,
        "set value name with NUL",
    )?;

    // Empty key ≠ missing key.
    ensure(ok(reg.key_exists(&a), "key_exists")?, "empty key exists")?;
    ensure(
        ok(reg.get(&a, "Nope"), "get missing value")?.is_none(),
        "missing value = None",
    )?;
    err_kind(
        reg.get(&root.join("Missing"), "x"),
        SysErrorKind::NotFound,
        "get on missing key",
    )?;

    // Value type is preserved, names are case-insensitive.
    ok(reg.set(&a, "Flag", &RegValue::Dword(1)), "set dword")?;
    let v = ok(reg.get(&a, "FLAG"), "get other case")?;
    ensure(
        v == Some(RegValue::Dword(1)),
        "dword round-trip, case-insensitive name",
    )?;
    ensure(
        v != Some(RegValue::String("1".into())),
        "dword differs from string",
    )?;
    let names: Vec<String> = ok(reg.values(&a), "values")?
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    ensure(names == ["Flag"], "value name keeps original case")?;

    // Default value.
    ok(
        reg.set(&a, "", &RegValue::String("default".into())),
        "set default",
    )?;
    ensure(
        ok(reg.get(&a, ""), "get default")? == Some(RegValue::String("default".into())),
        "default value",
    )?;

    // A key with subkeys cannot be deleted.
    let child = a.join("Child");
    ok(reg.create_key(&child), "create child")?;
    let subs = ok(reg.subkeys(&root.join("ALPHA")), "subkeys other case")?;
    ensure(subs == ["Child"], "subkeys keep original case")?;
    err_kind(
        reg.delete_key(&a),
        SysErrorKind::NotEmpty,
        "delete_key with subkeys",
    )?;
    err_kind(
        reg.delete_value(&a, "Nope"),
        SysErrorKind::NotFound,
        "delete missing value",
    )?;

    // Clean up.
    ok(reg.delete_key(&child), "delete child")?;
    ok(reg.delete_value(&a, "Flag"), "delete value")?;
    ok(reg.delete_value(&a, ""), "delete default")?;
    ok(reg.delete_key(&a), "delete key")?;
    ensure(
        !ok(reg.key_exists(&a), "key_exists after delete")?,
        "key gone",
    )?;
    err_kind(
        reg.delete_key(&a),
        SysErrorKind::NotFound,
        "delete missing key",
    )
}

/// Topology contract: self-consistent data.
pub fn topology_contract(sys: &dyn System) -> ContractResult {
    let t = ok(sys.topology().read(), "topology read")?;
    ensure(t.logical_count() > 0, "at least one logical cpu")?;
    ensure(t.core_count() <= t.logical_count(), "cores <= logical cpus")?;
    ensure(
        t.cpus.iter().all(|c| t.llc_sizes.contains_key(&c.llc)),
        "every llc has a size",
    )?;
    let mut seen = std::collections::BTreeSet::new();
    ensure(
        t.cpus.iter().all(|c| seen.insert((c.group, c.index))),
        "(group, index) unique",
    )
}
