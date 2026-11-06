//! Registry write contract (P2-9, RW1 to RW10): [`RegistryWrite`] against the fake and, in a
//! private app hive, against `sys::win`. Every key and value another program would make is
//! made by the [`RegFixture`]; the contract changes only keys below `root`.

use std::cell::Cell;
use std::rc::Rc;

use super::{RegFixture, Skipped, ensure, err_kind, ok, skip};
use crate::sys::SysErrorKind;
use crate::sys::registry::{Hive, KeyState, RegKey, RegValue, RegView, RegistryWrite, reg_type};
use crate::sys::seq::reg::hook;

/// Value names of `k` as stored, sorted.
fn names(w: &dyn RegistryWrite, k: &RegKey, what: &str) -> Result<Vec<String>, String> {
    let mut v: Vec<String> = ok(w.values(k), what)?.into_iter().map(|(n, _)| n).collect();
    v.sort();
    Ok(v)
}

fn get(w: &dyn RegistryWrite, k: &RegKey, name: &str) -> Result<Option<RegValue>, String> {
    ok(w.get(k, name), &format!("get {k} @ {name:?}"))
}

/// Registry write contract. `root` must be an existing, empty key in `HKCU`, native view.
/// Skipped cases: `"key_link"` (no link keys), `"rename_key"` (the fixture cannot rename a key
/// between the walk and the act), `"volatile_key"`.
pub fn registry_write_contract(
    w: &dyn RegistryWrite,
    fx: &dyn RegFixture,
    root: &RegKey,
) -> Result<Skipped, String> {
    let mut skips = Skipped::new();
    ensure(
        ok(w.key_state(root), "key_state root")?
            == KeyState::Present {
                values: 0,
                subkeys: 0,
            },
        "root exists and is empty",
    )?;

    // RW1: create_key creates one segment and tells whether it did; another spelling is the
    // same key and its stored spelling stays.
    let a = root.join("Alpha");
    ensure(
        ok(w.create_key(&a), "create_key")?,
        "create_key reports a new key",
    )?;
    ensure(
        !ok(w.create_key(&a), "create_key again")?,
        "create_key reports an existing key",
    )?;
    ensure(
        !ok(
            w.create_key(&root.join("ALPHA")),
            "create_key other spelling",
        )?,
        "another spelling is the existing key",
    )?;
    ensure(
        ok(w.subkeys(root), "subkeys")? == ["Alpha"],
        "the stored spelling of a key stays",
    )?;
    err_kind(
        w.create_key(&root.join(r"Missing\Child")),
        SysErrorKind::NotFound,
        "create_key with a missing parent",
    )?;
    err_kind(
        w.create_key(&RegKey::new(root.hive, root.view, "")),
        SysErrorKind::InvalidPath,
        "create_key of the hive root",
    )?;

    // RW2: set with the expected old value, on the walked handle, read back.
    ok(w.set(&a, "Flag", None, &RegValue::Dword(1)), "set new")?;
    ensure(
        get(w, &a, "flag")? == Some(RegValue::Dword(1)),
        "set stores",
    )?;
    err_kind(
        w.set(&a, "Flag", None, &RegValue::Dword(2)),
        SysErrorKind::Mismatch,
        "set expecting a missing value",
    )?;
    err_kind(
        w.set(&a, "Flag", Some(&RegValue::Dword(9)), &RegValue::Dword(2)),
        SysErrorKind::Mismatch,
        "set expecting another value",
    )?;
    err_kind(
        w.set(&a, "Nope", Some(&RegValue::Dword(1)), &RegValue::Dword(2)),
        SysErrorKind::Mismatch,
        "set expecting a value that is missing",
    )?;
    ensure(
        get(w, &a, "Flag")? == Some(RegValue::Dword(1)) && get(w, &a, "Nope")?.is_none(),
        "a refused set writes nothing",
    )?;
    let text = RegValue::String("x".into());
    ok(
        w.set(&a, "FLAG", Some(&RegValue::Dword(1)), &text),
        "set another type in another spelling",
    )?;
    ensure(
        get(w, &a, "Flag")? == Some(text.clone()),
        "the type changes",
    )?;
    ensure(
        names(w, &a, "values")? == ["Flag"],
        "the stored spelling of a value name stays (observed on Windows)",
    )?;
    let raw = RegValue::decode(reg_type::REG_NONE, &[1, 2, 3]);
    ok(w.set(&a, "Raw", None, &raw), "set raw")?;
    ensure(
        get(w, &a, "Raw")? == Some(raw.clone()),
        "a raw value is exact",
    )?;
    ensure(
        ok(w.read(&a, "RAW"), "read raw")? == Some(raw.clone()),
        "read returns the exact value",
    )?;
    err_kind(
        w.set(&a, "Bad", None, &RegValue::String("a\0b".into())),
        SysErrorKind::Unsupported,
        "set a value without a canonical encoding",
    )?;
    ensure(
        get(w, &a, "Bad")?.is_none(),
        "a refused value is not stored",
    )?;
    let default = RegValue::String("default".into());
    ok(w.set(&a, "", None, &default), "set the default value")?;
    ensure(
        get(w, &a, "")? == Some(default.clone()),
        "the default value",
    )?;
    err_kind(
        w.set(&root.join("Missing"), "v", None, &RegValue::Dword(1)),
        SysErrorKind::NotFound,
        "set on a missing key",
    )?;

    // RW3: delete_value with the expected value.
    err_kind(
        w.delete_value(&a, "Flag", &RegValue::Dword(1)),
        SysErrorKind::Mismatch,
        "delete_value expecting another value",
    )?;
    ensure(
        get(w, &a, "Flag")? == Some(text.clone()),
        "a refused delete keeps",
    )?;
    err_kind(
        w.delete_value(&a, "Nope", &RegValue::Dword(1)),
        SysErrorKind::NotFound,
        "delete_value of a missing value",
    )?;
    ok(w.delete_value(&a, "flag", &text), "delete_value")?;
    ensure(get(w, &a, "Flag")?.is_none(), "the value is gone")?;

    // RW4 and RW10: delete_empty_key only on an empty key; key_state without following.
    let child = a.join("Child");
    ok(w.create_key(&child), "create Child")?;
    ensure(
        ok(w.key_state(&a), "key_state Alpha")?
            == KeyState::Present {
                values: 2,
                subkeys: 1,
            },
        "key_state counts values and subkeys",
    )?;
    ensure(
        ok(
            w.key_state(&root.join(r"Missing\Deeper")),
            "key_state missing",
        )? == KeyState::Missing,
        "a missing key (or parent) is Missing",
    )?;
    err_kind(
        w.read(&root.join("Missing"), "v"),
        SysErrorKind::NotFound,
        "read on a missing key",
    )?;
    ensure(
        ok(w.read(&a, "Nope"), "read missing")?.is_none(),
        "read missing value",
    )?;
    err_kind(
        w.delete_empty_key(&a),
        SysErrorKind::NotEmpty,
        "delete_empty_key with values and a subkey",
    )?;
    ok(w.delete_empty_key(&child), "delete Child")?;
    err_kind(
        w.delete_empty_key(&a),
        SysErrorKind::NotEmpty,
        "delete_empty_key with values",
    )?;
    err_kind(
        w.delete_empty_key(&child),
        SysErrorKind::NotFound,
        "delete_empty_key of a missing key",
    )?;
    err_kind(
        w.delete_empty_key(&RegKey::new(root.hive, root.view, "")),
        SysErrorKind::InvalidPath,
        "delete_empty_key of the hive root",
    )?;
    ok(w.delete_value(&a, "Raw", &raw), "delete Raw")?;
    ok(w.delete_value(&a, "", &default), "delete the default value")?;
    ok(w.delete_empty_key(&a), "delete Alpha")?;
    ensure(
        ok(w.key_state(&a), "key_state after delete")? == KeyState::Missing,
        "the key is gone",
    )?;

    link_keys(w, fx, root, &mut skips)?;

    // RW6: HKLM and the 32-bit view are refused by every method.
    for k in [
        RegKey::new(Hive::LocalMachine, RegView::Native, r"SOFTWARE\Rerun"),
        RegKey::new(root.hive, RegView::Wow32, &root.path),
    ] {
        let v = RegValue::Dword(1);
        for (what, r) in [
            ("key_state", w.key_state(&k).map(drop)),
            ("read", w.read(&k, "v").map(drop)),
            ("create_key", w.create_key(&k.join("X")).map(drop)),
            ("set", w.set(&k, "v", None, &v)),
            ("delete_value", w.delete_value(&k, "v", &v)),
            ("delete_empty_key", w.delete_empty_key(&k.join("X"))),
        ] {
            err_kind(r, SysErrorKind::Unsupported, &format!("{what} on {k}"))?;
        }
    }
    err_kind(
        w.flush(Hive::LocalMachine),
        SysErrorKind::Unsupported,
        "flush HKLM",
    )?;

    // RW7: flush the user's hive.
    ok(w.flush(root.hive), "flush")?;

    // RW8: the input rules come first.
    let v = RegValue::Dword(1);
    err_kind(
        w.create_key(&root.join("Bad\0Name")),
        SysErrorKind::InvalidPath,
        "create_key with NUL",
    )?;
    err_kind(
        w.set(root, "Bad\0Name", None, &v),
        SysErrorKind::InvalidPath,
        "set with NUL in the value name",
    )?;
    err_kind(
        w.key_state(&RegKey {
            path: format!(r"{}\\x", root.path),
            ..root.clone()
        }),
        SysErrorKind::InvalidPath,
        "an empty segment",
    )?;

    renamed_between_walk_and_act(w, fx, root, &mut skips)?;

    // S4: a volatile key (or one below it) is never written.
    let vol = root.join("Volatile");
    if ok(fx.volatile_key(&vol), "fixture: volatile key")? {
        err_kind(
            w.set(&vol, "v", None, &v),
            SysErrorKind::Unsupported,
            "set in a volatile key",
        )?;
        err_kind(
            w.create_key(&vol.join("Sub")),
            SysErrorKind::Unsupported,
            "create_key below a volatile key",
        )?;
        ensure(
            get(w, &vol, "v")?.is_none() && ok(w.subkeys(&vol), "subkeys")?.is_empty(),
            "nothing was written to the volatile key",
        )?;
    } else {
        skip(&mut skips, "volatile_key");
    }
    Ok(skips)
}

/// RW5: a link key as an intermediate or the last segment is `ReparsePoint` for every method;
/// the link and its target stay as they are, and `link` still reports it.
fn link_keys(
    w: &dyn RegistryWrite,
    fx: &dyn RegFixture,
    root: &RegKey,
    skips: &mut Skipped,
) -> Result<(), String> {
    let target = root.join("Target");
    let lk = root.join("Lnk");
    ok(fx.key(&target.join("Sub")), "fixture: link target")?;
    ok(
        fx.raw(&target, "t", reg_type::REG_DWORD, &[5, 0, 0, 0]),
        "fixture: target value",
    )?;
    if !ok(fx.link(&lk, &target), "fixture: link")? {
        skip(skips, "key_link");
        return Ok(());
    }
    let t = RegValue::Dword(5);
    let v = RegValue::Dword(1);
    let below = lk.join("Sub");
    for (what, r) in [
        ("create_key below", w.create_key(&lk.join("New")).map(drop)),
        ("create_key at", w.create_key(&lk).map(drop)),
        (
            "create_key two below",
            w.create_key(&below.join("New")).map(drop),
        ),
        ("set at", w.set(&lk, "t", Some(&t), &v)),
        ("set below", w.set(&below, "v", None, &v)),
        ("delete_value at", w.delete_value(&lk, "t", &t)),
        ("delete_empty_key at", w.delete_empty_key(&lk)),
        ("delete_empty_key below", w.delete_empty_key(&below)),
        ("key_state at", w.key_state(&lk).map(drop)),
        ("key_state below", w.key_state(&below).map(drop)),
        ("read at", w.read(&lk, "t").map(drop)),
    ] {
        err_kind(r, SysErrorKind::ReparsePoint, &format!("{what} a link key"))?;
    }
    ensure(
        ok(w.values(&target), "values of the target")? == [("t".to_owned(), t)]
            && ok(w.subkeys(&target), "subkeys of the target")? == ["Sub"]
            && ok(w.subkeys(&target.join("Sub")), "subkeys of Sub")?.is_empty()
            && !ok(w.key_exists(&target.join("New")), "nothing created")?,
        "the link target is unchanged",
    )?;
    ensure(
        ok(w.link(&lk), "link")?.is_some(),
        "the link key is still a link",
    )?;
    Ok(())
}

/// RW9: another program renames the key between the walk and the act: `Busy`, nothing is
/// written, at the old name or the new one.
fn renamed_between_walk_and_act(
    w: &dyn RegistryWrite,
    fx: &dyn RegFixture,
    root: &RegKey,
    skips: &mut Skipped,
) -> Result<(), String> {
    let k = root.join("Renamed");
    let moved = root.join("RenamedAway");
    let v = RegValue::Dword(1);
    let cases: [(&str, &dyn Fn() -> crate::sys::SysResult<()>); 3] = [
        ("set", &|| w.set(&k, "v", None, &v)),
        ("create_key", &|| w.create_key(&k.join("Kid")).map(drop)),
        ("delete_empty_key", &|| w.delete_empty_key(&k)),
    ];
    for (what, act) in cases {
        ok(fx.key(&k), "fixture: key to rename")?;
        let Some(rename) = ok(fx.rename_later(&k, "RenamedAway"), "fixture: rename")? else {
            skip(skips, "rename_key");
            ok(fx.delete_key(&k), "fixture: cleanup")?;
            return Ok(());
        };
        let fired = Rc::new(Cell::new(false));
        let flag = fired.clone();
        hook::after_walk_once(move |_| {
            flag.set(rename().is_ok());
        });
        let r = act();
        hook::clear();
        ensure(
            fired.get(),
            &format!("{what}: the rename ran between walk and act"),
        )?;
        err_kind(r, SysErrorKind::Busy, &format!("{what} on a renamed key"))?;
        ensure(
            !ok(w.key_exists(&k), "old name")?
                && get(w, &moved, "v")?.is_none()
                && ok(w.subkeys(&moved), "subkeys of the moved key")?.is_empty(),
            &format!("{what}: nothing written to the renamed key"),
        )?;
        ok(fx.delete_key(&moved), "fixture: cleanup")?;
    }
    Ok(())
}
