//! Snapshot contract (P2-5): `sys::snapshot` against the fake and against `sys::win` (a
//! `TestRoot` opened as a `GameDir`, a private app hive). Every change another program could
//! make is done by the fixtures; for each kind of change the snapshot must differ in exactly
//! one line, at the changed entry, and be identical again once the change is undone. That
//! pins "what exact means" (ADR 0017, ADR 0018) on both, and a `Dir` or `Registry` that loses
//! an attribute, the link count or the case of a name is caught (`sys::fake` tests).

use std::path::Path;

use super::{FsContractResult, FsFixture, RegFixture, Skipped, ensure, ok, rel, skip};
use crate::sys::SysErrorKind;
use crate::sys::fs::Attrs;
use crate::sys::registry::{RegKey, Registry, reg_type};
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};

/// Takes snapshots of one root and one key.
struct Taker<'a> {
    root: SnapRoot<'a>,
    reg: &'a dyn Registry,
    key: RegKey,
}

impl Taker<'_> {
    fn scope(&self) -> Scope<'_> {
        Scope {
            dirs: vec![self.root.clone()],
            keys: vec![self.key.clone()],
        }
    }

    fn take(&self, what: &str) -> Result<Snapshot, String> {
        ok(snapshot(self.reg, &self.scope()), what)
    }

    /// The snapshot now differs from `before` in exactly one line, which starts with `sign`
    /// and names `needle`.
    fn one_diff(
        &self,
        before: &Snapshot,
        sign: char,
        needle: &str,
        what: &str,
    ) -> Result<(), String> {
        let after = self.take(what)?;
        let diff = before.diff(&after);
        // Case-insensitive: a line holds the folded location next to the names, and a case
        // change shows in exactly one line anyway.
        let found = diff
            .first()
            .is_some_and(|l| l.to_lowercase().contains(&needle.to_lowercase()));
        ensure(
            diff.len() == 1 && diff[0].starts_with(sign) && found,
            &format!("{what}: one difference {sign} at {needle:?}, got {diff:#?}"),
        )
    }

    /// The snapshot now equals `before`.
    fn same(&self, before: &Snapshot, what: &str) -> Result<(), String> {
        let after = self.take(what)?;
        ensure(
            *before == after,
            &format!("{what}: identical, got {:#?}", before.diff(&after)),
        )
    }
}

fn attrs(readonly: bool, hidden: bool, system: bool) -> Attrs {
    Attrs {
        readonly,
        hidden,
        system,
    }
}

fn sz(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Snapshot contract. `root` is the root handle of the existing, empty directory `work`;
/// `key` an existing key without values and subkeys, read through `reg` and changed through
/// `rfx`. Leaves its entries behind (the runner cleans up). Skipped cases: `"utf16_name"`,
/// `"case_sensitive_dir"`, `"delete_pending"`, `"wof_compress"`, `"restricted"`.
pub fn snapshot_contract(
    root: SnapRoot<'_>,
    fx: &dyn FsFixture,
    work: &Path,
    reg: &dyn Registry,
    rfx: &dyn RegFixture,
    key: &RegKey,
) -> FsContractResult {
    let mut skips = Skipped::new();
    let t = Taker {
        root,
        reg,
        key: key.clone(),
    };
    let empty = t.take("empty scope")?;
    ensure(
        empty.len() == 1,
        &format!("an empty root and key: only the key, got {empty:?}"),
    )?;

    // The tree and the key every case starts from.
    let data = work.join("Data");
    let a = data.join("a.bin");
    let outside = work
        .parent()
        .ok_or("contract setup: work has no parent")?
        .join(format!(
            "{}-outside",
            work.file_name().and_then(|n| n.to_str()).unwrap_or("w")
        ));
    let (t1, t2) = (outside.join("t1"), outside.join("t2"));
    ok(fx.file(&a, b"alpha"), "fixture a.bin")?;
    ok(fx.dir(&data.join("Sub")), "fixture Sub")?;
    ok(fx.dir(&t1), "fixture t1")?;
    ok(fx.dir(&t2), "fixture t2")?;
    let link = work.join("link");
    ok(fx.junction(&link, &t1), "fixture junction")?;
    ok(
        rfx.raw(key, "Lang", reg_type::REG_SZ, &sz("de")),
        "fixture Lang",
    )?;
    ok(rfx.key(&key.join("Child")), "fixture Child")?;
    let before = t.take("baseline")?;
    t.same(&before, "a second snapshot of the same state")?;

    // Files: content of the same length, length, case of the name.
    ok(fx.file(&a, b"ALPHA"), "fixture: content")?;
    t.one_diff(&before, '~', "a.bin", "content of the same length")?;
    ok(fx.file(&a, b"alphabet"), "fixture: length")?;
    t.one_diff(&before, '~', "a.bin", "length")?;
    ok(fx.file(&a, b"alpha"), "fixture: content back")?;
    t.same(&before, "content back")?;
    ok(fx.rename(&a, &data.join("A.bin")), "fixture: case")?;
    t.one_diff(&before, '~', "A.bin", "case of a file name")?;
    ok(fx.rename(&data.join("A.bin"), &a), "fixture: case back")?;
    t.same(&before, "case back")?;

    // R/H/S on a file, a directory and a reparse point.
    for (path, needle) in [(&a, "a.bin"), (&data.join("Sub"), "Sub"), (&link, "link")] {
        for set in [
            attrs(true, false, false),
            attrs(false, true, false),
            attrs(false, false, true),
        ] {
            let what = format!("{set:?} on {needle}");
            ok(fx.set_attrs(path, set), &format!("fixture: {what}"))?;
            t.one_diff(&before, '~', needle, &what)?;
            ok(
                fx.set_attrs(path, Attrs::default()),
                "fixture: attributes back",
            )?;
            t.same(&before, &format!("{what} back"))?;
        }
    }

    // Hard link count, junction target.
    let other = outside.join("a-link.bin");
    ok(fx.hardlink(&a, &other), "fixture: hard link")?;
    t.one_diff(&before, '~', "2 links", "a second hard link")?;
    ok(fx.remove(&other), "fixture: hard link gone")?;
    t.same(&before, "hard link gone")?;
    ok(fx.remove(&link), "fixture: junction gone")?;
    ok(fx.junction(&link, &t2), "fixture: junction elsewhere")?;
    t.one_diff(&before, '~', "t2", "junction target")?;
    ok(fx.remove(&link), "fixture: junction gone again")?;
    ok(fx.junction(&link, &t1), "fixture: junction back")?;
    t.same(&before, "junction back")?;

    // A file that someone holds without sharing read cannot be hashed: `Busy`, no snapshot.
    {
        let _held = ok(
            fx.hold_open(&a, super::Access::READ, super::Share::NONE),
            "fixture: hold a.bin",
        )?;
        match snapshot(t.reg, &t.scope()) {
            Err(e) if e.kind == SysErrorKind::Busy => {}
            other => {
                return Err(format!(
                    "contract violated: a file held without read sharing: expected Busy, got \
                     {other:?}"
                ));
            }
        }
    }
    t.same(&before, "the hold is gone")?;

    // A delete-pending file is skipped (user decision E2): identical to before it existed.
    match ok(
        fx.delete_pending(&data.join("pending.bin")),
        "fixture: delete-pending",
    )? {
        Some(held) => {
            t.same(&before, "a delete-pending file is skipped")?;
            drop(held);
            t.same(&before, "the delete-pending file is gone")?;
        }
        None => skip(&mut skips, "delete_pending"),
    }

    // `below`: the entry itself and the tree below it; missing is `Missing`.
    let sub = t.root.clone().below(rel(r"Data\Sub")?);
    let sub_snap = ok(
        snapshot(
            reg,
            &Scope {
                dirs: vec![sub],
                keys: vec![],
            },
        ),
        "below Data\\Sub",
    )?;
    let lines = sub_snap.diff(&Snapshot::default());
    ensure(
        sub_snap.len() == 1 && lines.iter().any(|l| l.contains("dir \"Sub\"")),
        &format!("below captures the directory itself: {lines:#?}"),
    )?;
    let gone = ok(
        snapshot(
            reg,
            &Scope {
                dirs: vec![t.root.clone().below(rel(r"Data\nope")?)],
                keys: vec![],
            },
        ),
        "below a missing entry",
    )?;
    ensure(
        gone.diff(&Snapshot::default())
            .iter()
            .any(|l| l.contains("<missing>")),
        "below a missing entry is Missing",
    )?;

    // Registry: exact bytes, type with the same bytes, case of a value and a key name, an
    // empty key against a missing one.
    ok(
        rfx.raw(key, "Lang", reg_type::REG_SZ, &sz("fr")),
        "fixture: bytes",
    )?;
    t.one_diff(&before, '~', "Lang", "value bytes")?;
    ok(
        rfx.raw(key, "Lang", reg_type::REG_EXPAND_SZ, &sz("de")),
        "fixture: type",
    )?;
    t.one_diff(
        &before,
        '~',
        "REG_EXPAND_SZ",
        "value type with the same bytes",
    )?;
    ok(
        rfx.raw(key, "Lang", reg_type::REG_SZ, &sz("de")),
        "fixture: value back",
    )?;
    t.same(&before, "value back")?;
    ok(rfx.delete_value(key, "Lang"), "fixture: value gone")?;
    ok(
        rfx.raw(key, "LANG", reg_type::REG_SZ, &sz("de")),
        "fixture: value name case",
    )?;
    t.one_diff(&before, '~', "LANG", "case of a value name")?;
    ok(rfx.delete_value(key, "LANG"), "fixture: value gone again")?;
    ok(
        rfx.raw(key, "Lang", reg_type::REG_SZ, &sz("de")),
        "fixture: value name back",
    )?;
    t.same(&before, "value name back")?;
    ok(rfx.delete_key(&key.join("Child")), "fixture: key gone")?;
    t.one_diff(&before, '-', "Child", "an empty key against a missing one")?;
    ok(rfx.key(&key.join("CHILD")), "fixture: key name case")?;
    t.one_diff(&before, '~', "CHILD", "case of a key name")?;
    ok(
        rfx.delete_key(&key.join("CHILD")),
        "fixture: key gone again",
    )?;
    ok(rfx.key(&key.join("Child")), "fixture: key back")?;
    t.same(&before, "key back")?;

    // Names that list alike (unpaired surrogates): anomalies kept as a multiset, a change of
    // one of them is one difference. Last for both sides: the fixtures cannot remove them.
    let (high, low) = ([0x61, 0xD800, 0x62], [0x61, 0xDC00, 0x62]);
    let made = ok(fx.utf16_file(&data, &high, b"1"), "fixture: raw file")?
        && ok(fx.utf16_file(&data, &low, b"22"), "fixture: raw file 2")?
        && ok(rfx.utf16_key(key, &high), "fixture: raw key")?
        && ok(rfx.utf16_key(key, &low), "fixture: raw key 2")?
        && ok(
            rfx.utf16_value(key, &high, reg_type::REG_DWORD, &[1, 0, 0, 0]),
            "fixture: raw value",
        )?
        && ok(
            rfx.utf16_value(key, &low, reg_type::REG_DWORD, &[2, 0, 0, 0]),
            "fixture: raw value 2",
        )?;
    if made {
        let lossy = t.take("raw names")?;
        let lines = before.diff(&lossy);
        ensure(
            lines.len() == 6
                && lines.iter().all(|l| l.starts_with('+'))
                && lines
                    .iter()
                    .filter(|l| l.contains("anomaly \"a\u{FFFD}b\""))
                    .count()
                    == 2
                && lines
                    .iter()
                    .filter(|l| l.contains("anomaly key \"a\u{FFFD}b\" (lossy name)"))
                    .count()
                    == 2
                && lines
                    .iter()
                    .filter(|l| l.contains("anomaly value \"a\u{FFFD}b\" (lossy name)"))
                    .count()
                    == 2,
            &format!("names with unpaired surrogates are six anomalies: {lines:#?}"),
        )?;
        t.same(&lossy, "a second snapshot with raw names")?;
        ok(
            fx.utf16_file(&data, &low, b"333"),
            "fixture: raw file changed",
        )?;
        t.one_diff(&lossy, '~', "3 bytes", "one of two raw file names changed")?;
        ok(fx.utf16_file(&data, &low, b"22"), "fixture: raw file back")?;
        ok(
            rfx.utf16_value(key, &low, reg_type::REG_DWORD, &[3, 0, 0, 0]),
            "fixture: raw value changed",
        )?;
        t.one_diff(
            &lossy,
            '~',
            "0x00000003",
            "one of two raw value names changed",
        )?;
        ok(
            rfx.utf16_value(key, &low, reg_type::REG_DWORD, &[2, 0, 0, 0]),
            "fixture: raw value back",
        )?;
        t.same(&lossy, "raw names back")?;
    } else {
        skip(&mut skips, "utf16_name");
    }

    // A case-sensitive directory: every entry an anomaly, "a" and "A" both kept.
    let cs = work.join("cs");
    if ok(fx.case_sensitive_dir(&cs), "fixture: case-sensitive dir")? {
        ok(fx.file(&cs.join("a"), b"1"), "fixture: cs a")?;
        ok(fx.file(&cs.join("A"), b"2"), "fixture: cs A")?;
        let snap = t.take("case-sensitive")?;
        let lines = snap.diff(&Snapshot::default());
        ensure(
            lines
                .iter()
                .filter(|l| l.contains("anomaly \"a\" File"))
                .count()
                == 1
                && lines
                    .iter()
                    .filter(|l| l.contains("anomaly \"A\" File"))
                    .count()
                    == 1,
            &format!("both entries of a case-sensitive directory are anomalies: {lines:#?}"),
        )?;
        t.same(&snap, "a second snapshot of the case-sensitive directory")?;
    } else {
        skip(&mut skips, "case_sensitive_dir");
    }

    // A WOF-compressed file: the snapshot does not change (the tag is hidden or not compared).
    let wof = data.join("wof.bin");
    let blob: Vec<u8> = (0..64 * 1024_u32)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    ok(fx.file(&wof, &blob), "fixture: wof.bin")?;
    let plain = t.take("before compression")?;
    if ok(fx.wof_compress(&wof), "fixture: compress")? {
        t.same(&plain, "a WOF-compressed file")?;
    } else {
        skip(&mut skips, "wof_compress");
    }

    // Restricted, last: the fixture cannot lift it. Recorded from the listing, never opened.
    let now = t.take("before restricting")?;
    if ok(fx.restricted(&a), "fixture: restricted")? {
        t.one_diff(&now, '~', "restricted \"a.bin\"", "a restricted file")?;
        let again = t.take("restricted again")?;
        t.same(&again, "a second snapshot with a restricted file")?;
    } else {
        skip(&mut skips, "restricted");
    }
    Ok(skips)
}
