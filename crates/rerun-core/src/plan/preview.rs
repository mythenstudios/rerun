//! The preview of a plan (core rule 5, ADR 0020 "Preview"): every op with its root, path,
//! content source, SHA-256, length and attributes, the old state of a replace, the hint for a
//! configuration file, and once per plan what a revert does not restore (ADR 0017, D3). Every
//! untrusted field is an [`escape::Shown`] (`escape::path` for paths and for the source,
//! which joins package ID, version and file), built from the decoded plan, i.e. from the stored bytes.
//!
//! Registry ops (P2-10b) show the key and the value name (`escape::path`, `(default)` for the
//! default value), the old value (decoded from the plan's inline bytes up to `OLD_INLINE`,
//! strings through `escape::text`; otherwise type, length and SHA-256; `missing`) with a type
//! change marked (audit nit N6: the one place where old registry data reaches output, ADR 0016),
//! and the new value; a plan with registry ops adds [`REGISTRY_NOTE`] once.
//!
//! An `add tokens` op (P2-11) shows the value name (the executable's path), the old value, the
//! tokens it adds and the new value; a plan with such an op adds [`LAYERS_NOTE`] once.
//!
//! An `edit ini` op (P2-12) shows the file with its old and new hash, length and R/H/S (kept),
//! and per key `[section] key`, the old value (`missing`, `new section`) and the new one, every
//! name and value through `escape::text`; a plan with such an op adds [`INI_NOTE`] once.

use std::fmt;

use super::{
    ContentRef, FileState, Op, Plan, PlanOrigin, Target, ValueState, allowed, created_key,
};
use crate::escape::{self, Shown};
use crate::policy::ini::Old;
use crate::sys::fs::Attrs;
use crate::sys::registry::{RegValue, reg_type};
use crate::wire::hex32;

/// What a revert does not restore (ADR 0017, "What exact means", user decision D3).
pub const NOT_RESTORED: &str = "a revert restores existence, content, length, read-only, \
hidden and system; not timestamps, file IDs, permissions, alternate data streams, short names \
or the archive attribute";

/// What a plan with registry ops says once (ADR 0020 amendment P2-10b, review S4): the normal
/// case of a game that writes its own key, and what a revert does not restore there.
pub const REGISTRY_NOTE: &str = "registry: if the game fills a created key or changes a value \
later (also by writing it with another type), a revert leaves it as it is and the transaction \
is closed with forget; a revert restores keys and values exactly, not the last-write times of \
registry keys";

/// What a plan with compatibility-layer ops says once (P2-11, ADR 0020 amendment P2-11; review
/// N3): what a revert of a shared value does.
pub const LAYERS_NOTE: &str = "compatibility layers: a revert removes only the tokens Rerun \
added; what you or Windows change in the value afterwards stays, and a value nobody changed is \
restored exactly. A token already in the value is not added again, also one an earlier Rerun \
transaction added: reverting that transaction removes it. A token you add yourself after the \
apply that Rerun added too is removed by the revert. The keys AppCompatFlags and Layers are \
shared with Windows: a revert deletes one Rerun created only when it is empty, so reverting \
transactions in another order than newest first can leave them empty for good";

/// What a plan with INI ops says once (P2-12, ADR 0020 amendment P2-12; user decisions E1 b, E2
/// a, E5 a).
pub const INI_NOTE: &str = "INI files: a file nobody changed is restored exactly by the revert. \
If the game rewrote it, the revert sets back only the keys that still hold Rerun's value; keys \
the game or you changed, and everything else in the file, stay. A key the game sets to the \
same value as Rerun is set back too. A file that is gone at the time of the revert stays gone. \
The main executable must be the program that writes the file when it exits (with a launcher, \
the game itself)";

/// The old state of a key for display (senior-dev nit): the untrusted value as `Shown`, or a word
/// of Rerun's, never mixed in one string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IniOldShown {
    /// The value (through `escape::text`).
    Value(Shown<'static>),
    /// The key was missing.
    Missing,
    /// The section was missing.
    NewSection,
}

impl fmt::Display for IniOldShown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(v) => write!(f, "{v}"),
            Self::Missing => f.write_str("missing"),
            Self::NewSection => f.write_str("missing (new section)"),
        }
    }
}

/// One key of an `edit ini` op for display: every part through `escape::text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IniShown {
    /// The section.
    pub section: Shown<'static>,
    /// The key.
    pub key: Shown<'static>,
    /// The old value.
    pub old: IniOldShown,
    /// The new value.
    pub new: Shown<'static>,
}

/// One root of a [`Preview`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRoot {
    /// Index in the plan.
    pub index: usize,
    /// Canonical path.
    pub path: Shown<'static>,
    /// The Steam app and library, if the root is a Steam install folder.
    pub steam: Option<(u32, Shown<'static>)>,
    /// The main executable asked by `users()`.
    pub main_exe: Option<Shown<'static>>,
}

/// One op of a [`Preview`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewOp {
    /// Index in the plan.
    pub index: usize,
    /// What it does: `create folder`, `create file`, `replace file`, `create key`, `set value`,
    /// `add tokens`.
    pub action: &'static str,
    /// Root index (`None` for a registry op).
    pub root: Option<usize>,
    /// Path below the root, or the registry key (`HKCU\…`).
    pub path: Shown<'static>,
    /// The value name of a `set value` (`(default)` for the default value).
    pub name: Option<Shown<'static>>,
    /// The old value of a `set value` or `add tokens` (kind `missing` if there was none).
    pub old_value: Option<RegShown>,
    /// The new value of a `set value` or `add tokens`.
    pub new_value: Option<RegShown>,
    /// The tokens an `add tokens` adds, in order (their form is `[A-Z0-9_]`).
    pub tokens: Option<String>,
    /// A `set value` changes the value's type.
    pub type_change: bool,
    /// Source: `<package id> <version>: <file>`.
    pub source: Option<Shown<'static>>,
    /// SHA-256 (hex) and length of the new content.
    pub content: Option<(String, u64)>,
    /// R/H/S of the new file (`-` for none).
    pub attrs: Option<String>,
    /// The old state of a replaced file: SHA-256 (hex), length, R/H/S.
    pub old: Option<(String, u64, String)>,
    /// A configuration file: a revert after the user edited it leaves it.
    pub config: bool,
    /// The keys of an `edit ini` op.
    pub ini: Vec<IniShown>,
}

/// A registry value for display (review S3: the `Shown` guarantee kept): `kind` is built by
/// Rerun only (the type, a number, or type, length and SHA-256; `missing`), `text` is the
/// untrusted string data through `escape::text`, shown last on its line with nothing after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegShown {
    /// `REG_SZ`, `REG_DWORD 1 (0x00000001)`, `REG_BINARY, 3 bytes, sha256 …`, `missing`.
    pub kind: String,
    /// The string data of a `REG_SZ`/`REG_EXPAND_SZ`.
    pub text: Option<Shown<'static>>,
}

impl fmt::Display for RegShown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.text {
            Some(t) => write!(f, "{}: {t}", self.kind),
            None => f.write_str(&self.kind),
        }
    }
}

/// The preview of a whole plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    /// The roots.
    pub roots: Vec<PreviewRoot>,
    /// The ops, in order.
    pub ops: Vec<PreviewOp>,
    /// [`NOT_RESTORED`], once per plan.
    pub not_restored: &'static str,
    /// [`REGISTRY_NOTE`], once per plan with registry ops.
    pub registry: Option<&'static str>,
    /// [`LAYERS_NOTE`], once per plan with `add tokens` ops.
    pub layers: Option<&'static str>,
    /// [`INI_NOTE`], once per plan with `edit ini` ops.
    pub ini: Option<&'static str>,
}

/// `RHS` letters of the set attributes, `-` for none.
fn rhs(a: &Attrs) -> String {
    let s: String = [(a.readonly, 'R'), (a.hidden, 'H'), (a.system, 'S')]
        .into_iter()
        .filter_map(|(on, c)| on.then_some(c))
        .collect();
    if s.is_empty() { "-".to_owned() } else { s }
}

fn old(o: &FileState) -> (String, u64, String) {
    (hex32::to_string(&o.sha256), o.len, rhs(&o.attrs))
}

/// A registry type for display.
fn type_name(kind: u32) -> String {
    match kind {
        reg_type::REG_SZ => "REG_SZ".to_owned(),
        reg_type::REG_EXPAND_SZ => "REG_EXPAND_SZ".to_owned(),
        reg_type::REG_BINARY => "REG_BINARY".to_owned(),
        reg_type::REG_DWORD => "REG_DWORD".to_owned(),
        reg_type::REG_MULTI_SZ => "REG_MULTI_SZ".to_owned(),
        reg_type::REG_QWORD => "REG_QWORD".to_owned(),
        k => format!("type {k}"),
    }
}

/// A value by type, length and SHA-256.
fn opaque(s: &ValueState) -> String {
    format!(
        "{}, {} bytes, sha256 {}",
        type_name(s.kind),
        s.len,
        hex32::to_string(&s.sha256)
    )
}

/// A registry value for display: numbers and strings decoded (strings through
/// `escape::text`), anything else by type, length and SHA-256 (ADR 0016).
fn value_text(v: &RegValue, s: &ValueState) -> RegShown {
    let plain = |kind: String| RegShown { kind, text: None };
    let text = |kind: &str, t: &str| RegShown {
        kind: kind.to_owned(),
        text: Some(escape::text(t).into_owned()),
    };
    match v {
        RegValue::Dword(n) => plain(format!("REG_DWORD {n} ({n:#010x})")),
        RegValue::Qword(n) => plain(format!("REG_QWORD {n} ({n:#018x})")),
        RegValue::String(t) => text("REG_SZ", t),
        RegValue::ExpandString(t) => text("REG_EXPAND_SZ", t),
        _ => plain(opaque(s)),
    }
}

/// The old value of a `set value` for display.
fn old_value(o: Option<&ValueState>) -> RegShown {
    match o {
        None => RegShown {
            kind: "missing".to_owned(),
            text: None,
        },
        Some(s) => match &s.data {
            Some(d) => value_text(&RegValue::decode(s.kind, d), s),
            None => RegShown {
                kind: opaque(s),
                text: None,
            },
        },
    }
}

/// The key (`HKCU\…`) and value name of a registry op, for display; a slot the policy
/// refuses (never in a decoded plan) is shown as such.
fn reg_target(p: &Plan, k: usize, t: Target<'_>) -> (Shown<'static>, Option<Shown<'static>>) {
    let refused = || escape::path("(a slot the policy refuses)").into_owned();
    let key_text = |key: &crate::sys::registry::RegKey| {
        escape::path(&format!(r"{}\{}", key.hive, key.path)).into_owned()
    };
    match t {
        Target::Key { slot, segs } => match created_key(p, slot, segs, k) {
            Ok((_, key)) => (key_text(&key), None),
            Err(_) => (refused(), None),
        },
        Target::Value { slot } => match allowed(p, slot, k) {
            Ok(av) => {
                let name = if av.name().is_empty() {
                    escape::path("(default)").into_owned()
                } else {
                    escape::path(av.name()).into_owned()
                };
                (key_text(av.key().key()), Some(name))
            }
            Err(_) => (refused(), None),
        },
        Target::File { path, .. } => (escape::path(path.as_str()).into_owned(), None),
    }
}

/// The preview of `p`.
pub fn preview(p: &Plan) -> Preview {
    let roots = p
        .roots
        .iter()
        .enumerate()
        .map(|(index, r)| PreviewRoot {
            index,
            path: escape::path(&r.path.to_string()).into_owned(),
            steam: match &r.origin {
                PlanOrigin::Steam { store, app_id, .. } => {
                    Some((*app_id, escape::path(&store.to_string()).into_owned()))
                }
                PlanOrigin::Manual => None,
            },
            main_exe: r
                .main_exe
                .as_ref()
                .map(|m| escape::path(m.as_str()).into_owned()),
        })
        .collect();
    let ops = p
        .ops
        .iter()
        .enumerate()
        .map(|(index, op)| {
            let (action, attrs, old_state) = match op {
                Op::CreateDir { .. } => ("create folder", None, None),
                Op::CreateFile { attrs, .. } => ("create file", Some(rhs(attrs)), None),
                Op::ReplaceFile { attrs, old: o, .. } => {
                    ("replace file", Some(rhs(attrs)), Some(old(o)))
                }
                Op::CreateKey { .. } => ("create key", None, None),
                Op::SetValue { .. } => ("set value", None, None),
                Op::TokenList { .. } => ("add tokens", None, None),
                Op::IniValue { old: o, .. } => ("edit ini", Some(rhs(&o.attrs)), Some(old(o))),
            };
            let (old_value, new_value, type_change) = match op {
                Op::SetValue { old: o, new, .. } => {
                    let v = new.value();
                    let shown = ValueState::of(&v).map_or_else(
                        || RegShown {
                            kind: "a value without an encoding".to_owned(),
                            text: None,
                        },
                        |s| value_text(&v, &s),
                    );
                    let changed = o
                        .as_ref()
                        .is_some_and(|o| v.encode().is_some_and(|(k, _)| k != o.kind));
                    (Some(old_value(o.as_ref())), Some(shown), changed)
                }
                Op::TokenList { old: o, new, .. } => {
                    let v = RegValue::String(new.clone());
                    let shown = ValueState::of(&v).map_or_else(
                        || RegShown {
                            kind: "a value without an encoding".to_owned(),
                            text: None,
                        },
                        |s| value_text(&v, &s),
                    );
                    (Some(old_value(o.as_ref())), Some(shown), false)
                }
                _ => (None, None, false),
            };
            let tokens = match op {
                Op::TokenList { add, .. } => Some(
                    add.iter()
                        .map(crate::policy::registry::TokenName::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
                _ => None,
            };
            let (source, content, config) = match op.content() {
                Some(ContentRef::Package {
                    id,
                    version,
                    file,
                    sha256,
                    len,
                    config,
                }) => (
                    Some(escape::path(&format!("{id} {version}: {file}")).into_owned()),
                    Some((hex32::to_string(sha256), *len)),
                    *config,
                ),
                None => match op {
                    Op::IniValue { new, .. } => {
                        (None, Some((hex32::to_string(&new.sha256), new.len)), false)
                    }
                    _ => (None, None, false),
                },
            };
            let ini = match op {
                Op::IniValue { edits, .. } => edits
                    .iter()
                    .map(|e| IniShown {
                        section: escape::text(e.section.as_str()).into_owned(),
                        key: escape::text(e.key.as_str()).into_owned(),
                        old: match &e.old {
                            Old::Value(v) => {
                                IniOldShown::Value(escape::text(v.as_str()).into_owned())
                            }
                            Old::NoKey => IniOldShown::Missing,
                            Old::NoSection => IniOldShown::NewSection,
                        },
                        new: escape::text(e.new.as_str()).into_owned(),
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let (root, path, name) = match op.target() {
                Target::File { root, path, .. } => (
                    Some(usize::from(root.0)),
                    escape::path(path.as_str()).into_owned(),
                    None,
                ),
                t @ (Target::Key { .. } | Target::Value { .. }) => {
                    let (path, name) = reg_target(p, index, t);
                    (None, path, name)
                }
            };
            PreviewOp {
                index,
                action,
                root,
                path,
                name,
                old_value,
                new_value,
                tokens,
                type_change,
                source,
                content,
                attrs,
                old: old_state,
                config,
                ini,
            }
        })
        .collect();
    let registry = p
        .ops
        .iter()
        .any(|o| o.target().is_registry())
        .then_some(REGISTRY_NOTE);
    let layers = p
        .ops
        .iter()
        .any(|o| matches!(o, Op::TokenList { .. }))
        .then_some(LAYERS_NOTE);
    let ini = p
        .ops
        .iter()
        .any(|o| matches!(o, Op::IniValue { .. }))
        .then_some(INI_NOTE);
    Preview {
        roots,
        ops,
        not_restored: NOT_RESTORED,
        registry,
        layers,
        ini,
    }
}

impl fmt::Display for Preview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for r in &self.roots {
            write!(f, "root {}: {}", r.index, r.path)?;
            if let Some((app, store)) = &r.steam {
                write!(f, " (Steam app {app} in {store})")?;
            }
            if let Some(m) = &r.main_exe {
                write!(f, ", main executable {m}")?;
            }
            writeln!(f)?;
        }
        if self.ops.is_empty() {
            writeln!(f, "nothing to do")?;
        }
        for o in &self.ops {
            match (o.root, &o.name) {
                (Some(r), _) => write!(f, "{:>3}. {} {}:{}", o.index, o.action, r, o.path)?,
                (None, Some(n)) => write!(f, "{:>3}. {} {} @ {}", o.index, o.action, o.path, n)?,
                (None, None) => write!(f, "{:>3}. {} {}", o.index, o.action, o.path)?,
            }
            if let Some(s) = &o.source {
                write!(f, " from {s}")?;
            }
            writeln!(f)?;
            if let Some((sha, len)) = &o.content {
                write!(f, "     new sha256 {sha}, {len} bytes")?;
                if let Some(a) = &o.attrs {
                    write!(f, ", attributes {a}")?;
                }
                writeln!(f)?;
            }
            if let Some((sha, len, a)) = &o.old {
                writeln!(f, "     old sha256 {sha}, {len} bytes, attributes {a}")?;
            }
            if let Some(t) = &o.tokens {
                writeln!(f, "     adds {t}")?;
            }
            if let (Some(old), Some(new)) = (&o.old_value, &o.new_value) {
                writeln!(f, "     old {old}")?;
                writeln!(f, "     new {new}")?;
                if o.type_change {
                    writeln!(f, "     the type of the value changes")?;
                }
            }
            for k in &o.ini {
                writeln!(f, "     [{}] {}: {} -> {}", k.section, k.key, k.old, k.new)?;
            }
            if o.config {
                writeln!(
                    f,
                    "     configuration file: once edited, a revert leaves it as it is"
                )?;
            }
        }
        writeln!(f, "note: {}", self.not_restored)?;
        if let Some(r) = self.registry {
            writeln!(f, "note: {r}")?;
        }
        if let Some(l) = self.layers {
            writeln!(f, "note: {l}")?;
        }
        if let Some(i) = self.ini {
            writeln!(f, "note: {i}")?;
        }
        Ok(())
    }
}
