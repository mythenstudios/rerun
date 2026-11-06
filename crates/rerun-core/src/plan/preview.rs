//! The preview of a plan (core rule 5, ADR 0020 "Preview"): every op with its root, path,
//! content source, SHA-256, length and attributes, the old state of a replace, the hint for a
//! configuration file, and once per plan what a revert does not restore (ADR 0017, D3). Every
//! untrusted field is an [`escape::Shown`] (`escape::path` for paths and for the source,
//! which joins package ID, version and file), built from the decoded plan, i.e. from the stored bytes.

use std::fmt;

use super::{ContentRef, FileState, Op, Plan, PlanOrigin, Target};
use crate::escape::{self, Shown};
use crate::sys::fs::Attrs;
use crate::wire::hex32;

/// What a revert does not restore (ADR 0017, "What exact means", user decision D3).
pub const NOT_RESTORED: &str = "a revert restores existence, content, length, read-only, \
hidden and system; not timestamps, file IDs, permissions, alternate data streams, short names \
or the archive attribute";

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
    /// What it does: `create folder`, `create file`, `replace file`.
    pub action: &'static str,
    /// Root index.
    pub root: usize,
    /// Path below the root.
    pub path: Shown<'static>,
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
                None => (None, None, false),
            };
            let (root, path) = match op.target() {
                Target::File { root, path, .. } => (usize::from(root.0), path),
            };
            PreviewOp {
                index,
                action,
                root,
                path: escape::path(path.as_str()).into_owned(),
                source,
                content,
                attrs,
                old: old_state,
                config,
            }
        })
        .collect();
    Preview {
        roots,
        ops,
        not_restored: NOT_RESTORED,
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
            write!(f, "{:>3}. {} {}:{}", o.index, o.action, o.root, o.path)?;
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
            if o.config {
                writeln!(
                    f,
                    "     configuration file: once edited, a revert leaves it as it is"
                )?;
            }
        }
        writeln!(f, "note: {}", self.not_restored)
    }
}
