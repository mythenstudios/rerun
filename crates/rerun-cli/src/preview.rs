//! The one renderer of a plan's preview (P2-13): `plan`, `apply`, and the roots and ops of a
//! transaction in `status`, `revert` and `forget`. Pure: a [`Preview`] in, one message per
//! line out. Every untrusted field arrives escaped from the core (`escape::Shown`) and stands
//! last on its line; an INI key's old and new value each get their own line. Registry text
//! appears only where the core put it: the preview of a stored plan (a recorded head comes
//! masked, `plan::preview_head`).

use rerun_core::escape::{self, Shown};
use rerun_core::plan::{Preview, PreviewOp};

use crate::messages::{At, Message, OpRef, TxnMsg};

fn m(t: TxnMsg<'_>) -> Message<'_> {
    Message::Txn(t)
}

/// What and where op `o` acts.
pub fn op_ref(o: &PreviewOp) -> OpRef<'_> {
    OpRef {
        action: o.action,
        at: match o.root {
            Some(root) => At::File {
                root,
                path: o.path.clone(),
            },
            None => At::Reg {
                key: o.path.clone(),
            },
        },
    }
}

/// The roots of `p`.
pub fn roots(p: &Preview) -> Vec<Message<'_>> {
    let mut out = Vec::new();
    for r in &p.roots {
        out.push(m(TxnMsg::Root {
            index: r.index,
            path: r.path.clone(),
        }));
        if let Some((app_id, library)) = &r.steam {
            out.push(m(TxnMsg::RootSteam {
                app_id: *app_id,
                library: library.clone(),
            }));
        }
        if let Some(path) = &r.main_exe {
            out.push(m(TxnMsg::RootMainExe { path: path.clone() }));
        }
    }
    out
}

/// One op with everything the preview knows about it.
pub fn op(o: &PreviewOp) -> Vec<Message<'_>> {
    let mut out = vec![m(TxnMsg::Op {
        index: o.index,
        op: op_ref(o),
    })];
    if let Some(name) = &o.name {
        out.push(m(TxnMsg::ValueName { name: name.clone() }));
    }
    if let Some(source) = &o.source {
        out.push(m(TxnMsg::Source {
            source: source.clone(),
        }));
    }
    if let Some((sha256, len)) = &o.content {
        out.push(m(TxnMsg::NewContent {
            sha256,
            len: *len,
            attrs: o.attrs.as_deref(),
        }));
    }
    if let Some((sha256, len, attrs)) = &o.old {
        out.push(m(TxnMsg::OldContent {
            sha256,
            len: *len,
            attrs,
        }));
    }
    if let Some(t) = &o.tokens {
        out.push(m(TxnMsg::Tokens { tokens: tokens(t) }));
    }
    if let Some(v) = &o.old_value {
        out.push(m(TxnMsg::OldValue(v)));
    }
    if let Some(v) = &o.new_value {
        out.push(m(TxnMsg::NewValue(v)));
    }
    if o.type_change {
        out.push(m(TxnMsg::TypeChange));
    }
    for k in &o.ini {
        out.push(m(TxnMsg::IniKey {
            section: k.section.clone(),
            key: k.key.clone(),
        }));
        out.push(m(TxnMsg::IniOld(&k.old)));
        out.push(m(TxnMsg::IniNew {
            value: k.new.clone(),
        }));
    }
    if o.config {
        out.push(m(TxnMsg::Config));
    }
    out
}

/// The tokens of an `add tokens` op (their grammar is `[A-Z0-9_]`; escaped all the same: the
/// preview field is a plain string).
fn tokens(t: &str) -> Shown<'_> {
    escape::text(t)
}

/// The whole preview: roots, ops, notes.
pub fn render(p: &Preview) -> Vec<Message<'_>> {
    let mut out = roots(p);
    for o in &p.ops {
        out.extend(op(o));
    }
    out.push(m(TxnMsg::Note(p.not_restored)));
    for note in [p.registry, p.layers, p.ini].into_iter().flatten() {
        out.push(m(TxnMsg::Note(note)));
    }
    out
}

#[cfg(test)]
mod tests;
