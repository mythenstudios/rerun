//! `rerun package list | remove <id>@<version> | prune` (P5-8b-2, ADR 0025 amendment P5-8b): a
//! renderer over `rerun_core::flow::store`; the rules are the core's (`exec::remove_packages`,
//! `pkg::store::remove`).
//!
//! - `list` reads only: every package with its name in the current index (or that it is not in
//!   it and cannot be downloaded again), its state, files and bytes, its archives, the
//!   transactions that use it and why it stays; archives without a package, leftovers, entries
//!   Rerun never touches.
//! - `remove` and `prune` list what goes (every file, rule 5) and what stays with the reason,
//!   then ask (only at a console, like `history clear`; `--yes` skips it, `--dry-run` stops after
//!   the list) and remove exactly that.
//!
//! Exit codes: 0 done, nothing to do, or a list; 3 refused with nothing removed (the package is
//! used or stays, not in the store, the store changed since the list, an unreadable transaction,
//! elevated, declined); 1 passing (another Rerun holds a lock, a file was in use and stays, the
//! store or the journal cannot be read); 2 no console without `--yes`.

use std::io::Write;

use rerun_core::escape;
use rerun_core::exec::{ExecError, Refusal};
use rerun_core::flow::{
    self, ActError, PackageKeep, Pick, RemovePreview, StoreGate, StoredPackage,
};

use crate::cli::{Exit, PackageSpec};
use crate::confirm::Answer;
use crate::host::{Host, after_change, before_change, gate, shown};
use crate::messages::{Message, StaysWhy, StoreMsg};
use crate::out::Out;
use crate::txn::line_text;

fn m(s: StoreMsg<'_>) -> Message<'_> {
    Message::Store(s)
}

fn fail<E: Write>(err: &mut Out<E>, s: StoreMsg<'_>, exit: Exit) -> Exit {
    let _ = err.line(&m(s));
    exit
}

fn why(k: &PackageKeep) -> StaysWhy {
    match k {
        PackageKeep::InUse => StaysWhy::InUse,
        PackageKeep::UnknownUse(ts) => StaysWhy::UnknownUse(ts.clone()),
        PackageKeep::Store(k) => StaysWhy::Store(*k),
        PackageKeep::SharedArchive => StaysWhy::SharedArchive,
    }
}

/// The head line of a package.
fn head(p: &StoredPackage) -> Message<'_> {
    m(StoreMsg::Package {
        id: escape::text(&p.id),
        version: escape::text(&p.version),
        name: p.name.as_deref().map(escape::text),
        state: p.state,
        files: p.files,
        bytes: p.bytes,
    })
}

/// The transactions that use `p`.
fn users(p: &StoredPackage) -> impl Iterator<Item = Message<'_>> {
    p.used_by.iter().map(|u| {
        m(StoreMsg::UsedBy {
            txn: u.txn,
            app: u.app,
            state: line_text(&u.line),
        })
    })
}

/// A store gate on stderr: no Rerun folder is an empty store (not an error).
fn gate_exit<W: Write, E: Write>(out: &mut Out<W>, err: &mut Out<E>, g: StoreGate) -> Exit {
    match g {
        StoreGate::NoAppDir => out
            .line(&m(StoreMsg::Empty))
            .and_then(|()| out.flush())
            .map_or_else(|e| before_change(err, e), |()| Exit::Report),
        StoreGate::Journal(e) => fail(err, StoreMsg::Error { error: shown(&e) }, Exit::Fatal),
        StoreGate::Store(e) => fail(err, StoreMsg::Error { error: shown(&e) }, Exit::Fatal),
        StoreGate::NotFound => Exit::Refused,
    }
}

/// `rerun package list` (module docs).
pub fn list<W: Write, E: Write>(host: &Host<'_>, out: &mut Out<W>, err: &mut Out<E>) -> Exit {
    let g = match flow::guard(host.env()) {
        Ok(g) => g,
        Err(x) => return gate(err, x),
    };
    let v = match flow::package_store(&g) {
        Ok(v) => v,
        Err(x) => return gate_exit(out, err, x),
    };
    let mut lines = Vec::new();
    if !v.packages.is_empty() {
        lines.push(m(StoreMsg::PackagesHeader));
        for p in &v.packages {
            lines.push(head(p));
            lines.extend(p.archives.iter().map(|a| {
                m(StoreMsg::Archive {
                    name: escape::text(a),
                })
            }));
            lines.extend(users(p));
            if let Some(k) = &p.keep {
                lines.push(m(StoreMsg::Stays { why: why(k) }));
            }
        }
    }
    if !v.loose_archives.is_empty() {
        lines.push(m(StoreMsg::LooseHeader));
        lines.extend(v.loose_archives.iter().map(|(name, bytes)| {
            m(StoreMsg::Loose {
                name: escape::text(name),
                bytes: *bytes,
            })
        }));
    }
    if v.leftovers.0 > 0 {
        lines.push(m(StoreMsg::Leftovers {
            n: v.leftovers.0,
            bytes: v.leftovers.1,
        }));
    }
    if !v.foreign.is_empty() {
        lines.push(m(StoreMsg::ForeignHeader));
        lines.extend(v.foreign.iter().map(|(path, why)| {
            m(StoreMsg::Foreign {
                path: escape::text(path),
                why: *why,
            })
        }));
    }
    if lines.is_empty() {
        lines.push(m(StoreMsg::Empty));
    }
    out.lines(&lines)
        .and_then(|()| out.flush())
        .map_or_else(|e| before_change(err, e), |()| Exit::Report)
}

/// The lines of a preview: what goes (every file and archive), what stays and why.
fn preview_lines(p: &RemovePreview) -> Vec<Message<'_>> {
    let mut lines = Vec::new();
    let goes = !p.remove.is_empty() || !p.loose_archives.is_empty() || p.leftovers.0 > 0;
    if goes {
        lines.push(m(StoreMsg::GoesHeader));
        for x in &p.remove {
            lines.push(head(x));
            lines.extend(x.paths.iter().map(|f| {
                m(StoreMsg::File {
                    path: escape::text(f),
                })
            }));
            lines.extend(x.archives.iter().map(|a| {
                m(StoreMsg::Archive {
                    name: escape::text(a),
                })
            }));
        }
        lines.extend(p.loose_archives.iter().map(|(name, bytes)| {
            m(StoreMsg::Loose {
                name: escape::text(name),
                bytes: *bytes,
            })
        }));
        if p.leftovers.0 > 0 {
            lines.push(m(StoreMsg::Leftovers {
                n: p.leftovers.0,
                bytes: p.leftovers.1,
            }));
        }
    }
    if !p.stays.is_empty() {
        lines.push(m(StoreMsg::StaysHeader));
        for x in &p.stays {
            if let Some(k) = &x.keep {
                lines.push(m(StoreMsg::PackageStays {
                    id: escape::text(&x.id),
                    version: escape::text(&x.version),
                    why: why(k),
                }));
            }
            lines.extend(users(x));
        }
    }
    lines
}

/// The exit code of a failed removal: refused with nothing removed 3, a lock another Rerun holds
/// 1 (try again), anything else 1 (no transaction is involved). Only for `package remove` and
/// `prune`; every other command keeps `host::exit_for_exec`.
fn exit_for_store(e: &ExecError) -> Exit {
    match e {
        ExecError::Refused(Refusal::JournalBusy | Refusal::StoreBusy) => Exit::Fatal,
        ExecError::Refused(_) => Exit::Refused,
        _ => Exit::Fatal,
    }
}

/// `rerun package remove <id>@<version>` (`spec`) and `rerun package prune` (`None`), module docs.
pub fn remove<W: Write, E: Write>(
    host: &mut Host<'_>,
    spec: Option<&PackageSpec>,
    dry_run: bool,
    yes: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match run_remove(host, spec, dry_run, yes, out, err) {
        Ok(e) | Err(e) => e,
    }
}

fn run_remove<W: Write, E: Write>(
    host: &mut Host<'_>,
    spec: Option<&PackageSpec>,
    dry_run: bool,
    yes: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    let install = host.install.clone();
    let env = flow::Env {
        sys: host.sys,
        http: host.http,
        install: &install,
    };
    let g = flow::guard(env).map_err(|x| gate(err, x))?;
    let pick = match spec {
        Some(s) => Pick::Package {
            id: s.id.to_string(),
            version: s.version.clone(),
        },
        None => Pick::Unused,
    };
    let (p, s) = match flow::remove_preview(&g, &pick) {
        Ok(x) => x,
        Err(StoreGate::NoAppDir) if spec.is_none() => {
            let _ = out.line(&m(StoreMsg::Nothing)).and_then(|()| out.flush());
            return Ok(Exit::Report);
        }
        Err(StoreGate::NoAppDir | StoreGate::NotFound) => {
            let package = spec.map_or_else(String::new, |s| format!("{}@{}", s.id, s.version));
            return Err(fail(
                err,
                StoreMsg::NotFound {
                    package: escape::text(&package),
                },
                Exit::Refused,
            ));
        }
        Err(x) => return Err(gate_exit(out, err, x)),
    };
    let mut lines = preview_lines(&p);
    if s.is_empty() {
        let stays = !p.stays.is_empty();
        lines.push(m(StoreMsg::Nothing));
        let written = out.lines(&lines).and_then(|()| out.flush());
        // A package asked for by name that stays is a refusal (exit 3); prune with nothing to
        // remove is done.
        let exit = if spec.is_some() && stays {
            Exit::Refused
        } else {
            Exit::Report
        };
        return Ok(written.map_or_else(|e| before_change(err, e), |()| exit));
    }
    lines.push(m(StoreMsg::Unchanged));
    lines.push(Message::Blank);
    out.lines(&lines)
        .and_then(|()| out.flush())
        .map_err(|e| before_change(err, e))?;
    if dry_run {
        return Ok(Exit::Report);
    }
    if !yes {
        let q = m(StoreMsg::Ask {
            packages: p.remove.len(),
            archives: p.loose_archives.len(),
            leftovers: p.leftovers.0,
            bytes: p.bytes,
        });
        match host.confirm.ask(&q) {
            Answer::Yes => {}
            Answer::No => {
                let _ = err.line(&Message::Txn(crate::messages::TxnMsg::NothingDone));
                return Err(Exit::Refused);
            }
            Answer::NoConsole => {
                let _ = err.line(&Message::Txn(crate::messages::TxnMsg::NoConsole));
                return Err(Exit::Usage);
            }
        }
    }
    let r = match flow::remove(&g, s) {
        Ok(r) => r,
        Err(ActError::Changed) => return Err(fail(err, StoreMsg::Changed, Exit::Refused)),
        Err(ActError::Exec(e)) => {
            return Err(fail(
                err,
                StoreMsg::Error { error: shown(&e) },
                exit_for_store(&e),
            ));
        }
    };
    let mut done = vec![m(StoreMsg::Removed {
        packages: r.packages.len(),
        archives: r.archives,
        leftovers: r.leftovers,
        bytes: r.bytes,
    })];
    // What stopped stays and shows again; the command did not finish: exit 1.
    let exit = if r.stopped.is_empty() {
        Exit::Report
    } else {
        done.push(m(StoreMsg::StaysHeader));
        done.extend(r.stopped.iter().map(|(name, why)| {
            m(StoreMsg::Stopped {
                name: escape::text(name),
                why: *why,
            })
        }));
        Exit::Fatal
    };
    Ok(out
        .lines(&done)
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, exit), |()| exit))
}

#[cfg(test)]
mod tests {
    use rerun_core::exec::{ExecError, Refusal};

    use super::exit_for_store;
    use crate::cli::Exit;

    #[test]
    fn a_lock_is_passing_and_every_other_refusal_refused() {
        let e = |r| exit_for_store(&ExecError::Refused(r));
        assert_eq!(e(Refusal::JournalBusy), Exit::Fatal);
        assert_eq!(e(Refusal::StoreBusy), Exit::Fatal);
        assert_eq!(e(Refusal::StoreChanged), Exit::Refused);
        assert_eq!(e(Refusal::Elevated), Exit::Refused);
        // Other commands keep their mapping.
        assert_eq!(
            crate::host::exit_for_exec(&ExecError::Refused(Refusal::JournalBusy)),
            Exit::Refused
        );
    }
}
