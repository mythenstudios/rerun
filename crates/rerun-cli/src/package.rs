//! `rerun package fetch <id>@<version>` (ADR 0025): every download of a package of the current
//! signed index into `<LocalAppData>\Rerun\cache`, through `rerun_core::pkg::download`, then
//! the files the package names into `<LocalAppData>\Rerun\packages\<id>\<version>`, through
//! `rerun_core::pkg::extract` (only after every download is in the cache).
//!
//! The elevated guard first (user decision E3), then the current index (read back and checked
//! like `index show`; none is "nothing done"), the package by ID and its one version (user
//! decision E2 a: another version is another package), its downloads (a community package has
//! none: its page is the way), then each download in turn, then the unpacking (one line per
//! file). The first failure ends the command; what was fetched or unpacked before it stays (each
//! cache entry only under its pinned hash, each file only with its own).
//!
//! Exit codes (ADR 0025): 0 when every download is in the cache, and also when a download fails
//! after this run stored an archive, removed a damaged entry or unpacked a file (the lines of
//! what was done, then the failure); otherwise 1 for a passing or environment failure (`FetchError::transient`: the
//! network, HTTP 5xx and 429, a body that does not match its length, the deadline, a cache entry
//! in use, the file system) and 3 for a refusal by policy or integrity (nothing changed).

use std::io::Write;

use rerun_core::catalog::store;
use rerun_core::catalog::{Package, model::Arch, trusted_keys};
use rerun_core::escape;
use rerun_core::pkg::download::{self, FetchError, How};
use rerun_core::pkg::extract::{self, ExtractError};
use rerun_core::policy::root::{AppDir, Create};

use crate::cli::{Exit, PackageSpec};
use crate::host::{Host, after_change, shown, standard_user};
use crate::messages::{FetchedHow, Message, PackageMsg, TxnMsg, UnpackedHow};
use crate::out::Out;

fn note<E: Write>(err: &mut Out<E>, m: PackageMsg<'_>, exit: Exit) -> Exit {
    let _ = err.line(&Message::Package(m));
    exit
}

/// The exit code of a failure when nothing was changed in this run.
fn failed<E: Write>(err: &mut Out<E>, e: &FetchError) -> Exit {
    let exit = if e.transient() {
        Exit::Fatal
    } else {
        Exit::Refused
    };
    note(err, PackageMsg::Failed { error: shown(e) }, exit)
}

fn arch(a: Arch) -> &'static str {
    match a {
        Arch::X86 => "x86",
        Arch::X64 => "x64",
    }
}

/// `rerun package fetch` (module docs).
pub fn fetch<W: Write, E: Write>(
    host: &Host<'_>,
    spec: &PackageSpec,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match run(host, spec, out, err) {
        Ok(e) | Err(e) => e,
    }
}

fn package<'c, E: Write>(
    c: &'c rerun_core::catalog::Catalog,
    spec: &PackageSpec,
    err: &mut Out<E>,
) -> Result<&'c Package, Exit> {
    let id = escape::text(spec.id.as_str()).into_owned();
    let p = c
        .package(spec.id.as_str())
        .ok_or_else(|| note(err, PackageMsg::Unknown { id: id.clone() }, Exit::Refused))?;
    if p.version != spec.version {
        return Err(note(
            err,
            PackageMsg::OtherVersion {
                id,
                version: escape::text(&p.version).into_owned(),
            },
            Exit::Refused,
        ));
    }
    Ok(p)
}

fn run<W: Write, E: Write>(
    host: &Host<'_>,
    spec: &PackageSpec,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    standard_user(host.sys, err)?;
    let app = match AppDir::open(host.sys, Create::Never) {
        Ok(Some(a)) => a,
        Ok(None) => return Err(note(err, PackageMsg::NoIndex, Exit::Refused)),
        Err(e) => {
            let _ = err.line(&Message::Txn(TxnMsg::AppDir { error: shown(&e) }));
            return Err(Exit::Fatal);
        }
    };
    let catalog = match store::current(&app, &trusted_keys()) {
        Ok(Some(c)) => c,
        Ok(None) => return Err(note(err, PackageMsg::NoIndex, Exit::Refused)),
        Err(e) => {
            return Err(note(
                err,
                PackageMsg::Failed { error: shown(&e) },
                Exit::Refused,
            ));
        }
    };
    let p = package(&catalog, spec, err)?;
    let downloads = download::downloads(p).map_err(|e| failed(err, &e))?;
    let mut lines = Vec::new();
    let mut changed = false;
    for d in &downloads {
        let got = match download::fetch_noting(host.sys, host.http, &app, d, &mut changed) {
            Ok(got) => got,
            Err(e) if changed => {
                // Progress in this run: what was done, then the failure; not "nothing changed".
                let exit = out
                    .lines(&lines)
                    .and_then(|()| out.flush())
                    .map_or_else(|o| after_change(err, o, Exit::Report), |()| Exit::Report);
                return Err(note(err, PackageMsg::Failed { error: shown(&e) }, exit));
            }
            Err(e) => {
                // Nothing changed, but earlier downloads may have been cache hits: list them.
                let _ = out.lines(&lines).and_then(|()| out.flush());
                return Err(failed(err, &e));
            }
        };
        lines.push(Message::Package(PackageMsg::Fetched {
            id: escape::text(p.id.as_str()).into_owned(),
            version: escape::text(&p.version).into_owned(),
            arch: d.arch().map(arch),
            how: match got.how {
                How::Cached => FetchedHow::Cached,
                How::Downloaded {
                    redirects,
                    replaced,
                } => FetchedHow::Downloaded {
                    redirects,
                    replaced,
                },
            },
            len: got.len,
            sha256: download::cache_name(&got.sha256),
        }));
    }
    let mut unpacked = Vec::new();
    let result = extract::extract_noting(host.sys, &app, p, &mut unpacked);
    for u in &unpacked {
        if u.how != extract::How::Present {
            changed = true;
        }
        lines.push(Message::Package(PackageMsg::Unpacked {
            id: escape::text(p.id.as_str()).into_owned(),
            version: escape::text(&p.version).into_owned(),
            file: escape::path(u.dest.as_str()).into_owned(),
            how: match u.how {
                extract::How::Present => UnpackedHow::Present,
                extract::How::Extracted => UnpackedHow::Unpacked,
                extract::How::Replaced => UnpackedHow::Replaced,
                extract::How::Removed => UnpackedHow::Removed,
            },
            len: u.len,
        }));
    }
    let written = out.lines(&lines).and_then(|()| out.flush());
    match result {
        Ok(()) => {
            Ok(written.map_or_else(|e| after_change(err, e, Exit::Report), |()| Exit::Report))
        }
        Err(e) => {
            let exit = if changed {
                Exit::Report
            } else {
                unpack_exit(&e)
            };
            let exit = written.map_or_else(|o| after_change(err, o, exit), |()| exit);
            Err(note(
                err,
                PackageMsg::NotUnpacked { error: shown(&e) },
                exit,
            ))
        }
    }
}

/// The exit code of an unpacking failure when nothing was changed in this run.
fn unpack_exit(e: &ExtractError) -> Exit {
    if e.transient() {
        Exit::Fatal
    } else {
        Exit::Refused
    }
}
