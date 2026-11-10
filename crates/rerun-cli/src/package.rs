//! `rerun package fetch <id>@<version>` (ADR 0025): every download of a package of the current
//! signed index into `<LocalAppData>\Rerun\cache`, through `rerun_core::pkg::download`.
//!
//! The elevated guard first (user decision E3), then the current index (read back and checked
//! like `index show`; none is "nothing done"), the package by ID and its one version (user
//! decision E2 a: another version is another package), its downloads (a community package has
//! none: its page is the way), then each download in turn. The first failure ends the command;
//! what was fetched before it stays in the cache (each entry only under its pinned hash).

use std::io::Write;

use rerun_core::catalog::store;
use rerun_core::catalog::{Package, model::Arch, trusted_keys};
use rerun_core::escape;
use rerun_core::pkg::download::{self, FetchError, How};
use rerun_core::policy::root::{AppDir, Create};

use crate::cli::{Exit, PackageSpec};
use crate::host::{Host, after_change, shown, standard_user};
use crate::messages::{FetchedHow, Message, PackageMsg, TxnMsg};
use crate::out::Out;

fn note<E: Write>(err: &mut Out<E>, m: PackageMsg<'_>, exit: Exit) -> Exit {
    let _ = err.line(&Message::Package(m));
    exit
}

fn failed<E: Write>(err: &mut Out<E>, e: &FetchError) -> Exit {
    let exit = match e {
        FetchError::Network(_) | FetchError::Root(_) | FetchError::Sys(_) => Exit::Fatal,
        _ => Exit::Refused,
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
    for d in &downloads {
        let got = download::fetch(host.sys, host.http, &app, d).map_err(|e| {
            // What was fetched before the failure is reported first.
            let _ = out.lines(&lines).and_then(|()| out.flush());
            failed(err, &e)
        })?;
        lines.push(Message::Package(PackageMsg::Fetched {
            id: escape::text(p.id.as_str()).into_owned(),
            version: escape::text(&p.version).into_owned(),
            arch: d.arch.map(arch),
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
    Ok(out
        .lines(&lines)
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, Exit::Report), |()| Exit::Report))
}
