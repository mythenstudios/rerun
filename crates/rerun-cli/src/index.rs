//! `rerun index import <index.json> <index.json.sig>` and `rerun index show` (ADR 0024). No
//! network: until phase 6 an index comes as two files the user names.
//!
//! `import`: the elevated guard (user decision E3), both files through
//! `policy::root::read_input` (the index at most `MAX_INDEX_BYTES`, the signature at most 64
//! bytes), then `catalog::store::import` with the keys this build trusts: the signature is
//! checked over the raw bytes before anything is parsed, an older index (lower `seq`) or another
//! one with the same number is refused, and Rerun's folder is created only for an index that
//! passed. `show`: reads the current index back like an import (signature, form) and prints its
//! facts; it creates nothing.

use std::io::Write;
use std::path::Path;

use rerun_core::catalog::store::{self, Imported, StoreError};
use rerun_core::catalog::{Catalog, MAX_INDEX_BYTES, SIG_BYTES, trusted_keys};
use rerun_core::escape;
use rerun_core::flow::{self, IndexState};
use rerun_core::policy::root::{AppDir, Create, read_input};

use crate::cli::Exit;
use crate::host::{Host, after_change, gate, shown, standard_user};
use crate::messages::{IndexMsg, Message, TxnMsg};
use crate::out::Out;

fn note<E: Write>(err: &mut Out<E>, m: IndexMsg<'_>, exit: Exit) -> Exit {
    let _ = err.line(&Message::Index(m));
    exit
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn facts(c: &Catalog) -> [Message<'static>; 2] {
    [
        Message::Index(IndexMsg::Facts {
            seq: c.seq(),
            topos: c.topos().len(),
            packages: c.packages().len(),
            key: c.key().to_string(),
            sha256: hex(c.sha256()),
        }),
        Message::Index(IndexMsg::Issued {
            issued: escape::text(c.issued()).into_owned(),
        }),
    ]
}

fn read<E: Write>(
    host: &Host<'_>,
    p: &Path,
    max: usize,
    which: &'static str,
    err: &mut Out<E>,
) -> Result<Vec<u8>, Exit> {
    let file = std::path::absolute(p).map_err(|e| {
        note(
            err,
            IndexMsg::File {
                which,
                error: shown(&e),
            },
            Exit::Refused,
        )
    })?;
    read_input(host.sys, &file, max as u64).map_err(|e| {
        note(
            err,
            IndexMsg::File {
                which,
                error: shown(&e),
            },
            Exit::Refused,
        )
    })
}

/// `rerun index import` (module docs).
pub fn import<W: Write, E: Write>(
    host: &Host<'_>,
    index: &Path,
    sig: &Path,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match run_import(host, index, sig, out, err) {
        Ok(e) | Err(e) => e,
    }
}

fn run_import<W: Write, E: Write>(
    host: &Host<'_>,
    index: &Path,
    sig: &Path,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    standard_user(host.sys, err)?;
    let bytes = read(host, index, MAX_INDEX_BYTES, "index", err)?;
    let sig = read(host, sig, SIG_BYTES, "signature", err)?;
    let keys = trusted_keys();
    // Verified and checked before Rerun's folder is created: a refused index leaves nothing.
    let v = rerun_core::catalog::verify(&bytes, &sig, &keys)
        .map_err(|e| note(err, IndexMsg::Refused { error: shown(&e) }, Exit::Refused))?;
    Catalog::from_verified(&v)
        .map_err(|e| note(err, IndexMsg::Refused { error: shown(&e) }, Exit::Refused))?;
    let app = match AppDir::open(host.sys, Create::IfMissing) {
        Ok(Some(a)) => a,
        Ok(None) => {
            let _ = err.line(&Message::Txn(TxnMsg::NoAppDir));
            return Err(Exit::Fatal);
        }
        Err(e) => {
            let _ = err.line(&Message::Txn(TxnMsg::AppDir { error: shown(&e) }));
            return Err(Exit::Fatal);
        }
    };
    let done = store::import(&app, &bytes, &sig, &keys).map_err(|e| {
        let exit = match e {
            StoreError::Root(_) | StoreError::Sys(_) => Exit::Fatal,
            _ => Exit::Refused,
        };
        note(err, IndexMsg::Refused { error: shown(&e) }, exit)
    })?;
    let (first, c) = match &done {
        Imported::New { catalog, previous } => (
            IndexMsg::Imported {
                seq: catalog.seq(),
                previous: *previous,
            },
            catalog,
        ),
        Imported::AlreadyCurrent(catalog) => {
            (IndexMsg::AlreadyCurrent { seq: catalog.seq() }, catalog)
        }
    };
    let mut lines = vec![Message::Index(first)];
    lines.extend(facts(c));
    Ok(out
        .lines(&lines)
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, Exit::Report), |()| Exit::Report))
}

/// `rerun index show` (module docs).
pub fn show<W: Write, E: Write>(host: &Host<'_>, out: &mut Out<W>, err: &mut Out<E>) -> Exit {
    let app = match flow::open_app(host.sys) {
        Ok(app) => app,
        Err(g) => return gate(err, g),
    };
    match flow::index_state(app.as_ref()) {
        IndexState::None => print(out, err, &[Message::Index(IndexMsg::NoneYet)]),
        IndexState::Current(c) => print(out, err, &facts(&c)),
        IndexState::Refused(e) => note(err, IndexMsg::Refused { error: shown(&e) }, Exit::Refused),
    }
}

fn print<W: Write, E: Write>(out: &mut Out<W>, err: &mut Out<E>, lines: &[Message<'_>]) -> Exit {
    out.lines(lines)
        .and_then(|()| out.flush())
        .map_or_else(|e| crate::out::failed(err, e), |()| Exit::Report)
}
