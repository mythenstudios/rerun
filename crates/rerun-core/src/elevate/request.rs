//! The helper request (ADR 0023 §4, §12; A4 S1): its file form, its name and the command line
//! that names it. Pure.
//!
//! **The file** (`<AppDir>\elevate\<txn>-<n>.req`, JSON, at most [`MAX_REQUEST_BYTES`]):
//! `{"format":1,"build":…,"txn":…,"body":{"add":{…}}}` or `…{"remove":{…}}`. [`decode`] reads
//! in a fixed order: the size, then `format` alone (another one is a request error), then
//! `build` alone (another build is [`RequestError::Build`], whatever else the file holds), then
//! the whole request with `deny_unknown_fields` at every level, then the form rules: 1 to
//! [`MAX_BATCH_OPS`] ops with consecutive op indices, the plan source's form (ADR 0020
//! amendment P4-4), every identity in its one text form. Nothing in it is trusted beyond its
//! form: the helper derives what follows (§5).
//!
//! **The command line** (§3 step 5): exactly `--volume <GUID> --dir <32 lower-case hex>
//! --request <txn>-<n>.req --sha256 <64 lower-case hex>`: the `elevate` folder by identity
//! ([`DirRef`]), the fixed-form file name ([`RequestName`]) and the file's SHA-256. No path.

use std::ffi::OsString;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::MAX_BATCH_OPS;
use crate::catalog::model::Id;
use crate::path::{RelPath, RootPath};
use crate::plan::PlanSource;
use crate::policy::firewall::{Direction, Program, TxnId};
use crate::policy::root::RootId;
use crate::sys::VolumeGuid;
use crate::wire::{hex32, hex128};

/// The request format this build writes and reads.
pub const REQUEST_FORMAT: u32 = 1;
/// Most bytes of a request file (§4).
pub const MAX_REQUEST_BYTES: u64 = 64 << 10;

/// A folder by identity (A4 S1): opened by ID only, never by path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirRef {
    /// The volume.
    pub volume: VolumeGuid,
    /// The folder's 128-bit file ID on it.
    pub file_id: u128,
}

/// The request file name `<txn>-<n>.req` (§4): `<txn>` in its one form (ADR 0019), `<n>` a
/// decimal number from 1 without leading zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestName {
    name: String,
    txn: TxnId,
    n: u32,
}

impl RequestName {
    /// The name of request `n` (from 1) of `txn`.
    pub fn new(txn: TxnId, n: u32) -> Option<Self> {
        (n >= 1).then(|| Self {
            name: format!("{txn}-{n}.req"),
            txn,
            n,
        })
    }

    /// Exactly the form [`Self::new`] writes.
    pub fn parse(s: &str) -> Option<Self> {
        let stem = s.strip_suffix(".req")?;
        let (txn, n) = stem.rsplit_once('-')?;
        if n.is_empty() || n.starts_with('0') || !n.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let parsed = Self::new(TxnId::from_str(txn).ok()?, n.parse().ok()?)?;
        (parsed.name == s).then_some(parsed)
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// The transaction it names.
    pub fn txn(&self) -> TxnId {
        self.txn
    }

    /// Its number.
    pub fn n(&self) -> u32 {
        self.n
    }
}

impl fmt::Display for RequestName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// The `elevate` folder and the request file in it (§12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRef {
    /// The `elevate` folder.
    pub dir: DirRef,
    /// The file.
    pub name: RequestName,
}

impl RequestRef {
    /// The helper's command line for this request and its SHA-256 (§3 step 5).
    pub fn to_args(&self, sha256: &[u8; 32]) -> Vec<String> {
        vec![
            "--volume".to_owned(),
            self.dir.volume.to_string(),
            "--dir".to_owned(),
            format!("{:032x}", self.dir.file_id),
            "--request".to_owned(),
            self.name.as_str().to_owned(),
            "--sha256".to_owned(),
            hex32::to_string(sha256),
        ]
    }

    /// Exactly the form of [`Self::to_args`] (the program name not included); anything else is
    /// `None` (`Refused(Usage)`).
    pub fn parse_args(args: &[OsString]) -> Option<(Self, [u8; 32])> {
        let a: Vec<&str> = args.iter().map(|a| a.to_str()).collect::<Option<_>>()?;
        let [
            "--volume",
            volume,
            "--dir",
            dir,
            "--request",
            name,
            "--sha256",
            sha,
        ] = a.as_slice()
        else {
            return None;
        };
        let file_id = crate::wire::parse_hex(dir, 32)?;
        let r = Self {
            dir: DirRef {
                volume: VolumeGuid::parse(volume)?,
                file_id,
            },
            name: RequestName::parse(name)?,
        };
        Some((r, hex32::from_str(sha)?))
    }
}

/// The game folder of an add request (§5 step 4): its identity and the canonical path the CLI
/// read on its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRef {
    /// The volume.
    pub volume: VolumeGuid,
    /// Volume serial and file ID.
    pub id: RootId,
    /// The canonical path.
    pub path: RootPath,
}

/// One op of an add batch: its index in the plan and the executable (a `match.exes` path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddOp {
    /// The op index in the plan (part of the rule name).
    pub op: u16,
    /// The executable below the root.
    pub program: RelPath,
}

/// One op of a remove batch: the rule as recorded in the journal head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveOp {
    /// The op index in the plan.
    pub op: u16,
    /// The program path as recorded.
    pub program: Program,
    /// The direction as recorded.
    pub direction: Direction,
}

/// What the helper is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "one request per run, never in a collection"
)]
pub enum Body {
    /// Add Rerun's rules for the `firewall_rule` steps of the picked variants (§5 "Add").
    Add {
        /// The signed index, the Topo and the picks (binding, never authorisation).
        source: PlanSource,
        /// The `index` folder by identity (A4 S1).
        index_dir: DirRef,
        /// The game folder.
        root: RootRef,
        /// The ops, in plan order.
        ops: Vec<AddOp>,
    },
    /// Remove Rerun's rules as recorded (§5 "Remove", R1).
    Remove {
        /// The Topo.
        topo: Id,
        /// The ops, in plan order.
        ops: Vec<RemoveOp>,
    },
}

/// A helper request (§12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The CLI's build ID (`rerun_core::BUILD_ID`).
    pub build: String,
    /// The transaction.
    pub txn: TxnId,
    /// What to do.
    pub body: Body,
}

impl Request {
    /// The ops of the batch.
    pub fn op_count(&self) -> usize {
        match &self.body {
            Body::Add { ops, .. } => ops.len(),
            Body::Remove { ops, .. } => ops.len(),
        }
    }
}

/// Why a request file is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// More than [`MAX_REQUEST_BYTES`].
    #[error("the request is larger than {MAX_REQUEST_BYTES} bytes")]
    TooLarge,
    /// Another `format` (or none).
    #[error("the request is not of format {REQUEST_FORMAT}")]
    Format,
    /// Written by another build (§2, R12).
    #[error("the request is from another build of Rerun")]
    Build,
    /// Not of the request's form (never quotes the file).
    #[error("the request is not of the request form: {0}")]
    Form(&'static str),
}

// ---------- the file form ----------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDir {
    volume: String,
    #[serde(with = "hex128")]
    file_id: u128,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRoot {
    volume: String,
    id: RootId,
    path: RootPath,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAddOp {
    op: u16,
    program: RelPath,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRemoveOp {
    op: u16,
    program: String,
    direction: Direction,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAdd {
    source: PlanSource,
    index_dir: WireDir,
    root: WireRoot,
    ops: Vec<WireAddOp>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRemove {
    topo: Id,
    ops: Vec<WireRemoveOp>,
}

#[derive(Serialize, Deserialize)]
#[expect(
    clippy::large_enum_variant,
    reason = "one request per run, never in a collection"
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum WireBody {
    Add(WireAdd),
    Remove(WireRemove),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    format: u32,
    build: String,
    txn: String,
    body: WireBody,
}

/// `format` alone, read first.
#[derive(Deserialize)]
struct FormatOnly {
    format: u32,
}

/// `build` alone, read second.
#[derive(Deserialize)]
struct BuildOnly {
    build: String,
}

fn wire_dir(d: &DirRef) -> WireDir {
    WireDir {
        volume: d.volume.to_string(),
        file_id: d.file_id,
    }
}

fn dir_of(w: &WireDir) -> Result<DirRef, RequestError> {
    Ok(DirRef {
        volume: VolumeGuid::parse(&w.volume).ok_or(RequestError::Form("a volume GUID"))?,
        file_id: w.file_id,
    })
}

/// The op indices: 1 to [`MAX_BATCH_OPS`], consecutive (a batch is the last ops of a plan, §9).
fn check_ops(ops: impl ExactSizeIterator<Item = u16>) -> Result<(), RequestError> {
    let n = ops.len();
    if n == 0 || n > MAX_BATCH_OPS {
        return Err(RequestError::Form("1 to 8 ops"));
    }
    let v: Vec<u16> = ops.collect();
    if v.windows(2).any(|w| w[0].checked_add(1) != Some(w[1])) {
        return Err(RequestError::Form("consecutive op indices"));
    }
    Ok(())
}

/// The request file (module docs). The bytes are at most [`MAX_REQUEST_BYTES`].
///
/// # Errors
/// [`RequestError::TooLarge`] above the bound; [`RequestError::Form`] for a request that breaks
/// a form rule (op count and indices, the plan source).
pub fn encode(r: &Request) -> Result<Vec<u8>, RequestError> {
    let body = match &r.body {
        Body::Add {
            source,
            index_dir,
            root,
            ops,
        } => {
            check_ops(ops.iter().map(|o| o.op))?;
            source
                .check()
                .map_err(|_| RequestError::Form("a plan source"))?;
            WireBody::Add(WireAdd {
                source: source.clone(),
                index_dir: wire_dir(index_dir),
                root: WireRoot {
                    volume: root.volume.to_string(),
                    id: root.id,
                    path: root.path.clone(),
                },
                ops: ops
                    .iter()
                    .map(|o| WireAddOp {
                        op: o.op,
                        program: o.program.clone(),
                    })
                    .collect(),
            })
        }
        Body::Remove { topo, ops } => {
            check_ops(ops.iter().map(|o| o.op))?;
            WireBody::Remove(WireRemove {
                topo: topo.clone(),
                ops: ops
                    .iter()
                    .map(|o| WireRemoveOp {
                        op: o.op,
                        program: o.program.as_str().to_owned(),
                        direction: o.direction,
                    })
                    .collect(),
            })
        }
    };
    let wire = WireRequest {
        format: REQUEST_FORMAT,
        build: r.build.clone(),
        txn: r.txn.to_string(),
        body,
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| RequestError::Form("not encodable"))?;
    if u64::try_from(bytes.len()).map_or(true, |n| n > MAX_REQUEST_BYTES) {
        return Err(RequestError::TooLarge);
    }
    Ok(bytes)
}

/// Reads a request file for a helper of build `build` (module docs).
///
/// # Errors
/// [`RequestError`]: the first rule broken, in the order of the module docs.
pub fn decode(b: &[u8], build: &str) -> Result<Request, RequestError> {
    if u64::try_from(b.len()).map_or(true, |n| n > MAX_REQUEST_BYTES) {
        return Err(RequestError::TooLarge);
    }
    let f: FormatOnly = serde_json::from_slice(b).map_err(|_| RequestError::Format)?;
    if f.format != REQUEST_FORMAT {
        return Err(RequestError::Format);
    }
    let bo: BuildOnly = serde_json::from_slice(b).map_err(|_| RequestError::Form("no build ID"))?;
    if bo.build != build {
        return Err(RequestError::Build);
    }
    let w: WireRequest =
        serde_json::from_slice(b).map_err(|_| RequestError::Form("fields of the request"))?;
    let txn = TxnId::from_str(&w.txn).map_err(|_| RequestError::Form("a transaction ID"))?;
    let body = match w.body {
        WireBody::Add(a) => {
            check_ops(a.ops.iter().map(|o| o.op))?;
            a.source
                .check()
                .map_err(|_| RequestError::Form("a plan source"))?;
            Body::Add {
                source: a.source,
                index_dir: dir_of(&a.index_dir)?,
                root: RootRef {
                    volume: VolumeGuid::parse(&a.root.volume)
                        .ok_or(RequestError::Form("a volume GUID"))?,
                    id: a.root.id,
                    path: a.root.path,
                },
                ops: a
                    .ops
                    .into_iter()
                    .map(|o| AddOp {
                        op: o.op,
                        program: o.program,
                    })
                    .collect(),
            }
        }
        WireBody::Remove(r) => {
            check_ops(r.ops.iter().map(|o| o.op))?;
            let ops = r
                .ops
                .into_iter()
                .map(|o| {
                    Ok(RemoveOp {
                        op: o.op,
                        program: Program::parse(&o.program)
                            .map_err(|_| RequestError::Form("a program path"))?,
                        direction: o.direction,
                    })
                })
                .collect::<Result<Vec<_>, RequestError>>()?;
            Body::Remove { topo: r.topo, ops }
        }
    };
    Ok(Request {
        build: w.build,
        txn,
        body,
    })
}
