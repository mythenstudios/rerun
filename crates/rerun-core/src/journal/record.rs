//! Records, wire format 1 (ADR 0019 amendment, P2-7).
//!
//! A record file `NNNN.json` is one JSON object `{"format":1,"n":N,"head":"<sha256>",
//! "record":{"<kind>":{…}}}` exactly as `serde_json::to_vec` writes it: the reader parses with
//! `deny_unknown_fields`, checks `format` first (another value is [`Damage::Format`], not
//! "unparsable") and accepts the bytes only if serialising the parsed record gives the same
//! bytes, so every accepted file has exactly one form. No `flatten` (it does not work with
//! `deny_unknown_fields`).
//!
//! The record form of P2-10a (ADR 0019 amendment), fixed once for P2-10 to P2-12: an intent
//! keeps the old state its revert needs in [`Before`] (a file or a large old value in
//! `op-NNNN.bin`, a small old value inline); `Done.file_id` is only for what has a file ID;
//! `RevertIntent { from, to }` names the digests of a semantic revert, both or neither: written
//! since P2-12, for `IniValue` only ([`Semantic`]).
//!
//! `RevertDone.old_left` (P2-15; format 1 stays unstable until A6): the sequence indices of the
//! `.old` files the revert left, not a flag; the grammar bounds them by the op's records.
//!
//! `Rebind` (P2-14, additive; format 1 stays unstable until A6): root `root` of the head is bound
//! from here on to the game folder `steamapps\common\<installdir>` of the Steam library `store`,
//! with the identities seen when the user confirmed it, and the file IDs of the folders the plan
//! created as found there ([`DirProof`]). No game path: the install folder is always the head's
//! (senior-dev S3).

use serde::{Deserialize, Serialize};

use super::Damage;
use crate::path::RootPath;
use crate::policy::root::RootId;
use crate::sys::fs::TmpName;

/// The one record format.
pub const FORMAT: u32 = 1;

/// What a revert observed of an op before it acted (ADR 0020, "Observing and reverting").
/// Defined here because `RevertDone` records it; `exec` produces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observed {
    /// As before the op.
    Before,
    /// Exactly as the op left it.
    After,
    /// Semantic ops only: Rerun's own part is as it set it, the rest changed.
    Drifted,
    /// Anything else; never overwritten or deleted (D10).
    Foreign,
}

/// How a transaction was closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Closing {
    /// An apply failed and every op was reverted (no `Applied`).
    RolledBack,
    /// An applied transaction was reverted completely.
    Reverted,
    /// Closed by `forget` without (complete) revert.
    Forgotten,
}

/// Content by its SHA-256 and length: a backup `op-NNNN.bin`, or the bytes a semantic revert
/// starts from and ends in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    /// SHA-256 of the content.
    #[serde(with = "crate::wire::hex32")]
    pub sha256: [u8; 32],
    /// Length in bytes.
    pub len: u64,
}

/// A semantic revert (P2-12, ADR 0019 amendment): the whole content it starts from (as observed)
/// and the whole content it writes. Recorded as `RevertIntent { from, to }` before the first
/// change, so the replace sequence of the revert has known start and end states (ADR 0017 B2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Semantic {
    /// The content observed.
    pub from: Digest,
    /// The content written.
    pub to: Digest,
}

/// Most bytes of an old state kept inline in an intent (ADR 0019 budgets); more go to
/// `op-NNNN.bin`. A larger inline value is against the grammar (`Damaged`).
pub const INLINE_MAX: usize = 16 << 10;

/// The old state an intent keeps for its revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Before {
    /// In `op-NNNN.bin` of its op, with this digest (a replaced file, a large old value).
    Bin(Digest),
    /// In the record, as lower-case hex, at most [`INLINE_MAX`] bytes (a small old value).
    Inline(#[serde(with = "crate::wire::hex_bytes")] Vec<u8>),
}

/// A folder a `CreateDir` op created, by the file ID it has in the folder a `Rebind` binds (a
/// copy of the library gives every folder a new file ID; P2-14, user decision E-R2 a). The revert
/// takes it as it takes `Done.file_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirProof {
    /// Op index (a `CreateDir` of the rebound root; `exec` checks the kind).
    pub op: u16,
    /// File ID of the folder.
    #[serde(with = "crate::wire::hex128")]
    pub file_id: u128,
}

/// Most [`DirProof`]s of one `Rebind` (a plan has at most 128 ops).
pub const MAX_DIRS: usize = 128;

/// One record (ADR 0019 amendment). `op` is the index of the op in the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Record {
    /// Before op `op` changes anything: its temp name and the old state its revert needs.
    Intent {
        /// Op index.
        op: u16,
        /// Temp name the change uses next to its target.
        tmp: Option<TmpName>,
        /// The old state (`None`: the op creates its object).
        before: Option<Before>,
    },
    /// Op `op` is done.
    Done {
        /// Op index.
        op: u16,
        /// File ID of what a file op created or wrote (`None` for keys and values).
        #[serde(with = "crate::wire::hex128_opt")]
        file_id: Option<u128>,
        /// `<tmp>.old` was left behind (mapped as an image, ADR 0017).
        old_left: bool,
    },
    /// Every op is done and flushed.
    Applied {
        /// Number of ops.
        ops: u16,
    },
    /// Before the revert of op `op` changes anything (repeatable until `RevertDone`).
    RevertIntent {
        /// Op index.
        op: u16,
        /// Temp name the revert uses (a restore creates `<tmp>`).
        tmp: Option<TmpName>,
        /// A semantic revert (P2-12): the content it starts from; with `to`, or neither.
        from: Option<Digest>,
        /// A semantic revert (P2-12): the content it writes; with `from`, or neither.
        to: Option<Digest>,
    },
    /// The revert of op `op` is done.
    RevertDone {
        /// Op index.
        op: u16,
        /// What the revert observed before it acted.
        observed: Observed,
        /// The sequences of the op whose `.old` this revert left (mapped as an image), by
        /// index: 0 the apply's (`Intent.tmp`), `i` the `i`-th `RevertIntent` with a temp name;
        /// strictly ascending (P2-15). Never a name or a path: the name and its expected
        /// content follow from the records.
        old_left: Vec<u16>,
    },
    /// From here on, root `root` of the head is the game folder of the head's install folder in
    /// the Steam library `store` (P2-14). Only after `Applied`; repeatable, the last one of a
    /// root holds.
    Rebind {
        /// Root index in the head.
        root: u16,
        /// The identity of the game folder as bound before (the head's, or the last rebind's).
        old: RootId,
        /// The Steam library (canonical path), parsed again on read.
        store: RootPath,
        /// Identity of the library.
        store_id: RootId,
        /// Identity of the game folder.
        id: RootId,
        /// The folders the plan created, by their file ID there, by op ascending.
        dirs: Vec<DirProof>,
    },
    /// The transaction is closed; nothing follows.
    Closed {
        /// How.
        how: Closing,
    },
}

/// A record file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordFile {
    /// [`FORMAT`].
    pub(crate) format: u32,
    /// Number of the record, equal to its file name.
    pub(crate) n: u16,
    /// SHA-256 of `head.json`.
    #[serde(with = "crate::wire::hex32")]
    pub(crate) head: [u8; 32],
    /// The record.
    pub(crate) record: Record,
}

/// Only the format, read before the strict parse.
#[derive(Deserialize)]
struct Probe {
    format: u32,
}

/// The bytes of record `n`.
pub(crate) fn encode(n: u16, head: &[u8; 32], record: &Record) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&RecordFile {
        format: FORMAT,
        n,
        head: *head,
        record: record.clone(),
    })
}

/// Parses the file `NNNN.json` with the number `n` of its name against the head hash.
pub(crate) fn decode(bytes: &[u8], n: u16, head: &[u8; 32]) -> Result<Record, Damage> {
    let probe: Probe = serde_json::from_slice(bytes).map_err(|_| Damage::Unparsable { n })?;
    if probe.format != FORMAT {
        return Err(Damage::Format { n });
    }
    let file: RecordFile = serde_json::from_slice(bytes).map_err(|_| Damage::Unparsable { n })?;
    if serde_json::to_vec(&file).ok().as_deref() != Some(bytes) {
        return Err(Damage::Unparsable { n });
    }
    if file.n != n {
        return Err(Damage::Numbering { n });
    }
    if &file.head != head {
        return Err(Damage::HeadHash { n });
    }
    Ok(file.record)
}

#[cfg(test)]
mod tests {
    use super::{Before, Closing, Digest, DirProof, Observed, Record, decode, encode};
    use crate::journal::Damage;
    use crate::path::RootPath;
    use crate::policy::root::RootId;
    use crate::sys::fs::TmpName;

    fn id(serial: u64, file: u128) -> RootId {
        RootId {
            volume_serial: serial,
            file_id: file,
        }
    }

    /// A `Rebind` of root 0 into `E:\SteamLibrary` with `dirs`.
    pub(crate) fn rebind(dirs: Vec<DirProof>) -> Record {
        Record::Rebind {
            root: 0,
            old: id(0x44, 7),
            store: RootPath::new(r"E:\SteamLibrary").unwrap(),
            store_id: id(0x45, 1),
            id: id(0x45, 9),
            dirs,
        }
    }

    pub(crate) fn every_kind() -> Vec<Record> {
        vec![
            Record::Intent {
                op: 0,
                tmp: Some(TmpName::new(0xab, 1)),
                before: Some(Before::Bin(Digest {
                    sha256: [7; 32],
                    len: 3,
                })),
            },
            Record::Intent {
                op: 1,
                tmp: None,
                before: None,
            },
            Record::Intent {
                op: 2,
                tmp: None,
                before: Some(Before::Inline(vec![0, 0xab, 0xff])),
            },
            Record::Intent {
                op: 3,
                tmp: None,
                before: Some(Before::Inline(Vec::new())),
            },
            Record::Done {
                op: 0,
                file_id: Some(u128::MAX),
                old_left: true,
            },
            Record::Done {
                op: 2,
                file_id: None,
                old_left: false,
            },
            Record::Applied { ops: 2 },
            Record::RevertIntent {
                op: 1,
                tmp: Some(TmpName::new(0xab, 2)),
                from: None,
                to: None,
            },
            Record::RevertIntent {
                op: 1,
                tmp: None,
                from: Some(Digest {
                    sha256: [1; 32],
                    len: 0,
                }),
                to: Some(Digest {
                    sha256: [2; 32],
                    len: u64::MAX,
                }),
            },
            Record::RevertDone {
                op: 1,
                observed: Observed::Foreign,
                old_left: Vec::new(),
            },
            Record::RevertDone {
                op: 1,
                observed: Observed::Before,
                old_left: vec![0],
            },
            Record::RevertDone {
                op: 1,
                observed: Observed::After,
                old_left: vec![0, 2],
            },
            rebind(Vec::new()),
            rebind(vec![
                DirProof { op: 0, file_id: 5 },
                DirProof {
                    op: 3,
                    file_id: u128::MAX,
                },
            ]),
            Record::Closed {
                how: Closing::RolledBack,
            },
        ]
    }

    #[test]
    fn records_round_trip_in_one_form() {
        let head = [9u8; 32];
        for (i, r) in every_kind().into_iter().enumerate() {
            let n = u16::try_from(i + 1).unwrap();
            let bytes = encode(n, &head, &r).unwrap();
            assert_eq!(decode(&bytes, n, &head), Ok(r.clone()), "{r:?}");
            // Another number or head is refused.
            assert_eq!(
                decode(&bytes, n + 1, &head),
                Err(Damage::Numbering { n: n + 1 })
            );
            assert_eq!(decode(&bytes, n, &[0; 32]), Err(Damage::HeadHash { n }));
        }
        let bytes = encode(1, &head, &Record::Applied { ops: 2 }).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            format!(
                r#"{{"format":1,"n":1,"head":"{}","record":{{"applied":{{"ops":2}}}}}}"#,
                "09".repeat(32)
            )
        );
        // The wire form of the P2-10a fields.
        let wire = |r: &Record| {
            let b = encode(1, &head, r).unwrap();
            let s = String::from_utf8(b).unwrap();
            let at = s.find(r#""record":"#).unwrap() + 9;
            s[at..s.len() - 1].to_owned()
        };
        let all = every_kind();
        assert_eq!(
            wire(&all[0]),
            format!(
                r#"{{"intent":{{"op":0,"tmp":".rerun-00000000000000ab-1.tmp","before":{{"bin":{{"sha256":"{}","len":3}}}}}}}}"#,
                "07".repeat(32)
            )
        );
        assert_eq!(
            wire(&all[2]),
            r#"{"intent":{"op":2,"tmp":null,"before":{"inline":"00abff"}}}"#
        );
        assert_eq!(
            wire(&all[5]),
            r#"{"done":{"op":2,"file_id":null,"old_left":false}}"#
        );
        assert_eq!(
            wire(&all[7]),
            r#"{"revert_intent":{"op":1,"tmp":".rerun-00000000000000ab-2.tmp","from":null,"to":null}}"#
        );
        // P2-15: the sequence indices, never a name.
        assert_eq!(
            wire(&all[9]),
            r#"{"revert_done":{"op":1,"observed":"foreign","old_left":[]}}"#
        );
        assert_eq!(
            wire(&all[11]),
            r#"{"revert_done":{"op":1,"observed":"after","old_left":[0,2]}}"#
        );
        // P2-14: no game path, the library by its canonical path.
        assert_eq!(
            wire(&all[13]),
            format!(
                r#"{{"rebind":{{"root":0,"old":"0000000000000044-{:032x}","store":"E:\\SteamLibrary","store_id":"0000000000000045-{:032x}","id":"0000000000000045-{:032x}","dirs":[{{"op":0,"file_id":"{:032x}"}},{{"op":3,"file_id":"{}"}}]}}}}"#,
                7,
                1,
                9,
                5,
                "f".repeat(32)
            )
        );
    }

    /// J3 for `Rebind` (P2-14): one form only; every field parsed again.
    #[test]
    fn edited_rebind_records_are_unparsable() {
        let head = [9u8; 32];
        let good = String::from_utf8(
            encode(
                4,
                &head,
                &rebind(vec![DirProof {
                    op: 2,
                    file_id: 0xab,
                }]),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode(good.as_bytes(), 4, &head),
            Ok(rebind(vec![DirProof {
                op: 2,
                file_id: 0xab
            }]))
        );
        let ab = format!("{:032x}", 0xab);
        for bad in [
            // Another path style or spelling of the drive.
            good.replace(r"E:\\SteamLibrary", "E:/SteamLibrary"),
            good.replace(r"E:\\SteamLibrary", r"e:\\SteamLibrary"),
            good.replace(r"E:\\SteamLibrary", r"E:\\SteamLibrary\\"),
            // Not a root path at all.
            good.replace(r"E:\\SteamLibrary", r"\\\\server\\lib"),
            good.replace(r"E:\\SteamLibrary", r"E:\\"),
            good.replace(r"E:\\SteamLibrary", r"E:\\a\\..\\b"),
            // Upper-case hex, a short ID, a number.
            good.replace(&ab, &ab.to_uppercase()),
            good.replace(&ab, "ab"),
            good.replace(&format!(r#""{ab}""#), "171"),
            good.replace("0000000000000045-", "0000000000000045_"),
            // An unknown field, a missing one, a game path.
            good.replace(r#""dirs":"#, r#""x":1,"dirs":"#),
            good.replace(&format!(r#","dirs":[{{"op":2,"file_id":"{ab}"}}]"#), ""),
            good.replace(r#""root":0,"#, ""),
            good.replace(r#""store":"#, r#""path":"E:\\x","store":"#),
            good.replace(r#""op":2,"#, r#""op":2,"x":0,"#),
        ] {
            assert_ne!(bad, good);
            assert_eq!(
                decode(bad.as_bytes(), 4, &head),
                Err(Damage::Unparsable { n: 4 }),
                "{bad}"
            );
        }
    }

    /// J3 for `RevertDone.old_left` (P2-15): one form, numbers only, never a name or a flag.
    #[test]
    fn j3_edited_old_left_lists_are_unparsable() {
        let head = [9u8; 32];
        let rec = Record::RevertDone {
            op: 1,
            observed: Observed::After,
            old_left: vec![0, 2],
        };
        let good = String::from_utf8(encode(5, &head, &rec).unwrap()).unwrap();
        assert_eq!(decode(good.as_bytes(), 5, &head), Ok(rec));
        for bad in [
            good.replace("[0,2]", "[0, 2]"),
            good.replace("[0,2]", "[0,2,]"),
            good.replace("[0,2]", r#"["0",2]"#),
            good.replace("[0,2]", "[-1,2]"),
            good.replace("[0,2]", "[0.0,2]"),
            good.replace("[0,2]", "[00,2]"),
            good.replace("[0,2]", "[0,65536]"),
            good.replace("[0,2]", "true"),
            good.replace("[0,2]", "null"),
            good.replace("[0,2]", "2"),
            good.replace("[0,2]", r#"[".rerun-00000000000000ab-1.tmp"]"#),
            good.replace("[0,2]", r#"[".rerun-00000000000000ab-1.tmp.old"]"#),
            good.replace(r#""old_left":[0,2]"#, r#""old_left":[0,2],"x":0"#),
            good.replace(r#","old_left":[0,2]"#, ""),
        ] {
            assert_ne!(bad, good);
            assert_eq!(
                decode(bad.as_bytes(), 5, &head),
                Err(Damage::Unparsable { n: 5 }),
                "{bad}"
            );
        }
    }

    #[test]
    fn edited_records_are_refused_with_their_reason() {
        let head = [9u8; 32];
        let good =
            String::from_utf8(encode(3, &head, &Record::Applied { ops: 2 }).unwrap()).unwrap();
        let cases: Vec<(String, Damage)> = vec![
            (
                good.replace(r#""format":1"#, r#""format":2"#),
                Damage::Format { n: 3 },
            ),
            (
                good.replace(r#""ops":2"#, r#""ops":2,"x":1"#),
                Damage::Unparsable { n: 3 },
            ),
            (
                good.replace(r#""n":3"#, r#""n":3,"y":0"#),
                Damage::Unparsable { n: 3 },
            ),
            (
                good.replace(r#""n":3,"#, r#" "n":3,"#),
                Damage::Unparsable { n: 3 },
            ),
            (
                good.replace(r#""n":3"#, r#""n":3,"n":3"#),
                Damage::Unparsable { n: 3 },
            ),
            (
                good.replace("applied", "Applied"),
                Damage::Unparsable { n: 3 },
            ),
            (good.replace("09", "0A"), Damage::Unparsable { n: 3 }),
            (
                good[..good.len() - 1].to_owned(),
                Damage::Unparsable { n: 3 },
            ),
            (format!("{good}\n"), Damage::Unparsable { n: 3 }),
            ("[]".to_owned(), Damage::Unparsable { n: 3 }),
            (
                good.replace(r#""n":3"#, r#""n":4"#),
                Damage::Numbering { n: 3 },
            ),
        ];
        for (bytes, want) in cases {
            assert_eq!(
                decode(bytes.as_bytes(), 3, &head),
                Err(want.clone()),
                "{bytes}"
            );
        }
        // A temp name that is not Rerun's form, a hex field in upper case.
        let intent = String::from_utf8(
            encode(
                1,
                &head,
                &Record::Intent {
                    op: 0,
                    tmp: Some(TmpName::new(0xab, 1)),
                    before: Some(Before::Inline(vec![0xab])),
                },
            )
            .unwrap(),
        )
        .unwrap();
        for bad in [
            intent.replace(".rerun-00000000000000ab-1.tmp", r"..\\x"),
            intent.replace(".rerun-00000000000000ab-1.tmp", ".rerun-ab-1.tmp"),
            intent.replace(r#","before":{"inline":"ab"}"#, ""),
            intent.replace(r#"{"inline":"ab"}"#, "null,\"backup\":null"),
            intent.replace(r#""inline":"ab""#, r#""inline":"AB""#),
            intent.replace(r#""inline":"ab""#, r#""inline":"a""#),
            intent.replace(r#""inline":"ab""#, r#""inline":[171]"#),
            intent.replace(r#"{"inline":"ab"}"#, r#"{"bin":{"sha256":"ab","len":1}}"#),
        ] {
            assert_eq!(
                decode(bad.as_bytes(), 1, &head),
                Err(Damage::Unparsable { n: 1 }),
                "{bad}"
            );
        }
    }
}
