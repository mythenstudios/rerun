//! Records, wire format 1 (ADR 0019 amendment, P2-7).
//!
//! A record file `NNNN.json` is one JSON object `{"format":1,"n":N,"head":"<sha256>",
//! "record":{"<kind>":{…}}}` exactly as `serde_json::to_vec` writes it: the reader parses with
//! `deny_unknown_fields`, checks `format` first (another value is [`Damage::Format`], not
//! "unparsable") and accepts the bytes only if serialising the parsed record gives the same
//! bytes, so every accepted file has exactly one form. No `flatten` (it does not work with
//! `deny_unknown_fields`).

use serde::{Deserialize, Serialize};

use super::Damage;
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

/// The backup an intent names: `op-NNNN.bin` of its op, with hash and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRef {
    /// SHA-256 of the backup (the guard's hash of the old file).
    #[serde(with = "crate::wire::hex32")]
    pub sha256: [u8; 32],
    /// Length in bytes.
    pub len: u64,
}

/// One record (ADR 0019 amendment). `op` is the index of the op in the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Record {
    /// Before op `op` changes anything: its temp name and its backup.
    Intent {
        /// Op index.
        op: u16,
        /// Temp name the change uses next to its target.
        tmp: Option<TmpName>,
        /// Backup of the old content.
        backup: Option<BackupRef>,
    },
    /// Op `op` is done.
    Done {
        /// Op index.
        op: u16,
        /// File ID of what the op created.
        #[serde(with = "crate::wire::hex128")]
        file_id: u128,
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
    },
    /// The revert of op `op` is done.
    RevertDone {
        /// Op index.
        op: u16,
        /// What the revert observed before it acted.
        observed: Observed,
        /// `<tmp>.old` was left behind.
        old_left: bool,
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
    use super::{BackupRef, Closing, Observed, Record, decode, encode};
    use crate::journal::Damage;
    use crate::sys::fs::TmpName;

    pub(crate) fn every_kind() -> Vec<Record> {
        vec![
            Record::Intent {
                op: 0,
                tmp: Some(TmpName::new(0xab, 1)),
                backup: Some(BackupRef {
                    sha256: [7; 32],
                    len: 3,
                }),
            },
            Record::Intent {
                op: 1,
                tmp: None,
                backup: None,
            },
            Record::Done {
                op: 0,
                file_id: u128::MAX,
                old_left: true,
            },
            Record::Applied { ops: 2 },
            Record::RevertIntent {
                op: 1,
                tmp: Some(TmpName::new(0xab, 2)),
            },
            Record::RevertDone {
                op: 1,
                observed: Observed::Foreign,
                old_left: false,
            },
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
                    backup: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        for bad in [
            intent.replace(".rerun-00000000000000ab-1.tmp", r"..\\x"),
            intent.replace(".rerun-00000000000000ab-1.tmp", ".rerun-ab-1.tmp"),
            intent.replace(r#","backup":null"#, ""),
        ] {
            assert_eq!(
                decode(bad.as_bytes(), 1, &head),
                Err(Damage::Unparsable { n: 1 }),
                "{bad}"
            );
        }
    }
}
