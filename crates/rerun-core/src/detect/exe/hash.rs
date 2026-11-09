//! Streaming SHA-1 and SHA-256 over a reader (ADR 0014, "Hashes"). Only with `--hashes`.
//!
//! One buffer of [`HashLimits::chunk_bytes`] (clamped to 1 byte ..= [`MAX_CHUNK_BYTES`]); each
//! chunk is fed to both hashes in one pass.
//! The length is the number of bytes read, never asked from metadata. A read past the cap
//! stops after at most the cap plus one chunk. `Interrupted` is retried as in the parser.
//! SHA-1 is an identity hint for Topo and package matching, never authorization (the
//! elevated helper and `laa_patch` check SHA-256 only).

use std::fmt;
use std::io::{ErrorKind, Read, Seek, SeekFrom};

use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::ExeError;

/// `Interrupted` from the reader is retried this many times per read, then reported (as in
/// the PE parser).
const MAX_INTERRUPTS: u32 = 16;

/// The largest read buffer [`stream`] allocates, whatever [`HashLimits::chunk_bytes`] says.
pub const MAX_CHUNK_BYTES: usize = 16 << 20;

/// Bounds of the hashing. A value of exactly the limit is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HashLimits {
    /// Bytes per file.
    pub max_file_bytes: u64,
    /// Files per game (`scan_game` only).
    pub max_files: usize,
    /// Bytes per game (`scan_game` only).
    pub max_game_bytes: u64,
    /// Size of the one read buffer, clamped to 1 byte ..= [`MAX_CHUNK_BYTES`] (also the
    /// overshoot past a cap: at most one chunk).
    pub chunk_bytes: usize,
}

impl HashLimits {
    /// The shipped limits (ADR 0014, user decision 4).
    pub const DEFAULT: Self = Self {
        max_file_bytes: 2 << 30,
        max_files: 8,
        max_game_bytes: 4 << 30,
        chunk_bytes: 256 << 10,
    };
}

/// The hashes of one file, in uppercase hex (the Topo format).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hashes {
    /// Bytes read (the whole file).
    pub len: u64,
    /// SHA-1, 40 hex digits.
    pub sha1: String,
    /// SHA-256, 64 hex digits.
    pub sha256: String,
}

/// Why a file was not hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashSkip {
    /// Not a `Game` candidate.
    NotGame,
    /// [`HashLimits::max_files`] files were already hashed for this game.
    TooManyFiles {
        /// The limit.
        max: usize,
    },
    /// The file does not fit what is left of [`HashLimits::max_game_bytes`].
    GameBudget {
        /// The limit.
        max: u64,
    },
    /// The file is larger than [`HashLimits::max_file_bytes`].
    TooLarge {
        /// The limit.
        max: u64,
    },
}

impl fmt::Display for HashSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotGame => f.write_str("not a game executable"),
            Self::TooManyFiles { max } => write!(f, "{max} files already hashed for this game"),
            Self::GameBudget { max } => write!(f, "over the {max} bytes hashed per game"),
            Self::TooLarge { max } => write!(f, "larger than {max} bytes"),
        }
    }
}

/// Why hashing failed. Never carries file content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HashError {
    /// Reading failed (only the kind of the I/O error is kept, not its message).
    #[error("read failed while hashing ({0})")]
    Io(ErrorKind),
    /// The file was replaced between the first inspection and the one that hashed it; the
    /// hash would not belong to the facts shown.
    #[error("the file changed while it was scanned; not hashed")]
    Changed,
    /// The inspection that was to hash the file failed (it was removed or replaced by
    /// something unreadable after the first one).
    #[error("{0}")]
    Inspect(Box<ExeError>),
}

/// The hashes of a parsed executable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashOutcome {
    /// Not asked for (`--hashes` not given).
    NotRequested,
    /// Hashed.
    Done(Hashes),
    /// Deliberately not hashed.
    Skipped(HashSkip),
    /// Hashing failed.
    Failed(HashError),
}

impl fmt::Display for HashOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRequested => f.write_str("not requested"),
            Self::Done(h) => write!(f, "{} bytes, SHA-1 {}, SHA-256 {}", h.len, h.sha1, h.sha256),
            Self::Skipped(why) => write!(f, "skipped: {why}"),
            Self::Failed(e) => write!(f, "failed: {e}"),
        }
    }
}

/// Why [`stream`] stopped, and how many bytes it had read by then (charged to the game
/// budget by the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// More than the cap.
    TooLarge {
        /// Bytes read, at most the cap plus one chunk.
        read: u64,
    },
    /// Seeking or reading failed.
    Io {
        /// The kind of the I/O error.
        kind: ErrorKind,
        /// Bytes read before it.
        read: u64,
    },
}

/// Hashes `reader` from offset 0 to its end with one buffer of `chunk` bytes (clamped to
/// 1 ..= [`MAX_CHUNK_BYTES`]). More than `cap` bytes is [`Stop::TooLarge`], after reading at
/// most `cap` plus one chunk.
pub(crate) fn stream<R: Read + Seek>(
    mut reader: R,
    cap: u64,
    chunk: usize,
) -> Result<Hashes, Stop> {
    reader.seek(SeekFrom::Start(0)).map_err(|e| Stop::Io {
        kind: e.kind(),
        read: 0,
    })?;
    let mut buf = vec![0u8; chunk.clamp(1, MAX_CHUNK_BYTES)];
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut len: u64 = 0;
    loop {
        let n = read_some(&mut reader, &mut buf).map_err(|kind| Stop::Io { kind, read: len })?;
        let Some(data) = buf.get(..n).filter(|d| !d.is_empty()) else {
            break;
        };
        len = len.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if len > cap {
            return Err(Stop::TooLarge { read: len });
        }
        sha1.update(data);
        sha256.update(data);
    }
    Ok(Hashes {
        len,
        sha1: hex(&sha1.finalize()),
        sha256: hex(&sha256.finalize()),
    })
}

/// One read into `buf`, `Interrupted` retried; a reader that claims more than the buffer is
/// clamped, never trusted.
fn read_some<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, ErrorKind> {
    let mut interrupts = 0;
    loop {
        match reader.read(buf) {
            Ok(n) => return Ok(n.min(buf.len())),
            Err(e) if e.kind() == ErrorKind::Interrupted && interrupts < MAX_INTERRUPTS => {
                interrupts += 1;
            }
            Err(e) => return Err(e.kind()),
        }
    }
}

/// Uppercase hex.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0F)]));
    }
    s
}

#[cfg(test)]
mod tests;
