//! Bounded range reads with a total budget (ADR 0013, "Reading"). Every access is one `seek`
//! and reads into a buffer whose size the caller takes from a limit; the budget is charged with
//! the requested length before anything is read.

use std::io::{ErrorKind, Read, Seek, SeekFrom};

use super::error::{PeError, PeErrorKind};

/// `Interrupted` from the reader is retried this many times per read, then reported.
const MAX_INTERRUPTS: u32 = 16;

/// The reader with its budget.
#[derive(Debug)]
pub(super) struct Source<R> {
    inner: R,
    used: u64,
    budget: u64,
}

impl<R: Read + Seek> Source<R> {
    pub(super) fn new(inner: R, budget: u64) -> Self {
        Self {
            inner,
            used: 0,
            budget,
        }
    }

    /// Bytes charged so far.
    pub(super) fn used(&self) -> u64 {
        self.used
    }

    pub(super) fn into_inner(self) -> R {
        self.inner
    }

    /// Reads up to `len` bytes at `offset`. Shorter only where the file ends.
    pub(super) fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, PeError> {
        let want = u64::try_from(len).unwrap_or(u64::MAX);
        let total = self
            .used
            .checked_add(want)
            .filter(|&t| t <= self.budget)
            .ok_or(PeError::at(PeErrorKind::ReadBudget, offset))?;
        self.used = total;
        let io = |e: std::io::Error| PeError::at(PeErrorKind::Io(e.kind()), offset);
        self.inner.seek(SeekFrom::Start(offset)).map_err(io)?;
        let mut buf = vec![0u8; len];
        let mut filled = 0;
        let mut interrupts = 0;
        while let Some(rest) = buf.get_mut(filled..).filter(|r| !r.is_empty()) {
            let room = rest.len();
            match self.inner.read(rest) {
                Ok(0) => break,
                // A reader that claims more than the buffer is clamped, never trusted.
                Ok(n) => filled += n.min(room),
                Err(e) if e.kind() == ErrorKind::Interrupted && interrupts < MAX_INTERRUPTS => {
                    interrupts += 1;
                }
                Err(e) => return Err(io(e)),
            }
        }
        buf.truncate(filled);
        Ok(buf)
    }
}

/// Little-endian `u16` at `at`, `None` outside `b`.
pub(super) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([*s.first()?, *s.get(1)?]))
}

/// Little-endian `u32` at `at`, `None` outside `b`.
pub(super) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(s))
}

/// Little-endian `u64` at `at`, `None` outside `b`.
pub(super) fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    let s: [u8; 8] = b.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(s))
}

/// `usize` offset as a file offset.
pub(super) fn off(at: usize) -> u64 {
    u64::try_from(at).unwrap_or(u64::MAX)
}
