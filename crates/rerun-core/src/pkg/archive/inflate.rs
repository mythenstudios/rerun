//! Raw DEFLATE through `miniz_oxide` (pure Rust, `forbid(unsafe_code)`) and the gzip member
//! around it (RFC 1952), both over input that is entirely in memory, so "more input" never
//! exists: a stream that wants more is truncated.

use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

use super::ArchiveError;
use super::crc32::Crc32;

/// Something that yields bytes until it ends (`Ok(0)`), or fails with the archive's reason.
pub(super) trait Pull {
    fn pull(&mut self, out: &mut [u8]) -> Result<usize, ArchiveError>;
}

/// A slice, as is (a stored zip entry).
pub(super) struct Stored<'a> {
    pub(super) data: &'a [u8],
}

impl Pull for Stored<'_> {
    fn pull(&mut self, out: &mut [u8]) -> Result<usize, ArchiveError> {
        let n = out.len().min(self.data.len());
        let (head, tail) = self.data.split_at(n);
        out.get_mut(..n)
            .ok_or(ArchiveError::Internal)?
            .copy_from_slice(head);
        self.data = tail;
        Ok(n)
    }
}

/// One raw DEFLATE stream over `input`. Ends at the stream's final block; [`Self::consumed`]
/// is then exact (`miniz_oxide` gives back the bytes its bit buffer read ahead).
pub(super) struct Inflate<'a> {
    state: Box<InflateState>,
    input: &'a [u8],
    pos: usize,
    ended: bool,
}

impl<'a> Inflate<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self {
            state: InflateState::new_boxed(DataFormat::Raw),
            input,
            pos: 0,
            ended: false,
        }
    }

    /// The stream reached its end.
    pub(super) fn ended(&self) -> bool {
        self.ended
    }

    /// Input bytes the stream used so far.
    pub(super) fn consumed(&self) -> usize {
        self.pos
    }
}

impl Pull for Inflate<'_> {
    fn pull(&mut self, out: &mut [u8]) -> Result<usize, ArchiveError> {
        if self.ended || out.is_empty() {
            return Ok(0);
        }
        loop {
            let rest = self.input.get(self.pos..).ok_or(ArchiveError::Internal)?;
            let r = inflate(&mut self.state, rest, out, MZFlush::None);
            self.pos = self.pos.saturating_add(r.bytes_consumed);
            match r.status {
                Ok(MZStatus::StreamEnd) => {
                    self.ended = true;
                    return Ok(r.bytes_written);
                }
                Ok(_) if r.bytes_written > 0 => return Ok(r.bytes_written),
                // No output, but input used: the decoder read headers; go on.
                Ok(_) if r.bytes_consumed > 0 => {}
                // No progress: everything there was used and the stream wants more.
                Ok(_) | Err(MZError::Buf) if r.bytes_written == 0 => {
                    return Err(ArchiveError::Truncated("a compressed stream"));
                }
                Ok(_) | Err(MZError::Buf) => return Ok(r.bytes_written),
                Err(_) => return Err(ArchiveError::Corrupt("a compressed stream")),
            }
        }
    }
}

/// gzip header flags (RFC 1952 2.3.1).
const FTEXT: u8 = 0x01;
const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;
/// Most bytes of the optional name or comment of a gzip header (each).
const MAX_GZIP_TEXT: usize = 1024;

/// One gzip member over the whole archive: the header checked, the DEFLATE stream counted
/// against `max_out`, and at its end the trailer (CRC-32, length mod 2^32) checked and nothing
/// after it. More than one member, or trailing bytes, are refused.
pub(super) struct Gunzip<'a> {
    inflate: Inflate<'a>,
    body: &'a [u8],
    crc: Crc32,
    out: u64,
    max_out: u64,
    checked: bool,
}

impl<'a> Gunzip<'a> {
    /// Checks the header of `bytes`.
    pub(super) fn new(bytes: &'a [u8], max_out: u64) -> Result<Self, ArchiveError> {
        let not = ArchiveError::NotFormat("tar.gz (gzip)");
        let head = bytes.get(..10).ok_or(not.clone())?;
        if head.get(..3) != Some(&[0x1F, 0x8B, 0x08][..]) {
            return Err(not);
        }
        let flags = head.get(3).copied().unwrap_or(0xFF);
        if flags & !(FTEXT | FHCRC | FEXTRA | FNAME | FCOMMENT) != 0 {
            return Err(ArchiveError::Corrupt("the gzip header flags"));
        }
        let mut pos = 10usize;
        let truncated = ArchiveError::Truncated("the gzip header");
        if flags & FEXTRA != 0 {
            let xlen = bytes.get(pos..pos + 2).ok_or(truncated.clone())?;
            let xlen = usize::from(u16::from_le_bytes([xlen[0], xlen[1]]));
            pos = pos
                .checked_add(2 + xlen)
                .filter(|p| *p <= bytes.len())
                .ok_or(truncated.clone())?;
        }
        for flag in [FNAME, FCOMMENT] {
            if flags & flag != 0 {
                let rest = bytes.get(pos..).ok_or(truncated.clone())?;
                let window = rest
                    .get(..rest.len().min(MAX_GZIP_TEXT + 1))
                    .unwrap_or(rest);
                let nul =
                    window
                        .iter()
                        .position(|b| *b == 0)
                        .ok_or(if rest.len() > MAX_GZIP_TEXT {
                            ArchiveError::Corrupt("the gzip header (name or comment too long)")
                        } else {
                            truncated.clone()
                        })?;
                pos += nul + 1;
            }
        }
        if flags & FHCRC != 0 {
            let want = bytes.get(pos..pos + 2).ok_or(truncated)?;
            let want = u16::from_le_bytes([want[0], want[1]]);
            let have = Crc32::of(bytes.get(..pos).unwrap_or_default()).to_le_bytes();
            if u16::from_le_bytes([have[0], have[1]]) != want {
                return Err(ArchiveError::Corrupt("the gzip header CRC"));
            }
            pos += 2;
        }
        let body = bytes.get(pos..).ok_or(ArchiveError::Internal)?;
        Ok(Self {
            inflate: Inflate::new(body),
            body,
            crc: Crc32::new(),
            out: 0,
            max_out,
            checked: false,
        })
    }

    /// Bytes produced so far.
    pub(super) fn produced(&self) -> u64 {
        self.out
    }

    /// The trailer after the stream's end: CRC-32 and length, then nothing.
    fn check_trailer(&mut self) -> Result<(), ArchiveError> {
        let at = self.inflate.consumed();
        let t = self
            .body
            .get(at..at + 8)
            .ok_or(ArchiveError::Truncated("the gzip trailer"))?;
        let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
        let len = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
        if crc != self.crc.value() {
            return Err(ArchiveError::Crc("the gzip stream".to_owned()));
        }
        if u64::from(len) != self.out & 0xFFFF_FFFF {
            return Err(ArchiveError::Corrupt("the gzip length"));
        }
        if self.body.len() != at + 8 {
            return Err(ArchiveError::Trailing);
        }
        self.checked = true;
        Ok(())
    }
}

impl Pull for Gunzip<'_> {
    fn pull(&mut self, out: &mut [u8]) -> Result<usize, ArchiveError> {
        if out.is_empty() {
            return Ok(0);
        }
        // Never more than one byte past the limit is asked for, so the limit holds exactly.
        let room = self.max_out.saturating_sub(self.out).saturating_add(1);
        let take = out.len().min(usize::try_from(room).unwrap_or(usize::MAX));
        let buf = out.get_mut(..take).ok_or(ArchiveError::Internal)?;
        let n = self.inflate.pull(buf)?;
        self.out = self
            .out
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if self.out > self.max_out {
            return Err(ArchiveError::TooLarge("the decompressed tar stream"));
        }
        self.crc.update(buf.get(..n).unwrap_or_default());
        if n == 0 && self.inflate.ended() && !self.checked {
            self.check_trailer()?;
        }
        Ok(n)
    }
}

/// Reads exactly `out.len()` bytes; `Ok(false)` if the source ended before the first byte,
/// [`ArchiveError::Truncated`] if it ended in between.
pub(super) fn fill(
    src: &mut dyn Pull,
    out: &mut [u8],
    what: &'static str,
) -> Result<bool, ArchiveError> {
    let mut got = 0;
    while got < out.len() {
        let n = src.pull(out.get_mut(got..).ok_or(ArchiveError::Internal)?)?;
        if n == 0 {
            return if got == 0 {
                Ok(false)
            } else {
                Err(ArchiveError::Truncated(what))
            };
        }
        got += n;
    }
    Ok(true)
}

/// Pulls and drops `n` bytes; [`ArchiveError::Truncated`] if the source ends first.
pub(super) fn skip(src: &mut dyn Pull, mut n: u64, what: &'static str) -> Result<(), ArchiveError> {
    let mut buf = vec![0u8; 64 * 1024];
    while n > 0 {
        let want = usize::try_from(n).unwrap_or(usize::MAX).min(buf.len());
        let got = src.pull(buf.get_mut(..want).ok_or(ArchiveError::Internal)?)?;
        if got == 0 {
            return Err(ArchiveError::Truncated(what));
        }
        n -= u64::try_from(got).unwrap_or(u64::MAX);
    }
    Ok(())
}
