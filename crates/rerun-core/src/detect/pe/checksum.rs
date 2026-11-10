//! The image checksum of the optional header (`CheckSum`), computed as `CheckSumMappedFile` of
//! `imagehlp.dll` computes it (P4-10, `laa_patch`): the one's-complement sum of the file as
//! little-endian 16-bit words (an odd last byte padded with a zero byte), folded to 16 bits,
//! minus the two words of the `CheckSum` field as it is stored in the summed bytes (with the
//! one's-complement borrow), plus the file length. The PE format names the algorithm only by its
//! DLL ("The algorithm for computing the checksum is incorporated into IMAGHELP.DLL"); this is
//! the published reference implementation of the same function (Wine `dlls/imagehlp/modify.c`,
//! `CheckSumMappedFile`), and a Windows-only test compares it with the real
//! `CheckSumMappedFile` on synthetic images (`sys::win::tests`).
//!
//! Streamed: [`PeChecksum::update`] takes the bytes in chunks of any size (a word split across
//! two chunks is joined), so a file of up to 2 GiB is summed without being held in memory.

/// The running sum of [`super::checksum`]'s algorithm over a stream of bytes.
#[derive(Debug, Clone, Default)]
pub struct PeChecksum {
    /// The folded running sum (`Sum` of `CalcCheckSum`, at most 0x1_0000 between words).
    sum: u32,
    /// The first byte of a word whose second byte has not come yet.
    pending: Option<u8>,
    /// Bytes summed so far.
    len: u64,
}

impl PeChecksum {
    /// An empty sum.
    pub fn new() -> Self {
        Self::default()
    }

    fn word(&mut self, w: u16) {
        // `CalcCheckSum`: add, fold when the high word is not zero.
        self.sum = self.sum.wrapping_add(u32::from(w));
        if self.sum >> 16 != 0 {
            self.sum = (self.sum & 0xFFFF) + (self.sum >> 16);
        }
    }

    /// Adds `bytes`, the next bytes of the file.
    pub fn update(&mut self, bytes: &[u8]) {
        self.len = self
            .len
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let mut rest = bytes;
        if let Some(lo) = self.pending.take() {
            match rest.split_first() {
                Some((&hi, tail)) => {
                    self.word(u16::from_le_bytes([lo, hi]));
                    rest = tail;
                }
                None => {
                    self.pending = Some(lo);
                    return;
                }
            }
        }
        let (pairs, tail) = rest.as_chunks::<2>();
        for p in pairs {
            self.word(u16::from_le_bytes(*p));
        }
        self.pending = tail.first().copied();
    }

    /// Bytes summed so far.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// No byte summed yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The checksum of the summed file whose `CheckSum` field held `stored` while it was summed:
    /// `None` when the file is longer than `u32::MAX` bytes (the field and `FileLength` are
    /// 32 bits; Rerun patches at most 2 GiB anyway).
    pub fn finish(mut self, stored: u32) -> Option<u32> {
        let len = u32::try_from(self.len).ok()?;
        // `(FileLength + 1) / 2` words: an odd last byte with a zero byte after it.
        if let Some(lo) = self.pending.take() {
            self.word(u16::from_le_bytes([lo, 0]));
        }
        // The `WORD` that `CalcCheckSum` returns.
        let mut calc = ((self.sum & 0xFFFF) + (self.sum >> 16)) & 0xFFFF;
        // Subtract the stored field, low word, then high word, with the one's-complement
        // borrow (`modify.c`: `if (LOWORD(CalcSum) >= LOWORD(HdrSum)) … else … - 1`).
        for part in [stored & 0xFFFF, stored >> 16] {
            let low = calc & 0xFFFF;
            calc = if low >= part {
                calc.wrapping_sub(part)
            } else {
                (low.wrapping_sub(part) & 0xFFFF).wrapping_sub(1)
            };
        }
        Some(calc.wrapping_add(len))
    }
}

/// The checksum of `file` (whole, in memory) whose `CheckSum` field holds `stored`.
pub fn checksum(file: &[u8], stored: u32) -> Option<u32> {
    let mut c = PeChecksum::new();
    c.update(file);
    c.finish(stored)
}

#[cfg(test)]
mod tests {
    use super::{PeChecksum, checksum};

    /// The sum does not depend on how the stream is cut, also with odd chunks.
    #[test]
    fn chunks_do_not_change_the_sum() {
        let data: Vec<u8> = (0..1001u32)
            .map(|i| u8::try_from(i * 7919 % 251).unwrap())
            .collect();
        let whole = checksum(&data, 0x1234_5678).unwrap();
        for cut in [1usize, 2, 3, 7, 64, 999] {
            let mut c = PeChecksum::new();
            for part in data.chunks(cut) {
                c.update(part);
            }
            assert_eq!(c.len(), 1001);
            assert_eq!(c.finish(0x1234_5678), Some(whole), "chunks of {cut}");
        }
    }

    /// Small cases by hand: words summed, the stored field taken out again, the length added.
    #[test]
    fn hand_computed_values() {
        // Two words 0x0201 + 0x0403 = 0x0604, no stored field, plus 4 bytes.
        assert_eq!(checksum(&[1, 2, 3, 4], 0), Some(0x0604 + 4));
        // An odd last byte is padded: 0x0201 + 0x0003.
        assert_eq!(checksum(&[1, 2, 3], 0), Some(0x0204 + 3));
        // The fold: 0xFFFF + 0x0002 = 0x1_0001 → 0x0002.
        assert_eq!(checksum(&[0xFF, 0xFF, 2, 0], 0), Some(0x0002 + 4));
        // A stored field counted in the sum is taken out: the bytes of 0x0000_0201 summed and
        // subtracted again leave only the other word.
        assert_eq!(checksum(&[1, 2, 0, 0, 5, 0], 0x0201), Some(0x0005 + 6));
        // The borrow: a stored low word above the sum.
        assert_eq!(checksum(&[1, 0], 2), Some(0xFFFE + 2));
    }

    #[test]
    fn longer_than_u32_is_none() {
        let mut c = PeChecksum::new();
        c.len = u64::from(u32::MAX) + 1;
        assert_eq!(c.finish(0), None);
    }
}
