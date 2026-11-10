//! CRC-32 (ISO-HDLC, polynomial `0xEDB88320` reflected): the check value of zip entries and of
//! gzip members. A table computed at compile time; no dependency.

#[expect(clippy::cast_possible_truncation, reason = "i < 256 fits a u32")]
const fn table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static TABLE: [u32; 256] = table();

/// A running CRC-32.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Crc32(u32);

impl Crc32 {
    pub(crate) const fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut c = self.0;
        for &b in data {
            let low = (c ^ u32::from(b)).to_le_bytes()[0];
            c = TABLE[usize::from(low)] ^ (c >> 8);
        }
        self.0 = c;
    }

    pub(crate) const fn value(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }

    /// The CRC-32 of `data`.
    pub(crate) fn of(data: &[u8]) -> u32 {
        let mut c = Self::new();
        c.update(data);
        c.value()
    }
}

#[cfg(test)]
mod tests {
    use super::Crc32;

    #[test]
    fn check_values() {
        // The standard check value of CRC-32/ISO-HDLC.
        assert_eq!(Crc32::of(b"123456789"), 0xCBF4_3926);
        assert_eq!(Crc32::of(b""), 0);
        let mut c = Crc32::new();
        c.update(b"1234");
        c.update(b"56789");
        assert_eq!(c.value(), 0xCBF4_3926);
    }
}
