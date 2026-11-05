//! Streaming SHA-1/SHA-256 (ADR 0014, "Hashes") over readers that are not a file system.

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::{HashLimits, HashSkip, Hashes, Stop, hex, stream};

const EMPTY_SHA1: &str = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
const EMPTY_SHA256: &str = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
const ABC_SHA1: &str = "A9993E364706816ABA3E25717850C26C9CD0D89D";
const ABC_SHA256: &str = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";

fn hash(data: &[u8], chunk: usize) -> Hashes {
    stream(Cursor::new(data.to_vec()), u64::MAX, chunk).unwrap()
}

/// 1 MiB plus 3 bytes of a pattern that is not periodic in any chunk size used here.
fn pattern() -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..(1 << 20) + 3)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn known_vectors_in_uppercase_hex() {
    let e = hash(b"", 256 << 10);
    assert_eq!(
        (e.len, e.sha1.as_str(), e.sha256.as_str()),
        (0, EMPTY_SHA1, EMPTY_SHA256)
    );
    let a = hash(b"abc", 256 << 10);
    assert_eq!(
        (a.len, a.sha1.as_str(), a.sha256.as_str()),
        (3, ABC_SHA1, ABC_SHA256)
    );
    assert_eq!(hex(&[0x00, 0x0F, 0xA5, 0xFF]), "000FA5FF");
}

#[test]
fn every_chunk_size_gives_the_same_result() {
    let data = pattern();
    let whole = Hashes {
        len: u64::try_from(data.len()).unwrap(),
        sha1: hex(&Sha1::digest(&data)),
        sha256: hex(&Sha256::digest(&data)),
    };
    for chunk in [0, 1, 7, 4096, 65_537, 256 << 10, 4 << 20] {
        assert_eq!(hash(&data, chunk), whole, "chunk {chunk}");
    }
}

/// A reader over `data` that serves at most `per_call` bytes per read, fails with
/// `Interrupted` on every call while `interrupts` is above 0 (counting down), may claim more
/// than it filled, fails with `fail` once its position reaches `fail_at`, and counts what it
/// served.
struct Odd {
    data: Cursor<Vec<u8>>,
    per_call: usize,
    interrupts: u32,
    claim_extra: bool,
    fail_at: Option<(u64, io::ErrorKind)>,
    served: u64,
}

impl Odd {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data: Cursor::new(data),
            per_call: usize::MAX,
            interrupts: 0,
            claim_extra: false,
            fail_at: None,
            served: 0,
        }
    }
}

impl Read for Odd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.interrupts > 0 {
            self.interrupts -= 1;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Some((at, kind)) = self.fail_at
            && self.data.position() >= at
        {
            return Err(io::Error::new(kind, "SECRETMARKER from the device"));
        }
        let want = buf.len().min(self.per_call);
        let n = self.data.read(&mut buf[..want])?;
        self.served += u64::try_from(n).unwrap();
        if self.claim_extra && n > 0 {
            Ok(n + buf.len())
        } else {
            Ok(n)
        }
    }
}

impl Seek for Odd {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        assert!(
            matches!(to, SeekFrom::Start(_)),
            "the length is never asked for"
        );
        self.data.seek(to)
    }
}

#[test]
fn a_trickling_reader_and_a_reader_positioned_elsewhere() {
    let data = pattern();
    let expected = hash(&data, 256 << 10);
    let mut odd = Odd::new(data.clone());
    odd.per_call = 7;
    odd.data.set_position(1000);
    assert_eq!(stream(&mut odd, u64::MAX, 256 << 10).unwrap(), expected);
}

#[test]
fn interrupted_is_retried_sixteen_times() {
    let mut odd = Odd::new(b"abc".to_vec());
    odd.interrupts = 16;
    let h = stream(&mut odd, u64::MAX, 64).unwrap();
    assert_eq!(h.sha1, ABC_SHA1);
    let mut odd = Odd::new(b"abc".to_vec());
    odd.interrupts = 17;
    assert_eq!(
        stream(&mut odd, u64::MAX, 64),
        Err(Stop::Io {
            kind: io::ErrorKind::Interrupted,
            read: 0
        })
    );
}

#[test]
fn a_failing_reader_keeps_only_its_kind() {
    let mut odd = Odd::new(pattern());
    odd.fail_at = Some((4096, io::ErrorKind::InvalidData));
    let r = stream(&mut odd, u64::MAX, 1024);
    // The bytes read before the error are reported (charged to the game budget).
    assert_eq!(
        r,
        Err(Stop::Io {
            kind: io::ErrorKind::InvalidData,
            read: 4096
        })
    );
    assert!(!format!("{r:?}").contains("SECRET"));
}

#[test]
fn a_reader_claiming_more_than_the_buffer_is_clamped() {
    let data = pattern();
    let mut odd = Odd::new(data.clone());
    odd.per_call = 100;
    odd.claim_extra = true;
    // Never a panic; the claimed bytes are clamped to the buffer, so the result is wrong only
    // for this broken reader and its length stays bounded by the reads.
    let h = stream(&mut odd, u64::MAX, 4096).unwrap();
    assert!(h.len >= odd.served);
}

#[test]
fn the_cap_is_exact_and_stops_after_one_more_chunk() {
    let data = pattern();
    let len = u64::try_from(data.len()).unwrap();
    assert_eq!(hash(&data, 4096).len, len);
    let mut odd = Odd::new(data.clone());
    assert_eq!(stream(&mut odd, len, 4096).unwrap().len, len);

    let mut odd = Odd::new(data);
    assert_eq!(
        stream(&mut odd, len - 1, 4096),
        Err(Stop::TooLarge { read: len })
    );
    assert!(odd.served <= len - 1 + 4096, "{}", odd.served);

    // A small cap on a large file reads at most the cap plus one chunk.
    let mut odd = Odd::new(pattern());
    let Err(Stop::TooLarge { read }) = stream(&mut odd, 10_000, 4096) else {
        panic!("expected TooLarge");
    };
    assert_eq!(read, odd.served);
    assert!(odd.served <= 10_000 + 4096, "{}", odd.served);
}

#[test]
fn the_buffer_is_clamped() {
    // A huge chunk size allocates at most `MAX_CHUNK_BYTES`; the overshoot past a cap is at
    // most that much.
    let data = vec![7u8; (super::MAX_CHUNK_BYTES * 2) + 5];
    let mut odd = Odd::new(data);
    let Err(Stop::TooLarge { read }) = stream(&mut odd, 1, usize::MAX) else {
        panic!("expected TooLarge");
    };
    assert_eq!(read, u64::try_from(super::MAX_CHUNK_BYTES).unwrap());
}

#[test]
fn the_shipped_limits_and_messages() {
    let l = HashLimits::DEFAULT;
    assert_eq!(l.max_file_bytes, 2 * 1024 * 1024 * 1024);
    assert_eq!(l.max_files, 8);
    assert_eq!(l.max_game_bytes, 4 * 1024 * 1024 * 1024);
    assert_eq!(l.chunk_bytes, 256 * 1024);
    assert_eq!(HashSkip::NotGame.to_string(), "not a game executable");
    assert_eq!(
        HashSkip::TooManyFiles { max: 8 }.to_string(),
        "8 files already hashed for this game"
    );
    assert_eq!(
        HashSkip::TooLarge { max: 2 }.to_string(),
        "larger than 2 bytes"
    );
}
