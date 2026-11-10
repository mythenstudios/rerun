//! The image checksum of `detect::pe::checksum` against the real `CheckSumMappedFile` of
//! `imagehlp.dll` (P4-10, `laa_patch`): synthetic images (`detect::pe::testfx`) in memory, odd
//! and even lengths, stored checksums of every kind, and each image again with Large Address
//! Aware set and its new checksum written, which Windows must then compute as stored. Reads
//! memory only; nothing is written anywhere.

#![allow(
    unsafe_code,
    reason = "FFI to CheckSumMappedFile on a buffer of this test; every block has a SAFETY comment"
)]

use windows_sys::Win32::System::Diagnostics::Debug::CheckSumMappedFile;

use crate::detect::pe::checksum::checksum;
use crate::detect::pe::layout as l;
use crate::detect::pe::testfx::{Builder, put32};

/// `(stored, computed)` as `CheckSumMappedFile` reports them for `image`; `None` if it fails.
pub(super) fn windows_of(image: &[u8]) -> Option<(u32, u32)> {
    let len = u32::try_from(image.len()).ok()?;
    // One spare zero byte: for an odd length the function reads the second byte of the last
    // word past the end (it sums `(len + 1) / 2` words, as a mapped view allows).
    let mut buf = image.to_vec();
    buf.push(0);
    let (mut stored, mut computed) = (0u32, 0u32);
    // SAFETY: `buf` holds `len + 1` initialised bytes and lives for the whole call, so the
    // `(len + 1) / 2` words CheckSumMappedFile reads from its base lie inside it; it only reads
    // that memory. The two out pointers are valid, aligned locals that outlive the call. The
    // returned header pointer is only compared with null.
    let headers =
        unsafe { CheckSumMappedFile(buf.as_ptr().cast(), len, &raw mut stored, &raw mut computed) };
    (!headers.is_null()).then_some((stored, computed))
}

fn images() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for x86 in [true, false] {
        for stored in [0u32, 1, 0xFFFF, 0x0001_0000, 0x1234_5678, 0xFFFF_FFFF] {
            for data in [0usize, 1, 2, 0x1FF, 0x2001] {
                let mut b = if x86 { Builder::x86() } else { Builder::x64() };
                b.checksum = stored;
                b.data = (0..data)
                    .map(|i| u8::try_from(i * 131 % 256).unwrap())
                    .collect();
                let mut img = b.build().bytes;
                // Odd lengths too: a trailing byte (overlay data after the sections).
                if data % 2 == 1 {
                    img.push(0xA5);
                }
                out.push(img);
            }
        }
    }
    out
}

#[test]
fn the_checksum_is_the_one_of_checksummappedfile() {
    for img in images() {
        let at = {
            let e = usize::try_from(u32::from_le_bytes(
                img[l::DOS_E_LFANEW..l::DOS_E_LFANEW + 4]
                    .try_into()
                    .unwrap(),
            ))
            .unwrap();
            e + 4 + l::FILE_HEADER_SIZE + l::OPT_CHECKSUM
        };
        let stored = u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
        let (w_stored, w_computed) = windows_of(&img).expect("CheckSumMappedFile");
        assert_eq!(w_stored, stored);
        assert_eq!(
            checksum(&img, stored),
            Some(w_computed),
            "len {}",
            img.len()
        );
        // Written back, Windows computes exactly what is stored.
        let mut fixed = img.clone();
        put32(&mut fixed, at, w_computed);
        let (s, c) = windows_of(&fixed).expect("CheckSumMappedFile");
        assert_eq!((s, c), (w_computed, w_computed), "len {}", img.len());
        assert_eq!(checksum(&fixed, w_computed), Some(w_computed));
    }
}
