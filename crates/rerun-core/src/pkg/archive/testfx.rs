//! Test archives (tests and feature `fake` only), written byte by byte so every field can be set
//! wrong on purpose. Deflate is `miniz_oxide`'s own compressor (the same crate as the reader's
//! inflate).

use super::crc32::Crc32;

fn u16le(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn u32le(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn len16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Raw DEFLATE of `data`.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, 6)
}

/// How a zip entry's sizes and CRC are given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Descriptor {
    /// In the local header.
    None,
    /// In a data descriptor with its signature (local header fields 0).
    WithSig,
    /// In a data descriptor without a signature.
    NoSig,
}

/// One zip entry to write.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub deflate: bool,
    pub flags: u16,
    pub descriptor: Descriptor,
    pub made_by: u16,
    pub attrs: u32,
    pub extra: Vec<u8>,
    /// The CRC-32 written (central, local, descriptor); `None`: the right one.
    pub crc: Option<u32>,
    /// The uncompressed size written; `None`: the right one.
    pub size: Option<u32>,
    /// Another CRC-32 in the data descriptor only.
    pub descriptor_crc: Option<u32>,
}

impl ZipEntry {
    /// A deflated file.
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            data: data.to_vec(),
            deflate: true,
            flags: 0,
            descriptor: Descriptor::None,
            made_by: 20,
            attrs: 0,
            extra: Vec::new(),
            crc: None,
            size: None,
            descriptor_crc: None,
        }
    }

    /// A stored file.
    pub fn stored(name: &str, data: &[u8]) -> Self {
        Self {
            deflate: false,
            ..Self::file(name, data)
        }
    }

    /// A folder (`name` ends in `/`).
    pub fn dir(name: &str) -> Self {
        Self::stored(name, b"")
    }
}

/// Where the parts of a written zip are.
#[derive(Debug, Clone)]
pub struct ZipLayout {
    pub bytes: Vec<u8>,
    pub locals: Vec<usize>,
    pub centrals: Vec<usize>,
    pub eocd: usize,
}

/// A zip of `entries` with `comment`; the central directory points at the local headers.
pub fn zip_layout(entries: &[ZipEntry], comment: &[u8]) -> ZipLayout {
    let mut b = Vec::new();
    let mut locals = Vec::new();
    let mut meta = Vec::new();
    for e in entries {
        let body = if e.deflate {
            deflate(&e.data)
        } else {
            e.data.clone()
        };
        let crc = e.crc.unwrap_or_else(|| Crc32::of(&e.data));
        let usize_ = e.size.unwrap_or_else(|| len32(e.data.len()));
        let csize = len32(body.len());
        let method: u16 = if e.deflate { 8 } else { 0 };
        let mut flags = e.flags;
        if e.descriptor != Descriptor::None {
            flags |= 0x0008;
        }
        locals.push(b.len());
        u32le(&mut b, 0x0403_4B50);
        u16le(&mut b, 20);
        u16le(&mut b, flags);
        u16le(&mut b, method);
        u32le(&mut b, 0); // time, date
        let (lc, ls, lu) = if e.descriptor == Descriptor::None {
            (crc, csize, usize_)
        } else {
            (0, 0, 0)
        };
        u32le(&mut b, lc);
        u32le(&mut b, ls);
        u32le(&mut b, lu);
        u16le(&mut b, len16(e.name.len()));
        u16le(&mut b, len16(e.extra.len()));
        b.extend_from_slice(&e.name);
        b.extend_from_slice(&e.extra);
        b.extend_from_slice(&body);
        let dcrc = e.descriptor_crc.unwrap_or(crc);
        match e.descriptor {
            Descriptor::None => {}
            Descriptor::WithSig => {
                u32le(&mut b, 0x0807_4B50);
                u32le(&mut b, dcrc);
                u32le(&mut b, csize);
                u32le(&mut b, usize_);
            }
            Descriptor::NoSig => {
                u32le(&mut b, dcrc);
                u32le(&mut b, csize);
                u32le(&mut b, usize_);
            }
        }
        meta.push((flags, method, crc, csize, usize_));
    }
    let cd = b.len();
    let mut centrals = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let (flags, method, crc, csize, usize_) = meta[i];
        centrals.push(b.len());
        u32le(&mut b, 0x0201_4B50);
        u16le(&mut b, e.made_by);
        u16le(&mut b, 20);
        u16le(&mut b, flags);
        u16le(&mut b, method);
        u32le(&mut b, 0);
        u32le(&mut b, crc);
        u32le(&mut b, csize);
        u32le(&mut b, usize_);
        u16le(&mut b, len16(e.name.len()));
        u16le(&mut b, len16(e.extra.len()));
        u16le(&mut b, 0); // comment
        u16le(&mut b, 0); // disk
        u16le(&mut b, 0); // internal attributes
        u32le(&mut b, e.attrs);
        u32le(&mut b, len32(locals[i]));
        b.extend_from_slice(&e.name);
        b.extend_from_slice(&e.extra);
    }
    let cd_size = b.len() - cd;
    let eocd = b.len();
    u32le(&mut b, 0x0605_4B50);
    u16le(&mut b, 0);
    u16le(&mut b, 0);
    u16le(&mut b, len16(entries.len()));
    u16le(&mut b, len16(entries.len()));
    u32le(&mut b, len32(cd_size));
    u32le(&mut b, len32(cd));
    u16le(&mut b, len16(comment.len()));
    b.extend_from_slice(comment);
    ZipLayout {
        bytes: b,
        locals,
        centrals,
        eocd,
    }
}

/// A zip of `entries`.
pub fn zip(entries: &[ZipEntry]) -> Vec<u8> {
    zip_layout(entries, b"").bytes
}

/// Writes `v` little-endian at `at`.
pub fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

/// Writes `v` little-endian at `at`.
pub fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// One tar entry to write.
#[derive(Debug, Clone)]
pub struct TarEntry {
    pub name: Vec<u8>,
    pub prefix: Vec<u8>,
    pub kind: u8,
    pub data: Vec<u8>,
    pub gnu: bool,
    /// Another checksum than the right one.
    pub checksum: Option<u64>,
    /// Another size field than the data's.
    pub size: Option<u64>,
}

impl TarEntry {
    /// A file in GNU format (as DXVK's release is written).
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            prefix: Vec::new(),
            kind: b'0',
            data: data.to_vec(),
            gnu: true,
            checksum: None,
            size: None,
        }
    }

    /// A folder (`name` ends in `/`).
    pub fn dir(name: &str) -> Self {
        Self {
            kind: b'5',
            ..Self::file(name, b"")
        }
    }

    /// An entry of type `kind` without content.
    pub fn typed(name: &str, kind: u8) -> Self {
        Self {
            kind,
            ..Self::file(name, b"")
        }
    }
}

fn octal_field(f: &mut [u8], v: u64) {
    let s = format!("{v:0width$o}\0", width = f.len() - 1);
    f.copy_from_slice(s.as_bytes());
}

/// One tar header block.
pub fn tar_header(e: &TarEntry) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..e.name.len()].copy_from_slice(&e.name);
    octal_field(&mut h[100..108], 0o644);
    octal_field(&mut h[108..116], 0);
    octal_field(&mut h[116..124], 0);
    octal_field(&mut h[124..136], e.size.unwrap_or(e.data.len() as u64));
    octal_field(&mut h[136..148], 0);
    h[156] = e.kind;
    if e.gnu {
        h[257..265].copy_from_slice(b"ustar  \0");
    } else {
        h[257..265].copy_from_slice(b"ustar\x0000");
        h[345..345 + e.prefix.len()].copy_from_slice(&e.prefix);
    }
    let mut sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    sum += 8 * u64::from(b' ');
    let s = format!("{:06o}\0 ", e.checksum.unwrap_or(sum));
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

/// A tar of `entries` with two zero blocks at the end, padded to 10,240 bytes like GNU tar.
pub fn tar(entries: &[TarEntry]) -> Vec<u8> {
    let mut b = Vec::new();
    for e in entries {
        b.extend_from_slice(&tar_header(e));
        b.extend_from_slice(&e.data);
        b.resize(b.len().div_ceil(512) * 512, 0);
    }
    b.extend_from_slice(&[0u8; 1024]);
    b.resize(b.len().div_ceil(10240) * 10240, 0);
    b
}

/// One gzip member of `data`.
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut b = vec![0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0xFF];
    b.extend_from_slice(&deflate(data));
    u32le(&mut b, Crc32::of(data));
    u32le(&mut b, len32(data.len()));
    b
}

/// A tar.gz of `entries`.
pub fn tar_gz(entries: &[TarEntry]) -> Vec<u8> {
    gzip(&tar(entries))
}
