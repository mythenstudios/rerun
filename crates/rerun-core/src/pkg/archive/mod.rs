//! Bounded readers for package archives (ADR 0025 part 2, P4-7): `zip` (stored or deflated
//! entries) and `tar.gz` (a ustar or GNU tar in one gzip member). Anything else is refused.
//!
//! An archive is untrusted even after its SHA-256 matched the pin: the pin says *which* bytes,
//! not that they are harmless. The readers therefore follow the style of ADR 0013:
//!
//! - **Whole archive in memory**, at most [`Limits::max_archive_bytes`] (the download limit):
//!   the caller hashes exactly the bytes it hands in, so nothing can change between the hash
//!   and the parse.
//! - **Structure first, then content.** [`Archive::open`] checks every entry of the archive
//!   before anything is extracted: for a zip the end record, the central directory and every
//!   local header (and data descriptor), for a tar.gz the whole gzip member (its CRC and length
//!   included) and every tar header. Only then does [`Archive::extract`] read the content of
//!   the entries the caller asks for, each against its declared size and (zip) CRC-32.
//! - **One name rule** ([`entry_name`]): every entry of the archive, extracted or not, must be
//!   a [`RelPath`] once its separators are `/` (a `\` is refused), so `..`, absolute paths,
//!   drives, UNC paths, alternate data streams, reserved device names and deceptive Unicode
//!   never pass. No two entries share a name (compared like NTFS, case-insensitively), and no
//!   entry lies below a file entry.
//! - **Only files and folders.** Links (tar types `1`/`2`, a zip entry with a Unix link mode),
//!   devices, GNU long names, pax headers, sparse files, encryption, zip64 and archives over
//!   several disks are refused.
//! - **Limits** ([`Limits`]): entries, name length, size per entry, total size, compression
//!   ratio; a value of exactly the limit is accepted. No recursion; every loop is bounded by
//!   the input or a limit.
//!
//! Inflate is `miniz_oxide` (pure Rust, raw DEFLATE only); CRC-32 is [`crc32`].

mod crc32;
mod inflate;
mod tar;
mod zip;

#[cfg(any(test, feature = "fake"))]
pub mod testfx;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read};

use crate::fold::fold;
use crate::path::RelPath;

use inflate::{Inflate, Pull, Stored};

pub(crate) use crc32::Crc32;

/// The archive formats Rerun reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A zip archive: stored or deflated entries.
    Zip,
    /// A tar archive in one gzip member.
    TarGz,
}

impl Format {
    /// The format named by a download's file name (the last segment of its URL path): `.zip`,
    /// `.tar.gz` or `.tgz`, ASCII case ignored. Anything else is `None` (refused).
    pub fn of_file_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        if lower.len() > 4 && lower.ends_with(".zip") {
            Some(Self::Zip)
        } else if (lower.len() > 7 && lower.ends_with(".tar.gz"))
            || (lower.len() > 4 && lower.ends_with(".tgz"))
        {
            Some(Self::TarGz)
        } else {
            None
        }
    }
}

/// The bounds of one archive (ADR 0025 part 2). Tests pass smaller ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most bytes of the archive itself.
    pub max_archive_bytes: u64,
    /// Most entries (files and folders).
    pub max_entries: usize,
    /// Most bytes of one entry name as stored.
    pub max_name_bytes: usize,
    /// Most bytes of one entry, decompressed.
    pub max_entry_bytes: u64,
    /// Most bytes of all entries together, decompressed (for a tar.gz: the whole tar stream).
    pub max_total_bytes: u64,
    /// Most decompressed bytes per compressed byte, for anything above [`Self::ratio_floor`]
    /// (a zip entry, or the whole tar stream).
    pub max_ratio: u64,
    /// Sizes up to this are never refused for their ratio (a small file of zeros compresses to
    /// almost nothing, and is harmless).
    pub ratio_floor: u64,
}

impl Limits {
    /// The product's limits.
    pub const DEFAULT: Self = Self {
        max_archive_bytes: super::download::MAX_DOWNLOAD_BYTES,
        max_entries: 4096,
        max_name_bytes: 1024,
        max_entry_bytes: 256 * 1024 * 1024,
        max_total_bytes: 512 * 1024 * 1024,
        max_ratio: 100,
        ratio_floor: 1024 * 1024,
    };

    /// `size` decompressed from `compressed` is within the ratio.
    fn ratio_ok(&self, size: u64, compressed: u64) -> bool {
        size <= self.ratio_floor || size <= compressed.saturating_mul(self.max_ratio)
    }
}

/// Why an archive or one of its entries is refused. Entry names are untrusted: they are shown
/// only through `escape::path`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ArchiveError {
    /// Not an archive of the expected format.
    #[error("not a {0} archive")]
    NotFormat(&'static str),
    /// A structure ends before it is complete.
    #[error("the archive is truncated ({0})")]
    Truncated(&'static str),
    /// A structure that is not what the format says.
    #[error("the archive is damaged ({0})")]
    Corrupt(&'static str),
    /// Data after the end of the archive.
    #[error("the archive has data after its end")]
    Trailing,
    /// A feature Rerun does not read.
    #[error("the archive uses {0}, which Rerun does not read")]
    Unsupported(&'static str),
    /// An entry that is neither a file nor a folder.
    #[error("the archive holds {kind} {}, which Rerun never extracts", crate::escape::path(.name))]
    Special {
        /// The entry as stored.
        name: String,
        /// What it is.
        kind: &'static str,
    },
    /// An entry name outside the rules.
    #[error("the archive holds an entry named {} ({why})", crate::escape::path(.name))]
    BadName {
        /// The name as stored (lossy if not text).
        name: String,
        /// Why.
        why: &'static str,
    },
    /// Two entries with one name (also when they differ only in case).
    #[error("the archive holds {} twice (names compare like Windows: case is ignored)", crate::escape::path(.0))]
    Duplicate(String),
    /// An entry below a file entry.
    #[error("the archive holds {} below a file", crate::escape::path(.0))]
    BelowFile(String),
    /// Over a limit.
    #[error("the archive is over a limit: {0}")]
    TooLarge(&'static str),
    /// Two zip entries share bytes (an overlapping archive, a zip bomb form).
    #[error("the archive's entries overlap")]
    Overlap,
    /// An entry or stream whose CRC-32 is not the stored one.
    #[error("{} does not have its stored CRC-32", crate::escape::path(.0))]
    Crc(String),
    /// An entry that decompresses to another size than it declares.
    #[error("{} does not have its declared size", crate::escape::path(.0))]
    Size(String),
    /// The archive has no entry of that name (exactly, case included).
    #[error("the archive has no file {}{}", crate::escape::path(.name), if *.other_case { " (only in another case; names must match exactly)" } else { "" })]
    NotFound {
        /// The asked name.
        name: String,
        /// An entry differs only in case.
        other_case: bool,
    },
    /// The entry asked for is a folder.
    #[error("{} is a folder in the archive, not a file", crate::escape::path(.0))]
    Folder(String),
    /// A bug: an invariant of the reader broke.
    #[error("internal error of the archive reader")]
    Internal,
}

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A file.
    File,
    /// A folder.
    Dir,
}

/// Where an entry's content is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Loc {
    /// A zip entry's compressed bytes `[start, start + len)`.
    Zip {
        start: usize,
        len: usize,
        deflated: bool,
        crc: u32,
    },
    /// The offset of a tar entry's content in the decompressed tar stream.
    Tar { offset: u64 },
}

/// One entry of an archive, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its name (a valid [`RelPath`]; separators `\`).
    pub name: RelPath,
    /// File or folder.
    pub kind: EntryKind,
    /// Its size in bytes, decompressed (0 for a folder).
    pub size: u64,
    loc: Loc,
}

/// A checked archive over its bytes ([`Archive::open`]).
pub struct Archive<'a> {
    bytes: &'a [u8],
    format: Format,
    limits: Limits,
    entries: Vec<Entry>,
}

impl fmt::Debug for Archive<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Archive")
            .field("format", &self.format)
            .field("len", &self.bytes.len())
            .field("entries", &self.entries.len())
            .finish()
    }
}

/// A raw entry as a reader found it, before the name rule.
pub(super) struct RawEntry {
    pub(super) name: String,
    pub(super) dir: bool,
    pub(super) size: u64,
    pub(super) loc: Loc,
}

/// The name rule (module docs): `raw` as stored, `/`-separated. A folder may end in one `/`;
/// for a tar, one leading `./` is dropped, and the entry `./` itself is `None` (skipped).
pub(super) fn entry_name(raw: &str, dir: bool, tar: bool) -> Result<Option<RelPath>, ArchiveError> {
    let bad = |why: &'static str| ArchiveError::BadName {
        name: raw.to_owned(),
        why,
    };
    let mut s = raw;
    if tar {
        if let Some(rest) = s.strip_prefix("./") {
            s = rest;
        }
        if s.is_empty() && dir {
            return Ok(None);
        }
    }
    if dir {
        s = s.strip_suffix('/').unwrap_or(s);
    } else if s.ends_with('/') {
        return Err(bad("a file name ending in /"));
    }
    if s.contains('\\') {
        return Err(bad("a backslash; archive names separate with /"));
    }
    RelPath::parse(s).map(Some).map_err(|e| bad(e.reason))
}

/// The name rule, duplicates and "below a file" over all raw entries, in archive order.
fn check_entries(raw: Vec<RawEntry>, tar: bool) -> Result<Vec<Entry>, ArchiveError> {
    let mut seen = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        let Some(name) = entry_name(&r.name, r.dir, tar)? else {
            continue;
        };
        let folded = fold(name.as_str());
        if !seen.insert(folded.clone()) {
            return Err(ArchiveError::Duplicate(name.as_str().to_owned()));
        }
        if !r.dir {
            files.insert(folded);
        }
        out.push(Entry {
            name,
            kind: if r.dir {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            size: r.size,
            loc: r.loc,
        });
    }
    for e in &out {
        let mut p = e.name.parent();
        while let Some(a) = p {
            if files.contains(&fold(a.as_str())) {
                return Err(ArchiveError::BelowFile(e.name.as_str().to_owned()));
            }
            p = a.parent();
        }
    }
    Ok(out)
}

impl<'a> Archive<'a> {
    /// Checks the whole structure of `bytes` as `format` (module docs) and lists its entries.
    pub fn open(bytes: &'a [u8], format: Format, limits: &Limits) -> Result<Self, ArchiveError> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limits.max_archive_bytes {
            return Err(ArchiveError::TooLarge("the archive's size"));
        }
        let (raw, tar) = match format {
            Format::Zip => (zip::scan(bytes, limits)?, false),
            Format::TarGz => (tar::scan(bytes, limits)?, true),
        };
        let entries = check_entries(raw, tar)?;
        Ok(Self {
            bytes,
            format,
            limits: *limits,
            entries,
        })
    }

    /// Every entry, in archive order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The index of the file entry named exactly `name` (case included).
    pub fn find(&self, name: &RelPath) -> Result<usize, ArchiveError> {
        if let Some(i) = self.entries.iter().position(|e| e.name.same_spelling(name)) {
            return match self.entries.get(i).map(|e| e.kind) {
                Some(EntryKind::File) => Ok(i),
                _ => Err(ArchiveError::Folder(name.as_str().to_owned())),
            };
        }
        Err(ArchiveError::NotFound {
            name: name.as_str().to_owned(),
            other_case: self.entries.iter().any(|e| e.name == *name),
        })
    }

    /// Reads the content of the entries `wanted` (indices of [`Self::entries`], file entries,
    /// each once) in archive order and hands each to `sink` as an [`EntryReader`] that yields
    /// exactly the entry's bytes and fails once they are not what the archive declares (size,
    /// CRC-32, the end of the compressed stream). `sink` must read its reader to the end; what
    /// it leaves is read here and checked too.
    ///
    /// The first failure ends the extraction: an archive failure (also one the sink saw as an
    /// I/O error from the reader) as [`Extraction::Archive`], else the sink's own.
    pub fn extract<E>(
        &self,
        wanted: &[usize],
        sink: &mut dyn FnMut(&Entry, &mut EntryReader<'_>) -> Result<(), E>,
    ) -> Result<(), Extraction<E>> {
        let mut order: Vec<usize> = wanted.to_vec();
        order.sort_unstable();
        order.dedup();
        let total: u64 = order
            .iter()
            .filter_map(|i| self.entries.get(*i))
            .map(|e| e.size)
            .fold(0u64, u64::saturating_add);
        if total > self.limits.max_total_bytes {
            return Err(Extraction::Archive(ArchiveError::TooLarge(
                "the total size of the files",
            )));
        }
        match self.format {
            Format::Zip => self.extract_zip(&order, sink),
            Format::TarGz => self.extract_tar(&order, sink),
        }
    }

    fn entry(&self, i: usize) -> Result<&Entry, ArchiveError> {
        match self.entries.get(i) {
            Some(e) if e.kind == EntryKind::File => Ok(e),
            Some(e) => Err(ArchiveError::Folder(e.name.as_str().to_owned())),
            None => Err(ArchiveError::Internal),
        }
    }

    fn extract_zip<E>(
        &self,
        order: &[usize],
        sink: &mut dyn FnMut(&Entry, &mut EntryReader<'_>) -> Result<(), E>,
    ) -> Result<(), Extraction<E>> {
        for &i in order {
            let e = self.entry(i)?;
            let Loc::Zip {
                start,
                len,
                deflated,
                crc,
            } = e.loc
            else {
                return Err(ArchiveError::Internal.into());
            };
            let data = self
                .bytes
                .get(start..start.saturating_add(len))
                .ok_or(ArchiveError::Internal)?;
            if deflated {
                let mut src = Inflate::new(data);
                let mut r = EntryReader::new(e, &mut src, Some(crc));
                run(e, &mut r, sink)?;
                // The stream ends exactly at the end of the entry's compressed bytes.
                if !src.ended() || src.consumed() != data.len() {
                    return Err(ArchiveError::Size(e.name.as_str().to_owned()).into());
                }
            } else {
                let mut src = Stored { data };
                let mut r = EntryReader::new(e, &mut src, Some(crc));
                run(e, &mut r, sink)?;
            }
        }
        Ok(())
    }

    fn extract_tar<E>(
        &self,
        order: &[usize],
        sink: &mut dyn FnMut(&Entry, &mut EntryReader<'_>) -> Result<(), E>,
    ) -> Result<(), Extraction<E>> {
        let mut gz = inflate::Gunzip::new(self.bytes, self.limits.max_total_bytes)?;
        for &i in order {
            let e = self.entry(i)?;
            let Loc::Tar { offset } = e.loc else {
                return Err(ArchiveError::Internal.into());
            };
            let at = gz.produced();
            if offset < at {
                return Err(ArchiveError::Internal.into());
            }
            inflate::skip(&mut gz, offset - at, "a tar entry")?;
            let mut r = EntryReader::new(e, &mut gz, None);
            run(e, &mut r, sink)?;
        }
        Ok(())
    }
}

/// Hands `r` to `sink`, then reads what it left and reports the first failure.
fn run<E>(
    e: &Entry,
    r: &mut EntryReader<'_>,
    sink: &mut dyn FnMut(&Entry, &mut EntryReader<'_>) -> Result<(), E>,
) -> Result<(), Extraction<E>> {
    let res = sink(e, r);
    if let Some(a) = r.failed.take() {
        return Err(Extraction::Archive(a));
    }
    res.map_err(Extraction::Sink)?;
    r.finish().map_err(Extraction::Archive)
}

/// Why [`Archive::extract`] stopped.
#[derive(Debug)]
pub enum Extraction<E> {
    /// The archive.
    Archive(ArchiveError),
    /// The sink.
    Sink(E),
}

impl<E> From<ArchiveError> for Extraction<E> {
    fn from(e: ArchiveError) -> Self {
        Self::Archive(e)
    }
}

/// The content of one entry: exactly its declared size, checked against its CRC-32 (zip) at
/// the end. A failure is an I/O error for the reader's user and is kept for
/// [`Archive::extract`], which reports it as what it was.
pub struct EntryReader<'s> {
    src: &'s mut dyn Pull,
    name: String,
    remaining: u64,
    crc: Crc32,
    expect_crc: Option<u32>,
    failed: Option<ArchiveError>,
    done: bool,
}

impl fmt::Debug for EntryReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryReader")
            .field("remaining", &self.remaining)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<'s> EntryReader<'s> {
    fn new(e: &Entry, src: &'s mut dyn Pull, expect_crc: Option<u32>) -> Self {
        Self {
            src,
            name: e.name.as_str().to_owned(),
            remaining: e.size,
            crc: Crc32::new(),
            expect_crc,
            failed: None,
            done: false,
        }
    }

    fn stop(&mut self, why: ArchiveError) -> io::Error {
        self.failed = Some(why);
        io::Error::other("archive entry refused")
    }

    /// The checks at the end of the entry: nothing more comes, the CRC-32.
    fn end(&mut self) -> Result<(), ArchiveError> {
        if self.done {
            return Ok(());
        }
        if let Some(want) = self.expect_crc {
            // A deflated entry must not yield more than declared.
            let mut probe = [0u8; 1];
            if self.src.pull(&mut probe)? != 0 {
                return Err(ArchiveError::Size(self.name.clone()));
            }
            if self.crc.value() != want {
                return Err(ArchiveError::Crc(self.name.clone()));
            }
        }
        self.done = true;
        Ok(())
    }

    /// Reads what the user left and runs the end checks.
    fn finish(&mut self) -> Result<(), ArchiveError> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match self.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(self.failed.take().unwrap_or(ArchiveError::Internal)),
            }
        }
    }
}

impl Read for EntryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.failed.is_some() {
            return Err(io::Error::other("archive entry refused"));
        }
        if self.remaining == 0 {
            return match self.end() {
                Ok(()) => Ok(0),
                Err(e) => Err(self.stop(e)),
            };
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let Some(out) = buf.get_mut(..want) else {
            return Err(self.stop(ArchiveError::Internal));
        };
        let n = match self.src.pull(out) {
            Ok(0) => return Err(self.stop(ArchiveError::Size(self.name.clone()))),
            Ok(n) => n,
            Err(e) => return Err(self.stop(e)),
        };
        self.crc.update(out.get(..n).unwrap_or_default());
        self.remaining -= u64::try_from(n).unwrap_or(u64::MAX);
        Ok(n)
    }
}
