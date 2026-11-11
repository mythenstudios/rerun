//! `laa_patch` (P4-10, ADR 0020 amendment P4-10): the Large Address Aware flag
//! (`IMAGE_FILE_LARGE_ADDRESS_AWARE`, bit 5 of `IMAGE_FILE_HEADER::Characteristics`) of a 32-bit
//! game executable, so a 32-bit game may use up to 4 GiB of address space on 64-bit Windows
//! instead of 2 GiB.
//!
//! Only from a Topo (the step file refuses the step): the engine names an executable of the
//! Topo's `match.exes` in exactly its spelling, whose entry has a `sha256` that matched (ADR 0024
//! "sha256 for elevated anchors", P4 condition R6), and passes that hash here. The planner reads
//! only, through the game folder's handle:
//!
//! 1. The game folder can be written by the user (user decision E1 = 0: an admin-only folder is
//!    refused with a hint; the helper does not replace files before phase 6).
//! 2. The executable is a plain file with one link (`file_install::readable_file`), named in the
//!    plan in its stored spelling.
//! 3. Its headers (`detect::pe`, ADR 0013): x86 and PE32, an executable (no DLL), not Large
//!    Address Aware yet, no CLR header (.NET: the runtime decides), no section of a protection
//!    wrapper ([`PROTECTED_SECTIONS`]: SteamStub, SecuROM, SafeDisc, StarForce; changing such an
//!    image breaks its integrity check, and the Topo's curators exclude DRM builds anyway).
//! 4. Streamed twice through the same handle: the SHA-256 (must be the Topo's) and the image
//!    checksum of the patched bytes (`detect::pe::checksum`, as `CheckSumMappedFile`); then the
//!    SHA-256 of the result.
//!
//! The op is one `ReplaceFile` with [`ContentRef::Patch`]: the low byte of `Characteristics`
//! with `0x20` set and, when the stored `CheckSum` is not 0, the bytes of the new checksum that
//! differ (P4-10 question a: Windows checks the checksum of drivers, boot-time DLLs and DLLs of
//! critical processes only, so a game would start either way; a stored one is kept valid, as
//! `editbin` and every tool that rewrites an image do through `CheckSumMappedFile`, so a game or
//! launcher that compares it with `MapFileAndCheckSum` finds it as before; a 0 stays 0). The old
//! R/H/S are kept. An Authenticode signature (a certificate table) becomes invalid: the engine
//! warns ([`inspect`]). Smart App Control decides per file whether the patched executable may
//! run; the engine warns while it is not off and plans the step anyway (ADR 0020 amendment
//! P4-13, which replaced the refusal of P4-10), more strongly for an executable with a Valve
//! header ([`LaaFacts::valve_stub`]). The revert restores the original file bit for bit.

use std::io::{Read, Seek, SeekFrom};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::file_install::readable_file;
use super::{Builder, PlanCtx, folded};
use crate::detect::pe::checksum::PeChecksum;
use crate::detect::pe::layout::{FILE_LARGE_ADDRESS_AWARE, SECTION_NAME_SIZE};
use crate::detect::pe::{self, Machine, PeFormat, open_game_exe};
use crate::path::RelPath;
use crate::plan::{
    ByteEdit, ContentRef, FileState, MAX_FILE_LEN, Op, Patched, PlanError, RootIx, apply_edits,
};
use crate::policy::root::GameDir;
use crate::sys::SysError;

/// The `laa_patch` step as the planner takes it: the executable and the SHA-256 the Topo's
/// `match.exes` entry names for it (the engine fills both from the entry, never from the step's
/// own spelling).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaaPatchSpec {
    /// The executable below the game folder.
    pub exe: RelPath,
    /// Its SHA-256 as the Topo names it.
    #[serde(with = "crate::wire::hex32")]
    pub sha256: [u8; 32],
}

/// Section names of protection wrappers (P4-10): an image with one of them is refused. Compared
/// with the stored 8 bytes cut at the first NUL, ASCII case ignored (fail closed). Sources:
/// SteamStub `.bind`: Steamless by atom0s, `Steamless.Unpacker.Variant31.x86/Main.cs`
/// (`HasSection(".bind")`, <https://github.com/atom0s/Steamless>); SecuROM `.securom`, `.dsstext`,
/// `.cms_t`, `.cms_d`: Detect It Easy `db/PE/protector_SecuROM.2.sg`; SafeDisc `stxt774`,
/// `stxt371`: Detect It Easy `db/PE/protector_SafeDisc.2.sg`; StarForce `.sforce3`: Detect It
/// Easy `db/PE/protector_StarForce.2.sg` (<https://github.com/horsicq/Detect-It-Easy>, MIT).
pub const PROTECTED_SECTIONS: &[(&str, &str)] = &[
    (".bind", "SteamStub"),
    (".securom", "SecuROM"),
    (".dsstext", "SecuROM"),
    (".cms_t", "SecuROM"),
    (".cms_d", "SecuROM"),
    ("stxt774", "SafeDisc"),
    ("stxt371", "SafeDisc"),
    (".sforce3", "StarForce"),
];

/// What the engine shows about an executable before it is patched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaaFacts {
    /// It carries a certificate table (an Authenticode signature), which the patch makes
    /// invalid.
    pub signed: bool,
    /// Its DOS stub carries a Valve header (`ImageFields::valve_stub`, P4-13): likely built per
    /// user by Steam, so a patched copy has a hash Smart App Control has never seen.
    pub valve_stub: bool,
}

fn refuse(exe: &RelPath, why: impl std::fmt::Display) -> PlanError {
    PlanError::Step(format!(
        "laa_patch of {}: {why}",
        crate::escape::path(exe.as_str())
    ))
}

/// The protection wrapper whose section `name` is, if any.
fn protected(name: &[u8; SECTION_NAME_SIZE]) -> Option<(&'static str, &'static str)> {
    let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
    let n = name.get(..end).unwrap_or_default();
    PROTECTED_SECTIONS
        .iter()
        .copied()
        .find(|(s, _)| s.as_bytes().eq_ignore_ascii_case(n))
}

/// The stored spelling of `exe`, segment by segment.
fn stored(game: &GameDir<'_>, exe: &RelPath) -> Result<RelPath, PlanError> {
    let mut at: Option<RelPath> = None;
    for seg in exe.segments() {
        let asked = match &at {
            None => RelPath::from_segment(seg),
            Some(p) => p.child(seg),
        }
        .map_err(|e| refuse(exe, e))?;
        let name = game
            .dir()
            .stored_name(&asked)
            .map_err(|e| refuse(exe, e))?
            .ok_or_else(|| refuse(exe, "it is not in the game folder"))?;
        at = Some(
            match &at {
                None => RelPath::from_segment(&name),
                Some(p) => p.child(&name),
            }
            .map_err(|e| refuse(exe, e))?,
        );
    }
    at.ok_or_else(|| refuse(exe, "an empty path"))
}

/// The header facts of `exe` and why it cannot be patched (step 3 of the module docs).
fn headers<'g>(
    game: &'g GameDir<'_>,
    exe: &RelPath,
) -> Result<(pe::GameExe<'g>, pe::ImageFields, u16), PlanError> {
    let img = open_game_exe(game, exe, &pe::Limits::DEFAULT).map_err(|e| refuse(exe, e))?;
    let h = img.headers().clone();
    if h.machine != Machine::X86 || h.format != PeFormat::Pe32 {
        return Err(refuse(
            exe,
            "it is not a 32-bit (x86) executable; the flag matters for 32-bit games only",
        ));
    }
    if h.is_dll() {
        return Err(refuse(exe, "it is a DLL, not an executable"));
    }
    if h.large_address_aware() {
        return Err(refuse(exe, "it is Large Address Aware already"));
    }
    if h.managed {
        return Err(refuse(
            exe,
            "it is a .NET executable; its address space is the runtime's",
        ));
    }
    let f = img.image_fields();
    if let Some((name, system)) = f.section_names.iter().find_map(protected) {
        return Err(refuse(
            exe,
            format!(
                "it has the section {name} of {system}, a protected build; patching would \
                 break it"
            ),
        ));
    }
    Ok((img, f, h.characteristics))
}

/// The facts the engine warns about (headers only; the planner checks everything again).
pub fn inspect(game: &GameDir<'_>, exe: &RelPath) -> Result<LaaFacts, PlanError> {
    let (_, f, _) = headers(game, exe)?;
    Ok(LaaFacts {
        signed: f.certificates.is_some(),
        valve_stub: f.valve_stub,
    })
}

/// Streams `r` from offset 0 through `edits` into `sink`; the bytes read.
fn stream(
    r: &mut (dyn Read + '_),
    edits: &[ByteEdit],
    exe: &RelPath,
    mut sink: impl FnMut(&[u8]),
) -> Result<u64, PlanError> {
    let mut p = Patched::new(r.take(MAX_FILE_LEN.saturating_add(1)), edits);
    let mut buf = vec![0u8; 256 * 1024];
    let mut len = 0u64;
    loop {
        let n = match p.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(SysError::io(&e, exe.as_str()).into()),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        sink(chunk);
        len = len.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    if len > MAX_FILE_LEN {
        return Err(refuse(exe, "it is larger than 2 GiB"));
    }
    Ok(len)
}

/// Plans `spec` into `b` (module docs).
pub(crate) fn plan_into(
    spec: &LaaPatchSpec,
    ctx: &PlanCtx<'_>,
    b: &mut Builder,
) -> Result<(), PlanError> {
    let exe = &spec.exe;
    // E1 = 0: no file is replaced in a folder only administrators can write (phase 6).
    if !ctx.game.info().user_writable {
        return Err(refuse(
            exe,
            "the game folder can only be changed with administrator rights; patching an \
             executable there is not supported in this version",
        ));
    }
    let key = folded(exe);
    if b.targets.contains(&key) || b.ini_files.contains(&key) {
        return Err(refuse(exe, "another step of the plan changes it too"));
    }
    let game = ctx.game;
    let m = game
        .dir()
        .metadata(exe)
        .map_err(|e| refuse(exe, e))?
        .ok_or_else(|| refuse(exe, "it is not in the game folder"))?;
    readable_file(&m).map_err(|why| refuse(exe, why))?;
    if !m.is_single_link() {
        return Err(refuse(exe, "it is hard-linked (managed by a mod manager)"));
    }
    let path = stored(game, exe)?;
    let (img, fields, characteristics) = headers(game, &path)?;
    let mut r = img.into_inner();
    let low = characteristics.to_le_bytes()[0];
    let flag = ByteEdit {
        offset: fields.characteristics_at,
        old: low,
        new: low | FILE_LARGE_ADDRESS_AWARE.to_le_bytes()[0],
    };

    // Pass 1: the file's SHA-256, and the checksum of its bytes with the flag set (the stored
    // checksum field still in them, as `CheckSumMappedFile` sums an image before it is fixed).
    r.seek(SeekFrom::Start(0)).map_err(|e| refuse(exe, e))?;
    let mut h = Sha256::new();
    let mut sum = PeChecksum::new();
    let mut at = 0u64;
    let mut failed = None;
    let mut patched = Vec::new();
    let len = stream(&mut r, &[], exe, |c| {
        h.update(c);
        patched.clear();
        patched.extend_from_slice(c);
        if let Err(e) = apply_edits(&[flag], at, &mut patched) {
            failed.get_or_insert(e);
        }
        sum.update(&patched);
        at = at.saturating_add(u64::try_from(c.len()).unwrap_or(u64::MAX));
    })?;
    if let Some(e) = failed {
        return Err(refuse(exe, e));
    }
    let old_sha: [u8; 32] = h.finalize().into();
    if old_sha != spec.sha256 {
        return Err(refuse(
            exe,
            "it is not the build the Topo names (its SHA-256 differs); plan again",
        ));
    }
    let mut edits = vec![flag];
    if fields.checksum != 0 {
        let new = sum
            .finish(fields.checksum)
            .ok_or_else(|| refuse(exe, "it is larger than 4 GiB"))?;
        let (old_b, new_b) = (fields.checksum.to_le_bytes(), new.to_le_bytes());
        for (i, (o, n)) in old_b.iter().zip(new_b).enumerate() {
            if *o != n {
                edits.push(ByteEdit {
                    offset: fields.checksum_at + u64::try_from(i).unwrap_or(u64::MAX),
                    old: *o,
                    new: n,
                });
            }
        }
    }
    edits.sort_by_key(|e| e.offset);

    // Pass 2: the SHA-256 of the result.
    r.seek(SeekFrom::Start(0)).map_err(|e| refuse(exe, e))?;
    let mut h = Sha256::new();
    let len2 = stream(&mut r, &edits, exe, |c| h.update(c))?;
    if len2 != len || len != m.len {
        return Err(refuse(exe, "it changed while it was read; plan again"));
    }
    let old = FileState {
        sha256: old_sha,
        len,
        attrs: m.attrs,
    };
    b.targets.push(key);
    b.ops.push(Op::ReplaceFile {
        root: RootIx(0),
        path,
        old,
        content: ContentRef::Patch {
            base: old,
            edits,
            sha256: h.finalize().into(),
        },
        attrs: m.attrs,
    });
    Ok(())
}
