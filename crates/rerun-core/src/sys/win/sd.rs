//! Parser of a self-relative security descriptor (`SECURITY_DESCRIPTOR_RELATIVE`, `winnt.h`)
//! into owner and DACL facts (ADR 0023 §2, A4 N1). Pure: the bytes come from
//! `token::owner_and_dacl`, so no structure is read through a raw pointer, and every offset is
//! bounds-checked. No `unsafe`.
//!
//! Layout (all little-endian): header `Revision` u8, `Sbz1` u8, `Control` u16, `Owner` u32,
//! `Group` u32, `Sacl` u32, `Dacl` u32 (offsets from the start, 0 = absent). ACL: `AclRevision`
//! u8, `Sbz1` u8, `AclSize` u16, `AceCount` u16, `Sbz2` u16, then the ACEs. ACE: `AceType` u8,
//! `AceFlags` u8, `AceSize` u16, `Mask` u32, then (for the plain types) the SID. SID:
//! `Revision` u8, `SubAuthorityCount` u8, `IdentifierAuthority` 6 bytes big-endian, then the
//! sub-authorities as u32.

use crate::sys::fs::{AceFact, ace};

/// `SE_DACL_PRESENT`.
const SE_DACL_PRESENT: u16 = 0x0004;
/// `SE_SELF_RELATIVE`.
const SE_SELF_RELATIVE: u16 = 0x8000;
/// Most sub-authorities a SID may have (`SID_MAX_SUB_AUTHORITIES`).
const MAX_SUB: usize = 15;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The SID at `at` of `b` in its string form; `None` if it does not fit or is malformed.
pub(super) fn sid_at(b: &[u8], at: usize) -> Option<String> {
    let rev = *b.get(at)?;
    let count = usize::from(*b.get(at.checked_add(1)?)?);
    if rev != 1 || count > MAX_SUB {
        return None;
    }
    let auth = b.get(at.checked_add(2)?..at.checked_add(8)?)?;
    let authority = auth.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let mut s = if authority >> 32 == 0 {
        format!("S-1-{authority}")
    } else {
        format!("S-1-0x{authority:012X}")
    };
    for i in 0..count {
        let sub = u32_at(b, at.checked_add(8)?.checked_add(4 * i)?)?;
        s.push_str(&format!("-{sub}"));
    }
    Some(s)
}

/// The ACE types whose SID follows the mask directly.
fn plain_layout(t: u8) -> bool {
    matches!(
        t,
        ace::ALLOWED | ace::DENIED | ace::ALLOWED_CALLBACK | ace::DENIED_CALLBACK
    )
}

/// Owner and DACL of a self-relative descriptor: `Some((owner, dacl))`, `dacl` `None` for a
/// NULL DACL (absent or `SE_DACL_PRESENT` with offset 0). `None` if the bytes are not a
/// self-relative descriptor or anything lies outside them (fail closed).
pub(super) fn parse(b: &[u8]) -> Option<(Option<String>, Option<Vec<AceFact>>)> {
    let control = u16_at(b, 2)?;
    if *b.first()? != 1 || control & SE_SELF_RELATIVE == 0 {
        return None;
    }
    let owner_at = usize::try_from(u32_at(b, 4)?).ok()?;
    let dacl_at = usize::try_from(u32_at(b, 16)?).ok()?;
    let owner = if owner_at == 0 {
        None
    } else {
        Some(sid_at(b, owner_at)?)
    };
    if control & SE_DACL_PRESENT == 0 || dacl_at == 0 {
        return Some((owner, None));
    }
    let size = usize::from(u16_at(b, dacl_at.checked_add(2)?)?);
    let count = usize::from(u16_at(b, dacl_at.checked_add(4)?)?);
    let end = dacl_at.checked_add(size)?;
    if end > b.len() || size < 8 {
        return None;
    }
    let mut aces = Vec::with_capacity(count.min(size / 8));
    let mut at = dacl_at + 8;
    for _ in 0..count {
        let ace_type = *b.get(at)?;
        let flags = *b.get(at + 1)?;
        let ace_size = usize::from(u16_at(b, at + 2)?);
        let ace_end = at.checked_add(ace_size)?;
        if ace_size < 8 || ace_end > end {
            return None;
        }
        let mask = u32_at(b, at + 4)?;
        let sid = if plain_layout(ace_type) {
            let s = sid_at(&b[..ace_end], at + 8)?;
            Some(s)
        } else {
            None
        };
        aces.push(AceFact {
            ace_type,
            flags,
            mask,
            sid,
        });
        at = ace_end;
    }
    Some((owner, Some(aces)))
}

#[cfg(test)]
pub(super) mod tests {
    use super::{parse, sid_at};
    use crate::sys::fs::ace;

    /// A SID `S-1-<auth>-<subs…>` as bytes.
    pub(in crate::sys::win) fn sid(auth: u8, subs: &[u32]) -> Vec<u8> {
        let mut b = vec![1, u8::try_from(subs.len()).unwrap(), 0, 0, 0, 0, 0, auth];
        for s in subs {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    fn ace_bytes(t: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
        let size = u16::try_from(8 + sid.len()).unwrap();
        let mut b = vec![t, flags];
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&mask.to_le_bytes());
        b.extend_from_slice(sid);
        b
    }

    /// A self-relative descriptor with `owner` and a DACL of `aces` (`None` = no DACL).
    fn sd(owner: Option<&[u8]>, aces: Option<&[Vec<u8>]>) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = 1;
        let mut control: u16 = 0x8000;
        if let Some(o) = owner {
            let at = u32::try_from(b.len()).unwrap();
            b[4..8].copy_from_slice(&at.to_le_bytes());
            b.extend_from_slice(o);
        }
        if let Some(aces) = aces {
            control |= 0x0004;
            let at = u32::try_from(b.len()).unwrap();
            b[16..20].copy_from_slice(&at.to_le_bytes());
            let body: Vec<u8> = aces.concat();
            let size = u16::try_from(8 + body.len()).unwrap();
            b.extend_from_slice(&[2, 0]);
            b.extend_from_slice(&size.to_le_bytes());
            b.extend_from_slice(&u16::try_from(aces.len()).unwrap().to_le_bytes());
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&body);
        }
        b[2..4].copy_from_slice(&control.to_le_bytes());
        b
    }

    #[test]
    fn sids_are_written_like_windows() {
        assert_eq!(sid_at(&sid(5, &[32, 544]), 0).unwrap(), "S-1-5-32-544");
        assert_eq!(sid_at(&sid(5, &[18]), 0).unwrap(), "S-1-5-18");
        assert_eq!(sid_at(&sid(1, &[0]), 0).unwrap(), "S-1-1-0");
        let mut big = sid(0, &[1]);
        big[2] = 1;
        assert_eq!(sid_at(&big, 0).unwrap(), "S-1-0x010000000000-1");
        // Short, another revision, too many sub-authorities.
        assert!(sid_at(&sid(5, &[32, 544])[..11], 0).is_none());
        let mut rev = sid(5, &[18]);
        rev[0] = 2;
        assert!(sid_at(&rev, 0).is_none());
        let mut many = sid(5, &[18]);
        many[1] = 16;
        assert!(sid_at(&many, 0).is_none());
    }

    #[test]
    fn owner_and_dacl_are_parsed_in_order() {
        let admins = sid(5, &[32, 544]);
        let users = sid(5, &[32, 545]);
        let b = sd(
            Some(&admins),
            Some(&[
                ace_bytes(ace::ALLOWED, 0, 0x1F01FF, &admins),
                ace_bytes(ace::DENIED, 0, 0x2, &users),
                ace_bytes(ace::ALLOWED, ace::INHERIT_ONLY | 0x3, 0x1000_0000, &users),
                ace_bytes(ace::ALLOWED_CALLBACK, 0, 0x2, &users),
                // An object ACE: no SID read.
                ace_bytes(ace::ALLOWED_OBJECT, 0, 0x2, &[0; 12]),
            ]),
        );
        let (owner, dacl) = parse(&b).unwrap();
        assert_eq!(owner.as_deref(), Some("S-1-5-32-544"));
        let dacl = dacl.unwrap();
        assert_eq!(dacl.len(), 5);
        assert_eq!(dacl[0].mask, 0x1F01FF);
        assert_eq!(dacl[1].ace_type, ace::DENIED);
        assert_eq!(dacl[2].flags & ace::INHERIT_ONLY, ace::INHERIT_ONLY);
        assert_eq!(dacl[3].sid.as_deref(), Some("S-1-5-32-545"));
        assert_eq!(dacl[4].sid, None);
    }

    #[test]
    fn a_null_dacl_and_a_missing_owner_are_reported() {
        let (owner, dacl) = parse(&sd(None, None)).unwrap();
        assert_eq!((owner, dacl), (None, None));
        let (_, dacl) = parse(&sd(None, Some(&[]))).unwrap();
        assert_eq!(dacl, Some(vec![]));
    }

    #[test]
    fn broken_descriptors_are_refused() {
        let admins = sid(5, &[32, 544]);
        let good = sd(
            Some(&admins),
            Some(&[ace_bytes(ace::ALLOWED, 0, 1, &admins)]),
        );
        assert!(parse(&good).is_some());
        // Every truncation fails (never a partial DACL).
        for n in 0..good.len() {
            assert!(parse(&good[..n]).is_none(), "{n}");
        }
        // Not self-relative; another revision.
        let mut abs = good.clone();
        abs[3] &= 0x7F;
        assert!(parse(&abs).is_none());
        let mut rev = good.clone();
        rev[0] = 2;
        assert!(parse(&rev).is_none());
        // An ACE count beyond the ACL.
        let mut count = good.clone();
        let dacl_at =
            usize::try_from(u32::from_le_bytes(good[16..20].try_into().unwrap())).unwrap();
        count[dacl_at + 4] = 2;
        assert!(parse(&count).is_none());
        // An ACE size beyond the ACL, and below the header.
        let mut size = good.clone();
        size[dacl_at + 8 + 2] = 0xFF;
        assert!(parse(&size).is_none());
        let mut tiny = good;
        tiny[dacl_at + 8 + 2] = 4;
        tiny[dacl_at + 8 + 3] = 0;
        assert!(parse(&tiny).is_none());
    }
}
