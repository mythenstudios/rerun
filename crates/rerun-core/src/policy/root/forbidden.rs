//! The forbidden-root list (ADR 0007, "Only policy hands out roots" and its amendment).

use std::fmt;
use std::path::Path;

use super::{RootError, open_abs};
use crate::fold::fold;
use crate::path::RootPath;
use crate::sys::{KnownFolder, SysErrorKind, System};

/// A folder no root may overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protected {
    /// A known folder itself.
    Known(KnownFolder),
    /// A folder one segment below a known folder (`ProgramFiles\WindowsApps`).
    Derived(KnownFolder, &'static str),
    /// The default location of a per-user folder below the profile (`AppData\Local\Microsoft`),
    /// forbidden even when `LocalAppData` or `RoamingAppData` is redirected elsewhere.
    ProfileDefault(&'static str),
    /// Rerun's own install folder.
    InstallDir,
}

impl fmt::Display for Protected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(k) => write!(f, "{k}"),
            Self::Derived(k, name) => write!(f, "{k}\\{name}"),
            Self::ProfileDefault(rel) => write!(f, "{}\\{rel}", KnownFolder::Profile),
            Self::InstallDir => f.write_str("Rerun's install folder"),
        }
    }
}

/// Why a root is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Forbidden {
    /// The root is the protected folder.
    #[error("is {0}")]
    Is(Protected),
    /// The root lies inside the protected folder.
    #[error("inside {0}")]
    Inside(Protected),
    /// The root contains the protected folder.
    #[error("contains {0}")]
    Contains(Protected),
    /// The root lies in another user's profile (also `Public`, `Default`).
    #[error("inside another user's profile")]
    OtherUserProfile,
    /// The root lies in a per-volume system folder (`$Recycle.Bin`, `Recovery`, …).
    #[error("inside volume folder {0:?}")]
    VolumeFolder(String),
    /// The root is the root of a volume (also one mounted in a folder).
    #[error("is a volume root")]
    VolumeRoot,
}

/// The known folders the forbidden list is resolved from, explicitly (audit A1 should-item
/// 10). Not [`KnownFolder::ALL`]: a known folder added later (`Documents`, the base of the
/// `UserData` root of phase 4) can then be a root itself without becoming forbidden. Every
/// folder the rules below name must be listed here; a folder missing here would resolve to
/// no path and its rule would silently protect nothing (pinned by a test).
const FORBIDDEN_SOURCES: [KnownFolder; 10] = [
    KnownFolder::Windows,
    KnownFolder::ProgramFiles,
    KnownFolder::ProgramFilesX86,
    KnownFolder::ProgramFilesCommon,
    KnownFolder::ProgramFilesCommonX86,
    KnownFolder::ProgramData,
    KnownFolder::UserProfiles,
    KnownFolder::Profile,
    KnownFolder::LocalAppData,
    KnownFolder::RoamingAppData,
];

/// Protected folders a root must neither be, lie in, nor contain.
const OVERLAP_KNOWN: [KnownFolder; 3] = [
    KnownFolder::Windows,
    KnownFolder::ProgramFilesCommon,
    KnownFolder::ProgramFilesCommonX86,
];

/// Folders one segment below a known folder; same rule as [`OVERLAP_KNOWN`]. Never opened
/// (a standard user cannot open `WindowsApps`).
const DERIVED: [(KnownFolder, &str); 9] = [
    (KnownFolder::ProgramFiles, "WindowsApps"),
    (KnownFolder::ProgramFiles, "Windows Defender"),
    (KnownFolder::ProgramFilesX86, "Windows Defender"),
    (KnownFolder::ProgramData, "Microsoft"),
    (KnownFolder::RoamingAppData, "Microsoft"),
    (KnownFolder::LocalAppData, "Microsoft"),
    (KnownFolder::LocalAppData, "Packages"),
    (KnownFolder::LocalAppData, "VirtualStore"),
    (KnownFolder::LocalAppData, "Rerun"),
];

/// The default forms of the [`DERIVED`] entries below `LocalAppData` and `RoamingAppData`
/// (ADR 0007, ADR 0009): `User Shell Folders` can redirect both folders, so these entries are
/// also derived from every form (lexical and canonical) of `<Profile>\AppData\Local` and
/// `<Profile>\AppData\Roaming`, for every form of the profile, and a redirection can only add
/// entries, never remove one. Same rule as [`OVERLAP_KNOWN`]. The two parents are opened like
/// a known folder (missing: lexical form only; any other failure: fail closed); the entries
/// themselves are never opened. `(parent, child, reported name)`.
const PROFILE_DEFAULTS: [(&str, &str, &str); 5] = [
    (r"AppData\Local", "Microsoft", r"AppData\Local\Microsoft"),
    (r"AppData\Local", "Packages", r"AppData\Local\Packages"),
    (
        r"AppData\Local",
        "VirtualStore",
        r"AppData\Local\VirtualStore",
    ),
    (r"AppData\Local", "Rerun", r"AppData\Local\Rerun"),
    (
        r"AppData\Roaming",
        "Microsoft",
        r"AppData\Roaming\Microsoft",
    ),
];

/// The parents of [`PROFILE_DEFAULTS`].
const PROFILE_DEFAULT_PARENTS: [&str; 2] = [r"AppData\Local", r"AppData\Roaming"];

/// Folders a root must neither be nor contain; folders inside them stay allowed.
const UPWARD_KNOWN: [KnownFolder; 5] = [
    KnownFolder::ProgramFiles,
    KnownFolder::ProgramFilesX86,
    KnownFolder::ProgramData,
    KnownFolder::UserProfiles,
    KnownFolder::Profile,
];

/// First segments below a drive that are forbidden on every volume (folded). Names
/// starting with `$` are forbidden too. `WindowsApps`, `WpSystem` and `WUDownloadCache` are
/// the per-volume Microsoft Store / Game Pass folders on secondary drives.
const VOLUME_FOLDERS: [&str; 8] = [
    "SYSTEM VOLUME INFORMATION",
    "RECOVERY",
    "BOOT",
    "WINDOWS.OLD",
    "CONFIG.MSI",
    "WINDOWSAPPS",
    "WPSYSTEM",
    "WUDOWNLOADCACHE",
];

/// The resolved forbidden-root list. Built once per process with [`Self::resolve`]; the
/// elevated helper resolves its own.
#[derive(Debug, Clone)]
pub struct ForbiddenRoots {
    overlap: Vec<(Protected, RootPath)>,
    upward: Vec<(Protected, RootPath)>,
    user_profiles: Vec<RootPath>,
    own_profile: Vec<RootPath>,
}

impl ForbiddenRoots {
    /// Resolves the list from the known folders in [`FORBIDDEN_SOURCES`] (never environment
    /// variables) and Rerun's install folder (the directory of the running executable, passed
    /// in by the caller).
    ///
    /// Fails closed: if any folder cannot be resolved, no root can be handed out. Each folder
    /// is kept in its lexical and its canonical form. A folder that does not exist keeps
    /// only its lexical form. `RoamingAppData` on a network path is never opened and skipped.
    pub fn resolve(sys: &dyn System, install_dir: &Path) -> Result<Self, RootError> {
        let kf = sys.known_folders();
        let mut forms = Vec::with_capacity(FORBIDDEN_SOURCES.len());
        for folder in FORBIDDEN_SOURCES {
            let what = folder.to_string();
            let raw = kf
                .get(folder)
                .map_err(|e| incomplete(&what, e.to_string()))?;
            let s = raw.to_string_lossy();
            let on_share =
                s.starts_with(r"\\") && !s.starts_with(r"\\?\") && !s.starts_with(r"\\.\");
            if folder == KnownFolder::RoamingAppData && on_share {
                forms.push((folder, Vec::new()));
                continue;
            }
            forms.push((folder, forms_of(sys, &raw, &what, true)?));
        }
        let get = |k: KnownFolder| -> &[RootPath] {
            forms
                .iter()
                .find(|(f, _)| *f == k)
                .map_or(&[], |(_, v)| v.as_slice())
        };

        let mut overlap = Vec::new();
        for k in OVERLAP_KNOWN {
            overlap.extend(get(k).iter().map(|r| (Protected::Known(k), r.clone())));
        }
        for (k, name) in DERIVED {
            for parent in get(k) {
                let child = parent
                    .child(name)
                    .map_err(|e| incomplete(&format!("{k}\\{name}"), e.to_string()))?;
                overlap.push((Protected::Derived(k, name), child));
            }
        }
        for parent_rel in PROFILE_DEFAULT_PARENTS {
            let what = format!("{}\\{parent_rel}", KnownFolder::Profile);
            for profile in get(KnownFolder::Profile) {
                let mut parent = profile.clone();
                for seg in parent_rel.split('\\') {
                    parent = parent
                        .child(seg)
                        .map_err(|e| incomplete(&what, e.to_string()))?;
                }
                for form in forms_of(sys, parent.path(), &what, true)? {
                    for (_, name, rel) in
                        PROFILE_DEFAULTS.iter().filter(|(p, _, _)| *p == parent_rel)
                    {
                        let child = form
                            .child(name)
                            .map_err(|e| incomplete(&format!("{what}\\{name}"), e.to_string()))?;
                        overlap.push((Protected::ProfileDefault(rel), child));
                    }
                }
            }
        }
        let install = forms_of(sys, install_dir, "install folder", false)?;
        overlap.extend(install.into_iter().map(|r| (Protected::InstallDir, r)));

        let mut upward = Vec::new();
        for k in UPWARD_KNOWN {
            upward.extend(get(k).iter().map(|r| (Protected::Known(k), r.clone())));
        }
        Ok(Self {
            overlap,
            upward,
            user_profiles: get(KnownFolder::UserProfiles).to_vec(),
            own_profile: get(KnownFolder::Profile).to_vec(),
        })
    }

    /// Checks a root path against the list. Pure; also usable as a pre-check in the UI.
    /// Does not know whether the path is a volume root; [`super::StoreDir::open`] checks that
    /// on the handle.
    pub fn check(&self, root: &RootPath) -> Result<(), Forbidden> {
        volume_folder(root.first_segment())?;
        for (p, f) in &self.upward {
            if root == f {
                return Err(Forbidden::Is(*p));
            }
            if root.contains(f) {
                return Err(Forbidden::Contains(*p));
            }
        }
        for (p, f) in &self.overlap {
            if root == f {
                return Err(Forbidden::Is(*p));
            }
            if f.contains(root) {
                return Err(Forbidden::Inside(*p));
            }
            if root.contains(f) {
                return Err(Forbidden::Contains(*p));
            }
        }
        let in_profiles = self.user_profiles.iter().any(|u| u.contains(root));
        let in_own = self.own_profile.iter().any(|o| contains_strict(o, root));
        if in_profiles && !in_own {
            return Err(Forbidden::OtherUserProfile);
        }
        Ok(())
    }
}

/// The per-volume folder rule for the first segment below a volume root (`$*`,
/// `System Volume Information`, `Recovery`, …).
pub(super) fn volume_folder(first: &str) -> Result<(), Forbidden> {
    let folded = fold(first);
    if folded.starts_with('$') || VOLUME_FOLDERS.contains(&folded.as_str()) {
        return Err(Forbidden::VolumeFolder(first.to_owned()));
    }
    Ok(())
}

/// Like [`RootPath::contains`], but only ASCII letters compare case-insensitively. Used for
/// the one exception that *allows* (own profile): folding beyond ASCII may differ from the
/// NTFS upcase table (`ſ`, `ı`), and a wrong match here must fall back to "forbidden".
fn contains_strict(outer: &RootPath, inner: &RootPath) -> bool {
    let (Some(o), Some(i)) = (outer.path().to_str(), inner.path().to_str()) else {
        return false;
    };
    i.get(..o.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(o))
        && (i.len() == o.len() || i.as_bytes().get(o.len()) == Some(&b'\\'))
}

fn incomplete(what: &str, reason: String) -> RootError {
    RootError::ForbiddenListIncomplete {
        what: what.to_owned(),
        reason,
    }
}

/// Lexical and canonical form of a folder. `missing_ok`: a folder that does not exist keeps
/// its lexical form; otherwise it is an error.
fn forms_of(
    sys: &dyn System,
    raw: &Path,
    what: &str,
    missing_ok: bool,
) -> Result<Vec<RootPath>, RootError> {
    // A raw path that is not a plain drive-letter folder (UNC, `PROGRA~1`, a drive root) is
    // unexpected for a known folder: fail closed rather than guess.
    let lexical = RootPath::new(raw).map_err(|e| incomplete(what, e.to_string()))?;
    let mut forms = vec![lexical];
    match open_abs(sys, raw) {
        Ok(dir) => {
            let info = dir.info().map_err(|e| incomplete(what, e.to_string()))?;
            let canonical = RootPath::from_final_path(&info.final_path)
                .map_err(|e| incomplete(what, e.to_string()))?;
            if !forms.contains(&canonical) {
                forms.push(canonical);
            }
        }
        Err(e) if e.kind == SysErrorKind::NotFound && missing_ok => {}
        Err(e) => return Err(incomplete(what, e.to_string())),
    }
    Ok(forms)
}

#[cfg(test)]
mod tests {
    use super::{DERIVED, FORBIDDEN_SOURCES, OVERLAP_KNOWN, UPWARD_KNOWN};
    use crate::sys::KnownFolder;

    /// The sources are pinned: changing them changes what is forbidden. Today they are the
    /// same set as `KnownFolder::ALL`, so the split changed no behaviour.
    #[test]
    fn forbidden_sources_are_pinned() {
        use KnownFolder as K;
        assert_eq!(
            FORBIDDEN_SOURCES,
            [
                K::Windows,
                K::ProgramFiles,
                K::ProgramFilesX86,
                K::ProgramFilesCommon,
                K::ProgramFilesCommonX86,
                K::ProgramData,
                K::UserProfiles,
                K::Profile,
                K::LocalAppData,
                K::RoamingAppData,
            ]
        );
        let mut sorted = FORBIDDEN_SOURCES.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), FORBIDDEN_SOURCES.len(), "no duplicates");
    }

    /// Every folder a rule names is resolved: one missing from the sources would resolve to
    /// no path and its rule would protect nothing (fail open).
    #[test]
    fn every_folder_a_rule_names_is_a_source() {
        let named = OVERLAP_KNOWN
            .iter()
            .chain(UPWARD_KNOWN.iter())
            .chain(DERIVED.iter().map(|(k, _)| k))
            .chain(&[KnownFolder::UserProfiles, KnownFolder::Profile]);
        for k in named {
            assert!(FORBIDDEN_SOURCES.contains(k), "{k} is not resolved");
        }
    }
}
