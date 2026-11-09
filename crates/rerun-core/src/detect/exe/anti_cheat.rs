//! Anti-cheat in a game folder (P4-4, user decision E4 of the phase 4 plan; non-goal in
//! `docs/00-vision.md`). Read only: one `metadata` per marker and folder, handle-relative
//! through the [`GameDir`], nothing opened, nothing followed.
//!
//! The markers are a fixed table ([`MARKERS`]): a folder or a file of an anti-cheat system
//! next to the game, each with its source (`docs/05-sources-policy.md`, "Reference data"; an
//! entry without a vendor source yet says so). Fail closed: any entry of that name (a file, a
//! folder, a link) counts as found; an entry the user may not open, and a named folder that is
//! a link or cannot be asked, is [`AntiCheatScan::unreadable`]: the Topo engine applies the
//! rule for it and no release of a dead system covers it. A
//! false find costs fixes, never a ban (P4 risk R7): leftovers of an old system (a `pb`
//! folder of PunkBuster) count too, until a signed Topo releases that system as dead.
//!
//! Where it looks: the game folder and the folders the caller names (the folders of the
//! executables a Topo matches and of its `launch.start`; for `rerun scan` the folders of the
//! main executable). Never below them: the walk's skip list keeps these folders out of the
//! exe scan already (ADR 0014).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::path::RelPath;
use crate::policy::root::GameDir;
use crate::sys::fs::EntryKind;
use crate::sys::{Dir, SysErrorKind};

/// An anti-cheat system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AntiCheat {
    /// Easy Anti-Cheat (Epic).
    EasyAntiCheat,
    /// BattlEye.
    Battleye,
    /// PunkBuster (Even Balance).
    Punkbuster,
    /// nProtect GameGuard.
    Gameguard,
    /// XIGNCODE (Wellbia).
    Xigncode,
    /// EA anticheat (Javelin).
    EaAnticheat,
}

impl AntiCheat {
    /// The spelling of the Topo field `anti_cheat.dead` and of the output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EasyAntiCheat => "easy-anti-cheat",
            Self::Battleye => "battleye",
            Self::Punkbuster => "punkbuster",
            Self::Gameguard => "gameguard",
            Self::Xigncode => "xigncode",
            Self::EaAnticheat => "ea-anticheat",
        }
    }
}

impl fmt::Display for AntiCheat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a marker is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerKind {
    /// A folder of this name.
    Folder,
    /// A file of this name.
    File,
}

/// One entry of [`MARKERS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    /// The system.
    pub system: AntiCheat,
    /// Folder or file (a hint for the table; any entry of the name counts).
    pub kind: MarkerKind,
    /// The name, one segment, compared as the file system does (case-insensitively).
    pub name: &'static str,
    /// Where it comes from: a link, the developer-machine dump, or `TODO` with the reason.
    pub source: &'static str,
}

/// The dump of the developer machine (ADR 0014 amendment 2026-11-05).
const DUMP: &str = "developer-machine dump, ADR 0014 amendment 2026-11-05";
/// No vendor source found yet (P4-4): detected anyway, a false find only costs fixes (R7).
const NO_SOURCE: &str = "TODO: no vendor source yet (fail closed, P4 risk R7)";

/// The markers (P4-4). Mirrored in `docs/05-sources-policy.md`, "Reference data".
pub const MARKERS: &[Marker] = &[
    Marker {
        system: AntiCheat::EasyAntiCheat,
        kind: MarkerKind::Folder,
        name: "EasyAntiCheat",
        source: NO_SOURCE,
    },
    Marker {
        system: AntiCheat::EasyAntiCheat,
        kind: MarkerKind::Folder,
        name: "EasyAntiCheat_EOS",
        source: NO_SOURCE,
    },
    Marker {
        system: AntiCheat::EasyAntiCheat,
        kind: MarkerKind::File,
        name: "start_protected_game.exe",
        source: "https://redpoint-games-docs.pages.dev/docs/setup/networking/anticheat",
    },
    Marker {
        system: AntiCheat::Battleye,
        kind: MarkerKind::Folder,
        name: "BattlEye",
        source: "https://www.battleye.com/support/faq/",
    },
    Marker {
        system: AntiCheat::Punkbuster,
        kind: MarkerKind::Folder,
        name: "PunkBuster",
        source: DUMP,
    },
    Marker {
        system: AntiCheat::Punkbuster,
        kind: MarkerKind::Folder,
        name: "pb",
        source: "https://www.pbbans.com/info-center-pbsetup.html",
    },
    Marker {
        system: AntiCheat::Gameguard,
        kind: MarkerKind::Folder,
        name: "GameGuard",
        source: NO_SOURCE,
    },
    Marker {
        system: AntiCheat::Xigncode,
        kind: MarkerKind::Folder,
        name: "XIGNCODE",
        source: NO_SOURCE,
    },
    Marker {
        system: AntiCheat::EaAnticheat,
        kind: MarkerKind::File,
        name: "EAAntiCheat.GameServiceLauncher.exe",
        source: NO_SOURCE,
    },
];

/// One marker found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiCheatHit {
    /// The system.
    pub system: AntiCheat,
    /// The entry, relative to the game folder.
    pub path: RelPath,
}

/// What [`find`] saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AntiCheatScan {
    /// Markers found, in folder order, then table order.
    pub found: Vec<AntiCheatHit>,
    /// Marker paths that could not be asked (an error other than "not found"): treated like a
    /// find by the Topo engine (fail closed).
    pub unreadable: Vec<RelPath>,
}

impl AntiCheatScan {
    /// Nothing found and nothing unreadable.
    pub fn is_clear(&self) -> bool {
        self.found.is_empty() && self.unreadable.is_empty()
    }

    /// The systems found, sorted, each once.
    pub fn systems(&self) -> Vec<AntiCheat> {
        let mut v: Vec<AntiCheat> = self.found.iter().map(|h| h.system).collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Looks for every marker in the game folder and in each of `dirs` (relative folders; the
/// game folder itself is always asked first, duplicates once).
pub fn find(game: &GameDir<'_>, dirs: &[RelPath]) -> AntiCheatScan {
    find_in(game.dir(), dirs)
}

/// [`find`] on any read handle of a game folder (the elevated helper's root opened by identity,
/// ADR 0023 §5 step 6).
pub fn find_in(game: &dyn Dir, dirs: &[RelPath]) -> AntiCheatScan {
    let mut where_: Vec<Option<&RelPath>> = vec![None];
    for d in dirs {
        let folded = crate::fold::fold(d.as_str());
        if !where_
            .iter()
            .flatten()
            .any(|w| crate::fold::fold(w.as_str()) == folded)
        {
            where_.push(Some(d));
        }
    }
    let mut out = AntiCheatScan::default();
    for dir in where_ {
        // A named folder is asked once: missing or a file holds no marker; a link or a folder
        // that cannot be asked is unreadable as a whole (never one find per marker).
        if let Some(d) = dir {
            match game.metadata(d) {
                Ok(Some(md))
                    if md.kind == EntryKind::Dir && md.reparse.is_none() && !md.restricted => {}
                Ok(Some(md)) if md.kind == EntryKind::File => continue,
                Ok(None) => continue,
                Err(e) if e.kind == SysErrorKind::NotFound => continue,
                _ => {
                    out.unreadable.push(d.clone());
                    continue;
                }
            }
        }
        for m in MARKERS {
            let path = match dir {
                None => RelPath::from_segment(m.name),
                Some(d) => d.child(m.name),
            };
            let Ok(path) = path else {
                // A folder too long for one more segment: nothing can lie there by that name.
                continue;
            };
            match game.metadata(&path) {
                // An entry the user may not open could be anything: counted, never released.
                Ok(Some(md)) if md.restricted => out.unreadable.push(path),
                Ok(Some(_)) => out.found.push(AntiCheatHit {
                    system: m.system,
                    path,
                }),
                Ok(None) => {}
                Err(e) if e.kind == SysErrorKind::NotFound => {}
                // The entry itself is a link: something of that name is there.
                Err(e) if e.kind == SysErrorKind::ReparsePoint => out.found.push(AntiCheatHit {
                    system: m.system,
                    path,
                }),
                Err(_) => out.unreadable.push(path),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{AntiCheat, MARKERS, find};
    use crate::path::RelPath;
    use crate::policy::root::{ForbiddenRoots, GameDir};
    use crate::sys::fake::FakeSystem;
    use std::path::Path;

    const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";

    #[test]
    fn every_marker_is_one_segment_and_names_its_source() {
        for m in MARKERS {
            assert!(RelPath::from_segment(m.name).is_ok(), "{}", m.name);
            assert!(!m.source.is_empty(), "{}", m.name);
            assert!(
                m.source.starts_with("https://")
                    || m.source.starts_with("developer-machine dump")
                    || m.source.starts_with("TODO: "),
                "{}",
                m.name
            );
        }
    }

    #[test]
    fn finds_markers_in_the_root_and_named_folders_only() {
        let sys = FakeSystem::builder()
            .windows_layout()
            .dir(INSTALL)
            .dir(r"D:\G")
            .dir(r"D:\G\pb")
            .dir(r"D:\G\bin")
            .file(r"D:\G\bin\game.exe", b"x")
            .dir(r"D:\G\bin\BattlEye")
            .dir(r"D:\G\data\GameGuard")
            .build()
            .unwrap();
        let fr = ForbiddenRoots::resolve(&sys, Path::new(INSTALL)).unwrap();
        let g = GameDir::open_manual(&sys, &fr, Path::new(r"D:\G")).unwrap();
        let none = find(&g, &[]);
        assert_eq!(none.systems(), vec![AntiCheat::Punkbuster]);
        let bin = RelPath::parse("bin").unwrap();
        let s = find(&g, &[bin.clone(), bin]);
        assert_eq!(
            s.systems(),
            vec![AntiCheat::Battleye, AntiCheat::Punkbuster]
        );
        assert_eq!(s.found.len(), 2, "a folder is asked once");
        assert!(s.unreadable.is_empty());
        assert_eq!(s.found[1].path.as_str(), r"bin\BattlEye");
    }
}
