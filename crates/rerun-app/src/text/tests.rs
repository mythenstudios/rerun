//! The text catalogue (ADR 0027, `docs/07-ui.md` copy rules): every message in every language
//! is non-empty and has the same numbers as its English text; no exclamation mark, no
//! superlative; German uses "du" (never the formal "Sie"/"Ihr") and "ss" (never "ß").

use super::{Lang, Msg, Sym, t};

/// Every message once (count messages with 1 and with 3, where the plural differs).
/// [`exhaustive`] fails to compile when a variant is added and not listed there.
fn every() -> Vec<Msg> {
    use Msg::*;
    vec![
        AppName,
        ByMythen,
        Minimize,
        Maximize,
        Restore,
        Close,
        NavLabel,
        NavLibrary,
        NavApplied,
        NavHistory,
        NavSystem,
        NavSettings,
        StatusNoBackground,
        StatusIndex { seq: 4711 },
        StatusIndexNone,
        StatusIndexRefused,
        StatusSignatureChecked,
        StatusSignatureNone,
        StatusReading,
        TestKeyBuild,
        ElevatedTitle,
        ElevatedBody,
        ElevatedHow,
        GuardTitle,
        GuardBody,
        Detail,
        FirstRunTitle,
        FirstRun1Lead,
        FirstRun1,
        FirstRun2Lead,
        FirstRun2,
        FirstRun3Lead,
        FirstRun3,
        FirstRunDismiss,
        LibraryTitle,
        LibraryReading,
        LibrarySummary {
            games: 1,
            libraries: 1,
        },
        LibrarySummary {
            games: 3,
            libraries: 3,
        },
        SearchLabel,
        SearchPlaceholder,
        GroupByStatus,
        ViewLabel,
        ViewList,
        GroupTopo,
        GroupNoTopo,
        GroupNotReady,
        GroupAll,
        NoSearchMatch,
        Rescan,
        GameListLabel { shown: 1 },
        GameListLabel { shown: 3 },
        BadgeTopo,
        BadgeNoTopo,
        BadgeNoIndex,
        BadgeUpdating,
        BadgeNotInstalled,
        BadgeNotRead,
        RowNoMainExe,
        RowSeveralExes,
        RowUpdating,
        RowNotInstalled,
        RowNotOpened,
        RowApiUnknown,
        NoSteamTitle,
        NoSteamBody,
        NoGamesTitle,
        NoGamesBody,
        ScanProblemsTitle { count: 1 },
        ScanProblemsTitle { count: 3 },
        ScanProblemsBody,
        ShowProblems,
        HideProblems,
        IndexNoneTitle,
        IndexNoneBody,
        IndexNoKeysTitle,
        IndexNoKeysBody,
        IndexRefusedTitle,
        IndexRefusedBody,
        BackToLibrary,
        GameEyebrow,
        GameReading,
        UnnamedGame { app_id: 4711 },
        HeroNoIndex,
        HeroNoTopo,
        HeroNoMatch,
        HeroNoMatchSub,
        HeroRetired,
        HeroSeveral,
        HeroAffects {
            problems: 1,
            fixes: 1,
        },
        HeroAffects {
            problems: 3,
            fixes: 3,
        },
        HeroMayOccur {
            problems: 1,
            fixes: 1,
        },
        HeroMayOccur {
            problems: 3,
            fixes: 3,
        },
        HeroNothingHere,
        HeroNoFixHere,
        HeroReadOnly,
        HeroUpdating,
        HeroNotInstalled,
        HeroNoSteam,
        HeroNotListed,
        HeroTwice,
        HeroFolder,
        HeroIndexRefused,
        HeroEngine,
        FactsLabel,
        FactSteamApp,
        FactProgram,
        FactGraphics,
        FactTopo,
        TopoRevision { rev: 4711 },
        TopoActive,
        TopoNeedsRetest,
        TopoRetired,
        TopoDraft,
        NoteAntiCheat,
        NoteAntiCheatUnreadable,
        NoteAntiCheatReleased,
        NoteSeveralGpus,
        NoteNeedsRetest,
        ProblemsTitle,
        WhenYes,
        WhenUnknown,
        WhenNo,
        ProblemFixes,
        ProblemNoFix,
        FixesTitle,
        FixesIntro,
        KindFix,
        KindEnhancement,
        StatusVerified,
        StatusReported,
        StatusUnverified,
        FixSolves,
        FixOffered,
        FixNotOffered,
        FixRefusedAntiCheat,
        FixRefusedLaunch,
        FixWarned,
        FixesReadOnly,
        AppliedTitle,
        AppliedIntro,
        AppliedEmpty,
        AppliedEmptySub,
        AppliedSome { count: 1 },
        AppliedSome { count: 3 },
        AppliedSomeSub,
        AppliedUnreadable,
        HistoryTitle,
        HistoryIntro,
        HistoryLater,
        SystemTitle,
        SystemIntro,
        SystemReading,
        SysGraphics,
        SysProcessor,
        SysWindows,
        SysSac,
        SysSteam,
        SysVram { mb: 4711 },
        SysIntegrated,
        SysNoAdapter,
        SysUnreadable,
        SysCpu {
            threads: 1,
            cores: 1,
            groups: 1,
        },
        SysCpu {
            threads: 3,
            cores: 3,
            groups: 3,
        },
        SysBuild { build: 4711 },
        SysBuildUbr {
            build: 4711,
            ubr: 4711,
        },
        SacOff,
        SacOn,
        SacEvaluation,
        SacUnknown,
        SteamFound { libraries: 1 },
        SteamFound { libraries: 3 },
        SteamNotFound,
        SettingsTitle,
        SettingsIntro,
        SettingsSafety,
        SetPreview,
        SetPreviewDesc,
        SetSources,
        SetSourcesDesc,
        AlwaysOn,
        SettingsLook,
        SetTheme,
        ThemeMythen,
        SetLanguage,
        LanguageName,
        SettingsAbout,
        AboutVersion,
        AboutLicence,
    ]
}

/// Compile-time completeness: a new variant must be added here and to [`every`].
#[allow(dead_code, reason = "only compiled, never called")]
fn exhaustive(m: Msg) {
    use Msg::*;
    match m {
        AppName
        | ByMythen
        | Minimize
        | Maximize
        | Restore
        | Close
        | NavLabel
        | NavLibrary
        | NavApplied
        | NavHistory
        | NavSystem
        | NavSettings
        | StatusNoBackground
        | StatusIndex { .. }
        | StatusIndexNone
        | StatusIndexRefused
        | StatusSignatureChecked
        | StatusSignatureNone
        | StatusReading
        | TestKeyBuild
        | ElevatedTitle
        | ElevatedBody
        | ElevatedHow
        | GuardTitle
        | GuardBody
        | Detail
        | FirstRunTitle
        | FirstRun1Lead
        | FirstRun1
        | FirstRun2Lead
        | FirstRun2
        | FirstRun3Lead
        | FirstRun3
        | FirstRunDismiss
        | LibraryTitle
        | LibraryReading
        | LibrarySummary { .. }
        | SearchLabel
        | SearchPlaceholder
        | GroupByStatus
        | ViewLabel
        | ViewList
        | GroupTopo
        | GroupNoTopo
        | GroupNotReady
        | GroupAll
        | NoSearchMatch
        | Rescan
        | GameListLabel { .. }
        | BadgeTopo
        | BadgeNoTopo
        | BadgeNoIndex
        | BadgeUpdating
        | BadgeNotInstalled
        | BadgeNotRead
        | RowNoMainExe
        | RowSeveralExes
        | RowUpdating
        | RowNotInstalled
        | RowNotOpened
        | RowApiUnknown
        | NoSteamTitle
        | NoSteamBody
        | NoGamesTitle
        | NoGamesBody
        | ScanProblemsTitle { .. }
        | ScanProblemsBody
        | ShowProblems
        | HideProblems
        | IndexNoneTitle
        | IndexNoneBody
        | IndexNoKeysTitle
        | IndexNoKeysBody
        | IndexRefusedTitle
        | IndexRefusedBody
        | BackToLibrary
        | GameEyebrow
        | GameReading
        | UnnamedGame { .. }
        | HeroNoIndex
        | HeroNoTopo
        | HeroNoMatch
        | HeroNoMatchSub
        | HeroRetired
        | HeroSeveral
        | HeroAffects { .. }
        | HeroMayOccur { .. }
        | HeroNothingHere
        | HeroNoFixHere
        | HeroReadOnly
        | HeroUpdating
        | HeroNotInstalled
        | HeroNoSteam
        | HeroNotListed
        | HeroTwice
        | HeroFolder
        | HeroIndexRefused
        | HeroEngine
        | FactsLabel
        | FactSteamApp
        | FactProgram
        | FactGraphics
        | FactTopo
        | TopoRevision { .. }
        | TopoActive
        | TopoNeedsRetest
        | TopoRetired
        | TopoDraft
        | NoteAntiCheat
        | NoteAntiCheatUnreadable
        | NoteAntiCheatReleased
        | NoteSeveralGpus
        | NoteNeedsRetest
        | ProblemsTitle
        | WhenYes
        | WhenUnknown
        | WhenNo
        | ProblemFixes
        | ProblemNoFix
        | FixesTitle
        | FixesIntro
        | KindFix
        | KindEnhancement
        | StatusVerified
        | StatusReported
        | StatusUnverified
        | FixSolves
        | FixOffered
        | FixNotOffered
        | FixRefusedAntiCheat
        | FixRefusedLaunch
        | FixWarned
        | FixesReadOnly
        | AppliedTitle
        | AppliedIntro
        | AppliedEmpty
        | AppliedEmptySub
        | AppliedSome { .. }
        | AppliedSomeSub
        | AppliedUnreadable
        | HistoryTitle
        | HistoryIntro
        | HistoryLater
        | SystemTitle
        | SystemIntro
        | SystemReading
        | SysGraphics
        | SysProcessor
        | SysWindows
        | SysSac
        | SysSteam
        | SysVram { .. }
        | SysIntegrated
        | SysNoAdapter
        | SysUnreadable
        | SysCpu { .. }
        | SysBuild { .. }
        | SysBuildUbr { .. }
        | SacOff
        | SacOn
        | SacEvaluation
        | SacUnknown
        | SteamFound { .. }
        | SteamNotFound
        | SettingsTitle
        | SettingsIntro
        | SettingsSafety
        | SetPreview
        | SetPreviewDesc
        | SetSources
        | SetSourcesDesc
        | AlwaysOn
        | SettingsLook
        | SetTheme
        | ThemeMythen
        | SetLanguage
        | LanguageName
        | SettingsAbout
        | AboutVersion
        | AboutLicence => {}
    }
}

/// The ASCII digit runs of `s`, sorted.
fn numbers(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.sort();
    out
}

/// Whether `s` has `word` as a whole word.
fn has_word(s: &str, word: &str) -> bool {
    s.split(|c: char| !c.is_alphabetic()).any(|w| w == word)
}

#[test]
fn every_message_is_non_empty_in_every_language() {
    let all = every();
    assert!(all.len() > 150, "{}", all.len());
    for lang in Lang::ALL {
        for m in &all {
            let s = t(lang, *m);
            assert!(!s.trim().is_empty(), "{lang:?} {m:?}");
            assert_eq!(s.trim(), s, "{lang:?} {m:?}: surrounding space");
        }
    }
}

#[test]
fn the_numbers_of_a_message_are_the_same_in_every_language() {
    for m in every() {
        let en = numbers(&t(Lang::En, m));
        for lang in Lang::ALL {
            assert_eq!(numbers(&t(lang, m)), en, "{lang:?} {m:?}");
        }
    }
}

#[test]
fn the_copy_rules_hold() {
    let superlatives = [
        "best",
        "fastest",
        "easiest",
        "perfect",
        "amazing",
        "ultimate",
        "awesome",
        "beste",
        "schnellste",
        "einfachste",
        "perfekt",
        "genial",
        "ultimativ",
    ];
    for lang in Lang::ALL {
        for m in every() {
            let s = t(lang, m);
            assert!(!s.contains('!'), "{lang:?} {m:?}: {s}");
            let lower = s.to_lowercase();
            for w in superlatives {
                assert!(!has_word(&lower, w), "{lang:?} {m:?}: {s}");
            }
        }
    }
    for m in every() {
        let s = t(Lang::De, m);
        assert!(!s.contains('\u{df}'), "{m:?}: {s}");
        for formal in ["Sie", "Ihr", "Ihre", "Ihnen", "Ihren"] {
            assert!(!has_word(&s, formal), "{m:?}: {s}");
        }
    }
}

#[test]
fn the_copy_rule_checks_have_teeth() {
    assert_eq!(
        numbers("3 of 12, build 26300.4061"),
        ["12", "26300", "3", "4061"]
    );
    assert!(has_word("Starten Sie es neu", "Sie"));
    assert!(!has_word("Siehe unten", "Sie"));
}

#[test]
fn plurals_follow_the_count() {
    assert_eq!(
        t(
            Lang::En,
            Msg::HeroAffects {
                problems: 1,
                fixes: 1
            }
        ),
        "1 problem affects your PC \u{b7} 1 fix available"
    );
    assert_eq!(
        t(
            Lang::En,
            Msg::HeroAffects {
                problems: 2,
                fixes: 3
            }
        ),
        "2 problems affect your PC \u{b7} 3 fixes available"
    );
    assert_eq!(
        t(
            Lang::De,
            Msg::HeroAffects {
                problems: 2,
                fixes: 1
            }
        ),
        "2 Probleme betreffen deinen PC \u{b7} 1 Fix verfügbar"
    );
}

#[test]
fn the_language_follows_windows() {
    // de-CH 0x0807, de-DE 0x0407, de-AT 0x0c07; en-US 0x0409, fr-CH 0x100c.
    for id in [0x0807, 0x0407, 0x0c07] {
        assert_eq!(Lang::from_langid(id), Lang::De);
    }
    for id in [0x0409, 0x100c, 0] {
        assert_eq!(Lang::from_langid(id), Lang::En);
    }
}

#[test]
fn every_status_glyph_is_one_character() {
    for s in [
        Sym::Affects,
        Sym::Open,
        Sym::Applied,
        Sym::None,
        Sym::Unknown,
        Sym::Attention,
        Sym::NotHere,
        Sym::Verified,
        Sym::Unconfirmed,
    ] {
        assert_eq!(s.glyph().chars().count(), 1, "{s:?}");
    }
}
