//! The text catalogue (ADR 0027, `docs/07-ui.md` copy rules): every message in every language
//! is non-empty and has the same numbers as its English text; no exclamation mark, no
//! superlative; German uses "du" (never the formal "Sie"/"Ihr") and "ss" (never "ß").

use super::{Lang, Msg, Sym, t};

/// Every message once (count messages with 1 and with 3, where the plural differs); checked
/// against [`ordinal`] by [`every_ordinal_is_listed`].
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

/// The number of messages: one more than the highest [`ordinal`].
const COUNT: usize = 180;

/// A message's position in the enum. The `match` is exhaustive: a new variant does not compile
/// without an ordinal here, and [`every_ordinal_is_listed`] fails until [`every`] lists it.
fn ordinal(m: Msg) -> usize {
    use Msg::*;
    match m {
        AppName => 0,
        ByMythen => 1,
        Minimize => 2,
        Maximize => 3,
        Restore => 4,
        Close => 5,
        NavLabel => 6,
        NavLibrary => 7,
        NavApplied => 8,
        NavHistory => 9,
        NavSystem => 10,
        NavSettings => 11,
        StatusNoBackground => 12,
        StatusIndex { .. } => 13,
        StatusIndexNone => 14,
        StatusIndexRefused => 15,
        StatusSignatureChecked => 16,
        StatusSignatureNone => 17,
        StatusReading => 18,
        TestKeyBuild => 19,
        ElevatedTitle => 20,
        ElevatedBody => 21,
        ElevatedHow => 22,
        GuardTitle => 23,
        GuardBody => 24,
        Detail => 25,
        FirstRunTitle => 26,
        FirstRun1Lead => 27,
        FirstRun1 => 28,
        FirstRun2Lead => 29,
        FirstRun2 => 30,
        FirstRun3Lead => 31,
        FirstRun3 => 32,
        FirstRunDismiss => 33,
        LibraryTitle => 34,
        LibraryReading => 35,
        LibrarySummary { .. } => 36,
        SearchLabel => 37,
        SearchPlaceholder => 38,
        GroupByStatus => 39,
        ViewLabel => 40,
        ViewList => 41,
        GroupTopo => 42,
        GroupNoTopo => 43,
        GroupNotReady => 44,
        GroupAll => 45,
        NoSearchMatch => 46,
        Rescan => 47,
        GameListLabel { .. } => 48,
        BadgeTopo => 49,
        BadgeNoTopo => 50,
        BadgeNoIndex => 51,
        BadgeUpdating => 52,
        BadgeNotInstalled => 53,
        BadgeNotRead => 54,
        RowNoMainExe => 55,
        RowSeveralExes => 56,
        RowUpdating => 57,
        RowNotInstalled => 58,
        RowNotOpened => 59,
        RowApiUnknown => 60,
        NoSteamTitle => 61,
        NoSteamBody => 62,
        NoGamesTitle => 63,
        NoGamesBody => 64,
        ScanProblemsTitle { .. } => 65,
        ScanProblemsBody => 66,
        ShowProblems => 67,
        HideProblems => 68,
        IndexNoneTitle => 69,
        IndexNoneBody => 70,
        IndexNoKeysTitle => 71,
        IndexNoKeysBody => 72,
        IndexRefusedTitle => 73,
        IndexRefusedBody => 74,
        BackToLibrary => 75,
        GameEyebrow => 76,
        GameReading => 77,
        UnnamedGame { .. } => 78,
        HeroNoIndex => 79,
        HeroNoTopo => 80,
        HeroNoMatch => 81,
        HeroNoMatchSub => 82,
        HeroRetired => 83,
        HeroSeveral => 84,
        HeroAffects { .. } => 85,
        HeroMayOccur { .. } => 86,
        HeroNothingHere => 87,
        HeroNoFixHere => 88,
        HeroReadOnly => 89,
        HeroUpdating => 90,
        HeroNotInstalled => 91,
        HeroNoSteam => 92,
        HeroNotListed => 93,
        HeroTwice => 94,
        HeroFolder => 95,
        HeroIndexRefused => 96,
        HeroEngine => 97,
        FactsLabel => 98,
        FactSteamApp => 99,
        FactProgram => 100,
        FactGraphics => 101,
        FactTopo => 102,
        TopoRevision { .. } => 103,
        TopoActive => 104,
        TopoNeedsRetest => 105,
        TopoRetired => 106,
        TopoDraft => 107,
        NoteAntiCheat => 108,
        NoteAntiCheatUnreadable => 109,
        NoteAntiCheatReleased => 110,
        NoteSeveralGpus => 111,
        NoteNeedsRetest => 112,
        ProblemsTitle => 113,
        WhenYes => 114,
        WhenUnknown => 115,
        WhenNo => 116,
        ProblemFixes => 117,
        ProblemNoFix => 118,
        FixesTitle => 119,
        FixesIntro => 120,
        KindFix => 121,
        KindEnhancement => 122,
        StatusVerified => 123,
        StatusReported => 124,
        StatusUnverified => 125,
        FixSolves => 126,
        FixOffered => 127,
        FixNotOffered => 128,
        FixRefusedAntiCheat => 129,
        FixRefusedLaunch => 130,
        FixWarned => 131,
        FixesReadOnly => 132,
        AppliedTitle => 133,
        AppliedIntro => 134,
        AppliedEmpty => 135,
        AppliedEmptySub => 136,
        AppliedSome { .. } => 137,
        AppliedSomeSub => 138,
        AppliedUnreadable => 139,
        HistoryTitle => 140,
        HistoryIntro => 141,
        HistoryLater => 142,
        SystemTitle => 143,
        SystemIntro => 144,
        SystemReading => 145,
        SysGraphics => 146,
        SysProcessor => 147,
        SysWindows => 148,
        SysSac => 149,
        SysSteam => 150,
        SysVram { .. } => 151,
        SysIntegrated => 152,
        SysNoAdapter => 153,
        SysUnreadable => 154,
        SysCpu { .. } => 155,
        SysBuild { .. } => 156,
        SysBuildUbr { .. } => 157,
        SacOff => 158,
        SacOn => 159,
        SacEvaluation => 160,
        SacUnknown => 161,
        SteamFound { .. } => 162,
        SteamNotFound => 163,
        SettingsTitle => 164,
        SettingsIntro => 165,
        SettingsSafety => 166,
        SetPreview => 167,
        SetPreviewDesc => 168,
        SetSources => 169,
        SetSourcesDesc => 170,
        AlwaysOn => 171,
        SettingsLook => 172,
        SetTheme => 173,
        ThemeMythen => 174,
        SetLanguage => 175,
        LanguageName => 176,
        SettingsAbout => 177,
        AboutVersion => 178,
        AboutLicence => 179,
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
fn every_ordinal_is_listed() {
    let mut seen = [false; COUNT];
    for m in every() {
        seen[ordinal(m)] = true;
    }
    let missing: Vec<usize> = (0..COUNT).filter(|i| !seen[*i]).collect();
    assert!(missing.is_empty(), "ordinals not in every(): {missing:?}");
    // COUNT is right: the last variant has the highest ordinal.
    assert_eq!(ordinal(Msg::AboutLicence), COUNT - 1);
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
