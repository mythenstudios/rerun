//! The app's typed text catalogue (ADR 0027): every user-facing string is a [`Msg`] variant with
//! typed parameters, and [`t`] has one exhaustive `match` per language, so a missing
//! translation is a compile error. No Fluent, no run-time lookup.
//!
//! Parameters are numbers and trusted enums only. Untrusted text (Steam names, paths, Topo
//! texts, error details) never enters a message: the view model carries it as
//! `escape::Shown` and `ui` draws it in its own element (ADR 0016, ADR 0026).
//!
//! Copy rules (`docs/07-ui.md`): calm, direct, short; no exclamation marks, no superlatives;
//! German with "du" and "ss" (Swiss spelling). English is the base; German is complete in P5-3
//! and reviewed with P5-11.

use std::borrow::Cow;

/// A language of the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// English (the base).
    #[default]
    En,
    /// German (Switzerland: "ss").
    De,
}

impl Lang {
    /// Every language.
    #[cfg(test)]
    pub const ALL: [Self; 2] = [Self::En, Self::De];

    /// The language for a Windows UI language ID (`LANGID`): German for every German locale
    /// (primary language `LANG_GERMAN`, 0x07), English otherwise.
    pub fn from_langid(langid: u16) -> Self {
        if langid & 0x3ff == 0x07 {
            Self::De
        } else {
            Self::En
        }
    }
}

/// A status glyph. Always shown next to a word (`docs/07-ui.md`): the glyph alone carries no
/// meaning, and screen readers read the word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sym {
    /// ◆ affects this PC.
    Affects,
    /// □ a fix is available.
    Open,
    /// ■ applied.
    Applied,
    /// ○ nothing offered.
    None,
    /// ? unknown or may occur.
    Unknown,
    /// ! needs attention.
    Attention,
    /// – does not apply.
    NotHere,
    /// ✓ verified.
    Verified,
    /// ◌ not confirmed.
    Unconfirmed,
}

impl Sym {
    /// The glyph.
    pub fn glyph(self) -> &'static str {
        match self {
            Self::Affects => "\u{25C6}",
            Self::Open => "\u{25A1}",
            Self::Applied => "\u{25A0}",
            Self::None => "\u{25CB}",
            Self::Unknown => "?",
            Self::Attention => "!",
            Self::NotHere => "\u{2013}",
            Self::Verified => "\u{2713}",
            Self::Unconfirmed => "\u{25CC}",
        }
    }
}

/// Every message of the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Msg {
    // ---- window
    /// The app's name in the title bar and the window title.
    AppName,
    /// "by Mythen Studios" next to the lockup.
    ByMythen,
    /// The window button.
    Minimize,
    /// The window button.
    Maximize,
    /// The window button.
    Restore,
    /// The window button.
    Close,
    /// The label of the navigation.
    NavLabel,
    /// A section.
    NavLibrary,
    /// A section.
    NavApplied,
    /// A section.
    NavHistory,
    /// A section.
    NavSystem,
    /// A section.
    NavSettings,
    /// The status bar: rule 1.
    StatusNoBackground,
    /// The status bar: the index.
    StatusIndex {
        /// Its `seq`.
        seq: u64,
    },
    /// The status bar: no index.
    StatusIndexNone,
    /// The status bar: the index is refused.
    StatusIndexRefused,
    /// The status bar: the signature was checked.
    StatusSignatureChecked,
    /// The status bar: nothing to check.
    StatusSignatureNone,
    /// The status bar while the first scan runs.
    StatusReading,
    /// The status bar of a test-key build.
    TestKeyBuild,

    // ---- blocked
    /// The process is elevated (rule 6).
    ElevatedTitle,
    /// Its explanation.
    ElevatedBody,
    /// Its second sentence.
    ElevatedHow,
    /// A guard failed for another reason.
    GuardTitle,
    /// Its explanation.
    GuardBody,
    /// The label of an error detail (the core's English text, escaped).
    Detail,

    // ---- first launch
    /// The card's heading.
    FirstRunTitle,
    /// Sentence 1, bold part.
    FirstRun1Lead,
    /// Sentence 1.
    FirstRun1,
    /// Sentence 2, bold part.
    FirstRun2Lead,
    /// Sentence 2.
    FirstRun2,
    /// Sentence 3, bold part.
    FirstRun3Lead,
    /// Sentence 3.
    FirstRun3,
    /// Hides the card for this session.
    FirstRunDismiss,

    // ---- library
    /// The page title.
    LibraryTitle,
    /// While the scan runs.
    LibraryReading,
    /// After the scan.
    LibrarySummary {
        /// Games listed.
        games: usize,
        /// Steam libraries.
        libraries: usize,
    },
    /// The search field's label.
    SearchLabel,
    /// The search field's placeholder.
    SearchPlaceholder,
    /// The switch.
    GroupByStatus,
    /// The view selector's label.
    ViewLabel,
    /// The view.
    ViewList,
    /// A group.
    GroupTopo,
    /// A group.
    GroupNoTopo,
    /// A group.
    GroupNotReady,
    /// The one group without grouping.
    GroupAll,
    /// No game matches the search.
    NoSearchMatch,
    /// Scan again.
    Rescan,
    /// The accessible label of the game list.
    GameListLabel {
        /// Rows shown.
        shown: usize,
    },
    /// A row's badge.
    BadgeTopo,
    /// A row's badge.
    BadgeNoTopo,
    /// A row's badge without an index.
    BadgeNoIndex,
    /// A row's badge.
    BadgeUpdating,
    /// A row's badge.
    BadgeNotInstalled,
    /// A row's badge.
    BadgeNotRead,
    /// A row's second line.
    RowNoMainExe,
    /// A row's second line.
    RowSeveralExes,
    /// A row's second line.
    RowUpdating,
    /// A row's second line.
    RowNotInstalled,
    /// A row's second line.
    RowNotOpened,
    /// A row's second line: the API is not named by the imports.
    RowApiUnknown,
    /// The library: Steam not found.
    NoSteamTitle,
    /// Its explanation.
    NoSteamBody,
    /// The library: no games.
    NoGamesTitle,
    /// Its explanation.
    NoGamesBody,
    /// The library: problems while reading.
    ScanProblemsTitle {
        /// How many.
        count: usize,
    },
    /// Its explanation.
    ScanProblemsBody,
    /// Shows the problems.
    ShowProblems,
    /// Hides the problems.
    HideProblems,
    /// The library: no index.
    IndexNoneTitle,
    /// Its explanation.
    IndexNoneBody,
    /// The library: this build trusts no key yet.
    IndexNoKeysTitle,
    /// Its explanation.
    IndexNoKeysBody,
    /// The library: the stored index is refused.
    IndexRefusedTitle,
    /// Its explanation.
    IndexRefusedBody,

    // ---- game page
    /// Back to the library.
    BackToLibrary,
    /// The eyebrow above the title.
    GameEyebrow,
    /// While the game is read.
    GameReading,
    /// The game's name when Steam lists none.
    UnnamedGame {
        /// The app ID.
        app_id: u32,
    },
    /// Hero: no index.
    HeroNoIndex,
    /// Hero: no Topo.
    HeroNoTopo,
    /// Hero: no Topo matches the files.
    HeroNoMatch,
    /// Its second line.
    HeroNoMatchSub,
    /// Hero: only a retired Topo.
    HeroRetired,
    /// Hero: several Topos match.
    HeroSeveral,
    /// Hero: problems affect this PC.
    HeroAffects {
        /// Problems with a known fix that affect this PC.
        problems: usize,
        /// Fixes that can be offered.
        fixes: usize,
    },
    /// Hero: problems may occur.
    HeroMayOccur {
        /// Problems with a known fix that may occur.
        problems: usize,
        /// Fixes that can be offered.
        fixes: usize,
    },
    /// Hero: no known problem affects this PC.
    HeroNothingHere,
    /// Hero: problems, but no fix can be offered here.
    HeroNoFixHere,
    /// Hero sub line: choosing fixes comes later.
    HeroReadOnly,
    /// Hero: Steam is updating the game.
    HeroUpdating,
    /// Hero: the game is not installed.
    HeroNotInstalled,
    /// Hero: Steam is not found.
    HeroNoSteam,
    /// Hero: no library lists the game.
    HeroNotListed,
    /// Hero: two libraries list the game.
    HeroTwice,
    /// Hero: the game folder did not open.
    HeroFolder,
    /// Hero: the index is refused.
    HeroIndexRefused,
    /// Hero: the engine refuses the Topo.
    HeroEngine,
    /// The facts' accessible label.
    FactsLabel,
    /// A fact.
    FactSteamApp,
    /// A fact.
    FactProgram,
    /// A fact.
    FactGraphics,
    /// A fact.
    FactTopo,
    /// A fact's value.
    TopoRevision {
        /// The revision.
        rev: u32,
    },
    /// Topo status.
    TopoActive,
    /// Topo status.
    TopoNeedsRetest,
    /// Topo status.
    TopoRetired,
    /// Topo status.
    TopoDraft,
    /// Note: an anti-cheat system is enforced.
    NoteAntiCheat,
    /// Note: the anti-cheat could not be checked fully.
    NoteAntiCheatUnreadable,
    /// Note: the anti-cheat is released as inactive.
    NoteAntiCheatReleased,
    /// Note: several graphics adapters.
    NoteSeveralGpus,
    /// Note: the Topo is to be tested again.
    NoteNeedsRetest,
    /// The heading.
    ProblemsTitle,
    /// The issue applies.
    WhenYes,
    /// The issue may apply.
    WhenUnknown,
    /// The issue does not apply.
    WhenNo,
    /// The fixes of an issue, before the list.
    ProblemFixes,
    /// An issue without a fix.
    ProblemNoFix,
    /// The heading.
    FixesTitle,
    /// The explanation under it.
    FixesIntro,
    /// The kind.
    KindFix,
    /// The kind.
    KindEnhancement,
    /// The evidence.
    StatusVerified,
    /// The evidence.
    StatusReported,
    /// The evidence.
    StatusUnverified,
    /// Before the issues a fix solves.
    FixSolves,
    /// A fix is offered.
    FixOffered,
    /// A fix is not offered.
    FixNotOffered,
    /// A fix is refused: anti-cheat.
    FixRefusedAntiCheat,
    /// A fix is refused: the launch cannot carry it.
    FixRefusedLaunch,
    /// The anti-cheat rule warns about a fix.
    FixWarned,
    /// Fixes cannot be chosen in this version.
    FixesReadOnly,

    // ---- applied, history, system, settings
    /// The page title.
    AppliedTitle,
    /// The page's intro.
    AppliedIntro,
    /// Nothing applied.
    AppliedEmpty,
    /// Its second line.
    AppliedEmptySub,
    /// Open transactions exist (shown in P5-5a).
    AppliedSome {
        /// How many.
        count: usize,
    },
    /// Its second line.
    AppliedSomeSub,
    /// The journal could not be read.
    AppliedUnreadable,
    /// The page title.
    HistoryTitle,
    /// The page's intro.
    HistoryIntro,
    /// The placeholder.
    HistoryLater,
    /// The page title.
    SystemTitle,
    /// The page's intro.
    SystemIntro,
    /// While the profile is read.
    SystemReading,
    /// A label.
    SysGraphics,
    /// A label.
    SysProcessor,
    /// A label.
    SysWindows,
    /// A label.
    SysSac,
    /// A label.
    SysSteam,
    /// A value: adapter memory.
    SysVram {
        /// MiB.
        mb: u64,
    },
    /// A value: integrated.
    SysIntegrated,
    /// A value: no hardware adapter.
    SysNoAdapter,
    /// A value: could not be read.
    SysUnreadable,
    /// A value: the CPU layout.
    SysCpu {
        /// Logical processors.
        threads: usize,
        /// Cores.
        cores: usize,
        /// Last-level cache groups.
        groups: usize,
    },
    /// A value: the Windows build.
    SysBuild {
        /// The build.
        build: u32,
    },
    /// A value: the Windows build with its revision.
    SysBuildUbr {
        /// The build.
        build: u32,
        /// The revision.
        ubr: u32,
    },
    /// A value.
    SacOff,
    /// A value.
    SacOn,
    /// A value.
    SacEvaluation,
    /// A value.
    SacUnknown,
    /// A value: Steam found.
    SteamFound {
        /// Libraries.
        libraries: usize,
    },
    /// A value: Steam not found.
    SteamNotFound,
    /// The page title.
    SettingsTitle,
    /// The page's intro.
    SettingsIntro,
    /// A group.
    SettingsSafety,
    /// A setting.
    SetPreview,
    /// Its description.
    SetPreviewDesc,
    /// A setting.
    SetSources,
    /// Its description.
    SetSourcesDesc,
    /// The state of a fixed setting.
    AlwaysOn,
    /// A group.
    SettingsLook,
    /// A setting.
    SetTheme,
    /// Its value.
    ThemeMythen,
    /// A setting.
    SetLanguage,
    /// Its value.
    LanguageName,
    /// A group.
    SettingsAbout,
    /// The version line.
    AboutVersion,
    /// The licence line.
    AboutLicence,
}

/// The text of `m` in `lang`.
pub fn t(lang: Lang, m: Msg) -> Cow<'static, str> {
    match lang {
        Lang::En => en(m),
        Lang::De => de(m),
    }
}

/// `n` with the singular or plural form.
fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

fn en(m: Msg) -> Cow<'static, str> {
    use Msg::*;
    let s: &'static str = match m {
        AppName => "Rerun",
        ByMythen => "by Mythen Studios",
        Minimize => "Minimize",
        Maximize => "Maximize",
        Restore => "Restore",
        Close => "Close",
        NavLabel => "Sections",
        NavLibrary => "Library",
        NavApplied => "Applied",
        NavHistory => "History",
        NavSystem => "System",
        NavSettings => "Settings",
        StatusNoBackground => "No background process",
        StatusIndex { seq } => return format!("Topo index {seq}").into(),
        StatusIndexNone => "No Topo index",
        StatusIndexRefused => "Topo index refused",
        StatusSignatureChecked => "Signature checked",
        StatusSignatureNone => "No signature to check",
        StatusReading => "Reading",
        TestKeyBuild => "Test key build, not for release",
        ElevatedTitle => "Rerun runs as administrator.",
        ElevatedBody => {
            "Start it normally. Rerun never runs with administrator rights and reads nothing while it does."
        }
        ElevatedHow => {
            "Close this window and open Rerun again without \u{201C}Run as administrator\u{201D}."
        }
        GuardTitle => "Rerun cannot read its folders.",
        GuardBody => "Rerun stops here and changes nothing.",
        Detail => "Detail",
        FirstRunTitle => "How Rerun works",
        FirstRun1Lead => "Nothing runs in the background.",
        FirstRun1 => {
            "Rerun is no service and does not start with Windows. It runs only while you have it open, and at most as long as a game you start with Rerun."
        }
        FirstRun2Lead => "Everything can be undone.",
        FirstRun2 => {
            "Before every change Rerun shows you exactly what happens and writes it to its journal. Undo restores the state from before."
        }
        FirstRun3Lead => "Only verified sources.",
        FirstRun3 => {
            "Fixes come from a signed index with a fixed version and checksum. Rerun downloads nothing from arbitrary sites."
        }
        FirstRunDismiss => "Got it",
        LibraryTitle => "Library",
        LibraryReading => "Reading the Steam libraries.",
        LibrarySummary { games, libraries } => {
            return format!(
                "{} in {}. Choose a game to see what is wrong.",
                count(games, "game", "games"),
                count(libraries, "Steam library", "Steam libraries")
            )
            .into();
        }
        SearchLabel => "Search games",
        SearchPlaceholder => "Type a name",
        GroupByStatus => "Group by status",
        ViewLabel => "View",
        ViewList => "List",
        GroupTopo => "Topo available",
        GroupNoTopo => "No Topo, nothing offered",
        GroupNotReady => "Not ready",
        GroupAll => "All games",
        NoSearchMatch => "No game matches the search.",
        Rescan => "Scan again",
        GameListLabel { shown } => {
            return format!("Games, {}", count(shown, "entry", "entries")).into();
        }
        BadgeTopo => "Topo",
        BadgeNoTopo => "No Topo",
        BadgeNoIndex => "No Topo list",
        BadgeUpdating => "Updating",
        BadgeNotInstalled => "Not installed",
        BadgeNotRead => "Not read",
        RowNoMainExe => "No game program found",
        RowSeveralExes => "Several game programs",
        RowUpdating => "Steam is updating this game",
        RowNotInstalled => "Listed by Steam, not installed",
        RowNotOpened => "The game folder could not be read",
        RowApiUnknown => "Graphics not recognised",
        NoSteamTitle => "Steam was not found.",
        NoSteamBody => {
            "Rerun reads the Steam libraries of this Windows account. Other stores follow later."
        }
        NoGamesTitle => "No games found.",
        NoGamesBody => "The Steam libraries list no installed game.",
        ScanProblemsTitle { count: n } => {
            return format!("{} while reading.", count(n, "problem", "problems")).into();
        }
        ScanProblemsBody => "Rerun skipped what it could not read and listed the rest.",
        ShowProblems => "Show problems",
        HideProblems => "Hide problems",
        IndexNoneTitle => "Rerun has no Topo list yet.",
        IndexNoneBody => {
            "Without the signed Topo index Rerun offers no fix and changes nothing. The games are listed anyway."
        }
        IndexNoKeysTitle => "This build of Rerun trusts no index key yet.",
        IndexNoKeysBody => {
            "Every Topo index is refused until a release key is built in. Rerun offers no fix and changes nothing."
        }
        IndexRefusedTitle => "The stored Topo index is refused.",
        IndexRefusedBody => {
            "Rerun offers no fix until a valid index is imported. Nothing was changed."
        }
        BackToLibrary => "Library",
        GameEyebrow => "Game \u{00B7} Steam",
        GameReading => "Reading the game folder.",
        UnnamedGame { app_id } => return format!("Steam app {app_id}").into(),
        HeroNoIndex => "Rerun has no Topo list yet. It offers nothing and changes nothing.",
        HeroNoTopo => "There is no Topo for this game. Rerun offers nothing and changes nothing.",
        HeroNoMatch => "Rerun does not know this version of the game.",
        HeroNoMatchSub => {
            "The Topo describes other files. Rerun never guesses, so it offers nothing."
        }
        HeroRetired => "The Topo for this game was retired. Rerun offers nothing.",
        HeroSeveral => "Several Topos fit this game. Rerun chooses none and offers nothing.",
        HeroAffects { problems, fixes } => {
            return format!(
                "{} {} your PC \u{00B7} {} available",
                count(problems, "problem", "problems"),
                if problems == 1 { "affects" } else { "affect" },
                count(fixes, "fix", "fixes")
            )
            .into();
        }
        HeroMayOccur { problems, fixes } => {
            return format!(
                "{} can occur \u{00B7} {} available",
                count(problems, "known problem", "known problems"),
                count(fixes, "fix", "fixes")
            )
            .into();
        }
        HeroNothingHere => "No known problem affects this PC.",
        HeroNoFixHere => "Rerun cannot offer a fix on this PC.",
        HeroReadOnly => "Choosing and applying fixes comes with the next version of the app.",
        HeroUpdating => "Steam is updating this game. Open it again when the update is done.",
        HeroNotInstalled => "This game is listed by Steam but not installed.",
        HeroNoSteam => "Steam was not found, so Rerun cannot read this game.",
        HeroNotListed => "No Steam library lists this game any more.",
        HeroTwice => "Two Steam libraries list this game. Rerun does not guess which one counts.",
        HeroFolder => "Rerun cannot open the game folder.",
        HeroIndexRefused => "The stored Topo index is refused. Rerun offers nothing.",
        HeroEngine => "The Topo cannot be checked on this PC. Rerun offers nothing.",
        FactsLabel => "Technical details",
        FactSteamApp => "Steam app",
        FactProgram => "Program",
        FactGraphics => "Graphics",
        FactTopo => "Topo",
        TopoRevision { rev } => return format!("Revision {rev}").into(),
        TopoActive => "active",
        TopoNeedsRetest => "to be tested again",
        TopoRetired => "retired",
        TopoDraft => "draft",
        NoteAntiCheat => {
            "Anti-cheat found: fixes that change how the game starts or runs are not offered."
        }
        NoteAntiCheatUnreadable => "An anti-cheat marker could not be checked and counts as found.",
        NoteAntiCheatReleased => "Anti-cheat found, but the Topo lists it as no longer active.",
        NoteSeveralGpus => {
            "This PC has several graphics adapters. Rerun does not know which one the game uses, so graphics conditions stay open."
        }
        NoteNeedsRetest => "This Topo is due for a new test.",
        ProblemsTitle => "Problems on this PC",
        WhenYes => "Affects this PC",
        WhenUnknown => "May occur",
        WhenNo => "Does not affect this PC",
        ProblemFixes => "Fixes for it",
        ProblemNoFix => "No known fix.",
        FixesTitle => "Fixes",
        FixesIntro => {
            "One fix can solve several problems. It is listed once, with every problem it solves."
        }
        KindFix => "Fix",
        KindEnhancement => "Enhancement",
        StatusVerified => "Verified",
        StatusReported => "Reported",
        StatusUnverified => "Not confirmed",
        FixSolves => "Solves",
        FixOffered => "Available",
        FixNotOffered => "Not offered",
        FixRefusedAntiCheat => "Not offered: an anti-cheat system was found.",
        FixRefusedLaunch => "Not offered: the way this game starts cannot carry this fix.",
        FixWarned => "The anti-cheat rule allows this fix with a warning.",
        FixesReadOnly => "Fixes cannot be chosen yet in this version.",
        AppliedTitle => "Applied",
        AppliedIntro => "Everything Rerun has changed on your games.",
        AppliedEmpty => "Nothing applied",
        AppliedEmptySub => "Your games are unchanged.",
        AppliedSome { count: n } => {
            return format!("{} in the journal", count(n, "open change", "open changes")).into();
        }
        AppliedSomeSub => {
            "The list with undo comes with the next version of the app. The command line shows it: rerun status."
        }
        AppliedUnreadable => "The journal could not be read.",
        HistoryTitle => "History",
        HistoryIntro => "The journal. Rerun writes every entry before it changes anything.",
        HistoryLater => "The history comes with the next version of the app.",
        SystemTitle => "System",
        SystemIntro => {
            "Rerun reads these facts when you open this page. They decide which problems fit your PC."
        }
        SystemReading => "Reading the system.",
        SysGraphics => "Graphics",
        SysProcessor => "Processor",
        SysWindows => "Windows",
        SysSac => "Smart App Control",
        SysSteam => "Steam",
        SysVram { mb } => return format!("{mb} MiB video memory").into(),
        SysIntegrated => "integrated",
        SysNoAdapter => "No hardware graphics adapter",
        SysUnreadable => "Could not be read",
        SysCpu {
            threads,
            cores,
            groups,
        } => {
            return format!(
                "{} \u{00B7} {} \u{00B7} {}",
                count(threads, "logical processor", "logical processors"),
                count(cores, "core", "cores"),
                count(groups, "cache group", "cache groups")
            )
            .into();
        }
        SysBuild { build } => return format!("Build {build}").into(),
        SysBuildUbr { build, ubr } => return format!("Build {build}.{ubr}").into(),
        SacOff => "Off",
        SacOn => "On",
        SacEvaluation => "Evaluation",
        SacUnknown => "Unknown",
        SteamFound { libraries } => {
            return format!("Found, {}", count(libraries, "library", "libraries")).into();
        }
        SteamNotFound => "Not found",
        SettingsTitle => "Settings",
        SettingsIntro => "More settings follow with the next versions of the app.",
        SettingsSafety => "Safety",
        SetPreview => "Preview before every change",
        SetPreviewDesc => "Always on. Rerun changes nothing you have not seen first.",
        SetSources => "Only sources from the signed index",
        SetSourcesDesc => "Always on. Downloads only with a fixed version and checksum.",
        AlwaysOn => "Always on",
        SettingsLook => "Appearance",
        SetTheme => "Theme",
        ThemeMythen => "Mythen",
        SetLanguage => "Language",
        LanguageName => "English (follows Windows)",
        SettingsAbout => "About Rerun",
        AboutVersion => "Rerun \u{00B7} by Mythen Studios",
        AboutLicence => {
            "Free software under the GNU General Public License, version 3. No warranty."
        }
    };
    Cow::Borrowed(s)
}

fn de(m: Msg) -> Cow<'static, str> {
    use Msg::*;
    let s: &'static str = match m {
        AppName => "Rerun",
        ByMythen => "by Mythen Studios",
        Minimize => "Minimieren",
        Maximize => "Maximieren",
        Restore => "Wiederherstellen",
        Close => "Schliessen",
        NavLabel => "Bereiche",
        NavLibrary => "Bibliothek",
        NavApplied => "Angewendet",
        NavHistory => "Verlauf",
        NavSystem => "System",
        NavSettings => "Einstellungen",
        StatusNoBackground => "Kein Hintergrundprozess",
        StatusIndex { seq } => return format!("Topo-Index {seq}").into(),
        StatusIndexNone => "Kein Topo-Index",
        StatusIndexRefused => "Topo-Index abgelehnt",
        StatusSignatureChecked => "Signatur geprüft",
        StatusSignatureNone => "Keine Signatur zu prüfen",
        StatusReading => "Liest ein",
        TestKeyBuild => "Testschlüssel-Build, nicht zur Weitergabe",
        ElevatedTitle => "Rerun läuft als Administrator.",
        ElevatedBody => {
            "Starte es normal. Rerun läuft nie mit Administratorrechten und liest so auch nichts ein."
        }
        ElevatedHow => {
            "Schliesse dieses Fenster und öffne Rerun ohne \u{AB}Als Administrator ausführen\u{BB}."
        }
        GuardTitle => "Rerun kann seine Ordner nicht lesen.",
        GuardBody => "Rerun hört hier auf und ändert nichts.",
        Detail => "Detail",
        FirstRunTitle => "So arbeitet Rerun",
        FirstRun1Lead => "Nichts läuft im Hintergrund.",
        FirstRun1 => {
            "Rerun ist kein Dienst und startet nicht mit Windows. Es läuft nur, wenn du es öffnest, und höchstens so lange wie ein Spiel, das du mit Rerun startest."
        }
        FirstRun2Lead => "Alles lässt sich rückgängig machen.",
        FirstRun2 => {
            "Vor jeder Änderung zeigt dir Rerun genau, was passiert, und schreibt es ins Journal. Rückgängig stellt den Zustand davor wieder her."
        }
        FirstRun3Lead => "Nur geprüfte Quellen.",
        FirstRun3 => {
            "Fixes kommen aus einem signierten Index mit fester Version und Prüfsumme. Rerun lädt nichts von beliebigen Seiten."
        }
        FirstRunDismiss => "Verstanden",
        LibraryTitle => "Bibliothek",
        LibraryReading => "Rerun liest die Steam-Bibliotheken ein.",
        LibrarySummary { games, libraries } => {
            return format!(
                "{} in {}. Wähle ein Spiel, um zu sehen, was nicht stimmt.",
                count(games, "Spiel", "Spiele"),
                count(libraries, "Steam-Bibliothek", "Steam-Bibliotheken")
            )
            .into();
        }
        SearchLabel => "Spiel suchen",
        SearchPlaceholder => "Name eingeben",
        GroupByStatus => "Nach Status gruppieren",
        ViewLabel => "Ansicht",
        ViewList => "Liste",
        GroupTopo => "Topo vorhanden",
        GroupNoTopo => "Ohne Topo, nichts angeboten",
        GroupNotReady => "Nicht bereit",
        GroupAll => "Alle Spiele",
        NoSearchMatch => "Kein Spiel passt zur Suche.",
        Rescan => "Neu einlesen",
        GameListLabel { shown } => {
            return format!("Spiele, {}", count(shown, "Eintrag", "Einträge")).into();
        }
        BadgeTopo => "Topo",
        BadgeNoTopo => "Kein Topo",
        BadgeNoIndex => "Keine Topo-Liste",
        BadgeUpdating => "Wird aktualisiert",
        BadgeNotInstalled => "Nicht installiert",
        BadgeNotRead => "Nicht gelesen",
        RowNoMainExe => "Kein Spielprogramm gefunden",
        RowSeveralExes => "Mehrere Spielprogramme",
        RowUpdating => "Steam aktualisiert dieses Spiel",
        RowNotInstalled => "Bei Steam eingetragen, nicht installiert",
        RowNotOpened => "Der Spielordner liess sich nicht lesen",
        RowApiUnknown => "Grafik nicht erkannt",
        NoSteamTitle => "Steam wurde nicht gefunden.",
        NoSteamBody => {
            "Rerun liest die Steam-Bibliotheken dieses Windows-Kontos. Andere Stores folgen später."
        }
        NoGamesTitle => "Keine Spiele gefunden.",
        NoGamesBody => "In den Steam-Bibliotheken ist kein installiertes Spiel eingetragen.",
        ScanProblemsTitle { count: n } => {
            return format!("{} beim Einlesen.", count(n, "Problem", "Probleme")).into();
        }
        ScanProblemsBody => {
            "Rerun hat übersprungen, was es nicht lesen konnte, und den Rest aufgelistet."
        }
        ShowProblems => "Probleme zeigen",
        HideProblems => "Probleme ausblenden",
        IndexNoneTitle => "Rerun hat noch keine Topo-Liste.",
        IndexNoneBody => {
            "Ohne den signierten Topo-Index bietet Rerun keinen Fix an und ändert nichts. Die Spiele stehen trotzdem da."
        }
        IndexNoKeysTitle => "Dieser Build von Rerun vertraut noch keinem Index-Schlüssel.",
        IndexNoKeysBody => {
            "Jeder Topo-Index wird abgelehnt, bis ein Release-Schlüssel eingebaut ist. Rerun bietet keinen Fix an und ändert nichts."
        }
        IndexRefusedTitle => "Der gespeicherte Topo-Index wird abgelehnt.",
        IndexRefusedBody => {
            "Rerun bietet keinen Fix an, bis ein gültiger Index importiert ist. Nichts wurde verändert."
        }
        BackToLibrary => "Bibliothek",
        GameEyebrow => "Spiel \u{00B7} Steam",
        GameReading => "Rerun liest den Spielordner ein.",
        UnnamedGame { app_id } => return format!("Steam-App {app_id}").into(),
        HeroNoIndex => "Rerun hat noch keine Topo-Liste. Es bietet nichts an und ändert nichts.",
        HeroNoTopo => {
            "Für dieses Spiel gibt es keinen Topo. Rerun bietet nichts an und ändert nichts."
        }
        HeroNoMatch => "Rerun kennt diese Version des Spiels nicht.",
        HeroNoMatchSub => {
            "Der Topo beschreibt andere Dateien. Rerun rät nie und bietet deshalb nichts an."
        }
        HeroRetired => "Der Topo für dieses Spiel wurde zurückgezogen. Rerun bietet nichts an.",
        HeroSeveral => {
            "Mehrere Topos passen zu diesem Spiel. Rerun wählt keinen und bietet nichts an."
        }
        HeroAffects { problems, fixes } => {
            return format!(
                "{} {} deinen PC \u{00B7} {} verfügbar",
                count(problems, "Problem", "Probleme"),
                if problems == 1 {
                    "betrifft"
                } else {
                    "betreffen"
                },
                count(fixes, "Fix", "Fixes")
            )
            .into();
        }
        HeroMayOccur { problems, fixes } => {
            return format!(
                "{} {} auftreten \u{00B7} {} verfügbar",
                count(problems, "bekanntes Problem", "bekannte Probleme"),
                if problems == 1 { "kann" } else { "können" },
                count(fixes, "Fix", "Fixes")
            )
            .into();
        }
        HeroNothingHere => "Kein bekanntes Problem betrifft diesen PC.",
        HeroNoFixHere => "Rerun kann auf diesem PC keinen Fix anbieten.",
        HeroReadOnly => "Fixes auswählen und anwenden kommt mit der nächsten Version der App.",
        HeroUpdating => {
            "Steam aktualisiert dieses Spiel. Öffne es wieder, wenn das Update fertig ist."
        }
        HeroNotInstalled => "Dieses Spiel ist bei Steam eingetragen, aber nicht installiert.",
        HeroNoSteam => "Steam wurde nicht gefunden, deshalb kann Rerun dieses Spiel nicht lesen.",
        HeroNotListed => "Keine Steam-Bibliothek führt dieses Spiel mehr.",
        HeroTwice => "Zwei Steam-Bibliotheken führen dieses Spiel. Rerun rät nicht, welche gilt.",
        HeroFolder => "Rerun kann den Spielordner nicht öffnen.",
        HeroIndexRefused => "Der gespeicherte Topo-Index wird abgelehnt. Rerun bietet nichts an.",
        HeroEngine => "Der Topo lässt sich auf diesem PC nicht prüfen. Rerun bietet nichts an.",
        FactsLabel => "Technische Angaben",
        FactSteamApp => "Steam-App",
        FactProgram => "Programm",
        FactGraphics => "Grafik",
        FactTopo => "Topo",
        TopoRevision { rev } => return format!("Revision {rev}").into(),
        TopoActive => "aktiv",
        TopoNeedsRetest => "neu zu prüfen",
        TopoRetired => "zurückgezogen",
        TopoDraft => "Entwurf",
        NoteAntiCheat => {
            "Anti-Cheat gefunden: Fixes, die ändern, wie das Spiel startet oder läuft, werden nicht angeboten."
        }
        NoteAntiCheatUnreadable => {
            "Ein Anti-Cheat-Merkmal liess sich nicht prüfen und gilt als gefunden."
        }
        NoteAntiCheatReleased => {
            "Anti-Cheat gefunden, der Topo führt es aber als nicht mehr aktiv."
        }
        NoteSeveralGpus => {
            "Dieser PC hat mehrere Grafikkarten. Rerun weiss nicht, welche das Spiel nutzt, deshalb bleiben Grafikbedingungen offen."
        }
        NoteNeedsRetest => "Dieser Topo soll neu geprüft werden.",
        ProblemsTitle => "Probleme auf diesem PC",
        WhenYes => "Betrifft diesen PC",
        WhenUnknown => "Kann auftreten",
        WhenNo => "Betrifft diesen PC nicht",
        ProblemFixes => "Fixes dafür",
        ProblemNoFix => "Kein bekannter Fix.",
        FixesTitle => "Fixes",
        FixesIntro => {
            "Ein Fix kann mehrere Probleme beheben. Er steht einmal da, mit allen Problemen, die er behebt."
        }
        KindFix => "Fix",
        KindEnhancement => "Verbesserung",
        StatusVerified => "Bestätigt",
        StatusReported => "Gemeldet",
        StatusUnverified => "Nicht bestätigt",
        FixSolves => "Behebt",
        FixOffered => "Verfügbar",
        FixNotOffered => "Nicht angeboten",
        FixRefusedAntiCheat => "Nicht angeboten: Ein Anti-Cheat-System wurde gefunden.",
        FixRefusedLaunch => {
            "Nicht angeboten: So, wie dieses Spiel startet, lässt sich dieser Fix nicht anwenden."
        }
        FixWarned => "Die Anti-Cheat-Regel erlaubt diesen Fix mit einem Hinweis.",
        FixesReadOnly => "In dieser Version lassen sich Fixes noch nicht auswählen.",
        AppliedTitle => "Angewendet",
        AppliedIntro => "Alles, was Rerun an deinen Spielen geändert hat.",
        AppliedEmpty => "Nichts angewendet",
        AppliedEmptySub => "Deine Spiele sind unverändert.",
        AppliedSome { count: n } => {
            return format!(
                "{} im Journal",
                count(n, "offene Änderung", "offene Änderungen")
            )
            .into();
        }
        AppliedSomeSub => {
            "Die Liste mit Rückgängig kommt mit der nächsten Version der App. Die Kommandozeile zeigt sie: rerun status."
        }
        AppliedUnreadable => "Das Journal liess sich nicht lesen.",
        HistoryTitle => "Verlauf",
        HistoryIntro => "Das Journal. Rerun schreibt jeden Eintrag, bevor es etwas ändert.",
        HistoryLater => "Der Verlauf kommt mit der nächsten Version der App.",
        SystemTitle => "System",
        SystemIntro => {
            "Diese Angaben liest Rerun, wenn du diese Seite öffnest. Danach richtet sich, welche Probleme zu deinem PC passen."
        }
        SystemReading => "Rerun liest das System ein.",
        SysGraphics => "Grafik",
        SysProcessor => "Prozessor",
        SysWindows => "Windows",
        SysSac => "Smart App Control",
        SysSteam => "Steam",
        SysVram { mb } => return format!("{mb} MiB Grafikspeicher").into(),
        SysIntegrated => "integriert",
        SysNoAdapter => "Keine Hardware-Grafikkarte",
        SysUnreadable => "Liess sich nicht lesen",
        SysCpu {
            threads,
            cores,
            groups,
        } => {
            return format!(
                "{} \u{00B7} {} \u{00B7} {}",
                count(threads, "logischer Prozessor", "logische Prozessoren"),
                count(cores, "Kern", "Kerne"),
                count(groups, "Cache-Gruppe", "Cache-Gruppen")
            )
            .into();
        }
        SysBuild { build } => return format!("Build {build}").into(),
        SysBuildUbr { build, ubr } => return format!("Build {build}.{ubr}").into(),
        SacOff => "Aus",
        SacOn => "Ein",
        SacEvaluation => "Auswertung",
        SacUnknown => "Unbekannt",
        SteamFound { libraries } => {
            return format!(
                "Gefunden, {}",
                count(libraries, "Bibliothek", "Bibliotheken")
            )
            .into();
        }
        SteamNotFound => "Nicht gefunden",
        SettingsTitle => "Einstellungen",
        SettingsIntro => "Weitere Einstellungen folgen mit den nächsten Versionen der App.",
        SettingsSafety => "Sicherheit",
        SetPreview => "Vorschau vor jeder Änderung",
        SetPreviewDesc => "Immer an. Rerun ändert nichts, ohne dass du es vorher gesehen hast.",
        SetSources => "Nur Quellen aus dem signierten Index",
        SetSourcesDesc => "Immer an. Downloads nur mit fester Version und Prüfsumme.",
        AlwaysOn => "Immer an",
        SettingsLook => "Darstellung",
        SetTheme => "Thema",
        ThemeMythen => "Mythen",
        SetLanguage => "Sprache",
        LanguageName => "Deutsch (wie Windows)",
        SettingsAbout => "Über Rerun",
        AboutVersion => "Rerun \u{00B7} by Mythen Studios",
        AboutLicence => {
            "Freie Software unter der GNU General Public License, Version 3. Ohne Gewährleistung."
        }
    };
    Cow::Borrowed(s)
}

#[cfg(test)]
mod tests;
