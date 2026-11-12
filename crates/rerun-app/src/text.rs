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

    /// The select control of a fix.
    FixSelect,
    /// A fix that needs the elevated helper, which is not installed safely.
    FixNeedsHelper,
    /// A fix that needs a package download.
    FixNeedsDownload,
    /// Label of a fix's side effects.
    FixTradeoffs,
    /// No side effect is listed.
    FixNoTradeoffs,
    /// Label of a fix's sources.
    FixSources,
    /// The fix cannot be combined with these.
    FixExclusive,
    /// Why a fix is preselected.
    FixPreselected,
    /// A source type.
    SourceRepo,
    /// A source type.
    SourceSteamGuide,
    /// A source type.
    SourceSteamThread,
    /// A source type.
    SourcePcgw,
    /// A source type.
    SourceOfficial,
    /// Heading of the preview.
    PreviewTitle,
    /// No fix is selected.
    PreviewNone,
    /// The preview is being made.
    PreviewPlanning,
    /// Under the heading of a preview.
    PreviewIntro,
    /// The number of changes of a plan.
    PreviewChanges {
        /// A number.
        n: usize,
    },
    /// Label.
    PreviewGameFolder,
    /// Label of the plan hash.
    PreviewChecksum,
    /// The plan needs no administrator rights.
    PreviewAdminNo,
    /// What undo does with a plan.
    PreviewUndo {
        /// The plan writes a launch profile.
        profile: bool,
    },
    /// Before an apply.
    PreviewCloseGame,
    /// While a write runs.
    PreviewApplying,
    /// A button.
    BtnApply,
    /// A button.
    BtnCancel,
    /// A button.
    BtnDismiss,
    /// A button.
    BtnUndo,
    /// A button.
    BtnForget,
    /// An action.
    ActCreateFolder,
    /// An action.
    ActCreateFile,
    /// An action.
    ActReplaceFile,
    /// An action.
    ActPatchFile,
    /// An action.
    ActCreateKey,
    /// An action.
    ActSetValue,
    /// An action.
    ActAddTokens,
    /// An action.
    ActGpuPref,
    /// An action.
    ActEditIni,
    /// An action.
    ActFirewall,
    /// An action.
    ActHold,
    /// An action.
    ActOther,
    /// A label.
    LblFrom,
    /// A label.
    LblNew,
    /// A label.
    LblOld,
    /// A label.
    LblValue,
    /// A label.
    LblValueNow,
    /// A label.
    LblValueNew,
    /// A label.
    LblAdds,
    /// A label.
    LblIniKey,
    /// A label.
    LblProfile,
    /// A label.
    LblCpuRule,
    /// A label.
    LblPriority,
    /// A label.
    LblStart,
    /// A label.
    LblTarget,
    /// A label.
    LblPatch,
    /// A label.
    LblUndo,
    /// A kept shared file.
    HeldLine,
    /// An old INI value.
    IniMissing,
    /// An old INI value.
    IniNewSection,
    /// A size.
    Bytes {
        /// A number.
        n: u64,
    },
    /// One patched byte.
    PatchByte {
        /// A number.
        offset: u64,
        /// A number.
        old: u8,
        /// A number.
        new: u8,
    },
    /// What undo does.
    UndoRemoves,
    /// What undo does.
    UndoRestoresFile,
    /// What undo does.
    UndoRestoresValue,
    /// What undo does.
    UndoRemovesTokens,
    /// What undo does.
    UndoSetsKeys,
    /// What undo does.
    UndoKeepsShared,
    /// What undo does.
    UndoRemovesRule,
    /// A note.
    NoteNotRestored,
    /// A note.
    NoteRegistry,
    /// A note.
    NoteLayers,
    /// A note.
    NoteIni,
    /// A note.
    NoteProfile,
    /// A note.
    NoteProfileWatch,
    /// A note.
    NoteFirewall,
    /// A note.
    NoteHold,
    /// A note.
    NotePatch,
    /// A note.
    NoteGpuPref,
    /// A note.
    NoteUserData,
    /// The word of a warning.
    WarningWord,
    /// A warning.
    WarnSacOn,
    /// A warning.
    WarnSacEvaluation,
    /// A warning.
    WarnSacUnknown,
    /// A warning.
    WarnSteamPerUser,
    /// A warning.
    WarnSignedExe,
    /// A warning.
    WarnWhenUnknown,
    /// A warning.
    WarnNeedsRetest,
    /// A warning.
    WarnAntiCheat,
    /// A warning.
    WarnGpuSet,
    /// A warning.
    WarnRequiresGpu,
    /// A warning.
    WarnSteamInput,
    /// A warning.
    WarnVsCopy,
    /// A warning.
    WarnVsLink,
    /// A warning.
    WarnVsUnchecked,
    /// Heading.
    LaunchHeading,
    /// The CPU limit on this PC.
    LaunchCpu {
        /// A number.
        threads: u16,
        /// A number.
        of: u16,
    },
    /// No CPU rule.
    LaunchCpuNone,
    /// The selection is unknown.
    LaunchCpuUnknown,
    /// The launch option.
    LaunchOptionIntro,
    /// The launch option.
    LaunchOptionCombine,
    /// The launch option.
    LaunchOptionByHand,
    /// The launch option.
    LaunchShimStays,
    /// A launch problem.
    LaunchShimMissing,
    /// A launch problem.
    LaunchShimUnchecked,
    /// A launch problem.
    LaunchInstallUnknown,
    /// A launch problem.
    LaunchNotShowable,
    /// A button.
    LaunchCopy,
    /// After the copy.
    LaunchCopied,
    /// What a card's undo takes back.
    CardNote {
        /// A number.
        n: usize,
        /// The transaction writes a launch profile.
        profile: bool,
    },
    /// A label.
    CardGame,
    /// A label.
    CardTxn,
    /// A state.
    StateApplied,
    /// A state.
    StateInterrupted,
    /// A state.
    StateCleanup,
    /// A state.
    StateDamaged,
    /// A state.
    StateUnreadable,
    /// A state.
    StateForeign,
    /// A card's problem.
    ProblemInterrupted,
    /// A card's problem.
    ProblemCleanup,
    /// A card's problem.
    ProblemDamaged,
    /// A card's problem.
    ProblemUnreadable,
    /// A card's problem.
    ProblemForeign,
    /// Heading on a game page.
    AppliedHere,
    /// A card without steps.
    CardNoOps,
    /// The undo dialog.
    UndoTitle,
    /// The undo dialog.
    UndoIntro,
    /// The undo dialog.
    UndoCloseGame,
    /// What undo meets.
    FateBefore,
    /// What undo meets.
    FateAfter,
    /// What undo meets.
    FateDrifted,
    /// What undo meets.
    FateForeign,
    /// What undo meets.
    FateKept,
    /// What undo meets.
    FateNotReached,
    /// Where undo would stop.
    UndoHalt {
        /// A number.
        op: u16,
    },
    /// Copies undo deletes.
    UndoCleanup {
        /// A number.
        n: usize,
        /// A number.
        in_use: usize,
    },
    /// An empty record.
    UndoEmpty,
    /// An undo that needs the helper, which is not installed safely.
    UndoPrompt,
    /// Heading.
    UndoAfter,
    /// The launch option after an undo.
    LaunchFateGone,
    /// The launch option after an undo.
    LaunchUntilRemoved,
    /// The launch option after an undo.
    LaunchFatePrev,
    /// The launch option after an undo.
    LaunchFateStays,
    /// The launch option after an undo.
    LaunchFateLeft,
    /// After a changed preview.
    ChangedNote,
    /// The confirm button.
    UndoBtn,
    /// The forget dialog.
    ForgetTitle,
    /// The forget dialog.
    ForgetIntro,
    /// The forget dialog.
    ForgetWould,
    /// The forget dialog.
    ForgetNow,
    /// A result.
    ResAppliedTitle,
    /// A result.
    ResAppliedBody,
    /// A result.
    ResNothingTitle,
    /// A result.
    ResNothingBody,
    /// A result.
    ResRolledBackTitle,
    /// A result.
    ResRolledBackBody,
    /// A result.
    ResOpenTitle,
    /// A result: the rollback did not finish (LeftOpen).
    ResOpenBody,
    /// A result.
    ResRevertedTitle,
    /// A result.
    ResRevertedBody,
    /// A result.
    ResHaltedTitle,
    /// A result.
    ResHaltedBody,
    /// A result.
    ResInUseTitle,
    /// A result.
    ResInUseBody,
    /// A result.
    ResKeptTitle,
    /// A result.
    ResKeptBody,
    /// A result.
    ResForeignTitle,
    /// A result.
    ResForeignBody,
    /// A result.
    ResForgottenTitle,
    /// A result.
    ResForgottenBody,
    /// A result.
    ResChangedTitle,
    /// A result.
    ResUnconfirmedTitle,
    /// A result.
    ResUnconfirmedBody,
    /// While a write runs.
    ResWorking,
    /// The window cannot close.
    ResClosingTitle,
    /// The window cannot close.
    ResClosingBody,
    /// A refusal.
    RefBusyTitle,
    /// A refusal.
    RefBusyBody,
    /// A refusal.
    RefJournalBusyTitle,
    /// A refusal.
    RefJournalBusyBody,
    /// A refusal.
    RefBlockedTitle,
    /// A refusal.
    RefBlockedBody,
    /// A refusal.
    RefOrderTitle,
    /// A refusal.
    RefOrderBody,
    /// A refusal.
    RefSlotTitle,
    /// A refusal.
    RefSlotBody,
    /// A refusal.
    RefCleanupTitle,
    /// A refusal.
    RefCleanupBody,
    /// A refusal.
    RefSteamTitle,
    /// A refusal.
    RefSteamBody,
    /// A refusal.
    RefStaleTitle,
    /// A refusal.
    RefStaleBody,
    /// A refusal.
    RefAdminTitle,
    /// A refusal.
    RefAdminBody,
    /// A refusal.
    RefHelperTitle,
    /// A refusal.
    RefHelperBody,
    /// A refusal.
    RefNothingTitle,
    /// A refusal.
    RefNothingBody,
    /// A refusal.
    RefUnexpectedTitle,
    /// A refusal.
    RefUnexpectedBody,
    /// A refusal.
    RefPlanTitle,
    /// A refusal.
    RefPlanBody,
    /// A refusal.
    RefNoPreviewTitle,
    /// A refusal.
    RefNoPreviewBody,
    /// The plan needs the helper; Windows shows its dialog.
    PreviewAdminYes,

    // ---- package download (P5-5b)
    /// A fix that needs a package Rerun does not download.
    FixNoPackage,
    /// The question before a download.
    DlConsentTitle,
    /// Under the question.
    DlConsentIntro,
    /// The progress dialog.
    DlProgressTitle,
    /// Under the progress title.
    DlProgressIntro,
    /// The dialog after a failure.
    DlFailedTitle,
    /// The word before a package's name.
    DlPackage,
    /// A label.
    DlLblSource,
    /// A label.
    DlLblRelease,
    /// A label.
    DlLblHost,
    /// A label.
    DlLblSha,
    /// A label.
    DlLblLicence,
    /// A label.
    DlLblSize,
    /// A label.
    DlLblStatus,
    /// The size before the download starts.
    DlSizeLater,
    /// What happens after the download.
    DlChecked,
    /// The consent button.
    DlBtn,
    /// The button after a failure.
    DlBtnRetry,
    /// The cancel button while downloading.
    DlBtnCancel,
    /// While a cancel is not confirmed yet.
    DlCancelling,
    /// A package's state.
    DlStWaiting,
    /// A package's state.
    DlStDownloading,
    /// A package's state.
    DlStCached,
    /// A package's state.
    DlStUnpacking,
    /// A package's state.
    DlStDone,
    /// A package's state after a failure.
    DlStNotStarted,
    /// A failure.
    DlErrOffline,
    /// A failure.
    DlErrTimedOut,
    /// A failure.
    DlErrInterrupted,
    /// A failure.
    DlErrRedirect,
    /// A failure.
    DlErrStatus,
    /// A failure.
    DlErrHash,
    /// A failure.
    DlErrTooLarge,
    /// A failure.
    DlErrExtract,
    /// A failure.
    DlErrChanged,
    /// A failure.
    DlErrUnobtainable,
    /// A failure.
    DlErrOther,
    /// The banner after a cancel.
    DlCancelledTitle,
    /// The banner after a cancel.
    DlCancelledBody,
    /// The window cannot close yet.
    DlClosingTitle,
    /// The window cannot close yet.
    DlClosingBody,
    /// A confirm that matches no shown list.
    DlNoConsentTitle,
    /// A confirm that matches no shown list.
    DlNoConsentBody,
    /// A package's state after a failure.
    DlStFailed,
    /// A label: the hosts a download may be handed over to.
    DlLblVia,
    /// The size line while downloading.
    DlSize {
        /// Bytes read.
        read: u64,
        /// The announced length.
        total: Option<u64>,
    },

    // ---- the helper from the app (P5-5c)
    /// A fix that needs the helper, which is ready (P5-5c).
    FixHelperAsks,
    /// A fix that needs the helper; Windows grants no elevation.
    FixNoElevation,
    /// The plan needs the helper; Windows shows no dialog.
    PreviewAdminNoDialog,
    /// The UAC dialog: consent.
    AdminConsent,
    /// The UAC dialog: credentials.
    AdminCredentials,
    /// The UAC dialog is not on the secure desktop.
    AdminNotSecure,
    /// Windows elevates signed images only.
    AdminSignedOnly,
    /// Waiting for the UAC dialog.
    UacWaitTitle,
    /// Waiting for the UAC dialog.
    UacWaitBody,
    /// Waiting for the UAC dialog.
    UacWaitHidden,
    /// A result: UAC declined during an apply.
    ResDeclinedTitle,
    /// A result: UAC declined during an apply.
    ResDeclinedBody,
    /// A result: the helper refused or did not run; rolled back.
    ResHelperNotDoneTitle,
    /// A result: the helper refused or did not run; rolled back.
    ResHelperNotDoneBody,
    /// A result: the helper batch stays open (HelperOpen).
    ResHelperOpenBody,
    /// A result: rolled back, a replaced file still in use (CleanupPending).
    ResCleanupOpenBody,
    /// A result: UAC declined during an undo.
    ResUndoDeclinedTitle,
    /// A result: UAC declined during an undo.
    ResUndoDeclinedBody,
    /// A refusal: Windows grants no elevation.
    RefNoElevationTitle,
    /// A refusal: Windows grants no elevation.
    RefNoElevationBody,
    /// A refusal: a helper may still run.
    RefHelperBusyTitle,
    /// A refusal: a helper may still run.
    RefHelperBusyBody,
    /// A pick the app cannot apply here.
    RefUnavailableTitle,
    /// A pick the app cannot apply here.
    RefUnavailableBody,
    /// An undo that needs the helper; Windows grants no elevation.
    UndoNoElevation,
    /// A fix that needs the helper; it cannot be used for another reason.
    FixHelperUnavailable,
    /// An undo that needs the helper; it cannot be used for another reason.
    UndoHelperUnavailable,
}

/// The text of `m` in `lang`.
pub fn t(lang: Lang, m: Msg) -> Cow<'static, str> {
    match lang {
        Lang::En => en(m),
        Lang::De => de(m),
    }
}

/// A size for people: bytes, KB, or MB with one decimal (a comma in German).
fn bytes(n: u64, de: bool) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    if n < KB {
        format!("{n} B")
    } else if n < MB {
        format!("{} KB", (n + KB / 2) / KB)
    } else {
        let tenths = (n.saturating_mul(10).saturating_add(MB / 2)) / MB;
        let sep = if de { ',' } else { '.' };
        format!("{}{sep}{} MB", tenths / 10, tenths % 10)
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
        HeroReadOnly => "Select the fixes you want to see exactly what they change.",
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
        FixesReadOnly => "Rerun shows the preview first and changes nothing until you apply.",
        AppliedTitle => "Applied",
        AppliedIntro => "Everything Rerun has changed on your games.",
        AppliedEmpty => "Nothing applied",
        AppliedEmptySub => "Your games are unchanged.",
        AppliedSome { count: n } => {
            return format!("{} in the journal", count(n, "open change", "open changes")).into();
        }
        AppliedSomeSub => {
            "Each card is one change Rerun applied. Undo takes the whole card back, after showing you what it restores."
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

        FixSelect => "Select this fix",
        FixNeedsHelper => "This fix needs Rerun's administrator helper, and it is not installed safely on this PC (in Program Files, folder Rerun, for administrators only). The installed version of Rerun brings it.",
        FixNeedsDownload => "This fix needs a package download first. Ticking it shows what would be downloaded; nothing is downloaded unless you agree.",
        FixTradeoffs => "Side effects",
        FixNoTradeoffs => "No side effects listed",
        FixSources => "Sources",
        FixExclusive => "Cannot be combined with",
        FixPreselected => "Preselected: tested by us, and the problem affects this PC",
        SourceRepo => "Repository",
        SourceSteamGuide => "Steam guide",
        SourceSteamThread => "Steam discussion",
        SourcePcgw => "PCGamingWiki",
        SourceOfficial => "Official page",
        PreviewTitle => "Preview",
        PreviewNone => "Select a fix to see exactly what Rerun would change.",
        PreviewPlanning => "Preparing the preview ...",
        PreviewIntro => "Nothing has been changed yet. This is everything Rerun would do.",
        PreviewChanges { n } => return (if n == 1 { "1 change".to_owned() } else { format!("{n} changes") }).into(),
        PreviewGameFolder => "Game folder",
        PreviewChecksum => "Plan checksum",
        PreviewAdminNo => "Administrator rights: not needed",
        PreviewUndo { profile } => return format!("Undo takes this whole plan back together{}. Before it restores anything, Rerun shows what it will do.", if profile { ", the launch profile included" } else { "" }).into(),
        PreviewCloseGame => "Close the game before you apply.",
        PreviewApplying => "Applying. Rerun finishes this before the window closes.",
        BtnApply => "Apply",
        BtnCancel => "Cancel",
        BtnDismiss => "Dismiss",
        BtnUndo => "Undo",
        BtnForget => "Close without undoing",
        ActCreateFolder => "Create folder",
        ActCreateFile => "Create file",
        ActReplaceFile => "Replace file",
        ActPatchFile => "Patch file",
        ActCreateKey => "Create registry key",
        ActSetValue => "Set registry value",
        ActAddTokens => "Add compatibility layers",
        ActGpuPref => "Set graphics preference",
        ActEditIni => "Edit INI file",
        ActFirewall => "Add firewall rule",
        ActHold => "Keep shared file",
        ActOther => "Other change",
        LblFrom => "From",
        LblNew => "New file",
        LblOld => "Current file",
        LblValue => "Value",
        LblValueNow => "Now",
        LblValueNew => "Set to",
        LblAdds => "Adds",
        LblIniKey => "Key",
        LblProfile => "Launch profile",
        LblCpuRule => "Limit",
        LblPriority => "Priority",
        LblStart => "Starts",
        LblTarget => "Looks for",
        LblPatch => "Changed byte",
        LblUndo => "On undo",
        HeldLine => "The file is there already with exactly this content. Rerun keeps it as it is.",
        IniMissing => "missing",
        IniNewSection => "missing (new section)",
        Bytes { n } => return (if n == 1 { "1 byte".to_owned() } else { format!("{n} bytes") }).into(),
        PatchByte { offset, old, new } => return (format!("0x{offset:x}: 0x{old:02x} -> 0x{new:02x}")).into(),
        UndoRemoves => "Undo removes it",
        UndoRestoresFile => "Undo restores the file as it was",
        UndoRestoresValue => "Undo restores the previous value",
        UndoRemovesTokens => "Undo removes only the layers Rerun added",
        UndoSetsKeys => "Undo sets back only the keys Rerun changed",
        UndoKeepsShared => "Undo keeps the shared file until the last change that needs it is undone",
        UndoRemovesRule => "Undo removes the rule",
        NoteNotRestored => "Undo restores existence, content, length and the read-only, hidden and system flags. It does not restore timestamps, permissions or file IDs.",
        NoteRegistry => "Registry: if the game fills a key or changes a value later, undo leaves it as it is, and the change can only be closed without undoing.",
        NoteLayers => "Compatibility layers apply only when Windows starts the game by exactly the path shown. Undo removes only the layers Rerun added.",
        NoteIni => "INI files: if the game rewrote the file, undo sets back only the keys that still hold Rerun's value. Keys you or the game changed stay.",
        NoteProfile => "Launch profile: it applies only when Steam starts the game through the launch option shown below. While Steam runs as administrator, no rule applies.",
        NoteProfileWatch => "Launch profile (watch): after Steam starts the game, Rerun looks for the game process for up to 120 seconds. The rule reaches the game shortly after it started.",
        NoteFirewall => "Firewall rules are added with administrator rights, with one Windows prompt, and removed again on undo.",
        NoteHold => "Shared files: a file that is there already with exactly this content is kept. This change relies on it.",
        NotePatch => "Patched files: only the bytes shown change. A patch makes a digital signature of the file invalid. Undo restores the original file bit for bit.",
        NoteGpuPref => "Graphics preference: only the preference of this program changes, to High performance. It takes effect at the next start.",
        NoteUserData => "Your Documents folder: the game's folder there lies outside the game folder. A cloud save may write the file again.",
        WarningWord => "Warning",
        WarnSacOn => "Smart App Control is on. It may block the patched file. Undo restores the original.",
        WarnSacEvaluation => "Smart App Control is in evaluation mode. It blocks nothing now, but Windows may turn it on later and then block the patched file. Undo restores the original.",
        WarnSacUnknown => "Rerun cannot read the state of Smart App Control. It may block the patched file. Undo restores the original.",
        WarnSteamPerUser => "Steam built this program for your account. Smart App Control does not know the patched copy and is likely to block it.",
        WarnSignedExe => "The program has a digital signature. The patch makes it invalid.",
        WarnWhenUnknown => "Rerun cannot tell whether a problem you picked affects your PC.",
        WarnNeedsRetest => "This Topo is due to be tested again.",
        WarnAntiCheat => "An anti-cheat rule allows this fix only with a warning.",
        WarnGpuSet => "The graphics preference is High performance already. There is nothing to change here.",
        WarnRequiresGpu => "A package needs a Vulkan driver for the game's graphics card. Rerun does not check that.",
        WarnSteamInput => "A hint: enable Steam Input for the game in Steam. Rerun changes nothing there.",
        WarnVsCopy => "A copy of a file Rerun changes is in the VirtualStore. The game probably reads that copy, not the file Rerun changes.",
        WarnVsLink => "A link in the VirtualStore was not followed, so Rerun could not look behind it.",
        WarnVsUnchecked => "Rerun could not look for copies in the VirtualStore.",
        LaunchHeading => "Steam launch option",
        LaunchCpu { threads, of } => return format!("The game is limited to {threads} of {of} threads on this PC.").into(),
        LaunchCpuNone => "This profile sets no CPU limit.",
        LaunchCpuUnknown => "Rerun cannot tell which threads the limit would pick on this PC.",
        LaunchOptionIntro => "Rerun does not change Steam's settings. Paste this into the game's launch options in Steam (Properties, General):",
        LaunchOptionCombine => "Launch options the game has already go after %command%. An option that already contains %command% cannot be combined.",
        LaunchOptionByHand => "After an undo, remove the option by hand.",
        LaunchShimStays => "Moving or deleting rerun-launch.exe breaks the start through Steam until the option is removed.",
        LaunchShimMissing => "rerun-launch.exe is not in Rerun's install folder. The option would not start the game.",
        LaunchShimUnchecked => "Rerun could not check whether rerun-launch.exe is in its install folder.",
        LaunchInstallUnknown => "Rerun's install folder is unknown, so no launch option can be shown.",
        LaunchNotShowable => "The path of Rerun's install folder holds characters that cannot be shown as they are. Move Rerun to another path.",
        LaunchCopy => "Copy launch option",
        LaunchCopied => "Copied",
        CardNote { n, profile } => { let inc = if profile { ", the launch profile included" } else { "" }; return (if n == 1 { format!("This card holds 1 change. Undo takes it back{inc}. To change it later, undo the card and apply again.") } else { format!("This card holds {n} changes. Undo takes them all back together{inc}. To change one of them later, undo the card and apply again.") }).into() }
        CardGame => "Game",
        CardTxn => "Transaction",
        StateApplied => "Applied",
        StateInterrupted => "Interrupted",
        StateCleanup => "Cleanup pending",
        StateDamaged => "Damaged",
        StateUnreadable => "Unreadable",
        StateForeign => "Needs you",
        ProblemInterrupted => "This was interrupted before it finished. Undo finishes the job.",
        ProblemCleanup => "Everything is undone, but a file Rerun left is still in use. Undo once more deletes it when it is free.",
        ProblemDamaged => "The record is damaged. Rerun cannot undo it; only closing it helps.",
        ProblemUnreadable => "The record cannot be read. Rerun cannot undo it; only closing it helps.",
        ProblemForeign => "Someone else changed a file Rerun changed. Rerun leaves it as it is; closing the card without undoing is the way out.",
        AppliedHere => "Applied to this game",
        CardNoOps => "The record lists no changes.",
        UndoTitle => "Undo this change?",
        UndoIntro => "Nothing has been changed yet. Undo would do this, newest change first:",
        UndoCloseGame => "The game must be closed. Rerun refuses to undo while it runs.",
        FateBefore => "Already as before, nothing to do",
        FateAfter => "Will be set back",
        FateDrifted => "Rerun's part is set back; later changes by you or the game stay",
        FateForeign => "Someone else changed it. Rerun leaves it as it is",
        FateKept => "Stays for another change that relies on it",
        FateNotReached => "Not reached: undo stops earlier",
        UndoHalt { op } => return format!("Undo would stop at change {op} and leave the rest as it is. The reason is below.").into(),
        UndoCleanup { n, in_use } => { let copies = if n == 1 { "1 copy".to_owned() } else { format!("{n} copies") }; let is = if in_use == 1 { "1 is".to_owned() } else { format!("{in_use} are") }; return format!("Undo also deletes {copies} Rerun made; {is} in use now and deleted once free.").into() }
        UndoEmpty => "This record changed nothing. Undo only closes it.",
        UndoPrompt => "Undoing this needs Rerun's administrator helper, and it is not installed safely on this PC. The installed version of Rerun brings it; until then the change stays.",
        UndoAfter => "After the undo",
        LaunchFateGone => "Remove this launch option of the game in Steam by hand. Rerun does not change Steam's settings:",
        LaunchUntilRemoved => "Until you remove it, Steam starts the game through rerun-launch, which finds no profile and starts the game unchanged.",
        LaunchFatePrev => "The launch profile from before this change is back and keeps applying through the launch option. Leave the option set.",
        LaunchFateStays => "The launch profile stays and keeps applying through the launch option until you remove it. To stop it, remove this launch option by hand:",
        LaunchFateLeft => "An earlier undo left the launch profile as found, because someone else changed it. If it is still there, it keeps applying until you remove the launch option by hand:",
        ChangedNote => "The preview was updated. Something changed since you looked; please look at it again.",
        UndoBtn => "Undo this change",
        ForgetTitle => "Close this change without undoing it?",
        ForgetIntro => "Rerun forgets the record. Nothing on disk changes, and Rerun can no longer undo this change. Use this only when undoing is not possible.",
        ForgetWould => "An undo would finish this cleanly. Think about undoing instead.",
        ForgetNow => "This is on disk now, which Rerun leaves as it is:",
        ResAppliedTitle => "Applied",
        ResAppliedBody => "The change is listed under Applied. Undo takes it back together.",
        ResNothingTitle => "Nothing to change",
        ResNothingBody => "The game already has these settings.",
        ResRolledBackTitle => "Rerun took the change back",
        ResRolledBackBody => "Something went wrong while applying. Rerun restored everything it had changed. Nothing is different now.",
        ResOpenTitle => "The change is only partly done",
        ResOpenBody => "Open Applied: it shows what is left and what you can do. Nothing more was changed.",
        ResRevertedTitle => "Undone",
        ResRevertedBody => "Everything this change touched is as before.",
        ResHaltedTitle => "Undo stopped",
        ResHaltedBody => "Rerun stopped before the end and left the rest as it is. The card under Applied says what is left.",
        ResInUseTitle => "Undone, one file is still in use",
        ResInUseBody => "A copy Rerun made is still in use. Close the program that uses it and undo again to delete it.",
        ResKeptTitle => "Undone, a copy is kept",
        ResKeptBody => "Rerun kept a copy next to a file that changed. Undo again once it is safe to delete it.",
        ResForeignTitle => "Part of it was changed by someone else",
        ResForeignBody => "Rerun left those parts as they are and did not close the change. Closing it without undoing is the way out.",
        ResForgottenTitle => "Closed",
        ResForgottenBody => "Rerun forgot this change. It changed nothing on disk and can no longer undo it.",
        ResChangedTitle => "Look again",
        ResUnconfirmedTitle => "Rerun cannot confirm the result",
        ResUnconfirmedBody => "Look at Applied to see where things stand.",
        ResWorking => "Working ...",
        ResClosingTitle => "Rerun finishes the running operation first",
        ResClosingBody => "Close the window once it has finished. This keeps your files in a known state.",
        RefBusyTitle => "A file of the game is in use",
        RefBusyBody => "Close the game, then try again. Nothing was changed.",
        RefJournalBusyTitle => "Another Rerun operation is running",
        RefJournalBusyBody => "Wait until it has finished, then try again. Nothing was changed.",
        RefBlockedTitle => "An earlier change is damaged",
        RefBlockedBody => "Close it first under Applied. Nothing was changed.",
        RefOrderTitle => "Another change comes first",
        RefOrderBody => "A change of Rerun that touches the same files must be undone first (the transaction is named below). Open Applied. Nothing was changed.",
        RefSlotTitle => "Another fix already uses that file",
        RefSlotBody => "Two packages cannot share a DLL. Undo the other change first, or keep it instead. Nothing was changed.",
        RefCleanupTitle => "A file Rerun left is still there",
        RefCleanupBody => "Undo that change once more under Applied; it deletes the file once it is free. Nothing was changed.",
        RefSteamTitle => "Steam is busy with this game",
        RefSteamBody => "Wait until Steam has finished, then try again. Nothing was changed.",
        RefStaleTitle => "The game changed since the preview",
        RefStaleBody => "This is not a problem. Rerun updated the page; look at the fixes and the preview again. Nothing was changed.",
        RefAdminTitle => "This needs administrator rights",
        RefAdminBody => "The folder needs administrator rights. The app cannot do that yet. Nothing was changed.",
        RefHelperTitle => "The administrator helper is not installed safely",
        RefHelperBody => "This needs Rerun's helper in Program Files, folder Rerun, installed for administrators only. The installed version of Rerun brings it. Nothing was changed, and Windows did not ask.",
        RefNothingTitle => "Nothing to undo",
        RefNothingBody => "This change is closed already, or Rerun has no record of it.",
        RefUnexpectedTitle => "Rerun could not do this",
        RefUnexpectedBody => "The reason is below. Look at Applied if you are unsure what state things are in.",
        RefPlanTitle => "Rerun cannot plan this selection",
        RefPlanBody => "Nothing was changed. The reason is below.",
        RefNoPreviewTitle => "The preview is no longer current",
        RefNoPreviewBody => "Select the fixes again and apply once the preview shows. Nothing was changed.",
        PreviewAdminYes => "Administrator: yes – Windows asks you in a moment (UAC)",
        FixNoPackage => "This fix needs a package that Rerun does not download itself (a community build you fetch from its own page). The app cannot apply it; the command line shows the details.",
        DlConsentTitle => "These files will be downloaded",
        DlConsentIntro => "This fix needs the package below. Rerun downloads it only if you agree, only from the source named here (which may hand it over to the storage hosts listed), and keeps it only if it has the SHA-256 shown. Nothing in your game is changed by this step; the usual preview comes next.",
        DlProgressTitle => "Downloading",
        DlProgressIntro => "Nothing in your game is changed. If you cancel, Rerun keeps nothing of the download that is running.",
        DlFailedTitle => "The download did not finish",
        DlPackage => "Package",
        DlLblSource => "Source",
        DlLblRelease => "Release",
        DlLblHost => "Host",
        DlLblSha => "SHA-256",
        DlLblLicence => "Licence",
        DlLblSize => "Size",
        DlLblStatus => "Status",
        DlSizeLater => "Shown while it downloads (the index lists no size)",
        DlChecked => "Checked after the download: Rerun keeps the file only if it has this SHA-256",
        DlBtn => "Download",
        DlBtnRetry => "Try again",
        DlBtnCancel => "Cancel download",
        DlCancelling => "Cancelling ...",
        DlStWaiting => "Waiting",
        DlStDownloading => "Downloading",
        DlStCached => "Already downloaded; checking it again",
        DlStUnpacking => "Unpacking the files it names",
        DlStDone => "Done",
        DlStNotStarted => "Not downloaded",
        DlErrOffline => "Rerun cannot reach the source. Check your internet connection and try again.",
        DlErrTimedOut => "The source took too long to answer. Try again later.",
        DlErrInterrupted => "The connection broke before the file was complete. Rerun kept nothing of it.",
        DlErrRedirect => "The source sent Rerun to a place that is not allowed. Rerun did not follow it and kept nothing.",
        DlErrStatus => "The source answered with an error. Rerun kept nothing.",
        DlErrHash => "The file is not the one the index names: its SHA-256 differs. Rerun deleted it.",
        DlErrTooLarge => "The file is larger than Rerun allows. Rerun deleted it.",
        DlErrExtract => "The package could not be unpacked safely, so Rerun refused it. Nothing in your game was changed.",
        DlErrChanged => "The package list changed since you looked at it. Close this and look at the fix again.",
        DlErrUnobtainable => "Rerun cannot download this package.",
        DlErrOther => "The download failed. The reason is below. Nothing in your game was changed.",
        DlCancelledTitle => "Download cancelled",
        DlCancelledBody => "Rerun kept nothing of the download that was running. Nothing in your game was changed.",
        DlClosingTitle => "Rerun cancels the download first",
        DlClosingBody => "The window closes by itself as soon as the download has stopped, usually within seconds. If the connection hangs it closes after 15 seconds anyway; a leftover temporary file is removed by the next download.",
        DlNoConsentTitle => "That was not the download you were shown",
        DlNoConsentBody => "Open the fix again and read what would be downloaded. Nothing was downloaded.",
        DlStFailed => "Failed",
        DlLblVia => "May be handed over to",
        DlSize { read, total } => return match total { Some(t) => format!("{} of {}", bytes(read, false), bytes(t, false)), None => format!("{} so far (the source did not announce a size)", bytes(read, false)) }.into(),
        FixHelperAsks => "Needs administrator rights: when you apply it, Windows asks you to confirm (UAC).",
        FixNoElevation => "This fix needs administrator rights, and Windows does not grant them to this account (or User Account Control is off). It cannot be applied here.",
        PreviewAdminNoDialog => "Administrator: yes – Windows does not ask on this PC, so your click on Apply is the only confirmation",
        AdminConsent => "Windows shows its consent dialog: confirm it with Yes. Rerun waits until you have answered.",
        AdminCredentials => "Windows asks for the password of an administrator account. Rerun waits until you have answered.",
        AdminNotSecure => "The dialog appears on your normal desktop, not on the secure desktop, because that is switched off on this PC: other programs could reach it.",
        AdminSignedOnly => "This PC lets only signed programs run as administrator. The helper of this version may not start; then Rerun keeps nothing of the change.",
        UacWaitTitle => "Waiting for Windows (UAC) ...",
        UacWaitBody => "Confirm the User Account Control dialog. Rerun waits until you answer it; this window stays open until then.",
        UacWaitHidden => "If you do not see the dialog, look for a flashing shield in the taskbar.",
        ResDeclinedTitle => "Not applied: administrator approval declined",
        ResDeclinedBody => "You declined the Windows dialog. Rerun took back everything it had changed before it; nothing is different now, and the change is closed.",
        ResHelperNotDoneTitle => "Not applied: the administrator helper did not finish",
        ResHelperNotDoneBody => "Rerun took back everything it had changed; nothing is different now, and the change is closed. The reason is below.",
        ResHelperOpenBody => "Rerun could not confirm what the administrator helper did, so the change stays open. Nothing more was changed. Undo it under Applied; Windows asks once more if a firewall rule is there.",
        ResCleanupOpenBody => "Rerun took the change back, but a file it replaced is still in use, so the change stays open until Undo under Applied removes it.",
        ResUndoDeclinedTitle => "Not undone: administrator approval declined",
        ResUndoDeclinedBody => "You declined the Windows dialog. Nothing was undone; the change stays as it was under Applied. Undo asks Windows again.",
        RefNoElevationTitle => "Windows does not grant administrator rights here",
        RefNoElevationBody => "This account cannot get administrator rights (or User Account Control is off), so Rerun cannot start its helper. Nothing was changed.",
        RefHelperBusyTitle => "Rerun's administrator helper is still busy",
        RefHelperBusyBody => "A helper from an earlier run may still be working, or another program holds its lock. Wait a moment, then try again. Nothing was changed.",
        RefUnavailableTitle => "Not available here",
        RefUnavailableBody => "This fix cannot be applied from the app right now. Nothing was changed.",
        UndoNoElevation => "Undoing this needs administrator rights, and Windows does not grant them to this account (or User Account Control is off).",
        FixHelperUnavailable => "This fix needs Rerun's administrator helper, which cannot be used here right now. It cannot be applied.",
        UndoHelperUnavailable => "Undoing this needs Rerun's administrator helper, which cannot be used here right now; until then the change stays.",
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
        HeroReadOnly => "Wähle die Fixes, von denen du genau sehen willst, was sie ändern.",
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
        FixesReadOnly => "Rerun zeigt zuerst die Vorschau und ändert nichts, bis du anwendest.",
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
            "Jede Karte ist eine Änderung, die Rerun angewendet hat. Rückgängig nimmt die ganze Karte zurück, nachdem es dir gezeigt hat, was es wiederherstellt."
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

        FixSelect => "Diesen Fix auswählen",
        FixNeedsHelper => "Dieser Fix braucht den Administrator-Helfer von Rerun, und der ist auf diesem PC nicht sicher installiert (unter Programme im Ordner Rerun, nur für Administratoren). Die installierte Version von Rerun bringt ihn mit.",
        FixNeedsDownload => "Dieser Fix braucht zuerst einen Paket-Download. Beim Anhaken siehst du, was heruntergeladen würde; ohne deine Zustimmung wird nichts heruntergeladen.",
        FixTradeoffs => "Nebenwirkungen",
        FixNoTradeoffs => "Keine Nebenwirkungen angegeben",
        FixSources => "Quellen",
        FixExclusive => "Lässt sich nicht kombinieren mit",
        FixPreselected => "Vorausgewählt: von uns getestet, und das Problem betrifft diesen PC",
        SourceRepo => "Repository",
        SourceSteamGuide => "Steam-Guide",
        SourceSteamThread => "Steam-Diskussion",
        SourcePcgw => "PCGamingWiki",
        SourceOfficial => "Offizielle Seite",
        PreviewTitle => "Vorschau",
        PreviewNone => "Wähle einen Fix, um genau zu sehen, was Rerun ändern würde.",
        PreviewPlanning => "Die Vorschau wird erstellt ...",
        PreviewIntro => "Noch wurde nichts geändert. Das ist alles, was Rerun tun würde.",
        PreviewChanges { n } => return (if n == 1 { "1 Änderung".to_owned() } else { format!("{n} Änderungen") }).into(),
        PreviewGameFolder => "Spielordner",
        PreviewChecksum => "Prüfsumme des Plans",
        PreviewAdminNo => "Administratorrechte: nicht nötig",
        PreviewUndo { profile } => return format!("Rückgängig nimmt diesen ganzen Plan gemeinsam zurück{}. Bevor Rerun etwas wiederherstellt, zeigt es dir, was es tun wird.", if profile { ", das Startprofil eingeschlossen" } else { "" }).into(),
        PreviewCloseGame => "Schliesse das Spiel, bevor du anwendest.",
        PreviewApplying => "Wird angewendet. Rerun beendet das, bevor sich das Fenster schliesst.",
        BtnApply => "Anwenden",
        BtnCancel => "Abbrechen",
        BtnDismiss => "Ausblenden",
        BtnUndo => "Rückgängig",
        BtnForget => "Abschliessen ohne Rückgängig",
        ActCreateFolder => "Ordner anlegen",
        ActCreateFile => "Datei anlegen",
        ActReplaceFile => "Datei ersetzen",
        ActPatchFile => "Datei patchen",
        ActCreateKey => "Registry-Schlüssel anlegen",
        ActSetValue => "Registry-Wert setzen",
        ActAddTokens => "Kompatibilitätsebenen hinzufügen",
        ActGpuPref => "Grafikeinstellung setzen",
        ActEditIni => "INI-Datei bearbeiten",
        ActFirewall => "Firewall-Regel hinzufügen",
        ActHold => "Gemeinsame Datei behalten",
        ActOther => "Andere Änderung",
        LblFrom => "Aus",
        LblNew => "Neue Datei",
        LblOld => "Aktuelle Datei",
        LblValue => "Wert",
        LblValueNow => "Jetzt",
        LblValueNew => "Wird gesetzt auf",
        LblAdds => "Fügt hinzu",
        LblIniKey => "Schlüssel",
        LblProfile => "Startprofil",
        LblCpuRule => "Begrenzung",
        LblPriority => "Priorität",
        LblStart => "Startet",
        LblTarget => "Sucht nach",
        LblPatch => "Geändertes Byte",
        LblUndo => "Beim Rückgängigmachen",
        HeldLine => "Die Datei ist schon mit genau diesem Inhalt da. Rerun lässt sie, wie sie ist.",
        IniMissing => "fehlt",
        IniNewSection => "fehlt (neuer Abschnitt)",
        Bytes { n } => return (if n == 1 { "1 Byte".to_owned() } else { format!("{n} Bytes") }).into(),
        PatchByte { offset, old, new } => return (format!("0x{offset:x}: 0x{old:02x} -> 0x{new:02x}")).into(),
        UndoRemoves => "Rückgängig entfernt es",
        UndoRestoresFile => "Rückgängig stellt die Datei wieder her, wie sie war",
        UndoRestoresValue => "Rückgängig stellt den früheren Wert wieder her",
        UndoRemovesTokens => "Rückgängig entfernt nur die Ebenen, die Rerun hinzugefügt hat",
        UndoSetsKeys => "Rückgängig setzt nur die Schlüssel zurück, die Rerun geändert hat",
        UndoKeepsShared => "Rückgängig behält die gemeinsame Datei, bis die letzte Änderung, die sie braucht, zurückgenommen ist",
        UndoRemovesRule => "Rückgängig entfernt die Regel",
        NoteNotRestored => "Rückgängig stellt Vorhandensein, Inhalt, Länge sowie die Attribute Schreibgeschützt, Versteckt und System wieder her, nicht aber Zeitstempel, Berechtigungen oder Datei-IDs.",
        NoteRegistry => "Registry: Wenn das Spiel später einen Schlüssel füllt oder einen Wert ändert, lässt Rückgängig ihn, wie er ist, und die Änderung lässt sich nur noch ohne Rückgängig abschliessen.",
        NoteLayers => "Kompatibilitätsebenen gelten nur, wenn Windows das Spiel genau über den gezeigten Pfad startet. Rückgängig entfernt nur die Ebenen, die Rerun hinzugefügt hat.",
        NoteIni => "INI-Dateien: Hat das Spiel die Datei neu geschrieben, setzt Rückgängig nur die Schlüssel zurück, die noch Reruns Wert haben. Schlüssel, die du oder das Spiel geändert haben, bleiben.",
        NoteProfile => "Startprofil: Es gilt nur, wenn Steam das Spiel über die unten gezeigte Startoption startet. Solange Steam als Administrator läuft, gilt keine Regel.",
        NoteProfileWatch => "Startprofil (Beobachten): Nachdem Steam das Spiel gestartet hat, sucht Rerun bis zu 120 Sekunden nach dem Spielprozess. Die Regel erreicht das Spiel kurz nach dem Start.",
        NoteFirewall => "Firewall-Regeln werden mit Administratorrechten und einer Windows-Abfrage hinzugefügt und beim Rückgängigmachen wieder entfernt.",
        NoteHold => "Gemeinsame Dateien: Eine Datei, die schon mit genau diesem Inhalt da ist, bleibt. Diese Änderung verlässt sich darauf.",
        NotePatch => "Gepatchte Dateien: Nur die gezeigten Bytes ändern sich. Ein Patch macht eine digitale Signatur der Datei ungültig. Rückgängig stellt die Originaldatei Bit für Bit wieder her.",
        NoteGpuPref => "Grafikeinstellung: Nur die Einstellung dieses Programms ändert sich, auf Hohe Leistung. Die Einstellung gilt ab dem nächsten Start.",
        NoteUserData => "Dein Dokumente-Ordner: Der Ordner des Spiels dort liegt ausserhalb des Spielordners. Ein Cloud-Spielstand kann die Datei erneut schreiben.",
        WarningWord => "Warnung",
        WarnSacOn => "Die intelligente App-Kontrolle ist an. Die App-Kontrolle kann die gepatchte Datei blockieren. Rückgängig stellt das Original wieder her.",
        WarnSacEvaluation => "Die intelligente App-Kontrolle ist im Testmodus. Die App-Kontrolle blockiert jetzt nichts, aber Windows kann sie später einschalten und dann die gepatchte Datei blockieren. Rückgängig stellt das Original wieder her.",
        WarnSacUnknown => "Rerun kann den Zustand der intelligenten App-Kontrolle nicht lesen. Die App-Kontrolle kann die gepatchte Datei blockieren. Rückgängig stellt das Original wieder her.",
        WarnSteamPerUser => "Steam hat dieses Programm für dein Konto gebaut. Die intelligente App-Kontrolle kennt die gepatchte Kopie nicht und blockiert sie wahrscheinlich.",
        WarnSignedExe => "Das Programm hat eine digitale Signatur. Der Patch macht sie ungültig.",
        WarnWhenUnknown => "Rerun kann nicht sagen, ob ein gewähltes Problem deinen PC betrifft.",
        WarnNeedsRetest => "Dieses Topo soll nochmals getestet werden.",
        WarnAntiCheat => "Eine Anti-Cheat-Regel erlaubt diesen Fix nur mit einem Hinweis.",
        WarnGpuSet => "Die Grafikeinstellung ist schon Hohe Leistung. Hier gibt es nichts zu ändern.",
        WarnRequiresGpu => "Ein Paket braucht einen Vulkan-Treiber für die Grafikkarte des Spiels. Rerun prüft das nicht.",
        WarnSteamInput => "Ein Hinweis: Aktiviere Steam Input für das Spiel in Steam. Rerun ändert dort nichts.",
        WarnVsCopy => "Eine Kopie einer Datei, die Rerun ändert, liegt im VirtualStore. Das Spiel liest wahrscheinlich diese Kopie und nicht die Datei, die Rerun ändert.",
        WarnVsLink => "Ein Link im VirtualStore wurde nicht verfolgt, darum konnte Rerun nicht dahinter nachsehen.",
        WarnVsUnchecked => "Rerun konnte nicht nach Kopien im VirtualStore suchen.",
        LaunchHeading => "Steam-Startoption",
        LaunchCpu { threads, of } => return format!("Das Spiel wird auf {threads} von {of} Threads dieses PCs beschränkt.").into(),
        LaunchCpuNone => "Dieses Profil setzt keine CPU-Begrenzung.",
        LaunchCpuUnknown => "Rerun kann nicht sagen, welche Threads die Begrenzung auf diesem PC wählen würde.",
        LaunchOptionIntro => "Rerun ändert die Einstellungen von Steam nicht. Füge dies in Steam bei den Startoptionen des Spiels ein (Eigenschaften, Allgemein):",
        LaunchOptionCombine => "Startoptionen, die das Spiel schon hat, kommen hinter %command%. Eine Option, die schon %command% enthält, lässt sich nicht kombinieren.",
        LaunchOptionByHand => "Nach dem Rückgängigmachen entfernst du die Option von Hand.",
        LaunchShimStays => "Wird rerun-launch.exe verschoben oder gelöscht, startet das Spiel über Steam nicht mehr, bis die Option entfernt ist.",
        LaunchShimMissing => "rerun-launch.exe liegt nicht im Installationsordner von Rerun. Die Option würde das Spiel nicht starten.",
        LaunchShimUnchecked => "Rerun konnte nicht prüfen, ob rerun-launch.exe in seinem Installationsordner liegt.",
        LaunchInstallUnknown => "Der Installationsordner von Rerun ist unbekannt, darum lässt sich keine Startoption zeigen.",
        LaunchNotShowable => "Der Pfad zum Installationsordner von Rerun enthält Zeichen, die sich nicht unverändert zeigen lassen. Verschiebe Rerun an einen anderen Pfad.",
        LaunchCopy => "Startoption kopieren",
        LaunchCopied => "Kopiert",
        CardNote { n, profile } => { let inc = if profile { ", das Startprofil eingeschlossen" } else { "" }; return (if n == 1 { format!("Diese Karte enthält 1 Änderung. Rückgängig nimmt sie zurück{inc}. Um sie später zu ändern, mache die Karte rückgängig und wende neu an.") } else { format!("Diese Karte enthält {n} Änderungen. Rückgängig nimmt sie alle gemeinsam zurück{inc}. Um eine davon später zu ändern, mache die Karte rückgängig und wende neu an.") }).into() }
        CardGame => "Spiel",
        CardTxn => "Vorgang",
        StateApplied => "Angewendet",
        StateInterrupted => "Unterbrochen",
        StateCleanup => "Aufräumen ausstehend",
        StateDamaged => "Beschädigt",
        StateUnreadable => "Nicht lesbar",
        StateForeign => "Braucht dich",
        ProblemInterrupted => "Das wurde unterbrochen, bevor es fertig war. Rückgängig bringt es zu Ende.",
        ProblemCleanup => "Alles ist rückgängig gemacht, aber eine Datei, die Rerun hinterlassen hat, ist noch in Gebrauch. Nochmals Rückgängig löscht sie, sobald sie frei ist.",
        ProblemDamaged => "Der Eintrag ist beschädigt. Rerun kann ihn nicht rückgängig machen; nur Abschliessen hilft.",
        ProblemUnreadable => "Der Eintrag lässt sich nicht lesen. Rerun kann ihn nicht rückgängig machen; nur Abschliessen hilft.",
        ProblemForeign => "Jemand anderes hat eine Datei geändert, die Rerun geändert hat. Rerun lässt sie, wie sie ist; der Ausweg ist, die Karte ohne Rückgängig abzuschliessen.",
        AppliedHere => "Auf dieses Spiel angewendet",
        CardNoOps => "Der Eintrag listet keine Änderungen.",
        UndoTitle => "Diese Änderung rückgängig machen?",
        UndoIntro => "Noch wurde nichts geändert. Rückgängig würde Folgendes tun, die neueste Änderung zuerst:",
        UndoCloseGame => "Das Spiel muss geschlossen sein. Rerun macht nichts rückgängig, solange es läuft.",
        FateBefore => "Schon wie vorher, nichts zu tun",
        FateAfter => "Wird zurückgesetzt",
        FateDrifted => "Rerun setzt seinen Teil zurück; spätere Änderungen von dir oder dem Spiel bleiben",
        FateForeign => "Jemand anderes hat es geändert. Rerun lässt es, wie es ist",
        FateKept => "Bleibt für eine andere Änderung, die sich darauf verlässt",
        FateNotReached => "Nicht erreicht: Rückgängig hält vorher an",
        UndoHalt { op } => return format!("Rückgängig würde bei Änderung {op} anhalten und den Rest lassen, wie er ist. Der Grund steht unten.").into(),
        UndoCleanup { n, in_use } => { let copies = if n == 1 { "1 Kopie".to_owned() } else { format!("{n} Kopien") }; let is = if in_use == 1 { "1 ist".to_owned() } else { format!("{in_use} sind") }; return format!("Rückgängig löscht auch {copies}, die Rerun gemacht hat; {is} gerade in Gebrauch und wird gelöscht, sobald frei.").into() }
        UndoEmpty => "Dieser Eintrag hat nichts geändert. Rückgängig schliesst ihn nur ab.",
        UndoPrompt => "Das Rückgängigmachen braucht den Administrator-Helfer von Rerun, und der ist auf diesem PC nicht sicher installiert. Die installierte Version von Rerun bringt ihn mit; bis dahin bleibt die Änderung.",
        UndoAfter => "Nach dem Rückgängigmachen",
        LaunchFateGone => "Entferne diese Startoption des Spiels in Steam von Hand. Rerun ändert die Einstellungen von Steam nicht:",
        LaunchUntilRemoved => "Bis du sie entfernst, startet Steam das Spiel über rerun-launch, das kein Profil findet und das Spiel unverändert startet.",
        LaunchFatePrev => "Das Startprofil von vor dieser Änderung ist zurück und gilt weiter über die Startoption. Lass die Option gesetzt.",
        LaunchFateStays => "Das Startprofil bleibt und gilt weiter über die Startoption, bis du sie entfernst. Um es zu stoppen, entferne diese Startoption von Hand:",
        LaunchFateLeft => "Ein früheres Rückgängigmachen hat das Startprofil so gelassen, wie es war, weil jemand anderes es geändert hat. Falls es noch da ist, gilt es weiter, bis du die Startoption von Hand entfernst:",
        ChangedNote => "Die Vorschau wurde aktualisiert. Seit deinem Blick hat sich etwas geändert; bitte sieh sie dir nochmals an.",
        UndoBtn => "Diese Änderung rückgängig machen",
        ForgetTitle => "Diese Änderung abschliessen, ohne sie rückgängig zu machen?",
        ForgetIntro => "Rerun vergisst den Eintrag. Auf der Festplatte ändert sich nichts, und Rerun kann diese Änderung nicht mehr rückgängig machen. Nutze das nur, wenn Rückgängig nicht möglich ist.",
        ForgetWould => "Rückgängig würde das sauber abschliessen. Überlege dir, stattdessen rückgängig zu machen.",
        ForgetNow => "Das liegt jetzt auf der Festplatte, und Rerun lässt es so:",
        ResAppliedTitle => "Angewendet",
        ResAppliedBody => "Die Änderung steht unter Angewendet. Rückgängig nimmt sie gemeinsam zurück.",
        ResNothingTitle => "Nichts zu ändern",
        ResNothingBody => "Das Spiel hat diese Einstellungen schon.",
        ResRolledBackTitle => "Rerun hat die Änderung zurückgenommen",
        ResRolledBackBody => "Beim Anwenden ging etwas schief. Rerun hat alles wiederhergestellt, was es geändert hatte. Jetzt ist nichts anders.",
        ResOpenTitle => "Die Änderung ist nur teilweise erledigt",
        ResOpenBody => "Öffne Angewendet: Dort steht, was übrig ist und was du tun kannst. Es wurde nichts weiter geändert.",
        ResRevertedTitle => "Rückgängig gemacht",
        ResRevertedBody => "Alles, was diese Änderung berührt hat, ist wie vorher.",
        ResHaltedTitle => "Rückgängig hat angehalten",
        ResHaltedBody => "Rerun hat vor dem Ende angehalten und den Rest gelassen, wie er ist. Die Karte unter Angewendet sagt, was übrig ist.",
        ResInUseTitle => "Rückgängig gemacht, eine Datei ist noch in Gebrauch",
        ResInUseBody => "Eine Kopie, die Rerun gemacht hat, ist noch in Gebrauch. Schliesse das Programm, das sie nutzt, und mache nochmals rückgängig, um sie zu löschen.",
        ResKeptTitle => "Rückgängig gemacht, eine Kopie bleibt",
        ResKeptBody => "Rerun hat neben einer geänderten Datei eine Kopie behalten. Mache nochmals rückgängig, sobald sie sich gefahrlos löschen lässt.",
        ResForeignTitle => "Ein Teil wurde von jemand anderem geändert",
        ResForeignBody => "Rerun hat diese Teile gelassen, wie sie sind, und die Änderung nicht abgeschlossen. Der Ausweg ist, sie ohne Rückgängig abzuschliessen.",
        ResForgottenTitle => "Abgeschlossen",
        ResForgottenBody => "Rerun hat diese Änderung vergessen. Auf der Festplatte hat es nichts geändert und kann sie nicht mehr rückgängig machen.",
        ResChangedTitle => "Bitte nochmals ansehen",
        ResUnconfirmedTitle => "Rerun kann das Ergebnis nicht bestätigen",
        ResUnconfirmedBody => "Sieh unter Angewendet nach, wie es steht.",
        ResWorking => "Wird ausgeführt ...",
        ResClosingTitle => "Rerun beendet zuerst den laufenden Vorgang",
        ResClosingBody => "Schliesse das Fenster, sobald er fertig ist. So bleiben deine Dateien in einem bekannten Zustand.",
        RefBusyTitle => "Eine Datei des Spiels ist in Gebrauch",
        RefBusyBody => "Schliesse das Spiel und versuche es nochmals. Es wurde nichts geändert.",
        RefJournalBusyTitle => "Ein anderer Rerun-Vorgang läuft",
        RefJournalBusyBody => "Warte, bis er fertig ist, und versuche es dann nochmals. Es wurde nichts geändert.",
        RefBlockedTitle => "Eine frühere Änderung ist beschädigt",
        RefBlockedBody => "Schliesse sie zuerst unter Angewendet ab. Es wurde nichts geändert.",
        RefOrderTitle => "Eine andere Änderung kommt zuerst",
        RefOrderBody => "Eine Änderung von Rerun, die dieselben Dateien berührt, muss zuerst rückgängig gemacht werden (der Vorgang steht unten). Öffne Angewendet. Es wurde nichts geändert.",
        RefSlotTitle => "Ein anderer Fix nutzt diese Datei schon",
        RefSlotBody => "Zwei Pakete können sich keine DLL teilen. Mache die andere Änderung zuerst rückgängig oder behalte sie. Es wurde nichts geändert.",
        RefCleanupTitle => "Eine Datei, die Rerun hinterlassen hat, ist noch da",
        RefCleanupBody => "Mache diese Änderung unter Angewendet nochmals rückgängig; dabei wird die Datei gelöscht, sobald sie frei ist. Es wurde nichts geändert.",
        RefSteamTitle => "Steam ist mit diesem Spiel beschäftigt",
        RefSteamBody => "Warte, bis Steam fertig ist, und versuche es dann nochmals. Es wurde nichts geändert.",
        RefStaleTitle => "Das Spiel hat sich seit der Vorschau geändert",
        RefStaleBody => "Das ist kein Problem. Rerun hat die Seite aktualisiert; sieh dir die Fixes und die Vorschau nochmals an. Es wurde nichts geändert.",
        RefAdminTitle => "Das braucht Administratorrechte",
        RefAdminBody => "Der Ordner braucht Administratorrechte. Die App kann das noch nicht. Es wurde nichts geändert.",
        RefHelperTitle => "Der Administrator-Helfer ist nicht sicher installiert",
        RefHelperBody => "Das braucht den Helfer von Rerun unter Programme im Ordner Rerun, nur für Administratoren installiert. Die installierte Version von Rerun bringt ihn mit. Es wurde nichts geändert, und Windows hat nicht gefragt.",
        RefNothingTitle => "Nichts rückgängig zu machen",
        RefNothingBody => "Diese Änderung ist schon abgeschlossen, oder Rerun hat keinen Eintrag dazu.",
        RefUnexpectedTitle => "Rerun konnte das nicht ausführen",
        RefUnexpectedBody => "Der Grund steht unten. Sieh unter Angewendet nach, wenn du unsicher bist, in welchem Zustand die Dinge sind.",
        RefPlanTitle => "Rerun kann diese Auswahl nicht planen",
        RefPlanBody => "Es wurde nichts geändert. Der Grund steht unten.",
        RefNoPreviewTitle => "Die Vorschau ist nicht mehr aktuell",
        RefNoPreviewBody => "Wähle die Fixes nochmals und wende an, sobald die Vorschau da ist. Es wurde nichts geändert.",
        PreviewAdminYes => "Administrator: ja – Windows fragt dich gleich (UAC)",
        FixNoPackage => "Dieser Fix braucht ein Paket, das Rerun nicht selbst herunterlädt (ein Community-Build, den du von seiner eigenen Seite holst). Die App kann ihn nicht anwenden; die Kommandozeile zeigt die Einzelheiten.",
        DlConsentTitle => "Diese Dateien werden heruntergeladen",
        DlConsentIntro => "Dieser Fix braucht das Paket unten. Rerun lädt es nur herunter, wenn du zustimmst, nur von der hier genannten Quelle (die an die aufgeführten Speicher-Server weiterleiten darf), und behält es nur, wenn es den angezeigten SHA-256 hat. Dieser Schritt ändert nichts an deinem Spiel; danach kommt die gewohnte Vorschau.",
        DlProgressTitle => "Wird heruntergeladen",
        DlProgressIntro => "An deinem Spiel wird nichts geändert. Wenn du abbrichst, behält Rerun nichts vom laufenden Download.",
        DlFailedTitle => "Der Download ist nicht abgeschlossen",
        DlPackage => "Paket",
        DlLblSource => "Quelle",
        DlLblRelease => "Release",
        DlLblHost => "Server",
        DlLblSha => "SHA-256",
        DlLblLicence => "Lizenz",
        DlLblSize => "Grösse",
        DlLblStatus => "Stand",
        DlSizeLater => "Wird beim Herunterladen angezeigt (der Index nennt keine Grösse)",
        DlChecked => "Wird nach dem Herunterladen geprüft: Rerun behält die Datei nur, wenn sie diesen SHA-256 hat",
        DlBtn => "Herunterladen",
        DlBtnRetry => "Erneut versuchen",
        DlBtnCancel => "Download abbrechen",
        DlCancelling => "Wird abgebrochen ...",
        DlStWaiting => "Wartet",
        DlStDownloading => "Wird heruntergeladen",
        DlStCached => "Schon heruntergeladen; wird nochmals geprüft",
        DlStUnpacking => "Die genannten Dateien werden entpackt",
        DlStDone => "Fertig",
        DlStNotStarted => "Nicht heruntergeladen",
        DlErrOffline => "Rerun erreicht die Quelle nicht. Prüfe deine Internetverbindung und versuche es nochmals.",
        DlErrTimedOut => "Die Quelle hat zu lange nicht geantwortet. Versuche es später nochmals.",
        DlErrInterrupted => "Die Verbindung brach ab, bevor die Datei vollständig war. Rerun hat nichts davon behalten.",
        DlErrRedirect => "Die Quelle hat Rerun an einen nicht erlaubten Ort verwiesen. Rerun ist nicht gefolgt und hat nichts behalten.",
        DlErrStatus => "Die Quelle hat mit einem Fehler geantwortet. Rerun hat nichts behalten.",
        DlErrHash => "Die Datei ist nicht die, die der Index nennt: ihr SHA-256 weicht ab. Rerun hat sie gelöscht.",
        DlErrTooLarge => "Die Datei ist grösser, als Rerun erlaubt. Rerun hat sie gelöscht.",
        DlErrExtract => "Das Paket liess sich nicht sicher entpacken, darum hat Rerun es abgelehnt. An deinem Spiel wurde nichts geändert.",
        DlErrChanged => "Die Paketliste hat sich geändert, seit du sie angesehen hast. Schliesse das und sieh dir den Fix nochmals an.",
        DlErrUnobtainable => "Rerun kann dieses Paket nicht herunterladen.",
        DlErrOther => "Der Download ist fehlgeschlagen. Der Grund steht unten. An deinem Spiel wurde nichts geändert.",
        DlCancelledTitle => "Download abgebrochen",
        DlCancelledBody => "Rerun hat nichts vom laufenden Download behalten. An deinem Spiel wurde nichts geändert.",
        DlClosingTitle => "Rerun bricht zuerst den Download ab",
        DlClosingBody => "Das Fenster schliesst von selbst, sobald der Download gestoppt ist, meist innert Sekunden. Hängt die Verbindung, schliesst es nach 15 Sekunden trotzdem; eine übrig gebliebene temporäre Datei entfernt der nächste Download.",
        DlNoConsentTitle => "Das war nicht der Download, den du gesehen hast",
        DlNoConsentBody => "Öffne den Fix nochmals und lies, was heruntergeladen würde. Es wurde nichts heruntergeladen.",
        DlStFailed => "Fehlgeschlagen",
        DlLblVia => "Darf weiterleiten an",
        DlSize { read, total } => return match total { Some(t) => format!("{} von {}", bytes(read, true), bytes(t, true)), None => format!("{} bisher (die Quelle hat keine Grösse genannt)", bytes(read, true)) }.into(),
        FixHelperAsks => "Braucht Administratorrechte: Beim Anwenden fragt dich Windows nach einer Bestätigung (UAC).",
        FixNoElevation => "Dieser Fix braucht Administratorrechte, und Windows gibt sie diesem Konto nicht (oder die Benutzerkontensteuerung ist aus). Er kann hier nicht angewendet werden.",
        PreviewAdminNoDialog => "Administrator: ja – Windows fragt auf diesem PC nicht nach, dein Klick auf Anwenden ist also die einzige Bestätigung",
        AdminConsent => "Windows zeigt seinen Bestätigungsdialog: Bestätige ihn mit Ja. Rerun wartet, bis du geantwortet hast.",
        AdminCredentials => "Windows fragt nach dem Passwort eines Administratorkontos. Rerun wartet, bis du geantwortet hast.",
        AdminNotSecure => "Der Dialog erscheint auf deinem normalen Desktop und nicht auf dem sicheren, weil dieser auf diesem PC ausgeschaltet ist: Andere Programme könnten ihn erreichen.",
        AdminSignedOnly => "Dieser PC lässt nur signierte Programme als Administrator laufen. Der Helfer dieser Version startet dann vielleicht nicht; dann behält Rerun nichts von der Änderung.",
        UacWaitTitle => "Warte auf Windows-Bestätigung (UAC) ...",
        UacWaitBody => "Bestätige die Abfrage der Benutzerkontensteuerung. Rerun wartet, bis du sie beantwortest; dieses Fenster bleibt so lange offen.",
        UacWaitHidden => "Siehst du den Dialog nicht, schau in der Taskleiste nach einem blinkenden Schild.",
        ResDeclinedTitle => "Nicht angewendet: Administrator-Bestätigung abgelehnt",
        ResDeclinedBody => "Du hast den Windows-Dialog abgelehnt. Rerun hat alles zurückgenommen, was es davor geändert hatte; jetzt ist nichts anders, und die Änderung ist abgeschlossen.",
        ResHelperNotDoneTitle => "Nicht angewendet: Der Administrator-Helfer hat nicht abgeschlossen",
        ResHelperNotDoneBody => "Rerun hat alles zurückgenommen, was es geändert hatte; jetzt ist nichts anders, und die Änderung ist abgeschlossen. Der Grund steht unten.",
        ResHelperOpenBody => "Rerun konnte nicht bestätigen, was der Administrator-Helfer getan hat, darum bleibt die Änderung offen. Es wurde nichts weiter geändert. Mach sie unter Angewendet rückgängig; Windows fragt nochmals, wenn eine Firewall-Regel da ist.",
        ResCleanupOpenBody => "Rerun hat die Änderung zurückgenommen, aber eine ersetzte Datei ist noch in Gebrauch, darum bleibt die Änderung offen, bis Rückgängig unter Angewendet sie entfernt.",
        ResUndoDeclinedTitle => "Nicht rückgängig gemacht: Administrator-Bestätigung abgelehnt",
        ResUndoDeclinedBody => "Du hast den Windows-Dialog abgelehnt. Es wurde nichts rückgängig gemacht; die Änderung bleibt unter Angewendet, wie sie war. Rückgängig fragt Windows nochmals.",
        RefNoElevationTitle => "Windows gibt hier keine Administratorrechte",
        RefNoElevationBody => "Dieses Konto bekommt keine Administratorrechte (oder die Benutzerkontensteuerung ist aus), darum kann Rerun seinen Helfer nicht starten. Es wurde nichts geändert.",
        RefHelperBusyTitle => "Der Administrator-Helfer von Rerun ist noch beschäftigt",
        RefHelperBusyBody => "Ein Helfer eines früheren Laufs arbeitet vielleicht noch, oder ein anderes Programm hält seine Sperre. Warte einen Moment und versuche es dann nochmals. Es wurde nichts geändert.",
        RefUnavailableTitle => "Hier nicht verfügbar",
        RefUnavailableBody => "Dieser Fix kann gerade nicht aus der App angewendet werden. Es wurde nichts geändert.",
        UndoNoElevation => "Das Rückgängigmachen braucht Administratorrechte, und Windows gibt sie diesem Konto nicht (oder die Benutzerkontensteuerung ist aus).",
        FixHelperUnavailable => "Dieser Fix braucht den Administrator-Helfer von Rerun, der hier gerade nicht nutzbar ist. Er kann nicht angewendet werden.",
        UndoHelperUnavailable => "Das Rückgängigmachen braucht den Administrator-Helfer von Rerun, der hier gerade nicht nutzbar ist; bis dahin bleibt die Änderung.",
    };
    Cow::Borrowed(s)
}

#[cfg(test)]
mod tests;
