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

use rerun_core::exec::launch_result::{AppliedCpu, Ended, Mode, Priority, SkipReason, Start};
use rerun_core::journal::TxnId;

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
    /// The language choice that follows Windows (P5-10d).
    LangWindows,
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

    // ---- set-aside Topos (ADR 0024 amendment "Forward compatibility" §10)
    /// The library row and the hero: the only Topos of the game need a newer Rerun.
    BadgeNeedsNewer,
    /// The library row and the hero: this version cannot use the game's Topos.
    BadgeUnsupported,
    /// The hero's second line for [`Msg::BadgeNeedsNewer`].
    HeroNeedsNewerSub,
    /// The hero's second line for [`Msg::BadgeUnsupported`].
    HeroUnsupportedSub,
    /// A note next to a usable Topo: another one needs a newer Rerun.
    NoteAsideNewer,
    /// A note next to a usable Topo: this version cannot use another one.
    NoteAsideUnsupported,
    /// Shows the reasons.
    ShowDetails,
    /// Hides them.
    HideDetails,
    /// The status bar: entries of the index this version does not use.
    StatusAside {
        /// How many.
        count: usize,
    },

    // ---- history and launch results (P5-6a)
    /// The history: how the entries are ordered.
    HistoryOrder,
    /// The history: nothing in the journal.
    HistoryEmpty,
    /// The history: nothing in the journal, second line.
    HistoryEmptySub,
    /// The history: the journal could not be read.
    HistoryUnreadable,
    /// History group: open changes.
    HistGroupOpen,
    /// History group hint: open changes.
    HistGroupOpenHint,
    /// History group: undone changes.
    HistGroupReverted,
    /// History group: rolled back.
    HistGroupRolledBack,
    /// History group hint: rolled back.
    HistGroupRolledBackHint,
    /// History group: closed without undo.
    HistGroupForgotten,
    /// History group hint: closed without undo.
    HistGroupForgottenHint,
    /// A history entry: undone.
    HistStateReverted,
    /// A history entry: rolled back.
    HistStateRolledBack,
    /// A history entry: closed without undo.
    HistStateForgotten,
    /// A history entry: where the backups stay.
    HistoryBackupsIn,
    /// A history entry: files that may remain next to the game files.
    HistoryMayRemain,
    /// The history: entries in the journal folder that are not Rerun's.
    HistoryForeignEntries {
        /// The n.
        n: usize,
    },
    /// A history entry: a forgotten change still holds a launch profile.
    HolderForgotten,
    /// The game page fact: the last start.
    LaunchLast,
    /// The history: heading of the launch results.
    LaunchTitle,
    /// The history: intro of the launch results.
    LaunchIntro,
    /// The history: the launch folder cannot be read.
    LaunchFolderUnreadable,
    /// The history: entries of the launch folder that are not Rerun's.
    LaunchOther {
        /// The n.
        n: usize,
    },
    /// A launch result of a game Rerun cannot name: the label before the profile ID.
    LaunchProfileOf,
    /// A time: less than a minute ago.
    AgoNow,
    /// A time: minutes ago.
    AgoMinutes {
        /// The n.
        n: u64,
    },
    /// A time: hours ago.
    AgoHours {
        /// The n.
        n: u64,
    },
    /// A time: days ago.
    AgoDays {
        /// The n.
        n: u64,
    },
    /// A launch result: the label of the exact time.
    LaunchExact,
    /// A launch result: the rule was applied.
    LaunchBadgeApplied,
    /// A launch result: the game changed the rule after the start.
    LaunchBadgeReset,
    /// A launch result: the process ended before the check.
    LaunchBadgeEnded,
    /// A launch result: the check failed.
    LaunchBadgeFailed,
    /// A launch result: the rule was not applied.
    LaunchBadgeSkipped,
    /// A launch result: the file cannot be read.
    LaunchBadgeUnreadable,
    /// A launch result: the file cannot be read, the sentence.
    LaunchUnreadable,
    /// A launch result: what the rule set.
    LaunchSet {
        /// The cpu.
        cpu: Option<AppliedCpu>,
        /// The priority.
        priority: Option<Priority>,
    },
    /// A launch result: the check found everything as set.
    LaunchCheckOk {
        /// The soft.
        soft: bool,
        /// The watch.
        watch: bool,
    },
    /// A launch result: the game limited itself within the rule.
    LaunchCheckNarrowed,
    /// A launch result: something changed after the start.
    LaunchCheckReset {
        /// The cpu.
        cpu: bool,
        /// The priority.
        priority: bool,
    },
    /// A launch result: the process ended before the check.
    LaunchCheckExitedEarly {
        /// The watch.
        watch: bool,
    },
    /// A launch result: the check itself failed.
    LaunchCheckFailed {
        /// The code.
        code: u32,
    },
    /// A launch result: why the rule was not applied.
    LaunchSkipWhy {
        /// The reason.
        reason: SkipReason,
    },
    /// A launch result: how Steam's command was started.
    LaunchStart {
        /// The start.
        start: Start,
        /// The watch.
        watch: bool,
    },
    /// A launch result: how the paused child with the rule was ended.
    LaunchEnded {
        /// The ended.
        ended: Ended,
    },
    /// A launch note: the option was still set without a profile.
    LaunchOptionStillSet,
    /// A launch note: the option was still set without a profile, a change holds one now (a
    /// reapplied fix needs the option: no advice to remove it).
    LaunchOptionStillSetHeld {
        /// The txn.
        txn: TxnId,
    },
    /// A launch note: the option was still set, a forgotten change left the profile.
    LaunchOptionStillSetForgotten,
    /// A launch note: the check covered a launcher.
    LaunchCheckedLauncher,
    /// A launch note: method watch.
    LaunchWatched,
    /// A launch note: the priority class could not be put back.
    LaunchPriorityNotRestored {
        /// The code.
        code: u32,
    },
    /// A history entry: its plan cannot be read (the reason follows as a detail).
    HistHeadUnreadable,
    // ---- problem states (P5-6b)
    /// A card: an undo began and did not finish.
    StateUndoInterrupted,
    /// A card: what to do after an interrupted undo.
    ProblemUndoInterrupted,
    /// The band on every page: how many changes need you.
    AttentionTitle {
        /// The count.
        count: usize,
    },
    /// The band: what Rerun does and does not do.
    AttentionBody,
    /// The band: the button to the Applied page.
    AttentionView,
    /// An undo report: only Rerun's part of a change was set back.
    ReportDrifted,
    /// An undo report: someone else changed it, Rerun left it as found.
    ReportForeign,
    /// An undo report: the old value is in the journal record.
    ReportForeignInline,
    /// An undo report: a later change relies on it.
    ReportKept,
    /// An undo report: a copy of Rerun's is in use.
    ReportOldInUse,
    /// An undo report: a copy of Rerun's is kept.
    ReportOldKept,
    /// An undo report: a file that is not Rerun's.
    ReportOldForeign,
    /// An undo report: the launch profiles were set back in another folder.
    ReportProfilesMoved,
    /// A result: a rebind that may or may not be on disk.
    ResRebindUnconfirmedTitle,
    /// A result: a rebind that may or may not be on disk.
    ResRebindUnconfirmedBody,
    /// The system page: rules without a change.
    OrphansTitle,
    /// The system page: what the rules are and how to remove them.
    OrphansHint,
    /// The system page: the label of a rule's program.
    OrphansProgram,
    /// The system page: the firewall cannot be read.
    OrphansUnreadable,
    /// The system page: the journal cannot be read.
    OrphansNoJournal,
    /// The band: the journal cannot be read at all.
    AttentionUnreadableTitle,
    /// The band: the journal cannot be read at all.
    AttentionUnreadableBody,
    // ---- the rebind dialog (P5-6c)
    /// The undo dialog: the game folder is another folder now.
    UndoFolderChanged,
    /// The undo dialog: what Rerun can do about it.
    UndoFolderChangedBody,
    /// The undo dialog: the second button.
    RebindCheckBtn,
    /// The rebind dialog: the question.
    RebindTitle,
    /// The rebind dialog: under the question.
    RebindIntro,
    /// The rebind dialog: the folder bound now.
    RebindLblOld,
    /// The rebind dialog: a Steam library.
    RebindLblLibrary,
    /// The rebind dialog: why the recorded folder does not open.
    RebindLblWhy,
    /// The rebind dialog: the folder Steam lists now.
    RebindLblNew,
    /// The rebind dialog: the library that holds it.
    RebindLblNewLibrary,
    /// The rebind dialog: a folder the change created, found in the new folder.
    RebindCreatedFound,
    /// The rebind dialog: a folder the change created, missing in the new folder.
    RebindCreatedMissing,
    /// The rebind dialog: registry changes.
    RebindRegistryNote,
    /// The rebind dialog: only the new folder is undone.
    RebindScopeNote,
    /// The rebind dialog: the binding is permanent.
    RebindPermanentNote,
    /// The rebind dialog: the confirm button.
    RebindBtn,
    /// The rebind dialog: a change with a firewall rule cannot be rebound here.
    RebindFirewallBlocked {
        /// The transaction.
        txn: TxnId,
    },
    /// A refusal of a rebind: the heading.
    RefRebindTitle,
    /// A rebind refusal.
    RefRebindNotNeeded,
    /// A rebind refusal.
    RefRebindManual,
    /// A rebind refusal.
    RefRebindNotApplied,
    /// A rebind refusal.
    RefRebindUndecided,
    /// A rebind refusal.
    RefRebindMoreThanOne,
    /// A rebind refusal.
    RefRebindNoCandidate,
    /// A rebind refusal.
    RefRebindAmbiguous,
    /// A rebind refusal.
    RefRebindLibraryUnreadable,
    /// A rebind refusal.
    RefRebindUpdatePending,
    /// A rebind refusal.
    RefRebindOtherInstallDir,
    /// A rebind refusal.
    RefRebindCandidate,
    /// A rebind refusal.
    RefRebindSharedFolder,
    /// A rebind refusal.
    RefRebindHalts,
    /// A rebind refusal.
    RefRebindNotWritable,
    /// A rebind refusal.
    RefRebindForeign,
    /// A rebind refusal.
    RefRebindRevertPending,
    /// A rebind refusal.
    RefRebindNoRoom,
    /// The rebind dialog: the plan of the change cannot be read.
    RebindHeadUnavailable,
    /// The rebind dialog: the game folder is at the same path but is another folder.
    RebindSamePath,
    /// A rebind result: the record is written, the undo did not finish.
    RebindBoundNow,
    // ---- the tidy history view (P5-6d-0)
    /// A history group: the button that shows its entries.
    HistShowGroup,
    /// A history group: the button that hides its entries.
    HistHideGroup,
    /// A history group: the button that shows more entries.
    HistShowOlder {
        /// How many entries are not shown.
        n: usize,
    },
    // ---- keeping the history short and clearing it (P5-6d-1b)
    /// The history page: what Rerun keeps and when older entries go.
    HistKeepNote {
        /// How many undone or rolled back entries always stay.
        n: usize,
    },
    /// An entry that changed nothing.
    HistStateEmpty,
    /// The history page: the button that opens the clear dialog.
    ClearBtn,
    /// The clear dialog: the title and its confirm button.
    ClearTitle,
    /// The clear dialog: what goes.
    ClearIntro,
    /// The clear dialog: nothing can be removed now.
    ClearNothing,
    /// The clear dialog: the heading of the entries that go.
    ClearEntriesHeading {
        /// How many.
        n: usize,
    },
    /// The clear dialog: the heading of the launch results that go.
    ClearResultsHeading {
        /// How many.
        n: usize,
    },
    /// The clear dialog: the heading of what stays.
    ClearStaysHeading {
        /// How many.
        n: usize,
    },
    /// The clear dialog: the number of an entry.
    ClearNumber {
        /// The journal's sequence number.
        n: u32,
    },
    /// The clear dialog: why an entry stays (not finished).
    ClearKeepNotSettled,
    /// The clear dialog: why an entry stays (its folder cannot be read).
    ClearKeepUnreadable,
    /// The clear dialog: why an entry stays (it holds a launch profile).
    ClearKeepHoldsProfile,
    /// The clear dialog: why an entry stays (a newer change may rely on what it handed over).
    ClearKeepHandedOver,
    /// The clear dialog: why an entry stays (its folder holds something that is not Rerun's).
    ClearKeepForeign,
    /// The clear dialog: why an entry stays (too many files).
    ClearKeepTooMany,
    /// The clear dialog: why an entry stays (closed without undoing, backups kept).
    ClearKeepForgotten,
    /// The clear dialog: why an entry stays (a file is in use).
    ClearKeepInUse,
    /// The clear dialog: why an entry stays (a reason a later version adds).
    ClearKeepOther,
    /// The clear dialog: why a launch result stays (the Steam option is still set).
    ClearResultOptionSet,
    /// The clear dialog: why a launch result stays (it cannot be read).
    ClearResultUnreadable,
    /// The clear dialog: what is not touched.
    ClearUnchanged,
    /// The clear dialog: the preview was shown again because the history changed.
    ClearChanged,
    /// After clearing: the title.
    ClearDoneTitle,
    /// After clearing: how many entries and launch results went.
    ClearDoneBody {
        /// Entries removed.
        entries: usize,
        /// Launch results removed.
        results: usize,
    },
    /// After a write: how many older entries Rerun removed by itself.
    TidyLine {
        /// How many.
        n: usize,
    },
    /// The clear dialog: the empty entries (they changed nothing) as one line.
    ClearEmptySummary {
        /// How many.
        n: usize,
    },

    // ---- the package store in the settings (P5-8b-3)
    /// The settings: the heading of the packages group.
    PkHeading,
    /// The settings: what the packages are and that undoing never needs them.
    PkIntro,
    /// The settings: Rerun holds no package.
    PkEmpty,
    /// A package the current index no longer lists: it cannot be downloaded again.
    PkNotInIndex,
    /// A package's size, files and archives on one line.
    PkFacts {
        /// Files and archives, in bytes.
        bytes: u64,
        /// Its files.
        files: u32,
        /// Its archives in the cache.
        archives: usize,
    },
    /// A package's files are all there.
    PkStateUnpacked,
    /// A package lacks a file of the index.
    PkStateIncomplete,
    /// Only the download of a package is there.
    PkStateArchiveOnly,
    /// "Used by" in front of the game and the change that uses a package.
    PkUsedBy,
    /// No change uses the package.
    PkNotUsed,
    /// The button of a package row that opens the removal dialog.
    PkRemoveBtn,
    /// The button that removes every unused package.
    PkRemoveAllBtn,
    /// Why a package stays: a change that is not settled uses it.
    PkKeepInUse,
    /// Why a package stays: changes cannot be read, so any package may be in use.
    PkKeepUnknownUse {
        /// How many changes cannot be read.
        n: usize,
    },
    /// Why a package stays: its folder holds a link.
    PkKeepReparse,
    /// Why a package stays: its folder holds a file with more than one hard link.
    PkKeepLinked,
    /// Why a package stays: a read-only, hidden or system entry, or one Rerun cannot open.
    PkKeepAttributes,
    /// Why a package stays: too many entries.
    PkKeepTooMany,
    /// Why a package stays: a name that is not Rerun's.
    PkKeepBadName,
    /// Why a package stays: a file is in use right now.
    PkKeepBusy,
    /// Why a package stays: it changed while it was removed.
    PkKeepChanged,
    /// Why a package stays: the drive cannot remove it.
    PkKeepUnsupported,
    /// Why a package stays: a reason a later version adds.
    PkKeepOther,
    /// Why a package stays: only its download is left, which a package that stays needs too.
    PkKeepShared,
    /// Downloads no package of the index names.
    PkLoose {
        /// How many.
        n: usize,
        /// Their bytes.
        bytes: u64,
    },
    /// Leftovers of interrupted downloads.
    PkLeftovers {
        /// How many.
        n: usize,
        /// Their bytes.
        bytes: u64,
    },
    /// The heading of the entries Rerun never touches.
    PkForeignHeading {
        /// How many.
        n: usize,
    },
    /// The package store cannot be shown: the title.
    PkUnreadableTitle,
    /// The package store cannot be shown: what it means.
    PkUnreadableBody,
    /// The removal dialog: the title and its confirm button.
    PkDlgTitle,
    /// The removal dialog: what goes.
    PkDlgIntro,
    /// The removal dialog: nothing can be removed now.
    PkDlgNothing,
    /// The removal dialog: the heading of the packages that go.
    PkDlgGoesHeading {
        /// How many.
        n: usize,
    },
    /// The removal dialog: the heading of the downloads without a package that go.
    PkDlgLooseHeading {
        /// How many.
        n: usize,
    },
    /// The removal dialog: leftovers that go.
    PkDlgLeftovers {
        /// How many.
        n: usize,
        /// Their bytes.
        bytes: u64,
    },
    /// The removal dialog: the button that shows the files of a package.
    PkDlgFilesShow {
        /// Files and archives.
        n: usize,
    },
    /// The removal dialog: the button that hides them again.
    PkDlgFilesHide,
    /// The removal dialog: the bytes it frees.
    PkDlgFreed {
        /// The bytes.
        bytes: u64,
    },
    /// The removal dialog: what is not touched.
    PkDlgUnchanged,
    /// The removal dialog: shown again because the store or the use of a package changed.
    PkDlgChanged,
    /// After a removal: the title.
    PkDoneTitle,
    /// After a removal: what went.
    PkDoneBody {
        /// Packages removed.
        packages: usize,
        /// Archives removed.
        archives: usize,
        /// Leftovers removed.
        leftovers: usize,
        /// Bytes freed.
        bytes: u64,
    },
    /// After a removal: nothing went.
    PkDoneNothing,
    /// The package asked for is not in the store any more: the title.
    PkGoneTitle,
    /// The package asked for is not in the store any more: what happens.
    PkGoneBody,
    /// A removal refused: a change uses the package (title).
    RefPkInUseTitle,
    /// A removal refused: a change uses the package (body).
    RefPkInUseBody,
    /// A removal refused: the store changed since the list (title).
    RefPkChangedTitle,
    /// A removal refused: the store changed since the list (body).
    RefPkChangedBody,
    /// A removal refused: another Rerun downloads or unpacks (title).
    RefPkBusyTitle,
    /// A removal refused: another Rerun downloads or unpacks (body).
    RefPkBusyBody,
    // ---- links, the report and the data folder (P5-10a)
    /// The game page: the button that opens the report dialog.
    ReportBtn,
    /// The report dialog: the title.
    ReportTitle,
    /// The report dialog: what happens with the text.
    ReportIntro,
    /// The report dialog: where it goes and what it needs.
    ReportWhere,
    /// The report dialog: the label of the issue's title.
    ReportLabelTitle,
    /// The report dialog: the label of the issue's text.
    ReportLabelText,
    /// The confirm of the report dialog, and what a source link's button does.
    OpenInBrowser,
    /// The button next to a source link of a fix.
    SourceOpen,
    /// A link or the folder was not opened: the title.
    OpenFailedTitle,
    /// Not opened: the link is not of the form Rerun opens.
    OpenRefusedForm,
    /// Not opened: the current index no longer has the link.
    OpenNotInIndex,
    /// Not opened: Rerun's folder does not exist.
    OpenNoFolder,
    /// Not opened: Windows could not open it.
    OpenShellFailed,
    /// Not opened: the dialog was out of date.
    OpenStale,
    /// The settings: the heading of the data group.
    SettingsData,
    /// The settings: what Rerun's folder holds.
    DataIntro,
    /// The settings: the button that shows Rerun's folder in Explorer.
    DataOpenBtn,
    /// The settings: Rerun's folder does not exist yet.
    DataNotCreated,
    /// The settings: where Rerun's folder is cannot be told.
    DataUnknown,
    /// The settings: the second theme's name (P5-10c).
    ThemeNacht,
    /// The settings: what the two themes are.
    SetThemeDesc,
    /// The settings: Windows' high contrast is on and overrides the theme.
    ThemeHighContrast,
    /// The language choice: English (written in English in both languages).
    LangEnglish,
    /// The language choice: German (written in German in both languages).
    LangGerman,
    /// The settings: that the language applies at once.
    SetLanguageDesc,
    /// The library view: one short line per game.
    ViewCompact,
    /// The settings: the library view.
    SetLibraryView,
    /// The settings: what the two library views are.
    SetLibraryViewDesc,
    /// About Rerun (P5-10e): the copyright line.
    AboutCopyright,
    /// About Rerun: the build ID's label.
    AboutBuild,
    /// About Rerun: the Topo index's label.
    AboutIndex,
    /// About Rerun: the licence's label.
    AboutLicenceTitle,
    /// About Rerun: the GPL notice (free software, GPL-3.0-only for the app, no warranty).
    AboutGpl,
    /// About Rerun: the link to the source code of this build.
    AboutSource,
    /// About Rerun: the link to the repository.
    AboutRepository,
    /// About Rerun: the third-party licences (also the dialog's title).
    AboutLicences,
    /// About Rerun: what the third-party licences are.
    AboutLicencesDesc,
    /// About Rerun: the button that shows them.
    AboutLicencesShow,
    /// The licences dialog: its close button.
    LicencesClose,
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

/// `parts` as "a, b and c".
fn join_and(parts: &[String], and: &str) -> String {
    match parts {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} {and} {last}", init.join(", ")),
    }
}

/// What a removal came to as a sentence part (the empty counts left out).
fn removed_parts(counts: [usize; 3], names: [(&str, &str); 3], and: &str) -> String {
    let v: Vec<String> = counts
        .into_iter()
        .zip(names)
        .filter(|(n, _)| *n > 0)
        .map(|(n, (one, many))| count(n, one, many))
        .collect();
    join_and(&v, and)
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
        LangWindows => "Like Windows",
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
        ProblemCleanup => "Everything is undone, but a copy Rerun left is still there, in use or kept next to a file that changed. Undo once more deletes it when that is safe; the report of the undo names the way out.",
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
        BadgeNeedsNewer => "Needs a newer version of Rerun",
        BadgeUnsupported => "Not supported by this version of Rerun",
        HeroNeedsNewerSub => "A newer version of Rerun can read the Topo for this game. Until then Rerun offers nothing and changes nothing.",
        HeroUnsupportedSub => "This version of Rerun cannot use the Topo for this game. Rerun offers nothing and changes nothing.",
        NoteAsideNewer => "Another Topo for this game needs a newer version of Rerun.",
        NoteAsideUnsupported => "Another Topo for this game is not supported by this version of Rerun.",
        ShowDetails => "Show details",
        HideDetails => "Hide details",
        StatusAside { count: n } => {
            return format!("{} not usable", count(n, "entry", "entries")).into();
        }
        HistoryOrder => "Newest first. The journal keeps the order of the entries, not their time.",
        HistoryEmpty => "Nothing in the journal yet",
        HistoryEmptySub => "Rerun writes an entry before it changes anything.",
        HistoryUnreadable => "The journal could not be read.",
        HistGroupOpen => "Open",
        HistGroupOpenHint => "These are still under Applied, where you can undo or close them.",
        HistGroupReverted => "Undone",
        HistGroupRolledBack => "Rolled back",
        HistGroupRolledBackHint => "An apply failed and Rerun put everything back.",
        HistGroupForgotten => "Closed without undoing",
        HistGroupForgottenHint => "Rerun cannot undo these any more. What they changed stays, and their backups stay where listed.",
        HistStateReverted => "Undone",
        HistStateRolledBack => "Rolled back",
        HistStateForgotten => "Closed without undo",
        HistoryBackupsIn => "Backups stay in",
        HistoryMayRemain => "These files may remain next to the game's files",
        HistoryForeignEntries { n } => {
            return format!("{} in the journal folder not Rerun's (not read)", count(n, "other entry", "other entries")).into();
        }
        HolderForgotten => "It still holds the launch profile. The Steam launch option keeps working until you remove it by hand.",
        LaunchLast => "Last start",
        LaunchTitle => "Last start of each game",
        LaunchIntro => "Written by Rerun's launcher each time Steam starts a game through it.",
        LaunchFolderUnreadable => "The launch results cannot be read.",
        LaunchOther { n } => {
            return format!("{} in the launch folder not Rerun's (not read)", count(n, "other entry", "other entries")).into();
        }
        LaunchProfileOf => "Profile",
        AgoNow => "just now",
        AgoMinutes { n } => {
            return (if n == 1 { "1 minute ago".to_owned() } else { format!("{n} minutes ago") }).into();
        }
        AgoHours { n } => {
            return (if n == 1 { "1 hour ago".to_owned() } else { format!("{n} hours ago") }).into();
        }
        AgoDays { n } => {
            return (if n == 1 { "1 day ago".to_owned() } else { format!("{n} days ago") }).into();
        }
        LaunchExact => "Exact time",
        LaunchBadgeApplied => "Rule applied",
        LaunchBadgeReset => "Changed after start",
        LaunchBadgeEnded => "Ended early",
        LaunchBadgeFailed => "Check failed",
        LaunchBadgeSkipped => "Rule not applied",
        LaunchBadgeUnreadable => "Unreadable",
        LaunchUnreadable => "Rerun cannot read this result.",
        LaunchSet { cpu, priority } => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(c) = cpu {
                let kind = match c.mode {
                    Mode::Hard => "hard limit",
                    Mode::Soft => "soft limit, CPU Sets",
                };
                parts.push(format!("{} of {} threads ({kind})", c.threads, c.of));
            }
            if let Some(p) = priority {
                let word = match p {
                    Priority::Normal => "normal",
                    Priority::AboveNormal => "above normal",
                    Priority::High => "high",
                };
                parts.push(format!("priority {word}"));
            }
            if parts.is_empty() {
                return "Set: no CPU rule, no priority".into();
            }
            return format!("Set: {}", parts.join(", ")).into();
        }
        LaunchCheckOk { soft, watch } => {
            return match (soft, watch) {
                (true, true) => "Checked about 5 seconds after the start: as set. CPU Sets of the game process only; whether threads already running follow them is unproven.",
                (true, false) => "Checked about 5 seconds after the start: as set. CPU Sets of the started process only.",
                (false, _) => "Checked about 5 seconds after the start: as set.",
            }
            .into();
        }
        LaunchCheckNarrowed => "The game limited itself to fewer threads within the rule. That is not an error; the rule holds.",
        LaunchCheckReset { cpu, priority } => {
            return match (cpu, priority) {
                (true, true) => "The affinity and the priority changed after the start.",
                (true, false) => "The affinity changed after the start.",
                _ => "The priority changed after the start.",
            }
            .into();
        }
        LaunchCheckExitedEarly { watch } => {
            return if watch {
                "The game process ended within 5 seconds, before the check, and no other one followed in time. It crashed, or it hands over to a process of another path."
            } else {
                "The started process ended within 5 seconds, before the check. It crashed, or it is a launcher that starts the game as another process."
            }
            .into();
        }
        LaunchCheckFailed { code } => {
            return format!("The check failed (Windows error {code}).").into();
        }
        LaunchSkipWhy { reason } => {
            return match reason {
                SkipReason::ProfileMissing => "The launch profile was missing.".to_owned(),
                SkipReason::ProfileUnreadable { code } => format!("The profile could not be read (Windows error {code})."),
                SkipReason::ProfileReparsePoint => "The profile is a link; Rerun does not follow it.".to_owned(),
                SkipReason::ProfileNotAFile => "The profile is not a file.".to_owned(),
                SkipReason::ProfileInvalid => "The profile is too large or cannot be decoded.".to_owned(),
                SkipReason::MethodUnsupported => "The result was written by an older launcher that did not know method watch.".to_owned(),
                SkipReason::PathMismatch => "Steam started another program than the profile names.".to_owned(),
                SkipReason::TopologyUnavailable => "The processor layout could not be read.".to_owned(),
                SkipReason::TopologyInvalid => "Windows reported a processor layout Rerun does not accept.".to_owned(),
                SkipReason::SelectionEmpty => "The rule selects no processor on this PC.".to_owned(),
                SkipReason::MaskTooWide => "The selection does not fit the affinity mask of this build.".to_owned(),
                SkipReason::SpawnFailed { code } => format!("The job or the paused process could not be created (Windows error {code})."),
                SkipReason::JobFailed { code } => format!("The processor limit of the job could not be set (Windows error {code})."),
                SkipReason::ReadBackFailed { code } => format!("The limit could not be read back (Windows error {code})."),
                SkipReason::Mismatch => "The limit read back differed from the selection.".to_owned(),
                SkipReason::CpuSetsFailed { code } => format!("The CPU Sets could not be set (Windows error {code})."),
                SkipReason::ResumeFailed { code } => format!("The paused process could not be resumed (Windows error {code})."),
                SkipReason::ElevationRequired => "The game needs administrator rights, so it started through the Windows prompt without a rule.".to_owned(),
                SkipReason::RunFailed { code } => format!("The program the profile names instead of Steam's could not be started (Windows error {code}); Steam's own program started without the rule."),
                SkipReason::TargetNotFound => "No new game process appeared within 120 seconds. A launcher may be waiting for a login or an update; start the game again.".to_owned(),
                SkipReason::JobIneffective => "The game process joined the job but kept another limit, from a job it was already in.".to_owned(),
                SkipReason::TargetElevated => "The game process runs as administrator; Rerun leaves it alone.".to_owned(),
                SkipReason::TargetDenied { code } => format!("A process of the game's name could not be opened (Windows error {code}): protected, another account, or running as administrator. Nothing was set."),
                SkipReason::SearchFailed { code } => format!("No game process could be looked for (Windows error {code}). Nothing was set."),
                SkipReason::PriorityFailed { code } => format!("The priority class of the game process could not be read or set (Windows error {code}). Nothing was set."),
            }
            .into();
        }
        LaunchStart { start, watch } => {
            return match start {
                Start::Created if watch => "Steam's command started unchanged.".to_owned(),
                Start::Created => "The game started unchanged.".to_owned(),
                Start::Shell | Start::ShellNoProcess => "The game started unchanged through the Windows prompt for administrator rights.".to_owned(),
                Start::NotExe => "Nothing started (not an .exe).".to_owned(),
                Start::Failed { code } => format!("Nothing started (Windows error {code})."),
            }
            .into();
        }
        LaunchEnded { ended } => {
            return match ended {
                Ended::Ended => "The paused process created with the rule was ended first.".to_owned(),
                Ended::Failed { code } => format!("The paused process created with the rule could not be ended (Windows error {code})."),
                Ended::NotConfirmed { code } => format!("The paused process created with the rule was not seen ending (Windows error {code})."),
            }
            .into();
        }
        LaunchOptionStillSet => "The Steam launch option for Rerun's launcher was still set at that start, but no profile was found. The game starts unchanged through it; remove the option in Steam.",
        LaunchOptionStillSetHeld { txn } => {
            return format!("The Steam launch option for Rerun's launcher was still set at that start, but no profile was found, so the game started unchanged. Change {txn} holds this profile now; see it under Applied.").into();
        }
        LaunchOptionStillSetForgotten => "The Steam launch option was still set at that start. A change closed without undoing it left a profile that was missing then. Remove the launch option by hand.",
        LaunchCheckedLauncher => "Steam starts a launcher here. The check covered the launcher, not the game.",
        LaunchWatched => "Method watch: the rule is for the game process found after the start, not for the program Steam starts.",
        LaunchPriorityNotRestored { code } => {
            return format!("The priority class set on the game process could not be put back (Windows error {code}). It stays until the game exits.").into();
        }
        HistHeadUnreadable => "Its plan cannot be read, so what it changed cannot be listed.",
        StateUndoInterrupted => "Undo interrupted",
        ProblemUndoInterrupted => "An undo of this change began and did not finish. Undo it again to finish, or close it without undoing.",
        AttentionTitle { count } => {
            return (if count == 1 { "1 change needs you".to_owned() } else { format!("{count} changes need you") }).into();
        }
        AttentionBody => "Rerun changes nothing by itself. Look at them under Applied, then decide whether to undo or close them.",
        AttentionView => "View",
        ReportDrifted => "Only Rerun's part was set back; what changed since stays.",
        ReportForeign => "Someone else changed it, so Rerun left it as found. Closing the change without undoing ends it.",
        ReportForeignInline => "Its old value is kept in the journal entry.",
        ReportKept => "A later change relies on it, so Rerun left it to that change.",
        ReportOldInUse => "A copy of Rerun's is still in use, so it stays until the program using it ends. Undo again then:",
        ReportOldKept => "A copy of Rerun's is kept next to a file that changed since, as it may be the last copy of a state. Delete it by hand, or close the change without undoing:",
        ReportOldForeign => "This is not Rerun's copy; Rerun did not touch it:",
        ReportProfilesMoved => "The launch profiles were set back in another folder than the plan names:",
        ResRebindUnconfirmedTitle => "Rerun cannot tell whether the new folder was recorded",
        ResRebindUnconfirmedBody => "The change may be bound to the new folder now, but the journal cannot be read again to confirm it. Look at Applied to see where things stand.",
        OrphansTitle => "Firewall rules of Rerun without a change",
        OrphansHint => "No change of this Windows account owns these rules. They may belong to another account. Rerun does not remove them; remove them in Windows Defender Firewall with Advanced Security.",
        OrphansProgram => "Program",
        OrphansUnreadable => "The firewall cannot be read now, so Rerun cannot list its rules.",
        OrphansNoJournal => "The journal cannot be read now, so the rules cannot be matched to changes.",
        AttentionUnreadableTitle => "The journal cannot be read",
        AttentionUnreadableBody => "Rerun cannot tell what it has changed, and changes nothing by itself. Look under Applied for the reason.",
        UndoFolderChanged => "The game folder has changed",
        UndoFolderChangedBody => "Steam may have moved or reinstalled the game. Rerun can check the folder Steam lists now; nothing changes before you confirm. A folder you chose yourself is never rebound: close the change without undoing instead.",
        RebindCheckBtn => "Check new folder",
        RebindTitle => "Bind this change to the new folder?",
        RebindIntro => "Nothing has been changed yet. Rerun would bind this change to the folder Steam lists now and undo it there, newest change first:",
        RebindLblOld => "Recorded folder",
        RebindLblLibrary => "Library",
        RebindLblWhy => "Why it does not open",
        RebindLblNew => "Folder Steam lists now",
        RebindLblNewLibrary => "Its library",
        RebindCreatedFound => "Folder the change created, found there; it is removed only if it is empty",
        RebindCreatedMissing => "Folder the change created, missing there",
        RebindRegistryNote => "Registry changes are undone where Rerun made them, also a compatibility-layer value under the old program path; a value under the new program path is not touched.",
        RebindScopeNote => "Only the folder bound now is undone; a copy of the game elsewhere (a renamed old folder, a library removed from Steam while its drive was away) keeps Rerun's files.",
        RebindPermanentNote => "The new binding is permanent: every later undo of this change uses the new folder.",
        RebindBtn => "Rebind and undo",
        RebindFirewallBlocked { txn } => {
            return format!("This change includes a firewall rule, which needs the Windows administrator prompt. Rebinding it from the app is not offered yet; use the command line: rerun revert {txn} --rebind.").into();
        }
        RefRebindTitle => "Rerun cannot bind this change to a new folder",
        RefRebindNotNeeded => "Every folder of this change opens as recorded. Undo it without a rebind.",
        RefRebindManual => "You chose this game folder yourself, so Rerun never rebinds it. Only closing the change without undoing ends it.",
        RefRebindNotApplied => "Only an applied change can be rebound. Undo it, or close it without undoing.",
        RefRebindUndecided => "Rerun cannot check the folder now. Try again later.",
        RefRebindMoreThanOne => "More than one folder of this change does not open, and a rebind binds only one.",
        RefRebindNoCandidate => "No Steam library holds the game now.",
        RefRebindAmbiguous => "The game is in more than one Steam library. Rerun does not choose between them.",
        RefRebindLibraryUnreadable => "A Steam library, or the game's manifest, cannot be read now. A rebind needs every library readable. Try again later.",
        RefRebindUpdatePending => "Steam is updating the game. Try again when it has finished.",
        RefRebindOtherInstallDir => "The game is installed in another folder in that library. Rerun does not bind that.",
        RefRebindCandidate => "The folder in that library cannot be opened.",
        RefRebindSharedFolder => "The folder in that library is another folder of this change already.",
        RefRebindHalts => "The undo would also stop at another folder of this change. Make it available first.",
        RefRebindNotWritable => "Rerun cannot write to the folder in that library.",
        RefRebindForeign => "A change there is not as Rerun left it. Only closing the change without undoing ends it.",
        RefRebindRevertPending => "An undo of a change in that folder has begun. Only closing the change without undoing ends it.",
        RefRebindNoRoom => "The journal of this change has no room for a rebind. Only closing it without undoing ends it.",
        RebindHeadUnavailable => "The plan of this change cannot be read, so Rerun cannot tell whether it still has a firewall rule that needs the administrator prompt. Rebinding it from the app is not offered.",
        RebindSamePath => "The folder is at the same path as recorded, but it is another folder now (the game was reinstalled).",
        RebindBoundNow => "This change is bound to the new folder now. Undo it again to finish, or close it without undoing.",
        HistShowGroup => "Show",
        HistHideGroup => "Hide",
        HistShowOlder { n } => {
            return format!("Show older ({n} not shown)").into();
        }
        HistKeepNote { n } => {
            return format!("Rerun keeps the last {n} undone or rolled back entries; older ones are removed when you apply or undo something.").into();
        }
        HistStateEmpty => "Changed nothing",
        ClearBtn => "Clear history\u{2026}",
        ClearTitle => "Clear history",
        ClearIntro => "These entries and launch results are removed from the history.",
        ClearNothing => "There is nothing Rerun can remove from the history now.",
        ClearEntriesHeading { n } => {
            return format!("Entries to be removed ({n})").into();
        }
        ClearResultsHeading { n } => {
            return format!("Launch results to be removed ({n})").into();
        }
        ClearStaysHeading { n } => {
            return format!("Stays ({n})").into();
        }
        ClearNumber { n } => {
            return format!("No. {n}").into();
        }
        ClearKeepNotSettled => "Not finished: undo it or close it first.",
        ClearKeepUnreadable => "Its folder cannot be read.",
        ClearKeepHoldsProfile => "It still holds a launch profile.",
        ClearKeepHandedOver => "It handed files over to a later change that is not finished yet.",
        ClearKeepForeign => "Its folder holds something Rerun did not write there.",
        ClearKeepTooMany => "Its folder has too many files.",
        ClearKeepForgotten => "Its backups stay.",
        ClearKeepInUse => "A backup is in use right now; a later clean-up removes the entry.",
        ClearKeepOther => "Rerun keeps it for now.",
        ClearResultOptionSet => "The Steam launch option still points at Rerun: remove it by hand first.",
        ClearResultUnreadable => "It cannot be read.",
        ClearUnchanged => "Game folders, the registry and the firewall stay unchanged.",
        ClearChanged => "The history changed; look at it again.",
        ClearDoneTitle => "History cleared",
        ClearDoneBody { entries, results } => {
            return format!(
                "{} and {} removed.",
                count(entries, "entry", "entries"),
                count(results, "launch result", "launch results")
            )
            .into();
        }
        ClearEmptySummary { n } => {
            return if n == 1 {
                "1 empty entry (changed nothing)".into()
            } else {
                format!("{n} empty entries (changed nothing)").into()
            };
        }
        PkHeading => "Packages",
        PkIntro => "Rerun keeps the packages it downloaded for fixes. Undoing a fix never needs them. A package you remove is downloaded again when a fix needs it, if the index still lists it.",
        PkEmpty => "Rerun holds no packages.",
        PkNotInIndex => "Not in the index: it can't be downloaded again.",
        PkFacts { bytes: b, files, archives } => {
            return format!(
                "{} \u{b7} {} \u{b7} {}",
                bytes(b, false),
                count(files as usize, "file", "files"),
                count(archives, "archive", "archives")
            )
            .into();
        }
        PkStateUnpacked => "Unpacked",
        PkStateIncomplete => "Incomplete",
        PkStateArchiveOnly => "Download only",
        PkUsedBy => "Used by",
        PkNotUsed => "Not used",
        PkRemoveBtn => "Remove\u{2026}",
        PkRemoveAllBtn => "Remove all unused\u{2026}",
        PkKeepInUse => "A change that is not undone or closed uses it: undo it first.",
        PkKeepUnknownUse { n } => {
            return if n == 1 {
                "1 change cannot be read, so any package may be in use. Look at the history.".into()
            } else {
                format!("{n} changes cannot be read, so any package may be in use. Look at the history.").into()
            };
        }
        PkKeepReparse => "Its folder holds a link (a junction or a symbolic link).",
        PkKeepLinked => "Its folder holds a file with more than one hard link.",
        PkKeepAttributes => "Its folder holds a read-only, hidden or system entry, or one Rerun cannot open.",
        PkKeepTooMany => "Its folder holds too many entries.",
        PkKeepBadName => "Its folder holds a name that is not Rerun's.",
        PkKeepBusy => "A file is in use right now (a virus scanner, say): try again later.",
        PkKeepChanged => "It changed while it was removed: look at the list again.",
        PkKeepUnsupported => "The drive does not allow it to be removed (FAT or exFAT).",
        PkKeepOther => "Rerun does not remove it.",
        PkKeepShared => "Only its download is left, and a package that stays needs it too.",
        PkLoose { n, bytes: b } => {
            return if n == 1 {
                format!("1 download without a package ({})", bytes(b, false)).into()
            } else {
                format!("{n} downloads without a package ({})", bytes(b, false)).into()
            };
        }
        PkLeftovers { n, bytes: b } => {
            return if n == 1 {
                format!("1 leftover of an interrupted download ({})", bytes(b, false)).into()
            } else {
                format!("{n} leftovers of interrupted downloads ({})", bytes(b, false)).into()
            };
        }
        PkForeignHeading { n } => {
            return format!("Not Rerun's, never touched ({n})").into();
        }
        PkUnreadableTitle => "The packages cannot be shown",
        PkUnreadableBody => "Rerun could not read its package folder or the history that says which packages are in use. Nothing was changed.",
        PkDlgTitle => "Remove packages",
        PkDlgIntro => "These packages are removed from Rerun's store.",
        PkDlgNothing => "There is nothing Rerun can remove from the store now.",
        PkDlgGoesHeading { n } => {
            return format!("Packages to be removed ({n})").into();
        }
        PkDlgLooseHeading { n } => {
            return format!("Downloads without a package to be removed ({n})").into();
        }
        PkDlgLeftovers { n, bytes: b } => {
            return format!("Leftovers to be removed: {n} ({})", bytes(b, false)).into();
        }
        PkDlgFilesShow { n } => {
            return format!("Show the files ({n})").into();
        }
        PkDlgFilesHide => "Hide the files",
        PkDlgFreed { bytes: b } => {
            return format!("This frees {}.", bytes(b, false)).into();
        }
        PkDlgUnchanged => "Game folders, the registry and the firewall stay unchanged. Undoing a fix never needs a package.",
        PkDlgChanged => "The packages changed; look at them again.",
        PkDoneTitle => "Packages removed",
        PkDoneBody { packages, archives, leftovers, bytes: b } => {
            let what = removed_parts(
                [packages, archives, leftovers],
                [("package", "packages"), ("archive", "archives"), ("leftover", "leftovers")],
                "and",
            );
            return format!("{what} removed, {} freed.", bytes(b, false)).into();
        }
        PkDoneNothing => "Nothing was removed.",
        PkGoneTitle => "The package is not in the store any more",
        PkGoneBody => "The list is read again. Nothing was changed.",
        RefPkInUseTitle => "A change still uses the package",
        RefPkInUseBody => "Undo or close that change first. Nothing was removed.",
        RefPkChangedTitle => "The packages changed",
        RefPkChangedBody => "Look at the list again. Nothing was removed.",
        RefPkBusyTitle => "Rerun is downloading or unpacking a package",
        RefPkBusyBody => "Try again when it has finished. Nothing was removed.",
        ReportBtn => "Report a problem\u{2026}",
        ReportTitle => "Report a problem",
        ReportIntro => "Rerun opens a new issue on GitHub in your browser, filled in with exactly this text. GitHub receives it as soon as the page opens. You can still change it there; nothing is submitted until you do.",
        ReportWhere => "Destination: github.com/mythenstudios/rerun. You need a GitHub account to submit it. The text holds only facts Rerun determines itself: no game name, no path, no account.",
        ReportLabelTitle => "Title",
        ReportLabelText => "Text",
        OpenInBrowser => "Open in browser",
        SourceOpen => "Open",
        OpenFailedTitle => "Nothing was opened",
        OpenRefusedForm => "Rerun opens only plain https links, and this one is not.",
        OpenNotInIndex => "The current index no longer has this link.",
        OpenNoFolder => "Rerun's folder does not exist yet.",
        OpenShellFailed => "Windows could not open it. The details say why.",
        OpenStale => "The dialog was out of date. Open it again.",
        SettingsData => "Data",
        DataIntro => "Rerun keeps its index, the changes it made with their backups, and its downloads in this folder. It is fixed; Rerun only shows it here.",
        DataOpenBtn => "Open in Explorer",
        DataNotCreated => "Not created yet. Rerun creates it when it first stores something.",
        DataUnknown => "Rerun cannot tell where its folder is.",
        ThemeNacht => "Night",
        SetThemeDesc => "Both are dark. Mythen is black and white, Night uses the greys of Windows 11.",
        ThemeHighContrast => "Windows high contrast is on, so Rerun uses its colours. The theme applies again once it is off.",
        LangEnglish => "English",
        LangGerman => "Deutsch",
        SetLanguageDesc => "Applies at once. Rerun reads the games again so that the library speaks the new language, too.",
        ViewCompact => "Compact",
        SetLibraryView => "Library view",
        SetLibraryViewDesc => "The list shows the graphics API and the executable of each game. Compact shows one short line per game.",
        AboutCopyright => "Copyright \u{00A9} 2026 Mythen Studios",
        AboutBuild => "Build",
        AboutIndex => "Topo index",
        AboutLicenceTitle => "Licence",
        AboutGpl => "Rerun is free software: you may pass it on and change it under the GNU General Public License, version 3 or (at your choice) any later version. This app links Slint under GPL-3.0-only and is therefore under version 3 only. Rerun comes with no warranty, to the extent the law allows. The full licence text is the first entry of the third-party licences.",
        AboutSource => "Source code of this version",
        AboutRepository => "Repository",
        AboutLicences => "Third-party licences",
        AboutLicencesDesc => "Rerun builds on open-source crates and on the fonts Archivo and IBM Plex (SIL Open Font License 1.1). Here are their licence texts and copyright notices, generated from the crates this version is built from.",
        AboutLicencesShow => "Show licences",
        LicencesClose => "Close",
        TidyLine { n } => {
            return if n == 1 {
                "1 older history entry removed".into()
            } else {
                format!("{n} older history entries removed").into()
            };
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
        BadgeNoIndex => "Kein Topo-Index",
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
        IndexNoneTitle => "Rerun hat noch keinen Topo-Index.",
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
        HeroNoIndex => "Rerun hat noch keinen Topo-Index. Es bietet nichts an und ändert nichts.",
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
        SystemTitle => "System",
        SystemIntro => {
            "Diese Angaben liest Rerun, wenn du diese Seite öffnest. Danach richtet sich, welche Probleme zu deinem PC passen."
        }
        SystemReading => "Rerun liest das System ein.",
        SysGraphics => "Grafik",
        SysProcessor => "Prozessor",
        SysWindows => "Windows",
        SysSac => "Intelligente App-Steuerung",
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
        LangWindows => "Wie Windows",
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
        WarnSacOn => "Die Intelligente App-Steuerung ist an und kann die gepatchte Datei blockieren. Rückgängig stellt das Original wieder her.",
        WarnSacEvaluation => "Die Intelligente App-Steuerung ist im Testmodus und blockiert jetzt nichts, aber Windows kann sie später einschalten und dann die gepatchte Datei blockieren. Rückgängig stellt das Original wieder her.",
        WarnSacUnknown => "Rerun kann den Zustand der Intelligenten App-Steuerung nicht lesen. Die App-Steuerung kann die gepatchte Datei blockieren. Rückgängig stellt das Original wieder her.",
        WarnSteamPerUser => "Steam hat dieses Programm für dein Konto gebaut. Die Intelligente App-Steuerung kennt die gepatchte Kopie nicht und blockiert sie wahrscheinlich.",
        WarnSignedExe => "Das Programm hat eine digitale Signatur. Der Patch macht sie ungültig.",
        WarnWhenUnknown => "Rerun kann nicht sagen, ob ein gewähltes Problem deinen PC betrifft.",
        WarnNeedsRetest => "Dieser Topo soll neu geprüft werden.",
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
        ProblemCleanup => "Alles ist rückgängig gemacht, aber eine Kopie, die Rerun hinterlassen hat, ist noch da, in Gebrauch oder neben einer Datei, die sich geändert hat. Nochmals Rückgängig löscht sie, sobald das sicher ist; der Bericht zum Rückgängigmachen nennt den Ausweg.",
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
        DlBtnRetry => "Nochmals versuchen",
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
        BadgeNeedsNewer => "Braucht eine neuere Rerun-Version",
        BadgeUnsupported => "Von dieser Rerun-Version nicht unterstützt",
        HeroNeedsNewerSub => "Eine neuere Rerun-Version kann den Topo für dieses Spiel lesen. Bis dahin bietet Rerun nichts an und ändert nichts.",
        HeroUnsupportedSub => "Diese Rerun-Version kann den Topo für dieses Spiel nicht verwenden. Rerun bietet nichts an und ändert nichts.",
        NoteAsideNewer => "Ein weiterer Topo für dieses Spiel braucht eine neuere Rerun-Version.",
        NoteAsideUnsupported => "Ein weiterer Topo für dieses Spiel wird von dieser Rerun-Version nicht unterstützt.",
        ShowDetails => "Details zeigen",
        HideDetails => "Details ausblenden",
        StatusAside { count: n } => {
            return format!("{} nicht nutzbar", count(n, "Eintrag", "Einträge")).into();
        }
        HistoryOrder => "Neueste zuerst. Das Journal hält die Reihenfolge der Einträge fest, nicht ihre Zeit.",
        HistoryEmpty => "Noch nichts im Journal",
        HistoryEmptySub => "Rerun schreibt einen Eintrag, bevor es etwas ändert.",
        HistoryUnreadable => "Das Journal konnte nicht gelesen werden.",
        HistGroupOpen => "Offen",
        HistGroupOpenHint => "Diese stehen noch unter Angewendet, wo du sie rückgängig machen oder abschliessen kannst.",
        HistGroupReverted => "Rückgängig gemacht",
        HistGroupRolledBack => "Zurückgerollt",
        HistGroupRolledBackHint => "Ein Anwenden ist fehlgeschlagen, und Rerun hat alles zurückgesetzt.",
        HistGroupForgotten => "Abgeschlossen ohne Rückgängig",
        HistGroupForgottenHint => "Rerun kann diese nicht mehr rückgängig machen. Was sie geändert haben, bleibt, und ihre Sicherungen bleiben dort, wo sie stehen.",
        HistStateReverted => "Rückgängig gemacht",
        HistStateRolledBack => "Zurückgerollt",
        HistStateForgotten => "Ohne Rückgängig abgeschlossen",
        HistoryBackupsIn => "Die Sicherungen bleiben in",
        HistoryMayRemain => "Diese Dateien können neben den Spieldateien bleiben",
        HistoryForeignEntries { n } => {
            return format!("{} im Journal-Ordner, nicht von Rerun (nicht gelesen)", count(n, "anderer Eintrag", "andere Einträge")).into();
        }
        HolderForgotten => "Es hält noch das Startprofil. Die Steam-Startoption wirkt weiter, bis du sie von Hand entfernst.",
        LaunchLast => "Letzter Start",
        LaunchTitle => "Letzter Start je Spiel",
        LaunchIntro => "Vom Rerun-Starter geschrieben, jedes Mal wenn Steam ein Spiel über ihn startet.",
        LaunchFolderUnreadable => "Die Startergebnisse können nicht gelesen werden.",
        LaunchOther { n } => {
            return format!("{} im Startordner, nicht von Rerun (nicht gelesen)", count(n, "anderer Eintrag", "andere Einträge")).into();
        }
        LaunchProfileOf => "Profil",
        AgoNow => "gerade eben",
        AgoMinutes { n } => {
            return (if n == 1 { "vor 1 Minute".to_owned() } else { format!("vor {n} Minuten") }).into();
        }
        AgoHours { n } => {
            return (if n == 1 { "vor 1 Stunde".to_owned() } else { format!("vor {n} Stunden") }).into();
        }
        AgoDays { n } => {
            return (if n == 1 { "vor 1 Tag".to_owned() } else { format!("vor {n} Tagen") }).into();
        }
        LaunchExact => "Genaue Zeit",
        LaunchBadgeApplied => "Regel angewendet",
        LaunchBadgeReset => "Nach dem Start geändert",
        LaunchBadgeEnded => "Früh beendet",
        LaunchBadgeFailed => "Prüfung fehlgeschlagen",
        LaunchBadgeSkipped => "Regel nicht angewendet",
        LaunchBadgeUnreadable => "Nicht lesbar",
        LaunchUnreadable => "Rerun kann dieses Ergebnis nicht lesen.",
        LaunchSet { cpu, priority } => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(c) = cpu {
                let kind = match c.mode {
                    Mode::Hard => "harte Grenze",
                    Mode::Soft => "weiche Grenze, CPU Sets",
                };
                parts.push(format!("{} von {} Threads ({kind})", c.threads, c.of));
            }
            if let Some(p) = priority {
                let word = match p {
                    Priority::Normal => "normal",
                    Priority::AboveNormal => "über normal",
                    Priority::High => "hoch",
                };
                parts.push(format!("Priorität {word}"));
            }
            if parts.is_empty() {
                return "Gesetzt: keine CPU-Regel, keine Priorität".into();
            }
            return format!("Gesetzt: {}", parts.join(", ")).into();
        }
        LaunchCheckOk { soft, watch } => {
            return match (soft, watch) {
                (true, true) => "Etwa 5 Sekunden nach dem Start geprüft: wie gesetzt. CPU Sets nur für den Spielprozess; ob schon laufende Threads ihnen folgen, ist nicht belegt.",
                (true, false) => "Etwa 5 Sekunden nach dem Start geprüft: wie gesetzt. CPU Sets nur für den gestarteten Prozess.",
                (false, _) => "Etwa 5 Sekunden nach dem Start geprüft: wie gesetzt.",
            }
            .into();
        }
        LaunchCheckNarrowed => "Das Spiel hat sich selbst auf weniger Threads innerhalb der Regel beschränkt. Das ist kein Fehler; die Regel gilt.",
        LaunchCheckReset { cpu, priority } => {
            return match (cpu, priority) {
                (true, true) => "Die Affinität und die Priorität haben sich nach dem Start geändert.",
                (true, false) => "Die Affinität hat sich nach dem Start geändert.",
                _ => "Die Priorität hat sich nach dem Start geändert.",
            }
            .into();
        }
        LaunchCheckExitedEarly { watch } => {
            return if watch {
                "Der Spielprozess ist innerhalb von 5 Sekunden vor der Prüfung zu Ende gegangen, und es folgte keiner rechtzeitig. Er ist abgestürzt, oder er übergibt an einen Prozess mit anderem Pfad."
            } else {
                "Der gestartete Prozess ist innerhalb von 5 Sekunden vor der Prüfung zu Ende gegangen. Er ist abgestürzt, oder er ist ein Starter, der das Spiel als anderen Prozess startet."
            }
            .into();
        }
        LaunchCheckFailed { code } => {
            return format!("Die Prüfung ist fehlgeschlagen (Windows-Fehler {code}).").into();
        }
        LaunchSkipWhy { reason } => {
            return match reason {
                SkipReason::ProfileMissing => "Das Startprofil fehlte.".to_owned(),
                SkipReason::ProfileUnreadable { code } => format!("Das Profil konnte nicht gelesen werden (Windows-Fehler {code})."),
                SkipReason::ProfileReparsePoint => "Das Profil ist ein Link; Rerun folgt ihm nicht.".to_owned(),
                SkipReason::ProfileNotAFile => "Das Profil ist keine Datei.".to_owned(),
                SkipReason::ProfileInvalid => "Das Profil ist zu gross oder lässt sich nicht lesen.".to_owned(),
                SkipReason::MethodUnsupported => "Das Ergebnis stammt von einem älteren Starter, der die Methode watch nicht kannte.".to_owned(),
                SkipReason::PathMismatch => "Steam hat ein anderes Programm gestartet, als das Profil nennt.".to_owned(),
                SkipReason::TopologyUnavailable => "Die Prozessorstruktur konnte nicht gelesen werden.".to_owned(),
                SkipReason::TopologyInvalid => "Windows hat eine Prozessorstruktur gemeldet, die Rerun nicht annimmt.".to_owned(),
                SkipReason::SelectionEmpty => "Die Regel wählt auf diesem PC keinen Prozessor aus.".to_owned(),
                SkipReason::MaskTooWide => "Die Auswahl passt nicht in die Affinitätsmaske dieses Builds.".to_owned(),
                SkipReason::SpawnFailed { code } => format!("Der Job oder der angehaltene Prozess konnte nicht erstellt werden (Windows-Fehler {code})."),
                SkipReason::JobFailed { code } => format!("Die Prozessorgrenze des Jobs konnte nicht gesetzt werden (Windows-Fehler {code})."),
                SkipReason::ReadBackFailed { code } => format!("Die Grenze konnte nicht zurückgelesen werden (Windows-Fehler {code})."),
                SkipReason::Mismatch => "Die zurückgelesene Grenze wich von der Auswahl ab.".to_owned(),
                SkipReason::CpuSetsFailed { code } => format!("Die CPU Sets konnten nicht gesetzt werden (Windows-Fehler {code})."),
                SkipReason::ResumeFailed { code } => format!("Der angehaltene Prozess konnte nicht fortgesetzt werden (Windows-Fehler {code})."),
                SkipReason::ElevationRequired => "Das Spiel braucht Administratorrechte und wurde über die Windows-Abfrage ohne Regel gestartet.".to_owned(),
                SkipReason::RunFailed { code } => format!("Das Programm, das das Profil statt Steams Programm nennt, konnte nicht gestartet werden (Windows-Fehler {code}); Steams eigenes Programm wurde ohne Regel gestartet."),
                SkipReason::TargetNotFound => "Innerhalb von 120 Sekunden ist kein neuer Spielprozess erschienen. Vielleicht wartet ein Starter auf eine Anmeldung oder ein Update; starte das Spiel nochmals.".to_owned(),
                SkipReason::JobIneffective => "Der Spielprozess ist dem Job beigetreten, behielt aber eine andere Grenze aus einem Job, in dem er schon war.".to_owned(),
                SkipReason::TargetElevated => "Der Spielprozess läuft als Administrator; Rerun lässt ihn in Ruhe.".to_owned(),
                SkipReason::TargetDenied { code } => format!("Ein Prozess mit dem Namen des Spiels konnte nicht geöffnet werden (Windows-Fehler {code}): geschützt, anderes Konto oder als Administrator gestartet. Es wurde nichts gesetzt."),
                SkipReason::SearchFailed { code } => format!("Es konnte kein Spielprozess gesucht werden (Windows-Fehler {code}). Es wurde nichts gesetzt."),
                SkipReason::PriorityFailed { code } => format!("Die Prioritätsklasse des Spielprozesses konnte nicht gelesen oder gesetzt werden (Windows-Fehler {code}). Es wurde nichts gesetzt."),
            }
            .into();
        }
        LaunchStart { start, watch } => {
            return match start {
                Start::Created if watch => "Der Befehl von Steam wurde unverändert gestartet.".to_owned(),
                Start::Created => "Das Spiel wurde unverändert gestartet.".to_owned(),
                Start::Shell | Start::ShellNoProcess => "Das Spiel wurde unverändert über die Windows-Abfrage für Administratorrechte gestartet.".to_owned(),
                Start::NotExe => "Es wurde nichts gestartet (keine .exe).".to_owned(),
                Start::Failed { code } => format!("Es wurde nichts gestartet (Windows-Fehler {code})."),
            }
            .into();
        }
        LaunchEnded { ended } => {
            return match ended {
                Ended::Ended => "Der angehaltene Prozess mit der Regel wurde zuerst beendet.".to_owned(),
                Ended::Failed { code } => format!("Der angehaltene Prozess mit der Regel konnte nicht beendet werden (Windows-Fehler {code})."),
                Ended::NotConfirmed { code } => format!("Es wurde nicht gesehen, dass der angehaltene Prozess mit der Regel endete (Windows-Fehler {code})."),
            }
            .into();
        }
        LaunchOptionStillSet => "Die Steam-Startoption für den Rerun-Starter war bei diesem Start noch gesetzt, aber es gab kein Profil. Das Spiel startet damit unverändert; entferne die Option in Steam.",
        LaunchOptionStillSetHeld { txn } => {
            return format!("Die Steam-Startoption für den Rerun-Starter war bei diesem Start noch gesetzt, aber es gab kein Profil, darum startete das Spiel unverändert. Die Änderung {txn} hält dieses Profil jetzt; sieh sie unter Angewendet an.").into();
        }
        LaunchOptionStillSetForgotten => "Die Steam-Startoption war bei diesem Start noch gesetzt. Eine ohne Rückgängig abgeschlossene Änderung hat ein Profil hinterlassen, das damals fehlte. Entferne die Startoption von Hand.",
        LaunchCheckedLauncher => "Steam startet hier einen Starter. Die Prüfung galt dem Starter, nicht dem Spiel.",
        LaunchWatched => "Methode watch: Die Regel gilt für den Spielprozess, der nach dem Start gefunden wird, nicht für das Programm, das Steam startet.",
        LaunchPriorityNotRestored { code } => {
            return format!("Die Prioritätsklasse des Spielprozesses konnte nicht zurückgesetzt werden (Windows-Fehler {code}). Die Klasse bleibt, bis das Spiel endet.").into();
        }
        HistHeadUnreadable => "Sein Plan kann nicht gelesen werden, darum lässt sich nicht auflisten, was es geändert hat.",
        StateUndoInterrupted => "Rückgängig unterbrochen",
        ProblemUndoInterrupted => "Ein Rückgängigmachen dieser Änderung hat begonnen und ist nicht zu Ende gekommen. Mache sie nochmals rückgängig, um es abzuschliessen, oder schliesse sie ohne Rückgängig ab.",
        AttentionTitle { count } => {
            return (if count == 1 { "1 Änderung braucht dich".to_owned() } else { format!("{count} Änderungen brauchen dich") }).into();
        }
        AttentionBody => "Rerun ändert von sich aus nichts. Sieh sie dir unter Angewendet an und entscheide dann, ob du sie rückgängig machst oder abschliesst.",
        AttentionView => "Ansehen",
        ReportDrifted => "Nur der Teil von Rerun wurde zurückgesetzt; was sich seither geändert hat, bleibt.",
        ReportForeign => "Jemand anderes hat es geändert, darum hat Rerun es so gelassen, wie es war. Das Abschliessen ohne Rückgängig beendet die Änderung.",
        ReportForeignInline => "Sein alter Wert liegt im Journal-Eintrag.",
        ReportKept => "Eine spätere Änderung verlässt sich darauf, darum hat Rerun es dieser überlassen.",
        ReportOldInUse => "Eine Kopie von Rerun ist noch in Benutzung und bleibt, bis das Programm, das sie nutzt, endet. Mache es dann nochmals rückgängig:",
        ReportOldKept => "Eine Kopie von Rerun bleibt neben einer Datei, die sich seither geändert hat, weil sie die letzte Kopie eines Zustands sein kann. Lösche sie von Hand, oder schliesse die Änderung ohne Rückgängig ab:",
        ReportOldForeign => "Das ist keine Kopie von Rerun; Rerun hat sie nicht angefasst:",
        ReportProfilesMoved => "Die Startprofile wurden in einem anderen Ordner zurückgesetzt, als der Plan nennt:",
        ResRebindUnconfirmedTitle => "Rerun kann nicht sagen, ob der neue Ordner festgehalten wurde",
        ResRebindUnconfirmedBody => "Die Änderung ist vielleicht jetzt dem neuen Ordner zugeordnet, aber das Journal lässt sich nicht nochmals lesen, um es zu bestätigen. Sieh unter Angewendet nach, wo es steht.",
        OrphansTitle => "Firewall-Regeln von Rerun ohne Änderung",
        OrphansHint => "Keine Änderung dieses Windows-Kontos besitzt diese Regeln. Möglicherweise gehören sie zu einem anderen Konto. Rerun entfernt sie nicht; entferne sie in der Windows Defender Firewall mit erweiterter Sicherheit.",
        OrphansProgram => "Programm",
        OrphansUnreadable => "Die Firewall lässt sich gerade nicht lesen, darum kann Rerun ihre Regeln nicht auflisten.",
        OrphansNoJournal => "Das Journal lässt sich gerade nicht lesen, darum lassen sich die Regeln nicht den Änderungen zuordnen.",
        AttentionUnreadableTitle => "Das Journal kann nicht gelesen werden",
        AttentionUnreadableBody => "Rerun kann nicht sagen, was es geändert hat, und ändert von sich aus nichts. Den Grund siehst du unter Angewendet.",
        UndoFolderChanged => "Der Spielordner hat sich geändert",
        UndoFolderChangedBody => "Steam hat das Spiel vielleicht verschoben oder neu installiert. Rerun kann den Ordner prüfen, den Steam jetzt nennt; vor deiner Bestätigung ändert sich nichts. Einen Ordner, den du selbst gewählt hast, ordnet Rerun nie neu zu: schliesse die Änderung dann ohne Rückgängig ab.",
        RebindCheckBtn => "Neuen Ordner prüfen",
        RebindTitle => "Diese Änderung dem neuen Ordner zuordnen?",
        RebindIntro => "Es wurde noch nichts geändert. Rerun würde diese Änderung dem Ordner zuordnen, den Steam jetzt nennt, und sie dort rückgängig machen, neueste Änderung zuerst:",
        RebindLblOld => "Gespeicherter Ordner",
        RebindLblLibrary => "Bibliothek",
        RebindLblWhy => "Warum er sich nicht öffnen lässt",
        RebindLblNew => "Ordner, den Steam jetzt nennt",
        RebindLblNewLibrary => "Seine Bibliothek",
        RebindCreatedFound => "Ordner, den die Änderung angelegt hat, dort gefunden; er wird nur entfernt, wenn er leer ist",
        RebindCreatedMissing => "Ordner, den die Änderung angelegt hat, dort nicht vorhanden",
        RebindRegistryNote => "Registry-Änderungen werden dort rückgängig gemacht, wo Rerun sie gemacht hat, auch ein Kompatibilitätsschicht-Wert unter dem alten Programmpfad; ein Wert unter dem neuen Programmpfad bleibt unberührt.",
        RebindScopeNote => "Nur der jetzt zugeordnete Ordner wird rückgängig gemacht; eine Kopie des Spiels anderswo (ein umbenannter alter Ordner, eine aus Steam entfernte Bibliothek, deren Laufwerk fehlte) behält die Dateien von Rerun.",
        RebindPermanentNote => "Die neue Zuordnung ist dauerhaft: Jedes spätere Rückgängigmachen dieser Änderung nutzt den neuen Ordner.",
        RebindBtn => "Neu zuordnen und rückgängig machen",
        RebindFirewallBlocked { txn } => {
            return format!("Diese Änderung enthält eine Firewall-Regel, die die Administrator-Abfrage von Windows braucht. Das Neu-Zuordnen aus der App ist noch nicht möglich; nutze die Befehlszeile: rerun revert {txn} --rebind.").into();
        }
        RefRebindTitle => "Rerun kann diese Änderung keinem neuen Ordner zuordnen",
        RefRebindNotNeeded => "Jeder Ordner dieser Änderung lässt sich wie gespeichert öffnen. Mache sie ohne Neu-Zuordnung rückgängig.",
        RefRebindManual => "Diesen Spielordner hast du selbst gewählt, darum ordnet Rerun ihn nie neu zu. Nur das Abschliessen ohne Rückgängig beendet die Änderung.",
        RefRebindNotApplied => "Nur eine angewendete Änderung lässt sich neu zuordnen. Mache sie rückgängig oder schliesse sie ohne Rückgängig ab.",
        RefRebindUndecided => "Rerun kann den Ordner gerade nicht prüfen. Versuche es später nochmals.",
        RefRebindMoreThanOne => "Mehr als ein Ordner dieser Änderung lässt sich nicht öffnen, und eine Neu-Zuordnung ordnet nur einen zu.",
        RefRebindNoCandidate => "Keine Steam-Bibliothek enthält das Spiel jetzt.",
        RefRebindAmbiguous => "Das Spiel liegt in mehr als einer Steam-Bibliothek. Rerun wählt nicht zwischen ihnen.",
        RefRebindLibraryUnreadable => "Eine Steam-Bibliothek oder das Manifest des Spiels lässt sich gerade nicht lesen. Eine Neu-Zuordnung braucht jede Bibliothek lesbar. Versuche es später nochmals.",
        RefRebindUpdatePending => "Steam aktualisiert das Spiel. Versuche es nochmals, wenn es fertig ist.",
        RefRebindOtherInstallDir => "Das Spiel ist in dieser Bibliothek in einem anderen Ordner installiert. Das ordnet Rerun nicht zu.",
        RefRebindCandidate => "Der Ordner in dieser Bibliothek lässt sich nicht öffnen.",
        RefRebindSharedFolder => "Der Ordner in dieser Bibliothek ist schon ein anderer Ordner dieser Änderung.",
        RefRebindHalts => "Das Rückgängigmachen würde auch an einem anderen Ordner dieser Änderung anhalten. Mache ihn zuerst verfügbar.",
        RefRebindNotWritable => "Rerun kann nicht in den Ordner in dieser Bibliothek schreiben.",
        RefRebindForeign => "Eine Änderung dort ist nicht so, wie Rerun sie hinterlassen hat. Nur das Abschliessen ohne Rückgängig beendet die Änderung.",
        RefRebindRevertPending => "Ein Rückgängigmachen einer Änderung in diesem Ordner hat begonnen. Nur das Abschliessen ohne Rückgängig beendet die Änderung.",
        RefRebindNoRoom => "Das Journal dieser Änderung hat keinen Platz für eine Neu-Zuordnung. Nur das Abschliessen ohne Rückgängig beendet sie.",
        RebindHeadUnavailable => "Der Plan dieser Änderung kann nicht gelesen werden, darum kann Rerun nicht sagen, ob sie noch eine Firewall-Regel hat, die die Administrator-Abfrage braucht. Das Neu-Zuordnen aus der App ist nicht möglich.",
        RebindSamePath => "Der Ordner liegt am gleichen Pfad wie gespeichert, ist aber jetzt ein anderer Ordner (das Spiel wurde neu installiert).",
        RebindBoundNow => "Diese Änderung ist dem neuen Ordner jetzt zugeordnet. Mache sie nochmals rückgängig, um es abzuschliessen, oder schliesse sie ohne Rückgängig ab.",
        HistShowGroup => "Anzeigen",
        HistHideGroup => "Ausblenden",
        HistShowOlder { n } => {
            return format!("Ältere zeigen ({n} nicht angezeigt)").into();
        }
        HistKeepNote { n } => {
            return format!("Rerun behält die letzten {n} rückgängig gemachten oder zurückgerollten Einträge; ältere werden entfernt, wenn du etwas anwendest oder rückgängig machst.").into();
        }
        HistStateEmpty => "Nichts geändert",
        ClearBtn => "Verlauf leeren\u{2026}",
        ClearTitle => "Verlauf leeren",
        ClearIntro => "Diese Einträge und Startergebnisse werden aus dem Verlauf entfernt.",
        ClearNothing => "Rerun kann jetzt nichts aus dem Verlauf entfernen.",
        ClearEntriesHeading { n } => {
            return format!("Einträge, die entfernt werden ({n})").into();
        }
        ClearResultsHeading { n } => {
            return format!("Startergebnisse, die entfernt werden ({n})").into();
        }
        ClearStaysHeading { n } => {
            return format!("Bleibt ({n})").into();
        }
        ClearNumber { n } => {
            return format!("Nr. {n}").into();
        }
        ClearKeepNotSettled => "Nicht abgeschlossen: Mache sie zuerst rückgängig oder schliesse sie ab.",
        ClearKeepUnreadable => "Sein Ordner kann nicht gelesen werden.",
        ClearKeepHoldsProfile => "Hält noch ein Startprofil.",
        ClearKeepHandedOver => "Hat Dateien an eine spätere Änderung übergeben, die noch nicht abgeschlossen ist.",
        ClearKeepForeign => "Sein Ordner enthält etwas, das Rerun nicht dorthin geschrieben hat.",
        ClearKeepTooMany => "Sein Ordner hat zu viele Dateien.",
        ClearKeepForgotten => "Seine Sicherungen bleiben.",
        ClearKeepInUse => "Eine Sicherung ist gerade in Gebrauch; die nächste Aufräumung entfernt den Eintrag.",
        ClearKeepOther => "Rerun behält es vorerst.",
        ClearResultOptionSet => "Die Steam-Startoption zeigt noch auf Rerun: Entferne sie zuerst von Hand.",
        ClearResultUnreadable => "Es kann nicht gelesen werden.",
        ClearUnchanged => "Spielordner, Registry und Firewall bleiben unverändert.",
        ClearChanged => "Der Verlauf hat sich geändert; sieh ihn dir nochmals an.",
        ClearDoneTitle => "Verlauf geleert",
        ClearDoneBody { entries, results } => {
            return format!(
                "{} und {} entfernt.",
                count(entries, "Eintrag", "Einträge"),
                count(results, "Startergebnis", "Startergebnisse")
            )
            .into();
        }
        ClearEmptySummary { n } => {
            return if n == 1 {
                "1 leerer Eintrag (nichts geändert)".into()
            } else {
                format!("{n} leere Einträge (nichts geändert)").into()
            };
        }
        PkHeading => "Pakete",
        PkIntro => "Rerun behält die Pakete, die es für Fixes geladen hat. Rückgängigmachen braucht sie nie. Ein entferntes Paket wird wieder geladen, wenn ein Fix es braucht und der Index es noch führt.",
        PkEmpty => "Rerun hat keine Pakete gespeichert.",
        PkNotInIndex => "Nicht im Index: kann nicht erneut geladen werden.",
        PkFacts { bytes: b, files, archives } => {
            return format!(
                "{} \u{b7} {} \u{b7} {}",
                bytes(b, true),
                count(files as usize, "Datei", "Dateien"),
                count(archives, "Archiv", "Archive")
            )
            .into();
        }
        PkStateUnpacked => "Entpackt",
        PkStateIncomplete => "Unvollständig",
        PkStateArchiveOnly => "Nur Download",
        PkUsedBy => "Gebraucht von",
        PkNotUsed => "Nicht gebraucht",
        PkRemoveBtn => "Entfernen\u{2026}",
        PkRemoveAllBtn => "Alle ungenutzten entfernen\u{2026}",
        PkKeepInUse => "Eine Änderung, die nicht rückgängig gemacht oder abgeschlossen ist, braucht es: Mache sie zuerst rückgängig.",
        PkKeepUnknownUse { n } => {
            return if n == 1 {
                "1 Änderung kann nicht gelesen werden, darum könnte jedes Paket gebraucht sein. Sieh im Verlauf nach.".into()
            } else {
                format!("{n} Änderungen können nicht gelesen werden, darum könnte jedes Paket gebraucht sein. Sieh im Verlauf nach.").into()
            };
        }
        PkKeepReparse => "Sein Ordner enthält einen Link (eine Junction oder einen symbolischen Link).",
        PkKeepLinked => "Sein Ordner enthält eine Datei mit mehr als einem Hardlink.",
        PkKeepAttributes => "Sein Ordner enthält einen schreibgeschützten, versteckten oder System-Eintrag oder einen, den Rerun nicht öffnen kann.",
        PkKeepTooMany => "Sein Ordner enthält zu viele Einträge.",
        PkKeepBadName => "Sein Ordner enthält einen Namen, der nicht von Rerun ist.",
        PkKeepBusy => "Eine Datei ist gerade in Gebrauch (ein Virenscanner etwa): Versuche es später nochmals.",
        PkKeepChanged => "Es hat sich beim Entfernen geändert: Sieh dir die Liste nochmals an.",
        PkKeepUnsupported => "Das Laufwerk erlaubt das Entfernen nicht (FAT oder exFAT).",
        PkKeepOther => "Rerun entfernt es nicht.",
        PkKeepShared => "Nur sein Download ist noch da, und ein Paket, das bleibt, braucht ihn auch.",
        PkLoose { n, bytes: b } => {
            return if n == 1 {
                format!("1 Download ohne Paket ({})", bytes(b, true)).into()
            } else {
                format!("{n} Downloads ohne Paket ({})", bytes(b, true)).into()
            };
        }
        PkLeftovers { n, bytes: b } => {
            return if n == 1 {
                format!("1 Rest eines abgebrochenen Downloads ({})", bytes(b, true)).into()
            } else {
                format!("{n} Reste abgebrochener Downloads ({})", bytes(b, true)).into()
            };
        }
        PkForeignHeading { n } => {
            return format!("Nicht von Rerun, wird nie angefasst ({n})").into();
        }
        PkUnreadableTitle => "Die Pakete können nicht angezeigt werden",
        PkUnreadableBody => "Rerun konnte seinen Paketordner oder den Verlauf, der sagt, welche Pakete gebraucht werden, nicht lesen. Es wurde nichts geändert.",
        PkDlgTitle => "Pakete entfernen",
        PkDlgIntro => "Diese Pakete werden aus dem Paketlager von Rerun entfernt.",
        PkDlgNothing => "Rerun kann jetzt nichts aus dem Paketlager entfernen.",
        PkDlgGoesHeading { n } => {
            return format!("Pakete, die entfernt werden ({n})").into();
        }
        PkDlgLooseHeading { n } => {
            return format!("Downloads ohne Paket, die entfernt werden ({n})").into();
        }
        PkDlgLeftovers { n, bytes: b } => {
            return format!("Reste, die entfernt werden: {n} ({})", bytes(b, true)).into();
        }
        PkDlgFilesShow { n } => {
            return format!("Dateien anzeigen ({n})").into();
        }
        PkDlgFilesHide => "Dateien ausblenden",
        PkDlgFreed { bytes: b } => {
            return format!("Das gibt {} frei.", bytes(b, true)).into();
        }
        PkDlgUnchanged => "Spielordner, Registry und Firewall bleiben unverändert. Rückgängigmachen braucht nie ein Paket.",
        PkDlgChanged => "Die Pakete haben sich geändert; sieh sie dir nochmals an.",
        PkDoneTitle => "Pakete entfernt",
        PkDoneBody { packages, archives, leftovers, bytes: b } => {
            let what = removed_parts(
                [packages, archives, leftovers],
                [("Paket", "Pakete"), ("Archiv", "Archive"), ("Rest", "Reste")],
                "und",
            );
            return format!("{what} entfernt, {} frei.", bytes(b, true)).into();
        }
        PkDoneNothing => "Es wurde nichts entfernt.",
        PkGoneTitle => "Das Paket ist nicht mehr im Lager",
        PkGoneBody => "Die Liste wird neu gelesen. Es wurde nichts geändert.",
        RefPkInUseTitle => "Eine Änderung braucht das Paket noch",
        RefPkInUseBody => "Mache diese Änderung zuerst rückgängig oder schliesse sie ab. Es wurde nichts entfernt.",
        RefPkChangedTitle => "Die Pakete haben sich geändert",
        RefPkChangedBody => "Sieh dir die Liste nochmals an. Es wurde nichts entfernt.",
        RefPkBusyTitle => "Rerun lädt oder entpackt gerade ein Paket",
        RefPkBusyBody => "Versuche es nochmals, wenn es fertig ist. Es wurde nichts entfernt.",
        ReportBtn => "Problem melden\u{2026}",
        ReportTitle => "Problem melden",
        ReportIntro => "Rerun öffnet auf GitHub in deinem Browser ein neues Issue, ausgefüllt mit genau diesem Text. GitHub erhält ihn, sobald die Seite offen ist. Du kannst ihn dort noch ändern; abgeschickt wird erst, wenn du es tust.",
        ReportWhere => "Ziel: github.com/mythenstudios/rerun. Zum Abschicken brauchst du ein GitHub-Konto. Der Text enthält nur Fakten, die Rerun selbst bestimmt: keinen Spielnamen, keinen Pfad, kein Konto.",
        ReportLabelTitle => "Titel",
        ReportLabelText => "Text",
        OpenInBrowser => "Im Browser öffnen",
        SourceOpen => "Öffnen",
        OpenFailedTitle => "Es wurde nichts geöffnet",
        OpenRefusedForm => "Rerun öffnet nur einfache https-Links, und dieser ist keiner.",
        OpenNotInIndex => "Der aktuelle Index hat diesen Link nicht mehr.",
        OpenNoFolder => "Der Ordner von Rerun existiert noch nicht.",
        OpenShellFailed => "Windows konnte es nicht öffnen. Die Details sagen, warum.",
        OpenStale => "Der Dialog war veraltet. Öffne ihn nochmals.",
        SettingsData => "Daten",
        DataIntro => "Rerun hält den Index, seine Änderungen mit ihren Sicherungen und die Downloads in diesem Ordner. Er ist fest; Rerun zeigt ihn hier nur an.",
        DataOpenBtn => "Im Explorer öffnen",
        DataNotCreated => "Noch nicht angelegt. Rerun legt ihn an, wenn es zum ersten Mal etwas speichert.",
        DataUnknown => "Rerun kann nicht feststellen, wo sein Ordner liegt.",
        ThemeNacht => "Nacht",
        SetThemeDesc => "Beide sind dunkel. Mythen ist schwarz-weiss, Nacht nutzt die Grautöne von Windows 11.",
        ThemeHighContrast => "Der hohe Kontrast von Windows ist an, darum nutzt Rerun dessen Farben. Das Thema gilt wieder, sobald er aus ist.",
        LangEnglish => "English",
        LangGerman => "Deutsch",
        SetLanguageDesc => "Gilt sofort. Rerun liest die Spiele noch einmal ein, damit auch die Bibliothek die neue Sprache spricht.",
        ViewCompact => "Kompakt",
        SetLibraryView => "Bibliotheksansicht",
        SetLibraryViewDesc => "Die Liste zeigt je Spiel die Grafik-Schnittstelle und die Programmdatei. Kompakt zeigt eine kurze Zeile je Spiel.",
        AboutCopyright => "Copyright \u{00A9} 2026 Mythen Studios",
        AboutBuild => "Build",
        AboutIndex => "Topo-Index",
        AboutLicenceTitle => "Lizenz",
        AboutGpl => "Rerun ist freie Software: Du darfst sie unter der GNU General Public License, Version 3 oder (nach deiner Wahl) jeder späteren Version, weitergeben und verändern. Diese App bindet Slint unter GPL-3.0-only ein und steht deshalb nur unter Version 3. Rerun kommt ohne jede Gewährleistung, soweit das Gesetz es zulässt. Der volle Lizenztext ist der erste Eintrag der Lizenzen von Drittanbietern.",
        AboutSource => "Quellcode dieser Version",
        AboutRepository => "Repository",
        AboutLicences => "Lizenzen von Drittanbietern",
        AboutLicencesDesc => "Rerun baut auf Open-Source-Crates und auf den Schriften Archivo und IBM Plex (SIL Open Font License 1.1) auf. Hier stehen deren Lizenztexte und Urheberrechtshinweise, erzeugt aus den Crates, aus denen diese Version gebaut ist.",
        AboutLicencesShow => "Lizenzen anzeigen",
        LicencesClose => "Schliessen",
        TidyLine { n } => {
            return if n == 1 {
                "1 älterer Verlaufseintrag entfernt".into()
            } else {
                format!("{n} ältere Verlaufseinträge entfernt").into()
            };
        }
    };
    Cow::Borrowed(s)
}

#[cfg(test)]
mod tests;
