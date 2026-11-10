//! The preview renderer: golden strings on directly built previews (every op kind, the notes),
//! and hostile fields (ESC, U+202E, U+2028, tag characters) escaped, the net never firing.

use rerun_core::escape;
use rerun_core::plan::{
    INI_NOTE, IniOldShown, IniShown, LAYERS_NOTE, NOT_RESTORED, Preview, PreviewOp, PreviewRoot,
    REGISTRY_NOTE, RegShown, RootKind,
};

use super::render;
use crate::messages::Message;
use crate::out::Out;

fn shown(ms: &[Message<'_>]) -> String {
    let mut out = Out::new(Vec::new());
    out.lines(ms).unwrap();
    String::from_utf8(out.into_inner()).unwrap()
}

fn op(index: usize, action: &'static str, root: Option<usize>, path: &str) -> PreviewOp {
    PreviewOp {
        index,
        action,
        root,
        path: escape::path(path).into_owned(),
        name: None,
        old_value: None,
        new_value: None,
        tokens: None,
        machine: Vec::new(),
        type_change: false,
        source: None,
        content: None,
        attrs: None,
        old: None,
        config: false,
        ini: Vec::new(),
        profile: None,
        replaces: false,
        firewall: None,
        held: false,
    }
}

fn reg(kind: &str, text: Option<&str>) -> RegShown {
    RegShown {
        kind: kind.to_owned(),
        text: text.map(|t| escape::text(t).into_owned()),
    }
}

fn preview(root_path: &str, ops: Vec<PreviewOp>) -> Preview {
    Preview {
        roots: vec![PreviewRoot {
            index: 0,
            kind: RootKind::Game,
            path: escape::path(root_path).into_owned(),
            steam: Some((220, escape::path(r"D:\SteamLibrary").into_owned())),
            main_exe: Some(escape::path(r"bin\game.exe").into_owned()),
        }],
        ops,
        not_restored: NOT_RESTORED,
        registry: Some(REGISTRY_NOTE),
        layers: Some(LAYERS_NOTE),
        ini: Some(INI_NOTE),
        profiles: None,
        firewall: None,
        held: None,
    }
}

#[test]
fn every_op_kind_and_the_notes() {
    let sha = "ab".repeat(32);
    let mut replace = op(0, "replace file", Some(0), "d3d9.dll");
    replace.source = Some(escape::path("fix-pack 1.0.2: d3d9.dll").into_owned());
    replace.content = Some((sha.clone(), 23));
    replace.attrs = Some("-".to_owned());
    replace.old = Some((sha.clone(), 20, "RH".to_owned()));
    replace.config = true;
    let mut ini = op(1, "edit ini", Some(0), r"cfg\game.ini");
    ini.content = Some((sha.clone(), 35));
    ini.attrs = Some("-".to_owned());
    ini.old = Some((sha.clone(), 35, "-".to_owned()));
    ini.ini = vec![
        IniShown {
            section: escape::text("Display").into_owned(),
            key: escape::text("Width").into_owned(),
            old: IniOldShown::Value(escape::text("1280").into_owned()),
            new: escape::text("1920").into_owned(),
        },
        IniShown {
            section: escape::text("New").into_owned(),
            key: escape::text("K").into_owned(),
            old: IniOldShown::NewSection,
            new: escape::text("1").into_owned(),
        },
    ];
    let key = op(2, "create key", None, r"HKCU\Software\Vendor");
    let mut value = op(3, "set value", None, r"HKCU\Software\Vendor\Game");
    value.name = Some(escape::path("Lang").into_owned());
    value.old_value = Some(reg("REG_SZ", Some("de")));
    value.new_value = Some(reg("REG_DWORD 1 (0x00000001)", None));
    value.type_change = true;
    let mut tokens = op(4, "add tokens", None, r"HKCU\Software\Layers");
    tokens.name = Some(escape::path(r"D:\Games\G\game.exe").into_owned());
    tokens.tokens = Some("ZZ_A ZZ_B".to_owned());
    tokens.machine = vec![("64-bit view", reg("REG_SZ", Some("~ RUNASADMIN")))];
    tokens.old_value = Some(reg("missing", None));
    tokens.new_value = Some(reg("REG_SZ", Some("~ ZZ_A ZZ_B")));
    let p = preview(r"D:\Games\G", vec![replace, ini, key, value, tokens]);
    let want = format!(
        r"root 0: D:\Games\G
  Steam app 220, library: D:\SteamLibrary
  main executable: bin\game.exe
op 0: replace file in root 0: d3d9.dll
  from package: fix-pack 1.0.2: d3d9.dll
  new: sha256 {sha}, 23 bytes, attributes -
  old: sha256 {sha}, 20 bytes, attributes RH
  configuration file: once edited, a revert leaves it as it is
op 1: edit ini in root 0: cfg\game.ini
  new: sha256 {sha}, 35 bytes, attributes -
  old: sha256 {sha}, 35 bytes, attributes -
  key [Display] Width
    old: 1280
    new: 1920
  key [New] K
    old: missing (new section)
    new: 1
op 2: create key: HKCU\Software\Vendor
op 3: set value: HKCU\Software\Vendor\Game
  value: Lang
  old value: REG_SZ: de
  new value: REG_DWORD 1 (0x00000001)
  the type of the value changes
op 4: add tokens: HKCU\Software\Layers
  value: D:\Games\G\game.exe
  adds tokens: ZZ_A ZZ_B
  all users (HKLM, 64-bit view), not changed: REG_SZ: ~ RUNASADMIN
  old value: missing
  new value: REG_SZ: ~ ZZ_A ZZ_B
note: {NOT_RESTORED}
note: {REGISTRY_NOTE}
note: {LAYERS_NOTE}
note: {INI_NOTE}
"
    );
    assert_eq!(shown(&render(&p)), want);
}

#[test]
fn hostile_fields_are_escaped_and_stand_last() {
    let evil = "x\u{1b}[2J\u{202E}y\u{2028}z\u{E0041}";
    let mut o = op(0, "set value", None, &format!(r"HKCU\Software\{evil}"));
    o.name = Some(escape::path(evil).into_owned());
    o.old_value = Some(reg("REG_SZ", Some(evil)));
    o.new_value = Some(reg("REG_SZ", Some("ok")));
    let mut f = op(1, "create file", Some(0), evil);
    f.source = Some(escape::path(evil).into_owned());
    let p = preview(&format!(r"D:\{evil}"), vec![o, f]);
    let text = shown(&render(&p));
    for bad in ['\u{1b}', '\u{202E}', '\u{2028}', '\u{E0041}'] {
        assert!(!text.contains(bad), "{text}");
    }
    // Root, key, value name, old value, file path, source: each quoted, last on its line.
    let hit: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(r"x\u{1b}[2J\u{202e}y"))
        .collect();
    assert_eq!(hit.len(), 6, "{text}");
    for line in hit {
        assert!(
            line.ends_with(r#"y\u{2028}z\u{e0041}""#),
            "untrusted text last: {line}"
        );
    }
}

// ---------- P3-3d: launch profiles (review S3) ----------

use rerun_core::exec::launch_result::ProfileId;
use rerun_core::prim::launch_method::{RuleMode, SelectStep};
use rerun_core::prim::{MachineView, MachineWhy, SelectionShown};

use super::{LaunchView, OptionText, launch_lines};
use crate::messages::{ProfileMsg, ranges};

/// Every `ProfileMsg` has its line (a table, like `every_outcome_has_its_line`).
#[test]
fn every_profile_line_has_its_text() {
    let id = ProfileId::from_hex("323ad79fbc93ca3e73b0b152a5d44616").unwrap();
    let p = |s: &str| escape::path(s).into_owned();
    let cases: Vec<(ProfileMsg<'_>, &str)> = vec![
        (
            ProfileMsg::ProfilesRoot,
            "  Rerun's launch profiles: written by apply, read by rerun-launch at a game start",
        ),
        (
            ProfileMsg::InlineSource,
            "  content: the launch profile, carried by the plan (no package)",
        ),
        (
            ProfileMsg::Profile {
                id: "ab",
                method: "direct",
                bitness: "x64",
            },
            "     launch profile ab: method direct, x64",
        ),
        (
            ProfileMsg::Rule {
                words: "max_threads 8",
            },
            "     cpu max_threads 8",
        ),
        (ProfileMsg::Priority { class: "high" }, "     priority high"),
        (
            ProfileMsg::Start {
                path: p(r"D:\G\g.exe"),
            },
            r"     start D:\G\g.exe",
        ),
        (
            ProfileMsg::Unreadable { why: p("bad") },
            "     not a launch profile of this version: bad",
        ),
        (
            ProfileMsg::MachineHeading,
            "on this computer now (not part of the plan; rerun-launch selects again at every start):",
        ),
        (
            ProfileMsg::Selection {
                threads: 4,
                of: 22,
                group: 1,
                mask: 0x55,
                cores: "0-3".to_owned(),
                llc: None,
            },
            "  4 of 22 logical processors, group 1, mask 0x0000000000000055, cores 0-3",
        ),
        (
            ProfileMsg::Selection {
                threads: 2,
                of: 8,
                group: 0,
                mask: 0x3,
                cores: "0, 2".to_owned(),
                llc: Some((1, 2, 512 << 10)),
            },
            "  2 of 8 logical processors, group 0, mask 0x0000000000000003, cores 0, 2, L2 #1 (512 KiB)",
        ),
        (
            ProfileMsg::Mode {
                mode: RuleMode::Hard,
            },
            "  hard: job affinity, inherited by the programs the started program starts",
        ),
        (
            ProfileMsg::Mode {
                mode: RuleMode::Soft,
            },
            "  soft: default CPU Sets of the started program only, not of its children; Windows may override them",
        ),
        (
            ProfileMsg::MachineUnknown {
                why: p("no topology"),
            },
            "  unknown here, rerun-launch decides at every start; the topology: no topology",
        ),
        (
            ProfileMsg::MachineEmpty {
                after: SelectStep::Bitness,
            },
            "  the rule selects nothing here (emptied by the 32-bit limit (processors 0 to 31)); the game would start unchanged",
        ),
        (ProfileMsg::MachineNoRule, "  no CPU rule (priority only)"),
        (
            ProfileMsg::MultiGroup,
            "  hint: this computer has more than one processor group; a hard rule may start the game unchanged here (ADR 0022, multi-group case unmeasured)",
        ),
        (
            ProfileMsg::X86Capped,
            "  hint: a 32-bit game gets processors 0 to 31 of its group only",
        ),
        (
            ProfileMsg::LauncherGame {
                main: p("game.exe"),
            },
            "  the game: game.exe",
        ),
        (
            ProfileMsg::PriorityNote { class: "high" },
            "  priority high is set only when Steam starts the game through the launch option (not from a shortcut or the exe), and only on the start program; the check reads it",
        ),
        (
            ProfileMsg::OptionHeading,
            "launch option for Steam (copy it):",
        ),
        (ProfileMsg::Option { option: p("opt") }, "  opt"),
        (
            ProfileMsg::InstallUnknown,
            "  no launch option shown: Rerun's install folder is unknown",
        ),
        (
            ProfileMsg::OptionNotShowable,
            "  no launch option shown: the path of Rerun's install folder holds characters that cannot be shown as they are; move Rerun to a path without them",
        ),
        (
            ProfileMsg::ShimUnchecked { why: p("denied") },
            "  warning: whether rerun-launch.exe is in Rerun's install folder could not be checked: denied",
        ),
        (
            ProfileMsg::PasteNow,
            "now paste the launch option shown in the preview into Steam (the game > Properties > General > Launch options)",
        ),
        (
            ProfileMsg::PasteNotYet,
            "the launch option could not be offered or would not start the game (see the preview); fix that before you set a launch option in Steam",
        ),
        (ProfileMsg::AfterRevert, "once the revert completes:"),
        (
            ProfileMsg::OptionAny { id },
            "  (and any launch option with --profile 323ad79fbc93ca3e73b0b152a5d44616)",
        ),
        (
            ProfileMsg::ProfilePreviousBack { id },
            "launch option: the launch profile 323ad79fbc93ca3e73b0b152a5d44616 from before this transaction is back and keeps applying through the launch option; leave the option set for it",
        ),
        (
            ProfileMsg::ProfileStays { id },
            "launch option: the launch profile 323ad79fbc93ca3e73b0b152a5d44616 stays and keeps applying through the launch option until the option is removed",
        ),
        (
            ProfileMsg::ProfilesMovedTo { now: p(r"C:\B") },
            r"  now C:\B",
        ),
        (
            ProfileMsg::ProfilesHalt,
            "  Rerun's profiles folder is missing: the revert stops at the launch profile after everything else is reverted; forget closes the transaction then",
        ),
    ];
    for (m, want) in cases {
        assert_eq!(m.to_string(), want);
    }
}

#[test]
fn ranges_and_sizes() {
    assert_eq!(ranges(&[0, 1, 2, 3, 5, 7, 8]), "0-3, 5, 7-8");
    assert_eq!(ranges(&[4]), "4");
    assert_eq!(ranges(&[]), "");
    assert_eq!(crate::messages::size_text(32 << 20), "32 MiB");
    assert_eq!(crate::messages::size_text(1536 << 10), "1536 KiB");
}

fn view(
    selection: Result<SelectionShown, MachineWhy>,
    groups: u16,
    x86_capped: bool,
) -> LaunchView {
    LaunchView {
        machine: MachineView {
            selection,
            groups,
            x86_capped,
        },
        option: OptionText::InstallUnknown,
        shim: None,
    }
}

fn sel(mode: RuleMode) -> SelectionShown {
    SelectionShown {
        threads: 32,
        of: 128,
        group: 0,
        mask: 0xffff_ffff,
        cores: (0..16).collect(),
        llc: None,
        mode,
    }
}

/// `launch_lines` on hand-built views: two groups with a hard rule, the x86 cap, soft (no
/// multi-group hint), empty, unknown (escaped), no rule.
#[test]
fn launch_lines_cover_every_machine_view() {
    let p = preview(r"D:\Games\G", Vec::new());
    let text = |v: &LaunchView| shown(&launch_lines(&p, v));
    let t = text(&view(Ok(sel(RuleMode::Hard)), 2, true));
    assert!(
        t.contains(
            "  32 of 128 logical processors, group 0, mask 0x00000000ffffffff, cores 0-15\n"
        ),
        "{t}"
    );
    assert!(
        t.contains("hint: this computer has more than one processor group"),
        "{t}"
    );
    assert!(
        t.contains("hint: a 32-bit game gets processors 0 to 31"),
        "{t}"
    );
    assert!(
        t.contains("no launch option shown: Rerun's install folder is unknown"),
        "{t}"
    );
    let t = text(&view(Ok(sel(RuleMode::Soft)), 2, false));
    assert!(!t.contains("more than one processor group"), "{t}");
    assert!(t.contains("  soft: default CPU Sets"), "{t}");
    let t = text(&view(
        Err(MachineWhy::Empty {
            after: SelectStep::L3,
        }),
        1,
        false,
    ));
    assert!(t.contains("emptied by single_l3 / prefer_l3"), "{t}");
    let t = text(&view(
        Err(MachineWhy::Topology("bad \u{1b}[2J \u{202e}x".to_owned())),
        0,
        false,
    ));
    assert!(!t.contains('\u{1b}') && !t.contains('\u{202e}'), "{t}");
    assert!(t.contains("unknown here"), "{t}");
    let t = text(&view(Err(MachineWhy::NoRule), 1, false));
    assert!(t.contains("no CPU rule (priority only)"), "{t}");
}

/// Hostile paths (ESC, U+202E) in profile lines are escaped, never raw.
#[test]
fn hostile_profile_paths_are_escaped() {
    let bad = "D:\\G\u{202e}exe.\\x\u{1b}[2J.exe";
    let lines = vec![
        Message::Profile(ProfileMsg::Start {
            path: escape::path(bad),
        }),
        Message::Profile(ProfileMsg::LauncherStarts {
            start: escape::path(bad),
        }),
        Message::Profile(ProfileMsg::Target {
            path: escape::path(bad),
        }),
        Message::Profile(ProfileMsg::ShimMissing {
            path: escape::path(bad),
        }),
        Message::Profile(ProfileMsg::ProfilesMovedFrom {
            planned: escape::path(bad),
        }),
    ];
    let t = shown(&lines);
    assert!(!t.contains('\u{1b}') && !t.contains('\u{202e}'), "{t}");
}

/// The `watch` lines of the preview (P3-4c): the target last on its line, the hard and soft
/// modes, the priority note, the stub and the left-alone hints.
#[test]
fn every_watch_profile_line_has_its_text() {
    let cases: Vec<(ProfileMsg<'_>, &str)> = vec![
        (
            ProfileMsg::Target {
                path: escape::path(r"D:\G\g.exe"),
            },
            r"     target D:\G\g.exe",
        ),
        (
            ProfileMsg::WatchMode {
                mode: RuleMode::Hard,
            },
            "  hard: a new job with the selection on the game process once found; the game cannot widen it, programs it starts inherit it, and it stays until the game exits (a job the game is already in keeps its own limit: job_ineffective)",
        ),
        (
            ProfileMsg::WatchMode {
                mode: RuleMode::Soft,
            },
            "  soft: default CPU Sets of the game process once found, not of programs it starts; Windows may override them, and whether threads already running follow them is unproven (the check reads only that they are set)",
        ),
        (
            ProfileMsg::WatchPriorityNote { class: "high" },
            "  priority high is set on the game process once found, only when Steam starts the game through the launch option (not from a shortcut or the exe); the check reads it, and it is put back if the CPU rule cannot be set",
        ),
        (
            ProfileMsg::WatchStub,
            "  hint: Steam starts the game's own program: watch looks for a second process of it (a stub that hands over to a launcher such as Ubisoft Connect, which starts the game again); if the game does not start itself again, it runs unchanged (target_not_found): use method direct",
        ),
        (
            ProfileMsg::WatchLeftAlone,
            "  hint: a game running as administrator, or started by a launcher that runs as administrator, is left alone (target_elevated); a game that does not appear within 120 s (a login or an update in the launcher) runs unchanged (target_not_found): start it again",
        ),
    ];
    for (m, want) in cases {
        assert_eq!(m.to_string(), want);
    }
}

/// P3-7: the VirtualStore lines, golden; a hostile path arrives escaped and stays last.
#[test]
fn virtual_store_lines() {
    use rerun_core::path::RelPath;
    use rerun_core::policy::root::Shadow;
    let copy = r"C:\Users\P\AppData\Local\VirtualStore\Program Files (x86)\G\settings.ini";
    let shadows = [
        Shadow::Copy {
            root: 0,
            file: RelPath::parse("settings.ini").unwrap(),
            copy: escape::path(copy).into_owned(),
        },
        Shadow::Link {
            root: 1,
            at: escape::path("C:\\VS\\G\u{202e}x").into_owned(),
        },
        Shadow::Unchecked {
            root: 0,
            why: escape::text("LocalAppData is unknown: not found").into_owned(),
            at: None,
        },
        Shadow::Unchecked {
            root: 2,
            why: escape::text("LocalAppData: invalid path: invisible or confusable character")
                .into_owned(),
            at: Some(escape::path("C:\\L\u{202e}x").into_owned()),
        },
    ];
    let lines = super::shadow_lines(&shadows);
    let text = shown(&lines);
    let want = [
        format!(
            "warning: root 0: Windows keeps a VirtualStore copy of a managed file; the game probably reads this copy, not the managed file: {copy}"
        ),
        r#"note: root 1: a link (junction or symbolic link) lies on the way to a VirtualStore copy; it is not followed, nothing behind it was checked: "C:\\VS\\G\u{202e}x""#.to_owned(),
        "note: root 0: VirtualStore copies of the managed files were not checked: LocalAppData is unknown: not found".to_owned(),
        r#"note: root 2: VirtualStore copies of the managed files were not checked: LocalAppData: invalid path: invisible or confusable character: "C:\\L\u{202e}x""#.to_owned(),
    ];
    assert_eq!(text.lines().collect::<Vec<_>>(), want);
    assert!(!text.contains('\u{202e}'));
}

/// P4-2d: a firewall rule op with its rule and program, the note once, and the administrator
/// prompt lines per prompt state (ADR 0023 §10, A4 N7).
#[test]
fn a_firewall_rule_and_the_prompt_lines() {
    use rerun_core::elevate::{PromptKind, PromptState};
    use rerun_core::plan::{FIREWALL_NOTE, FirewallShown};
    let mut r = op(1, "block in firewall", Some(0), "game.exe");
    r.firewall = Some(FirewallShown {
        program: escape::path(r"D:\Games\G\game.exe").into_owned(),
        direction: "outbound",
        name: escape::path("Rerun - invented-game - <transaction>-001").into_owned(),
        group: "Rerun",
    });
    let mut p = preview(r"D:\Games\G", vec![r]);
    p.firewall = Some(FIREWALL_NOTE);
    let s = shown(&render(&p));
    assert!(
        s.contains(
            "op 1: block in firewall in root 0: game.exe\n  firewall rule: outbound, block, \
             group Rerun, name Rerun - invented-game - <transaction>-001\n  program: \
             D:\\Games\\G\\game.exe\n"
        ),
        "{s}"
    );
    assert_eq!(
        s.matches("firewall rules: Rerun's helper adds them")
            .count(),
        1,
        "{s}"
    );
    let state = |kind, secure_desktop, signed_only| PromptState {
        kind,
        secure_desktop,
        signed_only,
    };
    let consent = "administrator: Windows asks once for administrator approval (UAC) when \
                   Rerun's helper changes the firewall rules\n";
    let password = "administrator: Windows asks once for an administrator's password (UAC) \
                    when Rerun's helper changes the firewall rules\n";
    let not_secure = "administrator: the Windows prompt appears on your normal desktop, not the \
                      secure desktop (PromptOnSecureDesktop is 0): other programs could reach \
                      it\n";
    let none = "administrator: Windows will not ask for administrator approval on this PC: your \
                confirmation here is the only one\n";
    let signed = "administrator: Windows elevates only signed programs on this PC \
                  (ValidateAdminCodeSignatures is 1): Rerun's helper of this version is not \
                  signed and will not start; the apply is then rolled back\n";
    for (st, want) in [
        (
            state(PromptKind::Consent, Some(true), false),
            consent.to_owned(),
        ),
        (state(PromptKind::Consent, None, false), consent.to_owned()),
        (
            state(PromptKind::Consent, Some(false), false),
            format!("{consent}{not_secure}"),
        ),
        (
            state(PromptKind::Credentials, Some(true), false),
            password.to_owned(),
        ),
        (state(PromptKind::NoPrompt, None, false), none.to_owned()),
        (state(PromptKind::Unknown, None, false), none.to_owned()),
        (
            state(PromptKind::Consent, Some(true), true),
            format!("{consent}{signed}"),
        ),
        // Refused before the lock, so never shown with a question.
        (state(PromptKind::Denied, None, false), String::new()),
        (state(PromptKind::UacOff, None, false), String::new()),
    ] {
        assert_eq!(shown(&super::prompt_lines_of(&st)), want, "{st:?}");
    }
}

/// P4-8: a `keep shared file` op shows what the file holds, that nothing is written, and the
/// note once.
#[test]
fn a_held_file_is_shown_as_kept() {
    let sha = "cd".repeat(32);
    let mut hold = op(0, rerun_core::plan::HOLD_ACTION, Some(0), "dinput8.dll");
    hold.source = Some(escape::path(r"ultimate-asi-loader 10.0.2: x86\dinput8.dll").into_owned());
    hold.content = Some((sha.clone(), 14));
    hold.held = true;
    let mut p = preview(r"D:\Games\G", vec![hold]);
    p.registry = None;
    p.layers = None;
    p.ini = None;
    p.held = Some(rerun_core::plan::HOLD_NOTE);
    let text = shown(&render(&p));
    for want in [
        "op 0: keep shared file in root 0: dinput8.dll\n",
        "  from package: ultimate-asi-loader 10.0.2: x86\\dinput8.dll\n",
        &format!("  holds: sha256 {sha}, 14 bytes (kept as it is, not written)\n"),
    ] {
        assert!(text.contains(want), "{want:?} not in\n{text}");
    }
    assert!(!text.contains("  new: sha256"), "{text}");
    assert_eq!(
        text.matches("shared files: a package file").count(),
        1,
        "{text}"
    );
}
