//! Name rules, the install folder hint and the similarity (ADR 0014, "Roles", "Ranking").
//! The names are the shapes the developer-machine dump showed, with invented games.

use super::{Role, name_role, similarity, stem};
use crate::path::RelPath;

fn role(name: &str) -> Role {
    name_role(name, None)
}

fn hinted(name: &str, hint: &str) -> Role {
    name_role(name, Some(&RelPath::parse(hint).unwrap()))
}

#[test]
fn crash_reporters() {
    for name in [
        "createdump.exe",
        "crashpad_handler.exe",
        "CrashReportClient.exe",
        "UnityCrashHandler32.exe",
        "UnityCrashHandler64.exe",
        "BsSndRpt.exe",
        "BsSndRpt64.exe",
        "crash_reporter.exe",
        "GameCrashUploader.EXE",
    ] {
        assert_eq!(role(name), Role::CrashReporter, "{name}");
    }
    assert_eq!(role("createdumps.exe"), Role::Game);
    assert_eq!(role("bssndrpt32.exe"), Role::Game);
}

#[test]
fn anti_cheat() {
    for name in [
        "start_protected_game.exe",
        "pbsvc.exe",
        "PnkBstrA.exe",
        "PnkBstrB.exe",
        "BEService_x64.exe",
        "EasyAntiCheat_Setup.exe",
        "Invented_BE.exe",
        "Invented_EAC.exe",
    ] {
        assert_eq!(role(name), Role::AntiCheat, "{name}");
    }
    // Prefixes: PunkBuster's services and their versions.
    for name in ["pbsvc2.exe", "PnkBstrK.exe"] {
        assert_eq!(role(name), Role::AntiCheat, "{name}");
    }
    for name in [
        "xpbsvc.exe",
        "Invented_BEx.exe",
        "Invented-BE.exe",
        "xbeservice.exe",
    ] {
        assert_eq!(role(name), Role::Game, "{name}");
    }
}

#[test]
fn installers() {
    for name in [
        "setup.exe",
        "InventedSetup.exe",
        "UbisoftConnectInstaller.exe",
        "uninstall.exe",
        "redist.exe",
        "vc_redist.x64.exe",
        "vcredist_x86.exe",
        "DXSETUP.exe",
        "dotNetFx40_Full_setup.exe",
        "PhysX_9.10.0513_SystemSoftware.exe",
        "oalinst.exe",
        "unins000.exe",
        "unins1.exe",
        "InventedPatcher.exe",
        "patch.exe",
        "Updater.exe",
        "InventedAutoUpdate.exe",
    ] {
        assert_eq!(role(name), Role::Installer, "{name}");
    }
    for name in ["unins.exe", "uninsx.exe", "unins00a.exe", "xphysx.exe"] {
        assert_eq!(role(name), Role::Game, "{name}");
    }
}

#[test]
fn launchers() {
    for name in [
        "launcher.exe",
        "FFLauncher.exe",
        "REDprelauncher.exe",
        "InventedLauncher.exe",
        "InventedLaunch.exe",
        "StartLaunchPad.exe",
    ] {
        assert_eq!(role(name), Role::Launcher, "{name}");
    }
    // A launcher without the word is the game by name (ranking decides).
    assert_eq!(role("PlayInvented.exe"), Role::Game);
}

#[test]
fn helpers() {
    for name in [
        "BF3WebHelper.exe",
        "steamwebhelper.exe",
        "CefSharp.BrowserSubprocess.exe",
        "cefprocess.exe",
        "QtWebEngineProcess.exe",
        "Invented_Server.exe",
        "invented-server.exe",
        "InventedDedicatedServer.exe",
        "Config.exe",
        "InventedSettings.exe",
        "LevelEditor.exe",
        "InventedShaderCompileWorker.exe",
        "ShaderCompiler.exe",
        "GameOverlayUI.exe",
        "Injector.exe",
        "ActivationUI.exe",
        "server.exe",
        "InventedServer.exe",
    ] {
        assert_eq!(role(name), Role::Helper, "{name}");
    }
    assert_eq!(role("Invented_Servers.exe"), Role::Game);
}

#[test]
fn the_first_matching_group_wins() {
    // Crash before anti-cheat, installer, launcher and helper.
    assert_eq!(role("CrashLauncher_BE.exe"), Role::CrashReporter);
    // Anti-cheat before installer ("EasyAntiCheat_Setup").
    assert_eq!(role("EasyAntiCheat_Setup.exe"), Role::AntiCheat);
    // Installer before launcher.
    assert_eq!(role("LauncherSetup.exe"), Role::Installer);
    // Launcher before helper.
    assert_eq!(role("LauncherConfig.exe"), Role::Launcher);
}

#[test]
fn games_and_odd_names() {
    for name in [
        "Invented.exe",
        "Invented-Win64-Shipping.exe",
        "game.exe",
        ".exe",
        "noextension",
        "Invented.EXE",
    ] {
        assert_eq!(role(name), Role::Game, "{name}");
    }
    // ASCII tokens match inside a stem with non-ASCII characters too.
    assert_eq!(role("Crash\u{00e9}.exe"), Role::CrashReporter);
    assert_eq!(role("\u{30b2}\u{30fc}\u{30e0}Launcher.exe"), Role::Launcher);
    assert_eq!(role("\u{30b2}\u{30fc}\u{30e0}.exe"), Role::Game);
    // The Kelvin sign does not fold to `k`: no token matches by accident.
    assert_eq!(role("Pn\u{212A}bstrA.exe"), Role::Game);
}

#[test]
fn the_install_folder_hint_suspends_the_rules() {
    // A rule is suspended only when its token occurs in the install folder name.
    assert_eq!(hinted("CrashBandicoot.exe", "Crash Bandicoot"), Role::Game);
    assert_eq!(hinted("Crash.exe", "Crash Bandicoot"), Role::Game);
    assert_eq!(hinted("Crash.exe", "Burnout Crash"), Role::Game);
    assert_eq!(hinted("SetupWorld.exe", "Setup World 2"), Role::Game);
    assert_eq!(hinted("Dispatch.exe", "Dispatch"), Role::Game);
    assert_eq!(hinted("Observer.exe", "Observer"), Role::Game);
    // The folder name alone does not suspend a rule whose token it lacks.
    assert_eq!(
        hinted("Invented4Launcher.exe", "Invented 4"),
        Role::Launcher
    );
    assert_eq!(
        hinted("UnityCrashHandler64.exe", "Invented"),
        Role::CrashReporter
    );
    // A suspended token lets the next rule decide.
    assert_eq!(
        hinted("CrashLauncher.exe", "Crash Bandicoot"),
        Role::Launcher
    );
    // Without a hint, nothing is suspended.
    assert_eq!(role("CrashBandicoot.exe"), Role::CrashReporter);
}

#[test]
fn similarity_of_stem_and_hint() {
    assert_eq!(similarity("CrashBandicoot", "Crash Bandicoot"), 2);
    assert_eq!(similarity("invented_game", "Invented-Game"), 2);
    assert_eq!(similarity("Invented", "Invented Game"), 1);
    assert_eq!(similarity("Invented Game Deluxe", "Invented Game"), 1);
    assert_eq!(similarity("Inve", "Invented"), 1, "four characters suffice");
    assert_eq!(similarity("Inv", "Invented"), 0, "three do not");
    // Containment in both directions, the shorter side at least four characters.
    assert_eq!(similarity("Game", "Invented Game"), 1);
    assert_eq!(similarity("Invented2", "Fortress Invented 2"), 1);
    assert_eq!(similarity("Fortress Invented 2 HD", "Invented 2"), 1);
    assert_eq!(similarity("IG", "Invented Game"), 0, "no acronyms");
    assert_eq!(similarity("logview_viewer", "Fortress Invented 2"), 0);
    assert_eq!(similarity("", "Invented"), 0);
    assert_eq!(similarity("---", "---"), 0, "nothing left after reducing");
    assert_eq!(
        similarity("\u{30b2}\u{30fc}\u{30e0}", "\u{30b2}\u{30fc}\u{30e0}"),
        0
    );
}

#[test]
fn stems() {
    assert_eq!(stem("Game.exe"), "Game");
    assert_eq!(stem("Game.EXE"), "Game");
    assert_eq!(stem("Game.exe.exe"), "Game.exe");
    assert_eq!(stem("Game"), "Game");
    assert_eq!(stem(".exe"), "");
    assert_eq!(stem("\u{30b2}.exe"), "\u{30b2}");
}

#[test]
fn roles_display() {
    use crate::detect::pe::LegacyFormat;
    assert_eq!(Role::Game.to_string(), "game");
    assert_eq!(Role::NotAnApp.to_string(), "DLL, not an application");
    assert_eq!(
        Role::Legacy(LegacyFormat::Ne).to_string(),
        "16-bit Windows (NE) executable"
    );
}
