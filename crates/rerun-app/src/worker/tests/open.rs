//! Links, "report a problem" and the data folder through the worker (P5-10a, ADR 0027 amendment
//! P5-10a), against the fake world and the fake shell: nothing is ever opened.
//! - AO2 a source link of the fix card opens exactly the URL of the current index; a reference
//!   the index does not have opens nothing and is a calm result; the page carries the Topo and
//!   which sources can be opened.
//! - AO3 the report dialog shows exactly the issue's title and text (only Rerun's facts: the open
//!   change's variant IDs, never the Steam name or a path), and "Open in browser" opens exactly
//!   that URL; English and German.
//! - AO5 the nonce: a confirm of another or an older dialog opens nothing; a second confirm of
//!   the same one neither; elevated, the guard stops every open job before anything is read.
//! - AO4 Settings > Data: no folder, "not created yet", no button, a click opens nothing and
//!   creates nothing; with the folder, its path and Explorer gets exactly it.
//! - AO6 Settings > About Rerun (P5-10e): "source code of this version" and "repository" open
//!   exactly the core's `OwnLink` URLs, also without an index and without Rerun's folder.

use std::sync::Arc;

use rerun_core::flow::LinkRef;
use rerun_core::policy::open::{OpenUrl, OwnLink};
use rerun_core::sys::fake::{FakeShell, Opened};

use super::write::{RERUN, Rig, result_of};
use super::*;
use crate::vm::{DialogKind, DialogVm, Tone};
use crate::worker::ShellRef;

/// A session that opens through `shell`.
fn session_with(shell: &Arc<FakeShell>) -> Session {
    Session {
        shell: ShellRef(shell.clone()),
        ..Session::default()
    }
}

fn dialog_of(ev: &[Event]) -> &DialogVm {
    match ev {
        [Event::Dialog(d)] => d,
        other => panic!("{other:?}"),
    }
}

/// The text a dialog shows as the issue: its title line and every line of the text.
fn issue_of(d: &DialogVm) -> (String, String) {
    let (title, lines) = d.details.split_first().unwrap();
    let body: Vec<&str> = lines.iter().map(|l| l.what.as_str()).collect();
    (
        title.what.as_str().to_owned(),
        format!("{}\n", body.join("\n")),
    )
}

/// Decodes `%XX`.
fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

#[test]
fn ao2_a_source_link_opens_exactly_the_index_url() {
    let sys = indexed("Invented AC");
    let shell = Arc::new(FakeShell::new());
    let mut session = session_with(&shell);
    let g = the_game(events_in(&sys, &mut session, &game_job()));
    assert_eq!(g.topo.as_deref(), Some("invented-ac"));
    let patch = &g.fixes[0];
    assert_eq!(patch.key, "patch");
    // `patch` under `online` has the repository and the wiki; both can be opened.
    assert_eq!(patch.solves[1].can_open, [true, true]);
    let r = LinkRef {
        app_id: 220,
        topo: "invented-ac".to_owned(),
        issue: patch.issues[1].0.clone(),
        variant: patch.key.clone(),
        source: 1,
    };
    assert_eq!(
        events_in(&sys, &mut session, &Job::OpenSource(r.clone())),
        [Event::Opened]
    );
    assert_eq!(
        shell.taken(),
        [Opened::Url(
            "https://www.pcgamingwiki.com/wiki/Invented_Game".to_owned()
        )]
    );
    // A source the index does not have: calm, nothing opened.
    for bad in [
        LinkRef {
            source: 2,
            ..r.clone()
        },
        LinkRef {
            variant: "limit".to_owned(),
            source: 0,
            ..r.clone()
        },
        LinkRef {
            app_id: 240,
            ..r.clone()
        },
    ] {
        let ev = events_in(&sys, &mut session, &Job::OpenSource(bad));
        let res = result_of(&ev);
        assert_eq!(res.tone, Tone::Calm);
        assert_eq!(res.notice.title, "Nothing was opened");
        assert_eq!(
            res.notice.body,
            "The current index no longer has this link."
        );
        assert!(!res.refresh);
    }
    assert_eq!(shell.taken().len(), 1);
}

#[test]
fn ao3_the_report_dialog_shows_exactly_what_opens() {
    for lang in Lang::ALL {
        let mut rig = Rig::new(lang);
        let shell = Arc::new(FakeShell::new());
        rig.session.shell = ShellRef(shell.clone());
        // An open change of the game: its variant IDs go into the report.
        let pv = rig.preview();
        let ev = rig.run(Job::Apply { hash: pv.hash });
        assert_eq!(result_of(&ev).tone, Tone::Done, "{ev:?}");
        let before = rig.snap_app();
        let ev = rig.run(Job::ReportAsk { app_id: 220 });
        let d = dialog_of(&ev).clone();
        assert_eq!(d.kind, DialogKind::Report);
        assert!(d.can_confirm && d.txn.is_none());
        let (title, body) = issue_of(&d);
        assert_eq!(title, "Problem with Steam app 220");
        assert!(body.contains("- Steam app: 220\n"), "{body}");
        assert!(
            body.contains("- Topos: invented-w rev 2 (active)\n"),
            "{body}"
        );
        let changes = body
            .lines()
            .find(|l| l.starts_with("- Open changes: "))
            .unwrap();
        assert!(
            changes.contains("limit") && changes.contains("ini"),
            "{changes}"
        );
        for needle in ["Invented W", "Player", "SteamLibrary", "\\", "AppData"] {
            assert!(!body.contains(needle), "{needle} in {body}");
        }
        match lang {
            Lang::En => {
                assert_eq!(d.title, "Report a problem");
                assert_eq!(d.confirm, "Open in browser");
                assert!(d.intro.starts_with("Rerun opens a new issue on GitHub"));
                assert_eq!(d.details[0].who.as_ref().unwrap().as_str(), "Title");
                assert_eq!(d.details[1].who.as_ref().unwrap().as_str(), "Text");
            }
            Lang::De => {
                assert_eq!(d.title, "Problem melden");
                assert_eq!(d.confirm, "Im Browser \u{f6}ffnen");
                assert!(d.intro.starts_with("Rerun \u{f6}ffnet auf GitHub"));
                assert_eq!(d.details[0].who.as_ref().unwrap().as_str(), "Titel");
                assert!(d.notes[0].starts_with("Ziel: github.com/mythenstudios/rerun."));
            }
        }
        // Asking opened nothing and wrote nothing.
        assert!(shell.taken().is_empty());
        assert_eq!(rig.snap_app(), before);
        // "Open in browser": exactly the issue the dialog showed.
        let ev = rig.run(Job::ReportOpen { nonce: d.nonce });
        assert_eq!(ev, [Event::Opened]);
        let taken = shell.taken();
        let [Opened::Url(url)] = taken.as_slice() else {
            panic!("{taken:?}");
        };
        let q = url
            .strip_prefix("https://github.com/mythenstudios/rerun/issues/new?title=")
            .unwrap();
        let (t, b) = q.split_once("&body=").unwrap();
        assert_eq!((decode(t), decode(b)), (title, body));
        assert!(url.len() <= rerun_core::policy::open::MAX_OPEN_URL);
    }
}

#[test]
fn ao5_only_the_shown_report_is_opened() {
    let mut rig = Rig::new(Lang::En);
    let shell = Arc::new(FakeShell::new());
    rig.session.shell = ShellRef(shell.clone());
    let first = dialog_of(&rig.run(Job::ReportAsk { app_id: 220 })).nonce;
    let second = dialog_of(&rig.run(Job::ReportAsk { app_id: 220 })).nonce;
    assert_ne!(first, second);
    // The older dialog, and one never shown: nothing.
    for nonce in [first, second + 1] {
        let ev = rig.run(Job::ReportOpen { nonce });
        let r = result_of(&ev);
        assert_eq!(r.notice.title, "Nothing was opened");
        assert_eq!(r.notice.body, "The dialog was out of date. Open it again.");
    }
    assert!(shell.taken().is_empty());
    // The stale confirm took the report away: the newest one needs its dialog again.
    let ev = rig.run(Job::ReportOpen { nonce: second });
    assert!(matches!(ev.as_slice(), [Event::Result(_)]), "{ev:?}");
    assert!(shell.taken().is_empty());
    let third = dialog_of(&rig.run(Job::ReportAsk { app_id: 220 })).nonce;
    assert_eq!(rig.run(Job::ReportOpen { nonce: third }), [Event::Opened]);
    // A second confirm of the same dialog opens nothing more.
    let ev = rig.run(Job::ReportOpen { nonce: third });
    assert!(matches!(ev.as_slice(), [Event::Result(_)]), "{ev:?}");
    assert_eq!(shell.taken().len(), 1);

    // Elevated: every open job stops at the guard, nothing read, nothing opened.
    let sys = indexed("Invented AC");
    let shell = Arc::new(FakeShell::new());
    let mut session = session_with(&shell);
    sys.fake_registry().set_elevated(true);
    sys.fake_fs().record_calls(true);
    for job in [
        Job::ReportAsk { app_id: 220 },
        Job::ReportOpen { nonce: 1 },
        Job::DataFolder,
        Job::OpenDataFolder,
        Job::OpenOwn(OwnLink::SourceOfThisBuild),
        Job::OpenSource(LinkRef {
            app_id: 220,
            topo: "invented-ac".to_owned(),
            issue: "online".to_owned(),
            variant: "patch".to_owned(),
            source: 0,
        }),
    ] {
        let ev = events_in(&sys, &mut session, &job);
        assert!(
            matches!(ev.as_slice(), [Event::Blocked(b)] if b.elevated),
            "{job:?}: {ev:?}"
        );
    }
    assert!(sys.fake_fs().take_calls().is_empty());
    assert!(shell.taken().is_empty());
}

#[test]
fn ao4_settings_data_shows_the_folder_and_opens_only_an_existing_one() {
    // No folder yet: the path where it would be, the note, no button; a click opens nothing and
    // creates nothing.
    for lang in Lang::ALL {
        let sys = steam_world("Invented AC");
        let shell = Arc::new(FakeShell::new());
        let mut session = session_with(&shell);
        let http = FakeHttp::default();
        let install = install();
        let env = Env {
            sys: &sys,
            http: &http,
            install: &install,
        };
        let mut ev = Vec::new();
        let _ = run_in(
            env,
            &Job::DataFolder,
            lang,
            &mut session,
            &mut || None,
            &mut |e| {
                ev.push(e);
            },
        );
        let [Event::DataFolder(d)] = ev.as_slice() else {
            panic!("{ev:?}");
        };
        assert_eq!(d.path.as_ref().unwrap().as_str(), RERUN);
        assert!(!d.exists);
        assert_eq!(
            d.note.as_deref(),
            Some(match lang {
                Lang::En => "Not created yet. Rerun creates it when it first stores something.",
                Lang::De => {
                    "Noch nicht angelegt. Rerun legt ihn an, wenn es zum ersten Mal etwas speichert."
                }
            })
        );
        let mut ev = Vec::new();
        let _ = run_in(
            env,
            &Job::OpenDataFolder,
            lang,
            &mut session,
            &mut || None,
            &mut |e| ev.push(e),
        );
        let r = result_of(&ev);
        assert_eq!(r.tone, Tone::Calm);
        assert_eq!(
            r.notice.body,
            match lang {
                Lang::En => "Rerun's folder does not exist yet.",
                Lang::De => "Der Ordner von Rerun existiert noch nicht.",
            }
        );
        assert!(shell.taken().is_empty());
        assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
    }
    // The folder exists: its path, the button, and Explorer gets exactly it.
    let sys = indexed("Invented AC");
    let shell = Arc::new(FakeShell::new());
    let mut session = session_with(&shell);
    let ev = events_in(&sys, &mut session, &Job::DataFolder);
    let [Event::DataFolder(d)] = ev.as_slice() else {
        panic!("{ev:?}");
    };
    assert!(d.exists && d.note.is_none());
    assert_eq!(d.path.as_ref().unwrap().as_str(), RERUN);
    assert_eq!(
        events_in(&sys, &mut session, &Job::OpenDataFolder),
        [Event::Opened]
    );
    match shell.taken().as_slice() {
        [Opened::Folder(p)] => assert_eq!(p.to_string(), RERUN),
        other => panic!("{other:?}"),
    }
    // A shell that fails: the error, never a guess.
    let failing = Arc::new(FakeShell::failing(rerun_core::sys::SysErrorKind::NotFound));
    let mut session = session_with(&failing);
    let ev = events_in(&sys, &mut session, &Job::OpenDataFolder);
    let r = result_of(&ev);
    assert_eq!(r.tone, Tone::Attention);
    assert_eq!(
        r.notice.body,
        "Windows could not open it. The details say why."
    );
    assert_eq!(r.notice.details.len(), 1);
}

#[test]
fn ao6_about_links_open_exactly_rerun_s_own_urls() {
    // No index and no Rerun folder: the links are compiled in and need neither.
    let sys = steam_world("Invented AC");
    let shell = Arc::new(FakeShell::new());
    let mut session = session_with(&shell);
    let links = [OwnLink::SourceOfThisBuild, OwnLink::Repository];
    for l in links {
        assert_eq!(
            events_in(&sys, &mut session, &Job::OpenOwn(l)),
            [Event::Opened]
        );
    }
    let want: Vec<Opened> = links
        .iter()
        .map(|l| Opened::Url(OpenUrl::own(*l).as_str().to_owned()))
        .collect();
    assert_eq!(shell.taken(), want);
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
}
