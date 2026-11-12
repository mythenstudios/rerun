//! Package downloads through the worker (P5-5b, ADR 0027 amendment P5-5b): consent, progress,
//! cancel, failures and the apply and undo of a package fix, in the fake world with scripted
//! HTTPS and no window. Every ID, URL and file is invented; nothing touches a network.
//! - AD1 nothing is downloaded without the consent of the list that was shown (a confirm of
//!   another nonce asks nobody); the consent lists what the index says; after the download the
//!   fix is selectable, and apply then undo leaves the game folder bit-identical.
//! - AD2 progress: every package's state in order, with the announced length.
//! - AD3 a cancel in the middle of the body ends the download cancelled with nothing in the
//!   cache and no packages folder; a second try works.
//! - AD4 failures are dialogs with "Try again": a wrong hash, a redirect to a foreign host,
//!   offline; none keeps anything; a package that changed in the index since the consent is
//!   refused before any request.
//! - AD5 the worker thread: a download counts as running from `send`, a cancel from the window
//!   ends it, and `downloading()` is false afterwards.

use std::sync::atomic::Ordering;

use rerun_core::journal::TxnId;
use rerun_core::pkg::archive::testfx::{ZipEntry, zip};
use rerun_core::plan::Pick;
use rerun_core::sys::SysErrorKind;
use rerun_core::sys::System;
use rerun_core::sys::fake::{FakeReply, Trip};
use rerun_core::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use sha2::{Digest, Sha256};

use super::*;
use crate::text::{Msg, t};
use crate::vm::{DownloadStage, DownloadVm, Offer, PackageState, Selection};
use crate::worker::DownloadOutcome;

const ASSET: &str = "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip";
const STORE: &str =
    "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sp=r";
const DLL: &[u8] = b"the fix dll";
const INI: &[u8] = b"[Fix]\r\nOn=1\r\n";

fn upper(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect()
}

/// Bytes that do not compress, so the archive is as large as its content.
fn noise(n: usize) -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            x.to_be_bytes()[0]
        })
        .collect()
}

fn archive() -> Vec<u8> {
    zip(&[
        ZipEntry::file("bin/fix.dll", DLL),
        ZipEntry::file("fix.ini", INI),
        ZipEntry::file("README.txt", &noise(300 * 1024)),
    ])
}

/// The index: one Topo whose only fix is the package `fix-pack`.
fn pkg_index(archive: &[u8], game_sha: &str, seq: u32) -> String {
    format!(
        r#"{{"format":1,"seq":{seq},"issued":"2026-11-12T12:00:00Z","topos":[{{"format":1,"id":"invented-p","title":"Invented P","status":"active","rev":1,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{game_sha}","api":"d3d9"}}]}},
"launch":{{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}},
"issues":[{{"id":"crash","title":"The game crashes","variants":[{{"id":"fix-pack","status":"verified","kind":"fix","steps":[{{"package":"fix-pack"}}]}}]}}]}}],
"packages":[{{"format":1,"id":"fix-pack","name":"Fix pack","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-pack","release":"{ASSET}"}},"version":"1.0","sha256":"{a}","license":"MIT","arch":["x86"],"slots":["fix.dll"],"files":[{{"from":"bin/fix.dll","to":"fix.dll","sha256":"{d}"}},{{"from":"fix.ini","to":"fix.ini","sha256":"{i}","config":true}}]}}]}}"#,
        a = upper(archive),
        d = upper(DLL),
        i = upper(INI),
    )
}

fn import(sys: &FakeSystem, index: &str) {
    let app = AppDir::open(sys, Create::IfMissing).unwrap().unwrap();
    catalog::store::import(
        &app,
        index.as_bytes(),
        &test_key::sign(index.as_bytes()),
        &catalog::trusted_keys(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    drop(app);
    sys.fake_fs().sync_all();
}

fn github(body: FakeReply) -> FakeHttp {
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::redirect(302, STORE));
    http.reply(STORE, body);
    http
}

/// A world, scripted HTTPS, a session and a language: jobs run as the worker thread runs them.
struct DRig {
    sys: FakeSystem,
    http: FakeHttp,
    session: Session,
    lang: Lang,
    archive: Vec<u8>,
}

impl DRig {
    fn new(lang: Lang, body: impl FnOnce(&[u8]) -> FakeReply) -> Self {
        let archive = archive();
        let sys = steam_world("Invented P");
        import(&sys, &pkg_index(&archive, &sha256_of(&sys, "game.exe"), 1));
        let http = github(body(&archive));
        Self {
            sys,
            http,
            session: Session::default(),
            lang,
            archive,
        }
    }

    fn run(&mut self, job: Job) -> Vec<Event> {
        let install = install();
        let env = Env {
            sys: &self.sys,
            http: &self.http,
            install: &install,
        };
        // As `Worker::send` does for a download.
        if job.downloads() {
            self.session.cancel.store(false, Ordering::SeqCst);
        }
        let mut out = Vec::new();
        let _ = run_in(
            env,
            &job,
            self.lang,
            &mut self.session,
            &mut || None,
            &mut |e| out.push(e),
        );
        out
    }

    fn page(&mut self) -> GameVm {
        match self
            .run(Job::Game {
                app_id: 220,
                name: Some(escape::text("Invented P").into_owned()),
            })
            .as_slice()
        {
            [Event::Game(g)] => g.clone(),
            other => panic!("{other:?}"),
        }
    }

    /// The click on the fix's checkbox: the consent dialog.
    fn ask(&mut self) -> DownloadVm {
        let ev = self.run(Job::DownloadAsk {
            app_id: 220,
            variant: "fix-pack".to_owned(),
        });
        match ev.as_slice() {
            [Event::Download(d)] => (**d).clone(),
            other => panic!("{other:?}"),
        }
    }

    /// The game folder: what an undo must restore bit for bit.
    fn snap(&self) -> Snapshot {
        let fr = ForbiddenRoots::resolve(&self.sys, Path::new(INSTALL)).unwrap();
        let g = GameDir::open_manual(&self.sys, &fr, Path::new(G)).unwrap();
        snapshot(
            System::registry(&self.sys),
            &Scope {
                dirs: vec![SnapRoot::new(g.dir(), G)],
                keys: Vec::new(),
            },
        )
        .unwrap()
    }

    /// The names in Rerun's `cache` or `packages` folder (without lock files); `None`: the
    /// folder does not exist.
    fn listed(&self, sub: &str) -> Option<Vec<String>> {
        let a = AppDir::open(&self.sys, Create::Never).unwrap().unwrap();
        let dir = match a.dir().open_dir(&RelPath::parse(sub).unwrap()) {
            Ok(d) => d,
            Err(e) if e.kind == SysErrorKind::NotFound => return None,
            Err(e) => panic!("{e}"),
        };
        let mut names: Vec<String> = dir
            .read_dir(None)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .filter(|n| n != "lock" && n != ".lock")
            .collect();
        names.sort();
        Some(names)
    }
}

fn ended(ev: &[Event]) -> Option<DownloadOutcome> {
    ev.iter().find_map(|e| match e {
        Event::DownloadEnded(o) => Some(*o),
        _ => None,
    })
}

fn dialogs(ev: &[Event]) -> Vec<&DownloadVm> {
    ev.iter()
        .filter_map(|e| match e {
            Event::Download(d) => Some(&**d),
            _ => None,
        })
        .collect()
}

/// The text of the line `label` of a package entry.
fn line<'a>(d: &'a DownloadVm, label: &str) -> Vec<&'a str> {
    d.packages[0]
        .lines
        .iter()
        .find(|l| l.label == label)
        .unwrap_or_else(|| panic!("no line {label}"))
        .values
        .iter()
        .map(Value::as_str)
        .collect()
}

#[test]
fn ad1_nothing_is_downloaded_without_the_consent_of_the_list_shown() {
    for lang in Lang::ALL {
        let mut r = DRig::new(lang, |a| FakeReply::ok(a).chunked(16 * 1024));
        let page = r.page();
        let fix = &page.fixes[0];
        // Not selectable, not preselected; a package that is not there asks first.
        assert_eq!(
            (fix.key.as_str(), fix.offer),
            ("fix-pack", Offer::NeedsDownload)
        );
        assert!(!fix.preselect);
        let mut sel = Selection::preselected(&page);
        sel.toggle(&page, 0);
        assert!(!sel.contains("fix-pack"), "ticking selects nothing");
        let ev = r.run(Job::Plan {
            app_id: 220,
            picks: vec![Pick {
                issue: "crash".to_owned(),
                variant: "fix-pack".to_owned(),
            }],
        });
        assert!(
            matches!(ev.as_slice(), [Event::PreviewRefused { .. }]),
            "{ev:?}"
        );

        // The consent: everything the index says, nothing requested, nothing created.
        let before = r.snap();
        let d = r.ask();
        assert_eq!(d.stage, DownloadStage::Consent);
        assert_eq!(d.title, t(lang, Msg::DlConsentTitle));
        assert_eq!(d.confirm.as_deref(), Some(&*t(lang, Msg::DlBtn)));
        assert_eq!(d.packages.len(), 1);
        assert_eq!(d.packages[0].target.as_str(), "Fix pack 1.0");
        assert_eq!(
            line(&d, &t(lang, Msg::DlLblSource)),
            ["https://github.com/owner/fix-pack"]
        );
        assert_eq!(line(&d, &t(lang, Msg::DlLblRelease)), [ASSET]);
        assert_eq!(line(&d, &t(lang, Msg::DlLblHost)), ["github.com"]);
        assert_eq!(
            line(&d, &t(lang, Msg::DlLblSha)),
            [upper(&r.archive).to_ascii_lowercase()]
        );
        assert_eq!(line(&d, &t(lang, Msg::DlLblLicence)), ["MIT"]);
        assert_eq!(
            line(&d, &t(lang, Msg::DlLblSize)),
            [&*t(lang, Msg::DlSizeLater)]
        );
        assert!(d.notes.contains(&t(lang, Msg::DlChecked).into_owned()));
        assert!(r.http.requests().is_empty(), "asking requests nothing");
        assert_eq!(r.listed("cache"), None, "asking creates nothing");
        assert_eq!(r.listed("packages"), None);
        assert!(r.snap() == before);

        // A confirm of another dialog downloads nothing.
        let ev = r.run(Job::Download { nonce: d.nonce + 1 });
        assert_eq!(ended(&ev), Some(DownloadOutcome::Refused), "{ev:?}");
        assert!(dialogs(&ev).is_empty());
        assert!(r.http.requests().is_empty());
        assert_eq!(r.listed("cache"), None);
        // ... and, as the shown list is still the one pending, the right nonce works.
        let ev = r.run(Job::Download { nonce: d.nonce });
        assert_eq!(ended(&ev), Some(DownloadOutcome::Done), "{ev:?}");
        assert_eq!(r.http.requests(), [ASSET, STORE]);
        // The fresh page follows the end: the fix is selectable now.
        let page = game_in(&ev).clone();
        assert_eq!(
            ev.last(),
            Some(&Event::DownloadEnded(DownloadOutcome::Done))
        );
        assert_eq!(page.fixes[0].offer, Offer::Selectable);
        let want = r.archive.len();
        assert_eq!(
            r.listed("cache"),
            Some(vec![upper(&r.archive).to_ascii_lowercase()]),
            "{want} bytes"
        );
        // A second confirm of the same dialog has nothing to confirm.
        let ev = r.run(Job::Download { nonce: d.nonce });
        assert_eq!(ended(&ev), Some(DownloadOutcome::Refused));

        // The usual flow goes on: select, preview (with the package files), apply, undo.
        let mut sel = Selection::default();
        sel.toggle(&page, 0);
        assert!(sel.contains("fix-pack"));
        let ev = r.run(Job::Plan {
            app_id: 220,
            picks: sel.picks(&page),
        });
        let pv = match ev.as_slice() {
            [Event::Preview { vm, .. }] => (**vm).clone(),
            other => panic!("{other:?}"),
        };
        let targets: Vec<&str> = pv.ops.iter().map(|o| o.target.as_str()).collect();
        assert!(
            targets.contains(&"fix.dll") && targets.contains(&"fix.ini"),
            "{targets:?}"
        );
        r.run(Job::PreviewShown {
            hash: pv.hash.clone(),
        });
        let ev = r.run(Job::Apply {
            hash: pv.hash.clone(),
        });
        assert_eq!(
            match ev.iter().find_map(|e| match e {
                Event::Result(r) => Some(r.tone),
                _ => None,
            }) {
                Some(t) => t,
                None => panic!("{ev:?}"),
            },
            crate::vm::Tone::Done,
            "{ev:?}"
        );
        assert!(r.snap() != before, "the fix is in the game folder");
        let txn: TxnId = ev
            .iter()
            .find_map(|e| match e {
                Event::Applied(a) => a.cards.first().map(|c| c.txn),
                _ => None,
            })
            .expect("the applied card");
        let ev = r.run(Job::RevertPreview { txn });
        let nonce = match ev.iter().find_map(|e| match e {
            Event::Dialog(d) => Some(d.nonce),
            _ => None,
        }) {
            Some(n) => n,
            None => panic!("{ev:?}"),
        };
        r.run(Job::Revert { txn, nonce });
        assert!(
            r.snap() == before,
            "the game folder is bit-identical after the undo ({lang:?})"
        );
        // Rerun's own package folder keeps the package (it is not the game).
        assert_eq!(r.listed("packages"), Some(vec!["fix-pack".to_owned()]));
    }
}

#[test]
fn ad2_progress_names_every_state_in_order() {
    let mut r = DRig::new(Lang::En, |a| FakeReply::ok(a).chunked(16 * 1024));
    r.page();
    let d = r.ask();
    let ev = r.run(Job::Download { nonce: d.nonce });
    let states: Vec<PackageState> = dialogs(&ev)
        .iter()
        .map(|d| {
            assert_eq!(d.stage, DownloadStage::Progress);
            // No confirm while it runs; the cancel button is there.
            assert!(d.confirm.is_none());
            assert_eq!(d.cancel, t(Lang::En, Msg::DlBtnCancel));
            // The state word of the one package.
            let status = d.packages[0]
                .lines
                .iter()
                .find(|l| l.label == t(Lang::En, Msg::DlLblStatus))
                .map(|l| l.values[0].as_str().to_owned())
                .unwrap();
            let size = d.packages[0]
                .lines
                .iter()
                .find(|l| l.label == t(Lang::En, Msg::DlLblSize))
                .map(|l| l.values[0].as_str().to_owned());
            match status.as_str() {
                s if s == t(Lang::En, Msg::DlStWaiting) => PackageState::Waiting,
                s if s == t(Lang::En, Msg::DlStDownloading) => {
                    // The size line says how far and of how much (the archive's length).
                    let size = size.expect("a size while it downloads");
                    assert!(size.contains(" of "), "{size}");
                    PackageState::Reading {
                        read: 0,
                        announced: None,
                    }
                }
                s if s == t(Lang::En, Msg::DlStUnpacking) => PackageState::Unpacking,
                s if s == t(Lang::En, Msg::DlStDone) => PackageState::Done,
                other => panic!("{other}"),
            }
        })
        .collect();
    // Waiting first, bodies, unpacking, done last.
    assert_eq!(states.first(), Some(&PackageState::Waiting));
    assert_eq!(states.last(), Some(&PackageState::Done));
    let kinds: Vec<u8> = states
        .iter()
        .map(|s| match s {
            PackageState::Waiting => 0,
            PackageState::Reading { .. } => 1,
            PackageState::Unpacking => 2,
            PackageState::Done => 3,
            _ => 9,
        })
        .collect();
    assert!(kinds.windows(2).all(|w| w[0] <= w[1]), "{kinds:?}");
    assert!(kinds.contains(&1) && kinds.contains(&2), "{kinds:?}");
    // The last event of the job is the end, then the fresh page.
    let tail: Vec<&str> = kinds_of(&ev);
    assert_eq!(&tail[tail.len() - 2..], ["game", "download-ended"]);
}

fn kinds_of(ev: &[Event]) -> Vec<&'static str> {
    super::kinds(ev)
}

#[test]
fn ad3_a_cancel_in_the_middle_leaves_nothing_and_a_second_try_works() {
    let trip = Trip::new();
    let mut r = DRig::new(Lang::En, |a| {
        FakeReply::ok(a)
            .chunked(16 * 1024)
            .trip_after(100 * 1024, &trip)
    });
    r.page();
    let before = r.snap();
    let d = r.ask();
    // The user's cancel is the session's flag.
    r.session.cancel = trip.shared();
    let ev = r.run(Job::Download { nonce: d.nonce });
    // `run` reset the flag as `send` does; the body sets it in the middle, so it ended there.
    assert_eq!(ended(&ev), Some(DownloadOutcome::Cancelled), "{ev:?}");
    // A calm banner says so; the page is read again (the fix still needs its download).
    let banner = ev
        .iter()
        .find_map(|e| match e {
            Event::Result(r) => Some(r),
            _ => None,
        })
        .expect("a notice");
    assert_eq!(banner.notice.title, t(Lang::En, Msg::DlCancelledTitle));
    assert_eq!(banner.tone, crate::vm::Tone::Calm);
    let page = game_in(&ev);
    assert_eq!(
        ev.last(),
        Some(&Event::DownloadEnded(DownloadOutcome::Cancelled))
    );
    assert_eq!(page.fixes[0].offer, Offer::NeedsDownload);
    // Nothing in the cache (no archive, no temp file), nothing unpacked, the game untouched.
    assert_eq!(r.listed("cache"), Some(Vec::new()));
    assert_eq!(r.listed("packages"), None);
    assert!(r.snap() == before);
    // The cancel was shown as progress first: the last dialog before the end says Downloading.
    assert!(
        dialogs(&ev)
            .iter()
            .any(|d| d.packages[0]
                .lines
                .iter()
                .any(|l| l.label == t(Lang::En, Msg::DlLblSize)
                    && l.values[0].as_str().contains(" of "))),
        "it was in the middle of the body"
    );

    // Again, not cancelled: whole, and the fix is selectable.
    r.http.reply(STORE, FakeReply::ok(&r.archive.clone()));
    r.session.cancel = Default::default();
    let d = r.ask();
    let ev = r.run(Job::Download { nonce: d.nonce });
    assert_eq!(ended(&ev), Some(DownloadOutcome::Done), "{ev:?}");
    assert_eq!(
        r.listed("cache"),
        Some(vec![upper(&r.archive).to_ascii_lowercase()])
    );
}

#[test]
fn ad4_a_failure_is_a_dialog_with_try_again_and_keeps_nothing() {
    for lang in Lang::ALL {
        // A wrong hash: another archive under the pinned URL.
        let mut r = DRig::new(lang, |_| FakeReply::ok(b"PK another archive"));
        r.page();
        let d = r.ask();
        let ev = r.run(Job::Download { nonce: d.nonce });
        assert_eq!(ended(&ev), Some(DownloadOutcome::Failed), "{ev:?}");
        let f = *dialogs(&ev).last().unwrap();
        assert_eq!(f.stage, DownloadStage::Failed);
        assert_eq!(f.title, t(lang, Msg::DlFailedTitle));
        assert_eq!(f.intro, t(lang, Msg::DlErrHash));
        // A wrong hash does not pass: no "Try again" and no consent kept.
        assert_eq!(f.confirm, None);
        // The same list is still shown, and the core's text is the detail.
        assert_eq!(f.packages.len(), 1);
        assert!(!f.details.is_empty());
        assert_eq!(r.listed("cache"), Some(Vec::new()), "{lang:?}");
        assert_eq!(r.listed("packages"), None);
        let good = r.archive.clone();
        r.http.reply(STORE, FakeReply::ok(&good));
        let ev = r.run(Job::Download { nonce: f.nonce });
        assert_eq!(
            ended(&ev),
            Some(DownloadOutcome::Refused),
            "no list is kept"
        );

        // A redirect to a foreign host is never followed.
        let mut r = DRig::new(lang, FakeReply::ok);
        r.http.reply(
            ASSET,
            FakeReply::redirect(302, "https://evil.example/fix-pack.zip"),
        );
        r.page();
        let d = r.ask();
        let ev = r.run(Job::Download { nonce: d.nonce });
        let f = *dialogs(&ev).last().unwrap();
        assert_eq!(f.intro, t(lang, Msg::DlErrRedirect));
        assert_eq!(
            r.http.requests(),
            [ASSET],
            "the foreign host is never asked"
        );
        assert_eq!(r.listed("cache"), Some(Vec::new()));

        // Offline: nobody answers.
        let mut r = DRig::new(lang, FakeReply::ok);
        r.http = FakeHttp::default();
        r.page();
        let d = r.ask();
        let ev = r.run(Job::Download { nonce: d.nonce });
        assert_eq!(ended(&ev), Some(DownloadOutcome::Failed));
        let f = *dialogs(&ev).last().unwrap();
        assert_eq!(f.intro, t(lang, Msg::DlErrOffline));
        assert!(f.confirm.is_some(), "offline can be tried again");
        // The network is back: try again.
        r.http = github(FakeReply::ok(&r.archive.clone()));
        let ev = r.run(Job::Download { nonce: f.nonce });
        assert_eq!(ended(&ev), Some(DownloadOutcome::Done), "{ev:?}");
    }
}

#[test]
fn ad4_a_package_changed_since_the_consent_is_refused_before_any_request() {
    let mut r = DRig::new(Lang::En, FakeReply::ok);
    r.page();
    let d = r.ask();
    // The index moves on: another archive (another pinned hash) for the same package.
    let other = zip(&[
        ZipEntry::file("bin/fix.dll", DLL),
        ZipEntry::file("fix.ini", INI),
    ]);
    import(
        &r.sys,
        &pkg_index(&other, &sha256_of(&r.sys, "game.exe"), 2),
    );
    let ev = r.run(Job::Download { nonce: d.nonce });
    assert_eq!(ended(&ev), Some(DownloadOutcome::Failed), "{ev:?}");
    let f = *dialogs(&ev).last().unwrap();
    assert_eq!(f.intro, t(Lang::En, Msg::DlErrChanged));
    assert!(f.confirm.is_none(), "trying again cannot help");
    assert!(r.http.requests().is_empty(), "nothing was asked for");
    assert_eq!(r.listed("cache"), None);
    // The page is read again: it offers the fix with its new list.
    assert!(
        matches!(ev.iter().rev().nth(1), Some(Event::Game(_))),
        "{ev:?}"
    );
}

#[test]
fn ad4_a_package_that_is_in_place_is_selectable_and_asks_nothing() {
    let mut r = DRig::new(Lang::En, FakeReply::ok);
    r.page();
    let d = r.ask();
    r.run(Job::Download { nonce: d.nonce });
    // A fresh session (the next app start): the package is unpacked, the fix selectable.
    r.session = Session::default();
    let page = r.page();
    assert_eq!(page.fixes[0].offer, Offer::Selectable);
    // A confirm that arrives for a fix that needs nothing asks for nothing.
    let ev = r.run(Job::DownloadAsk {
        app_id: 220,
        variant: "fix-pack".to_owned(),
    });
    assert!(
        matches!(ev.as_slice(), [Event::Result(_)]) && dialogs(&ev).is_empty(),
        "{ev:?}"
    );
}

/// AD5: on the worker thread a download counts from `send` to its end, a cancel from the window
/// stops it at the next read, and the end is reported.
#[test]
fn ad5_the_worker_counts_a_download_and_a_cancel_ends_it() {
    let make = |_| {
        let archive = archive();
        let sys = steam_world("Invented P");
        import(&sys, &pkg_index(&archive, &sha256_of(&sys, "game.exe"), 1));
        Ok(World {
            sys: Box::new(sys),
            http: Box::new(github(
                FakeReply::ok(&archive)
                    .chunked(16 * 1024)
                    .paced(std::time::Duration::from_millis(20)),
            )),
            install: install(),
        })
    };
    let woken = Arc::new(AtomicUsize::new(0));
    let worker = Worker::start(Lang::En, make, Box::new(Count(woken))).unwrap();
    worker.set_owner(None);
    assert!(!worker.downloading());
    worker.send(Job::Game {
        app_id: 220,
        name: None,
    });
    worker.send(Job::DownloadAsk {
        app_id: 220,
        variant: "fix-pack".to_owned(),
    });
    let ev = wait_for(&worker, 2);
    let nonce = match &ev[1] {
        Event::Download(d) => d.nonce,
        other => panic!("{other:?}"),
    };
    worker.send(Job::Download { nonce });
    // Counted from the send, before the thread picks it up.
    assert!(worker.downloading());
    // Wait for a body in flight, then cancel as the window's button (or its close) does.
    let mut seen = Vec::new();
    for _ in 0..2000 {
        while let Some(e) = worker.poll() {
            seen.push(e);
        }
        if seen.iter().any(|e| match e {
            Event::Download(d) => d.packages[0].lines.iter().any(|l| {
                l.label == t(Lang::En, Msg::DlLblSize) && l.values[0].as_str().contains(" of ")
            }),
            _ => false,
        }) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    worker.cancel_download();
    let mut ended = None;
    for _ in 0..2000 {
        while let Some(e) = worker.poll() {
            if let Event::DownloadEnded(o) = e {
                ended = Some(o);
            }
        }
        if ended.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(ended, Some(DownloadOutcome::Cancelled));
    // The count ends with the job (a moment after its last event).
    for _ in 0..2000 {
        if !worker.downloading() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("the download never stopped counting");
}

fn game_in(ev: &[Event]) -> &GameVm {
    ev.iter()
        .find_map(|e| match e {
            Event::Game(g) => Some(g),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no game page in {ev:?}"))
}

/// A second package for AD6.
const DLL2: &[u8] = b"the second dll";

/// A fix with two packages: `fix-pack` and `fix-two`.
fn two_index(a1: &[u8], a2: &[u8], game_sha: &str) -> String {
    let one = pkg_index(a1, game_sha, 1);
    let steps_old = r#""steps":[{"package":"fix-pack"}]"#;
    let steps_new = r#""steps":[{"package":"fix-pack"},{"package":"fix-two"}]"#;
    let two = format!(
        r#",{{"format":1,"id":"fix-two","name":"Fix two","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-two","release":"https://github.com/owner/fix-two/releases/download/v1.0/fix-two.zip"}},"version":"1.0","sha256":"{a}","license":"MIT","arch":["x86"],"slots":["two.dll"],"files":[{{"from":"two.dll","to":"two.dll","sha256":"{d}"}}]}}]}}"#,
        a = upper(a2),
        d = upper(DLL2),
    );
    let mut s = one.replace(steps_old, steps_new);
    assert!(s.ends_with("}]}"), "{s}");
    s.truncate(s.len() - 2);
    s.push_str(&two);
    s
}

const ASSET2: &str = "https://github.com/owner/fix-two/releases/download/v1.0/fix-two.zip";
const STORE2: &str =
    "https://release-assets.githubusercontent.com/github-production-release-asset/1/9?sp=r";

/// AD6: a fix with two packages: both are listed, the progress follows the first (done) and the
/// second; a connection that breaks in the second is a failure dialog that marks it failed and
/// the first done, offers "Try again" (a passing failure), and the retry takes the first from the
/// cache and finishes; the fix is selectable then.
#[test]
fn ad6_a_fix_with_two_packages_fails_on_the_second_and_retries() {
    let a1 = archive();
    let a2 = zip(&[ZipEntry::file("two.dll", DLL2)]);
    let sys = steam_world("Invented P");
    import(&sys, &two_index(&a1, &a2, &sha256_of(&sys, "game.exe")));
    let http = github(FakeReply::ok(&a1));
    let mut cut = FakeReply::ok(&a2);
    cut.cut_after = Some(10);
    http.reply(ASSET2, FakeReply::redirect(302, STORE2));
    http.reply(STORE2, cut);
    let mut r = DRig {
        sys,
        http,
        session: Session::default(),
        lang: Lang::En,
        archive: a1,
    };
    r.page();
    let d = r.ask();
    assert_eq!(d.packages.len(), 2);
    assert_eq!(d.packages[1].target.as_str(), "Fix two 1.0");
    let ev = r.run(Job::Download { nonce: d.nonce });
    assert_eq!(ended(&ev), Some(DownloadOutcome::Failed), "{ev:?}");
    let status = |d: &DownloadVm, i: usize| {
        d.packages[i]
            .lines
            .iter()
            .find(|l| l.label == t(Lang::En, Msg::DlLblStatus))
            .map(|l| l.values[0].as_str().to_owned())
            .unwrap()
    };
    // Progress saw the first done while the second was waiting.
    assert!(dialogs(&ev).iter().any(|d| {
        d.stage == DownloadStage::Progress
            && status(d, 0) == t(Lang::En, Msg::DlStDone)
            && status(d, 1) == t(Lang::En, Msg::DlStWaiting)
    }));
    let f = *dialogs(&ev).last().unwrap();
    assert_eq!(f.stage, DownloadStage::Failed);
    assert_eq!(status(f, 0), t(Lang::En, Msg::DlStDone));
    assert_eq!(status(f, 1), t(Lang::En, Msg::DlStFailed));
    assert_eq!(f.intro, t(Lang::En, Msg::DlErrInterrupted));
    assert!(f.confirm.is_some(), "a cut connection can be tried again");
    // The first package is in place, the second left nothing.
    assert_eq!(r.listed("packages"), Some(vec!["fix-pack".to_owned()]));
    // Retry with a working connection: the first is a cache hit.
    r.http.reply(STORE2, FakeReply::ok(&a2));
    r.http.clear_requests();
    let ev = r.run(Job::Download { nonce: f.nonce });
    assert_eq!(ended(&ev), Some(DownloadOutcome::Done), "{ev:?}");
    assert_eq!(r.http.requests(), [ASSET2, STORE2], "the first is cached");
    assert_eq!(game_in(&ev).fixes[0].offer, Offer::Selectable);
}
