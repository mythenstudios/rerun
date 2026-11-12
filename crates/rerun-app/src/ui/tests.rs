//! Start-time guard (P5-5 preparation): the window with its six embedded fonts is created,
//! shown and drawn once, headless through Slint's software renderer (no winit window, no
//! system access beyond reading the installed fonts). It measured about 5 ms to the first frame
//! and about 25 ms with a library page of mixed scripts (Latin, CJK, Cyrillic, Hangul, symbols,
//! which also takes the system font fallback), in a `ci` build on the developer machine, with
//! or without the fonts within 12 ms of each other. The bound is generous (the user's report of
//! 1.6 s to the first window was never in this part): it catches a font registration or a
//! fallback that starts to scan the system fonts or to shape everything again.

use std::rc::Rc;
use std::time::{Duration, Instant};

use slint::ComponentHandle as _;
use slint::Model as _;
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
use slint::platform::{Platform, WindowAdapter};

use super::download::download_data;
use super::{
    AppWindow, BadgeData, RowData, SectionData, ThemeId, model, set_strings, set_theme, theme,
};
use crate::text::Lang;
use crate::vm::{PackageState, consent, failed, progress};
use rerun_core::catalog::model::Tier;
use rerun_core::flow::{DownloadNeed, FetchError, NeedState, PackageNeed};

struct Headless(Rc<MinimalSoftwareWindow>);

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

const WIDTH: u32 = 1280;
const HEIGHT: u32 = 800;

/// The library page with names of several scripts and every status symbol.
fn rows() -> Vec<RowData> {
    let names = [
        "Mafia II",
        "ゲーム 日本語",
        "Игра Кириллица",
        "Game™ ® – “quoted”",
        "한국어 게임",
        "Ünïcödé Ångström",
    ];
    let symbols = ["■", "□", "◆", "—"];
    (0..60usize)
        .map(|i| RowData {
            app_id: i32::try_from(i).unwrap_or(0),
            name: names[i % names.len()].into(),
            detail: "C:/Games/Alpha — 1.2 GB".into(),
            exe: "game.exe".into(),
            badge: BadgeData {
                sym: symbols[i % symbols.len()].into(),
                word: "applied".into(),
                quiet: false,
            },
        })
        .collect()
}

/// The only test that installs a Slint platform: the platform is one per process.
#[test]
fn the_window_draws_its_first_frames_fast() {
    let start = Instant::now();
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(Headless(window.clone()))).unwrap();
    let ui = AppWindow::new().unwrap();
    let created = start.elapsed();
    set_theme(&ui, &theme::tokens(ThemeId::default()));
    set_strings(&ui, Lang::En);
    window.set_size(slint::PhysicalSize::new(WIDTH, HEIGHT));
    ui.show().unwrap();
    let buf = std::cell::RefCell::new(vec![Rgb565Pixel(0); (WIDTH * HEIGHT) as usize]);
    let draw = || {
        let mut drawn = false;
        window.draw_if_needed(|r| {
            r.render(&mut buf.borrow_mut(), WIDTH as usize);
            drawn = true;
        });
        drawn
    };
    assert!(draw(), "the first frame is drawn");
    let first = start.elapsed();
    ui.set_sections(model(vec![SectionData {
        title: "Section".into(),
        rows: model(rows()),
    }]));
    assert!(draw(), "the page with rows is drawn");
    let with_rows = start.elapsed();
    // The download dialogs (P5-5b) draw in the one dialog: consent, progress (no confirm button,
    // a cancel that waits), failure.
    let need = PackageNeed {
        id: "fix-pack".to_owned(),
        name: "Fix pack".to_owned(),
        version: "1.0".to_owned(),
        license: "MIT".to_owned(),
        tier: Tier::Established,
        repo: Some("https://github.com/owner/fix-pack".to_owned()),
        page: None,
        downloads: vec![DownloadNeed {
            arch: None,
            url: "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip".to_owned(),
            host: "github.com".to_owned(),
            sha256: "ab".repeat(32),
        }],
        state: NeedState::Missing,
    };
    let needs = [need];
    // What the window drew, as one number: a binding that is wrong draws another picture.
    let picture = || {
        buf.borrow().iter().fold(0u64, |a, p| {
            a.wrapping_mul(1_000_003).wrapping_add(u64::from(p.0))
        })
    };
    let closed = picture();
    ui.set_dialog(download_data(&consent(1, "fix-pack", &needs, 1, Lang::De)));
    ui.set_dialog_open(true);
    assert!(draw(), "the consent dialog is drawn");
    let d = ui.get_dialog();
    assert_eq!(d.kind, 2);
    assert!(!d.no_confirm && d.can_confirm && d.confirm == "Herunterladen");
    assert_eq!(d.ops.row_count(), 1);
    let consent_pic = picture();
    assert_ne!(consent_pic, closed, "the open dialog changes the picture");
    let reading = [PackageState::Reading {
        read: 1_300_000,
        announced: Some(3_250_000),
    }];
    ui.set_dialog(download_data(&progress(
        1,
        "fix-pack",
        &needs,
        &reading,
        1,
        true,
        Lang::En,
    )));
    assert!(draw(), "the progress dialog is drawn");
    let d = ui.get_dialog();
    assert!(d.no_confirm && d.cancel_disabled && d.cancel_label == "Cancelling ...");
    let progress_pic = picture();
    assert_ne!(
        progress_pic, consent_pic,
        "progress looks other than consent"
    );
    ui.set_dialog(download_data(&failed(
        1,
        "fix-pack",
        &needs,
        &reading,
        &FetchError::NoIndex,
        2,
        Lang::En,
    )));
    assert!(draw(), "the failure dialog is drawn");
    let d = ui.get_dialog();
    assert!(d.no_confirm && !d.cancel_disabled, "no retry for NoIndex");
    assert_ne!(picture(), progress_pic, "failure looks other than progress");
    ui.set_dialog_open(false);
    eprintln!(
        "headless start: window created {created:?}, first frame {first:?}, with 60 rows {with_rows:?}"
    );
    assert!(created < Duration::from_millis(500), "{created:?}");
    assert!(first < Duration::from_millis(750), "{first:?}");
    assert!(with_rows < Duration::from_secs(1), "{with_rows:?}");
}
