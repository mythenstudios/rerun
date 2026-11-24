//! Start-time guard (P5-5 preparation): the window with its six embedded fonts is created,
//! shown and drawn once, headless through Slint's software renderer (no winit window, no
//! system access beyond reading the installed fonts). It measured about 5 ms to the first frame
//! and about 25 ms with a library page of mixed scripts (Latin, CJK, Cyrillic, Hangul, symbols,
//! which also takes the system font fallback), in a `ci` build on the developer machine, with
//! or without the fonts within 12 ms of each other. The bound is generous (the user's report of
//! 1.6 s to the first window was never in this part): it catches a font registration or a
//! fallback that starts to scan the system fonts or to shape everything again. The dialogs of
//! the download (P5-5b) and the wait for the UAC dialog (P5-5c) are drawn too.

use std::rc::Rc;
use std::time::{Duration, Instant};

use slint::ComponentHandle as _;
use slint::Model as _;
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
use slint::platform::{Platform, WindowAdapter};

use super::download::download_data;
use super::store_data;
use super::write::dialog_data;
use super::write::uac_data;
use super::{
    AppWindow, BadgeData, RowData, SectionData, ThemeChoice, model, set_strings, set_theme, theme,
};
use crate::text::Lang;
use crate::vm::{Names, PackageState, consent, failed, progress, store, store_dialog, uac_wait};
use rerun_core::catalog::model::Tier;
use rerun_core::elevate::{PromptKind, PromptState};
use rerun_core::flow::{DownloadNeed, FetchError, NeedState, PackageNeed};
use rerun_core::flow::{RemovePreview, StoreView, StoredPackage, StoredState};

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
    set_theme(&ui, &theme::tokens(ThemeChoice::default()));
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
    let failed_pic = picture();
    assert_ne!(
        failed_pic, progress_pic,
        "failure looks other than progress"
    );
    // The wait for the UAC dialog (P5-5c): the same dialog without any button.
    let state = PromptState {
        kind: PromptKind::Credentials,
        secure_desktop: Some(false),
        signed_only: false,
    };
    ui.set_dialog(uac_data(&uac_wait(&state, Lang::De)));
    assert!(draw(), "the wait for Windows is drawn");
    let d = ui.get_dialog();
    assert!(d.kind == 3 && d.no_confirm && d.no_cancel);
    assert_eq!(d.title, "Warte auf Windows-Bestätigung (UAC) ...");
    assert_eq!(
        d.notes.row_count(),
        3,
        "credentials, not secure, the taskbar"
    );
    assert_ne!(picture(), failed_pic, "the wait looks other than a failure");
    // The packages group of the settings and its removal dialog (P5-8b-3): a package row, the
    // folded list of its files, and the open list.
    ui.set_dialog_open(false);
    let pkg = StoredPackage {
        id: "fix-pack".to_owned(),
        version: "1.0".to_owned(),
        name: Some("Fix pack".to_owned()),
        in_index: true,
        state: StoredState::Unpacked,
        files: 1,
        paths: vec!["fix.dll".to_owned()],
        bytes: 1_500_000,
        archives: vec!["ab".repeat(32)],
        used_by: Vec::new(),
        keep: None,
    };
    let view = StoreView {
        packages: vec![pkg.clone()],
        loose_archives: Vec::new(),
        leftovers: (0, 0),
        foreign: Vec::new(),
    };
    ui.set_page(4);
    assert!(draw(), "the settings page is drawn");
    let settings_before = picture();
    ui.set_store(store_data(&store(&view, &Names::new(), Lang::De)));
    assert!(draw(), "the packages group is drawn");
    assert_eq!(ui.get_store().rows.row_count(), 1);
    let row = ui.get_store().rows.row_data(0).unwrap();
    assert_eq!(
        (row.title.as_str(), row.remove_label.as_str()),
        ("Fix pack", "Entfernen\u{2026}")
    );
    assert!(row.can_remove);
    assert_ne!(
        picture(),
        settings_before,
        "the packages change the settings page"
    );
    let preview = RemovePreview {
        remove: vec![pkg],
        loose_archives: Vec::new(),
        leftovers: (0, 0),
        stays: Vec::new(),
        bytes: 1_500_000,
    };
    ui.set_dialog(dialog_data(&store_dialog(
        &preview,
        &Names::new(),
        false,
        1,
        Lang::De,
    )));
    ui.set_dialog_open(true);
    assert!(draw(), "the removal dialog is drawn");
    let d = ui.get_dialog();
    assert_eq!(d.kind, 6);
    assert!(d.can_confirm && !d.no_confirm);
    assert_eq!(d.lists.row_count(), 2, "the packages and the folded files");
    let files = d.lists.row_data(1).unwrap();
    assert!(!files.show.is_empty() && !files.hide.is_empty());
    assert_eq!(files.lines.row_count(), 2, "the file and the archive");
    ui.set_dialog_open(false);
    ui.set_page(0);
    eprintln!(
        "headless start: window created {created:?}, first frame {first:?}, with 60 rows {with_rows:?}"
    );
    assert!(created < Duration::from_millis(500), "{created:?}");
    assert!(first < Duration::from_millis(750), "{first:?}");
    assert!(with_rows < Duration::from_secs(1), "{with_rows:?}");
}

/// The window and the Rust side agree on where the focus goes back to after the clear dialog
/// (N12): the button of the history page takes it when `Modal.return-to` is `CLEAR_OPENER`, which
/// is what `st.opener` is while that dialog is open.
#[test]
fn the_clear_button_takes_the_focus_back() {
    let slint = include_str!("../../ui/app.slint");
    let want = format!(
        "take-focus: Modal.return-to == {};",
        super::write::CLEAR_OPENER
    );
    assert_eq!(slint.matches(&want).count(), 1, "{want}");
}

/// The window and the Rust side agree on where the focus goes back to after a removal dialog: the
/// button that opened it takes it when `Modal.return-to` is what `st.opener` was, and no two
/// openers share a value.
#[test]
fn the_packages_buttons_take_the_focus_back() {
    use super::write::{CLEAR_OPENER, STORE_ALL_OPENER, STORE_ROW_OPENER};
    let slint = include_str!("../../ui/app.slint");
    let all = format!("take-focus: Modal.return-to == {STORE_ALL_OPENER};");
    assert_eq!(slint.matches(&all).count(), 1, "{all}");
    let row = format!("take-focus: Modal.return-to == {STORE_ROW_OPENER} - root.index;");
    assert_eq!(slint.matches(&row).count(), 1, "{row}");
    const { assert!(STORE_ALL_OPENER != CLEAR_OPENER && STORE_ROW_OPENER < STORE_ALL_OPENER) };
}
