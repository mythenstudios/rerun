//! Links, "report a problem" and Rerun's folder (P5-10a, ADR 0027 amendment P5-10a): the report
//! dialog with exactly the text of the issue, what a refused or failed open says, and Settings >
//! Data. Framework free.

use rerun_core::escape::{self, Shown};
use rerun_core::flow::{DataFolder, OpenError, Report};
use rerun_core::policy::open::OpenRefusal;
use rerun_core::policy::root::RootError;

use super::write::{DialogKind, DialogVm, ResultVm, Tone, result, with_detail};
use super::{DetailVm, shown_error};
use crate::text::{Lang, Msg, t};

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// The report dialog (E4 a): what happens, then the issue's title and every line of its text,
/// each in its own monospaced element, exactly as the URL carries them; "Open in browser".
pub fn report_dialog(r: &Report, nonce: u64, lang: Lang) -> DialogVm {
    let label = |m| Some(escape::text(&tx(lang, m)).into_owned());
    let mut details = vec![DetailVm {
        who: label(Msg::ReportLabelTitle),
        what: escape::text(&r.title).into_owned(),
    }];
    // One element per line (a line break is a control character, the text rule would quote
    // it); the first carries the label. A final line break makes no element of its own.
    let body = r.body.strip_suffix('\n').unwrap_or(&r.body);
    details.extend(body.split('\n').enumerate().map(|(i, l)| DetailVm {
        who: if i == 0 {
            label(Msg::ReportLabelText)
        } else {
            None
        },
        what: escape::text(l).into_owned(),
    }));
    DialogVm {
        kind: DialogKind::Report,
        nonce,
        txn: None,
        title: tx(lang, Msg::ReportTitle),
        intro: tx(lang, Msg::ReportIntro),
        changed: None,
        ops: Vec::new(),
        notes: vec![tx(lang, Msg::ReportWhere)],
        details,
        launch: None,
        confirm: tx(lang, Msg::OpenInBrowser),
        can_confirm: true,
        blocked: None,
        secondary: None,
        lists: Vec::new(),
    }
}

/// Why a link or the folder was not opened, as a calm result (nothing changed).
pub fn open_failed(e: &OpenError, lang: Lang) -> ResultVm {
    let calm = |body| result(Tone::Calm, lang, Msg::OpenFailedTitle, body, false);
    match e {
        OpenError::Refused(OpenRefusal::NotInIndex | OpenRefusal::NoIndex) => {
            calm(Msg::OpenNotInIndex)
        }
        OpenError::Refused(OpenRefusal::NoAppDir) => calm(Msg::OpenNoFolder),
        OpenError::Refused(_) => calm(Msg::OpenRefusedForm),
        OpenError::Shell(err) => with_detail(
            result(
                Tone::Attention,
                lang,
                Msg::OpenFailedTitle,
                Msg::OpenShellFailed,
                false,
            ),
            shown_error(err),
        ),
    }
}

/// A confirm of a report dialog that is not the one the worker last showed: nothing opened.
pub fn open_stale(lang: Lang) -> ResultVm {
    result(
        Tone::Calm,
        lang,
        Msg::OpenFailedTitle,
        Msg::OpenStale,
        false,
    )
}

/// Settings > Data: Rerun's folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataVm {
    /// The path (escaped), if it can be told.
    pub path: Option<Shown<'static>>,
    /// It exists: "Open in Explorer" is offered.
    pub exists: bool,
    /// Under the path: not created yet, or why the path cannot be told.
    pub note: Option<String>,
    /// The core's text when the path cannot be told (escaped).
    pub detail: Option<Shown<'static>>,
}

/// Settings > Data from the core's answer.
pub fn data_folder(d: &Result<DataFolder, RootError>, lang: Lang) -> DataVm {
    match d {
        Ok(d) => DataVm {
            path: Some(escape::path(&d.path.to_string()).into_owned()),
            exists: d.exists,
            note: (!d.exists).then(|| tx(lang, Msg::DataNotCreated)),
            detail: None,
        },
        Err(e) => DataVm {
            path: None,
            exists: false,
            note: Some(tx(lang, Msg::DataUnknown)),
            detail: Some(shown_error(e)),
        },
    }
}
