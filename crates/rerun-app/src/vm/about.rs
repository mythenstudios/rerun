//! Settings > About Rerun (P5-10e, ADR 0026: the Appropriate Legal Notices of GPL-3.0): name,
//! version, build ID, copyright, the GPL notice with its "no warranty", the links to the source
//! code of this build and to the repository (shown as text next to their buttons; opened
//! through the core's `OwnLink`, never a URL from the window) and the third-party licences.
//! Framework free.

use rerun_core::policy::open::{OpenUrl, OwnLink};

use crate::text::{Lang, Msg, t};

/// About Rerun.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AboutVm {
    /// "Rerun · by Mythen Studios 0.1.0".
    pub version: String,
    /// The copyright line.
    pub copyright: String,
    /// `rerun_core::BUILD_ID`: the version and the commit (or the dev hash).
    pub build: String,
    /// The GPL notice.
    pub licence: String,
    /// The source code of this build, as the core opens it.
    pub source_url: String,
    /// The repository, as the core opens it.
    pub repo_url: String,
}

/// About Rerun in `lang`.
pub fn about(lang: Lang) -> AboutVm {
    AboutVm {
        version: format!(
            "{} {}",
            t(lang, Msg::AboutVersion),
            env!("CARGO_PKG_VERSION")
        ),
        copyright: t(lang, Msg::AboutCopyright).into_owned(),
        build: rerun_core::BUILD_ID.to_owned(),
        licence: t(lang, Msg::AboutGpl).into_owned(),
        source_url: OpenUrl::own(OwnLink::SourceOfThisBuild).as_str().to_owned(),
        repo_url: OpenUrl::own(OwnLink::Repository).as_str().to_owned(),
    }
}
