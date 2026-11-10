//! The phase 2 step file (ADR 0020, user decision D7; P2-13): the input of
//! `rerun plan <steps.json>`. Since the Topo engine (P4-4) the local, unsigned input for tests,
//! the Sandbox and experts (L8): its plans carry no `PlanSource`, so they never reach the
//! elevated helper. Removed at the earliest before A6.
//!
//! `{"format":1,"game":{"steam":440},"main_exe":"bin\\game.exe","steps":[{"ini_set":{…}}]}`
//! (or `"game":{"folder":"D:\\Games\\X"}` for a folder the user names). Untrusted input: at
//! most [`MAX_STEP_FILE`] bytes, the format first, then a strict parse (`deny_unknown_fields`
//! everywhere; paths through `RelPath` and `RootPath`, every step through its spec type).
//! `main_exe` is required (user decision E4 a): every plan names the program `users()` asks
//! before apply and revert. An error names its class, line and column, never the input text
//! (serde's own messages can quote it).
//!
//! P4-12: an optional `"user_data":{"documents":"My Games\X"}` names the game's folder below
//! the user's `Documents`, for a step with `"root":"user_data"` (the folder is opened only then;
//! such a step without it is refused by the planner).

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{Step, UserDataSpec};
use crate::path::{RelPath, RootPath};
use crate::plan::PlanError;

/// Most bytes of a step file.
pub const MAX_STEP_FILE: u64 = 1 << 20;

/// The one step file format.
pub const STEP_FILE_FORMAT: u32 = 1;

/// A step file (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepFile {
    /// [`STEP_FILE_FORMAT`].
    pub format: u32,
    /// The game folder the steps are planned for.
    pub game: GameRef,
    /// The game's main executable below the game folder.
    pub main_exe: RelPath,
    /// The game's folder below a known folder of the user (P4-12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<UserDataSpec>,
    /// The steps, in order.
    pub steps: Vec<Step>,
}

/// Which game folder a step file names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GameRef {
    /// The installed Steam app with this ID (found in exactly one library).
    Steam(u32),
    /// A folder the user names (opened like a manually added game folder).
    Folder(RootPath),
}

/// Why a step file was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StepFileError {
    /// Another format.
    #[error("step file format {0} is not supported (only {STEP_FILE_FORMAT})")]
    Format(u32),
    /// More bytes than [`MAX_STEP_FILE`].
    #[error("the step file is larger than {MAX_STEP_FILE} bytes")]
    TooLarge,
    /// A step that only a Topo of the signed index may carry (P4-10: `laa_patch`, whose
    /// executable and hash come from the Topo's `match.exes`).
    #[error("the step {0} comes only from a Topo of the signed index, not from a step file")]
    TopoOnly(&'static str),
    /// Not a step file: where and what kind of problem, never the text.
    #[error("the step file is not valid at line {line}, column {column}: {class}")]
    Parse {
        /// The kind of problem.
        class: ParseClass,
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
}

/// The kind of a parse problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseClass {
    /// Not JSON.
    Syntax,
    /// The text ends too early.
    Eof,
    /// JSON, but a field is unknown, missing or of the wrong form.
    Data,
}

impl fmt::Display for ParseClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Syntax => "not valid JSON",
            Self::Eof => "the text ends too early",
            Self::Data => "a field is unknown, missing or not of its form",
        })
    }
}

fn parse_error(e: &serde_json::Error) -> StepFileError {
    let class = match e.classify() {
        serde_json::error::Category::Syntax | serde_json::error::Category::Io => ParseClass::Syntax,
        serde_json::error::Category::Eof => ParseClass::Eof,
        serde_json::error::Category::Data => ParseClass::Data,
    };
    StepFileError::Parse {
        class,
        line: e.line(),
        column: e.column(),
    }
}

impl StepFile {
    /// Parses a step file (module docs).
    pub fn parse(b: &[u8]) -> Result<Self, PlanError> {
        if u64::try_from(b.len()).map_or(true, |n| n > MAX_STEP_FILE) {
            return Err(StepFileError::TooLarge.into());
        }
        #[derive(Deserialize)]
        struct Probe {
            format: u32,
        }
        let probe: Probe = serde_json::from_slice(b).map_err(|e| parse_error(&e))?;
        if probe.format != STEP_FILE_FORMAT {
            return Err(StepFileError::Format(probe.format).into());
        }
        let f: Self = serde_json::from_slice(b).map_err(|e| parse_error(&e))?;
        if f.steps.iter().any(|s| matches!(s, Step::LaaPatch(_))) {
            return Err(StepFileError::TopoOnly("laa_patch").into());
        }
        Ok(f)
    }
}

#[cfg(test)]
mod tests {
    use super::{GameRef, MAX_STEP_FILE, ParseClass, StepFile, StepFileError};
    use crate::plan::PlanError;
    use crate::prim::Step;

    const OK: &str = r#"{"format":1,"game":{"steam":440},"main_exe":"bin\\game.exe","steps":[{"ini_set":{"file":"game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}]}"#;

    fn err(s: &str) -> StepFileError {
        match StepFile::parse(s.as_bytes()) {
            Err(PlanError::StepFile(e)) => e,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_a_step_file() {
        let f = StepFile::parse(OK.as_bytes()).unwrap();
        assert_eq!(f.game, GameRef::Steam(440));
        assert_eq!(f.main_exe.as_str(), r"bin\game.exe");
        assert!(matches!(f.steps.as_slice(), [Step::IniSet(_)]));
        let folder = StepFile::parse(
            br#"{"format":1,"game":{"folder":"D:\\Games\\X"},"main_exe":"x.exe","steps":[]}"#,
        )
        .unwrap();
        assert!(matches!(folder.game, GameRef::Folder(p) if p.to_string() == r"D:\Games\X"));
    }

    #[test]
    fn refuses_anything_else_without_quoting_it() {
        assert_eq!(
            err(&OK.replace(r#""format":1"#, r#""format":2"#)),
            StepFileError::Format(2)
        );
        // The format comes first: an unknown field of format 2 is still a format error.
        assert_eq!(
            err(r#"{"format":2,"secret\u001b[2J":1}"#),
            StepFileError::Format(2)
        );
        for (bad, class) in [
            (OK.replace(r#""steps""#, r#""steps2""#), ParseClass::Data),
            (
                OK.replace(r#""main_exe":"bin\\game.exe","#, ""),
                ParseClass::Data,
            ),
            (
                OK.replace(
                    r#""main_exe":"bin\\game.exe""#,
                    r#""main_exe":"..\\evil.exe""#,
                ),
                ParseClass::Data,
            ),
            (
                OK.replace(r#"{"steam":440}"#, r#"{"folder":"\\\\server\\share\\x"}"#),
                ParseClass::Data,
            ),
            (
                OK.replace(r#"{"steam":440}"#, r#"{"steam":440,"folder":"D:\\X"}"#),
                ParseClass::Syntax,
            ),
            (
                OK.replace(r#""ini_set""#, r#""run_script""#),
                ParseClass::Data,
            ),
            (r#"{"format":1,"#.to_owned(), ParseClass::Eof),
            ("not json \u{1b}[2J".to_owned(), ParseClass::Syntax),
            (r#"{"main_exe":"x.exe"}"#.to_owned(), ParseClass::Data),
        ] {
            let e = err(&bad);
            assert!(
                matches!(e, StepFileError::Parse { class: c, .. } if c == class),
                "{bad}: {e:?}"
            );
            let text = PlanError::StepFile(e).to_string();
            assert!(
                !text.contains("evil") && !text.contains('\u{1b}') && !text.contains("run_script"),
                "{text}"
            );
        }
        assert_eq!(
            err(r#"{"format":1,
  "nope":1}"#),
            StepFileError::Parse {
                class: ParseClass::Data,
                line: 2,
                column: 8
            }
        );
        let big = vec![b' '; usize::try_from(MAX_STEP_FILE).unwrap() + 1];
        assert!(matches!(
            StepFile::parse(&big),
            Err(PlanError::StepFile(StepFileError::TooLarge))
        ));
    }
}
