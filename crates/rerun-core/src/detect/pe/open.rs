//! The only reader for executables in game folders (ADR 0013, "Layers").
//!
//! [`open_game_exe`] opens the file relative to an open [`GameDir`] handle (ADR 0007: never by
//! absolute path, never through a reparse point, a restricted entry or an online-only cloud
//! placeholder) and parses it with [`Pe::parse`]. The file length is never asked for: not from
//! metadata, not by seeking to the end. Every read after that is a bounded range read of the
//! parser, charged to [`Limits::max_read_bytes`]; the unbounded [`Dir::read`] is never used.

use super::{Limits, Pe, PeError};
use crate::path::RelPath;
use crate::policy::root::GameDir;
use crate::sys::fs::ReadSeek;
use crate::sys::{Dir, SysError};

/// An executable opened through [`open_game_exe`], over the handle of the game folder.
/// [`Pe::into_inner`] hands the file back, e.g. to hash the very handle that was parsed.
pub type GameExe<'g> = Pe<Box<dyn ReadSeek + 'g>>;

/// Error while opening an executable in a game folder. Names the file, never its content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeReadError {
    /// Opening failed: missing, a directory, a reparse point on the way, restricted, an
    /// online-only placeholder, busy, …
    #[error("{file}: {source}")]
    Open {
        /// The file, relative to the game folder.
        file: RelPath,
        /// Error of the system layer.
        source: SysError,
    },
    /// The parser refused the file (or reading it failed: [`super::PeErrorKind::Io`]).
    #[error("{file}: {error}")]
    Parse {
        /// The file, relative to the game folder.
        file: RelPath,
        /// The parse error.
        error: PeError,
    },
}

/// Opens `exe` (relative to the game folder) and parses its headers within `limits`.
pub fn open_game_exe<'g>(
    game: &'g GameDir<'_>,
    exe: &RelPath,
    limits: &Limits,
) -> Result<GameExe<'g>, PeReadError> {
    open_bounded(game.dir(), exe, limits)
}

/// [`open_game_exe`] on a bare handle; separate so the bound can be tested with a reader
/// that never ends. Detection never calls this with anything but a [`GameDir`] handle.
fn open_bounded<'d>(
    dir: &'d dyn Dir,
    exe: &RelPath,
    limits: &Limits,
) -> Result<GameExe<'d>, PeReadError> {
    let reader = dir.open_read(exe).map_err(|source| PeReadError::Open {
        file: exe.clone(),
        source,
    })?;
    Pe::parse(reader, limits).map_err(|error| PeReadError::Parse {
        file: exe.clone(),
        error,
    })
}

#[cfg(test)]
mod tests;
