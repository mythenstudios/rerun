# VDF fixtures

Synthetic Valve KeyValues files for `detect::vdf` and `detect::steam::files` (ADR 0011). Every
value is invented: paths, labels, app IDs, names, sizes, IDs and timestamps do not come from a
real machine or account. Do not add files copied from a real Steam installation.

- `libraryfolders-current.vdf`: current format (libraries as objects with `path`, `label`,
  `apps`), three libraries, one with a non-ASCII path.
- `libraryfolders-legacy.vdf`: format before 2021 (`"1" "D:\\Lib"`), with the
  `TimeNextStatsReport` and `ContentStatsID` keys that are ignored.
- `libraryfolders-comments.vdf`: current format with `//` comments, empty objects and every
  supported escape.
- `appmanifest-minimal.acf`: only the four required fields.
- `appmanifest-full.acf`: a manifest with depots, DLC, user and mounted config.

`.gitattributes` forces `eol=lf`, so CRLF and BOM cases are built inline in the tests.
