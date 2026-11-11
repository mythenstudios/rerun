# rerun-app

The Rerun app `rerun-app.exe`: a window over `rerun_core::flow` (ADR 0027), drawn with Slint
(ADR 0026). See `docs/07-ui.md`.

## Bundled fonts

The app embeds the brand fonts Archivo Expanded ExtraBold, IBM Plex Sans (400, 500, 600) and
IBM Plex Mono (400, 500) from `assets/fonts/`, unmodified, under the SIL Open Font License 1.1.
Each family's licence text is its `OFL.txt`; sources, versions and SHA-256 are in
`assets/fonts/FONTS.md`. The fonts are compiled into `rerun-app.exe` and not loaded at run time.
