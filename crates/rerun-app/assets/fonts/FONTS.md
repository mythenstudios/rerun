# Bundled fonts

The brand fonts of the Rerun app. They are the one exception to "no third-party binaries in the
repository" (`docs/05-sources-policy.md`): font files under the SIL Open Font License 1.1, taken
unmodified from the projects' own upstream, never an executable. `tests/fonts.rs` checks every
SHA-256 below against the file and that every folder holds its `OFL.txt`.

| File | Family | Weight | Version | SHA-256 |
|---|---|---|---|---|
| `archivo/ArchivoExpanded-ExtraBold.ttf` | Archivo Expanded | 800 | 2.001 | `1a9be279675c44ff26093fded726f2fd98e490445e778dac5d44812aaeab2d1a` |
| `ibm-plex-sans/IBMPlexSans-Regular.ttf` | IBM Plex Sans | 400 | 3.005 | `975dcda37d80f038dcd143c22e33ca2d97a0cc5a929aace1c749153b0fe1afa5` |
| `ibm-plex-sans/IBMPlexSans-Medium.ttf` | IBM Plex Sans | 500 | 3.005 | `331c8639d7598b2cde62a911a71db195e30cb655cd6bdf2e324a7e984955f907` |
| `ibm-plex-sans/IBMPlexSans-SemiBold.ttf` | IBM Plex Sans | 600 | 3.005 | `a20caf8286023a6a7a85e40b1d2a4ae9fc3e3b1f9eda8f4c542dd4986af67bb1` |
| `ibm-plex-mono/IBMPlexMono-Regular.ttf` | IBM Plex Mono | 400 | 2.005 | `7c6fbddca4b700be918f5f6183d9bd4464fa427fe435f0b480d77fe2bb8c5a43` |
| `ibm-plex-mono/IBMPlexMono-Medium.ttf` | IBM Plex Mono | 500 | 2.005 | `98fbd727aae340b236955879dabed4d991aac9e8e90b3b2a67ce4a59221cc97c` |

## Sources

- **Archivo Expanded ExtraBold**: the Archivo project, https://github.com/Omnibus-Type/Archivo
  (Omnibus-Type), commit `211127690e8ff106c36c935f7e5e697114cff103` (the repository has no tags
  or releases), file `fonts/ttf/ArchivoExpanded-ExtraBold.ttf`; licence `OFL.txt` from the same
  commit. Copyright 2020 The Archivo Project Authors.
- **IBM Plex Sans**: release `@ibm/plex-sans@1.1.0` of https://github.com/IBM/plex, asset
  `ibm-plex-sans.zip` (SHA-256 of the zip
  `fb365d910566e6d199cc2c15579a7dd9a267128e18431a394ed81f1970c69200`), files
  `ibm-plex-sans/fonts/complete/ttf/*.ttf`; licence `ibm-plex-sans/LICENSE.txt` of the zip.
  Copyright 2017 IBM Corp., Reserved Font Name "Plex".
- **IBM Plex Mono**: release `@ibm/plex-mono@2.5.0` of https://github.com/IBM/plex, asset
  `ibm-plex-mono.zip` (SHA-256 of the zip
  `6d23f01257663d8cc49a0d64c22ced630b79e0e2a0ac08a0da86e9a38bbc481c`, equal to the digest GitHub
  shows for the asset), files `ibm-plex-mono/fonts/complete/ttf/*.ttf`; licence
  `fonts/complete/ttf/license.txt` of the zip. Copyright 2017 IBM Corp., Reserved Font Name "Plex".

## Licence and use

All six files are licensed under the SIL Open Font License, Version 1.1 (the full text is the
`OFL.txt` in each folder). They are bundled unmodified (no subsetting, no renaming), embedded into
`rerun-app.exe` at build time by the Slint compiler, and neither loaded from disk nor from the
network at run time. A glyph the fonts lack (Cyrillic or CJK game titles, the status symbols) falls
back to a Windows system font. The OFL's reserved font names ("Plex") are the reason the files keep
their names and content.
