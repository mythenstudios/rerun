//! The preview renderer: golden strings on directly built previews (every op kind, the notes),
//! and hostile fields (ESC, U+202E, U+2028, tag characters) escaped, the net never firing.

use rerun_core::escape;
use rerun_core::plan::{
    INI_NOTE, IniOldShown, IniShown, LAYERS_NOTE, NOT_RESTORED, Preview, PreviewOp, PreviewRoot,
    REGISTRY_NOTE, RegShown, RootKind,
};

use super::render;
use crate::messages::Message;
use crate::out::Out;

fn shown(ms: &[Message<'_>]) -> String {
    let mut out = Out::new(Vec::new());
    out.lines(ms).unwrap();
    String::from_utf8(out.into_inner()).unwrap()
}

fn op(index: usize, action: &'static str, root: Option<usize>, path: &str) -> PreviewOp {
    PreviewOp {
        index,
        action,
        root,
        path: escape::path(path).into_owned(),
        name: None,
        old_value: None,
        new_value: None,
        tokens: None,
        type_change: false,
        source: None,
        content: None,
        attrs: None,
        old: None,
        config: false,
        ini: Vec::new(),
        profile: None,
    }
}

fn reg(kind: &str, text: Option<&str>) -> RegShown {
    RegShown {
        kind: kind.to_owned(),
        text: text.map(|t| escape::text(t).into_owned()),
    }
}

fn preview(root_path: &str, ops: Vec<PreviewOp>) -> Preview {
    Preview {
        roots: vec![PreviewRoot {
            index: 0,
            kind: RootKind::Game,
            path: escape::path(root_path).into_owned(),
            steam: Some((220, escape::path(r"D:\SteamLibrary").into_owned())),
            main_exe: Some(escape::path(r"bin\game.exe").into_owned()),
        }],
        ops,
        not_restored: NOT_RESTORED,
        registry: Some(REGISTRY_NOTE),
        layers: Some(LAYERS_NOTE),
        ini: Some(INI_NOTE),
        profiles: None,
    }
}

#[test]
fn every_op_kind_and_the_notes() {
    let sha = "ab".repeat(32);
    let mut replace = op(0, "replace file", Some(0), "d3d9.dll");
    replace.source = Some(escape::path("fix-pack 1.0.2: d3d9.dll").into_owned());
    replace.content = Some((sha.clone(), 23));
    replace.attrs = Some("-".to_owned());
    replace.old = Some((sha.clone(), 20, "RH".to_owned()));
    replace.config = true;
    let mut ini = op(1, "edit ini", Some(0), r"cfg\game.ini");
    ini.content = Some((sha.clone(), 35));
    ini.attrs = Some("-".to_owned());
    ini.old = Some((sha.clone(), 35, "-".to_owned()));
    ini.ini = vec![
        IniShown {
            section: escape::text("Display").into_owned(),
            key: escape::text("Width").into_owned(),
            old: IniOldShown::Value(escape::text("1280").into_owned()),
            new: escape::text("1920").into_owned(),
        },
        IniShown {
            section: escape::text("New").into_owned(),
            key: escape::text("K").into_owned(),
            old: IniOldShown::NewSection,
            new: escape::text("1").into_owned(),
        },
    ];
    let key = op(2, "create key", None, r"HKCU\Software\Vendor");
    let mut value = op(3, "set value", None, r"HKCU\Software\Vendor\Game");
    value.name = Some(escape::path("Lang").into_owned());
    value.old_value = Some(reg("REG_SZ", Some("de")));
    value.new_value = Some(reg("REG_DWORD 1 (0x00000001)", None));
    value.type_change = true;
    let mut tokens = op(4, "add tokens", None, r"HKCU\Software\Layers");
    tokens.name = Some(escape::path(r"D:\Games\G\game.exe").into_owned());
    tokens.tokens = Some("ZZ_A ZZ_B".to_owned());
    tokens.old_value = Some(reg("missing", None));
    tokens.new_value = Some(reg("REG_SZ", Some("~ ZZ_A ZZ_B")));
    let p = preview(r"D:\Games\G", vec![replace, ini, key, value, tokens]);
    let want = format!(
        r"root 0: D:\Games\G
  Steam app 220, library: D:\SteamLibrary
  main executable: bin\game.exe
op 0: replace file in root 0: d3d9.dll
  from package: fix-pack 1.0.2: d3d9.dll
  new: sha256 {sha}, 23 bytes, attributes -
  old: sha256 {sha}, 20 bytes, attributes RH
  configuration file: once edited, a revert leaves it as it is
op 1: edit ini in root 0: cfg\game.ini
  new: sha256 {sha}, 35 bytes, attributes -
  old: sha256 {sha}, 35 bytes, attributes -
  key [Display] Width
    old: 1280
    new: 1920
  key [New] K
    old: missing (new section)
    new: 1
op 2: create key: HKCU\Software\Vendor
op 3: set value: HKCU\Software\Vendor\Game
  value: Lang
  old value: REG_SZ: de
  new value: REG_DWORD 1 (0x00000001)
  the type of the value changes
op 4: add tokens: HKCU\Software\Layers
  value: D:\Games\G\game.exe
  adds tokens: ZZ_A ZZ_B
  old value: missing
  new value: REG_SZ: ~ ZZ_A ZZ_B
note: {NOT_RESTORED}
note: {REGISTRY_NOTE}
note: {LAYERS_NOTE}
note: {INI_NOTE}
"
    );
    assert_eq!(shown(&render(&p)), want);
}

#[test]
fn hostile_fields_are_escaped_and_stand_last() {
    let evil = "x\u{1b}[2J\u{202E}y\u{2028}z\u{E0041}";
    let mut o = op(0, "set value", None, &format!(r"HKCU\Software\{evil}"));
    o.name = Some(escape::path(evil).into_owned());
    o.old_value = Some(reg("REG_SZ", Some(evil)));
    o.new_value = Some(reg("REG_SZ", Some("ok")));
    let mut f = op(1, "create file", Some(0), evil);
    f.source = Some(escape::path(evil).into_owned());
    let p = preview(&format!(r"D:\{evil}"), vec![o, f]);
    let text = shown(&render(&p));
    for bad in ['\u{1b}', '\u{202E}', '\u{2028}', '\u{E0041}'] {
        assert!(!text.contains(bad), "{text}");
    }
    // Root, key, value name, old value, file path, source: each quoted, last on its line.
    let hit: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(r"x\u{1b}[2J\u{202e}y"))
        .collect();
    assert_eq!(hit.len(), 6, "{text}");
    for line in hit {
        assert!(
            line.ends_with(r#"y\u{2028}z\u{e0041}""#),
            "untrusted text last: {line}"
        );
    }
}
