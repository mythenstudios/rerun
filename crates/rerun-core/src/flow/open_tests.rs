//! Tests of opening links and Rerun's folder (P5-10a, ADR 0027 amendment P5-10a) against the fake
//! world and the fake shell; nothing is ever opened. Every ID and URL is invented.
//! - OL2 a source link is looked up in the current signed index by reference: another Topo,
//!   issue, variant, position or app, or no index, opens nothing; a URL the loader admits but the
//!   open grammar does not (a `"`) is refused; a non-ASCII one is encoded.
//! - OL3 the report holds only Rerun's own facts: a hostile Steam name, an adapter name and the
//!   user's paths never reach it; it is printable ASCII and `\n`; with the most facts the URL
//!   still fits, and decoding it gives exactly the title and text.
//! - OL4 the data folder: none, nothing opened and nothing created; there, exactly its canonical
//!   path for Explorer; a junction in its place stops the guard, nothing is opened.

use std::path::PathBuf;

use crate::catalog::key::test_key;
use crate::catalog::{self};
use crate::detect::steam::RootSource;
use crate::policy::open::{MAX_OPEN_URL, OpenRefusal, OwnLink};
use crate::policy::root::{AppDir, Create};
use crate::sys::fake::{FakeHttp, FakeShell, FakeSystem, FakeSystemBuilder, Opened, Prim};
use crate::sys::registry::RegValue;
use crate::sys::{GpuAdapter, SysErrorKind};

use super::{
    Facts, LinkRef, OpenError, body, data_folder, open_data_folder, open_url, report, report_of,
    source_url,
};
use crate::flow::{Env, Gate, Guarded, guard};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const RERUN: &str = r"C:\Users\Player\AppData\Local\Rerun";
const STEAM: &str = r"C:\Program Files (x86)\Steam";

/// A Steam library whose app 220 has a hostile name (a bidi control, a path, a user name), and an
/// adapter with a hostile name.
fn base() -> FakeSystemBuilder {
    let hostile = "Evil\u{202e}gnp.exe C:\\Users\\Player\\secret Player";
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .value(
            RootSource::CurrentUser.key(),
            RootSource::CurrentUser.value_name(),
            RegValue::String(STEAM.to_owned()),
        )
        .file(
            format!(r"{STEAM}\steamapps\libraryfolders.vdf"),
            format!(
                "\"libraryfolders\"\n{{\n\t\"0\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n}}\n",
                STEAM.replace('\\', r"\\")
            )
            .into_bytes(),
        )
        .file(
            format!(r"{STEAM}\steamapps\appmanifest_220.acf"),
            format!(
                "\"AppState\"\n{{\n\t\"appid\"\t\t\"220\"\n\t\"name\"\t\t\"{hostile}\"\n\t\"StateFlags\"\t\t\"4\"\n\t\"installdir\"\t\t\"G\"\n}}\n"
            )
            .into_bytes(),
        )
        .gpu(GpuAdapter {
            name: format!("Radeon {hostile}"),
            vendor_id: 0x1002,
            device_id: 0x7550,
            subsys_id: 0,
            revision: 0xc0,
            luid: 1,
            dedicated_video_memory: 16 << 30,
            shared_system_memory: 16 << 30,
            software: false,
            umd_version: None,
        })
}

/// The index: a Topo for app 220 whose variant has four sources (the last two are outside the
/// open grammar or need encoding).
fn index() -> String {
    let step = r#"{"compat_layer":{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}"#;
    let sources = r#"[{"type":"repo","url":"https://github.com/example/patch"},
{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented_Game#Fix"},
{"type":"official","url":"https://example.org/a\"b"},
{"type":"official","url":"https://example.org/Pok\u00e9mon"}]"#;
    format!(
        r#"{{"format":1,"seq":9,"issued":"2026-11-11T12:00:00Z","topos":[{{"format":1,"id":"invented-game","title":"Invented","status":"active","rev":4,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{h}","api":"d3d9"}}]}},
"issues":[{{"id":"controller","title":"Controllers","variants":[{{"id":"patch","status":"verified","kind":"fix","steps":[{step}],"sources":{sources}}}]}}]}}],"packages":[]}}"#,
        h = "0".repeat(64)
    )
}

/// [`base`] with the index imported (Rerun's folder created by the import).
fn indexed() -> FakeSystem {
    let sys = base().build().unwrap();
    let ix = index();
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    catalog::store::import(
        &app,
        ix.as_bytes(),
        &test_key::sign(ix.as_bytes()),
        &catalog::trusted_keys(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    drop(app);
    sys.fake_fs().sync_all();
    sys
}

fn with_guard<R>(sys: &FakeSystem, f: impl FnOnce(&Guarded<'_>) -> R) -> R {
    let http = FakeHttp::default();
    let ok: Result<PathBuf, String> = Ok(PathBuf::from(INSTALL));
    let g = guard(Env {
        sys,
        http: &http,
        install: &ok,
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    f(&g)
}

fn source_ref(topo: &str, issue: &str, variant: &str, source: usize) -> LinkRef {
    LinkRef {
        app_id: 220,
        topo: topo.to_owned(),
        issue: issue.to_owned(),
        variant: variant.to_owned(),
        source,
    }
}

#[test]
fn ol2_a_source_link_comes_from_the_current_index_only() {
    let sys = indexed();
    let shell = FakeShell::new();
    with_guard(&sys, |g| {
        let u = source_url(g, &source_ref("invented-game", "controller", "patch", 0)).unwrap();
        assert_eq!(u.as_str(), "https://github.com/example/patch");
        open_url(&shell, &u).unwrap();
        let u = source_url(g, &source_ref("invented-game", "controller", "patch", 1)).unwrap();
        assert_eq!(
            u.as_str(),
            "https://www.pcgamingwiki.com/wiki/Invented_Game#Fix"
        );
        // Admitted by the loader, refused by the open grammar.
        assert_eq!(
            source_url(g, &source_ref("invented-game", "controller", "patch", 2)),
            Err(OpenRefusal::Form)
        );
        // Encoded.
        assert_eq!(
            source_url(g, &source_ref("invented-game", "controller", "patch", 3))
                .unwrap()
                .as_str(),
            "https://example.org/Pok%C3%A9mon"
        );
        for r in [
            source_ref("invented-game", "controller", "patch", 4),
            source_ref("invented-game", "controller", "limit", 0),
            source_ref("invented-game", "online", "patch", 0),
            source_ref("other-game", "controller", "patch", 0),
            LinkRef {
                app_id: 230,
                ..source_ref("invented-game", "controller", "patch", 0)
            },
        ] {
            assert_eq!(source_url(g, &r), Err(OpenRefusal::NotInIndex), "{r:?}");
        }
    });
    assert_eq!(
        shell.taken(),
        [Opened::Url("https://github.com/example/patch".to_owned())]
    );
    // No index (no Rerun folder): nothing.
    let bare = base().build().unwrap();
    with_guard(&bare, |g| {
        assert_eq!(
            source_url(g, &source_ref("invented-game", "controller", "patch", 0)),
            Err(OpenRefusal::NoIndex)
        );
    });
    // A failing shell is an error of the shell, typed.
    let failing = FakeShell::failing(SysErrorKind::NotFound);
    let e = open_url(
        &failing,
        &crate::policy::open::OpenUrl::own(OwnLink::Repository),
    );
    assert!(matches!(e, Err(OpenError::Shell(_))), "{e:?}");
    assert!(failing.taken().is_empty());
}

/// Decodes `%XX`.
fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The title and text a report's URL carries.
fn carried(url: &str) -> (String, String) {
    let q = url
        .strip_prefix("https://github.com/mythenstudios/rerun/issues/new?title=")
        .unwrap();
    let (t, b) = q.split_once("&body=").unwrap();
    (decode(t), decode(b))
}

fn plain(s: &str) -> bool {
    s.chars()
        .all(|c| c == '\n' || c == ' ' || c.is_ascii_graphic())
}

#[test]
fn ol3_the_report_holds_only_rerun_s_own_facts() {
    let sys = indexed();
    sys.fake_fs().record_calls(true);
    let r = with_guard(&sys, |g| report(g, 220).unwrap());
    assert_eq!(r.title, "Problem with Steam app 220");
    for needle in [
        "Evil", "gnp", "Player", "secret", "Users", "AppData", "Radeon", "\\", ":\\", "\u{202e}",
    ] {
        assert!(!r.body.contains(needle), "{needle:?} in {}", r.body);
        assert!(!r.title.contains(needle), "{needle:?}");
    }
    assert!(plain(&r.body) && plain(&r.title), "{}", r.body);
    for fact in [
        crate::BUILD_ID,
        "- Steam app: 220\n",
        "- Index: seq 9\n",
        "- Topos: invented-game rev 4 (active)\n",
        "- Open changes: none\n",
        "- Graphics: AMD ",
        "- CPU: ",
        "- Last start: none recorded\n",
    ] {
        assert!(r.body.contains(fact), "{fact:?} not in {}", r.body);
    }
    assert!(r.url().as_str().len() <= MAX_OPEN_URL);
    assert_eq!(carried(r.url().as_str()), (r.title.clone(), r.body.clone()));
    // Looking creates nothing and writes nothing.
    let writes: Vec<_> = sys
        .fake_fs()
        .take_calls()
        .into_iter()
        .filter(|c| {
            matches!(
                c,
                Prim::CreateTmp
                    | Prim::CreateDir
                    | Prim::OpenLock
                    | Prim::Rename
                    | Prim::Write
                    | Prim::SetAttrs
                    | Prim::PosixDelete
                    | Prim::OpenFileDelete
                    | Prim::OpenDirDelete
            )
        })
        .collect();
    assert!(writes.is_empty(), "{writes:?}");
    // Without an index or Rerun's folder.
    let bare = base().build().unwrap();
    let r = with_guard(&bare, |g| report(g, 220).unwrap());
    assert!(
        r.body.contains("- Index: none\n- Topos: none\n"),
        "{}",
        r.body
    );
}

#[test]
fn ol3_the_most_facts_still_fit_and_decode_exactly() {
    let long = |p: &str, i: usize| format!("{p}{i:02}-{}", "x".repeat(60))[..64].to_owned();
    let f = Facts {
        os: "26100.4061".to_owned(),
        index: "seq 18446744073709551615".to_owned(),
        topos: (0..40)
            .map(|i| format!("{} rev 4294967295 (needs retest)", long("t", i)))
            .collect(),
        variants: (0..64).map(|i| long("v", i)).collect(),
        gpus: (0..16)
            .map(|_| "vendor 0xFFFFFFFF architecture not in the table".to_owned())
            .collect(),
        cpu: "4096 logical, 2048 cores, 256 L3 groups".to_owned(),
        last_start: "rule not applied (topology_unavailable)".to_owned(),
    };
    // Uncut, it would not fit.
    let full = body(u32::MAX, &f, [usize::MAX; 3]);
    assert!(full.len() > MAX_OPEN_URL, "{}", full.len());
    let r = report_of(u32::MAX, &f).unwrap();
    assert!(
        r.url().as_str().len() <= MAX_OPEN_URL,
        "{}",
        r.url().as_str().len()
    );
    assert_eq!(carried(r.url().as_str()), (r.title.clone(), r.body.clone()));
    assert!(r.body.contains(" more"), "{}", r.body);
    assert!(plain(&r.body));
}

#[test]
fn ol4_the_data_folder_is_opened_only_if_it_exists() {
    // None: where it would be, nothing opened, nothing created.
    let sys = base().build().unwrap();
    let shell = FakeShell::new();
    with_guard(&sys, |g| {
        let d = data_folder(g).unwrap();
        assert!(!d.exists);
        assert_eq!(d.path.to_string(), RERUN);
        let e = open_data_folder(g, &shell);
        assert!(
            matches!(e, Err(OpenError::Refused(OpenRefusal::NoAppDir))),
            "{e:?}"
        );
    });
    assert!(shell.taken().is_empty());
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
    // There: exactly its canonical path.
    let sys = indexed();
    with_guard(&sys, |g| {
        let d = data_folder(g).unwrap();
        assert!(d.exists);
        open_data_folder(g, &shell).unwrap();
        assert_eq!(shell.taken(), [Opened::Folder(d.path.clone())]);
    });
    match &shell.taken()[..] {
        [Opened::Folder(p)] => assert_eq!(p.to_string(), RERUN),
        other => panic!("{other:?}"),
    }
    // A junction in its place: the guard refuses, nothing is opened.
    let junction = base()
        .dir(r"C:\Elsewhere")
        .junction(RERUN, r"C:\Elsewhere")
        .build()
        .unwrap();
    let http = FakeHttp::default();
    let ok: Result<PathBuf, String> = Ok(PathBuf::from(INSTALL));
    let g = guard(Env {
        sys: &junction,
        http: &http,
        install: &ok,
    });
    assert!(matches!(g, Err(Gate::AppDir(_))));
}
