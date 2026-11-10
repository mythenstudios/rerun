//! T8 (P4-14): `--hashes-from` against the fake system. Synthetic PE images (the layout of
//! `rerun-core`'s `detect::pe::testfx::Builder::x86`, with an import table added); every name
//! and byte is invented.

use std::path::Path;
use std::time::Duration;

use rerun_core::catalog::Topo;
use rerun_core::catalog::model::Api;
use rerun_core::sys::fake::{FakeHttp, FakeReply, FakeSystem};
use sha2::{Digest, Sha256};

use super::*;
use crate::draft::tests::loads_as_draft_only;
use crate::draft::{Request, make};
use crate::pcgw::tests::{QUEST, QUEST_URL, RACER, RACER_URL};
use crate::pcgw::{PageName, Target};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const GAME: &str = r"D:\Games\Invented Quest";

/// A 32-bit GUI image importing `dll`, padded by `pad` bytes so two images differ.
fn pe(dll: &str, pad: u8) -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    let mut put = |at: usize, v: &[u8]| b[at..at + v.len()].copy_from_slice(v);
    put(0x0, b"MZ");
    put(0x3c, &0x80u32.to_le_bytes());
    put(0x80, b"PE\0\0");
    put(0x84, &0x014cu16.to_le_bytes()); // i386
    put(0x86, &1u16.to_le_bytes()); // one section
    put(0x94, &0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
    put(0x96, &0x0102u16.to_le_bytes()); // executable, 32-bit
    put(0x98, &0x010bu16.to_le_bytes()); // PE32
    put(0xb4, &0x0040_0000u32.to_le_bytes()); // ImageBase
    put(0xd4, &0x200u32.to_le_bytes()); // SizeOfHeaders
    put(0xdc, &2u16.to_le_bytes()); // GUI
    put(0xde, &0x8140u16.to_le_bytes());
    put(0xf4, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    put(0x100, &0x1000u32.to_le_bytes()); // import directory RVA
    put(0x104, &40u32.to_le_bytes()); // one descriptor and the terminator
    put(0x178, b".rdata\0\0");
    put(0x180, &0x200u32.to_le_bytes()); // VirtualSize
    put(0x184, &0x1000u32.to_le_bytes()); // VirtualAddress
    put(0x188, &0x200u32.to_le_bytes()); // SizeOfRawData
    put(0x18c, &0x200u32.to_le_bytes()); // PointerToRawData
    put(0x200 + 12, &0x1040u32.to_le_bytes()); // Name
    put(0x200 + 16, &0x1040u32.to_le_bytes()); // FirstThunk (only non-zero)
    put(0x240, dll.as_bytes());
    put(0x3ff, &[pad]);
    b
}

fn sys(files: &[(&str, Vec<u8>)]) -> FakeSystem {
    let mut b = FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(GAME);
    for (name, data) in files {
        b = b.file(format!(r"{GAME}\{name}"), data.clone());
    }
    b.build().unwrap()
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02X}")).collect()
}

fn scan(s: &FakeSystem) -> Result<Local, String> {
    exes_from(s, Path::new(INSTALL), Path::new(GAME))
}

#[test]
fn t8_real_hashes_of_the_main_executables() {
    let dx9 = pe("d3d9.dll", 1);
    let dx12 = pe("d3d12.dll", 2);
    let s = sys(&[("Quest_DX9.exe", dx9.clone()), ("Quest_DX12.exe", dx12)]);
    let (exes, notes) = scan(&s).unwrap();
    assert_eq!(exes.len(), 1, "{exes:?} {notes:?}");
    let e = &exes[0];
    assert_eq!(e.path.as_str(), "Quest_DX9.exe");
    assert_eq!(e.api, Api::D3d9);
    assert_eq!(e.sha256.to_string(), hex(&Sha256::digest(&dx9)));
    // Computed independently (Python's hashlib over the same synthetic image).
    assert_eq!(
        e.sha1.to_string(),
        "3ABF5CA25F7EFA8AC03E3785AB01DA565A8B1E03"
    );
    assert_eq!(
        e.sha256.to_string(),
        "E4483378B17DE651015B896FF56D3F98B6A21550DEB35C181E1F22516337ABE1"
    );
    assert_eq!(
        notes,
        ["Quest_DX12.exe left out: its graphics API (d3d12) is not one a Topo can name (ADR 0014)"]
    );
}

#[test]
fn t8_the_draft_holds_them_and_no_local_path() {
    let dx9 = pe("d3d9.dll", 1);
    let s = sys(&[
        ("Quest_DX9.exe", dx9.clone()),
        ("Quest_DX12.exe", pe("d3d12.dll", 2)),
    ]);
    let local = scan(&s).unwrap();
    // The quest names Direct3D 9 and 10 and OpenGL: without the local copy it is refused.
    let h = FakeHttp::default();
    h.reply(QUEST_URL, FakeReply::ok(QUEST));
    let r = Request {
        target: Target::Page(PageName::parse("Invented Quest: Gold Edition").unwrap()),
        id: Some(rerun_core::catalog::model::Id::parse("invented-quest").unwrap()),
        title: None,
        local: Some(local),
    };
    let (_, text) = make(&h, &r, Duration::ZERO, Duration::from_secs(60)).unwrap();
    let sha256 = hex(&Sha256::digest(&dx9));
    assert!(text.contains(&format!(
        "    - {{ path: \"Quest_DX9.exe\", sha1: \"{}\", sha256: \"{sha256}\", api: \"d3d9\" }}\n",
        r.local.as_ref().unwrap().0[0].sha1
    )));
    assert!(
        text.contains("# hashes from a local copy of the game: verify its files in Steam first\n")
    );
    assert!(text.contains("# Quest_DX12.exe left out: its graphics API (d3d12)"));
    for absolute in ["D:", "Games", "Users", "Player", "Rerun\\"] {
        assert!(!text.contains(absolute), "{absolute}");
    }
    // Through the same checks as T6: schema, Rules::Source yes, Rules::Release no, left out
    // of a bundle.
    let t: Topo = loads_as_draft_only(&text, r.id.as_ref().unwrap());
    assert_eq!(t.matches.exes.len(), 1);
    assert!(
        t.matches.exes[0]
            .sha256
            .as_ref()
            .is_some_and(|h| !h.is_todo())
    );
}

#[test]
fn t8_a_local_api_pcgw_does_not_name_is_a_todo() {
    let s = sys(&[("Racer.exe", pe("d3d11.dll", 1))]);
    let local = scan(&s).unwrap();
    let h = FakeHttp::default();
    h.reply(RACER_URL, FakeReply::ok(RACER));
    let r = Request {
        target: Target::Page(PageName::parse("Invented Racer 2").unwrap()),
        id: None,
        title: None,
        local: Some(local),
    };
    let (_, text) = make(&h, &r, Duration::ZERO, Duration::from_secs(60)).unwrap();
    assert!(text.contains("# TODO: the local executable uses d3d11, PCGW does not name it\n"));
}

#[test]
fn t8_refusals() {
    // Only an API a Topo cannot name: nothing to draft from.
    let e = scan(&sys(&[("Quest.exe", pe("d3d12.dll", 1))])).unwrap_err();
    assert!(
        e.contains("write match.exes by hand") && e.contains("d3d12"),
        "{e}"
    );
    // No executable at all.
    let e = scan(&sys(&[])).unwrap_err();
    assert!(e.contains("write match.exes by hand"), "{e}");
    // Elevated: refused before the folder is opened.
    let s = sys(&[("Quest_DX9.exe", pe("d3d9.dll", 1))]);
    s.fake_registry().set_elevated(true);
    let e = scan(&s).unwrap_err();
    assert!(e.contains("elevated"), "{e}");
    // A folder that does not exist, and the install folder's own tree.
    let s = sys(&[("Quest_DX9.exe", pe("d3d9.dll", 1))]);
    assert!(exes_from(&s, Path::new(INSTALL), Path::new(r"D:\Games\Nothing")).is_err());
    assert!(exes_from(&s, Path::new(INSTALL), Path::new(r"C:\Windows")).is_err());
}

#[test]
fn every_detected_api_maps_or_is_left_out() {
    for (g, want) in [
        (GraphicsApi::Ddraw, Some(Api::Ddraw)),
        (GraphicsApi::D3d8, Some(Api::D3d8)),
        (GraphicsApi::D3d9, Some(Api::D3d9)),
        (GraphicsApi::D3d10, Some(Api::D3d10)),
        (GraphicsApi::D3d11, Some(Api::D3d11)),
        (GraphicsApi::Opengl, Some(Api::Opengl)),
        (GraphicsApi::D3d12, None),
        (GraphicsApi::Vulkan, None),
        (GraphicsApi::Glide, None),
    ] {
        assert_eq!(topo_api(g), want, "{g}");
    }
}
