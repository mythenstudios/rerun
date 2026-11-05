//! The API mapping (ADR 0014, "Graphics API"). Pure; DLL names only.

use super::{ApiSet, ApiVerdict, Basis, Engine, GraphicsApi as A, classify};
use crate::detect::pe::DllName;

fn dlls(names: &[&str]) -> Vec<DllName> {
    names.iter().map(|n| DllName::for_test(n)).collect()
}

fn verdict(imports: &[&str], delay: &[&str], managed: bool) -> ApiVerdict {
    classify(&dlls(imports), &dlls(delay), managed).verdict
}

fn only(api: A) -> ApiVerdict {
    ApiVerdict::One {
        api,
        basis: Basis::Only,
    }
}

fn set(apis: &[A]) -> ApiSet {
    apis.iter().copied().collect()
}

#[test]
fn every_core_dll_in_any_case() {
    for (dll, api) in [
        ("ddraw.dll", A::Ddraw),
        ("d3d8.dll", A::D3d8),
        ("d3d9.dll", A::D3d9),
        ("d3d10.dll", A::D3d10),
        ("d3d10_1.dll", A::D3d10),
        ("d3d11.dll", A::D3d11),
        ("d3d12.dll", A::D3d12),
        ("opengl32.dll", A::Opengl),
        ("vulkan-1.dll", A::Vulkan),
        ("glide.dll", A::Glide),
        ("glide2x.dll", A::Glide),
        ("glide3x.dll", A::Glide),
    ] {
        for spelled in [dll.to_owned(), dll.to_ascii_uppercase()] {
            assert_eq!(
                verdict(&["KERNEL32.dll", &spelled], &[], false),
                only(api),
                "{spelled}"
            );
            assert_eq!(
                verdict(&[], &[&spelled], false),
                ApiVerdict::One {
                    api,
                    basis: Basis::DelayOnly
                },
                "{spelled}"
            );
        }
    }
    // `OPENGL32.dll` as games spell it.
    assert_eq!(verdict(&["OPENGL32.dll"], &[], false), only(A::Opengl));
}

#[test]
fn every_helper_dll() {
    for (dll, api) in [
        ("d3dx9_43.dll", A::D3d9),
        ("D3DX9_24.DLL", A::D3d9),
        ("d3dx10.dll", A::D3d10),
        ("d3dx10_43.dll", A::D3d10),
        ("d3dx11_43.dll", A::D3d11),
        ("d3drm.dll", A::Ddraw),
        ("d3dim.dll", A::Ddraw),
        ("d3dim700.dll", A::Ddraw),
        ("glu32.dll", A::Opengl),
    ] {
        let expected = ApiVerdict::One {
            api,
            basis: Basis::Helper,
        };
        assert_eq!(verdict(&[dll], &[], false), expected, "{dll}");
        assert_eq!(verdict(&[], &[dll], false), expected, "{dll} delay-loaded");
    }
}

#[test]
fn names_match_exactly() {
    for ignored in [
        "d3d9.dll.bak",
        "xd3d9.dll",
        "d3d9",
        "d3d9.dl",
        "d3d9 .dll",
        "d3dx9_4.dll",
        "d3dx9_431.dll",
        "d3dx9_ab.dll",
        "d3dx11.dll",
        "d3dcompiler_47.dll",
        "D3DCOMPILER_43.dll",
        "dxgi.dll.dll",
        "vulkan.dll",
        "opengl.dll",
        "UnityPlayer.dll.old",
        "KERNEL32.dll",
    ] {
        assert_eq!(
            verdict(&[ignored], &[], false),
            ApiVerdict::None,
            "{ignored}"
        );
    }
}

#[test]
fn duplicates_count_once() {
    assert_eq!(
        verdict(&["d3d9.dll", "D3D9.DLL", "d3d9.dll"], &[], false),
        only(A::D3d9)
    );
    let r = classify(
        &dlls(&["KERNEL32.dll", "KERNEL32.dll", "d3d9.dll"]),
        &[],
        false,
    );
    assert_eq!(r.evidence.imports.core, set(&[A::D3d9]));
}

#[test]
fn several_direct3d_versions_take_the_highest() {
    assert_eq!(
        verdict(&["d3d9.dll", "d3d11.dll", "dxgi.dll"], &[], false),
        ApiVerdict::One {
            api: A::D3d11,
            basis: Basis::HighestD3d
        }
    );
    assert_eq!(
        verdict(&["ddraw.dll", "d3d8.dll"], &[], false),
        ApiVerdict::One {
            api: A::D3d8,
            basis: Basis::HighestD3d
        }
    );
    assert_eq!(
        verdict(&["d3d10_1.dll", "d3d10.dll"], &[], false),
        only(A::D3d10),
        "two DLLs of one API are one API"
    );
    // In the delay table the basis stays `DelayOnly`.
    assert_eq!(
        verdict(&[], &["d3d9.dll", "d3d12.dll"], false),
        ApiVerdict::One {
            api: A::D3d12,
            basis: Basis::DelayOnly
        }
    );
}

#[test]
fn a_family_mix_is_several() {
    assert_eq!(
        verdict(&["d3d9.dll", "opengl32.dll"], &[], false),
        ApiVerdict::Several(set(&[A::D3d9, A::Opengl]))
    );
    assert_eq!(
        verdict(
            &["opengl32.dll", "vulkan-1.dll", "d3d11.dll", "d3d9.dll"],
            &[],
            false
        ),
        ApiVerdict::Several(set(&[A::D3d9, A::D3d11, A::Opengl, A::Vulkan]))
    );
    assert_eq!(
        verdict(&["glide2x.dll", "ddraw.dll"], &[], false),
        ApiVerdict::Several(set(&[A::Ddraw, A::Glide]))
    );
    assert_eq!(
        verdict(&[], &["opengl32.dll", "d3d9.dll"], false),
        ApiVerdict::Several(set(&[A::D3d9, A::Opengl])),
        "several stays several in the delay table"
    );
}

#[test]
fn rules_apply_in_order() {
    // 1. Static core imports win over everything else.
    assert_eq!(
        verdict(
            &["d3d9.dll", "d3dx11_43.dll", "dxgi.dll", "UnityPlayer.dll"],
            &["d3d11.dll"],
            true
        ),
        only(A::D3d9)
    );
    // 2. Delay core imports over helpers, dxgi and engines.
    assert_eq!(
        verdict(
            &["d3dx9_43.dll", "dxgi.dll", "UnityPlayer.dll"],
            &["opengl32.dll"],
            false
        ),
        ApiVerdict::One {
            api: A::Opengl,
            basis: Basis::DelayOnly
        }
    );
    // 3. Helpers of both tables over dxgi.
    assert_eq!(
        verdict(&["dxgi.dll"], &["d3dx9_43.dll", "d3dx11_43.dll"], false),
        ApiVerdict::One {
            api: A::D3d11,
            basis: Basis::Helper
        }
    );
    assert_eq!(
        verdict(&["glu32.dll"], &["d3dx9_43.dll"], false),
        ApiVerdict::Several(set(&[A::D3d9, A::Opengl]))
    );
    // 4. dxgi in either table over engines.
    assert_eq!(
        verdict(&["UnityPlayer.dll"], &["dxgi.dll"], true),
        ApiVerdict::DxgiOnly
    );
    assert_eq!(verdict(&["DXGI.dll"], &[], false), ApiVerdict::DxgiOnly);
    // 5. Engines over managed.
    assert_eq!(
        verdict(&["UnityPlayer.dll", "KERNEL32.dll"], &[], true),
        ApiVerdict::RendererInDll(Engine::Unity)
    );
    assert_eq!(
        verdict(&["Core.dll", "Engine.dll", "Window.dll"], &[], false),
        ApiVerdict::RendererInDll(Engine::UnrealClassic)
    );
    assert_eq!(
        verdict(&["Core.dll"], &["Engine.dll"], false),
        ApiVerdict::RendererInDll(Engine::UnrealClassic)
    );
    // 6. Managed, else none.
    assert_eq!(verdict(&["mscoree.dll"], &[], true), ApiVerdict::Managed);
    assert_eq!(verdict(&[], &[], false), ApiVerdict::None);
}

#[test]
fn core_without_engine_is_no_engine() {
    assert_eq!(verdict(&["Core.dll"], &[], false), ApiVerdict::None);
    assert_eq!(verdict(&["Engine.dll"], &[], false), ApiVerdict::None);
}

#[test]
fn the_evidence_is_kept_per_table() {
    let r = classify(
        &dlls(&["d3d11.dll", "d3d9.dll", "dxgi.dll", "d3dx9_43.dll"]),
        &dlls(&["opengl32.dll", "glu32.dll", "UnityPlayer.dll"]),
        false,
    );
    assert_eq!(r.evidence.imports.core, set(&[A::D3d9, A::D3d11]));
    assert_eq!(r.evidence.imports.helper, set(&[A::D3d9]));
    assert!(r.evidence.imports.dxgi);
    assert_eq!(r.evidence.delay.core, set(&[A::Opengl]));
    assert_eq!(r.evidence.delay.helper, set(&[A::Opengl]));
    assert!(!r.evidence.delay.dxgi);
    assert_eq!(r.evidence.engine, Some(Engine::Unity));
    assert!(!r.evidence.managed);
}

#[test]
fn display_names_the_verdict_and_its_basis() {
    let shown = |imports: &[&str], delay: &[&str], managed| {
        classify(&dlls(imports), &dlls(delay), managed).to_string()
    };
    assert_eq!(shown(&["d3d9.dll"], &[], false), "d3d9");
    assert_eq!(
        shown(&["d3d9.dll", "d3d11.dll", "dxgi.dll"], &[], false),
        "d3d11 (also d3d9)"
    );
    assert_eq!(
        shown(&["ddraw.dll", "d3d8.dll", "d3d9.dll"], &[], false),
        "d3d9 (also ddraw, d3d8)"
    );
    assert_eq!(shown(&[], &["d3d9.dll"], false), "d3d9 (delay-loaded)");
    assert_eq!(
        shown(&["d3dx9_43.dll"], &[], false),
        "d3d9 (helper DLL only)"
    );
    assert_eq!(
        shown(&["opengl32.dll", "d3d9.dll"], &[], false),
        "several: d3d9, opengl"
    );
    assert_eq!(
        shown(&["dxgi.dll"], &[], false),
        "dxgi only (Direct3D version chosen at runtime)"
    );
    assert_eq!(
        shown(&["UnityPlayer.dll"], &[], false),
        "renderer in a DLL (Unity, UnityPlayer.dll)"
    );
    assert_eq!(
        shown(&["Core.dll", "Engine.dll"], &[], false),
        "renderer in a DLL (Unreal Engine 1/2, Engine.dll)"
    );
    assert_eq!(shown(&[], &[], true), ".NET, no graphics import");
    assert_eq!(shown(&[], &[], false), "unknown (no graphics import)");
}

#[test]
fn strengths() {
    let strength = |imports: &[&str], delay: &[&str], managed| {
        classify(&dlls(imports), &dlls(delay), managed)
            .verdict
            .strength()
    };
    assert_eq!(strength(&["d3d9.dll"], &[], false), 5);
    assert_eq!(strength(&["d3d9.dll", "d3d11.dll"], &[], false), 4);
    assert_eq!(strength(&[], &["d3d9.dll"], false), 3);
    assert_eq!(strength(&["d3dx9_43.dll"], &[], false), 3);
    assert_eq!(strength(&["d3d9.dll", "opengl32.dll"], &[], false), 3);
    assert_eq!(strength(&["dxgi.dll"], &[], false), 2);
    assert_eq!(strength(&["UnityPlayer.dll"], &[], false), 2);
    assert_eq!(strength(&[], &[], true), 2);
    assert_eq!(strength(&[], &[], false), 0);
}

#[test]
fn topo_names_and_spellings() {
    let names: Vec<&str> = A::ALL.iter().map(|a| a.as_str()).collect();
    assert_eq!(
        names,
        [
            "ddraw", "d3d8", "d3d9", "d3d10", "d3d11", "d3d12", "opengl", "vulkan", "glide"
        ]
    );
    for a in A::ALL {
        let reserved = matches!(a, A::D3d12 | A::Vulkan | A::Glide);
        assert_eq!(a.topo_name().is_none(), reserved, "{a}");
        if let Some(t) = a.topo_name() {
            assert_eq!(t, a.as_str());
        }
        assert_eq!(a.is_direct3d(), a <= A::D3d12, "{a}");
    }
    assert_eq!(only(A::D3d9).api(), Some(A::D3d9));
    assert_eq!(ApiVerdict::DxgiOnly.api(), None);
}
