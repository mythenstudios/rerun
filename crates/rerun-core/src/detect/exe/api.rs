//! The graphics API from the imported DLL names (ADR 0014, "Graphics API"). Pure: no I/O.
//!
//! DLL names compare ASCII case-insensitively and exactly (no substring); duplicates count
//! once. The mapping is a heuristic with names in it, provisional until the developer-machine
//! dump (ADR 0014). Engine DLLs are not parsed (user decision 3).

use std::collections::BTreeSet;
use std::fmt;

use crate::detect::pe::DllName;

/// A graphics API detection can name. Ordered: the Direct3D family from `ddraw` to `d3d12`,
/// then `opengl`, `vulkan`, `glide`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GraphicsApi {
    /// DirectDraw, also Direct3D 7 and older.
    Ddraw,
    /// Direct3D 8.
    D3d8,
    /// Direct3D 9.
    D3d9,
    /// Direct3D 10 and 10.1.
    D3d10,
    /// Direct3D 11.
    D3d11,
    /// Direct3D 12.
    D3d12,
    /// OpenGL.
    Opengl,
    /// Vulkan.
    Vulkan,
    /// 3dfx Glide.
    Glide,
}

impl GraphicsApi {
    /// Every API, in order.
    pub const ALL: [Self; 9] = [
        Self::Ddraw,
        Self::D3d8,
        Self::D3d9,
        Self::D3d10,
        Self::D3d11,
        Self::D3d12,
        Self::Opengl,
        Self::Vulkan,
        Self::Glide,
    ];

    /// The spelling for output; for the Topo APIs the same as [`Self::topo_name`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ddraw => "ddraw",
            Self::D3d8 => "d3d8",
            Self::D3d9 => "d3d9",
            Self::D3d10 => "d3d10",
            Self::D3d11 => "d3d11",
            Self::D3d12 => "d3d12",
            Self::Opengl => "opengl",
            Self::Vulkan => "vulkan",
            Self::Glide => "glide",
        }
    }

    /// The Topo `api` value (`$defs/api` of both schemas), or `None` for `d3d12`, `vulkan`
    /// and `glide`: their spellings are reserved for an additive schema extension (ADR 0014,
    /// user decision 1).
    pub fn topo_name(self) -> Option<&'static str> {
        match self {
            Self::D3d12 | Self::Vulkan | Self::Glide => None,
            other => Some(other.as_str()),
        }
    }

    /// Direct3D family (`ddraw` to `d3d12`); its members compare by version.
    pub fn is_direct3d(self) -> bool {
        self <= Self::D3d12
    }
}

impl fmt::Display for GraphicsApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of APIs, in order.
pub type ApiSet = BTreeSet<GraphicsApi>;

/// An engine whose renderer lives in a DLL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Engine {
    /// Unity (`UnityPlayer.dll`).
    Unity,
    /// Unreal Engine 1 or 2 (`Core.dll` together with `Engine.dll`).
    UnrealClassic,
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unity => "Unity, UnityPlayer.dll",
            Self::UnrealClassic => "Unreal Engine 1/2, Engine.dll",
        })
    }
}

/// Where the core or helper imports of a verdict come from; decides the ranking strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// The static core imports.
    Static,
    /// The delay-load core imports (no static core import).
    Delay,
    /// Helper DLLs of either table (no core import).
    Helper,
}

impl Basis {
    /// The table the basis comes from.
    pub fn source(self) -> Source {
        match self {
            Self::Only | Self::HighestD3d => Source::Static,
            Self::DelayOnly => Source::Delay,
            Self::Helper => Source::Helper,
        }
    }
}

/// What a single API verdict rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Basis {
    /// Exactly one API among the static core imports.
    Only,
    /// Several Direct3D versions among the static core imports; the highest wins (user
    /// decision 2).
    HighestD3d,
    /// No static core import; from the delay-load core imports.
    DelayOnly,
    /// No core import; from helper DLLs (`d3dx9_43.dll`, `glu32.dll`).
    Helper,
}

/// The verdict (ADR 0014, rules 1 to 6, first that applies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiVerdict {
    /// One API.
    One {
        /// The API.
        api: GraphicsApi,
        /// What it rests on.
        basis: Basis,
    },
    /// APIs of more than one family (`opengl` next to Direct3D, …), no winner.
    Several {
        /// The APIs.
        apis: ApiSet,
        /// The table they come from.
        from: Source,
    },
    /// Only `dxgi.dll`: the Direct3D version is loaded at runtime, never guessed.
    DxgiOnly,
    /// The renderer lives in an engine DLL, which is not parsed.
    RendererInDll(Engine),
    /// A .NET image without a graphics import.
    Managed,
    /// No graphics import: packed or DRM stubs, renderers loaded with `LoadLibrary`.
    None,
}

impl ApiVerdict {
    /// Ranking strength by where the evidence comes from (ADR 0014, "Ranking"): 3 static core
    /// imports (`One` with any static basis, `Several` from the static table), 2 delay core
    /// imports, 1 helper DLLs, `DxgiOnly` and `RendererInDll`, 0 `Managed` and `None`. The
    /// verdict itself (`HighestD3d`, user decision 2) does not change the strength.
    pub fn strength(&self) -> u8 {
        let source = match self {
            Self::One { basis, .. } => basis.source(),
            Self::Several { from, .. } => *from,
            Self::DxgiOnly | Self::RendererInDll(_) => return 1,
            Self::Managed | Self::None => return 0,
        };
        match source {
            Source::Static => 3,
            Source::Delay => 2,
            Source::Helper => 1,
        }
    }

    /// The single API, if the verdict names one.
    pub fn api(&self) -> Option<GraphicsApi> {
        match self {
            Self::One { api, .. } => Some(*api),
            _ => None,
        }
    }
}

/// What one import table holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableEvidence {
    /// APIs of core DLLs (`d3d9.dll`, `opengl32.dll`, …).
    pub core: ApiSet,
    /// APIs of helper DLLs (`d3dx9_43.dll`, `glu32.dll`, …).
    pub helper: ApiSet,
    /// `dxgi.dll`.
    pub dxgi: bool,
}

/// The evidence of a verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiEvidence {
    /// The static import table.
    pub imports: TableEvidence,
    /// The delay-import table.
    pub delay: TableEvidence,
    /// An engine DLL in either table.
    pub engine: Option<Engine>,
    /// The image is .NET (CLR header present).
    pub managed: bool,
}

/// The verdict and its evidence. `Display` shows both briefly (`d3d11 (also d3d9)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiReport {
    /// The verdict.
    pub verdict: ApiVerdict,
    /// What it rests on.
    pub evidence: ApiEvidence,
}

impl fmt::Display for ApiReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.verdict {
            ApiVerdict::One { api, basis } => {
                write!(f, "{api}")?;
                let ev = &self.evidence;
                let helpers: ApiSet = ev.imports.helper.union(&ev.delay.helper).copied().collect();
                let (set, what) = match basis {
                    Basis::Only | Basis::HighestD3d => (&ev.imports.core, None),
                    Basis::DelayOnly => (&ev.delay.core, Some("delay-loaded")),
                    Basis::Helper => (&helpers, Some("helper DLL only")),
                };
                let others: Vec<&str> = set
                    .iter()
                    .filter(|a| *a != api)
                    .map(|a| a.as_str())
                    .collect();
                let also = (!others.is_empty()).then(|| format!("also {}", others.join(", ")));
                let parts: Vec<String> = what.map(str::to_owned).into_iter().chain(also).collect();
                if parts.is_empty() {
                    Ok(())
                } else {
                    write!(f, " ({})", parts.join(", "))
                }
            }
            ApiVerdict::Several { apis: set, .. } => {
                let all: Vec<&str> = set.iter().map(|a| a.as_str()).collect();
                write!(f, "several: {}", all.join(", "))
            }
            ApiVerdict::DxgiOnly => f.write_str("dxgi only (Direct3D version chosen at runtime)"),
            ApiVerdict::RendererInDll(engine) => write!(f, "renderer in a DLL ({engine})"),
            ApiVerdict::Managed => f.write_str(".NET, no graphics import"),
            ApiVerdict::None => f.write_str("unknown (no graphics import)"),
        }
    }
}

/// What a DLL name means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Meaning {
    Core(GraphicsApi),
    Helper(GraphicsApi),
    Dxgi,
    Unity,
    UnrealCore,
    UnrealEngine,
}

/// `name` is `prefix` followed by exactly two ASCII digits and `.dll`.
fn two_digits(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(".dll"))
        .is_some_and(|d| d.len() == 2 && d.bytes().all(|b| b.is_ascii_digit()))
}

/// The meaning of one DLL name (ADR 0014 table), `None` for everything else.
fn meaning(dll: &DllName) -> Option<Meaning> {
    use GraphicsApi as A;
    let name = dll.as_str().to_ascii_lowercase();
    let m = match name.as_str() {
        "ddraw.dll" => Meaning::Core(A::Ddraw),
        "d3d8.dll" => Meaning::Core(A::D3d8),
        "d3d9.dll" => Meaning::Core(A::D3d9),
        "d3d10.dll" | "d3d10_1.dll" => Meaning::Core(A::D3d10),
        "d3d11.dll" => Meaning::Core(A::D3d11),
        "d3d12.dll" => Meaning::Core(A::D3d12),
        "opengl32.dll" => Meaning::Core(A::Opengl),
        "vulkan-1.dll" => Meaning::Core(A::Vulkan),
        "glide.dll" | "glide2x.dll" | "glide3x.dll" => Meaning::Core(A::Glide),
        "d3dx10.dll" => Meaning::Helper(A::D3d10),
        "d3drm.dll" | "d3dim.dll" | "d3dim700.dll" => Meaning::Helper(A::Ddraw),
        "glu32.dll" => Meaning::Helper(A::Opengl),
        "dxgi.dll" => Meaning::Dxgi,
        "unityplayer.dll" => Meaning::Unity,
        "core.dll" => Meaning::UnrealCore,
        "engine.dll" => Meaning::UnrealEngine,
        n if two_digits(n, "d3dx9_") => Meaning::Helper(A::D3d9),
        n if two_digits(n, "d3dx10_") => Meaning::Helper(A::D3d10),
        n if two_digits(n, "d3dx11_") => Meaning::Helper(A::D3d11),
        _ => return None,
    };
    Some(m)
}

/// Engine flags seen in a table.
#[derive(Debug, Default, Clone, Copy)]
struct EngineSeen {
    unity: bool,
    unreal_core: bool,
    unreal_engine: bool,
}

fn table(dlls: &[DllName], engine: &mut EngineSeen) -> TableEvidence {
    let mut t = TableEvidence::default();
    for dll in dlls {
        match meaning(dll) {
            Some(Meaning::Core(api)) => {
                t.core.insert(api);
            }
            Some(Meaning::Helper(api)) => {
                t.helper.insert(api);
            }
            Some(Meaning::Dxgi) => t.dxgi = true,
            Some(Meaning::Unity) => engine.unity = true,
            Some(Meaning::UnrealCore) => engine.unreal_core = true,
            Some(Meaning::UnrealEngine) => engine.unreal_engine = true,
            None => {}
        }
    }
    t
}

/// One API, the highest Direct3D version, or several families; `None` for an empty set.
fn decide(set: &ApiSet, basis: Basis) -> Option<ApiVerdict> {
    let from = basis.source();
    let highest = *set.last()?;
    if set.len() == 1 {
        return Some(ApiVerdict::One {
            api: highest,
            basis,
        });
    }
    if set.iter().all(|a| a.is_direct3d()) {
        // `HighestD3d` only where it is the basis itself (static core imports); the delay and
        // helper rules keep their own basis.
        let basis = if basis == Basis::Only {
            Basis::HighestD3d
        } else {
            basis
        };
        return Some(ApiVerdict::One {
            api: highest,
            basis,
        });
    }
    Some(ApiVerdict::Several {
        apis: set.clone(),
        from,
    })
}

/// The verdict on the static imports `imports`, the delay imports `delay` and the CLR flag.
pub(crate) fn classify(imports: &[DllName], delay: &[DllName], managed: bool) -> ApiReport {
    let mut seen = EngineSeen::default();
    let evidence_imports = table(imports, &mut seen);
    let evidence_delay = table(delay, &mut seen);
    let engine = if seen.unity {
        Some(Engine::Unity)
    } else if seen.unreal_core && seen.unreal_engine {
        Some(Engine::UnrealClassic)
    } else {
        None
    };
    let helpers: ApiSet = evidence_imports
        .helper
        .union(&evidence_delay.helper)
        .copied()
        .collect();
    let verdict = decide(&evidence_imports.core, Basis::Only)
        .or_else(|| decide(&evidence_delay.core, Basis::DelayOnly))
        .or_else(|| decide(&helpers, Basis::Helper))
        .or_else(|| (evidence_imports.dxgi || evidence_delay.dxgi).then_some(ApiVerdict::DxgiOnly))
        .or_else(|| engine.map(ApiVerdict::RendererInDll))
        .unwrap_or(if managed {
            ApiVerdict::Managed
        } else {
            ApiVerdict::None
        });
    ApiReport {
        verdict,
        evidence: ApiEvidence {
            imports: evidence_imports,
            delay: evidence_delay,
            engine,
            managed,
        },
    }
}

#[cfg(test)]
mod tests;
