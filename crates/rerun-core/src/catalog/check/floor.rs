//! The floor of an entry (ADR 0024 amendment "Forward compatibility" §5): the lowest entry
//! format its content needs, and the field path of the first feature that needs it.
//!
//! Every struct of the model is destructured without `..` and every enum matched without `_`,
//! so a new field, step kind or enum value does not compile until its format is decided here.
//! That holds for a nested type only if it has its own function below that the entry's function
//! reaches (`dead_code` under `-D warnings` catches one nothing calls). Format 1 is frozen with
//! the first release (A6): until then every feature is format 1 and needs no line of its own.
//!
//! What the compiler cannot force (the `new-primitive` checklist, review only): serde attributes
//! that change what parses without changing a type (`default` on a required field, `alias`,
//! `rename`, `untagged`, `flatten`); the `try_from = "String"` types (`Id`, `RelPath`,
//! `ArchIdText`, `Hex`, `TodoMark`); the patterns, allowlists and limits of `catalog::check`;
//! the planners' own rules (the compatibility-layer token allowlist); gates (`*_REVIEWED`) and
//! relaxed limits. Each needs its line here by hand when it is loosened after A6.

use std::collections::BTreeMap;

use crate::catalog::model::{
    AntiCheatRelease, Api, Arch, ArchList, Asset, Chain, Check, Compare, Exe, Fallback,
    FirewallRuleSpec, GpuRequirement, Issue, Kind, LaaPatchStep, Launch, Links, Match, Method,
    Note, OptionIni, OptionValue, Package, PackageFile, PackageOption, PackageSource, Platform,
    Runtime, Source, SourceType, Status, SteamInput, Tier, Tips, Topo, TopoStep, Variant,
    VariantStatus, Vendor, When,
};
use crate::detect::exe::AntiCheat;
use crate::policy::firewall::Direction;
use crate::policy::registry::GpuPref;
use crate::prim::{
    CompatLayerSpec, CpuRuleSpec, ExcludeFirstSpec, GpuPreferenceSpec, IniSetSpec, IniSetValue,
    ModeSpec, PreferL3Spec, PreferSpec, PrioritySpec, RegValueEntry, RegistrySetSpec, StepRoot,
    UserDataSpec,
};

/// The lowest entry format an entry's content needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Floor {
    /// The format.
    pub format: u32,
    /// The field path of the first feature that needs it (`format` for format 1: the entry
    /// itself).
    pub at: &'static str,
}

impl Floor {
    /// Format 1: what every entry needs.
    pub const BASE: Self = Self {
        format: 1,
        at: "format",
    };

    /// The higher of both; on a tie the first.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        if other.format > self.format {
            other
        } else {
            self
        }
    }
}

/// Format 1 (every feature until the first release, §4).
const F1: Floor = Floor::BASE;

fn all<T>(items: impl IntoIterator<Item = T>, f: impl Fn(T) -> Floor) -> Floor {
    items.into_iter().map(f).fold(F1, Floor::max)
}

fn opt<T>(item: Option<T>, f: impl Fn(T) -> Floor) -> Floor {
    item.map_or(F1, f)
}

// ---------- Topo ----------

/// The floor of a Topo.
pub fn topo_floor(t: &Topo) -> Floor {
    let Topo {
        format: _,
        id: _,
        title: _,
        status,
        rev: _,
        tested_on,
        matches,
        launch,
        anti_cheat,
        user_data,
        issues,
        tips,
        links,
    } = t;
    F1.max(status_floor(*status))
        .max(all(tested_on, |p| platform(*p)))
        .max(match_floor(matches))
        .max(opt(launch.as_ref(), launch_floor))
        .max(opt(anti_cheat.as_ref(), anti_cheat_release))
        .max(opt(user_data.as_ref(), user_data_floor))
        .max(all(issues, issue))
        .max(opt(tips.as_ref(), tips_floor))
        .max(opt(links.as_ref(), links_floor))
}

fn status_floor(s: Status) -> Floor {
    match s {
        Status::Draft | Status::Active | Status::NeedsRetest | Status::Retired => F1,
    }
}

fn platform(p: Platform) -> Floor {
    match p {
        Platform::X64 | Platform::Arm64 => F1,
    }
}

fn match_floor(m: &Match) -> Floor {
    let Match {
        steam_appid: _,
        exes,
    } = m;
    all(exes, exe)
}

fn exe(e: &Exe) -> Floor {
    let Exe {
        path: _,
        sha1: _,
        sha256: _,
        api: a,
    } = e;
    api(*a)
}

fn api(a: Api) -> Floor {
    match a {
        Api::Ddraw | Api::D3d8 | Api::D3d9 | Api::D3d10 | Api::D3d11 | Api::Opengl => F1,
    }
}

fn launch_floor(l: &Launch) -> Floor {
    let Launch {
        chain: c,
        method,
        fallback,
        cpu,
        start: _,
        priority,
    } = l;
    all(c, |x| chain(*x))
        .max(opt(*method, method_floor))
        .max(opt(*fallback, fallback_floor))
        .max(opt(cpu.as_ref(), cpu_rule))
        .max(opt(*priority, priority_floor))
}

fn chain(c: Chain) -> Floor {
    match c {
        Chain::Steam
        | Chain::Upc
        | Chain::EaApp
        | Chain::Rockstar
        | Chain::Battlenet
        | Chain::Epic
        | Chain::GogGalaxy => F1,
    }
}

fn method_floor(m: Method) -> Floor {
    match m {
        Method::Auto
        | Method::Direct
        | Method::Watch
        | Method::Hold
        | Method::Ifeo
        | Method::Inproc => F1,
    }
}

fn fallback_floor(f: Fallback) -> Floor {
    match f {
        Fallback::Direct | Fallback::Watch | Fallback::Hold | Fallback::Ifeo | Fallback::Inproc => {
            F1
        }
    }
}

fn priority_floor(p: PrioritySpec) -> Floor {
    match p {
        PrioritySpec::Normal | PrioritySpec::AboveNormal | PrioritySpec::High => F1,
    }
}

fn cpu_rule(c: &CpuRuleSpec) -> Floor {
    let CpuRuleSpec {
        max_threads: _,
        prefer,
        single_l3: _,
        prefer_l3,
        smt: _,
        mode,
        exclude_first,
        report_cores: _,
    } = c;
    opt(*prefer, |p| match p {
        PreferSpec::Performance | PreferSpec::Any => F1,
    })
    .max(opt(*prefer_l3, |p| match p {
        PreferL3Spec::Largest => F1,
    }))
    .max(opt(*mode, |m| match m {
        ModeSpec::Hard | ModeSpec::Soft => F1,
    }))
    .max(opt(*exclude_first, |e| match e {
        ExcludeFirstSpec::Thread | ExcludeFirstSpec::Core => F1,
    }))
}

fn anti_cheat_release(a: &AntiCheatRelease) -> Floor {
    let AntiCheatRelease { dead, source: s } = a;
    all(dead, |d| anti_cheat(*d)).max(source(s))
}

fn anti_cheat(a: AntiCheat) -> Floor {
    match a {
        AntiCheat::EasyAntiCheat
        | AntiCheat::Battleye
        | AntiCheat::Punkbuster
        | AntiCheat::Gameguard
        | AntiCheat::Xigncode
        | AntiCheat::EaAnticheat => F1,
    }
}

fn user_data_floor(u: &UserDataSpec) -> Floor {
    match u {
        UserDataSpec::Documents(_) => F1,
    }
}

fn source(s: &Source) -> Floor {
    let Source { kind, url: _ } = s;
    match kind {
        SourceType::Repo
        | SourceType::SteamGuide
        | SourceType::SteamThread
        | SourceType::Pcgw
        | SourceType::Official => F1,
    }
}

fn issue(i: &Issue) -> Floor {
    let Issue {
        id: _,
        title: _,
        when,
        checks,
        variants,
    } = i;
    opt(when.as_ref(), when_floor)
        .max(all(checks, check))
        .max(all(variants, variant))
}

fn when_floor(w: &When) -> Floor {
    let When {
        gpu_vendor,
        gpu_arch: _,
        gpu_integrated: _,
        gpu_hybrid: _,
        cpu_threads,
        cpu_hybrid: _,
        os_build,
    } = w;
    opt(*gpu_vendor, vendor)
        .max(opt(cpu_threads.as_ref(), compare))
        .max(opt(os_build.as_ref(), compare))
}

fn vendor(v: Vendor) -> Floor {
    match v {
        Vendor::Amd | Vendor::Nvidia | Vendor::Intel => F1,
    }
}

fn compare(c: &Compare) -> Floor {
    let Compare {
        gt: _,
        gte: _,
        lt: _,
        lte: _,
        eq: _,
    } = c;
    F1
}

fn check(c: &Check) -> Floor {
    let Check { runtime } = c;
    match runtime {
        Runtime::VcredistX86 | Runtime::VcredistX64 | Runtime::DirectxJun2010 => F1,
    }
}

fn variant(v: &Variant) -> Floor {
    let Variant {
        id: _,
        status,
        kind: k,
        steps,
        tradeoffs: _,
        sources,
    } = v;
    let s = match status {
        VariantStatus::Verified | VariantStatus::Reported | VariantStatus::Unverified => F1,
    };
    s.max(kind(*k))
        .max(all(steps, step))
        .max(all(sources, source))
}

fn kind(k: Kind) -> Floor {
    match k {
        Kind::Fix | Kind::Enhancement => F1,
    }
}

fn step(s: &TopoStep) -> Floor {
    match s {
        TopoStep::Package(_) => F1,
        TopoStep::SteamInput(i) => match i {
            SteamInput::Enable => F1,
        },
        TopoStep::Cpu(c) => cpu_rule(c),
        TopoStep::RegistrySet(r) => registry_set(r),
        TopoStep::CompatLayer(c) => compat_layer(c),
        TopoStep::IniSet(i) => ini_set(i),
        TopoStep::FirewallRule(f) => firewall_rule(f),
        TopoStep::LaaPatch(l) => laa_patch(l),
        TopoStep::GpuPreference(g) => gpu_preference(g),
    }
}

fn registry_set(r: &RegistrySetSpec) -> Floor {
    let RegistrySetSpec { key: _, values } = r;
    all(values, |v| {
        let RegValueEntry {
            name: _,
            dword: _,
            qword: _,
            sz: _,
        } = v;
        F1
    })
}

fn compat_layer(c: &CompatLayerSpec) -> Floor {
    // The tokens' allowlist is the planner's (`policy::registry::layers`): a token newly allowed
    // after A6 needs a line here by hand (the token set of each format).
    let CompatLayerSpec { exe: _, layers: _ } = c;
    F1
}

fn ini_set(i: &IniSetSpec) -> Floor {
    let IniSetSpec {
        root,
        file: _,
        values,
    } = i;
    let r = match root {
        StepRoot::Game | StepRoot::UserData => F1,
    };
    r.max(all(values, |v| {
        let IniSetValue {
            section: _,
            key: _,
            value: _,
        } = v;
        F1
    }))
}

fn firewall_rule(f: &FirewallRuleSpec) -> Floor {
    let FirewallRuleSpec { exe: _, direction } = f;
    match direction {
        Direction::Out => F1,
    }
}

fn laa_patch(l: &LaaPatchStep) -> Floor {
    let LaaPatchStep { exe: _ } = l;
    F1
}

fn gpu_preference(g: &GpuPreferenceSpec) -> Floor {
    let GpuPreferenceSpec { exe: _, preference } = g;
    match preference {
        GpuPref::HighPerformance => F1,
    }
}

fn tips_floor(t: &Tips) -> Floor {
    let Tips {
        launch_options: _,
        notes,
    } = t;
    all(notes, |n| {
        let Note { text: _, source: s } = n;
        opt(s.as_ref(), source)
    })
}

fn links_floor(l: &Links) -> Floor {
    let Links { pcgw: _ } = l;
    F1
}

// ---------- Package ----------

/// The floor of a package.
pub fn package_floor(p: &Package) -> Floor {
    let Package {
        format: _,
        id: _,
        name: _,
        status,
        tier,
        source,
        version: _,
        sha256: _,
        assets,
        license: _,
        arch,
        apis,
        slots: _,
        slots_by_api,
        requires: _,
        requires_gpu,
        supports_exe_sha1: _,
        files,
        options,
    } = p;
    F1.max(status_floor(*status))
        .max(tier_floor(*tier))
        .max(package_source(source))
        .max(opt(assets.as_ref(), |a| all(a, asset)))
        .max(arch_list(arch))
        .max(opt(apis.as_ref(), |a| all(a, |x| api(*x))))
        .max(opt(slots_by_api.as_ref(), slots_by_api_floor))
        .max(all(requires_gpu, |g| match g {
            GpuRequirement::Vulkan => F1,
        }))
        .max(all(files, file))
        .max(all(options.values(), option))
}

fn tier_floor(t: Tier) -> Floor {
    match t {
        Tier::Official | Tier::Established | Tier::Community => F1,
    }
}

fn package_source(s: &PackageSource) -> Floor {
    let PackageSource {
        repo: _,
        page: _,
        release: _,
    } = s;
    F1
}

fn asset(a: &Asset) -> Floor {
    let Asset {
        arch: a,
        url: _,
        sha256: _,
    } = a;
    arch_floor(*a)
}

fn arch_floor(a: Arch) -> Floor {
    match a {
        Arch::X86 | Arch::X64 => F1,
    }
}

fn arch_list(a: &ArchList) -> Floor {
    match a {
        ArchList::List(l) => all(l, |x| arch_floor(*x)),
        ArchList::Todo(_) => F1,
    }
}

fn slots_by_api_floor(m: &BTreeMap<Api, Vec<String>>) -> Floor {
    all(m.keys(), |a| api(*a))
}

fn file(f: &PackageFile) -> Floor {
    let PackageFile {
        from: _,
        to: _,
        sha256: _,
        config: _,
        arch,
        api: apis,
    } = f;
    opt(arch.as_ref(), |a| all(a, |x| arch_floor(*x)))
        .max(opt(apis.as_ref(), |a| all(a, |x| api(*x))))
}

fn option(o: &PackageOption) -> Floor {
    let PackageOption {
        ini,
        default,
        kind: k,
    } = o;
    let OptionIni {
        file: _,
        section: _,
        key: _,
    } = ini;
    let d = match default {
        OptionValue::Bool(_) | OptionValue::Int(_) | OptionValue::Text(_) => F1,
    };
    d.max(opt(*k, kind))
}
