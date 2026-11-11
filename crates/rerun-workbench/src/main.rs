//! `rerun-workbench` – the curator tool (phase 4), never shipped (ADR 0024).
//!
//! - `index build --seq <n> --issued <YYYY-MM-DDTHH:MM:SSZ> [--root <repo>] <out>`: the YAML of
//!   `topos/` and `packages/` into the canonical bundle `index.json` (drafts left out).
//! - `index sign <bundle> <private-key>`: writes `<bundle>.sig` (64 raw bytes).
//! - `index sign-test <bundle>` (feature `test-key` only; ADR 0024 amendment P4-13): the same
//!   with the published test key, for the [DEV] test-key `rerun.exe` and its `index-test`.
//! - `key generate <out-dir>`: a new index key pair, never inside a Git working tree.
//! - `draft <steam-appid|pcgw-page> [--page <name>] [--id <id>] [--title <text>] [--into <dir>]`:
//!   a Topo draft from PCGamingWiki, the only command that goes online (at most two GETs to
//!   `www.pcgamingwiki.com`, ADR 0024 amendment P4-14); YAML on stdout, or a new
//!   `<dir>\<id>.yaml`. It never reads a key file. `--hashes-from <game folder>` takes the
//!   executables and their hashes from a local copy of the game (read only).
//!
//! `main` restricts the DLL search path first (ADR 0008; WinHTTP refuses without it).
//! A curator tool reads and writes the files it is pointed at with `std::fs` (the system layer
//! of `rerun-core` is for the shipped program, ADR 0004).

#![expect(
    clippy::disallowed_methods,
    reason = "curator tool, not shipped: reads the repository and writes files the curator names"
)]

#[cfg(windows)]
mod acl;
mod bundle;
mod draft;
mod keys;
mod local;
mod pcgw;
mod wikitext;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Rerun curator tool: builds and signs the Topo index, drafts Topos from PCGamingWiki.
#[derive(Debug, Parser)]
#[command(name = "rerun-workbench", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// The signed Topo index.
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },
    /// The index signing key.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// A Topo draft from a PCGamingWiki page (online: www.pcgamingwiki.com only).
    Draft(DraftArgs),
}

#[derive(Debug, clap::Args)]
struct DraftArgs {
    /// A Steam app ID (digits only) or a PCGamingWiki page name.
    #[arg(required_unless_present = "page", conflicts_with = "page")]
    target: Option<String>,
    /// A page name, also one of digits only.
    #[arg(long)]
    page: Option<String>,
    /// The Topo ID (default: from the page name).
    #[arg(long)]
    id: Option<String>,
    /// The title (default: the page name).
    #[arg(long)]
    title: Option<String>,
    /// Writes <dir>\<id>.yaml (never over a file) instead of printing the YAML.
    #[arg(long)]
    into: Option<PathBuf>,
    /// The executables and their hashes from this local copy of the game (absolute path; read
    /// only; verify the game files in Steam first).
    #[arg(long)]
    hashes_from: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum IndexCommand {
    /// Builds index.json from topos/ and packages/ (drafts are left out).
    Build {
        /// The sequence number, higher than every index published before.
        #[arg(long)]
        seq: u64,
        /// When it is issued, YYYY-MM-DDTHH:MM:SSZ (UTC).
        #[arg(long)]
        issued: String,
        /// The repository (default: the current folder).
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// Where to write index.json.
        out: PathBuf,
    },
    /// Signs a built index.json; writes <bundle>.sig next to it.
    Sign {
        /// The index.json to sign.
        bundle: PathBuf,
        /// The private key file (outside any Git working tree).
        key: PathBuf,
    },
    /// Signs a built index.json with the published test key (DEV only: trusted by test-key
    /// builds alone); writes <bundle>.sig next to it.
    #[cfg(feature = "test-key")]
    SignTest {
        /// The index.json to sign.
        bundle: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Generates a key pair into a folder outside any Git working tree.
    Generate {
        /// An existing folder (offline storage).
        out_dir: PathBuf,
    },
}

fn main() -> ExitCode {
    #[cfg(windows)]
    if let Err(e) = rerun_core::sys::win::restrict_dll_search() {
        eprintln!("rerun-workbench: the DLL search path: {e}");
        return ExitCode::FAILURE;
    }
    let cli = Cli::parse();
    let r = match cli.command {
        Command::Index {
            command:
                IndexCommand::Build {
                    seq,
                    issued,
                    root,
                    out,
                },
        } => build(&root, seq, &issued, &out),
        Command::Index {
            command: IndexCommand::Sign { bundle, key },
        } => sign(&bundle, &key),
        #[cfg(feature = "test-key")]
        Command::Index {
            command: IndexCommand::SignTest { bundle },
        } => sign_test(&bundle),
        Command::Key {
            command: KeyCommand::Generate { out_dir },
        } => generate(&out_dir),
        Command::Draft(args) => draft_cmd(&args),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rerun-workbench: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The `*.yaml` files of `dir`, sorted by name.
fn sources(dir: &Path) -> Result<Vec<bundle::SourceFile>, String> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let p = e.map_err(|e| e.to_string())?.path();
        if p.extension().is_some_and(|x| x == "yaml") {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| format!("{}: not a UTF-8 name", p.display()))?
                .to_owned();
            let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            v.push(bundle::SourceFile { name, text });
        }
    }
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(v)
}

fn build(root: &Path, seq: u64, issued: &str, out: &Path) -> Result<(), String> {
    let b = bundle::build(
        &sources(&root.join("topos"))?,
        &sources(&root.join("packages"))?,
        seq,
        issued,
    )?;
    fs::write(out, &b.bytes).map_err(|e| format!("{}: {e}", out.display()))?;
    for x in &b.excluded {
        println!("left out (draft): {x}");
    }
    println!(
        "{}: seq {}, {} topos, {} packages, {} bytes",
        out.display(),
        b.index.seq,
        b.index.topos.len(),
        b.index.packages.len(),
        b.bytes.len()
    );
    Ok(())
}

fn sign(bundle: &Path, key: &Path) -> Result<(), String> {
    let folder = key
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    keys::outside_repo(folder)?;
    let kp =
        keys::parse_key(&fs::read_to_string(key).map_err(|e| format!("{}: {e}", key.display()))?)?;
    let bytes = fs::read(bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
    let s = keys::sign(&bytes, &kp)?;
    write_sig(bundle, &s)
}

/// `index sign-test`: like [`sign`] with the published test key instead of a key file (the
/// same release rules, so a draft or a `TODO` is refused), verified back under that key.
#[cfg(feature = "test-key")]
fn sign_test(bundle: &Path) -> Result<(), String> {
    let bytes = fs::read(bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
    let s = keys::sign_test(&bytes)?;
    write_sig(bundle, &s)
}

/// Writes `<bundle>.sig` and the line naming what was signed.
fn write_sig(bundle: &Path, s: &keys::Signed) -> Result<(), String> {
    let mut out = bundle.as_os_str().to_owned();
    out.push(".sig");
    let out = PathBuf::from(out);
    fs::write(&out, s.sig).map_err(|e| format!("{}: {e}", out.display()))?;
    println!(
        "{}: seq {}, sha256 {}, key {}",
        out.display(),
        s.seq,
        s.sha256,
        s.key.id()
    );
    Ok(())
}

/// Creates `path` (never replacing a file) with `text`. `secret`: the empty file gets an
/// owner-only protected DACL before anything is written (ADR 0024); if that fails, the empty
/// file is removed again.
fn create_new(path: &Path, text: &str, secret: bool) -> Result<(), String> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(windows)]
    if secret {
        use std::os::windows::fs::OpenOptionsExt;
        opts.access_mode(acl::KEY_FILE_ACCESS);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if secret {
        #[cfg(windows)]
        let protected = acl::owner_only(&f);
        #[cfg(not(windows))]
        let protected: Result<(), String> = Err("a private key is written on Windows only".into());
        if let Err(e) = protected {
            drop(f);
            let _ = fs::remove_file(path);
            return Err(format!("{}: {e}", path.display()));
        }
    }
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The request of `draft`, checked before any request is made.
fn draft_request(a: &DraftArgs) -> Result<draft::Request, String> {
    use rerun_core::catalog::model::Id;
    let target = match (a.target.as_deref().map(str::trim), &a.page) {
        (_, Some(p)) => pcgw::Target::Page(pcgw::PageName::parse(p).map_err(|e| e.to_string())?),
        (Some(t), None) if !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit()) => {
            match t.parse::<u32>() {
                Ok(n) if n >= 1 => pcgw::Target::SteamApp(n),
                _ => return Err("a Steam app ID is 1 to 4294967295".into()),
            }
        }
        (Some(t), None) => pcgw::Target::Page(pcgw::PageName::parse(t).map_err(|e| e.to_string())?),
        (None, None) => return Err("name a Steam app ID or a page".into()),
    };
    let id = match &a.id {
        Some(s) => Some(Id::parse(s).ok_or("--id: a-z, 0-9 and single hyphens, at most 64")?),
        None => None,
    };
    if let Some(t) = &a.title {
        draft::check_title(t).ok_or(
            "--title: 1 to 200 characters, none of them control, format or bidi characters",
        )?;
    }
    if let Some(dir) = &a.into
        && !fs::metadata(dir).is_ok_and(|m| m.is_dir())
    {
        return Err(format!("--into {}: not a folder", dir.display()));
    }
    let local = match &a.hashes_from {
        None => None,
        Some(f) if !f.is_absolute() => {
            return Err("--hashes-from: an absolute path".into());
        }
        Some(f) => Some(hashes_from(f)?),
    };
    Ok(draft::Request {
        target,
        id,
        title: a.title.clone(),
        local,
    })
}

/// `--hashes-from` on the real system, before any request.
#[cfg(windows)]
fn hashes_from(folder: &Path) -> Result<local::Local, String> {
    let sys = rerun_core::sys::win::WinSystem::new().map_err(|e| e.to_string())?;
    let exe = std::env::current_exe().map_err(|e| format!("the workbench's own path: {e}"))?;
    let install = exe
        .parent()
        .ok_or("the workbench's own folder")?
        .to_path_buf();
    local::exes_from(&sys, &install, folder)
}

#[cfg(not(windows))]
fn hashes_from(_: &Path) -> Result<local::Local, String> {
    Err("--hashes-from: Windows only".into())
}

fn draft_cmd(a: &DraftArgs) -> Result<(), String> {
    let req = draft_request(a)?;
    #[cfg(windows)]
    let http = rerun_core::sys::win::WinHttp::new();
    #[cfg(not(windows))]
    let http = rerun_core::sys::NoHttp;
    let (d, text) = draft::make(&http, &req, draft::SPACING, draft::DEADLINE)?;
    match &a.into {
        None => {
            std::io::stdout()
                .write_all(text.as_bytes())
                .map_err(|e| format!("stdout: {e}"))?;
        }
        Some(dir) => {
            if let Some(n) = d.steam_appid {
                for f in draft::same_app(dir, n) {
                    eprintln!("warning: {f} names Steam app {n} too");
                }
            }
            let p = draft::write_into(dir, &d, &text)?;
            eprintln!("wrote {}", p.display());
        }
    }
    eprintln!(
        "draft {} from {}: {} TODO comments, curate before it leaves status draft",
        d.id,
        d.url,
        text.lines().filter(|l| l.contains("TODO")).count()
    );
    Ok(())
}

fn generate(out_dir: &Path) -> Result<(), String> {
    let dir = keys::outside_repo(out_dir)?;
    let kp = keys::generate()?;
    let key = dir.join(keys::KEY_FILE);
    let public = dir.join(keys::PUB_FILE);
    create_new(&key, &keys::key_text(&kp), true)?;
    create_new(&public, &keys::pub_text(&kp), false)?;
    let pk = rerun_core::catalog::key::PublicKey::new(*kp.pk);
    println!(
        "private key: {} (keep it offline, never in a repository)",
        out_dir.join(keys::KEY_FILE).display()
    );
    println!("public key:  {}", out_dir.join(keys::PUB_FILE).display());
    println!("key id:      {}", pk.id());
    println!("for RELEASE_KEYS in crates/rerun-core/src/catalog/key.rs:");
    println!("    {}", keys::release_line(&pk));
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use clap::Parser;

    use super::Cli;

    /// `index sign-test` exists exactly in a build with the feature `test-key` (ADR 0024
    /// amendment P4-13).
    #[test]
    fn sign_test_exists_only_with_the_feature() {
        let r = Cli::try_parse_from(["rerun-workbench", "index", "sign-test", "index.json"]);
        #[cfg(feature = "test-key")]
        assert!(matches!(
            r.unwrap().command,
            super::Command::Index {
                command: super::IndexCommand::SignTest { .. }
            }
        ));
        #[cfg(not(feature = "test-key"))]
        assert!(r.is_err());
        // `index sign` still needs its key file.
        assert!(Cli::try_parse_from(["rerun-workbench", "index", "sign", "index.json"]).is_err());
    }
}
