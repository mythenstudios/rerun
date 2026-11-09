//! `rerun-workbench` – the curator tool (phase 4), never shipped (ADR 0024).
//!
//! - `index build --seq <n> --issued <YYYY-MM-DDTHH:MM:SSZ> [--root <repo>] <out>`: the YAML of
//!   `topos/` and `packages/` into the canonical bundle `index.json` (drafts left out).
//! - `index sign <bundle> <private-key>`: writes `<bundle>.sig` (64 raw bytes).
//! - `key generate <out-dir>`: a new index key pair, never inside a Git working tree.
//!
//! A curator tool reads and writes the files it is pointed at with `std::fs` (the system layer
//! of `rerun-core` is for the shipped program, ADR 0004).

#![expect(
    clippy::disallowed_methods,
    reason = "curator tool, not shipped: reads the repository and writes files the curator names"
)]

#[cfg(windows)]
mod acl;
mod bundle;
mod keys;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Rerun curator tool: builds and signs the Topo index.
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
        Command::Key {
            command: KeyCommand::Generate { out_dir },
        } => generate(&out_dir),
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
