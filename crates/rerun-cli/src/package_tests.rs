//! `rerun package fetch` (ADR 0025) against the fake: a signed index with one package, scripted
//! HTTPS replies.

use std::path::Path;

use sha2::{Digest, Sha256};

use rerun_core::catalog::key::test_key;
use rerun_core::sys::fake::{FakeHttp, FakeReply, FakeSystem};

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::tests::{Ran, bare, expect, run_to_http};

const INDEX: &str = r"D:\Work\index.json";
const SIG: &str = r"D:\Work\index.json.sig";
const ASSET: &str = "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip";
const STORE: &str =
    "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sp=r";
const BODY: &[u8] = b"PK\x03\x04 the archive";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sys_with_index(sha: &str) -> FakeSystem {
    let sys = bare().dir(r"D:\Work").build().unwrap();
    sys.fake_fs().sync_all();
    let pkg = format!(
        r#"{{"format":1,"id":"fix-pack","name":"Fix pack","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-pack","release":"{ASSET}"}},"version":"1.0","sha256":"{sha}","license":"MIT","arch":["x86"]}}"#
    );
    let index = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-10T12:00:00Z","topos":[],"packages":[{pkg}]}}"#
    );
    let b = index.into_bytes();
    sys.fake_fs().put_file(Path::new(INDEX), &b).unwrap();
    sys.fake_fs()
        .put_file(Path::new(SIG), &test_key::sign(&b))
        .unwrap();
    expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
    sys
}

fn run(sys: &FakeSystem, http: &FakeHttp, args: &[&str], exit: Exit) -> Ran {
    let (mut r, out) = run_to_http(sys, http, args, Answer::No, Vec::new());
    r.stdout = String::from_utf8(out).unwrap();
    assert_eq!(
        r.exit,
        exit,
        "{}\n{}\n{}",
        args.join(" "),
        r.stdout,
        r.stderr
    );
    r
}

fn github() -> FakeHttp {
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::redirect(302, STORE));
    http.reply(STORE, FakeReply::ok(BODY));
    http
}

#[test]
fn fetch_downloads_then_finds_it_in_the_cache() {
    let sha: [u8; 32] = Sha256::digest(BODY).into();
    let sys = sys_with_index(&hex(&sha).to_ascii_uppercase());
    let http = github();
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Report,
    );
    assert_eq!(
        r.stdout,
        format!(
            "fix-pack 1.0: downloaded (redirects: 1), {} bytes, sha256 {}\n",
            BODY.len(),
            hex(&sha)
        )
    );
    assert_eq!(http.requests(), [ASSET, STORE]);
    http.clear_requests();
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Report,
    );
    assert!(
        r.stdout.starts_with("fix-pack 1.0: already in the cache, "),
        "{}",
        r.stdout
    );
    assert!(http.requests().is_empty());
}

#[test]
fn a_wrong_hash_unknown_package_or_version_is_refused() {
    let sys = sys_with_index(&"AB".repeat(32));
    let http = github();
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Refused,
    );
    assert!(
        r.stderr.contains("does not have the pinned SHA-256"),
        "{}",
        r.stderr
    );
    assert!(r.stdout.is_empty());

    let r = run(
        &sys,
        &http,
        &["package", "fetch", "other@1.0"],
        Exit::Refused,
    );
    assert_eq!(r.stderr, "rerun: the current index has no package other\n");
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@2.0"],
        Exit::Refused,
    );
    assert_eq!(
        r.stderr,
        "rerun: the current index has package fix-pack at version 1.0 only\n"
    );
}

#[test]
fn without_an_index_or_elevated_nothing_is_fetched() {
    let sys = bare().build().unwrap();
    let http = github();
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Refused,
    );
    assert!(r.stderr.contains("no signed index"), "{}", r.stderr);
    let sys = sys_with_index(&"AB".repeat(32));
    sys.fake_registry().set_elevated(true);
    run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Refused,
    );
    assert!(http.requests().is_empty());
}

#[test]
fn a_network_failure_is_fatal() {
    let sha: [u8; 32] = Sha256::digest(BODY).into();
    let sys = sys_with_index(&hex(&sha).to_ascii_uppercase());
    let r = run(
        &sys,
        &FakeHttp::default(),
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Fatal,
    );
    assert!(r.stderr.contains("network:"), "{}", r.stderr);
}

#[test]
fn a_malformed_spec_is_a_usage_error_before_any_access() {
    for bad in [
        "fix-pack",
        "Fix@1.0",
        "fix-pack@",
        "fix-pack@1..0",
        "fix-pack@-1",
    ] {
        let e =
            <crate::cli::Cli as clap::Parser>::try_parse_from(["rerun", "package", "fetch", bad]);
        assert!(e.is_err(), "{bad}");
    }
}
