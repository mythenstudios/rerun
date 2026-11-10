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
    sys_with_package(&format!(
        r#"{{"format":1,"id":"fix-pack","name":"Fix pack","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-pack","release":"{ASSET}"}},"version":"1.0","sha256":"{sha}","license":"MIT","arch":["x86"]}}"#
    ))
}

fn sys_with_package(pkg: &str) -> FakeSystem {
    let sys = bare().dir(r"D:\Work").build().unwrap();
    sys.fake_fs().sync_all();
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

fn upper(b: &[u8]) -> String {
    let sha: [u8; 32] = Sha256::digest(b).into();
    hex(&sha).to_ascii_uppercase()
}

#[test]
fn passing_failures_exit_1() {
    let sys = sys_with_index(&upper(BODY));
    // 503 from the asset host.
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::redirect(302, STORE));
    http.reply(STORE, FakeReply::status(503));
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Fatal,
    );
    assert!(r.stderr.contains("HTTP status 503"), "{}", r.stderr);
    // A body shorter than its Content-Length.
    let mut short = FakeReply::ok(BODY);
    short.length = Some(BODY.len() as u64 + 5);
    http.reply(STORE, short);
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Fatal,
    );
    assert!(r.stderr.contains("Content-Length"), "{}", r.stderr);
    // Another 4xx is a refusal.
    http.reply(STORE, FakeReply::status(404));
    run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Refused,
    );
}

#[test]
fn a_failure_after_progress_reports_what_was_done() {
    const X86: &str = "https://github.com/owner/fix-pack/releases/download/v1.0/x86.zip";
    const X64: &str = "https://github.com/owner/fix-pack/releases/download/v1.0/x64.zip";
    let (a, b): (&[u8], &[u8]) = (b"PK x86 build", b"PK x64 build");
    let sys = sys_with_package(&format!(
        r#"{{"format":1,"id":"fix-pack","name":"Fix pack","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-pack"}},"version":"1.0","assets":[{{"arch":"x86","url":"{X86}","sha256":"{}"}},{{"arch":"x64","url":"{X64}","sha256":"{}"}}],"license":"MIT","arch":["x86","x64"]}}"#,
        upper(a),
        upper(b)
    ));
    let http = FakeHttp::default();
    http.reply(X86, FakeReply::ok(a));
    http.reply(X64, FakeReply::ok(b"PK not the x64 build"));
    // The first asset is stored, the second does not match: exit 0 with the line and the failure.
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Report,
    );
    assert!(
        r.stdout.starts_with("fix-pack 1.0 (x86): downloaded"),
        "{}",
        r.stdout
    );
    assert!(r.stderr.contains("pinned SHA-256"), "{}", r.stderr);
    // Again: the first is a cache hit, nothing changes, the mismatch alone is exit 3.
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Refused,
    );
    assert!(
        r.stdout
            .starts_with("fix-pack 1.0 (x86): already in the cache"),
        "{}",
        r.stdout
    );
}

/// A package of the index whose one download is `archive`, with the file `from` (hash of `data`).
fn sys_with_files(archive: &[u8], from: &str, data: &[u8]) -> FakeSystem {
    sys_with_package(&format!(
        r#"{{"format":1,"id":"fix-pack","name":"Fix pack","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-pack","release":"{ASSET}"}},"version":"1.0","sha256":"{}","license":"MIT","arch":["x86"],"files":[{{"from":"{from}","to":"{from}","sha256":"{}"}}]}}"#,
        upper(archive),
        upper(data)
    ))
}

fn github_with(body: &[u8]) -> FakeHttp {
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::redirect(302, STORE));
    http.reply(STORE, FakeReply::ok(body));
    http
}

#[test]
fn fetch_unpacks_the_named_files() {
    use rerun_core::pkg::archive::testfx::{ZipEntry, zip};
    let archive = zip(&[
        ZipEntry::file("bin/fix.dll", b"the fix"),
        ZipEntry::file("readme.txt", b"not named"),
    ]);
    let sys = sys_with_files(&archive, "bin/fix.dll", b"the fix");
    let http = github_with(&archive);
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Report,
    );
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{}", r.stdout);
    assert!(
        lines[0].starts_with("fix-pack 1.0: downloaded"),
        "{}",
        r.stdout
    );
    assert_eq!(lines[1], r"fix-pack 1.0: bin\fix.dll unpacked, 7 bytes");
    // Again: both checked, nothing done.
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Report,
    );
    assert!(
        r.stdout
            .trim_end()
            .ends_with(r"fix-pack 1.0: bin\fix.dll already unpacked, 7 bytes"),
        "{}",
        r.stdout
    );
}

#[test]
fn a_refused_archive_is_reported_after_the_download() {
    use rerun_core::pkg::archive::testfx::{ZipEntry, zip};
    let mut slip = ZipEntry::file("../evil.dll", b"evil");
    slip.flags = 0x0800;
    let archive = zip(&[ZipEntry::file("bin/fix.dll", b"the fix"), slip]);
    let sys = sys_with_files(&archive, "bin/fix.dll", b"the fix");
    let http = github_with(&archive);
    // The download stored the archive in this run: exit 0, its line, then the refusal.
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Report,
    );
    assert!(
        r.stdout.starts_with("fix-pack 1.0: downloaded"),
        "{}",
        r.stdout
    );
    assert!(
        r.stderr.contains(
            "rerun: package not unpacked: package fix-pack: the archive holds an entry named"
        ),
        "{}",
        r.stderr
    );
    // Again: nothing changes, a refusal (exit 3).
    let r = run(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Exit::Refused,
    );
    assert!(r.stderr.contains("package not unpacked"), "{}", r.stderr);
}
