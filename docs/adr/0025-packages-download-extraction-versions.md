# ADR 0025 · Packages: download, extraction, versions

**Status:** accepted · 2026-11-10, part 1 (download and cache, P4-6); part 2 (extraction, the `package` step) follows with P4-7 · extends ADR 0008, ADR 0019, ADR 0024 · phase 4

## Context
A package (`docs/02-topo-format.md`) names an upstream release archive by URL and pins its SHA-256. Phase 4 must bring that archive onto the machine without a new crate (plan P4, L5: "HTTP over WinHTTP, redirects by hand only to fixed forge hosts, non-elevated only"), without trusting anything the network or the user-writable `<LocalAppData>\Rerun` holds, and so that the later steps (extraction, P4-7; the elevated helper never downloads) can rely on one property: an archive in the cache is used only after it hashed to its pin. One package is one version (user decision E2 a); the download is per package URL, so a version is just another package.

## Decision

### Part 1: download and cache (P4-6)

**One network path.** `sys::Http` (one `get(host, path)`: exactly one HTTPS request, no redirect followed, status, `Location`, `Content-Length` and the body as a stream) with the real `sys::win::WinHttp` and the scripted `sys::fake::FakeHttp`. `Http` is not part of `System`: the elevated helper's system can never reach the network (its source rule forbids `WinHttp` and `http::`), and the curator tool (P4-14) uses the same wrapper without a system.

**WinHTTP, fixed settings** (`sys::win::http`, the only WinHTTP calls; `windows-sys` feature `Win32_Networking_WinHttp`, no new crate; `winhttp.dll` joins `CLI_IMPORTS`, ADR 0008 amendment P4-6):
- a fresh session, connection and request per call, closed in that order when the body drops (owned handles);
- `WINHTTP_FLAG_SECURE`, port 443, TLS 1.2 or 1.3; Schannel validates the certificate as WinHTTP does by default, and nothing ever sets `WINHTTP_OPTION_SECURITY_FLAGS` (a workspace source rule fails on `SECURITY_FLAG_IGNORE_*` and on WinINet's `INTERNET_FLAG_IGNORE_CERT_*`);
- no automatic redirect (`WINHTTP_OPTION_REDIRECT_POLICY_NEVER`, `WINHTTP_DISABLE_REDIRECTS`), no cookie (`WINHTTP_DISABLE_COOKIES`), no authentication (`WINHTTP_DISABLE_AUTHENTICATION`), no automatic logon with the user's credentials (`WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH`; a proxy that asks for credentials answers 407, which is an error);
- the system proxy (`WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`), synchronous, 30 s per resolve, connect, send and receive, response headers at most 64 KiB, a `Location` at most 8.5 KiB of printable ASCII;
- the path is sent as given (`WINHTTP_FLAG_ESCAPE_DISABLE`, `…_QUERY`) after `sys::http::check_request` (plain host, path from `/`, printable ASCII without space, `\` or `#`, at most 8 KiB);
- the user agent is `Rerun/<version>` and nothing else; no other request header of Rerun's own;
- refused unless the process restricted its DLL search path first (`restrict_dll_search`, ADR 0008), because WinHTTP loads further system DLLs at run time.
- `clippy.toml` bans `WinHttpOpen` and `WinHttpSetOption` outside `sys::win::http`, and the URLMon download helpers (`URLDownloadToFileW`, `URLDownloadToCacheFileW`, `URLOpenBlockingStreamW`, `URLOpenStreamW`; they follow redirects and use the browser cache) everywhere.

**The URL rules** (`policy::url`, one grammar for the loader and the downloader; moved there from `catalog::check`): the form of docs/02 (`https_url`, `release_download`), provenance (`belongs`: a release download only of its own `source.repo`, anything else only on the host of `source.page`), and two download rules:
- `HttpsUrl::download`: a package URL in the form, printable ASCII without `#` (the loader's form admits more; the downloader refuses rather than encodes);
- `HttpsUrl::redirect`: a `Location` is followed only if it is an absolute `https` URL without userinfo, port or IP literal, its host passes the host rule and is listed for the host that sent the redirect in `REDIRECTS`, and its path is printable ASCII without `#`. `REDIRECTS` is fixed in code: `github.com` → `objects.githubusercontent.com`, `release-assets.githubusercontent.com`. No other host redirects anywhere, an asset host not further, and a redirect to the same host is refused too (on a forge it could leave the repository the provenance rule checked). A forge that changes its storage hosts fails closed until the list changes (risk R5 of the plan).

**`pkg::download`**: `downloads(package)` lists the downloads of a package of the signed index (`source.release` with `sha256`, or one per `assets[]`), re-checks form and provenance itself, and has none for a `community` package or a `TODO` value. `fetch(sys, http, app, download)`:
1. refuses an elevated process (or one whose elevation is unknown), as every changing command (`exec::standard_user`, P2-13 E3);
2. opens `<AppDir>\cache` handle-relative (created if missing, never through a reparse point) and holds `cache\lock` (share 0) for the whole fetch; deletes temp files (`.rerun-<tag>-<n>.tmp`) an interrupted fetch left, which under the lock none can be using;
3. a cache entry `<sha256>` (64 lower-case hex digits) is hashed on a guard every time: used if it hashes to its name, deleted on that guard and downloaded again if not; an entry that cannot be guarded (hard link, directory, reparse point) is an error that names it;
4. requests the package URL and follows at most three redirects (301, 302, 303, 307, 308) as `HttpsUrl::redirect` allows; a refused `Location` is never requested; any other status than 200 is an error;
5. refuses a `Content-Length` above `MAX_DOWNLOAD_BYTES` (64 MiB) before reading; otherwise the length is advisory, the limit is counted on the bytes read, and a body that ends before or runs past its `Content-Length` is refused;
6. streams the body through `DirWrite::create_new` (ADR 0017): a temp file next to the target, hashed on the way; a hash other than the pin, a transport error, the limit or any write error deletes the temp file, so the name `<sha256>` only ever holds exactly the pinned bytes; then the rename without replace and a flush of the folder.

A cached archive stays untrusted: its user (extraction, P4-7) hashes it again on its own handle before reading an entry.

**CLI:** `rerun package fetch <id>@<version>`: the elevated guard, the current signed index (read back and checked like `index show`; none is exit 3), the package by ID and its one version (another version is exit 3 and names the one in the index), then every download of it; one line per download (cached or downloaded, length, SHA-256). A refusal is exit 3, a network or file system failure exit 1.

### Part 2: extraction and the `package` step (P4-7)
Follows with P4-7: bounded zip/tar.gz readers, only the entries `files[].from` names, each with `files[].sha256`, below `<AppDir>\packages\<id>\<version>`.

## Alternatives
- **`reqwest`/`ureq` with rustls:** a TLS stack and an HTTP client as new dependencies (and certificate roots of their own instead of the Windows store, proxy handling of their own); refused by the plan (no new crate, Schannel, the system proxy).
- **WinHTTP's own redirect handling with a callback that vets each hop:** asynchronous mode and a status callback for one check that a loop of plain requests does with less code; the policy would also sit inside `sys`.
- **A size field per package** (exact length pinned next to the hash): stricter than one limit, but a format change for every package; the hash already pins the length, and one limit far above every known archive bounds the cost of a wrong one. Revisit if a package ever comes near the limit.
- **`.part` file names:** the existing `create_new` already writes through a journal-shaped temp name and deletes it on every failure; a second naming scheme would need its own cleanup.

## Consequences
- `rerun.exe` imports `winhttp.dll` (not a KnownDLL; loaded from System32 by `/DEPENDENTLOADFLAG:0x800`); the helper does not (`HELPER_IMPORTS` unchanged, its source rule forbids the network).
- Network tests run only in the sandbox suite: `sandbox_package_download_of_a_github_release_asset` downloads `EaglePatchAC1.zip` (v1.1, 44,574 bytes) through the product path as the CI standard user, checks it against the SHA-256 GitHub reports for the asset and measures it independently. Everything else runs against `FakeHttp` (`docs/09-testing.md`, "Package download").
- docs/01 (Network, `pkg`, `policy::url`, CLI), docs/02 (Download), docs/06 (#3, #23) updated with this ADR.
