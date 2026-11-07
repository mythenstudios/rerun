# 05 · Sources policy

## Tiers

| Tier | Criteria | Behavior in Rerun |
|---|---|---|
| `official` | Patch from the developer or publisher | direct download, hash pinned |
| `established` | Public repo with releases or long-established official project page, traceable author, listed on PCGamingWiki (e.g. DXVK, dxwrapper, dgVoodoo 2, Special K, Ultimate ASI Loader, ThirteenAG Widescreen Fixes, EaglePatch) | direct download from the original release, version + SHA256 pinned |
| `community` | Nexus Mods, PCGamingWiki community uploads, Steam Workshop/guides with a file – only with a traceable author | Rerun opens the original page, the user downloads it themselves, Rerun then checks the hash |

## Excluded

- Mirror and re-upload sites, even if the file is identical. Always only the author's source.
- No-CD/cracked exe files, DRM removal. Retail with SafeDisc/SecuROM → notice "GOG or Steam version required".
- Closed-source binaries from anonymous authors.
- Anything that requires disabling the virus scanner.
- File hosters without a link to the author (MediaFire, Mega, Google Drive), unless the author links them in the repo/guide themselves and the file gets a pinned hash.

## PCGamingWiki

- Research basis via the API (MediaWiki + Cargo). Status `hackable` = candidate for a fix.
- Content is licensed CC BY-NC-SA: do not copy, use own wording, link as source.
- PCGW is never evaluated live in the client. Topos are the reviewed form.

## Reference data

Tables that map hardware facts to names (the GPU architecture table `data/gpu-arch.yaml`, ADR 0015) follow the same standard as Topos:

- Every entry names its own source (`source`): vendor documentation or driver INF files, Mesa, the PCI ID Repository, or a dump of a real machine.
- No invented IDs: no extrapolated neighbours, ranges only as a source states them.
- Unknown stays unknown: a device without a sourced entry is `unknown`, never guessed from its name or nearby IDs.
- Licence check before any bulk import (e.g. Mesa under MIT; the PCI ID Repository under BSD-3-Clause, which requires a notice); notices travel with the data.
- Test entries are synthetic and stay in test code.

The compatibility-layer tokens (`policy::registry::layers`, ADR 0018 amendment P2-11b) follow the same standard. Their source is a dump of a real machine: Explorer's compatibility tab in Windows Sandbox (SB-L1, `docs/09-testing.md`), whose raw values are the fixture `tests/fixtures/layers/sb-l1-2026-11-07.txt`; a test binds every word of the lists to it. A token Rerun may add needs, besides, the SB-L6 probe (it starts a 32-bit and a 64-bit image without elevation in a non-elevated session, `__COMPAT_LAYER` holding it) and a fix that uses it. Microsoft documentation and PCGamingWiki are plausibility checks, not a gate; the PCGamingWiki link belongs in the Topo that uses a token. The source is bound to the build: before A6 the probes run again on the current build.

| Token (add allowlist) | Compatibility tab | SB-L1 dump | SB-L6 | Build, date |
|---|---|---|---|---|
| `DISABLEDXMAXIMIZEDWINDOWEDMODE` | Disable fullscreen optimizations | `layers-06-nofso` | no 740 on x86 and x64 | 26100, 2026-11-07 |
| `HIGHDPIAWARE` | Change high DPI settings: override, scaling performed by Application | `layers-10-dpi-app` | no 740 on x86 and x64 | 26100, 2026-11-07 |

Observed and in the group table only (not addable): `16BITCOLOR` (`layers-04-color16`), `256COLOR` (`layers-12-combined`), `640X480` (`layers-05-640x480`), `DPIUNAWARE` (`layers-21-dpi-system`), `GDIDPISCALING` (`layers-22-dpi-sysenh`), `WINXPSP3` (`layers-02-xpsp3`), `WIN7RTM` (`layers-03-win7`). Observed and neither: `RUNASADMIN` (`layers-07-admin`), `REGISTERAPPRESTART` (`layers-08-restart`), `TRANSFORMLEGACYCOLORMANAGED` (`layers-09-icc`).

## Links in the app

Every variant links directly to its source: the specific Steam guide, the thread, the repo, the PCGW section. Never just the home page.

## Review on inclusion

1. Original source found and documented.
2. License permits use (Rerun hosts nothing, only links).
3. Hash computed ourselves.
4. File run once through a malware scan during curation (not at runtime).
5. Trade-offs and side effects entered.
