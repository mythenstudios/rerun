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

- Research basis via the API (MediaWiki; anonymous Cargo queries are refused by the wiki, checked 2026-11-10). Status `hackable` = candidate for a fix.
- `rerun-workbench draft` (P4-14, curator tool, never shipped) reads a page's template parameters (app ID, API versions, `hackable` flags) and section anchors and writes a Topo draft of facts and links only: never a step, never a download of what the page links, never text of the page (`docs/02-topo-format.md`, "Drafts from PCGamingWiki").
- Content is licensed CC BY-NC-SA: do not copy, use own wording, link as source.
- PCGW is never evaluated live in the client. Topos are the reviewed form.

## Reference data

Tables that map hardware facts to names (the GPU architecture table `data/gpu-arch.yaml`, ADR 0015) follow the same standard as Topos:

- Every entry names its own source (`source`): vendor documentation or driver INF files, Mesa, the PCI ID Repository, or a dump of a real machine.
- No invented IDs: no extrapolated neighbours, ranges only as a source states them.
- Unknown stays unknown: a device without a sourced entry is `unknown`, never guessed from its name or nearby IDs.
- Licence check before any bulk import (e.g. Mesa under MIT; the PCI ID Repository under BSD-3-Clause, which requires a notice); notices travel with the data.
- Test entries are synthetic and stay in test code.

The compatibility-layer tokens (`policy::registry::layers`, ADR 0018 amendment P2-11b) follow the same standard. Their source is a dump of a real machine: Explorer's compatibility tab in Windows Sandbox (SB-L1, `docs/09-testing.md`), whose raw values are the fixture `tests/fixtures/layers/sb-l1-2026-11-07.txt`; a test binds every word of the lists to it. A token Rerun may add needs, besides, the SB-L6 probe (it starts a 32-bit and a 64-bit image without elevation in a non-elevated session, `__COMPAT_LAYER` holding it) and a fix that uses it; the two tokens below are in before any Topo exists (Topos come in phase 4) as the classic display fixes of old games, display only and no pair (user decision B2 of P2-11b), the others wait for the first Topo that needs them. Microsoft documentation and PCGamingWiki are plausibility checks, not a gate; the PCGamingWiki link belongs in the Topo that uses a token. The source is bound to the build: before A6 the probes run again on the current build.

| Token (add allowlist) | Compatibility tab | SB-L1 dump | SB-L6 | Build, date |
|---|---|---|---|---|
| `DISABLEDXMAXIMIZEDWINDOWEDMODE` | Disable fullscreen optimizations | `layers-06-nofso` | no 740 on x86 and x64 | 26100, 2026-11-07 |
| `HIGHDPIAWARE` | Change high DPI settings: override, scaling performed by Application | `layers-10-dpi-app` | no 740 on x86 and x64 | 26100, 2026-11-07 |

Observed and in the group table only (not addable): `16BITCOLOR` (`layers-04-color16`), `256COLOR` (`layers-12-combined`), `640X480` (`layers-05-640x480`), `DPIUNAWARE` (`layers-21-dpi-system`), `GDIDPISCALING` (`layers-22-dpi-sysenh`), `WINXPSP3` (`layers-02-xpsp3`), `WIN7RTM` (`layers-03-win7`). Observed and neither: `RUNASADMIN` (`layers-07-admin`), `REGISTERAPPRESTART` (`layers-08-restart`), `TRANSFORMLEGACYCOLORMANAGED` (`layers-09-icc`).

The anti-cheat markers (`detect::exe::anti_cheat::MARKERS`, P4-4, user decision E4) follow the same standard: a folder or file name of an anti-cheat system next to the game, each with its source. Any entry of the name counts (fail closed: a false find costs fixes, never a ban, P4 risk R7); an entry the user may not open, and a searched folder that is a link or cannot be asked, count as unreadable, which no release of a dead system covers. An entry without a vendor source yet is marked `TODO` and needs one, or a dump of a real machine, before A6.

| System | Marker | Source |
|---|---|---|
| `easy-anti-cheat` | folder `EasyAntiCheat` | TODO (no vendor source yet; already on the walk's skip list, ADR 0014) |
| `easy-anti-cheat` | folder `EasyAntiCheat_EOS` | TODO (no vendor source yet) |
| `easy-anti-cheat` | file `start_protected_game.exe` | https://redpoint-games-docs.pages.dev/docs/setup/networking/anticheat (third-party plugin documentation; to be replaced by Epic's own documentation once found) |
| `battleye` | folder `BattlEye` | https://www.battleye.com/support/faq/ ("the "BattlEye" folder in your game directory") |
| `punkbuster` | folder `PunkBuster` | developer-machine dump, ADR 0014 amendment 2026-11-05 |
| `punkbuster` | folder `pb` | https://www.pbbans.com/info-center-pbsetup.html ("the game PB folder") |
| `gameguard` | folder `GameGuard` | TODO (no vendor source yet) |
| `xigncode` | folder `XIGNCODE` | TODO (no vendor source yet) |
| `ea-anticheat` | file `EAAntiCheat.GameServiceLauncher.exe` | TODO (no vendor source yet) |

The graphics preference values (`policy::registry::gpu_pref`, ADR 0018 amendment P4-11) follow the same standard. `GpuPreference` `0` (let Windows decide), `1` (power saving), `2` (high performance) and the pair `AutoHDREnable` come from Microsoft Q&A and Kapil Arya, "Set Graphics Preference for Apps in Windows 11" (checked 2026-11-05, `03b-gpu-display.md` "Sources"); the digits and `SwapEffectUpgradeEnable` are confirmed by the dump of what Settings > System > Display > Graphics writes (SB-G1, developer machine, build 26300.9711, 2026-11-10: `tests/fixtures/gpu-pref/sb-g1-2026-11-10.txt`). Rerun writes only `2`, and plans only next to the known pairs `gpu_pref::KNOWN_PAIRS` (`AutoHDREnable`, `SwapEffectUpgradeEnable`); any other form or pair (a specific GPU, not measured) is refused.

## Links in the app

Every variant links directly to its source: the specific Steam guide, the thread, the repo, the PCGW section. Never just the home page.

## Review on inclusion

1. Original source found and documented.
2. License permits use (Rerun hosts nothing, only links).
3. Hash computed ourselves.
4. File run once through a malware scan during curation (not at runtime).
5. Trade-offs and side effects entered.
