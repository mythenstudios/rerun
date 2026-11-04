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

## Links in the app

Every variant links directly to its source: the specific Steam guide, the thread, the repo, the PCGW section. Never just the home page.

## Review on inclusion

1. Original source found and documented.
2. License permits use (Rerun hosts nothing, only links).
3. Hash computed ourselves.
4. File run once through a malware scan during curation (not at runtime).
5. Trade-offs and side effects entered.
