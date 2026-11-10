# PCGamingWiki replies (synthetic)

Replies in the shape of `action=parse&prop=wikitext|sections&format=json&formatversion=2` for
`rerun-workbench draft` (P4-14). Every game, page, app ID, section and text here is **invented**:
no content of PCGamingWiki is in the repository (user decision D3 b; the wiki's content is
CC BY-NC-SA). The real reply format was checked by hand (docs/09-testing.md, [DEV] PCGW-1).

The strings `...-NEVER-COPIED` stand in for prose of a page (`line` of a section, notes, fix
text): the tests check that none of them reaches a draft.

- `invented-racer-2.json`: one Direct3D 9 executable, fix sections, `hackable` features, a
  comment and a `<nowiki>` in the wikitext.
- `invented-quest.json`: Direct3D 9 and 10 and OpenGL, two app IDs, an anchor with a
  non-ASCII character.
