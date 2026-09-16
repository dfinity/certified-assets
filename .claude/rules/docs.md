---
paths:
  - "docs/**/*.md"
---

# User documentation

[`docs/`](../../docs/) is synced verbatim into
[developer-docs](https://github.com/dfinity/developer-docs) and published as the
Frontends section of `docs.internetcomputer.org`. This repo stays the single source
of truth: nothing is rewritten at sync time, so a page ships exactly as it is
committed here.

## Frontmatter is what readers see

Every page opens with `title`, `description`, and `sidebar.order`, and **no H1** —
the site renders `title` as the H1 and as the sidebar entry.

```yaml
---
title: "Routing and clean URLs"
description: "How request paths resolve to files, clean URLs, trailing slashes, 404 handling, and single-page apps"
sidebar:
  order: 2
---
```

That makes `title` invisible in the place most contributors read these files: on
GitHub it renders as a table row, not a heading. Write it as the thing a reader
clicks in a sidebar, and re-read it in that position rather than as the top of a
markdown blob.

- **`title`** — the action or the subject, phrased as a person would say it
  ("Deploy a static site", not "Static site overview"). Avoid noun piles.
- **`description`** — one sentence, no trailing period. It is the search result and
  the card blurb, so it stands alone without the title.
- **`sidebar.order`** — the section's reading order. Inserting a page renumbers the
  ones after it.

Anchors are load-bearing: 20 links inside `docs/` target headings in other pages,
and links that leave `docs/` are absolute GitHub URLs at `main`, because a relative
path breaks once published.

## Naming: one thing, three names

A reader arriving here can meet three names for what is functionally one thing, plus
the legacy asset canister they may be migrating from. Pick the name by what the
sentence is actually about:

| Name | Where it belongs |
|---|---|
| the goal, "a static site" | prose, headings, titles, descriptions, navigation |
| the recipe, `@dfinity/static-site` | code blocks, and prose where the reader pins a version |
| the canister, certified-assets | only where the canister's identity matters: its Candid interface, state-hash verification, contrasting it with another canister |

A page about what a visitor gets is about a static site. A page about what the
canister guarantees ([`how-it-works.md`](../../docs/how-it-works.md),
[`verifying-contents.md`](../../docs/verifying-contents.md)) is allowed to name the
canister, because there the identity is the point.
