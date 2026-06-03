# Agent guide

Development principles for working in this repo. User-facing documentation lives in [`docs/`](../docs/).

Topic-focused rules auto-load from [`.claude/rules/`](rules/):

- [`project-stage.md`](rules/project-stage.md) — project maturity and compatibility stance (applies to all work)
- [`testing.md`](rules/testing.md) — how tests are organized and when to add them

To add a rule that should load **only** when editing certain files, create a new file in `rules/` with a `paths:` frontmatter glob list. Files without `paths:` load on every session.
