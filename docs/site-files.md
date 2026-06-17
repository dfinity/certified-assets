# Site files & conventions

This page covers what actually gets uploaded from your asset directory, the special
files that configure behavior instead of being served, and the conventions for things
like custom domains.

## What gets served

Everything in your [`dir`](overview.md#configuration) is uploaded and served, with the
URL mirroring the path inside that directory:

| File on disk (`dir: dist`) | Served at |
|----------------------------|-----------|
| `dist/index.html` | `/` (see [clean URLs](routing.md#clean-urls)) |
| `dist/styles/app.css` | `/styles/app.css` |
| `dist/images/logo.svg` | `/images/logo.svg` |

The sync plugin diffs your directory against the canister on each `icp deploy` and
uploads only what changed, so re-deploys are fast.

## Special files

Two filenames are treated as **configuration, not content** — they're read for their
effect and never uploaded as assets. Place them at the root of your asset directory:

- [`_redirects`](redirects.md) — redirect, rewrite, and error-page rules.
- [`_headers`](headers.md) — custom response headers.

## Files that are skipped

To match common build-output conventions, the plugin skips:

- **Dotfiles and dot-directories** — anything whose name starts with `.` (for example
  `.DS_Store`, `.git/`, `.env`). The one exception is `.well-known/` (below), which is
  traversed normally.
- **Symbolic links** — both file and directory symlinks are ignored; only real files
  are uploaded.

Everything else under `dir` is fair game, so keep build artifacts you don't want
served out of that directory.

## Custom domains

To serve your site from your own domain, add a `.well-known/ic-domains` file listing
each custom domain, one per line:

```
example.com
www.example.com
```

`.well-known/` is uploaded despite the leading dot, so the file is served at
`/.well-known/ic-domains` — which is where the Internet Computer's boundary nodes look
when registering a custom domain. Registering the domain itself is an IC platform step;
see the [custom domains documentation](https://docs.internetcomputer.org/building-apps/frontends/custom-domains/using-custom-domains)
for the full process.

## The 404 page

A file named `404.html` at the root of your directory becomes your site-wide
not-found page. If you don't provide one, a certified default is served instead. See
[not-found handling](routing.md#not-found-handling).
