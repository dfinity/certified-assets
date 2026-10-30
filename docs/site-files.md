---
title: "Site files and conventions"
description: "What gets uploaded, the special _redirects, _headers and _preserve files, skipped files, custom domains, and the 404 page"
sidebar:
  order: 5
---

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

Three filenames are treated as **configuration, not content**: they're read for their
effect and never uploaded as assets. Place them at the root of your asset directory:

- [`_redirects`](redirects.md): redirect, rewrite, and error-page rules.
- [`_headers`](headers.md): custom response headers.
- [`_preserve`](#keeping-files-across-syncs): files the sync keeps on the canister
  when they're missing locally.

## Files that are skipped

To match common build-output conventions, the plugin skips:

- **Dotfiles and dot-directories.** Anything whose name starts with `.` (for example
  `.DS_Store`, `.git/`, `.env`). The one exception is `.well-known/` (below), which is
  traversed normally.
- **Symbolic links.** Both file and directory symlinks are ignored; only real files
  are uploaded.

Everything else under `dir` is fair game, so keep build artifacts you don't want
served out of that directory.

## Keeping files across syncs

A sync makes the canister match your directory: by default, any asset on the canister
that isn't in `dir` is deleted. To keep certain files when they're missing locally,
list them in a `_preserve` file, one path per line:

```
# Uploaded once; later deploys don't ship it.
/.well-known/ii-alternative-origins
/uploads/*
```

Paths use the same pattern syntax as [`_headers`](headers.md): they start with `/`, and
a single `*` matches any sequence of characters, including `/`. Blank lines and `#`
comments are ignored.

The file only changes what happens to assets that are **absent** from `dir`:

- **Present locally:** a preserved path syncs like any other file. Its new content,
  headers and content type replace the canister's copy.
- **Absent locally:** the canister's copy is left exactly as it is, including its
  headers. Edits to `_headers` don't reach it until the file is synced again.

A file gets onto the canister the usual way, from a sync where it *is* in `dir`.
`_preserve` only stops later syncs from deleting it.

Some caveats:

- **Served at its exact path only.** [Clean URLs](routing.md#clean-urls) are worked out
  from the files in `dir`, so a preserved `about.html` that's missing locally is served
  at `/about.html` but no longer at `/about`.
- **Compression can be dropped.** If a release changes how assets are compressed, the
  next sync re-prepares every asset. A preserved file that's missing locally can't be
  re-prepared, so its compressed copies are removed and it's served uncompressed until
  it's synced again.
- **The state hash includes it.** A preserved file stays in the canister's
  [state hash](verifying-contents.md), but it isn't in your build, so the hash of `dir`
  alone won't match. See [verifying contents](verifying-contents.md).

## Custom domains

To serve your site from your own domain, add a `.well-known/ic-domains` file listing
each custom domain, one per line:

```
example.com
www.example.com
```

`.well-known/` is uploaded despite the leading dot, so the file is served at
`/.well-known/ic-domains`, which is where the Internet Computer's boundary nodes look
when registering a custom domain. Registering the domain itself is an IC platform step;
see the [custom domains documentation](https://docs.internetcomputer.org/guides/frontends/custom-domains/)
for the full process.

## The 404 page

A file named `404.html` at the root of your directory becomes your site-wide
not-found page. If you don't provide one, a certified default is served instead. See
[not-found handling](routing.md#not-found-handling).
