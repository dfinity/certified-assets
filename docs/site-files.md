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
- [`_preserve`](#listing-files-in-_preserve): files a deploy keeps on the canister
  when they're missing locally. Discouraged; see
  [keeping files across syncs](#keeping-files-across-syncs).

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

> **Avoid this if you can.** A deploy is meant to make the canister match your
> directory exactly. That's what makes its [state hash](verifying-contents.md)
> reproducible from source, and what lets you
> reason about what it serves by reading your build. Everything in this section breaks
> that. If a file should be served, **put it in `dir` and deploy**, including files you
> generate (have your `build` step write them into `dir`).
>
> Reach for this only when you can't: for example, a platform that deploys a fixed,
> prebuilt bundle and has to customize one file for a particular canister afterwards,
> with no build step or shell to add it to the bundle.

A sync makes the canister match your directory: by default, any asset on the canister
that isn't in `dir` is deleted. Two pieces work together to change that for chosen
files:

- the `upload_asset` canister method writes a single file outside a deploy, and
- a `_preserve` file in `dir` stops later deploys from deleting it.

### Uploading a single file

Anyone who can deploy to the canister (a controller, or a principal authorized with
`authorize`) can write one file directly:

```bash
icp canister call frontend upload_asset '(record { key = "/.well-known/ii-alternative-origins"; content_type = "application/json"; headers = vec {}; content = blob "{\"alternativeOrigins\":[\"https://example.com\"]}" })'
```

It replaces any file at the same path, takes effect immediately, and returns the
canister's new state hash. Things to know:

- **One message, about 2 MB at most.** The whole file travels in a single call. A
  file served as an error page, such as `/404.html`, must be under 1.9 MB.
- **Stored uncompressed.** The file is served as uploaded, with no gzip or brotli copy.
- **You set the headers.** `_headers` rules don't apply: pass any response headers
  in `headers`, and the content type in `content_type`.
- **It waits for deploys.** The call is rejected while a deploy is in progress.
- **Not under governance.** A canister that [deploys by proposal](governance.md)
  rejects it, since every content change there has to go through a vote.

The next deploy deletes the file, unless `_preserve` names it.

### Listing files in `_preserve`

List the paths a deploy should keep, one per line, in a `_preserve` file at the root of
`dir`:

```
# Uploaded with `upload_asset`; this build doesn't ship it.
/.well-known/ii-alternative-origins
/uploads/*
```

Paths use the same pattern syntax as [`_headers`](headers.md): they start with `/`, and
a single `*` matches any sequence of characters, including `/`. Blank lines and `#`
comments are ignored. Only the file at the root of `dir` is read.

The file only changes what happens to files that are **absent** from `dir`:

- **Present locally:** a preserved path deploys like any other file. Its new content,
  headers and content type replace the canister's copy.
- **Absent locally:** the canister's copy is left exactly as it is, including its
  headers. Edits to `_headers` don't reach it.

A kept file is otherwise treated as part of the site. A kept `about.html` is still
served at `/about` (see [clean URLs](routing.md#clean-urls)), and a kept `404.html`
stays the [not-found page](#the-404-page) instead of being replaced by the default one.
Each deploy lists the files it kept.

Some caveats:

- **Compression can be dropped.** If a release changes how assets are compressed, the
  next deploy re-prepares every asset. A kept file can't be re-prepared, since its bytes
  aren't in `dir`, so any compressed copies are removed and it's served uncompressed.
- **The state hash won't reproduce.** A kept file is part of the canister's
  [state hash](verifying-contents.md) but not of your build, so `state-hash <dir>`
  won't match the canister.
- **Not under governance.** A deploy to a canister that [deploys by
  proposal](governance.md) fails if it would keep any file, because voters couldn't
  reproduce the proposed hash. Add the file to `dir`, or remove it from `_preserve`.

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
