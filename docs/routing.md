# Routing & clean URLs

This page explains how an incoming request path resolves to one of your files —
the automatic clean-URL behavior you get out of the box, and how unmatched paths
are handled. For *changing* where paths go, see [Redirects & rewrites](redirects.md);
for attaching headers to paths, see [Custom headers](headers.md).

## How a path resolves

For each request, the canister resolves the path in this order:

1. **An exact file match.** A file in your directory is served directly. `dist/app.js`
   answers a request for `/app.js`.
2. **A routing rule.** If no file matches the path verbatim, the rules apply — the
   automatic clean-URL rules below, then your own [`_redirects`](redirects.md), in
   that order. The first matching rule wins.
3. **The not-found fallback.** If nothing matches, the request resolves to the
   [404 page](#not-found-handling).

Every one of these outcomes is a *certified* response.

## Clean URLs

You don't link to `.html` files. The canister automatically maps each HTML file to a
clean, extension-less URL and treats that as its **canonical** address — following
[Cloudflare's `auto-trailing-slash` conventions](https://developers.cloudflare.com/workers/static-assets/routing/advanced/html-handling/).

| Your file | Canonical URL | Also handled |
|-----------|---------------|--------------|
| `dist/index.html` | `/` | `/index` → `/` |
| `dist/about.html` | `/about` | `/about/`, `/about/index` → `/about` |
| `dist/blog/index.html` | `/blog/` | `/blog`, `/blog/index` → `/blog/` |

The "also handled" forms issue a `307` redirect to the canonical URL, so every page
has exactly one address that search engines and visitors land on.

### A note on `.html` URLs

Requesting the underlying file directly — e.g. `/about.html` — currently serves the
file with a `200` rather than redirecting to the canonical `/about`. A file always
takes precedence over a routing rule at the same path, and `/about.html` *is* a file.
This is harmless for most sites; if you need strict canonicalization (one URL only),
avoid linking to the `.html` form. (The redirect rule for it exists and will activate
automatically if that precedence ever changes.)

## Not-found handling

Every request must resolve to a certified response, so there is always a `404` page.

- **Default.** If you ship nothing special, the canister serves a built-in, certified
  `404` page for any unmatched path.
- **Custom.** Add a file at the root of your directory named `404.html`. It's
  automatically wired up as the site-wide not-found page (served with a `404` status).
- **Client-side routing.** A [single-page app](#single-page-apps-spa) sends unmatched
  paths to its shell instead of to a 404 page.

## Single-page apps (SPA)

If your app does client-side routing — React Router, Vue Router, SvelteKit in SPA
mode, or a hand-rolled `history.pushState` router — the server has to answer *every*
URL with the app shell so the router can take over. Add one rule to
[`_redirects`](redirects.md):

```
/*  /index.html  200
```

That's the whole SPA configuration. `200` makes it a **rewrite**: the shell's
contents are served at the requested URL with no visible redirect, so
`/dashboard/settings` works on a fresh load and on a browser reload, not just on
in-app navigation. Every one of those responses is certified, including the ones at
paths that have no file behind them.

See the [`spa` example](../examples/spa/) for a complete, runnable project.

### What the `/*` rule changes

- **The default 404 page is not added.** Your root catch-all takes over the whole
  path space, so unknown paths serve the shell and the app decides what a bad route
  looks like.
- **A missing asset returns HTML.** A typo'd or stale `/assets/app-old.js` matches
  `/*` too, so it serves the shell with `Content-Type: text/html` and a `200`. This
  mirrors Netlify and Cloudflare Pages, and it's the one behavior worth overriding: a
  `fetch()` for missing JSON gets HTML it can't parse, and a missing script fails with
  a confusing MIME-type error instead of a plain 404.

  Give your build output an honest 404 by scoping a rule to it *above* the catch-all
  — rules are matched in file order:

  ```
  /assets/*  /404.html  404
  /*         /index.html  200
  ```

  Real files still win over both rules, so this only affects URLs under `/assets/`
  that don't exist. It needs a `404.html` in your directory: declaring `/*` means the
  built-in default is never added, and a 4xx rule whose target is missing goes
  inert.

### What it doesn't change

- **Real files still win.** Files are matched before any rule, so you can mix
  server-rendered pages into a SPA at no cost: ship `legal.html` and `/legal` serves
  it, while `/*` only catches what nothing else claimed.
- **Clean URLs still apply.** The [synthesized rules](#clean-urls) are matched before
  your `_redirects`, so `/index` still `307`s to `/` and `/legal/` to `/legal`.

### Two things to get right in the app

- **Link assets with absolute paths.** Use `/assets/app.js`, not `assets/app.js`. A
  relative URL resolves against the *client route*, so at `/dashboard/settings` the
  browser would request `/dashboard/settings/assets/app.js` — which the `/*` rule
  answers with the HTML shell.
- **Put shell headers on the file, not the route.** [`_headers`](headers.md) patterns
  match the file, and a rewrite reuses its target's headers, so a
  `Cache-Control` declared for `/index.html` (or `/*.html`) is what every client
  route gets. A block written against `/dashboard/*` matches no file and does
  nothing. See [patterns match files, not URLs](headers.md#patterns-match-files-not-urls).

## See also

- [Redirects & rewrites](redirects.md) — send one path to another, or serve one
  file's contents at a different URL.
- [Custom headers](headers.md) — attach cache-control, CSP, and other headers to paths.
