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
- **Single-page apps (SPA).** If your app does client-side routing, send every
  unmatched path to your shell instead of a 404, by adding this to
  [`_redirects`](redirects.md):

  ```
  /*  /index.html  200
  ```

  When you declare your own root catch-all (`/*`) like this, it takes over the whole
  path space and the default 404 page is not added — your rule wins, as a SPA needs.

## See also

- [Redirects & rewrites](redirects.md) — send one path to another, or serve one
  file's contents at a different URL.
- [Custom headers](headers.md) — attach cache-control, CSP, and other headers to paths.
