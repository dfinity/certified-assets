# Redirects & rewrites

Add a file named `_redirects` to the root of your asset directory to send one path
to another, serve a file's contents at a different URL, or set custom error pages.
The syntax follows [Netlify's `_redirects`](https://docs.netlify.com/manage/routing/redirects/overview/),
with one rule per line:

```
/old-path   /new-path   301
```

Each line is three whitespace-separated fields — `from`, `to`, and `status`. Blank
lines and lines starting with `#` are ignored.

## The three fields

**`from`** — the path to match. Always absolute (starts with `/`):

- `/about` — an exact path.
- `/blog/*` — a subtree: everything under `/blog/`. The `*` is only allowed as a
  trailing `/*`.
- `/*` — the entire site.

**`to`** — the destination:

- For a redirect (3xx), an absolute path (`/new`) **or** a full URL
  (`https://example.com/new`).
- For a rewrite or error page (200/404/410), an absolute path to one of your files.

**`status`** — what the canister does. One of:

| Status | Meaning |
|--------|---------|
| `301` | Permanent redirect. |
| `302` | Temporary redirect. |
| `307` | Temporary redirect, preserving the request method. |
| `308` | Permanent redirect, preserving the request method. |
| `200` | **Rewrite** — serve the `to` file's contents at the `from` URL, with no visible redirect. |
| `404` | Serve the `to` file as a not-found page. |
| `410` | Serve the `to` file, signalling the resource is permanently gone. |

A `404` or `410` error page must be a **small, single-chunk file** (under ~1.9 MB).
Large files are served as [`206` range responses](how-it-works.md#serving-large-assets)
that the gateway reassembles into a `200`, which can't carry a 4xx status — so the sync
plugin rejects a 4xx rule pointing at a multi-chunk asset at deploy time, naming the
offending rule. (A `200` rewrite to a large file is fine.)

## Examples

```
# Permanent redirect to a new internal path
/old-blog        /blog            301

# Redirect to an external site
/discord         https://discord.gg/example   302

# Rewrite: serve /content/article.html at the pretty URL, no redirect
/article         /content/article.html         200

# Subtree redirect: everything under /docs/v1/ moves to /docs/v2/
/docs/v1/*       /docs/v2/        301

# Single-page-app fallback: serve the shell for any unmatched path
/*               /index.html      200

# Custom error pages
/secret          /403.html        404
/retired-feature /sunset.html     410
```

## Ordering & precedence

Rules are evaluated top to bottom and **the first match wins**, within a fixed
overall order:

1. **Files.** An actual file at the requested path always wins over any rule. (This
   is why there's no Netlify-style `!` "force" suffix — to override a file, remove or
   rename it rather than forcing a rule past it.)
2. **Clean-URL rules.** The automatic [clean-URL redirects](routing.md#clean-urls)
   are applied next.
3. **Your `_redirects`.** Then your rules, in file order.
4. **The 404 fallback.** Finally the [not-found page](routing.md#not-found-handling).

So a `/*` rule at the end of your file only catches paths that nothing earlier
claimed — which is exactly what makes the
[SPA fallback](routing.md#single-page-apps-spa) above safe.

## What isn't supported: dynamic rules

There are no `:splat` or `:placeholder` captures — you can't write
`/old/:rest  /new/:rest  301` to forward a captured path segment. This isn't a
missing feature we plan to add; it's a consequence of how the Internet Computer
serves these assets.

**Every response the canister can return is certified ahead of time.** During sync,
the plugin builds a certification tree over a *finite, enumerable* set of
`path → response` mappings, and the HTTP gateway verifies each response against that
tree before serving it. A `:splat` rule would construct its destination — and thus
its response — dynamically from whatever path the visitor requested, producing
responses that were never certified. The gateway would reject them. (The same
constraint is why [header values](headers.md) can't use `:splat` substitution
either.)

Static rules — exact paths, `/*` subtrees, and fixed destinations — cover the common
cases and stay fully certifiable, so those are what `_redirects` supports.
