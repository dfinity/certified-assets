# Custom headers

Add a file named `_headers` to the root of your asset directory to attach response
headers — cache-control, a Content Security Policy, other security headers — to paths
on your site. The syntax follows [Netlify's `_headers`](https://docs.netlify.com/manage/routing/headers/):
a path pattern on its own line, followed by indented `Name: value` lines.

```
/*
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin

/assets/*
  Cache-Control: public, max-age=31536000, immutable
```

A blank line or a `#` comment ends a block.

## Path patterns

A pattern is an absolute path (leading `/`) with an optional `*` wildcard:

- `/` — the home page only.
- `/about` — one exact path.
- `/assets/*` — everything under `/assets/`.
- `/*.css` — every path ending in `.css`.
- `/*` — every path.

The single `*` matches any run of characters, including `/`. There is no `**`, no
`?`, and no `:placeholder` capture (see [why dynamic rules aren't supported](redirects.md#what-isnt-supported-dynamic-rules)).

## How rules combine

A path can match several blocks at once, and **all matching blocks contribute** their
headers — patterns don't override each other wholesale. For a single header name:

- Values from different matching blocks are combined into one header, comma-separated
  (per the HTTP spec).
- `Set-Cookie` is the exception: multiple cookies stay as separate `Set-Cookie`
  headers rather than being folded together.

So given the example at the top, a request for `/assets/app.css` gets both
`X-Frame-Options: DENY` (from `/*`) and the long `Cache-Control` (from `/assets/*`).

## Setting `Content-Type`

`Content-Type` is special: instead of adding a response header, it overrides the
**media type** the canister stores for the matching files. This is the way to fix the
type of an extension-less or unusual file:

```
/llms.txt
  Content-Type: text/markdown; charset=utf-8
```

Unlike other headers, `Content-Type` is single-valued and first-match-wins.

## No headers are added for you

The canister applies **no default headers** — no `Cache-Control`, no security headers,
no CSP. If you want them, declare them in `_headers`. The only response headers the
canister manages on its own are the ones tied to how it serves and certifies content:
`Content-Type`, `Content-Encoding`, `ETag`, the certification headers, and (on HTML
responses) its own `ic_env` cookie.

A useful baseline to copy and adapt:

```
/*
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'

# Fingerprinted build assets never change — cache them hard
/assets/*
  Cache-Control: public, max-age=31536000, immutable

# HTML should revalidate so deploys are picked up
/*.html
  Cache-Control: public, max-age=0, must-revalidate
```

You may set `Set-Cookie` freely; note the canister adds its own `ic_env` cookie to
HTML responses, so don't reuse that name.

## Reserved headers

Some headers can't be set in `_headers`. The canister either computes them itself or
they have no meaning for a certified asset served through the IC HTTP gateway — a
wrong value would corrupt the response or simply be unverifiable. Rather than silently
ignore these (as some CDNs do, which leads to confusing bugs), the sync plugin
**rejects them at deploy time** with an explanatory error, so you find out
immediately.

| Header | Why it's reserved |
|--------|-------------------|
| `Content-Type` | Set it via the bare `Content-Type:` form above; it routes to asset metadata, not a response header. |
| `Content-Length` | The canister sets it from the asset body. |
| `Content-Encoding` | The canister negotiates gzip/Brotli/identity per request and sets it itself. |
| `ETag` | Derived from the content hash, so there is exactly one trustworthy validator. |
| `Transfer-Encoding` | Body framing is handled by the HTTP gateway, not the canister. |
| `Accept-Ranges`, `Content-Range` | The canister doesn't serve range (`206 Partial Content`) responses. |
| `IC-Certificate`, `IC-CertificateExpression` | These carry the response certificate and are canister-managed. |
| `Location` | A `Location` here wouldn't redirect (the status stays `200`). Use [`_redirects`](redirects.md) instead. |

This list is intentionally conservative and may be relaxed in future releases — it's
easier to allow a header later than to start rejecting one that sites already rely on.
