# Certified Assets

This repo builds two WebAssembly modules — the assets **canister** (deployed to ICP) and the icp-cli sync **plugin** — each split into a logic library plus a thin wasm wrapper. All crates live under [`crates/`](crates/):

| Crate | Kind | Role |
|-------|------|------|
| [`canister-core`](crates/canister-core/) | library | Asset storage, certification (response verification), streaming, and access control. Can also be embedded in other canisters. |
| [`canister`](crates/canister/) | `cdylib`, `wasm32-unknown-unknown` | Thin wrapper that exposes `canister-core` as the deployable ICP assets canister. |
| [`sync-core`](crates/sync-core/) | library | Platform-agnostic sync logic: directory scanning, MIME detection, content encoding, canister diffing, and the `CanisterCall` trait that abstracts the transport layer. |
| [`sync-plugin`](crates/sync-plugin/) | `cdylib`, `wasm32-wasip2` | Thin `icp-cli` sync plugin that wraps `sync-core`. |
| [`e2e`](crates/e2e/) | tests | End-to-end tests driving the canister and plugin together through the `icp` CLI. |

The `*-core` crates hold the logic; the matching wrapper is just the wasm build target — `canister` wraps `canister-core`, `sync-plugin` wraps `sync-core`.

## Redirects, rewrites, and custom error pages

The canister honours a Netlify-style `_redirects` file at the root of the project's input directory. (The sync plugin only accepts one source directory — see [`crates/sync-plugin/README.md`](crates/sync-plugin/README.md#scope) for why.) Each line is `<from> <to> <status>`, where `<status>` is one of `{200, 301, 302, 307, 308, 404, 410}`:

```text
/old-page        /new-page              301   # 3xx redirect (Location header)
/external        https://example.com/   302
/about           /about.html            200   # 200 rewrite (serve target's body)
/blog/*          /blog/index.html       200   # subtree rewrite
/missing         /404.html              404   # custom error page
```

The file is consumed by the plugin and lowered to certified canister-side rules — a real asset at the rule's `from` path always wins. Ahead of the user's `_redirects`, the plugin auto-synthesises Cloudflare's [`auto-trailing-slash`](https://developers.cloudflare.com/workers/static-assets/routing/advanced/html-handling/#automatic-trailing-slashes-default) rule set for every `.html` asset, so `/foo.html` is reachable as `/foo`, `/bar/index.html` is reachable as `/bar/`, and the non-canonical forms (`/foo/`, `/foo/index`, etc.) 307 to the canonical URL. User-declared rules apply to paths the html-handling defaults don't claim — e.g. a SPA-style `/* /404.html 404` catch-all only fires for paths with no matching HTML asset. See [`crates/sync-plugin/README.md`](crates/sync-plugin/README.md#redirects) for the full reference and migration notes.

## Per-path response headers

The canister also honours a Netlify-style `_headers` file at the root of the project's input directory. Each block is a non-indented `<pattern>` line followed by one or more indented `Header-Name: value` lines:

```text
/_astro/*
  Cache-Control: public, max-age=31536000, immutable

/*
  X-Frame-Options: DENY
  X-Robots-Tag: noindex
```

`<pattern>` is an absolute path with optional `*` wildcards — `/about` is exact, `/_astro/*` is a subtree, `/*.md` matches any `.md` file at any depth. A single `*` matches any sequence including `/` and empty; `**` is not supported (redundant) and neither is `:placeholder`. All matching rules apply per the Cloudflare Pages / Netlify semantics — same-name values across rules concatenate with `, ` (RFC 7230), with `Set-Cookie` carved out (RFC 6265). `Content-Type` is recognised but routed to the asset's stored media type instead of the appended response headers — see below. See [`crates/sync-plugin/README.md`](crates/sync-plugin/README.md#headers) for the full reference and reject list.

### `Content-Type` overrides

The canister derives a `Content-Type` for every asset from its media type and certifies it as part of the response. To override what `mime_guess::from_path` picks (or to add a `charset` parameter), set `Content-Type:` inside any `_headers` block:

```text
/*.md
  Content-Type: text/markdown; charset=utf-8

/*.did
  Content-Type: text/plain; charset=utf-8

/llms.txt
  Content-Type: text/plain; charset=utf-8
```

The plugin extracts `Content-Type` and feeds it into `CreateAssetArguments.content_type` rather than appending it as a response header — so the canister emits exactly one `Content-Type` per response, no duplicates. Other headers in the same block continue to flow through `headers` as usual. `Content-Type` is single-valued, so when multiple blocks match the same asset the first matching `Content-Type` wins (other matching rules still contribute their non-`Content-Type` headers as normal).
