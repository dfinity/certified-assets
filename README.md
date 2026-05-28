# Certified Assets

Two Wasm modules, each backed by a library crate:

```
         ┌────────────────────┐   ┌────────────────────┐
         │     canister/      │   │      plugin/       │
         │  deployed to ICP   │   │  loaded by icp-cli │
         └─────────┬──────────┘   └─────────┬──────────┘
                   │ wraps                  │ wraps
         ┌─────────▼──────────┐   ┌─────────▼──────────┐
         │  ic-certified-     │   │   assets-sync/     │
         │    assets/         │   │                    │
         └────────────────────┘   └────────────────────┘
```

## [`canister/`](canister/)

The ICP assets canister — a deployable WebAssembly canister that serves certified static assets over HTTP. It wraps `ic-certified-assets` and exposes the canister interface.

### [`ic-certified-assets/`](ic-certified-assets/)

The core business logic library. Handles asset storage, certification (response verification), streaming, and access control. `canister` depends on this crate; it can also be embedded in other canisters.

## [`plugin/`](plugin/)

A thin `icp-cli` sync plugin. Delegates all sync logic to `assets-sync`.

### [`assets-sync/`](assets-sync/)

Platform-agnostic library implementing the asset sync logic: directory scanning, MIME detection, content encoding, canister diffing, and the `CanisterCall` trait that abstracts the transport layer.

## Redirects, rewrites, and custom error pages

The canister honours a Netlify-style `_redirects` file at the root of the project's input directory. (The sync plugin only accepts one source directory — see [`plugin/README.md`](plugin/README.md#scope) for why.) Each line is `<from> <to> <status>`, where `<status>` is one of `{200, 301, 302, 307, 308, 404, 410}`:

```text
/old-page        /new-page              301   # 3xx redirect (Location header)
/external        https://example.com/   302
/about           /about.html            200   # 200 rewrite (serve target's body)
/blog/*          /blog/index.html       200   # subtree rewrite
/missing         /404.html              404   # custom error page
```

The file is consumed by the plugin and lowered to certified canister-side rules — a real asset at the rule's `from` path always wins, and the canister no longer performs implicit `.html` / `index.html` aliasing. See [`plugin/README.md`](plugin/README.md#redirects) for the full reference and migration notes.

## Per-path response headers

The canister also honours a Netlify-style `_headers` file at the root of the project's input directory. Each block is a non-indented `<pattern>` line followed by one or more indented `Header-Name: value` lines:

```text
/_astro/*
  Cache-Control: public, max-age=31536000, immutable

/*
  X-Frame-Options: DENY
  X-Robots-Tag: noindex
```

`<pattern>` is an absolute path; a trailing `/*` makes it a subtree match. All matching rules apply per the Cloudflare Pages / Netlify semantics — same-name values across rules concatenate with `, ` (RFC 7230), with `Set-Cookie` carved out (RFC 6265). The file is parsed by the plugin and lowered to per-asset header lists; `Content-Type` is reserved (derived from the asset's media type). See [`plugin/README.md`](plugin/README.md#headers) for the full reference and reject list.
