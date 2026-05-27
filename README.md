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

The canister honours a Netlify-style `_redirects` file at the root of each input directory. Each line is `<from> <to> <status>`, where `<status>` is one of `{200, 301, 302, 307, 308, 404, 410}`:

```text
/old-page        /new-page              301   # 3xx redirect (Location header)
/external        https://example.com/   302
/about           /about.html            200   # 200 rewrite (serve target's body)
/blog/*          /blog/index.html       200   # subtree rewrite
/missing         /404.html              404   # custom error page
```

The file is consumed by the plugin and lowered to certified canister-side rules — a real asset at the rule's `from` path always wins, and the canister no longer performs implicit `.html` / `index.html` aliasing. See [`plugin/README.md`](plugin/README.md#redirects) for the full reference and migration notes.
