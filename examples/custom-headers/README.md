# Custom headers (`_headers`)

Attach your own HTTP response headers to assets using a
[`_headers`](https://developers.cloudflare.com/pages/configuration/headers/) file
— the same format Cloudflare Pages and Netlify use. The sync plugin parses it,
and the canister certifies the headers alongside the body, so the values your
visitors receive are the values you declared (the gateway rejects anything else).

It is exercised in CI by
[`crates/e2e/tests/headers.rs`](../../crates/e2e/tests/headers.rs), which deploys
this project and asserts the exact header values survive certification through the
gateway.

## What it demonstrates

- **Exact**, **subtree**, and **global** rules, and how they merge: `/index.html`
  gets its own security headers *plus* the global `X-Robots-Tag`.
- A one-year `immutable` `Cache-Control` on a fingerprinted asset directory
  (`/_astro/*`) — the standard pattern for hashed build output.
- Editing `_headers` and re-deploying propagates the new headers **without
  re-uploading content** (the plugin detects header drift and updates just those).

## Project structure

```
custom-headers
├── icp.yaml
└── dist
    ├── _headers          # the header rules
    ├── index.html        # picks up the /index.html + /* rules
    └── _astro
        └── app.js         # picks up the /_astro/* immutable-cache rule
```

## Prerequisites

- [icp-cli](https://cli.icp.build)
- A Rust toolchain with the `wasm32-unknown-unknown` and `wasm32-wasip2` targets,
  plus `make`.

## Run it

```sh
make wasm                 # from the repo root; builds the wasms into ../../dist
cd examples/custom-headers
icp network start -d
icp deploy
```

Note the `frontend` URL that `icp deploy` prints (it looks like
`http://<canister-id>.localhost:<port>`), then inspect the response headers:

```sh
curl -sI "http://<canister-id>.localhost:<port>/index.html"
```

You'll see `X-Frame-Options`, `X-Content-Type-Options`, and `X-Robots-Tag`. Fetch
`/_astro/app.js` the same way to see the `immutable` `Cache-Control`. Stop the
replica when done:

```sh
icp network stop
```
