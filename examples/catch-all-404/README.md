# Catch-all 404

Serve your own 404 page for every unknown URL with a single `_redirects` rule,
layered on top of the auto-synthesised [clean URLs](../clean-urls/):

```
/* /404.html 404
```

The sync plugin places the synthesised clean-URL rules *before* your `_redirects`,
so real assets and their canonical redirects win, and the `/*` catch-all only
fires for paths nothing else claims. The 404 response is certified, so the gateway
delivers it rather than erroring.

It is exercised in CI by the `html_handling_with_catchall_redirect` and
`removed_redirect_rule_clears_cert_tree` tests in
[`crates/e2e/tests/redirects.rs`](../../crates/e2e/tests/redirects.rs) — this
combination once tripped a certification bug (a `/*` wildcard response conflicting
with the synthesised exact rules), and these tests guard the fix.

## What it demonstrates

- A `/*` catch-all that returns a **custom, certified** 404 for unknown paths.
- It coexists cleanly with clean-URL handling: `/` and `/foo` still serve their
  assets, `/index` still 307-redirects to `/`, and only truly unmatched URLs hit
  the catch-all.

## Project structure

```
catch-all-404
├── icp.yaml
└── dist
    ├── _redirects        # /* /404.html 404
    ├── index.html
    ├── foo.html
    ├── 404.html          # the custom catch-all page
    └── blog
        └── index.html
```

## Prerequisites

- [icp-cli](https://cli.icp.build)
- A Rust toolchain with the `wasm32-unknown-unknown` and `wasm32-wasip2` targets,
  plus `make`.

## Run it

```sh
make wasm                 # from the repo root; builds the wasms into ../../dist
cd examples/catch-all-404
icp network start -d
icp deploy
```

Note the `frontend` URL that `icp deploy` prints, then:

```sh
BASE="http://<canister-id>.localhost:<port>"
curl -i "$BASE/foo"                 # 200, real asset
curl -i "$BASE/this-does-not-exist" # 404, custom page
```

Stop the replica when you're done:

```sh
icp network stop
```
