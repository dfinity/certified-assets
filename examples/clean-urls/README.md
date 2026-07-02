# Clean URLs (extensionless routing)

Serve `foo.html` at `/foo` and `blog/index.html` at `/blog/` — with no
configuration. When a project ships no `_redirects` file, the sync plugin
auto-synthesises [Cloudflare's `auto-trailing-slash`
rules](https://developers.cloudflare.com/pages/configuration/serving-pages/) for
every HTML asset, so pretty URLs and their canonical redirects just work, and
they're certified like everything else.

It is exercised in CI by the `html_handling_auto_synthesis` test in
[`crates/e2e/tests/redirects.rs`](../../crates/e2e/tests/redirects.rs), which
walks the full routing table through the HTTP gateway.

## What it demonstrates

For each HTML asset, the synthesised rules give one canonical URL and 307-redirect
the alternatives to it:

| Asset | Canonical URL (200) | Redirected (307) |
|---|---|---|
| `index.html` | `/` | `/index` |
| `foo.html` | `/foo` | `/foo/`, `/foo/index`, `/foo/index.html` |
| `blog/index.html` | `/blog/` | `/blog`, `/blog/index` |

An asset's own path still serves its body directly (e.g. `/foo.html` returns 200),
so existing deep links never break.

## Project structure

```
clean-urls
├── icp.yaml
└── dist                  # no _redirects — routing is synthesised
    ├── index.html
    ├── foo.html
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
cd examples/clean-urls
icp network start -d
icp deploy
```

Note the `frontend` URL that `icp deploy` prints, then:

```sh
BASE="http://<canister-id>.localhost:<port>"
curl -s  "$BASE/foo"     # 200, body of foo.html
curl -i  "$BASE/foo/"    # 307 → /foo
curl -i  "$BASE/blog"    # 307 → /blog/
```

Stop the replica when you're done:

```sh
icp network stop
```
