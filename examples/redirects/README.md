# Redirects & rewrites (`_redirects`)

Control how URLs map to assets with a
[`_redirects`](https://developers.cloudflare.com/pages/configuration/redirects/)
file — the same format Cloudflare Pages and Netlify use. Redirects, custom error
pages, and rewrites are all certified, so the status code and `Location` your
visitors receive are exactly the ones you declared.

It is exercised in CI by
[`crates/e2e/tests/redirects.rs`](../../crates/e2e/tests/redirects.rs), which
deploys this project and drives every rule through the verifying HTTP gateway.

## What it demonstrates

Every response kind a `_redirects` rule can produce:

| Rule | Request | Result |
|---|---|---|
| `/old /new.html 301` | `/old` | permanent redirect to `/new.html` |
| `/legacy https://example.com/ 302` | `/legacy` | temporary redirect to an external URL |
| `/missing-page /404.html 404` | `/missing-page` | custom **Not Found** page, 404 status |
| `/gone-page /410.html 410` | `/gone-page` | custom **Gone** page, 410 status |
| `/about /about.html 200` | `/about` | **rewrite** — serves `about.html`, URL stays `/about` |
| `/blog/* /blog/index.html 200` | `/blog/anything` | **subtree rewrite** — one page for a whole prefix |

## Project structure

```
redirects
├── icp.yaml
└── dist
    ├── _redirects        # the rules above
    ├── about.html        # 200-rewrite target for /about
    ├── new.html          # 301 target for /old
    ├── 404.html          # custom Not Found page
    ├── 410.html          # custom Gone page
    └── blog
        └── index.html     # 200-rewrite target for /blog/*
```

## Prerequisites

- [icp-cli](https://cli.icp.build)
- A Rust toolchain with the `wasm32-unknown-unknown` and `wasm32-wasip2` targets,
  plus `make`.

## Run it

```sh
make wasm                 # from the repo root; builds the wasms into ../../dist
cd examples/redirects
icp network start -d
icp deploy
```

Note the `frontend` URL that `icp deploy` prints, then try the rules (`-i` shows
the status line and `Location`, `-L` would follow the redirect):

```sh
BASE="http://<canister-id>.localhost:<port>"
curl -i  "$BASE/old"           # 301 → /new.html
curl -i  "$BASE/legacy"        # 302 → https://example.com/
curl -i  "$BASE/missing-page"  # 404 with the custom page
curl -sL "$BASE/about"         # 200, body of about.html
```

Stop the replica when you're done:

```sh
icp network stop
```
