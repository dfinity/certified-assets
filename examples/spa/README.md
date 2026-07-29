# Single-page app (SPA)

Serve a client-side-routed app — React, Vue, Svelte, or the 30 lines of vanilla
JS in this example — from a certified canister. The whole server-side contract is
one `_redirects` rule:

```
/*  /index.html  200
```

Any path no real asset (and no auto-synthesised [clean-URL](../clean-urls/) rule)
already claims serves the app shell with a **200**, so the router in the page can
read `location.pathname` and render. Every one of those responses is certified,
including the ones served at paths that have no file behind them.

Declaring a root `/*` also **replaces the default 404 page**: unknown paths get
the shell instead of an error, which is what a SPA wants — the app decides what a
bad route looks like.

## What it demonstrates

- **The `/*` fallback.** `/dashboard` and `/dashboard/settings/deep` have no
  files, yet both serve the shell with a 200 — on first load *and* on a full
  browser reload.
- **Static pages coexist.** `legal.html` is a real file, and files win over
  rules, so `/legal` serves it and the `/*` fallback never sees the request.
- **Headers reach client routes.** `_headers` patterns match the *file*, and a
  `200` rewrite reuses its target's headers — so the `Cache-Control` declared for
  `/*.html` is on the shell at every client route.
- **Absolute asset URLs.** The shell links `/assets/app.js`, not
  `assets/app.js`: at `/dashboard/settings` a relative path would request
  `/dashboard/settings/assets/app.js`, which the `/*` rule happily answers with
  the HTML shell.
- **An honest 404 for build output.** `/assets/* /404.html 404`, placed above the
  catch-all, keeps a missing bundle from being answered with the HTML shell and a
  200 — the failure mode that turns a stale script URL into a MIME-type error and
  a `fetch()` for missing JSON into unparseable HTML.

It is exercised in CI by [`crates/e2e/tests/spa.rs`](../../crates/e2e/tests/spa.rs).

## Project structure

```
spa
├── icp.yaml
└── dist
    ├── _redirects        # /assets/* → 404, then /*  /index.html  200
    ├── _headers          # cache the shell short, the bundle forever
    ├── index.html        # the app shell
    ├── legal.html        # a genuinely static page, alongside the app
    ├── 404.html          # for missing files under /assets/ only
    └── assets
        └── app.js        # the client-side router
```

A real project replaces `dist/` with a bundler's output directory and adds a
`build` step; see [the configuration reference](../../docs/overview.md#configuration).
If the app needs a backend canister's ID baked in, build it in
[`presync`](../../docs/overview.md#building-against-canister-ids-presync-vs-build)
instead.

## Prerequisites

- [icp-cli](https://cli.icp.build)
- A Rust toolchain with the `wasm32-unknown-unknown` and `wasm32-wasip2` targets,
  plus `make`.

## Run it

```sh
make wasm                 # from the repo root; builds the wasms into ../../dist
cd examples/spa
icp network start -d
icp deploy
```

Open the `frontend` URL that `icp deploy` prints and click through the nav — then
reload the page while on a nested route, which is the case that fails on hosts
without a SPA fallback. From the terminal:

```sh
BASE="http://<canister-id>.localhost:<port>"
curl -i "$BASE/dashboard/settings/deep"  # 200 + the shell, not a 404
curl -i "$BASE/legal"                    # 200 + legal.html — the file wins
curl -i "$BASE/assets/app.js"            # 200 + immutable Cache-Control
curl -i "$BASE/assets/app-old.js"        # 404 — a stale bundle URL, not the shell
```

Stop the replica when you're done:

```sh
icp network stop
```

## Caveats worth knowing

- **Outside `/assets/`, a missing file returns HTML, not a 404.** `/typo.js`
  matches `/*`, so it serves the shell with `Content-Type: text/html` and a 200 —
  the behaviour the scoped `/assets/*` rule exists to override. Widen that rule to
  cover wherever your bundler writes.
- **`404.html` is not the site-wide not-found page here.** The `/*` catch-all owns
  every other path, so this file is reached only through the `/assets/*` rule.
  Being a real file, it is also served directly at `/404.html` (and at `/404`, via
  its clean URL) with a 200.
- **Clean-URL aliases of real files still redirect.** `/index` 307s to `/` and
  `/legal/` 307s to `/legal`, because the synthesised rules are matched before
  your `_redirects`. Only unclaimed paths reach the `/*` fallback.
