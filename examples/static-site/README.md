# Static site (getting started)

The smallest possible `certified-assets` project: an `index.html` and a
stylesheet, synced to an asset canister and served — certified — over HTTP. Start
here if you're new to the tooling.

It is exercised in CI by several e2e tests (e.g.
[`crates/e2e/tests/sync.rs`](../../crates/e2e/tests/sync.rs)), which deploy this
project to a local replica and check the deploy/re-sync/update/delete workflow.

## What it demonstrates

- The minimal `icp.yaml`: one `frontend` asset canister, built from a pre-built
  canister wasm, with the sync plugin serving a single `dist/` directory.
- A plain `icp deploy` uploads changed files and skips unchanged ones — re-running
  it with no edits reports "up to date" and touches nothing.
- Every asset is served with a certified response, so the gateway can verify it.

## Project structure

```
static-site
├── icp.yaml          # the `frontend` asset canister config
└── dist              # the site that gets synced
    ├── index.html
    └── style.css
```

## Prerequisites

- [icp-cli](https://cli.icp.build)
- A Rust toolchain with the `wasm32-unknown-unknown` and `wasm32-wasip2` targets
  (to build the canister + plugin), plus `make`.

## Run it

From the repo root, build the canister and sync-plugin wasms — this example's
`icp.yaml` references them at `../../dist/`:

```sh
make wasm
```

Deploy to a local replica:

```sh
cd examples/static-site
icp network start -d
icp deploy
```

Open the `frontend` URL that `icp deploy` prints (it looks like
`http://<canister-id>.localhost:<port>`) — you'll see the page.

Edit `dist/index.html`, run `icp deploy` again, and reload: only the changed file
is re-uploaded. Stop the replica when you're done:

```sh
icp network stop
```
