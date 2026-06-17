# Architecture

This document is for **contributors**. If you're looking to *use* certified-assets to
deploy a site, start with the [user documentation](docs/overview.md) instead.

This repo builds two WebAssembly modules that work as a **version-locked pair**:

- the assets **canister** — deployed to ICP, it stores your files and serves them
  over HTTP with response certification; and
- the `icp-cli` sync **plugin** — it diffs a local directory against the canister
  and uploads only what changed.

The plugin refuses to sync a canister that reports a different version, so the two
always move together. See [Releasing](README.md#releasing) for what the version
number means.

## Crates

Each module is split into a logic **library** plus a thin **wasm wrapper**. The
`*-core` crates hold all the logic and compile natively, so the bulk of the code is
exercised by ordinary `cargo test` without a replica; the matching wrapper is just
the wasm build target. All crates live under [`crates/`](crates/):

| Crate | Kind | Role |
|-------|------|------|
| [`canister-core`](crates/canister-core/) | library | Asset storage, certification (response verification), streaming, and access control. Can also be embedded in other canisters. |
| [`canister`](crates/canister/) | `cdylib`, `wasm32-unknown-unknown` | Thin wrapper that exposes `canister-core` as the deployable ICP assets canister. |
| [`sync-core`](crates/sync-core/) | library | Platform-agnostic sync logic: directory scanning, MIME detection, content encoding, `_headers`/`_redirects` parsing, canister diffing, and the `CanisterCall` trait that abstracts the transport layer. |
| [`sync-plugin`](crates/sync-plugin/) | `cdylib`, `wasm32-wasip2` | Thin `icp-cli` sync plugin that wraps `sync-core`. |
| [`recipe-gen`](crates/recipe-gen/) | library + bin | Renders the `icp-cli` recipe (`recipe.hbs`) that wires the canister build and the sync plugin together. |
| [`e2e`](crates/e2e/) | tests | End-to-end tests driving the canister and plugin together through the `icp` CLI. |

The `*-core` crates hold the logic; the matching wrapper is just the wasm build
target — `canister` wraps `canister-core`, `sync-plugin` wraps `sync-core`.

## How a request is served

1. A browser requests a URL. The IC **HTTP gateway** turns it into an `http_request`
   call to the canister.
2. The canister picks the best stored encoding for the client's `Accept-Encoding`,
   handles conditional requests (`If-None-Match` → `304`), and returns a response
   carrying its certificate. Large bodies are returned in chunks via a streaming
   callback.
3. The gateway verifies the certificate against the canister's certified data before
   forwarding the response, so the browser only ever sees content the canister has
   provably committed to.

The user-facing side of all this — clean URLs, redirects, headers, compression,
ETag/304 — is documented under [`docs/`](docs/overview.md). The deeper "why" lives in
[Under the hood](docs/how-it-works.md).

## Where things live

- **Canister behavior** (serving, certification, permissions, stable state) →
  [`crates/canister-core/src/`](crates/canister-core/src/), tested in
  [`tests.rs`](crates/canister-core/src/tests.rs).
- **Sync behavior** (scanning, encoding, `_headers`/`_redirects`, diffing) →
  [`crates/sync-core/src/`](crates/sync-core/src/), with inline `#[cfg(test)]` tests
  per module.
- **The public Candid interface** → [`certified-assets.did`](certified-assets.did).
- **Build, release, and recipe mechanics** → [`README.md`](README.md).
