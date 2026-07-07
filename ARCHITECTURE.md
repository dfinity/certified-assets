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

A third, native tool — the [`state-hash`](crates/state-hash-cli/) verifier CLI — lets
anyone check that a canister serves exactly a known build, by recomputing its
**state hash** offline from source. See [Verifying contents](#verifying-contents).

## Crates

Each deployable module is a logic **library** plus a thin **wasm wrapper**
(`canister`/`canister-core`, `sync-plugin`/`sync-core`). The `*-core` libraries hold
the logic and compile natively, so the bulk of the code is exercised by ordinary
`cargo test` without a replica; the matching wrapper is just the wasm build target.
A few dependency-light **support libraries** are shared across modules, and one
**native binary** is the standalone verifier. All crates live under
[`crates/`](crates/):

| Crate | Kind | Role |
|-------|------|------|
| [`wire-types`](crates/wire-types/) | library (shared) | The Candid wire types crossing between canister and plugin, plus the shared release `Version`. Dependency-light so both sides share one definition. |
| [`state-hash`](crates/state-hash/) | library (shared) | The canonical **state hash**: the `Manifest` type, the frozen byte format, and `digest`. Computed identically by the canister (from stored state) and the offline verifier (from `dist/`). |
| [`canister-core`](crates/canister-core/) | library | Asset storage, certification (response verification), large-asset range serving, access control, and the cached state hash. Can also be embedded in other canisters. |
| [`canister`](crates/canister/) | `cdylib`, `wasm32-unknown-unknown` | Thin wrapper that exposes `canister-core` as the deployable ICP assets canister. |
| [`asset-prep`](crates/asset-prep/) | library (native) | Turns a `dist/` directory into prepared assets + redirect rules + the `state-hash` `Manifest`: directory scanning, MIME detection, content encoding/chunking/hashing, `_headers`/`_redirects` parsing, and html-handling/404 synthesis. One preparation path shared by `sync-core` and the verifier. |
| [`sync-core`](crates/sync-core/) | library | Canister-call orchestration: diffing prepared assets against current canister state, chunk upload/batching, staged execution, authorization, and the `CanisterCall` trait that abstracts the transport. |
| [`sync-plugin`](crates/sync-plugin/) | `cdylib`, `wasm32-wasip2` | Thin `icp-cli` sync plugin that wraps `sync-core`. |
| [`state-hash-cli`](crates/state-hash-cli/) | bin (native) | Standalone offline verifier (`state-hash <dist>`): computes a directory's state hash to compare against a canister's `state_hash()`. Depends only on `asset-prep` (+ `state-hash`), so it carries no canister-call, identity, or deploy code — a minimal trusted surface. |
| [`recipe-gen`](crates/recipe-gen/) | library + bin | Renders the `icp-cli` recipe (`recipe.hbs`) that wires the canister build and the sync plugin together. |
| [`e2e`](crates/e2e/) | tests | End-to-end tests driving the canister and plugin together through the `icp` CLI, by deploying the runnable [`examples/`](examples/) (and a few test-only fixtures) to a local replica. |

The local preparation (`asset-prep`) is deliberately split from the canister-call
orchestration (`sync-core`) so the verifier can reuse the *exact* preparation a sync
runs without linking any deploy capability.

## How a request is served

1. A browser requests a URL. The IC **HTTP gateway** turns it into an `http_request`
   call to the canister.
2. The canister picks the best stored encoding for the client's `Accept-Encoding`,
   handles conditional requests (`If-None-Match` → `304`), and returns a response
   carrying its certificate. Large bodies are split into chunks, each served as a
   certified `206` range response that the gateway reassembles into the full `200`.
3. The gateway verifies the certificate against the canister's certified data before
   forwarding the response, so the browser only ever sees content the canister has
   provably committed to.

The user-facing side of all this — clean URLs, redirects, headers, compression,
ETag/304 — is documented under [`docs/`](docs/overview.md). The deeper "why" lives in
[Under the hood](docs/how-it-works.md).

## Inside `canister-core`

The crate is organized into three layers, each with a deliberately narrow public
surface so the ones above can't reach into the ones below:

- [`store/`](crates/canister-core/src/store/) — the **durable** layer. `Store` is
  the sole owner of everything persisted in stable memory via `ic-stable-structures`
  (the authorized set, redirect rules, per-asset metadata, content chunks, tokens,
  the cached state hash) and the only place that touches a `StableCell`/
  `StableBTreeMap` or the `MemoryId` layout. Content bytes go through a private
  `chunks` submodule.
- [`cert/`](crates/canister-core/src/cert/) — the **certification** layer.
  `Certifier` owns the derived certified-response tree, the per-rule certified
  entries, and the env cookie, plus the policy that keeps each certified leaf
  byte-identical to the served response. Its Merkle-tree primitives stay private;
  only a small vocabulary of addressing/hashing helpers is re-exported.
- [`state/`](crates/canister-core/src/state/) — the **orchestrator**. `State`
  composes one `Store` and one `Certifier` (plus transient upload/session state and
  the hot-path token index) and holds all the behavior, split across per-concern
  submodules: `assets`, `rules`, `env`, `hashing`, `serving`, `sync`, `protection`,
  and `upgrade`. Every `impl State` block lives here, so the composed pieces stay
  private to this module tree.

The crate's own [`lib.rs`](crates/canister-core/src/lib.rs) holds the one `State`
instance and the entrypoints that forward to it; the thin
[`canister`](crates/canister/) wasm wrapper just re-exposes those as ICP endpoints.
There is no `pre_upgrade`/`post_upgrade` serialize step — durable state lives in
`store/` and survives upgrades untouched, and `post_upgrade` only rebuilds the derived
heap state (the certified tree) from it.

## Verifying contents

Certification proves each response matches what the canister *committed to*; the
**state hash** proves what it committed to matches a known source build. It is a
single SHA-256 over the canister's served-content model — every asset's
`content_type`, headers, and per-encoding content hashes, plus the redirect rules.

The key property is that one set of bytes is hashed two ways and must agree:

- the **canister** recomputes the hash at the end of every sync, folding its stored
  metadata + certified content hashes into a `state-hash::Manifest`, and caches it for
  the public `state_hash()` endpoint;
- the **verifier** (`state-hash-cli`) builds the *same* `Manifest` from a local
  `dist/` via `asset-prep` — the very code a real sync uses — and digests it.

Because both sides go through the one `asset-prep` preparation path and the one
`state-hash` byte format, a matching hash means the canister serves exactly the build
the verifier reproduced from source. The trust root is the source, never an operator's
reported number. User-facing details: [Verifying contents](docs/verifying-contents.md).

## Where things live

- **Canister behavior** (serving, certification, permissions, stable state, the
  cached state hash) → [`crates/canister-core/src/`](crates/canister-core/src/),
  layered into [`store/`](crates/canister-core/src/store/) (durable stable-memory
  state), [`cert/`](crates/canister-core/src/cert/) (the certified-response tree),
  and [`state/`](crates/canister-core/src/state/) (the `State` orchestrator, split
  into per-concern submodules) — see [Inside `canister-core`](#inside-canister-core).
  Tested in [`state/tests.rs`](crates/canister-core/src/state/tests.rs).
- **Local `dist/` preparation** (scanning, encoding, `_headers`/`_redirects`,
  html-handling/404, content hashing, the state-hash `Manifest`) →
  [`crates/asset-prep/src/`](crates/asset-prep/src/), with inline `#[cfg(test)]` tests
  per module.
- **Canister-call orchestration** (diffing, chunk upload, staged execution, auth) →
  [`crates/sync-core/src/`](crates/sync-core/src/).
- **The state-hash format** → [`crates/state-hash/src/`](crates/state-hash/src/); the
  **offline verifier** → [`crates/state-hash-cli/`](crates/state-hash-cli/).
- **The public Candid interface** → [`certified-assets.did`](certified-assets.did).
- **Runnable examples**, each doubling as an e2e test → [`examples/`](examples/),
  deployed by [`crates/e2e/`](crates/e2e/).
- **Build, release, and recipe mechanics** → [`README.md`](README.md).
