# Architecture

This repo builds two WebAssembly modules — the assets **canister** (deployed to ICP) and the `icp-cli` sync **plugin** — each split into a logic library plus a thin wasm wrapper. All crates live under [`crates/`](../crates/):

| Crate | Kind | Role |
|-------|------|------|
| [`canister-core`](../crates/canister-core/) | library | Asset storage, certification (response verification), streaming, and access control. Can also be embedded in other canisters. |
| [`canister`](../crates/canister/) | `cdylib`, `wasm32-unknown-unknown` | Thin wrapper that exposes `canister-core` as the deployable ICP assets canister. |
| [`sync-core`](../crates/sync-core/) | library | Platform-agnostic sync logic: directory scanning, MIME detection, content encoding, canister diffing, and the `CanisterCall` trait that abstracts the transport layer. |
| [`sync-plugin`](../crates/sync-plugin/) | `cdylib`, `wasm32-wasip2` | Thin `icp-cli` sync plugin that wraps `sync-core`. |
| [`e2e`](../crates/e2e/) | tests | End-to-end tests driving the canister and plugin together through the `icp` CLI. |

The `*-core` crates hold the logic; the matching wrapper is just the wasm build target — `canister` wraps `canister-core`, `sync-plugin` wraps `sync-core`.
