# icp-cli sync plugin

This crate is the sync plugin invoked by `icp-cli` for assets canister syncing.

## What

`icp-cli` added a new plugin system for canister syncing (operations that always run after canister module installation/upgrade).

This crate is an implementation of it that is supposed to be used with the [`assets canister`](../canister/) only.

It is a WASM component module that only access the functionalities exposed by the icp-cli plugin runtime.

It exports an `exec()` function which executes operations similar to the `sync()` function of the public `ic-asset` crate:
- Read access to one or more directories (assets to be uploaded)
- Sync them to a deployed assets canister

## How

The `icp-cli` project is at: `/Users/linwei.shang/dfinity/icp-cli`.
Its current `lwshang/sync_plugin` branch contains the runtime side of the plugin system:
- The runtime crate: `crates/icp-sync-plugin`
- An example: `examples/icp-sync-plugin`

The `ic-asset` crate (business logic) is at `/Users/linwei.shang/dfinity/sdk/src/canisters/frontend/ic-asset`. The protocol-level pieces (Candid types, batch/chunk upload flow, content encoding) were ported from there; the transport layer was rewritten on top of the host's `canister-call` import.

## Build

```sh
cargo build -p plugin --target wasm32-wasip2 --release
```

The output WASM lands at `../target/wasm32-wasip2/release/plugin.wasm` — the path that [`../example/icp.yaml`](../example/icp.yaml) references.

## Scope

The current implementation supports the V2 batch-upload protocol of the assets canister:
- Walks each directory passed via the manifest's `dirs:` setting.
- Hashes every file, computes `gzip` for text/HTML/JS, identity for everything else.
- Diffs against `list_assets()` and skips encodings that are already in place (matched by content_type + sha256).
- Creates a batch, uploads chunks via `create_chunk` (one chunk per call, 1.9 MB max), and commits the batch atomically.
- All canister calls are made `direct: true` (no proxy). The signing identity must therefore be a controller of the canister (or otherwise authorized by the canister's permission rules).

The plugin calls `api_version` first and aborts if the canister advertises anything below 2.

## TODO

- `.ic-assets.json5` parsing — per-directory config for `headers`, `max_age`, `allow_raw_access`, `enable_aliasing`, encoding overrides, ignore globs.
- Security policy — adopt `ic-asset`'s `security_policy.rs` (CSP / standard headers).
- Proxy support — route controller-gated calls through `--proxy` (`direct: false`) so a non-controller identity can still drive a sync.
- Batched chunk upload via `create_chunks` — fewer round-trips for projects with many small files.
- Asset properties update — emit `SetAssetProperties` ops for assets whose properties drifted.
- Brotli encoding — wired into the encoder enum but not selected by the default encoder policy.
