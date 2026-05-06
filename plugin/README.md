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

The runtime side of the plugin system lives in [`github.com/dfinity/icp-cli`](https://github.com/dfinity/icp-cli):
- The runtime crate: `crates/icp-sync-plugin`
- An example: `examples/icp-sync-plugin`

All sync logic (directory scanning, MIME detection, content encoding, canister diffing, and per-endpoint call wrappers) lives in the [`assets-sync`](../assets-sync/) library crate. This plugin crate is a thin WASI/WIT wrapper: it implements the `CanisterCall` trait (`WasiCall`) on top of the host's `canister-call` import, then delegates to `assets_sync::sync::sync()`.

The protocol-level pieces (Candid types, batch/chunk upload flow, content encoding) were ported from the `ic-asset` crate in [`github.com/dfinity/sdk`](https://github.com/dfinity/sdk) (`src/canisters/frontend/ic-asset`). The transport layer was rewritten on top of the host's `canister-call` import.

## Build

```sh
cargo build -p plugin --target wasm32-wasip2 --release
```

The output WASM lands at `../target/wasm32-wasip2/release/plugin.wasm` — the path that [`../example/icp.yaml`](../example/icp.yaml) references.

## Scope

The current implementation supports the V2 protocol of the assets canister (transactional batch API):
- Walks each directory passed via the manifest's `dirs:` setting; dotfiles are skipped.
- Detects the MIME type of each file and computes encodings: `gzip` for all `text/*`, `*/javascript`, and `*/html` types (only if the compressed output is smaller), `identity` for everything.
- Diffs against `list_assets()`: skips encodings already in place (matched by sha256), unsets encodings that are stale, and deletes assets that have been removed or whose `content_type` changed.
- Opens a transaction (`create_batch`), uploads each content chunk via `create_chunk` (one canister call per chunk, 1.9 MB max), then commits all operations atomically with a single `commit_batch` call.
- In normal mode all canister calls use `direct: true`. In proxy mode (when a `proxy_canister_id` is provided by the host) the plugin first ensures the signing identity has `Commit` permission, routing a `grant_permission` call through the proxy (which is the canister's controller) if needed, then proceeds with direct calls.

The plugin calls `api_version` first and aborts if the canister advertises anything below 2.

## TODO

- `.ic-assets.json5` parsing — per-directory config for `headers`, `max_age`, `allow_raw_access`, `enable_aliasing`, encoding overrides, ignore globs.
- Security policy — adopt `ic-asset`'s `security_policy.rs` (CSP / standard headers).
- Multi-chunk upload via `create_chunks` — send multiple chunks per canister call instead of one, reducing round-trips for projects with many small files.
- Asset properties update — emit `SetAssetProperties` ops for assets whose properties drifted.
- Brotli encoding — wired into the encoder enum but not selected by the default encoder policy.
- `commit_batch` chunking — split operations across multiple `commit_batch` calls to stay within the ~2 MB ICP ingress message limit, matching `ic-asset` behaviour.
