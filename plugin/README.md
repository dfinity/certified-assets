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

- [x] **`.ic-assets.json5` parsing** — per-directory config for `headers`, `max_age`, `allow_raw_access`, `enable_aliasing`, encoding overrides, and ignore globs.
  - Port `AssetSourceDirectoryConfiguration` and `AssetConfigRule` from `ic-asset/src/asset/config.rs` into `assets-sync`. The struct supports both `.ic-assets.json` and `.ic-assets.json5` via the `json5` crate.
  - Extend `AssetSource` (currently just `path` + `key`) to carry an `AssetConfig` resolved at scan time.
  - In `scan.rs`, load the config tree with `AssetSourceDirectoryConfiguration::load(root)` and call `get_asset_config(path)` for each file. Respect the `ignore` field to skip files, and skip the config files themselves (`.ic-assets.json`/`.ic-assets.json5`).
  - Thread the resolved `AssetConfig` through `prepare_asset` and into `build_operations` so that `CreateAssetArguments` fields (`max_age`, `headers`, `enable_aliasing`, `allow_raw_access`) are populated from config instead of hardcoded `None`.

- [x] **Warn on unmatched config rules** — track which `AssetConfigRule` glob patterns actually matched at least one asset during scanning, and warn about the unused ones so users are alerted to typos. Mirrors `ic-asset`'s `AssetSourceDirectoryConfiguration::get_unused_configs()` (see `ic-asset/src/asset/config.rs`).

- [x] **Security policy** — adopt `ic-asset`'s CSP / standard security headers. Depends on `.ic-assets.json5` parsing above.
  - Port `SecurityPolicy` enum (`disabled` / `standard` / `hardened`) and the `ConcreteSecurityPolicy` / `to_headers()` logic from `ic-asset/src/security_policy.rs` into `assets-sync`.
  - Wire it into `AssetConfig::combined_headers()` so that `security_policy` entries in `.ic-assets.json5` expand into the corresponding `Content-Security-Policy`, `Permissions-Policy`, `X-Frame-Options`, etc. headers before the headers map is passed to `CreateAssetArguments`.
  - Emit the same warnings as `ic-asset/src/sync.rs` (`gather_asset_descriptors`): warn when no security policy is set for any asset, warn when `standard` policy is in use (suggesting hardening), and error when `hardened` is declared but no custom headers are provided.

- [ ] **Asset properties update** — emit `SetAssetProperties` ops for assets whose properties drifted. Types are already in place.
  - Add a `get_asset_properties` call in `canister.rs` (the canister exposes `get_asset_properties` taking a list of keys; see `ic-asset/src/canister_api/methods/asset_properties.rs`).
  - Call it in `sync()` after `list_assets`, collecting a `HashMap<String, AssetProperties>`.
  - Add an `update_properties` step at the end of `build_operations`, mirroring `ic-asset/src/batch_upload/operations.rs::update_properties`: for each asset that already exists on the canister, compare `max_age`, `headers`, `allow_raw_access`, and `is_aliased` against the project config and push a `BatchOperationKind::SetAssetProperties` only when at least one field differs.
  - `SetAssetPropertiesArguments` is already defined in `canister.rs` and `BatchOperationKind::SetAssetProperties` is already a variant, so no new types are needed.

- [ ] **`commit_batch` chunking** — split operations across multiple `commit_batch` calls to stay within the ~2 MB ICP ingress message limit, matching `ic-asset` behaviour.
  - Replace the single `commit_batch` call in `sync()` with a `commit_in_stages` helper modelled on `ic-asset/src/sync.rs::commit_in_stages`.
  - Implement `create_commit_batches(ops)` that splits the operation list using two limits: 500 ops per batch (cert-tree work) and 1.5 MB of accumulated header data per batch (header maps dominate ingress size). Header size is the sum of key+value lengths across all `CreateAsset` and `SetAssetProperties` operations in the batch.
  - Each intermediate batch is committed with `batch_id = 0`; after all operation batches are committed, a final call with the real `batch_id` and an empty operations list closes the batch.

- [ ] **Multi-chunk upload via `create_chunks`** — send multiple small chunks per canister call instead of one, reducing round-trips for projects with many small files.
  - Add a `create_chunks` wrapper in `canister.rs` that calls the canister's `create_chunks` method (takes `batch_id` and `Vec<Vec<u8>>`, returns `Vec<Nat>` chunk IDs).
  - In `sync()`, replace the single-chunk loop with a batching uploader: accumulate chunks up to `MAX_CHUNK_SIZE` (1.9 MB) of total payload per call, then flush via `create_chunks`. The last chunk of each file can be sent inline as `last_chunk` in `SetAssetContentArguments` rather than as a separate chunk ID, saving one round-trip per file.

- [ ] **Brotli encoding** — wired into the encoder enum and `encode()` implementation but not selected by any policy.
  - Once `.ic-assets.json5` parsing is in place, encoding overrides from config (`"encodings": ["identity", "gzip", "br"]`) will naturally flow through `encoders_for` / `prepare_asset`, enabling Brotli for specific assets.
  - Remove the `#[allow(dead_code)]` on `Encoder::Brotli` in `content.rs` and add `br` as a recognised string in the `ContentEncoder` deserialisation (needed for the config parser).
  - Optionally add Brotli to the default encoder policy for compressible types, matching user expectations (the old `ic-asset` does not include it by default, but it could be added here).
