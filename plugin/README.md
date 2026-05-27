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
- The manifest's `dirs:` setting must list **exactly one** directory. The plugin rejects the sync before any canister call if zero or multiple entries are given — the assets canister owns the URL space below `/`, and a single tree keeps key collisions and `_redirects` precedence unambiguous.
- Walks that directory; dotfiles are skipped.
- Detects the MIME type of each file and computes encodings: `gzip` for all `text/*`, `*/javascript`, and `*/html` types (only if the compressed output is smaller), `identity` for everything.
- Diffs against `list_assets()`: skips encodings already in place (matched by sha256), unsets encodings that are stale, and deletes assets that have been removed or whose `content_type` changed.
- Reads `_redirects` at the root of the input directory and replaces the canister's ruleset in the same batch (see "Redirects" below).
- Opens a transaction (`create_batch`), uploads each content chunk via `create_chunks` (one chunk per call, 1.9 MB max), then commits all operations atomically with a single `commit_batch` call.
- In normal mode all canister calls use `direct: true`. In proxy mode (when a `proxy_canister_id` is provided by the host) the plugin first ensures the signing identity has `Commit` permission, routing a `grant_permission` call through the proxy (which is the canister's controller) if needed, then proceeds with direct calls.

The plugin calls `api_version` first and aborts if the canister advertises anything below 2.

## Redirects

The plugin reads a Netlify-style `_redirects` file at the root of the input directory (`dirs:` must list exactly one). The file itself is **not** uploaded as an asset — it's consumed by the plugin and lowered into canister-side rules. Each non-empty, non-comment line:

```
<from>  <to>  <status>
```

- `<from>` — absolute path. A trailing `/*` makes the rule match every URL whose path starts with the prefix (subtree). Anywhere else, `*` is an error.
- `<to>` — absolute path for `200` rewrites and `4xx` custom error pages. For `3xx` rules it may also be a fully-qualified URL (sent in the `Location` header).
- `<status>` — required integer, one of `{200, 301, 302, 307, 308, 404, 410}`. Unlike Netlify, there is no default; the explicit number keeps the intent (rewrite vs. redirect vs. error) unambiguous.
- Lines starting with `#` and blank lines are ignored. Inline `# comments` at the end of a rule line are stripped before parsing.

### Examples

```text
# 3xx — issue a Location-header redirect
/old-page        /new-page              301
/external        https://example.com/   302

# 200 — rewrite: serve the target asset's body at the source URL
/about           /about.html            200
/blog/*          /blog/index.html       200

# 4xx — custom error page (serves the target asset's body with the override status)
/missing         /404.html              404
/gone            /tombstone.html        410
```

A real asset at the rule's `from` path always wins — a file at `/about.html` is served at `/about.html` regardless of any rule. For 200 rewrites and 4xx error pages, the target asset's existing `Content-Type` and certified headers are inherited verbatim; the rule itself can't override them.

Rule order is significant: the plugin sends rules in declaration order, and the canister returns the first match. Replacing the file is a full replace-all operation — if you remove `_redirects` between deploys, the plugin emits an empty `SetRedirectRules` op so the canister clears its ruleset.

### Migration from built-in aliasing

Earlier versions of this canister implicitly served `/foo.html` at `/foo` and `/foo/index.html` at both `/foo/` and `/foo`. That behaviour has been removed — express the same routing explicitly in `_redirects`:

```text
# Replace "extensionless HTML" aliasing
/foo             /foo.html              200

# Replace per-directory index aliasing
/blog/           /blog/index.html       200

# SPA fallback (formerly served implicitly when no other asset matched)
/*               /index.html            200
```

The `enable_aliasing` field in `.ic-assets.json5` and `is_aliased` on `set_asset_properties` are no longer honoured by the plugin; the canister will drop them in a follow-up cleanup. If your config still sets `enable_aliasing`, the plugin emits a warning pointing you at `_redirects`.

### Unsupported syntax

- `:splat` and `:placeholder` substitution in `<to>` — deferred (see the design plan's tier-3 follow-up).
- Netlify's `!` force suffix on status codes — files always win over rules at the same path; remove the conflicting asset instead.
- Country/role conditions and query-string matching — out of scope.
- Inline headers as a fourth field — headers will arrive via a separate `_headers` file in a later track.

Parse errors abort the sync with the offending file path and 1-based line number, before any canister call is issued.

## TODO

- [x] **`.ic-assets.json5` parsing** — per-directory config for `headers`, `max_age`, `allow_raw_access`, `enable_aliasing`, encoding overrides, and ignore globs.
  - Port `AssetSourceDirectoryConfiguration` and `AssetConfigRule` from `ic-asset/src/asset/config.rs` into `assets-sync`. The struct supports both `.ic-assets.json` and `.ic-assets.json5` via the `json5` crate.
  - Extend `AssetSource` (currently just `path` + `key`) to carry an `AssetConfig` resolved at scan time.
  - In `scan.rs`, load the config tree with `AssetSourceDirectoryConfiguration::load(root)` and call `get_asset_config(path)` for each file. Respect the `ignore` field to skip files, and skip the config files themselves (`.ic-assets.json`/`.ic-assets.json5`).
  - Thread the resolved `AssetConfig` through `prepare_asset` and into `build_operations` so that `CreateAssetArguments` fields (`max_age`, `headers`, `enable_aliasing`, `allow_raw_access`) are populated from config instead of hardcoded `None`.

- [x] **Warn on unmatched config rules** — track which `AssetConfigRule` glob patterns actually matched at least one asset during scanning, and warn about the unused ones so users are alerted to typos. Mirrors `ic-asset`'s `AssetSourceDirectoryConfiguration::get_unused_configs()` (see `ic-asset/src/asset/config.rs`).

- [x] **Asset properties update** — emit `SetAssetProperties` ops for assets whose properties drifted on the canister. `get_asset_properties` is called after `list_assets` to collect the current `AssetProperties` for every canister asset, and `update_properties` compares `max_age`, `headers`, and `allow_raw_access` field-by-field against the resolved project config (headers compared order-insensitively). Mirrors `ic-asset/src/batch_upload/operations.rs::update_properties`. (`is_aliased` is no longer carried; the canister will drop it in a follow-up cleanup PR.)

- [ ] **Header representation: `Map` → `Vec<(name, value)>`** — replace `Option<BTreeMap<String, String>>` / `Option<HashMap<String, String>>` with a list of pairs across `ic-certified-assets` (`Asset`, `AssetProperties`, `CreateAssetArguments`, `SetAssetPropertiesArguments`, `build_headers`, `evidence::hash_headers`) and `assets-sync` (`canister::AssetProperties`, `config::HeadersConfig`, `update_properties`). Wire type `vec record { text; text }` is already a list, so this is a Rust-only change — no Candid breaking change, no stable-storage migration. Lets users have multiple `Set-Cookie` values (and removes the tactical Set-Cookie filter in `update_properties` once the canister appends rather than overwrites `ic_env`). Sort by `(name, value)` for deterministic certification/evidence hashing.

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
