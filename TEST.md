# Test Plan

This document describes the testing strategy for the certified-assets project and provides a PR-level checklist for implementation.

---

## Guiding Principles

- **No BATS.** All tests use native Rust test infrastructure (`#[test]`, `cargo test`).
- **Three layers**: canister unit tests, plugin unit tests, and full E2E tests via the `icp` CLI.
- **Scope**: Proposal/governance workflows are out of scope. The `icp` CLI with the sync plugin replaces both `icx-asset` and `dfx deploy` from the old SDK project.

---

## Layer 1 — Canister Unit Tests (`ic-certified-assets`)

**Location**: `ic-certified-assets/src/tests.rs`  
**Run**: `cargo test -p ic-certified-assets`  
**Status**: Comprehensive (5,277 lines). No new tests planned for this layer.

This test suite covers all canister behaviors using a mock system context (no live replica needed):

| Area | Coverage |
|---|---|
| Batch API | `create_batch`, `commit_batch`, `drop_batch`; atomicity; batch timeout; batch ID persistence across upgrades |
| Asset serving | Encoding selection (identity, gzip, brotli); `Accept-Encoding` negotiation; correct response body |
| SPA fallback | `index.html` served for missing paths when aliasing is enabled |
| Stable state | Upgrade/downgrade roundtrips; state survives canister upgrade |
| Streaming | Chunked delivery for large assets |
| HTTP semantics | Custom headers; `Cache-Control` / `max-age`; ETags; `Content-Integrity` |
| Aliases | Enable/disable aliasing behavior |
| IC environment | Root key encoding; public environment cookie |
| Certification | `ic_certification` tree insertions/deletions; V2 certification correctness |
| Permissions | `grant_permission`, `revoke_permission`, `list_permitted` |

---

## Layer 2 — Library Unit Tests (`assets-sync/`)

**Location**: Inline `#[cfg(test)]` modules in each source file.  
**Run**: `cargo test -p assets-sync`

All sync business logic lives in the `assets-sync` library crate, which has no WIT or WASI dependencies and compiles natively. The plugin crate itself contains only the `WasiCall` transport wrapper and has no testable logic of its own.

### 2a. `scan.rs` — Directory Scanning

Tests for `scan()` and the private `walk()` function using `tempfile` fixtures:

| Test | Asserts |
|---|---|
| Single file | Key is `/<filename>` with leading slash |
| Nested directory | Recursive walk; key is `/<subdir>/<file>` |
| Dotfile skipped | `.hidden` and `.gitignore` do not appear in results |
| Empty directory | Returns empty `Vec` |
| Duplicate key across two source dirs | Returns `Err` with the offending key named |
| Multiple source dirs | Files from both dirs merged into one result |
| Symlink skipped | All symlinks (to files or directories) are excluded from results |

### 2b. `content.rs` — MIME Detection and Encoding

Tests for `encoders_for()`, `Content::load()`, `Content::encode()`, `Content::sha256()`:

| Test | Asserts |
|---|---|
| `text/html` → encoder list | Returns `[Identity, Gzip]` |
| `text/css` → encoder list | Returns `[Identity, Gzip]` |
| `application/javascript` → encoder list | Returns `[Identity, Gzip]` |
| `text/javascript` → encoder list | Returns `[Identity, Gzip]` |
| `image/png` → encoder list | Returns `[Identity]` only |
| `application/wasm` → encoder list | Returns `[Identity]` only |
| Unknown extension → encoder list | Falls back to `APPLICATION_OCTET_STREAM`; returns `[Identity]` |
| `encode(Identity)` | Output data equals input data |
| `encode(Gzip)` | Output is valid gzip; decompressed equals input |
| `encode(Brotli)` | Output is valid brotli; decompressed equals input |
| `sha256()` | Same content produces same digest; different content produces different digest |
| `Content::load()` — HTML | Reads file bytes; infers `text/html` from `.html` extension |
| `Content::load()` — PNG | Infers `image/png` from `.png` extension |
| `Content::load()` — unknown | Falls back to `application/octet-stream` for unrecognised extensions |

### 2c. `sync.rs` — Operation Diffing (`build_operations`)

`build_operations` is a pure function: it takes `project_assets` and `canister_assets` maps and returns a `Vec<BatchOperationKind>`. It is tested inline via `#[cfg(test)]` without any canister calls. Because `assets-sync` has no WIT dependency, these tests compile and run natively with no extra stubs needed.

| Test | Asserts |
|---|---|
| New asset (not on canister) | Emits `CreateAsset` + `SetAssetContent` ops |
| Unchanged asset (SHA256 matches) | `already_in_place = true`; emits no ops for that encoding |
| Updated asset (SHA256 differs) | Emits `SetAssetContent`; no `CreateAsset` |
| Deleted asset (on canister, not in project) | Emits `DeleteAsset` |
| Content-type mismatch (same key, MIME changed) | Emits `DeleteAsset` + `CreateAsset` + `SetAssetContent` |
| Stale encoding on canister (e.g. `gzip` present but project only has `identity`) | Emits `UnsetAssetContent` for the stale encoding |
| New encoding added (e.g. file now compressible) | Emits `SetAssetContent` for the new encoding |
| Empty project, non-empty canister | All canister assets deleted |
| Everything in sync | Returns empty `Vec`; `commit_batch` not called |
| Gzip skipped when compressed ≥ original size | No `SetAssetContent` op for `gzip` encoding |

---

## Layer 3 — E2E Integration Tests (`e2e/`)

**Location**: New workspace member crate at `e2e/`  
**Run**: `cargo test -p e2e`

These tests verify the complete pipeline: `plugin.wasm` built → loaded by `icp` → assets synced to a live canister.

### Infrastructure

The `e2e/` crate uses:

| Crate | Role |
|---|---|
| `assert_cmd` | Invokes `icp` as a subprocess and asserts exit code / stdout |
| `tempfile` | Provides throwaway asset directories and `icp.yaml` configs |
| `candid` | Decodes binary Candid responses into typed structs |
| `hex` | Decodes hex output from `icp canister call -o hex` |
| `serde_json` | Parses JSON output from `icp network status --json` |

**Build script** (`e2e/build.rs`): Before any tests run, `build.rs` compiles `canister.wasm` (`wasm32-unknown-unknown`) and `plugin.wasm` (`wasm32-wasip2`) via nested `cargo build` invocations and exposes their paths as `CANISTER_WASM` / `PLUGIN_WASM` env vars baked into the test binary at compile time.

**Setup per test**:
1. Copy a committed fixture directory into a `TempDir` and place the pre-built WASMs under `wasms/`.
2. Start a local network with `icp network start -d`; shut it down with `icp network stop` in test cleanup.
3. Run `icp deploy` to install the canister WASM and execute the plugin sync step.
4. Verify the resulting canister state with `icp canister call` using `-o hex` to obtain binary Candid, decoded into typed structs.

#### Network lifecycle and teardown pattern

`LocalNetwork::start(project_dir)` in `e2e/src/lib.rs` encapsulates the start/stop lifecycle:

```rust
let _network = LocalNetwork::start(&project); // runs `icp network start -d`
// … test body …
// _network is dropped here → runs `icp network stop`
```

Key points:
- **Daemon mode** (`-d`): `icp network start -d` blocks until the replica is ready, then returns.
  The replica process continues running in the background.
- **State directory**: the replica writes its state to `.icp/` inside the project directory.
  Each test that uses a `tempfile::TempDir` as its project root therefore gets an isolated network state.
- **Teardown on panic**: `LocalNetwork` implements `Drop`, so `icp network stop` is called even when the test panics or the assertion fails.
- **Silent cleanup**: `Drop` ignores errors from `icp network stop` because the replica may have already exited.
- **Project root**: `icp` locates `icp.yaml` via a `--project-root-override=<dir>` flag rather than
  relying on `$PWD` or `getcwd(2)`.  The `icp_cmd(dir)` helper in `e2e/src/lib.rs` sets this flag
  automatically; always use it instead of `Command::new("icp")` directly.

#### Parsing `icp canister call` output

Pass `-o hex` to `icp canister call` to receive the raw binary Candid response as a hex string instead of pretty-printed text.  Decode it with `hex::decode` and then `candid::decode_args` into the typed structs defined in `e2e/src/lib.rs` (`AssetDetails`, `AssetEncodingDetails`).  This avoids `candid_parser` and dynamic `IDLValue` traversal.

### Test Scenarios

#### Basic Sync Workflow

| Test | Scenario | Asserts |
|---|---|---|
| Basic deploy | Empty canister, one HTML file | `/index.html` present in canister asset list |
| Basic deploy with proxy | Deploy via proxy canister | `/index.html` present after proxy-mode deploy |
| No-op sync | Run sync a second time without changes | Plugin logs "already up to date"; canister state unchanged |
| Content update | Modify HTML file content; re-sync | SHA256 on canister updated; other assets unchanged |
| Asset deletion | Remove a file from the local directory; re-sync | Key deleted from canister; remaining assets intact |
| Multi-directory | Two source dirs with non-overlapping files | All files from both dirs uploaded; keys namespaced correctly |

#### Encoding Policy

| Test | File type | Asserts |
|---|---|---|
| Text file gets gzip | `.html` / `.css` / `.js` | Canister holds both `identity` and `gzip` encodings |
| Binary file identity-only | `.png` / `.wasm` | Canister holds `identity` encoding only; no `gzip` |
| Gzip skipped when not smaller | Tiny text file where gzip output ≥ original | Only `identity` encoding stored |

#### Large File / Chunking

| Test | Scenario | Asserts |
|---|---|---|
| Multi-chunk upload | File > 1.9 MB | Plugin splits into multiple chunks; canister reconstructs correctly; SHA256 verified end-to-end |

#### Asset Listing and Pagination

| Test | Scenario | Asserts |
|---|---|---|
| Pagination | Sync > 100 assets | `list_assets` pagination loop retrieves all assets; count matches local files |

#### Authorization

| Test | Scenario | Asserts |
|---|---|---|
| Unauthorized identity | Sync with an identity that has no `Commit` permission | `icp` exits with non-zero; error message mentions permission |
| Proxy mode: permission grant | Sync in proxy mode where identity lacks `Commit` | Plugin grants permission via proxy; sync succeeds |
| Proxy mode: already permitted | Identity already has `Commit` | Grant step skipped (log message confirms); sync succeeds |

---

## Mapping to Old SDK Test Coverage

| Old SDK test | Replaced by |
|---|---|
| `ic-certified-assets/src/tests.rs` | `ic-certified-assets/src/tests.rs` (already ported and expanded) |
| `ic-asset/src/sync.rs` unit tests | `assets-sync` unit tests — `scan.rs` (Layer 2a) |
| `ic-asset/src/batch_upload/operations.rs` unit tests | `assets-sync` unit tests — `sync.rs::build_operations` (Layer 2c) |
| `ic-asset/src/asset/config.rs` unit tests | Not yet in scope (plugin has no `.ic-assets.json5` support yet) |
| `icx-asset.bash` (BATS) | E2E Layer 3 — basic sync, encoding, chunking, pagination |
| `assetscanister.bash` (BATS) — canister API behaviors | Covered by existing Layer 1 unit tests |
| `assetscanister.bash` — permission checks | E2E Layer 3 — authorization tests |
| `frontend.bash` (BATS) | Out of scope (`dfx deploy` UI/UX not applicable) |
| Playwright browser tests | Out of scope |
| Proposal / governance tests | Out of scope |

---

## Checklist

### Layer 2: Plugin Unit Tests

- [x] **`scan.rs` unit tests**  
  Inline `#[cfg(test)]` module in `assets-sync/src/scan.rs`. Uses `tempfile` for fixtures.  
  Covers: single file, nested dirs, dotfile skip, empty dir, duplicate key error, multiple source dirs.

- [x] **`content.rs` unit tests**  
  Add inline `#[cfg(test)]` module to `assets-sync/src/content.rs`.  
  Covers: `encoders_for` by MIME type, gzip/brotli round-trips, SHA256 determinism, identity passthrough.

- [x] **`sync.rs::build_operations` unit tests**  
  Inline `#[cfg(test)]` module in `assets-sync/src/sync.rs`. No WIT constraint applies since `assets-sync` has no WASI dependency.  
  Covers: create, no-op, update, delete, type-mismatch recreate, stale encoding unset, new encoding set, gzip-not-smaller skip, empty-project delete-all, everything-in-sync.

### Layer 3: E2E Tests

- [x] **E2E infrastructure**  
  `e2e/` crate wired up with `build.rs`, fixture directory, `LocalNetwork` helper, and two smoke tests (`basic_deploy`, `basic_deploy_with_proxy`). New CI job added.

- [x] **Basic sync E2E tests**  
  Covers: basic deploy, basic deploy with proxy, no-op sync, content update, asset deletion, multi-directory sync.

- [x] **Encoding policy unit tests**  
  Covered by unit tests instead of E2E: `encoders_for` MIME tests in `content.rs` (text gets gzip, binary identity-only); `prepare_asset_skips_gzip_when_not_smaller` in `sync.rs` (gzip skipped when not smaller).

- [x] **Chunking and pagination unit tests**  
  Covered by unit tests instead of E2E: `upload_chunks` boundary tests in `sync.rs` (empty, small, at MAX\_CHUNK\_SIZE, one-over, double, sequential IDs); `list_assets` pagination-loop tests in `canister.rs` (empty canister, single partial page, partial last page terminates early, full pages then empty, multiple full pages then partial). Canister-side chunking and pagination already covered by `ic-certified-assets` unit tests.

- [x] **Authorization unit tests**  
  Covered by unit tests instead of E2E: `ensure_commit_permission_grants_via_proxy_when_absent` and `ensure_commit_permission_skips_grant_when_already_permitted` in `sync.rs` (proxy-mode logic); `sync_propagates_permission_error_from_create_batch` in `sync.rs` (direct-mode error propagation). Canister-side permission enforcement already covered by `ic-certified-assets` Layer 1 tests.
