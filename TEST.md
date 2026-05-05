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

## Layer 2 — Plugin Unit Tests (`plugin/`)

**Location**: Inline `#[cfg(test)]` modules in each source file (or a `plugin/tests/` directory once the compilation constraint below is resolved).  
**Run**: `cargo test -p plugin`

The plugin crate is a `cdylib` compiled to `wasm32-wasip2`. Its pure business-logic functions have no WIT import dependencies and can be compiled and tested on the host. The WIT-generated `canister_call` extern only appears in `canister.rs`; the other three modules are fully self-contained.

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
| `Content::load()` | Reads file bytes; infers MIME from extension |

### 2c. `sync.rs` — Operation Diffing (`build_operations`)

`build_operations` is a pure function: it takes `project_assets` and `canister_assets` maps and returns a `Vec<BatchOperationKind>`. It can be tested inline via `#[cfg(test)]` without any canister calls.

> **Note on compilation**: The `sync` module imports from `canister.rs`, which references WIT-generated extern symbols. When `cargo test` compiles for the host these symbols are unresolved. The cleanest fix is to add stub implementations under `#[cfg(test)]` in `canister.rs`, or to extract the pure diff logic into a small private sub-module that does not import `canister`. This tradeoff should be settled in the PR that adds these tests.

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

**Setup per test**:
1. Create a temporary project directory containing:
   - `icp.yaml` referencing the workspace-built `canister.wasm` and `plugin.wasm`.
   - An asset directory populated either programmatically by the test or from committed test fixtures.
2. Start a local network with `icp network start -d`; shut it down with `icp network stop` in test cleanup.
3. Run `icp deploy` to install the canister WASM and execute the plugin sync step.
4. Verify the resulting canister state with `icp canister call` (Candid text for both arguments and return values).

### Test Scenarios

#### Basic Sync Workflow

| Test | Scenario | Asserts |
|---|---|---|
| Initial sync | Empty canister, one HTML + one PNG file | Both keys present; content types correct |
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
| `ic-asset/src/sync.rs` unit tests | Plugin unit tests — `scan.rs` (Layer 2a) |
| `ic-asset/src/batch_upload/operations.rs` unit tests | Plugin unit tests — `sync.rs::build_operations` (Layer 2c) |
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
  Add inline `#[cfg(test)]` module to `plugin/src/scan.rs`. Use `tempfile` for fixtures.  
  Covers: single file, nested dirs, dotfile skip, empty dir, duplicate key error, multiple source dirs.

- [ ] **`content.rs` unit tests**  
  Add inline `#[cfg(test)]` module to `plugin/src/content.rs`.  
  Covers: `encoders_for` by MIME type, gzip/brotli round-trips, SHA256 determinism, identity passthrough.

- [ ] **`sync.rs::build_operations` unit tests**  
  Resolve the WIT compilation constraint (stub imports or sub-module extraction), then add tests.  
  Covers: create, no-op, update, delete, type-mismatch recreate, stale encoding unset, new encoding set, gzip-not-smaller skip.

### Layer 3: E2E Tests

- [ ] **E2E infrastructure**  
  Add `e2e/` crate to workspace. Wire up `assert_cmd` and `tempfile`. Add a skeleton test and a new CI job (`cargo test -p e2e`). Document the `icp network start -d` lifecycle and teardown pattern, and the convention for parsing `icp canister call` output in assertions.

- [ ] **Basic sync E2E tests**  
  Covers: initial sync, no-op sync, content update, asset deletion, multi-directory sync.

- [ ] **Encoding policy E2E tests**  
  Covers: text gets gzip, binary identity-only, gzip skipped when not smaller.

- [ ] **Chunking and pagination E2E tests**  
  Covers: multi-chunk upload for files > 1.9 MB, and list pagination with > 100 assets.

- [ ] **Authorization E2E tests**  
  Covers: unauthorized sync rejects, proxy mode grants permission, proxy mode skips redundant grant.
