# Testing

Tests are organized around these components. Each runs independently.

## Asset preparation (`asset-prep`)

- **Location**: inline `#[cfg(test)]` modules in each [`crates/asset-prep/src/`](../../crates/asset-prep/src/)`*.rs` file
- **Run**: `cargo test -p asset-prep`

`asset-prep` is the native, local-only crate that turns a `dist/` directory into prepared assets + redirect rules + the canonical `state-hash::Manifest` (shared by `sync-core` and the `state-hash-cli` verifier). It owns directory scanning, MIME detection, encoding selection, `_headers`/`_redirects` parsing, html-handling synthesis, the 404 convention, content chunking/hashing, and the `dist → Manifest` builder.

**Add tests here when** you change how files are discovered, how MIME/encodings are chosen, how `_headers`/`_redirects` parse, how html-handling/404 rules are synthesised, or how content is chunked/hashed into a manifest.

## State hash (`state-hash`)

- **Location**: inline `#[cfg(test)]` in [`crates/state-hash/src/lib.rs`](../../crates/state-hash/src/lib.rs)
- **Run**: `cargo test -p state-hash`

`state-hash` is the tiny no-WASI crate owning the `Manifest` type and the **frozen canonical byte format** + digest, used identically by the canister and the verifier. Includes golden-vector tests that pin the byte layout against silent drift.

**Add tests here when** you touch the manifest shape or the canonical serialization. A format change must bump `VERSION` and update the golden vectors.

## Canister (`canister-core`)

- **Location**: [`crates/canister-core/src/tests.rs`](../../crates/canister-core/src/tests.rs)
- **Run**: `cargo test -p canister-core`

`canister-core` is the library crate behind `canister`. Its unit tests cover all canister behaviors using a mock system context — no live replica needed: asset CRUD, encoding selection, HTTP semantics, certification, permissions, stable state, and streaming.

**Add tests here when** you change anything inside `canister-core`: new canister endpoints, modified serving logic, certification changes, permission rules, or upgrade/downgrade behavior.

## Plugin (`sync-core`)

- **Location**: inline `#[cfg(test)]` modules in each [`crates/sync-core/src/`](../../crates/sync-core/src/)`*.rs` file
- **Run**: `cargo test -p sync-core`

`sync-core` is the library crate behind `sync-plugin`. It has no WASI dependency and compiles natively, and depends on `asset-prep` for local `dist/` preparation. Its unit tests cover the **canister-call orchestration**: operation diffing against current canister state, chunk upload / batch sequencing, canister API calls and pagination, and authorization. (Local preparation — scanning, MIME/encoding, header/redirect parsing — is tested in `asset-prep`.)

**Add tests here when** you change any sync orchestration: how diffs against the canister are computed, how chunks are packed/uploaded, how batch operations are sequenced, or how permissions are managed. Prefer this over E2E for new logic — tests are fast and require no infrastructure.

## End-to-end (`e2e`)

- **Location**: [`crates/e2e/`](../../crates/e2e/)
- **Run**: `cargo test -p e2e`

E2E tests verify that the canister and plugin work correctly together through the `icp` CLI against a live local replica. Covers the basic sync workflow: deploy, no-op re-sync, content update, deletion, and multi-directory sync.

**Add tests here when** you introduce a new top-level workflow or change how the plugin integrates with the CLI or canister in a way that unit tests cannot exercise — for example, a new deploy mode or wire-protocol changes. Keep this suite small; unit tests are preferred for logic coverage.
