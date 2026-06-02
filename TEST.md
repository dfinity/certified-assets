# Testing Guide

Tests are organized around three components. Each runs independently.

## Canister (`canister-core`)

**Location**: `crates/canister-core/src/tests.rs`  
**Run**: `cargo test -p canister-core`

`canister-core` is the library crate behind `canister`. Its unit tests cover all canister behaviors using a mock system context — no live replica needed: asset CRUD, encoding selection, HTTP semantics, certification, permissions, stable state, and streaming.

**Add tests here when** you change anything inside `canister-core`: new canister endpoints, modified serving logic, certification changes, permission rules, or upgrade/downgrade behavior.

## Plugin (`sync-core`)

**Location**: Inline `#[cfg(test)]` modules in each `crates/sync-core/src/*.rs` file  
**Run**: `cargo test -p sync-core`

`sync-core` is the library crate behind `sync-plugin`. It has no WASI dependency and compiles natively. Its unit tests cover all sync business logic: directory scanning, MIME detection and encoding, operation diffing, batch sequencing, canister API calls and pagination, and authorization.

**Add tests here when** you change any sync logic: how files are discovered, how encodings are chosen, how diffs are computed, how batch operations are sequenced, or how permissions are managed. Prefer this over E2E for new logic — tests are fast and require no infrastructure.

## End-to-End (`e2e`)

**Location**: `crates/e2e/`  
**Run**: `cargo test -p e2e`

E2E tests verify that the canister and plugin work correctly together through the `icp` CLI against a live local replica. Covers the basic sync workflow: deploy, no-op re-sync, content update, deletion, and multi-directory sync.

**Add tests here when** you introduce a new top-level workflow or change how the plugin integrates with the CLI or canister in a way that unit tests cannot exercise — for example, a new deploy mode or wire-protocol changes. Keep this suite small; unit tests are preferred for logic coverage.
