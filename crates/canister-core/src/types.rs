//! Candid types for the canister endpoints.
//!
//! The wire types shared with the sync plugin live in the [`wire_types`] crate
//! and are re-exported here so the rest of `canister-core` can keep referring to
//! them via `crate::types::*`.

// Shared wire types (defined once in `wire-types`, used by both sides).
pub use wire_types::{
    AssetDetails, AssetEncodingDetails, CancelSyncArguments, ChunkId, CreateAssetArguments,
    DeleteAssetArguments, ExecuteOperationsArguments, Operation, SessionId,
    SetAssetContentArguments, SetAssetHeadersArguments, SetRedirectRulesArguments, StartSyncResult,
    UnsetAssetContentArguments, UploadChunksArguments,
};
