//! Candid types for the canister endpoints.
//!
//! The wire types shared with the sync plugin live in the [`wire_types`] crate
//! and are re-exported here so the rest of `canister-core` can keep referring to
//! them via `crate::types::*`. Types that only the canister ever produces or
//! consumes are defined locally below.

use candid::{CandidType, Deserialize, Nat};

// Shared wire types (defined once in `wire-types`, used by both sides).
pub use wire_types::{
    BatchOperationKind, CancelSyncArguments, ChunkId, CreateAssetArguments, CreateChunksArguments,
    CreateChunksResponse, DeleteAssetArguments, ExecuteOperationsArguments, SessionId,
    SetAssetContentArguments, SetAssetPropertiesArguments, SetRedirectRulesArguments,
    StartSyncResult, UnsetAssetContentArguments,
};

// Canister-only types — these never cross to the plugin, so they stay here.

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct ListRequest {
    pub start: Option<Nat>,
    pub length: Option<Nat>,
}
