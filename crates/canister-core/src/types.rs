//! Candid types for the canister endpoints.
//!
//! The wire types shared with the sync plugin live in the [`wire_types`] crate
//! and are re-exported here so the rest of `canister-core` can keep referring to
//! them via `crate::types::*`. Types that only the canister ever produces or
//! consumes are defined locally below.

use crate::certification::AssetKey;
use crate::rc_bytes::RcBytes;
use candid::{CandidType, Deserialize, Nat};
use serde_bytes::ByteBuf;

// Shared wire types (defined once in `wire-types`, used by both sides).
pub use wire_types::{
    AssetProperties, BatchOperationKind, CancelSyncArguments, ChunkId, CreateAssetArguments,
    CreateChunksArguments, CreateChunksResponse, DeleteAssetArguments, ExecuteOperationsArguments,
    SessionId, SetAssetContentArguments, SetAssetPropertiesArguments, SetRedirectRulesArguments,
    StartSyncResult, UnsetAssetContentArguments,
};

// Canister-only types — these never cross to the plugin, so they stay here.

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct StateInfo {
    pub last_state_update_timestamp: u64,
    pub state_hash: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetArg {
    pub key: AssetKey,
    pub accept_encodings: Vec<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetChunkArg {
    pub key: AssetKey,
    pub content_encoding: String,
    pub index: Nat,
    pub sha256: Option<ByteBuf>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetChunkResponse {
    pub content: RcBytes,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct ListRequest {
    pub start: Option<Nat>,
    pub length: Option<Nat>,
}
