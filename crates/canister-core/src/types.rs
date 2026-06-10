//! This module defines types shared by the certified assets state machine and the canister
//! endpoints.
use crate::certification::AssetKey;
use crate::rc_bytes::RcBytes;
use crate::redirect::RedirectRule;
use candid::{CandidType, Deserialize, Nat, Principal};
use serde_bytes::ByteBuf;

/// Identifies an in-progress sync. Sequential and monotonic across the
/// canister's whole lifetime (persisted across upgrades), so a session id is
/// never reused — calls carrying a superseded id are cleanly rejected.
pub type SessionId = u64;
pub type ChunkId = u64;

// IDL Types

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct StateInfo {
    pub last_state_update_timestamp: u64,
    pub state_hash: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateAssetArguments {
    pub key: AssetKey,
    pub content_type: String,
    pub headers: Option<Vec<(String, String)>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SetAssetContentArguments {
    pub key: AssetKey,
    pub content_encoding: String,
    pub chunk_ids: Vec<ChunkId>,
    /// If set: appended as the final chunk.
    pub last_chunk: Option<ByteBuf>,
    pub sha256: Option<ByteBuf>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UnsetAssetContentArguments {
    pub key: AssetKey,
    pub content_encoding: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DeleteAssetArguments {
    pub key: AssetKey,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum BatchOperation {
    CreateAsset(CreateAssetArguments),
    SetAssetContent(SetAssetContentArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    DeleteAsset(DeleteAssetArguments),
    SetAssetProperties(SetAssetPropertiesArguments),
    SetRedirectRules(SetRedirectRulesArguments),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SetRedirectRulesArguments {
    pub rules: Vec<RedirectRule>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ExecuteOperationsArguments {
    pub session_id: SessionId,
    pub operations: Vec<BatchOperation>,
    /// Set on the last call of a sync. When all operations have been applied,
    /// the canister finalizes the sync and returns to the "no ongoing sync"
    /// state. Non-final calls keep the session open for further operations.
    pub is_final: bool,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CancelSyncArguments {
    pub session_id: SessionId,
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

/// Result of `start_sync`. `Busy` is a normal, expected outcome — not an error
/// — so the caller can surface who holds the lock and decide whether to wait.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum StartSyncResult {
    Started {
        session_id: SessionId,
    },
    Busy {
        owner: Principal,
        idle_for_secs: u64,
    },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateChunksArg {
    pub session_id: SessionId,
    pub content: Vec<ByteBuf>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateChunksResponse {
    pub chunk_ids: Vec<ChunkId>,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct AssetProperties {
    pub headers: Option<Vec<(String, String)>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SetAssetPropertiesArguments {
    pub key: AssetKey,
    pub headers: Option<Option<Vec<(String, String)>>>,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct ListRequest {
    pub start: Option<Nat>,
    pub length: Option<Nat>,
}
