//! This module defines types shared by the certified assets state machine and the canister
//! endpoints.
use crate::certification::AssetKey;
use crate::rc_bytes::RcBytes;
use crate::redirect::RedirectRule;
use candid::{CandidType, Deserialize, Nat};
use serde_bytes::ByteBuf;

pub type BatchId = Nat;
pub type ChunkId = Nat;

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
pub struct ClearArguments {}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum BatchOperation {
    CreateAsset(CreateAssetArguments),
    SetAssetContent(SetAssetContentArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    DeleteAsset(DeleteAssetArguments),
    Clear(ClearArguments),
    SetAssetProperties(SetAssetPropertiesArguments),
    SetRedirectRules(SetRedirectRulesArguments),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SetRedirectRulesArguments {
    pub rules: Vec<RedirectRule>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CommitBatchArguments {
    pub batch_id: BatchId,
    pub operations: Vec<BatchOperation>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DeleteBatchArguments {
    pub batch_id: BatchId,
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

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateBatchResponse {
    pub batch_id: BatchId,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateChunksArg {
    pub batch_id: BatchId,
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
