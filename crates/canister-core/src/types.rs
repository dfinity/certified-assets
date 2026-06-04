//! This module defines types shared by the certified assets state machine and the canister
//! endpoints.
use crate::certification::AssetKey;
use crate::rc_bytes::RcBytes;
use crate::redirect::RedirectRule;
use candid::{CandidType, Deserialize, Nat, Principal};
use serde_bytes::ByteBuf;

pub type BatchId = Nat;
pub type ChunkId = Nat;

// IDL Types

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ConfigureArguments {
    pub max_batches: Option<Option<u64>>,
    pub max_chunks: Option<Option<u64>>,
    pub max_bytes: Option<Option<u64>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ConfigurationResponse {
    pub max_batches: Option<u64>,
    pub max_chunks: Option<u64>,
    pub max_bytes: Option<u64>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct StateInfo {
    pub last_state_update_timestamp: u64,
    pub state_hash: Option<String>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateAssetArguments {
    pub key: AssetKey,
    pub content_type: String,
    pub max_age: Option<u64>,
    pub headers: Option<Vec<(String, String)>>,
    pub enable_aliasing: Option<bool>,
    pub allow_raw_access: Option<bool>,
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
pub struct StoreArg {
    pub key: AssetKey,
    pub content_type: String,
    pub content_encoding: String,
    pub content: ByteBuf,
    pub sha256: Option<ByteBuf>,
    pub aliased: Option<bool>,
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
    pub max_age: Option<u64>,
    pub headers: Option<Vec<(String, String)>>,
    pub allow_raw_access: Option<bool>,
    pub is_aliased: Option<bool>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SetAssetPropertiesArguments {
    pub key: AssetKey,
    pub max_age: Option<Option<u64>>,
    pub headers: Option<Option<Vec<(String, String)>>>,
    pub allow_raw_access: Option<Option<bool>>,
    pub is_aliased: Option<Option<bool>>,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct ListRequest {
    pub start: Option<Nat>,
    pub length: Option<Nat>,
}

/// The argument to `init` and `post_upgrade` needs to have the same argument type by definition.
/// `AssetCanisterArgs` is there so that the two functions can take different argument types.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum AssetCanisterArgs {
    Init(InitArgs),
    Upgrade(UpgradeArgs),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InitArgs {
    /// The authorized set: extra (non-controller) principals allowed to sync.
    /// Defaults to empty when no init args are given; controllers can always
    /// sync regardless.
    pub authorized: Vec<Principal>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpgradeArgs {
    /// Replaces the authorized set; an empty vector clears it. Pass no upgrade
    /// args at all to leave the existing set untouched.
    pub authorized: Vec<Principal>,
}
