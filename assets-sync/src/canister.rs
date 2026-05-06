//! Assets canister API: Candid wire types and call wrappers.
//!
//! Types are ported from `ic-asset` (`src/canisters/frontend/ic-asset/src/canister_api/`).
//! Only the subset needed for the V2 batch-upload flow is included.

#![allow(dead_code)]

use candid::{CandidType, Nat, Principal};
use serde::{de::DeserializeOwned, Deserialize};
use std::collections::HashMap;

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct AssetEncodingDetails {
    pub content_encoding: String,
    pub sha256: Option<Vec<u8>>,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct AssetDetails {
    pub key: String,
    pub encodings: Vec<AssetEncodingDetails>,
    pub content_type: String,
}

#[derive(CandidType, Clone, Debug)]
pub struct CreateAssetArguments {
    pub key: String,
    pub content_type: String,
    pub max_age: Option<u64>,
    pub headers: Option<HashMap<String, String>>,
    pub enable_aliasing: Option<bool>,
    pub allow_raw_access: Option<bool>,
}

#[derive(CandidType, Clone, Debug)]
pub struct SetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
    pub chunk_ids: Vec<Nat>,
    pub last_chunk: Option<Vec<u8>>,
    pub sha256: Option<Vec<u8>>,
}

#[derive(CandidType, Clone, Debug)]
pub struct UnsetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
}

#[derive(CandidType, Clone, Debug)]
pub struct DeleteAssetArguments {
    pub key: String,
}

#[derive(CandidType, Clone, Debug)]
pub struct ClearArguments {}

#[derive(CandidType, Clone, Debug)]
pub struct SetAssetPropertiesArguments {
    pub key: String,
    pub max_age: Option<Option<u64>>,
    pub headers: Option<Option<Vec<(String, String)>>>,
    pub allow_raw_access: Option<Option<bool>>,
    pub is_aliased: Option<Option<bool>>,
}

#[derive(CandidType, Clone, Debug)]
pub enum BatchOperationKind {
    Clear(ClearArguments),
    DeleteAsset(DeleteAssetArguments),
    CreateAsset(CreateAssetArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    SetAssetContent(SetAssetContentArguments),
    SetAssetProperties(SetAssetPropertiesArguments),
}

#[derive(CandidType, Debug)]
pub struct CommitBatchArguments {
    pub batch_id: Nat,
    pub operations: Vec<BatchOperationKind>,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub enum Permission {
    Commit,
    ManagePermissions,
    Prepare,
}

#[derive(CandidType, Debug)]
struct ListAssetsRequest {
    start: Option<Nat>,
    length: Option<Nat>,
}

#[derive(CandidType, Debug)]
struct CreateBatchRequest {}

#[derive(CandidType, Debug, Deserialize)]
struct CreateBatchResponse {
    batch_id: Nat,
}

#[derive(CandidType, Debug)]
struct CreateChunkRequest<'a> {
    batch_id: Nat,
    content: &'a [u8],
}

#[derive(CandidType, Debug, Deserialize)]
struct CreateChunkResponse {
    chunk_id: Nat,
}

#[derive(CandidType, Debug)]
struct ListPermittedArguments {
    permission: Permission,
}

#[derive(CandidType, Debug)]
struct GrantPermissionArguments {
    to_principal: Principal,
    permission: Permission,
}

#[derive(Debug, Clone, Copy)]
pub enum CallType {
    Update,
    Query,
}

pub trait CanisterCall {
    fn call<A, R>(
        &self,
        method: &str,
        arg: A,
        call_type: CallType,
        direct: bool,
    ) -> Result<R, String>
    where
        A: CandidType,
        R: CandidType + DeserializeOwned;
}

pub fn api_version(c: &impl CanisterCall) -> Result<u16, String> {
    c.call("api_version", (), CallType::Query, true)
}

// Ported from ic-asset. Unlike ic-asset, which must handle older canister versions
// that ignore `start`, this plugin targets only the canister in this repo, which
// always honours pagination.
pub fn list_assets(c: &impl CanisterCall) -> Result<Vec<AssetDetails>, String> {
    let mut all: Vec<AssetDetails> = Vec::new();
    let mut start: u64 = 0;
    let mut prev_page_size: Option<usize> = None;
    loop {
        let req = ListAssetsRequest {
            start: Some(Nat::from(start)),
            length: None,
        };
        let entries: Vec<AssetDetails> = c.call("list", req, CallType::Query, true)?;
        let n = entries.len();
        if n == 0 {
            break;
        }
        start += n as u64;
        all.extend(entries);
        if let Some(prev) = prev_page_size {
            if n < prev {
                break;
            }
        }
        prev_page_size = Some(n);
    }
    Ok(all)
}

pub fn create_batch(c: &impl CanisterCall) -> Result<Nat, String> {
    let resp: CreateBatchResponse = c.call(
        "create_batch",
        CreateBatchRequest {},
        CallType::Update,
        true,
    )?;
    Ok(resp.batch_id)
}

pub fn create_chunk(c: &impl CanisterCall, batch_id: &Nat, content: &[u8]) -> Result<Nat, String> {
    let req = CreateChunkRequest {
        batch_id: batch_id.clone(),
        content,
    };
    let resp: CreateChunkResponse = c.call("create_chunk", req, CallType::Update, true)?;
    Ok(resp.chunk_id)
}

pub fn commit_batch(c: &impl CanisterCall, args: CommitBatchArguments) -> Result<(), String> {
    c.call("commit_batch", args, CallType::Update, true)
}

pub fn list_permitted(
    c: &impl CanisterCall,
    permission: Permission,
) -> Result<Vec<Principal>, String> {
    c.call(
        "list_permitted",
        ListPermittedArguments { permission },
        CallType::Update,
        true,
    )
}

// Routes through the proxy (direct: false) so the proxy canister — the
// controller — can authorise the call on the assets canister.
pub fn grant_permission_via_proxy(
    c: &impl CanisterCall,
    to_principal: Principal,
    permission: Permission,
) -> Result<(), String> {
    c.call(
        "grant_permission",
        GrantPermissionArguments {
            to_principal,
            permission,
        },
        CallType::Update,
        false,
    )
}
