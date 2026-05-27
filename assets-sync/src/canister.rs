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

#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
pub enum RulePattern {
    Exact(String),
    Subtree(String),
}

#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
pub struct RedirectRule {
    pub from: RulePattern,
    pub to: String,
    pub status: u16,
    pub headers: Option<Vec<(String, String)>>,
}

#[derive(CandidType, Clone, Debug)]
pub struct SetRedirectRulesArguments {
    pub rules: Vec<RedirectRule>,
}

#[derive(CandidType, Clone, Debug)]
pub enum BatchOperationKind {
    Clear(ClearArguments),
    DeleteAsset(DeleteAssetArguments),
    CreateAsset(CreateAssetArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    SetAssetContent(SetAssetContentArguments),
    SetAssetProperties(SetAssetPropertiesArguments),
    SetRedirectRules(SetRedirectRulesArguments),
}

#[derive(CandidType, Debug)]
pub struct CommitBatchArguments {
    pub batch_id: Nat,
    pub operations: Vec<BatchOperationKind>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Default)]
pub struct AssetProperties {
    pub max_age: Option<u64>,
    pub headers: Option<HashMap<String, String>>,
    pub allow_raw_access: Option<bool>,
    pub is_aliased: Option<bool>,
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
struct CreateChunksRequest<'a> {
    batch_id: Nat,
    content: Vec<&'a [u8]>,
}

#[derive(CandidType, Debug, Deserialize)]
struct CreateChunksResponse {
    chunk_ids: Vec<Nat>,
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

pub fn create_chunks(
    c: &impl CanisterCall,
    batch_id: &Nat,
    content: &[&[u8]],
) -> Result<Vec<Nat>, String> {
    let req = CreateChunksRequest {
        batch_id: batch_id.clone(),
        content: content.to_vec(),
    };
    let resp: CreateChunksResponse = c.call("create_chunks", req, CallType::Update, true)?;
    Ok(resp.chunk_ids)
}

pub fn commit_batch(c: &impl CanisterCall, args: CommitBatchArguments) -> Result<(), String> {
    c.call("commit_batch", args, CallType::Update, true)
}

pub fn get_asset_properties(c: &impl CanisterCall, key: &str) -> Result<AssetProperties, String> {
    c.call(
        "get_asset_properties",
        key.to_string(),
        CallType::Query,
        true,
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use candid::CandidType;
    use serde::de::DeserializeOwned;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct PagedMock {
        pages: RefCell<VecDeque<Vec<AssetDetails>>>,
    }

    impl PagedMock {
        fn new(pages: Vec<Vec<AssetDetails>>) -> Self {
            Self {
                pages: RefCell::new(VecDeque::from(pages)),
            }
        }
    }

    impl CanisterCall for PagedMock {
        fn call<A, R>(&self, method: &str, _arg: A, _: CallType, _: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            assert_eq!(method, "list");
            let page = self.pages.borrow_mut().pop_front().unwrap_or_default();
            let bytes = candid::encode_one(page).map_err(|e| e.to_string())?;
            candid::decode_one(&bytes).map_err(|e| e.to_string())
        }
    }

    fn mk_assets(n: usize) -> Vec<AssetDetails> {
        (0..n)
            .map(|i| AssetDetails {
                key: format!("/asset-{i}"),
                encodings: vec![],
                content_type: "text/plain".to_string(),
            })
            .collect()
    }

    #[test]
    fn list_assets_empty_canister_returns_empty() {
        let result = list_assets(&PagedMock::new(vec![])).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn list_assets_single_partial_page_returns_all() {
        // 5 assets — one partial page, then the implicit empty page terminates the loop.
        let result = list_assets(&PagedMock::new(vec![mk_assets(5)])).unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn list_assets_partial_last_page_terminates_early() {
        // 100 + 50: the 50-item page is smaller than the 100-item page, so the loop
        // breaks without making a third request.
        let mock = PagedMock::new(vec![mk_assets(100), mk_assets(50)]);
        let result = list_assets(&mock).unwrap();
        assert_eq!(result.len(), 150);
        assert!(
            mock.pages.borrow().is_empty(),
            "no third request should be made"
        );
    }

    #[test]
    fn list_assets_full_pages_then_empty_returns_all() {
        // 100 + 100 + 0: two full pages followed by an empty page.
        let result = list_assets(&PagedMock::new(vec![
            mk_assets(100),
            mk_assets(100),
            vec![],
        ]))
        .unwrap();
        assert_eq!(result.len(), 200);
    }

    #[test]
    fn list_assets_multiple_full_pages_then_partial() {
        // 100 + 100 + 73: terminates on the smaller page.
        let result = list_assets(&PagedMock::new(vec![
            mk_assets(100),
            mk_assets(100),
            mk_assets(73),
        ]))
        .unwrap();
        assert_eq!(result.len(), 273);
    }
}
