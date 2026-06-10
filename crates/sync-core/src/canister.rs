//! Assets canister API: Candid wire types and call wrappers.
//!
//! Types are ported from `ic-asset` (`src/canisters/frontend/ic-asset/src/canister_api/`).
//! Only the subset needed for the V2 batch-upload flow is included.

#![allow(dead_code)]

use candid::{CandidType, Nat, Principal};
use serde::{de::DeserializeOwned, Deserialize};

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
    pub headers: Option<Vec<(String, String)>>,
}

#[derive(CandidType, Clone, Debug)]
pub struct SetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
    pub chunk_ids: Vec<u64>,
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
pub struct SetAssetPropertiesArguments {
    pub key: String,
    pub headers: Option<Option<Vec<(String, String)>>>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum RulePattern {
    Exact(String),
    Subtree(String),
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq)]
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
    DeleteAsset(DeleteAssetArguments),
    CreateAsset(CreateAssetArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    SetAssetContent(SetAssetContentArguments),
    SetAssetProperties(SetAssetPropertiesArguments),
    SetRedirectRules(SetRedirectRulesArguments),
}

#[derive(CandidType, Debug)]
pub struct ExecuteOperationsArguments {
    pub session_id: u64,
    pub operations: Vec<BatchOperationKind>,
    pub is_final: bool,
}

#[derive(CandidType, Clone, Debug, Deserialize, Default)]
pub struct AssetProperties {
    pub headers: Option<Vec<(String, String)>>,
}

#[derive(CandidType, Debug)]
struct ListAssetsRequest {
    start: Option<Nat>,
    length: Option<Nat>,
}

/// Result of `start_sync`. `Busy` is a normal outcome — another non-stale sync
/// holds the lock — not a transport error.
#[derive(CandidType, Debug, Deserialize)]
enum StartSyncResult {
    Started {
        session_id: u64,
    },
    Busy {
        owner: Principal,
        idle_for_secs: u64,
    },
}

#[derive(CandidType, Debug)]
struct CreateChunksRequest<'a> {
    session_id: u64,
    content: Vec<&'a [u8]>,
}

#[derive(CandidType, Debug, Deserialize)]
struct CreateChunksResponse {
    chunk_ids: Vec<u64>,
}

#[derive(CandidType, Debug)]
pub struct CancelSyncArguments {
    pub session_id: u64,
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

/// Begins a sync, returning its session id. A `Busy` result (another non-stale
/// sync is in progress) is surfaced as an error with the holder's principal and
/// idle time so the caller can decide whether to wait.
pub fn start_sync(c: &impl CanisterCall) -> Result<u64, String> {
    let resp: StartSyncResult = c.call("start_sync", (), CallType::Update, true)?;
    match resp {
        StartSyncResult::Started { session_id } => Ok(session_id),
        StartSyncResult::Busy {
            owner,
            idle_for_secs,
        } => Err(format!(
            "a sync is already in progress on this canister (started by {owner}, \
             idle for {idle_for_secs}s); retry once it completes, or after it goes stale"
        )),
    }
}

pub fn create_chunks(
    c: &impl CanisterCall,
    session_id: u64,
    content: &[&[u8]],
) -> Result<Vec<u64>, String> {
    let req = CreateChunksRequest {
        session_id,
        content: content.to_vec(),
    };
    let resp: CreateChunksResponse = c.call("create_chunks", req, CallType::Update, true)?;
    Ok(resp.chunk_ids)
}

pub fn execute_operations(
    c: &impl CanisterCall,
    args: ExecuteOperationsArguments,
) -> Result<(), String> {
    c.call("execute_operations", args, CallType::Update, true)
}

/// Abandons the active sync, releasing the lock. Best-effort cleanup on an
/// aborted sync; a sync left uncancelled is reclaimed once it goes stale.
pub fn cancel_sync(c: &impl CanisterCall, session_id: u64) -> Result<(), String> {
    c.call(
        "cancel_sync",
        CancelSyncArguments { session_id },
        CallType::Update,
        true,
    )
}

pub fn get_asset_properties(c: &impl CanisterCall, key: &str) -> Result<AssetProperties, String> {
    c.call(
        "get_asset_properties",
        key.to_string(),
        CallType::Query,
        true,
    )
}

pub fn get_redirect_rules(c: &impl CanisterCall) -> Result<Vec<RedirectRule>, String> {
    c.call("get_redirect_rules", (), CallType::Query, true)
}

// Whether the signing identity may sync assets (authorized or a controller).
// Called directly (not via proxy) so it reflects the identity's own access.
pub fn can_sync(c: &impl CanisterCall) -> Result<bool, String> {
    c.call("can_sync", (), CallType::Query, true)
}

// Routes through the proxy (direct: false) so the proxy canister — the
// controller — can authorise the call on the assets canister.
pub fn authorize_via_proxy(c: &impl CanisterCall, principal: Principal) -> Result<(), String> {
    c.call("authorize", principal, CallType::Update, false)
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
